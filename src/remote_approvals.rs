//! Remote notifications and approvals for MicroClaw Code (`mccode`).
//!
//! A paired `mccode` can ask the Server to (a) post a one-way notification
//! to a chat and (b) post an approval card with option buttons and learn
//! which option a person picked (`/api/code/*`, see `web/code_remote.rs`).
//!
//! Pending approvals live in memory in [`RemoteApprovalHub`]; a Server
//! restart drops them, and `mccode` then falls back to its own terminal
//! prompt. Answers reach the hub two ways:
//!
//! - **Button taps.** Card buttons carry `mcc:<id>:<n>` callback data. The
//!   agent's own approval buttons use `apv:`, so a remote-approval tap never
//!   resolves an agent approval and vice versa.
//! - **Text replies.** Channel adapters call [`intercept_text_reply`] for each
//!   inbound text message after their own allowlist checks and before the
//!   message is stored or handed to the agent. A reply that names an option
//!   (its number, value or label) of the newest pending card in that chat is
//!   consumed and never reaches the agent; anything else passes through.
//!
//! Security rules:
//!
//! - Approval cards may only be sent to a *control chat*
//!   (`control_chat_ids`), on a channel that can route the answer back
//!   (Telegram, Discord, Slack, Feishu/Lark). Notifications may go to any
//!   chat the Server already knows on an enabled channel.
//! - An answer is accepted only from the chat (or a thread/topic inside the
//!   chat) the card was sent to; a tap relayed from any other chat is
//!   rejected even if its callback data is valid.
//! - The sender must pass the channel's normal inbound checks (Telegram
//!   `allowed_user_ids` applies to every answer, including taps in groups;
//!   Discord/Slack `allowed_channels` and Feishu `allowed_chats` apply).
//! - Only the device (or an operator admin) that created an approval can
//!   read or cancel it over HTTP.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex, RwLock};

use chrono::{DateTime, Utc};
use serde::Serialize;
use tracing::warn;

use crate::runtime::AppState;
use microclaw_engine::storage::db::call_blocking;

/// Callback-data prefix for remote-approval buttons (`mcc:<id>:<n>`).
pub const CALLBACK_PREFIX: &str = "mcc:";
/// Default lifetime of a pending approval.
pub const DEFAULT_TTL_SECS: u64 = 30 * 60;
pub const MIN_TTL_SECS: u64 = 30;
pub const MAX_TTL_SECS: u64 = 24 * 60 * 60;
/// Most options a card can carry (Discord allows five buttons per row).
pub const MAX_OPTIONS: usize = 5;
pub const MAX_LABEL_CHARS: usize = 80;
pub const MAX_VALUE_CHARS: usize = 64;
pub const MAX_TITLE_CHARS: usize = 200;
pub const MAX_TEXT_CHARS: usize = 3000;
/// How long a finished (answered/expired/cancelled) approval stays readable.
const FINISHED_RETENTION_SECS: i64 = 60 * 60;

/// Channels whose adapters route text replies / taps back to the hub.
const APPROVAL_CHANNEL_KINDS: [&str; 4] = ["telegram", "discord", "slack", "feishu"];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteApprovalStatus {
    Pending,
    Answered,
    Expired,
    Cancelled,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalOption {
    pub value: String,
    pub label: String,
}

/// Where a card was posted, for later edits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CardRef {
    /// Native chat/channel id the message lives in.
    pub chat: String,
    /// Native message id (Telegram message id, Discord message id, Slack ts).
    pub message_id: String,
}

#[derive(Clone, Debug)]
pub struct RemoteApproval {
    pub id: String,
    /// Actor that created it (`device:<id>`, `api-key:<id>`, …).
    pub owner: String,
    /// Registry channel name (`telegram`, `telegram.sales`, `discord`, …).
    pub channel: String,
    pub external_chat_id: String,
    pub chat_id: i64,
    pub title: String,
    pub text: String,
    pub options: Vec<ApprovalOption>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub status: RemoteApprovalStatus,
    pub value: Option<String>,
    pub label: Option<String>,
    pub answered_by: Option<String>,
    pub finished_at: Option<DateTime<Utc>>,
    pub card: Option<CardRef>,
}

impl RemoteApproval {
    fn is_live(&self, now: DateTime<Utc>) -> bool {
        self.status == RemoteApprovalStatus::Pending && self.expires_at > now
    }
}

/// A resolved answer.
#[derive(Clone, Debug)]
pub struct RemoteAnswer {
    pub approval: RemoteApproval,
    pub option: ApprovalOption,
}

/// Result of a button tap.
#[derive(Clone, Debug)]
pub enum TapOutcome {
    /// Not a remote-approval button (no `mcc:` prefix or malformed).
    NotOurs,
    Answered(Box<RemoteAnswer>),
    /// A remote-approval button that cannot be answered; the string is the
    /// note to show in place of the buttons.
    Rejected(String),
}

/// A chat a request targets (`<channel>:<external chat id>`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChatTarget {
    pub channel: String,
    pub external_chat_id: String,
    pub chat_id: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetError {
    /// Malformed spec or channel unknown/disabled: HTTP 400.
    Invalid(String),
    /// The Server has never seen that chat: HTTP 404.
    UnknownChat(String),
    /// Not allowed to target that chat: HTTP 403.
    Forbidden(String),
}

impl std::fmt::Display for TargetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TargetError::Invalid(m) | TargetError::UnknownChat(m) | TargetError::Forbidden(m) => {
                f.write_str(m)
            }
        }
    }
}

/// Split `<channel>:<chat id>`; the chat id may itself contain `:` (Slack
/// threads, Telegram topics).
pub fn parse_chat_spec(spec: &str) -> Result<(String, String), TargetError> {
    let spec = spec.trim();
    let Some((channel, chat)) = spec.split_once(':') else {
        return Err(TargetError::Invalid(format!(
            "chat must look like <channel>:<chat id> (for example telegram:123456789), got '{spec}'"
        )));
    };
    let channel = channel.trim().to_ascii_lowercase();
    let chat = chat.trim();
    if channel.is_empty() || chat.is_empty() {
        return Err(TargetError::Invalid(format!(
            "chat must look like <channel>:<chat id>, got '{spec}'"
        )));
    }
    Ok((channel, chat.to_string()))
}

fn channel_kind(channel: &str) -> &str {
    channel.split('.').next().unwrap_or(channel)
}

/// Whether approval answers can be routed back on this channel.
pub fn channel_supports_approvals(channel: &str) -> bool {
    APPROVAL_CHANNEL_KINDS.contains(&channel_kind(channel))
}

/// Resolve and validate a chat spec. `for_approval` adds the approval rules
/// (supported channel, control chat).
pub async fn resolve_chat_target(
    state: &AppState,
    spec: &str,
    for_approval: bool,
) -> Result<ChatTarget, TargetError> {
    let (channel, external_chat_id) = parse_chat_spec(spec)?;
    if state.channel_registry.get(&channel).is_none() {
        return Err(TargetError::Invalid(format!(
            "channel '{channel}' is not enabled on this Server"
        )));
    }
    if for_approval && !channel_supports_approvals(&channel) {
        return Err(TargetError::Invalid(format!(
            "approvals are not supported on '{channel}' (supported: {}); use notify instead",
            APPROVAL_CHANNEL_KINDS.join(", ")
        )));
    }
    let lookup_channel = channel.clone();
    let lookup_chat = external_chat_id.clone();
    let chat_id = call_blocking(state.db.clone(), move |db| {
        db.find_chat_id(&lookup_channel, &lookup_chat)
    })
    .await
    .map_err(|e| TargetError::Invalid(format!("chat lookup failed: {e}")))?
    .ok_or_else(|| {
        TargetError::UnknownChat(format!(
            "chat {channel}:{external_chat_id} is not known to this Server; send the bot a message from that chat first"
        ))
    })?;
    if for_approval && !state.config.is_control_chat(chat_id) {
        return Err(TargetError::Forbidden(format!(
            "chat {channel}:{external_chat_id} is not a control chat; add {chat_id} to control_chat_ids in the Server config to receive approvals there"
        )));
    }
    Ok(ChatTarget {
        channel,
        external_chat_id,
        chat_id,
    })
}

/// Whether a reply from `reply_chat` belongs to the card's chat: the same
/// chat, or a thread/topic inside it (`<chat>:<thread>`).
pub fn chat_matches(card_chat: &str, reply_chat: &str) -> bool {
    reply_chat == card_chat
        || reply_chat
            .strip_prefix(card_chat)
            .is_some_and(|rest| rest.starts_with(':'))
}

/// Which option a free-text reply names: a 1-based number, an option value
/// or an option label (case-insensitive). Leading @mentions are ignored.
pub fn match_option(options: &[ApprovalOption], text: &str) -> Option<usize> {
    let mut rest = text.trim();
    loop {
        if let Some(after) = rest.strip_prefix("<@") {
            match after.find('>') {
                Some(end) => rest = after[end + 1..].trim_start(),
                None => break,
            }
        } else if rest.starts_with('@') {
            match rest.find(char::is_whitespace) {
                Some(end) => rest = rest[end..].trim_start(),
                None => return None,
            }
        } else {
            break;
        }
    }
    let normalized = rest
        .trim()
        .trim_end_matches(['.', '!', '。', '！'])
        .trim()
        .to_lowercase();
    if normalized.is_empty() {
        return None;
    }
    if let Ok(n) = normalized.parse::<usize>() {
        return (1..=options.len()).contains(&n).then(|| n - 1);
    }
    options
        .iter()
        .position(|o| o.value.to_lowercase() == normalized || o.label.to_lowercase() == normalized)
}

/// Callback data for option `index` (0-based) of approval `id`.
pub fn callback_data(id: &str, index: usize) -> String {
    format!("{CALLBACK_PREFIX}{id}:{}", index + 1)
}

/// Parse `mcc:<id>:<n>` into `(id, 0-based index)`.
pub fn parse_callback_data(data: &str) -> Option<(String, usize)> {
    let rest = data.strip_prefix(CALLBACK_PREFIX)?;
    let (id, n) = rest.split_once(':')?;
    let n = n.parse::<usize>().ok()?;
    if id.is_empty() || n == 0 {
        return None;
    }
    Some((id.to_string(), n - 1))
}

/// In-memory store of remote approvals.
#[derive(Default)]
pub struct RemoteApprovalHub {
    entries: Mutex<HashMap<String, RemoteApproval>>,
}

static GLOBAL_HUB: LazyLock<RemoteApprovalHub> = LazyLock::new(RemoteApprovalHub::default);

impl RemoteApprovalHub {
    /// The process-wide hub shared by the web routes and channel adapters.
    pub fn global() -> &'static RemoteApprovalHub {
        &GLOBAL_HUB
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, RemoteApproval>> {
        self.entries.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Mark overdue pending entries expired and drop long-finished ones.
    /// Returns the entries that just expired.
    fn sweep_locked(
        entries: &mut HashMap<String, RemoteApproval>,
        now: DateTime<Utc>,
    ) -> Vec<RemoteApproval> {
        let mut expired = Vec::new();
        for entry in entries.values_mut() {
            if entry.status == RemoteApprovalStatus::Pending && entry.expires_at <= now {
                entry.status = RemoteApprovalStatus::Expired;
                entry.finished_at = Some(entry.expires_at);
                expired.push(entry.clone());
            }
        }
        entries.retain(|_, e| {
            e.finished_at
                .is_none_or(|t| (now - t).num_seconds() < FINISHED_RETENTION_SECS)
        });
        expired
    }

    /// Mark overdue approvals expired; returns those that just expired.
    pub fn sweep(&self) -> Vec<RemoteApproval> {
        Self::sweep_locked(&mut self.lock(), Utc::now())
    }

    pub fn create(
        &self,
        owner: &str,
        target: &ChatTarget,
        title: &str,
        text: &str,
        options: Vec<ApprovalOption>,
        ttl: std::time::Duration,
    ) -> RemoteApproval {
        let now = Utc::now();
        let mut entries = self.lock();
        Self::sweep_locked(&mut entries, now);
        let id = loop {
            let candidate = uuid::Uuid::new_v4().simple().to_string()[..12].to_string();
            if !entries.contains_key(&candidate) {
                break candidate;
            }
        };
        let approval = RemoteApproval {
            id: id.clone(),
            owner: owner.to_string(),
            channel: target.channel.clone(),
            external_chat_id: target.external_chat_id.clone(),
            chat_id: target.chat_id,
            title: title.to_string(),
            text: text.to_string(),
            options,
            created_at: now,
            expires_at: now
                + chrono::Duration::from_std(ttl).unwrap_or(chrono::Duration::seconds(1800)),
            status: RemoteApprovalStatus::Pending,
            value: None,
            label: None,
            answered_by: None,
            finished_at: None,
            card: None,
        };
        entries.insert(id, approval.clone());
        approval
    }

    pub fn set_card(&self, id: &str, card: CardRef) {
        if let Some(entry) = self.lock().get_mut(id) {
            entry.card = Some(card);
        }
    }

    pub fn remove(&self, id: &str) {
        self.lock().remove(id);
    }

    /// Current state; the flag says whether this call expired it.
    pub fn get(&self, id: &str) -> Option<(RemoteApproval, bool)> {
        let mut entries = self.lock();
        let expired = Self::sweep_locked(&mut entries, Utc::now());
        let entry = entries.get(id)?.clone();
        let just_expired = expired.iter().any(|e| e.id == id);
        Some((entry, just_expired))
    }

    /// Cancel a pending approval. Returns the entry and whether it was
    /// still pending (and is now cancelled).
    pub fn cancel(&self, id: &str) -> Option<(RemoteApproval, bool)> {
        let now = Utc::now();
        let mut entries = self.lock();
        Self::sweep_locked(&mut entries, now);
        let entry = entries.get_mut(id)?;
        if entry.status != RemoteApprovalStatus::Pending {
            return Some((entry.clone(), false));
        }
        entry.status = RemoteApprovalStatus::Cancelled;
        entry.finished_at = Some(now);
        Some((entry.clone(), true))
    }

    fn resolve_locked(
        entry: &mut RemoteApproval,
        index: usize,
        answered_by: &str,
        now: DateTime<Utc>,
    ) -> RemoteAnswer {
        let option = entry.options[index].clone();
        entry.status = RemoteApprovalStatus::Answered;
        entry.value = Some(option.value.clone());
        entry.label = Some(option.label.clone());
        entry.answered_by = Some(answered_by.to_string());
        entry.finished_at = Some(now);
        RemoteAnswer {
            approval: entry.clone(),
            option,
        }
    }

    /// Whether `channel`/`chat` has a live approval card.
    pub fn has_pending_in_chat(&self, channel: &str, chat: &str) -> bool {
        let now = Utc::now();
        self.lock().values().any(|e| {
            e.is_live(now) && e.channel == channel && chat_matches(&e.external_chat_id, chat)
        })
    }

    /// Resolve the newest live card in this chat if `text` names one of its
    /// options. `None` leaves the message to the normal (agent) path.
    pub fn answer_text(
        &self,
        channel: &str,
        chat: &str,
        answered_by: &str,
        text: &str,
    ) -> Option<RemoteAnswer> {
        let now = Utc::now();
        let mut entries = self.lock();
        Self::sweep_locked(&mut entries, now);
        let entry = entries
            .values_mut()
            .filter(|e| {
                e.is_live(now) && e.channel == channel && chat_matches(&e.external_chat_id, chat)
            })
            .max_by_key(|e| e.created_at)?;
        let index = match_option(&entry.options, text)?;
        Some(Self::resolve_locked(entry, index, answered_by, now))
    }

    /// Resolve a button tap carrying `data`, coming from `channel`/`chat`.
    pub fn answer_tap(
        &self,
        data: &str,
        channel: &str,
        chat: &str,
        answered_by: &str,
    ) -> TapOutcome {
        let Some((id, index)) = parse_callback_data(data) else {
            return TapOutcome::NotOurs;
        };
        let now = Utc::now();
        let mut entries = self.lock();
        Self::sweep_locked(&mut entries, now);
        let Some(entry) = entries.get_mut(&id) else {
            return TapOutcome::Rejected("This request is no longer active.".into());
        };
        if entry.channel != channel || !chat_matches(&entry.external_chat_id, chat) {
            return TapOutcome::Rejected("This request belongs to another chat.".into());
        }
        match entry.status {
            RemoteApprovalStatus::Pending => {}
            RemoteApprovalStatus::Answered => {
                return TapOutcome::Rejected(format!(
                    "Already answered: {}",
                    entry.label.clone().unwrap_or_default()
                ))
            }
            RemoteApprovalStatus::Expired => {
                return TapOutcome::Rejected("This request expired.".into())
            }
            RemoteApprovalStatus::Cancelled => {
                return TapOutcome::Rejected(
                    "No longer needed (answered in the terminal or cancelled).".into(),
                )
            }
        }
        if index >= entry.options.len() {
            return TapOutcome::Rejected("Unknown option.".into());
        }
        TapOutcome::Answered(Box::new(Self::resolve_locked(
            entry,
            index,
            answered_by,
            now,
        )))
    }
}

// ---------------------------------------------------------------------------
// Card rendering and delivery
// ---------------------------------------------------------------------------

/// One button on a card.
#[derive(Clone, Debug)]
pub struct CardButton {
    pub label: String,
    pub data: String,
}

/// Native interactive-card support for a channel (Telegram, Discord, Slack).
#[async_trait::async_trait]
pub trait ApprovalCardSender: Send + Sync {
    async fn send_card(
        &self,
        external_chat_id: &str,
        text: &str,
        buttons: &[CardButton],
    ) -> Result<CardRef, String>;

    /// Replace the card text and remove its buttons.
    async fn edit_card(&self, card: &CardRef, text: &str) -> Result<(), String>;
}

type CardSenderMap = HashMap<String, Arc<dyn ApprovalCardSender>>;
static CARD_SENDERS: LazyLock<RwLock<CardSenderMap>> = LazyLock::new(Default::default);

/// Register native card support for a channel (called at channel boot).
pub fn register_card_sender(channel: &str, sender: Arc<dyn ApprovalCardSender>) {
    if let Ok(mut map) = CARD_SENDERS.write() {
        map.insert(channel.to_string(), sender);
    }
}

fn card_sender(channel: &str) -> Option<Arc<dyn ApprovalCardSender>> {
    CARD_SENDERS.read().ok()?.get(channel).cloned()
}

pub fn truncate_chars(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// Text of an approval card. With buttons the options are shown as buttons;
/// without, as a numbered list to reply to.
pub fn card_text(approval: &RemoteApproval, with_buttons: bool) -> String {
    let mut out = format!("[MicroClaw Code] {}", approval.title);
    if !approval.text.trim().is_empty() {
        out.push_str("\n\n");
        out.push_str(approval.text.trim());
    }
    out.push_str("\n\n");
    if with_buttons {
        out.push_str("Tap an option, or reply with its number.");
    } else {
        out.push_str("Reply with a number:");
        for (i, option) in approval.options.iter().enumerate() {
            out.push_str(&format!("\n{}. {}", i + 1, option.label));
        }
    }
    out
}

/// Text that replaces a finished card.
pub fn finished_card_text(approval: &RemoteApproval) -> String {
    let outcome = match approval.status {
        RemoteApprovalStatus::Answered => format!(
            "Answered: {}{}",
            approval.label.clone().unwrap_or_default(),
            approval
                .answered_by
                .as_deref()
                .map(|by| format!(" (by {by})"))
                .unwrap_or_default()
        ),
        RemoteApprovalStatus::Expired => "Expired without an answer.".to_string(),
        RemoteApprovalStatus::Cancelled => {
            "No longer needed (answered in the terminal or cancelled).".to_string()
        }
        RemoteApprovalStatus::Pending => "Waiting for an answer.".to_string(),
    };
    format!("[MicroClaw Code] {}\n\n{outcome}", approval.title)
}

/// Post the card for `approval`; returns the native message reference
/// when the channel supports buttons.
pub async fn deliver_approval_card(
    state: &AppState,
    approval: &RemoteApproval,
) -> Result<Option<CardRef>, String> {
    if let Some(sender) = card_sender(&approval.channel) {
        let buttons: Vec<CardButton> = approval
            .options
            .iter()
            .enumerate()
            .map(|(i, o)| CardButton {
                label: o.label.clone(),
                data: callback_data(&approval.id, i),
            })
            .collect();
        let text = card_text(approval, true);
        return sender
            .send_card(&approval.external_chat_id, &text, &buttons)
            .await
            .map(Some);
    }
    let adapter = state
        .channel_registry
        .get(&approval.channel)
        .ok_or_else(|| format!("channel '{}' is not enabled", approval.channel))?;
    adapter
        .send_text(&approval.external_chat_id, &card_text(approval, false))
        .await
        .map(|_| None)
}

/// Reflect a finished approval in the chat: edit the card when possible,
/// otherwise post a short note (only for expiry/cancel — a text answer
/// already got its acknowledgement).
pub async fn finish_card(state: &AppState, approval: &RemoteApproval) {
    let text = finished_card_text(approval);
    if let (Some(card), Some(sender)) = (approval.card.as_ref(), card_sender(&approval.channel)) {
        if let Err(e) = sender.edit_card(card, &text).await {
            warn!("remote approval {}: card edit failed: {e}", approval.id);
        }
        return;
    }
    if let Some(adapter) = state.channel_registry.get(&approval.channel) {
        if let Err(e) = adapter.send_text(&approval.external_chat_id, &text).await {
            warn!("remote approval {}: note send failed: {e}", approval.id);
        }
    }
}

/// Deliver a one-way notification through the normal delivery path
/// (stored as a bot message; failed sends go to the outbox).
pub async fn deliver_notification(
    state: &AppState,
    target: &ChatTarget,
    title: Option<&str>,
    text: &str,
) -> Result<microclaw_engine::channel::DeliveryOutcome, String> {
    let body = match title.map(str::trim).filter(|t| !t.is_empty()) {
        Some(title) => format!("[MicroClaw Code] {title}\n\n{}", text.trim()),
        None => format!("[MicroClaw Code] {}", text.trim()),
    };
    let bot_username = state.config.bot_username_for_channel(&target.channel);
    microclaw_engine::channel::deliver_and_store_bot_message_with_status(
        &state.channel_registry,
        state.db.clone(),
        &bot_username,
        target.chat_id,
        &body,
    )
    .await
}

/// Channel hook for inbound text. Returns `true` when the message answered
/// a remote approval and must not be stored or passed to the agent. Call it
/// after the channel's own allowlist checks.
pub async fn intercept_text_reply(
    state: &AppState,
    channel: &str,
    external_chat_id: &str,
    sender: &str,
    text: &str,
) -> bool {
    let hub = RemoteApprovalHub::global();
    if !hub.has_pending_in_chat(channel, external_chat_id) {
        return false;
    }
    let Some(answer) = hub.answer_text(channel, external_chat_id, sender, text) else {
        return false;
    };
    let approval = answer.approval;
    if approval.card.is_some() {
        // Remove the buttons so the card shows the answer.
        finish_card(state, &approval).await;
    } else if let Some(adapter) = state.channel_registry.get(channel) {
        let ack = format!("Answered: {} (sent to MicroClaw Code)", answer.option.label);
        if let Err(e) = adapter.send_text(external_chat_id, &ack).await {
            warn!("remote approval {}: ack failed: {e}", approval.id);
        }
    }
    true
}

/// Channel hook for a button tap. `data` is the raw callback data; the
/// caller renders [`TapOutcome`] (replace the buttons with
/// [`tap_ack_text`]). `NotOurs` means the tap is not a remote approval.
pub fn handle_tap(data: &str, channel: &str, external_chat_id: &str, sender: &str) -> TapOutcome {
    RemoteApprovalHub::global().answer_tap(data, channel, external_chat_id, sender)
}

/// Text to put in place of the card after a tap.
pub fn tap_ack_text(outcome: &TapOutcome) -> Option<String> {
    match outcome {
        TapOutcome::NotOurs => None,
        TapOutcome::Answered(answer) => Some(finished_card_text(&answer.approval)),
        TapOutcome::Rejected(note) => Some(format!("[MicroClaw Code] {note}")),
    }
}

/// Whether callback data belongs to a remote approval.
pub fn is_remote_callback(data: &str) -> bool {
    data.starts_with(CALLBACK_PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options() -> Vec<ApprovalOption> {
        vec![
            ApprovalOption {
                value: "approve".into(),
                label: "Approve once".into(),
            },
            ApprovalOption {
                value: "always".into(),
                label: "Always allow".into(),
            },
            ApprovalOption {
                value: "deny".into(),
                label: "Deny".into(),
            },
        ]
    }

    fn target(channel: &str, chat: &str) -> ChatTarget {
        ChatTarget {
            channel: channel.into(),
            external_chat_id: chat.into(),
            chat_id: 1,
        }
    }

    fn create(hub: &RemoteApprovalHub, channel: &str, chat: &str, ttl_secs: u64) -> RemoteApproval {
        hub.create(
            "device:d1",
            &target(channel, chat),
            "Run cargo test?",
            "bash: cargo test",
            options(),
            std::time::Duration::from_secs(ttl_secs),
        )
    }

    #[test]
    fn parses_chat_specs() {
        assert_eq!(
            parse_chat_spec("telegram:123").unwrap(),
            ("telegram".into(), "123".into())
        );
        assert_eq!(
            parse_chat_spec(" Slack:C1:1700.1 ").unwrap(),
            ("slack".into(), "C1:1700.1".into())
        );
        assert!(parse_chat_spec("telegram").is_err());
        assert!(parse_chat_spec(":1").is_err());
        assert!(parse_chat_spec("telegram:").is_err());
        assert!(channel_supports_approvals("telegram.sales"));
        assert!(channel_supports_approvals("feishu"));
        assert!(!channel_supports_approvals("web"));
        assert!(!channel_supports_approvals("weixin"));
    }

    #[test]
    fn matches_options_by_number_value_or_label() {
        let opts = options();
        assert_eq!(match_option(&opts, "1"), Some(0));
        assert_eq!(match_option(&opts, " 3. "), Some(2));
        assert_eq!(match_option(&opts, "4"), None);
        assert_eq!(match_option(&opts, "0"), None);
        assert_eq!(match_option(&opts, "ALWAYS"), Some(1));
        assert_eq!(match_option(&opts, "approve once"), Some(0));
        assert_eq!(match_option(&opts, "<@U123> deny"), Some(2));
        assert_eq!(match_option(&opts, "@bot 2"), Some(1));
        assert_eq!(match_option(&opts, "@bot"), None);
        assert_eq!(match_option(&opts, "please run it"), None);
        assert_eq!(match_option(&opts, ""), None);
    }

    #[test]
    fn callback_data_round_trips_and_is_distinct_from_agent_buttons() {
        let data = callback_data("abc123", 1);
        assert_eq!(data, "mcc:abc123:2");
        assert_eq!(parse_callback_data(&data), Some(("abc123".into(), 1)));
        assert!(is_remote_callback(&data));
        assert_eq!(parse_callback_data("apv:1:42:p"), None);
        assert!(!is_remote_callback("apv:1:42:p"));
        assert_eq!(parse_callback_data("mcc:abc:0"), None);
        assert_eq!(parse_callback_data("mcc::1"), None);
        assert!(data.len() <= 64, "Telegram callback_data limit");
    }

    #[test]
    fn chat_matching_accepts_threads_of_the_same_chat_only() {
        assert!(chat_matches("123", "123"));
        assert!(chat_matches("-100123", "-100123:45"));
        assert!(chat_matches("C1", "C1:1700.1"));
        assert!(!chat_matches("123", "1234"));
        assert!(!chat_matches("123", "12"));
        assert!(!chat_matches("C1:1700.1", "C1"));
    }

    #[test]
    fn text_reply_in_the_card_chat_resolves_it() {
        let hub = RemoteApprovalHub::default();
        let a = create(&hub, "telegram", "100", 600);
        // Other chats and other channels are unaffected.
        assert!(hub.answer_text("telegram", "200", "eve", "1").is_none());
        assert!(hub.answer_text("discord", "100", "eve", "1").is_none());
        // Non-option text passes through and leaves it pending.
        assert!(hub
            .answer_text("telegram", "100", "ann", "what is this?")
            .is_none());
        assert!(hub.has_pending_in_chat("telegram", "100"));
        let answer = hub.answer_text("telegram", "100", "ann", "deny").unwrap();
        assert_eq!(answer.option.value, "deny");
        let (state, _) = hub.get(&a.id).unwrap();
        assert_eq!(state.status, RemoteApprovalStatus::Answered);
        assert_eq!(state.value.as_deref(), Some("deny"));
        assert_eq!(state.answered_by.as_deref(), Some("ann"));
        // Once answered, the next "1" goes to the agent again.
        assert!(hub.answer_text("telegram", "100", "ann", "1").is_none());
        assert!(!hub.has_pending_in_chat("telegram", "100"));
    }

    #[test]
    fn text_reply_answers_the_newest_card() {
        let hub = RemoteApprovalHub::default();
        let older = create(&hub, "slack", "C1", 600);
        std::thread::sleep(std::time::Duration::from_millis(5));
        let newer = create(&hub, "slack", "C1", 600);
        let answer = hub.answer_text("slack", "C1:1700.1", "ann", "2").unwrap();
        assert_eq!(answer.approval.id, newer.id);
        assert_eq!(
            hub.get(&older.id).unwrap().0.status,
            RemoteApprovalStatus::Pending
        );
    }

    #[test]
    fn taps_resolve_only_from_the_card_chat() {
        let hub = RemoteApprovalHub::default();
        let a = create(&hub, "discord", "555", 600);
        let data = callback_data(&a.id, 0);
        // Agent approval buttons are not ours.
        assert!(matches!(
            hub.answer_tap("apv:1:555:p", "discord", "555", "x"),
            TapOutcome::NotOurs
        ));
        // A relayed tap from another chat is rejected and changes nothing.
        assert!(matches!(
            hub.answer_tap(&data, "discord", "666", "mallory"),
            TapOutcome::Rejected(_)
        ));
        assert!(matches!(
            hub.answer_tap(&data, "telegram", "555", "mallory"),
            TapOutcome::Rejected(_)
        ));
        assert!(matches!(
            hub.answer_tap(&callback_data(&a.id, 7), "discord", "555", "ann"),
            TapOutcome::Rejected(_)
        ));
        match hub.answer_tap(&data, "discord", "555", "ann") {
            TapOutcome::Answered(answer) => assert_eq!(answer.option.value, "approve"),
            other => panic!("unexpected {other:?}"),
        }
        // Second tap is rejected as already answered.
        match hub.answer_tap(&callback_data(&a.id, 2), "discord", "555", "bob") {
            TapOutcome::Rejected(note) => assert!(note.contains("Already answered")),
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(hub.get(&a.id).unwrap().0.value.as_deref(), Some("approve"));
    }

    #[test]
    fn approvals_expire_and_cancel() {
        let hub = RemoteApprovalHub::default();
        let a = create(&hub, "telegram", "100", 0);
        let (state, just_expired) = hub.get(&a.id).unwrap();
        assert_eq!(state.status, RemoteApprovalStatus::Expired);
        assert!(just_expired);
        let (_, again) = hub.get(&a.id).unwrap();
        assert!(!again, "expiry is reported once");
        assert!(hub.answer_text("telegram", "100", "ann", "1").is_none());
        assert!(matches!(
            hub.answer_tap(&callback_data(&a.id, 0), "telegram", "100", "ann"),
            TapOutcome::Rejected(_)
        ));

        let b = create(&hub, "telegram", "100", 600);
        let (cancelled, changed) = hub.cancel(&b.id).unwrap();
        assert!(changed);
        assert_eq!(cancelled.status, RemoteApprovalStatus::Cancelled);
        assert!(!hub.cancel(&b.id).unwrap().1);
        assert!(hub.answer_text("telegram", "100", "ann", "1").is_none());
        assert!(hub.cancel("missing").is_none());
    }

    #[test]
    fn finished_entries_are_pruned_after_retention() {
        let hub = RemoteApprovalHub::default();
        let a = create(&hub, "telegram", "100", 600);
        hub.cancel(&a.id);
        {
            let mut entries = hub.lock();
            entries.get_mut(&a.id).unwrap().finished_at =
                Some(Utc::now() - chrono::Duration::seconds(FINISHED_RETENTION_SECS + 1));
        }
        hub.sweep();
        assert!(hub.get(&a.id).is_none());
    }

    #[test]
    fn card_text_lists_options_without_buttons() {
        let hub = RemoteApprovalHub::default();
        let a = create(&hub, "feishu", "oc_1", 600);
        let text = card_text(&a, false);
        assert!(text.contains("Run cargo test?"));
        assert!(text.contains("1. Approve once"));
        assert!(text.contains("3. Deny"));
        assert!(!card_text(&a, true).contains("1. Approve once"));
    }
}
