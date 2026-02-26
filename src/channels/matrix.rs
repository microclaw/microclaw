use std::collections::HashMap;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use matrix_sdk::attachment::AttachmentConfig;
use matrix_sdk::authentication::matrix::MatrixSession;
use matrix_sdk::config::SyncSettings as MatrixSyncSettings;
use matrix_sdk::ruma::events::reaction::{ReactionEventContent, SyncReactionEvent};
use matrix_sdk::ruma::events::relation::Annotation;
use matrix_sdk::ruma::events::room::member::{MembershipState, StrippedRoomMemberEvent};
use matrix_sdk::ruma::events::room::message::{
    MessageType, RoomMessageEventContent, SyncRoomMessageEvent,
};
use matrix_sdk::ruma::events::Mentions;
use matrix_sdk::ruma::{OwnedDeviceId, OwnedEventId, OwnedRoomId, OwnedUserId};
use matrix_sdk::{Client as MatrixSdkClient, Room as MatrixSdkRoom, SessionMeta, SessionTokens};
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::agent_engine::process_with_agent_with_events;
use crate::agent_engine::should_suppress_user_error;
use crate::agent_engine::AgentEvent;
use crate::agent_engine::AgentRequestContext;
use crate::channels::startup_guard::{
    mark_channel_started, should_drop_pre_start_message, should_drop_recent_duplicate_message,
};
use crate::chat_commands::{handle_chat_command, is_slash_command, unknown_command_response};
use crate::runtime::AppState;
use crate::setup_def::{ChannelFieldDef, DynamicChannelDef};
use microclaw_channels::channel::ConversationKind;
use microclaw_channels::channel_adapter::ChannelAdapter;
use microclaw_core::text::split_text;
use microclaw_storage::db::call_blocking;
use microclaw_storage::db::StoredMessage;

pub const SETUP_DEF: DynamicChannelDef = DynamicChannelDef {
    name: "matrix",
    presence_keys: &["homeserver_url", "access_token", "bot_user_id"],
    fields: &[
        ChannelFieldDef {
            yaml_key: "homeserver_url",
            label: "Matrix homeserver URL (e.g. https://matrix.org)",
            default: "",
            secret: false,
            required: true,
        },
        ChannelFieldDef {
            yaml_key: "access_token",
            label: "Matrix access token",
            default: "",
            secret: true,
            required: true,
        },
        ChannelFieldDef {
            yaml_key: "bot_user_id",
            label: "Matrix bot user ID (e.g. @bot:example.org)",
            default: "",
            secret: false,
            required: true,
        },
        ChannelFieldDef {
            yaml_key: "bot_username",
            label: "Matrix bot username override (optional)",
            default: "",
            secret: false,
            required: false,
        },
    ],
};

fn default_enabled() -> bool {
    true
}

fn matrix_sdk_clients() -> &'static RwLock<HashMap<String, Arc<MatrixSdkClient>>> {
    static CLIENTS: OnceLock<RwLock<HashMap<String, Arc<MatrixSdkClient>>>> = OnceLock::new();
    CLIENTS.get_or_init(|| RwLock::new(HashMap::new()))
}

fn matrix_chat_locks() -> &'static Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>> {
    static LOCKS: OnceLock<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>> = OnceLock::new();
    LOCKS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn matrix_chat_lock(channel_name: &str, room_id: &str) -> Arc<tokio::sync::Mutex<()>> {
    let key = format!("{channel_name}:{room_id}");
    let Ok(mut guard) = matrix_chat_locks().lock() else {
        return Arc::new(tokio::sync::Mutex::new(()));
    };
    guard
        .entry(key)
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}

fn default_matrix_mention_required() -> bool {
    true
}

fn default_matrix_sync_timeout_ms() -> u64 {
    30_000
}

#[derive(Debug, Clone, Deserialize)]
pub struct MatrixAccountConfig {
    pub access_token: String,
    pub homeserver_url: String,
    pub bot_user_id: String,
    #[serde(default)]
    pub allowed_room_ids: Vec<String>,
    #[serde(default)]
    pub allowed_user_ids: Vec<String>,
    #[serde(default)]
    pub bot_username: String,
    #[serde(default = "default_matrix_mention_required")]
    pub mention_required: bool,
    #[serde(default = "default_matrix_sync_timeout_ms")]
    pub sync_timeout_ms: u64,
    #[serde(default)]
    pub backup_key: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MatrixChannelConfig {
    #[serde(default)]
    pub access_token: String,
    #[serde(default)]
    pub homeserver_url: String,
    #[serde(default)]
    pub bot_user_id: String,
    #[serde(default)]
    pub allowed_room_ids: Vec<String>,
    #[serde(default)]
    pub allowed_user_ids: Vec<String>,
    #[serde(default)]
    pub bot_username: String,
    #[serde(default = "default_matrix_mention_required")]
    pub mention_required: bool,
    #[serde(default = "default_matrix_sync_timeout_ms")]
    pub sync_timeout_ms: u64,
    #[serde(default)]
    pub backup_key: String,
    #[serde(default)]
    pub accounts: HashMap<String, MatrixAccountConfig>,
    #[serde(default)]
    pub default_account: Option<String>,
}

fn pick_default_account_id(
    configured: Option<&str>,
    accounts: &HashMap<String, MatrixAccountConfig>,
) -> Option<String> {
    let explicit = configured
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned);
    if explicit.is_some() {
        return explicit;
    }
    if accounts.contains_key("default") {
        return Some("default".to_string());
    }
    let mut keys: Vec<String> = accounts.keys().cloned().collect();
    keys.sort();
    keys.first().cloned()
}

#[derive(Clone)]
pub struct MatrixRuntimeContext {
    pub channel_name: String,
    pub access_token: String,
    pub homeserver_url: String,
    pub bot_user_id: String,
    pub bot_username: String,
    pub allowed_room_ids: Vec<String>,
    pub allowed_user_ids: Vec<String>,
    pub mention_required: bool,
    pub sync_timeout_ms: u64,
    pub backup_key: String,
    pub sdk_client: Option<Arc<RwLock<Option<Arc<MatrixSdkClient>>>>>,
}

impl MatrixRuntimeContext {
    fn normalized_homeserver_url(&self) -> String {
        self.homeserver_url.trim_end_matches('/').to_string()
    }

    fn sync_timeout_ms_or_default(&self) -> u64 {
        if self.sync_timeout_ms == 0 {
            default_matrix_sync_timeout_ms()
        } else {
            self.sync_timeout_ms
        }
    }

    fn should_process_group_room(&self, room_id: &str) -> bool {
        self.allowed_room_ids.is_empty() || self.allowed_room_ids.iter().any(|v| v == room_id)
    }

    fn should_process_dm_sender(&self, sender_user_id: &str) -> bool {
        self.allowed_user_ids.is_empty()
            || self
                .allowed_user_ids
                .iter()
                .any(|v| v.eq_ignore_ascii_case(sender_user_id))
    }

    fn bot_localpart(&self) -> String {
        let user = self.bot_user_id.trim();
        if let Some(rest) = user.strip_prefix('@') {
            return rest.split(':').next().unwrap_or(rest).to_string();
        }
        user.to_string()
    }

    fn should_respond(&self, text: &str, mentioned: bool, is_direct: bool) -> bool {
        if is_direct {
            return true;
        }

        if !self.mention_required {
            return true;
        }

        if text.trim_start().starts_with('/') {
            return true;
        }

        if mentioned {
            return true;
        }

        let text_lower = text.to_lowercase();
        let user_lower = self.bot_user_id.to_lowercase();
        if !user_lower.is_empty() && text_lower.contains(&user_lower) {
            return true;
        }

        let localpart = self.bot_localpart().to_lowercase();
        !localpart.is_empty() && text_lower.contains(&localpart)
    }
}

pub fn build_matrix_runtime_contexts(config: &crate::config::Config) -> Vec<MatrixRuntimeContext> {
    let Some(matrix_cfg) = config.channel_config::<MatrixChannelConfig>("matrix") else {
        return Vec::new();
    };

    let default_account =
        pick_default_account_id(matrix_cfg.default_account.as_deref(), &matrix_cfg.accounts);

    let mut runtimes = Vec::new();

    let mut account_ids: Vec<String> = matrix_cfg.accounts.keys().cloned().collect();
    account_ids.sort();
    for account_id in account_ids {
        let Some(account_cfg) = matrix_cfg.accounts.get(&account_id) else {
            continue;
        };
        if !account_cfg.enabled
            || account_cfg.access_token.trim().is_empty()
            || account_cfg.homeserver_url.trim().is_empty()
            || account_cfg.bot_user_id.trim().is_empty()
        {
            continue;
        }

        let is_default = default_account
            .as_deref()
            .map(|v| v == account_id.as_str())
            .unwrap_or(false);
        let channel_name = if is_default {
            "matrix".to_string()
        } else {
            format!("matrix.{account_id}")
        };

        let bot_username = if account_cfg.bot_username.trim().is_empty() {
            config.bot_username_for_channel(&channel_name)
        } else {
            account_cfg.bot_username.trim().to_string()
        };

        runtimes.push(MatrixRuntimeContext {
            channel_name,
            access_token: account_cfg.access_token.clone(),
            homeserver_url: account_cfg.homeserver_url.clone(),
            bot_user_id: account_cfg.bot_user_id.clone(),
            bot_username,
            allowed_room_ids: account_cfg.allowed_room_ids.clone(),
            allowed_user_ids: account_cfg.allowed_user_ids.clone(),
            mention_required: account_cfg.mention_required,
            sync_timeout_ms: account_cfg.sync_timeout_ms,
            backup_key: account_cfg.backup_key.clone(),
            sdk_client: None,
        });
    }

    if runtimes.is_empty()
        && !matrix_cfg.access_token.trim().is_empty()
        && !matrix_cfg.homeserver_url.trim().is_empty()
        && !matrix_cfg.bot_user_id.trim().is_empty()
    {
        runtimes.push(MatrixRuntimeContext {
            channel_name: "matrix".to_string(),
            access_token: matrix_cfg.access_token,
            homeserver_url: matrix_cfg.homeserver_url,
            bot_user_id: matrix_cfg.bot_user_id,
            bot_username: if matrix_cfg.bot_username.trim().is_empty() {
                config.bot_username_for_channel("matrix")
            } else {
                matrix_cfg.bot_username.trim().to_string()
            },
            allowed_room_ids: matrix_cfg.allowed_room_ids,
            allowed_user_ids: matrix_cfg.allowed_user_ids,
            mention_required: matrix_cfg.mention_required,
            sync_timeout_ms: matrix_cfg.sync_timeout_ms,
            backup_key: matrix_cfg.backup_key,
            sdk_client: None,
        });
    }

    runtimes
}

pub struct MatrixAdapter {
    name: String,
    homeserver_url: String,
    access_token: String,
    http_client: reqwest::Client,
}

impl MatrixAdapter {
    pub fn new(name: String, homeserver_url: String, access_token: String) -> Self {
        Self {
            name,
            homeserver_url: homeserver_url.trim_end_matches('/').to_string(),
            access_token,
            http_client: reqwest::Client::new(),
        }
    }
}

async fn get_registered_matrix_sdk_client(channel_name: &str) -> Option<Arc<MatrixSdkClient>> {
    matrix_sdk_clients().read().await.get(channel_name).cloned()
}

#[async_trait::async_trait]
impl ChannelAdapter for MatrixAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn chat_type_routes(&self) -> Vec<(&str, ConversationKind)> {
        vec![
            ("matrix", ConversationKind::Group),
            ("matrix_dm", ConversationKind::Private),
        ]
    }

    async fn send_text(&self, external_chat_id: &str, text: &str) -> Result<(), String> {
        let sdk_client = get_registered_matrix_sdk_client(&self.name).await;
        send_matrix_text_with_sdk(
            sdk_client,
            &self.http_client,
            &self.homeserver_url,
            &self.access_token,
            external_chat_id,
            text,
        )
        .await
    }

    async fn send_attachment(
        &self,
        external_chat_id: &str,
        file_path: &Path,
        caption: Option<&str>,
    ) -> Result<String, String> {
        let sdk_client = get_registered_matrix_sdk_client(&self.name).await;
        send_matrix_attachment_with_sdk(
            sdk_client,
            &self.http_client,
            &self.homeserver_url,
            &self.access_token,
            external_chat_id,
            file_path,
            caption,
        )
        .await
    }
}

enum MatrixIncomingEvent {
    Message {
        room_id: String,
        is_direct: bool,
        sender: String,
        event_id: String,
        body: String,
        mentioned_bot: bool,
        event_time_ms: Option<i64>,
    },
    Reaction {
        room_id: String,
        is_direct: bool,
        sender: String,
        event_id: String,
        relates_to_event_id: String,
        key: String,
        event_time_ms: Option<i64>,
    },
}

pub async fn start_matrix_bot(app_state: Arc<AppState>, runtime: MatrixRuntimeContext) {
    mark_channel_started(&runtime.channel_name);
    if let Some(client) = build_matrix_sdk_client(app_state.clone(), &runtime).await {
        let client = Arc::new(client);
        matrix_sdk_clients()
            .write()
            .await
            .insert(runtime.channel_name.clone(), client.clone());
        let client_slot = runtime
            .sdk_client
            .as_ref()
            .cloned()
            .unwrap_or_else(|| Arc::new(RwLock::new(None)));
        *client_slot.write().await = Some(client);

        let mut runtime_with_sdk = runtime.clone();
        runtime_with_sdk.sdk_client = Some(client_slot.clone());
        let e2ee_state = app_state.clone();
        tokio::spawn(async move {
            start_matrix_e2ee_sync(e2ee_state, runtime_with_sdk).await;
        });

        info!(
            "Matrix adapter '{}' using SDK sync path",
            runtime.channel_name.as_str()
        );
        return;
    }

    let mut since: Option<String> = None;
    let mut bootstrapped = false;

    loop {
        match sync_matrix_messages(&runtime, since.as_deref()).await {
            Ok((next_batch, events)) => {
                since = Some(next_batch);

                if !bootstrapped {
                    bootstrapped = true;
                    continue;
                }

                for event in events {
                    let state = app_state.clone();
                    let runtime_ctx = runtime.clone();
                    tokio::spawn(async move {
                        match event {
                            MatrixIncomingEvent::Message {
                                room_id,
                                is_direct,
                                sender,
                                event_id,
                                body,
                                mentioned_bot,
                                event_time_ms,
                            } => {
                                let msg = MatrixIncomingMessage {
                                    room_id,
                                    is_direct,
                                    sender,
                                    event_id,
                                    body,
                                    mentioned_bot,
                                    prefer_sdk_send: false,
                                    event_time_ms,
                                };
                                handle_matrix_message(state, runtime_ctx, msg).await;
                            }
                            MatrixIncomingEvent::Reaction {
                                room_id,
                                is_direct,
                                sender,
                                event_id,
                                relates_to_event_id,
                                key,
                                event_time_ms,
                            } => {
                                let reaction = MatrixIncomingReaction {
                                    room_id,
                                    is_direct,
                                    sender,
                                    event_id,
                                    relates_to_event_id,
                                    key,
                                    event_time_ms,
                                };
                                handle_matrix_reaction(state, runtime_ctx, reaction).await;
                            }
                        }
                    });
                }
            }
            Err(e) => {
                warn!(
                    "Matrix adapter '{}' sync error: {e}",
                    runtime.channel_name.as_str()
                );
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        }
    }
}

#[derive(Deserialize)]
struct MatrixWhoAmIResponse {
    user_id: String,
    #[serde(default)]
    device_id: Option<String>,
}

async fn build_matrix_sdk_client(
    app_state: Arc<AppState>,
    runtime: &MatrixRuntimeContext,
) -> Option<MatrixSdkClient> {
    let store_dir = matrix_sdk_store_dir(&app_state, runtime);
    if let Err(e) = std::fs::create_dir_all(&store_dir) {
        warn!(
            "Matrix SDK could not create store directory '{}': {e}",
            store_dir.display()
        );
        return None;
    }

    let sdk_client = match MatrixSdkClient::builder()
        .homeserver_url(runtime.homeserver_url.clone())
        .sqlite_store(&store_dir, None)
        .build()
        .await
    {
        Ok(client) => client,
        Err(e) => {
            warn!("Matrix SDK client init failed: {e}");
            return None;
        }
    };

    let whoami_url = format!(
        "{}/_matrix/client/v3/account/whoami",
        runtime.homeserver_url.trim_end_matches('/')
    );
    let whoami = match reqwest::Client::new()
        .get(&whoami_url)
        .bearer_auth(runtime.access_token.trim())
        .send()
        .await
    {
        Ok(resp) => match resp.json::<MatrixWhoAmIResponse>().await {
            Ok(v) => v,
            Err(e) => {
                warn!("Matrix SDK whoami parse failed: {e}");
                return None;
            }
        },
        Err(e) => {
            warn!("Matrix SDK whoami failed: {e}");
            return None;
        }
    };

    let user_id: OwnedUserId = match whoami.user_id.parse() {
        Ok(v) => v,
        Err(e) => {
            warn!("Matrix SDK invalid whoami user_id: {e}");
            return None;
        }
    };
    let Some(device_id_raw) = whoami.device_id else {
        warn!("Matrix SDK whoami missing device_id; cannot restore E2EE session");
        return None;
    };
    let device_id: OwnedDeviceId = device_id_raw.into();

    let session = MatrixSession {
        meta: SessionMeta { user_id, device_id },
        tokens: SessionTokens {
            access_token: runtime.access_token.clone(),
            refresh_token: None,
        },
    };

    if let Err(e) = sdk_client
        .matrix_auth()
        .restore_session(session, matrix_sdk::store::RoomLoadSettings::default())
        .await
    {
        warn!("Matrix SDK restore_session failed: {e}");
        return None;
    }

    if !runtime.backup_key.trim().is_empty() {
        let mut recovered = false;
        let mut last_err: Option<String> = None;
        for candidate in matrix_backup_key_candidates(runtime.backup_key.trim()) {
            match sdk_client.encryption().recovery().recover(&candidate).await {
                Ok(()) => {
                    recovered = true;
                    info!("Matrix SDK recovery initialized from configured backup_key");
                    break;
                }
                Err(e) => {
                    last_err = Some(e.to_string());
                }
            }
        }

        if !recovered {
            warn!(
                "Matrix SDK recovery setup failed with configured backup_key (all formats): {}",
                last_err.unwrap_or_else(|| "unknown error".to_string())
            );
        }
    }

    Some(sdk_client)
}

fn matrix_backup_key_candidates(raw_key: &str) -> Vec<String> {
    let trimmed = raw_key.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut push_unique = |v: String| {
        let k = v.trim().to_string();
        if !k.is_empty() && seen.insert(k.clone()) {
            out.push(k);
        }
    };

    push_unique(trimmed.to_string());

    let space_normalized = trimmed
        .chars()
        .map(|c| if c == '-' || c == '_' { ' ' } else { c })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    push_unique(space_normalized);

    let compact = trimmed
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>();
    push_unique(compact.clone());
    if compact.len() >= 8 {
        let grouped = compact
            .chars()
            .collect::<Vec<_>>()
            .chunks(4)
            .map(|chunk| chunk.iter().collect::<String>())
            .collect::<Vec<_>>()
            .join(" ");
        push_unique(grouped);
    }

    out
}

fn matrix_channel_slug(channel_name: &str) -> String {
    let mut out = String::with_capacity(channel_name.len());
    for ch in channel_name.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "matrix".to_string()
    } else {
        out
    }
}

fn matrix_sdk_store_dir(app_state: &AppState, runtime: &MatrixRuntimeContext) -> PathBuf {
    PathBuf::from(app_state.config.runtime_data_dir())
        .join("matrix_sdk")
        .join(matrix_channel_slug(&runtime.channel_name))
}

async fn auto_join_invited_rooms(client: &MatrixSdkClient) {
    for room in client.invited_rooms() {
        let room_id = room.room_id().to_string();
        match room.join().await {
            Ok(()) => info!("Matrix auto-joined invited room {}", room_id),
            Err(e) => warn!("Matrix failed to auto-join invited room {}: {e}", room_id),
        }
    }
}

async fn start_matrix_e2ee_sync(app_state: Arc<AppState>, runtime: MatrixRuntimeContext) {
    let Some(slot) = runtime.sdk_client.as_ref() else {
        return;
    };
    let client = {
        let guard = slot.read().await;
        guard.clone()
    };
    let Some(client) = client else {
        return;
    };

    let bootstrapped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let handler_state = app_state.clone();
    let handler_runtime = runtime.clone();
    let handler_boot = bootstrapped.clone();
    let invite_runtime = runtime.clone();

    client.add_event_handler(move |ev: StrippedRoomMemberEvent, room: MatrixSdkRoom| {
        let runtime = invite_runtime.clone();
        async move {
            if ev.content.membership != MembershipState::Invite {
                return;
            }
            if ev.state_key.as_str() != runtime.bot_user_id {
                return;
            }

            let room_id = room.room_id().to_string();
            match room.join().await {
                Ok(()) => info!("Matrix auto-joined invite room {}", room_id),
                Err(e) => warn!("Matrix failed to auto-join invite room {}: {e}", room_id),
            }
        }
    });

    client.add_event_handler(move |ev: SyncRoomMessageEvent, room: MatrixSdkRoom| {
        let app_state = handler_state.clone();
        let runtime = handler_runtime.clone();
        let bootstrapped = handler_boot.clone();
        async move {
            if !bootstrapped.load(std::sync::atomic::Ordering::SeqCst) {
                return;
            }
            let SyncRoomMessageEvent::Original(ev) = ev else {
                return;
            };
            if ev
                .sender
                .as_str()
                .eq_ignore_ascii_case(&runtime.bot_user_id)
            {
                return;
            }
            let Some(body) = normalize_matrix_sdk_message_type(&ev.content.msgtype) else {
                return;
            };
            if body.trim().is_empty() {
                return;
            }
            let mentioned_bot =
                is_bot_mentioned_in_mentions(ev.content.mentions.as_ref(), &runtime.bot_user_id);
            let room_id = room.room_id().to_string();
            let mut is_direct = room.is_direct().await.unwrap_or(false);
            if !is_direct {
                let members = room.active_members_count();
                if members > 0 && members <= 2 {
                    is_direct = true;
                }
            }
            if !is_direct && !runtime.should_process_group_room(&room_id) {
                return;
            }
            if is_direct && !runtime.should_process_dm_sender(ev.sender.as_str()) {
                return;
            }
            let msg = MatrixIncomingMessage {
                room_id,
                is_direct,
                sender: ev.sender.to_string(),
                event_id: ev.event_id.to_string(),
                body,
                mentioned_bot,
                prefer_sdk_send: true,
                event_time_ms: None,
            };
            handle_matrix_message(app_state, runtime, msg).await;
        }
    });

    let reaction_state = app_state.clone();
    let reaction_runtime = runtime.clone();
    let reaction_boot = bootstrapped.clone();
    client.add_event_handler(move |ev: SyncReactionEvent, room: MatrixSdkRoom| {
        let app_state = reaction_state.clone();
        let runtime = reaction_runtime.clone();
        let bootstrapped = reaction_boot.clone();
        async move {
            if !bootstrapped.load(std::sync::atomic::Ordering::SeqCst) {
                return;
            }
            let SyncReactionEvent::Original(ev) = ev else {
                return;
            };
            if ev
                .sender
                .as_str()
                .eq_ignore_ascii_case(&runtime.bot_user_id)
            {
                return;
            }
            let room_id = room.room_id().to_string();
            let mut is_direct = room.is_direct().await.unwrap_or(false);
            if !is_direct {
                let members = room.active_members_count();
                if members > 0 && members <= 2 {
                    is_direct = true;
                }
            }
            if !is_direct && !runtime.should_process_group_room(&room_id) {
                return;
            }
            if is_direct && !runtime.should_process_dm_sender(ev.sender.as_str()) {
                return;
            }
            let reaction = MatrixIncomingReaction {
                room_id,
                is_direct,
                sender: ev.sender.to_string(),
                event_id: ev.event_id.to_string(),
                relates_to_event_id: ev.content.relates_to.event_id.to_string(),
                key: ev.content.relates_to.key.clone(),
                event_time_ms: None,
            };
            handle_matrix_reaction(app_state, runtime, reaction).await;
        }
    });

    loop {
        let settings = || {
            MatrixSyncSettings::default()
                .timeout(Duration::from_millis(runtime.sync_timeout_ms_or_default()))
        };
        if !bootstrapped.load(std::sync::atomic::Ordering::SeqCst) {
            match client.sync_once(settings()).await {
                Ok(_) => {
                    auto_join_invited_rooms(&client).await;
                    bootstrapped.store(true, std::sync::atomic::Ordering::SeqCst);
                }
                Err(e) => {
                    warn!("Matrix SDK initial sync failed: {e}");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
            }
        }

        if let Err(e) = client.sync(settings()).await {
            warn!("Matrix SDK sync loop ended: {e}");
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }
}

async fn sync_matrix_messages(
    runtime: &MatrixRuntimeContext,
    since: Option<&str>,
) -> Result<(String, Vec<MatrixIncomingEvent>), String> {
    let homeserver_url = runtime.normalized_homeserver_url();
    let url = format!("{homeserver_url}/_matrix/client/v3/sync");

    let timeout_ms = if since.is_some() {
        runtime.sync_timeout_ms_or_default()
    } else {
        0
    };

    let client = reqwest::Client::new();
    let mut request = client
        .get(&url)
        .bearer_auth(runtime.access_token.trim())
        .query(&[("timeout", timeout_ms)]);

    if let Some(since_token) = since {
        request = request.query(&[("since", since_token)]);
    }

    let response = request
        .send()
        .await
        .map_err(|e| format!("Matrix /sync request failed: {e}"))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "Matrix /sync failed: HTTP {status} {}",
            body.chars().take(300).collect::<String>()
        ));
    }

    let payload: Value = response
        .json()
        .await
        .map_err(|e| format!("Matrix /sync response parse failed: {e}"))?;

    let next_batch = payload
        .get("next_batch")
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned)
        .ok_or_else(|| "Matrix /sync response missing next_batch".to_string())?;

    let mut incoming = Vec::new();
    let direct_rooms = extract_direct_room_ids(&payload);

    let joined_rooms = payload
        .pointer("/rooms/join")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();

    for (room_id, room_data) in joined_rooms {
        let is_direct = room_looks_direct(&room_data, direct_rooms.contains(&room_id));
        if !is_direct && !runtime.should_process_group_room(&room_id) {
            continue;
        }

        let Some(events) = room_data
            .pointer("/timeline/events")
            .and_then(|v| v.as_array())
        else {
            continue;
        };

        for event in events {
            let sender = event
                .get("sender")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if sender.trim().is_empty() || sender == runtime.bot_user_id {
                continue;
            }
            if is_direct && !runtime.should_process_dm_sender(&sender) {
                continue;
            }

            let event_type = event
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let event_id = event
                .get("event_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            if event_type == "m.room.message" {
                let body = normalize_matrix_message_body(event);
                if body.trim().is_empty() {
                    continue;
                }

                let mentioned_bot = event
                    .pointer("/content/m.mentions/user_ids")
                    .and_then(|v| v.as_array())
                    .map(|ids| {
                        ids.iter()
                            .filter_map(|v| v.as_str())
                            .any(|v| v == runtime.bot_user_id)
                    })
                    .unwrap_or(false);

                incoming.push(MatrixIncomingEvent::Message {
                    room_id: room_id.clone(),
                    is_direct,
                    sender,
                    event_id,
                    body,
                    mentioned_bot,
                    event_time_ms: event.get("origin_server_ts").and_then(|v| v.as_i64()),
                });
            } else if event_type == "m.reaction" {
                let key = event
                    .pointer("/content/m.relates_to/key")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let relates_to_event_id = event
                    .pointer("/content/m.relates_to/event_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                if key.trim().is_empty() || relates_to_event_id.trim().is_empty() {
                    continue;
                }

                incoming.push(MatrixIncomingEvent::Reaction {
                    room_id: room_id.clone(),
                    is_direct,
                    sender,
                    event_id,
                    relates_to_event_id,
                    key,
                    event_time_ms: event.get("origin_server_ts").and_then(|v| v.as_i64()),
                });
            }
        }
    }

    Ok((next_batch, incoming))
}

fn normalize_matrix_message_body(event: &Value) -> String {
    let msgtype = event
        .pointer("/content/msgtype")
        .and_then(|v| v.as_str())
        .unwrap_or("m.text");

    let body = event
        .pointer("/content/body")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    match msgtype {
        "m.image" | "m.file" | "m.audio" | "m.video" => {
            let url = event
                .pointer("/content/url")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if url.is_empty() {
                format!("[attachment:{msgtype}] {body}")
            } else {
                format!("[attachment:{msgtype}] {body} ({url})")
            }
        }
        _ => body.to_string(),
    }
}

fn normalize_matrix_sdk_message_type(msgtype: &MessageType) -> Option<String> {
    match msgtype {
        MessageType::Text(text) => Some(text.body.clone()),
        MessageType::Image(image) => Some(format!("[attachment:m.image] {}", image.body)),
        MessageType::File(file) => Some(format!("[attachment:m.file] {}", file.body)),
        MessageType::Audio(audio) => Some(format!("[attachment:m.audio] {}", audio.body)),
        MessageType::Video(video) => Some(format!("[attachment:m.video] {}", video.body)),
        _ => None,
    }
}

fn is_bot_mentioned_in_mentions(mentions: Option<&Mentions>, bot_user_id: &str) -> bool {
    mentions
        .map(|mentions| {
            mentions
                .user_ids
                .iter()
                .any(|uid| uid.as_str().eq_ignore_ascii_case(bot_user_id))
        })
        .unwrap_or(false)
}

fn extract_direct_room_ids(payload: &Value) -> std::collections::HashSet<String> {
    let mut direct_rooms = std::collections::HashSet::new();
    let Some(events) = payload
        .pointer("/account_data/events")
        .and_then(|v| v.as_array())
    else {
        return direct_rooms;
    };
    for event in events {
        if event.get("type").and_then(|v| v.as_str()) != Some("m.direct") {
            continue;
        }
        let Some(content) = event.get("content").and_then(|v| v.as_object()) else {
            continue;
        };
        for room_ids in content.values() {
            let Some(room_ids) = room_ids.as_array() else {
                continue;
            };
            for room_id in room_ids {
                if let Some(room_id) = room_id.as_str() {
                    if !room_id.trim().is_empty() {
                        direct_rooms.insert(room_id.to_string());
                    }
                }
            }
        }
    }
    direct_rooms
}

fn room_looks_direct(room_data: &Value, is_marked_direct: bool) -> bool {
    if is_marked_direct {
        return true;
    }
    let joined = room_data
        .pointer("/summary/m.joined_member_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let invited = room_data
        .pointer("/summary/m.invited_member_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    joined > 0 && (joined + invited) <= 2
}

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn extract_matrix_user_ids(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in text.split_whitespace() {
        let trimmed = raw
            .trim_matches(|c: char| {
                matches!(
                    c,
                    ',' | '.'
                        | ';'
                        | ':'
                        | '!'
                        | '?'
                        | ')'
                        | '('
                        | '['
                        | ']'
                        | '{'
                        | '}'
                        | '"'
                        | '\''
                )
            })
            .trim();

        if !trimmed.starts_with('@') || !trimmed.contains(':') {
            continue;
        }

        if trimmed.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '@' | ':' | '.' | '_' | '-' | '=' | '/')
        }) && !out.iter().any(|v| v == trimmed)
        {
            out.push(trimmed.to_string());
        }
    }
    out
}

fn matrix_message_payload_for_text(chunk: &str) -> Value {
    let user_ids = extract_matrix_user_ids(chunk);
    if user_ids.is_empty() {
        return serde_json::json!({
            "msgtype": "m.text",
            "body": chunk,
        });
    }

    let mut formatted = html_escape(chunk);
    for uid in &user_ids {
        let escaped_uid = html_escape(uid);
        let href = format!("https://matrix.to/#/{}", uid);
        let pill = format!("<a href=\"{}\">{}</a>", html_escape(&href), escaped_uid);
        formatted = formatted.replace(&escaped_uid, &pill);
    }

    serde_json::json!({
        "msgtype": "m.text",
        "body": chunk,
        "format": "org.matrix.custom.html",
        "formatted_body": formatted,
        "m.mentions": {
            "user_ids": user_ids,
        }
    })
}

async fn send_matrix_message_payload(
    client: &reqwest::Client,
    homeserver_url: &str,
    access_token: &str,
    room_id: &str,
    payload: &Value,
) -> Result<String, String> {
    let homeserver = homeserver_url.trim_end_matches('/');
    let txn_id = uuid::Uuid::new_v4().to_string();
    let url = format!(
        "{homeserver}/_matrix/client/v3/rooms/{}/send/m.room.message/{txn_id}",
        urlencoding::encode(room_id)
    );

    let response = client
        .put(&url)
        .bearer_auth(access_token.trim())
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .json(payload)
        .send()
        .await
        .map_err(|e| format!("Matrix send request failed: {e}"))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "Matrix send failed: HTTP {status} {}",
            body.chars().take(300).collect::<String>()
        ));
    }

    let json: Value = response
        .json()
        .await
        .map_err(|e| format!("Matrix send response parse failed: {e}"))?;

    Ok(json
        .get("event_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string())
}

async fn send_matrix_text(
    client: &reqwest::Client,
    homeserver_url: &str,
    access_token: &str,
    room_id: &str,
    text: &str,
) -> Result<(), String> {
    for chunk in split_text(text, 3800) {
        let payload = matrix_message_payload_for_text(&chunk);
        let _ =
            send_matrix_message_payload(client, homeserver_url, access_token, room_id, &payload)
                .await?;
    }

    Ok(())
}

fn matrix_mentions_for_text(text: &str) -> Option<Mentions> {
    let user_ids: Vec<OwnedUserId> = extract_matrix_user_ids(text)
        .into_iter()
        .filter_map(|raw| raw.parse::<OwnedUserId>().ok())
        .collect();
    if user_ids.is_empty() {
        None
    } else {
        Some(Mentions::with_user_ids(user_ids))
    }
}

async fn send_matrix_text_with_sdk(
    sdk_client: Option<Arc<MatrixSdkClient>>,
    http_client: &reqwest::Client,
    homeserver_url: &str,
    access_token: &str,
    room_id: &str,
    text: &str,
) -> Result<(), String> {
    if let Some(sdk_client) = sdk_client {
        let parsed_room_id: OwnedRoomId = room_id
            .parse()
            .map_err(|e| format!("Invalid Matrix room id '{room_id}': {e}"))?;
        if let Some(room) = sdk_client.get_room(&parsed_room_id) {
            for chunk in split_text(text, 3800) {
                let mut content = RoomMessageEventContent::text_plain(chunk.clone());
                content.mentions = matrix_mentions_for_text(&chunk);
                room.send(content)
                    .await
                    .map_err(|e| format!("Matrix SDK send failed: {e}"))?;
            }
            return Ok(());
        }
    }

    send_matrix_text(http_client, homeserver_url, access_token, room_id, text).await
}

async fn send_matrix_text_runtime(
    runtime: &MatrixRuntimeContext,
    room_id: &str,
    text: &str,
    prefer_sdk_send: bool,
) -> Result<(), String> {
    let sdk_client = if prefer_sdk_send {
        match runtime.sdk_client.as_ref() {
            Some(slot) => {
                let guard = slot.read().await;
                guard.clone()
            }
            None => None,
        }
    } else {
        None
    };
    let http_client = reqwest::Client::new();
    send_matrix_text_with_sdk(
        sdk_client,
        &http_client,
        &runtime.homeserver_url,
        &runtime.access_token,
        room_id,
        text,
    )
    .await
}

fn guess_mime_from_extension(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|v| v.to_str())
        .map(|v| v.to_ascii_lowercase())
        .as_deref()
    {
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("svg") => "image/svg+xml",
        Some("pdf") => "application/pdf",
        Some("txt") => "text/plain",
        Some("json") => "application/json",
        Some("md") => "text/markdown",
        Some("zip") => "application/zip",
        Some("mp3") => "audio/mpeg",
        Some("wav") => "audio/wav",
        Some("ogg") => "audio/ogg",
        Some("mp4") => "video/mp4",
        Some("mov") => "video/quicktime",
        _ => "application/octet-stream",
    }
}

fn matrix_msgtype_for_mime(mime: &str) -> &'static str {
    if mime.starts_with("image/") {
        "m.image"
    } else if mime.starts_with("audio/") {
        "m.audio"
    } else if mime.starts_with("video/") {
        "m.video"
    } else {
        "m.file"
    }
}

async fn send_matrix_attachment(
    client: &reqwest::Client,
    homeserver_url: &str,
    access_token: &str,
    room_id: &str,
    file_path: &Path,
    caption: Option<&str>,
) -> Result<String, String> {
    let bytes = tokio::fs::read(file_path)
        .await
        .map_err(|e| format!("Failed to read attachment file: {e}"))?;
    let file_name = file_path
        .file_name()
        .and_then(|v| v.to_str())
        .unwrap_or("attachment.bin")
        .to_string();

    let mime = guess_mime_from_extension(file_path);
    let homeserver = homeserver_url.trim_end_matches('/');
    let upload_url = format!(
        "{homeserver}/_matrix/media/v3/upload?filename={}",
        urlencoding::encode(&file_name)
    );

    let upload_response = client
        .post(&upload_url)
        .bearer_auth(access_token.trim())
        .header(reqwest::header::CONTENT_TYPE, mime)
        .body(bytes.clone())
        .send()
        .await
        .map_err(|e| format!("Matrix media upload failed: {e}"))?;

    if !upload_response.status().is_success() {
        let status = upload_response.status();
        let body = upload_response.text().await.unwrap_or_default();
        return Err(format!(
            "Matrix media upload failed: HTTP {status} {}",
            body.chars().take(300).collect::<String>()
        ));
    }

    let upload_json: Value = upload_response
        .json()
        .await
        .map_err(|e| format!("Matrix media upload parse failed: {e}"))?;

    let Some(content_uri) = upload_json.get("content_uri").and_then(|v| v.as_str()) else {
        return Err("Matrix media upload missing content_uri".to_string());
    };

    let msgtype = matrix_msgtype_for_mime(mime);
    let mut payload = serde_json::json!({
        "msgtype": msgtype,
        "body": file_name,
        "filename": file_name,
        "url": content_uri,
        "info": {
            "mimetype": mime,
            "size": bytes.len(),
        }
    });

    if let Some(c) = caption.map(str::trim).filter(|v| !v.is_empty()) {
        payload["body"] = Value::String(format!("{} ({})", file_path.display(), c));
    }

    let _ = send_matrix_message_payload(client, homeserver_url, access_token, room_id, &payload)
        .await?;

    if let Some(c) = caption.map(str::trim).filter(|v| !v.is_empty()) {
        send_matrix_text(client, homeserver_url, access_token, room_id, c).await?;
    }

    Ok(match caption {
        Some(c) => format!("[attachment:{}] {}", file_path.display(), c),
        None => format!("[attachment:{}]", file_path.display()),
    })
}

async fn send_matrix_attachment_with_sdk(
    sdk_client: Option<Arc<MatrixSdkClient>>,
    client: &reqwest::Client,
    homeserver_url: &str,
    access_token: &str,
    room_id: &str,
    file_path: &Path,
    caption: Option<&str>,
) -> Result<String, String> {
    if let Some(sdk_client) = sdk_client {
        let parsed_room_id: OwnedRoomId = room_id
            .parse()
            .map_err(|e| format!("Invalid Matrix room id '{room_id}': {e}"))?;
        if let Some(room) = sdk_client.get_room(&parsed_room_id) {
            let data = tokio::fs::read(file_path)
                .await
                .map_err(|e| format!("Failed to read attachment file: {e}"))?;
            let file_name = file_path
                .file_name()
                .and_then(|v| v.to_str())
                .unwrap_or("attachment.bin")
                .to_string();
            let mime_str = guess_mime_from_extension(file_path);
            let mime = mime_str
                .parse()
                .map_err(|e| format!("Invalid MIME type '{mime_str}': {e}"))?;

            room.send_attachment(file_name, &mime, data, AttachmentConfig::new())
                .await
                .map_err(|e| format!("Matrix SDK attachment send failed: {e}"))?;

            if let Some(c) = caption.map(str::trim).filter(|v| !v.is_empty()) {
                send_matrix_text_with_sdk(
                    Some(sdk_client.clone()),
                    client,
                    homeserver_url,
                    access_token,
                    room_id,
                    c,
                )
                .await?;
            }

            return Ok(match caption {
                Some(c) => format!("[attachment:{}] {}", file_path.display(), c),
                None => format!("[attachment:{}]", file_path.display()),
            });
        }
    }

    send_matrix_attachment(
        client,
        homeserver_url,
        access_token,
        room_id,
        file_path,
        caption,
    )
    .await
}

fn looks_like_reaction_token(text: &str) -> Option<String> {
    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed.contains(char::is_whitespace) {
        return None;
    }
    if trimmed.len() > 24 {
        return None;
    }
    if trimmed.chars().all(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    Some(trimmed.to_string())
}

async fn send_matrix_reaction(
    client: &reqwest::Client,
    homeserver_url: &str,
    access_token: &str,
    room_id: &str,
    target_event_id: &str,
    key: &str,
) -> Result<(), String> {
    let homeserver = homeserver_url.trim_end_matches('/');
    let txn_id = uuid::Uuid::new_v4().to_string();
    let url = format!(
        "{homeserver}/_matrix/client/v3/rooms/{}/send/m.reaction/{txn_id}",
        urlencoding::encode(room_id)
    );

    let payload = serde_json::json!({
        "m.relates_to": {
            "rel_type": "m.annotation",
            "event_id": target_event_id,
            "key": key,
        }
    });

    let response = client
        .put(&url)
        .bearer_auth(access_token.trim())
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("Matrix reaction send failed: {e}"))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "Matrix reaction send failed: HTTP {status} {}",
            body.chars().take(300).collect::<String>()
        ));
    }

    Ok(())
}

async fn send_matrix_reaction_runtime(
    runtime: &MatrixRuntimeContext,
    room_id: &str,
    target_event_id: &str,
    key: &str,
    prefer_sdk_send: bool,
) -> Result<(), String> {
    if prefer_sdk_send {
        if let Some(slot) = runtime.sdk_client.as_ref() {
            let sdk_client = {
                let guard = slot.read().await;
                guard.clone()
            };
            if let Some(sdk_client) = sdk_client {
                let parsed_room_id: OwnedRoomId = room_id
                    .parse()
                    .map_err(|e| format!("Invalid Matrix room id '{room_id}': {e}"))?;
                let parsed_event_id: OwnedEventId = target_event_id
                    .parse()
                    .map_err(|e| format!("Invalid Matrix event id '{target_event_id}': {e}"))?;
                if let Some(room) = sdk_client.get_room(&parsed_room_id) {
                    let content = ReactionEventContent::new(Annotation::new(
                        parsed_event_id,
                        key.to_string(),
                    ));
                    room.send(content)
                        .await
                        .map_err(|e| format!("Matrix SDK reaction send failed: {e}"))?;
                    return Ok(());
                }
            }
        }
    }

    send_matrix_reaction(
        &reqwest::Client::new(),
        &runtime.homeserver_url,
        &runtime.access_token,
        room_id,
        target_event_id,
        key,
    )
    .await
}

struct MatrixIncomingMessage {
    room_id: String,
    is_direct: bool,
    sender: String,
    event_id: String,
    body: String,
    mentioned_bot: bool,
    prefer_sdk_send: bool,
    event_time_ms: Option<i64>,
}

struct MatrixIncomingReaction {
    room_id: String,
    is_direct: bool,
    sender: String,
    event_id: String,
    relates_to_event_id: String,
    key: String,
    event_time_ms: Option<i64>,
}

async fn resolve_matrix_chat_id(
    app_state: Arc<AppState>,
    runtime: &MatrixRuntimeContext,
    room_id: &str,
    is_direct: bool,
) -> i64 {
    call_blocking(app_state.db.clone(), {
        let room = room_id.to_string();
        let title = format!("matrix-{}", room_id);
        let chat_type = if is_direct {
            "matrix_dm".to_string()
        } else {
            "matrix".to_string()
        };
        let channel_name = runtime.channel_name.clone();
        move |db| db.resolve_or_create_chat_id(&channel_name, &room, Some(&title), &chat_type)
    })
    .await
    .unwrap_or(0)
}

async fn handle_matrix_reaction(
    app_state: Arc<AppState>,
    runtime: MatrixRuntimeContext,
    reaction: MatrixIncomingReaction,
) {
    let chat_lock = matrix_chat_lock(&runtime.channel_name, &reaction.room_id);
    let _guard = chat_lock.lock().await;

    let chat_id = resolve_matrix_chat_id(
        app_state.clone(),
        &runtime,
        &reaction.room_id,
        reaction.is_direct,
    )
    .await;
    if chat_id == 0 {
        error!(
            "Matrix: failed to resolve chat ID for room {}",
            reaction.room_id
        );
        return;
    }

    let inbound_event_id = if reaction.event_id.trim().is_empty() {
        uuid::Uuid::new_v4().to_string()
    } else {
        reaction.event_id.clone()
    };
    if should_drop_pre_start_message(
        &runtime.channel_name,
        &inbound_event_id,
        reaction.event_time_ms,
    ) {
        return;
    }
    let reaction_text = format!(
        "[reaction] {} reacted {} to {}",
        reaction.sender, reaction.key, reaction.relates_to_event_id
    );
    let incoming = StoredMessage {
        id: inbound_event_id.clone(),
        chat_id,
        sender_name: reaction.sender,
        content: reaction_text,
        is_from_bot: false,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };
    let inserted = call_blocking(app_state.db.clone(), move |db| {
        db.store_message_if_new(&incoming)
    })
    .await
    .unwrap_or(false);
    if !inserted {
        info!(
            "Matrix: skipping duplicate reaction chat_id={} event_id={}",
            chat_id, inbound_event_id
        );
    }
}

async fn handle_matrix_message(
    app_state: Arc<AppState>,
    runtime: MatrixRuntimeContext,
    msg: MatrixIncomingMessage,
) {
    let chat_id =
        resolve_matrix_chat_id(app_state.clone(), &runtime, &msg.room_id, msg.is_direct).await;

    if chat_id == 0 {
        error!("Matrix: failed to resolve chat ID for room {}", msg.room_id);
        return;
    }

    let inbound_event_id = if msg.event_id.trim().is_empty() {
        uuid::Uuid::new_v4().to_string()
    } else {
        msg.event_id.clone()
    };
    if should_drop_pre_start_message(&runtime.channel_name, &inbound_event_id, msg.event_time_ms) {
        return;
    }
    if should_drop_recent_duplicate_message(&runtime.channel_name, &inbound_event_id) {
        return;
    }
    let should_respond = runtime.should_respond(&msg.body, msg.mentioned_bot, msg.is_direct);
    let trimmed = msg.body.trim();
    if is_slash_command(trimmed) {
        if !should_respond && !app_state.config.allow_group_slash_without_mention {
            return;
        }
        if let Some(reply) = handle_chat_command(
            &app_state,
            chat_id,
            &runtime.channel_name,
            trimmed,
            Some(msg.sender.as_str()),
        )
        .await
        {
            let _ =
                send_matrix_text_runtime(&runtime, &msg.room_id, &reply, msg.prefer_sdk_send).await;
        } else {
            let _ = send_matrix_text_runtime(
                &runtime,
                &msg.room_id,
                &unknown_command_response(),
                msg.prefer_sdk_send,
            )
            .await;
        }
        return;
    }

    let chat_lock = matrix_chat_lock(&runtime.channel_name, &msg.room_id);
    let _guard = chat_lock.lock().await;

    let incoming = StoredMessage {
        id: inbound_event_id.clone(),
        chat_id,
        sender_name: msg.sender.clone(),
        content: msg.body.clone(),
        is_from_bot: false,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };
    let inserted = call_blocking(app_state.db.clone(), move |db| {
        db.store_message_if_new(&incoming)
    })
    .await
    .unwrap_or(false);
    if !inserted {
        info!(
            "Matrix: skipping duplicate message chat_id={} event_id={}",
            chat_id, inbound_event_id
        );
        return;
    }
    if !should_respond {
        return;
    }

    info!(
        "Matrix message from {} in {}: {}",
        msg.sender,
        msg.room_id,
        msg.body.chars().take(100).collect::<String>()
    );

    let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel::<AgentEvent>();

    match process_with_agent_with_events(
        &app_state,
        AgentRequestContext {
            caller_channel: &runtime.channel_name,
            chat_id,
            chat_type: if msg.is_direct { "private" } else { "group" },
        },
        None,
        None,
        Some(&event_tx),
    )
    .await
    {
        Ok(response) => {
            drop(event_tx);
            let mut used_send_message_tool = false;
            while let Some(event) = event_rx.recv().await {
                if let AgentEvent::ToolStart { name } = event {
                    if name == "send_message" {
                        used_send_message_tool = true;
                    }
                }
            }

            if used_send_message_tool {
                if !response.is_empty() {
                    info!(
                        "Matrix: suppressing final response for chat {} because send_message already delivered output",
                        chat_id
                    );
                }
            } else if !response.is_empty() {
                if let Some(reaction_key) = looks_like_reaction_token(&response) {
                    if !msg.event_id.trim().is_empty() {
                        if let Err(e) = send_matrix_reaction_runtime(
                            &runtime,
                            &msg.room_id,
                            &msg.event_id,
                            &reaction_key,
                            msg.prefer_sdk_send,
                        )
                        .await
                        {
                            error!("Matrix: failed to send reaction: {e}");
                        } else {
                            let bot_msg = StoredMessage {
                                id: uuid::Uuid::new_v4().to_string(),
                                chat_id,
                                sender_name: runtime.bot_username.clone(),
                                content: format!("[reaction] {}", reaction_key),
                                is_from_bot: true,
                                timestamp: chrono::Utc::now().to_rfc3339(),
                            };
                            let _ = call_blocking(app_state.db.clone(), move |db| {
                                db.store_message(&bot_msg)
                            })
                            .await;
                            return;
                        }
                    }
                }

                if let Err(e) =
                    send_matrix_text_runtime(&runtime, &msg.room_id, &response, msg.prefer_sdk_send)
                        .await
                {
                    error!("Matrix: failed to send response: {e}");
                }

                let bot_msg = StoredMessage {
                    id: uuid::Uuid::new_v4().to_string(),
                    chat_id,
                    sender_name: runtime.bot_username.clone(),
                    content: response,
                    is_from_bot: true,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                };
                let _ =
                    call_blocking(app_state.db.clone(), move |db| db.store_message(&bot_msg)).await;
            } else {
                let fallback =
                    "I couldn't produce a visible reply after an automatic retry. Please try again.";
                let _ =
                    send_matrix_text_runtime(&runtime, &msg.room_id, fallback, msg.prefer_sdk_send)
                        .await;

                let bot_msg = StoredMessage {
                    id: uuid::Uuid::new_v4().to_string(),
                    chat_id,
                    sender_name: runtime.bot_username.clone(),
                    content: fallback.to_string(),
                    is_from_bot: true,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                };
                let _ =
                    call_blocking(app_state.db.clone(), move |db| db.store_message(&bot_msg)).await;
            }
        }
        Err(e) => {
            error!("Error processing Matrix message: {e}");
            if !should_suppress_user_error(&e) {
                let _ = send_matrix_text_runtime(
                    &runtime,
                    &msg.room_id,
                    &format!("Error: {e}"),
                    msg.prefer_sdk_send,
                )
                .await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        extract_matrix_user_ids, is_bot_mentioned_in_mentions, looks_like_reaction_token,
        matrix_backup_key_candidates, matrix_channel_slug, matrix_mentions_for_text,
        matrix_message_payload_for_text, matrix_sdk_clients, normalize_matrix_message_body,
        normalize_matrix_sdk_message_type, MatrixRuntimeContext, Mentions,
    };
    use matrix_sdk::ruma::events::room::message::{
        AudioMessageEventContent, FileMessageEventContent, ImageMessageEventContent, MessageType,
        TextMessageEventContent, VideoMessageEventContent,
    };
    use matrix_sdk::Client as MatrixSdkClient;
    use serde_json::json;
    use std::collections::BTreeSet;
    use std::sync::Arc;

    #[test]
    fn test_extract_matrix_user_ids() {
        let ids = extract_matrix_user_ids("ping @alice:example.org and @bob:matrix.org.");
        assert_eq!(ids, vec!["@alice:example.org", "@bob:matrix.org"]);
    }

    #[test]
    fn test_message_payload_mentions() {
        let payload = matrix_message_payload_for_text("hello @alice:example.org");
        let mentions = payload
            .pointer("/m.mentions/user_ids")
            .and_then(|v| v.as_array())
            .expect("mentions user_ids");
        assert_eq!(mentions.len(), 1);
        assert_eq!(mentions[0].as_str(), Some("@alice:example.org"));
    }

    #[test]
    fn test_reaction_token_detection() {
        assert_eq!(looks_like_reaction_token("👍"), Some("👍".to_string()));
        assert_eq!(looks_like_reaction_token("thanks"), None);
    }

    #[test]
    fn test_normalize_attachment_body() {
        let event = json!({
            "content": {
                "msgtype": "m.image",
                "body": "photo.png",
                "url": "mxc://localhost/abc"
            }
        });
        let body = normalize_matrix_message_body(&event);
        assert!(body.contains("[attachment:m.image]"));
        assert!(body.contains("mxc://localhost/abc"));
    }

    #[test]
    fn test_should_respond_when_mentioned_metadata() {
        let runtime = MatrixRuntimeContext {
            channel_name: "matrix".to_string(),
            access_token: "tok".to_string(),
            homeserver_url: "http://localhost:8008".to_string(),
            bot_user_id: "@bot:localhost".to_string(),
            bot_username: "bot".to_string(),
            allowed_room_ids: Vec::new(),
            allowed_user_ids: Vec::new(),
            mention_required: true,
            sync_timeout_ms: 30_000,
            backup_key: String::new(),
            sdk_client: None,
        };

        assert!(runtime.should_respond("hello there", true, false));
        assert!(!runtime.should_respond("hello there", false, false));
        assert!(runtime.should_respond("hello there", false, true));
    }

    #[test]
    fn test_should_process_dm_sender_allowlist() {
        let runtime = MatrixRuntimeContext {
            channel_name: "matrix".to_string(),
            access_token: "tok".to_string(),
            homeserver_url: "http://localhost:8008".to_string(),
            bot_user_id: "@bot:localhost".to_string(),
            bot_username: "bot".to_string(),
            allowed_room_ids: Vec::new(),
            allowed_user_ids: vec!["@alice:localhost".to_string()],
            mention_required: true,
            sync_timeout_ms: 30_000,
            backup_key: String::new(),
            sdk_client: None,
        };

        assert!(runtime.should_process_dm_sender("@alice:localhost"));
        assert!(!runtime.should_process_dm_sender("@bob:localhost"));
    }

    #[test]
    fn test_group_room_allowlist_does_not_imply_dm_blocklist() {
        let runtime = MatrixRuntimeContext {
            channel_name: "matrix".to_string(),
            access_token: "tok".to_string(),
            homeserver_url: "http://localhost:8008".to_string(),
            bot_user_id: "@bot:localhost".to_string(),
            bot_username: "bot".to_string(),
            allowed_room_ids: vec!["!group:localhost".to_string()],
            allowed_user_ids: Vec::new(),
            mention_required: true,
            sync_timeout_ms: 30_000,
            backup_key: String::new(),
            sdk_client: None,
        };

        assert!(runtime.should_process_group_room("!group:localhost"));
        assert!(!runtime.should_process_group_room("!some-dm:localhost"));
        assert!(runtime.should_process_dm_sender("@alice:localhost"));
    }

    #[test]
    fn test_matrix_mentions_for_text_parses_user_ids() {
        let mentions = matrix_mentions_for_text("hello @alice:example.org and @bob:example.org")
            .expect("mentions");
        let ids: BTreeSet<String> = mentions
            .user_ids
            .iter()
            .map(|v| v.as_str().to_string())
            .collect();
        assert!(ids.contains("@alice:example.org"));
        assert!(ids.contains("@bob:example.org"));
    }

    #[test]
    fn test_matrix_mentions_for_text_ignores_invalid_ids() {
        let mentions = matrix_mentions_for_text("hello @invalid and @alsoinvalid");
        assert!(mentions.is_none());
    }

    #[test]
    fn test_normalize_matrix_sdk_message_type_text_and_attachments() {
        let text = normalize_matrix_sdk_message_type(&MessageType::Text(
            TextMessageEventContent::plain("hello"),
        ));
        assert_eq!(text.as_deref(), Some("hello"));

        let image = normalize_matrix_sdk_message_type(&MessageType::Image(
            ImageMessageEventContent::plain(
                "photo.png".to_string(),
                matrix_sdk::ruma::mxc_uri!("mxc://example.org/abc").into(),
            ),
        ))
        .expect("image");
        assert!(image.contains("[attachment:m.image]"));

        let file =
            normalize_matrix_sdk_message_type(&MessageType::File(FileMessageEventContent::plain(
                "file.bin".to_string(),
                matrix_sdk::ruma::mxc_uri!("mxc://example.org/file").into(),
            )))
            .expect("file");
        assert!(file.contains("[attachment:m.file]"));

        let audio = normalize_matrix_sdk_message_type(&MessageType::Audio(
            AudioMessageEventContent::plain(
                "sound.ogg".to_string(),
                matrix_sdk::ruma::mxc_uri!("mxc://example.org/audio").into(),
            ),
        ))
        .expect("audio");
        assert!(audio.contains("[attachment:m.audio]"));

        let video = normalize_matrix_sdk_message_type(&MessageType::Video(
            VideoMessageEventContent::plain(
                "clip.mp4".to_string(),
                matrix_sdk::ruma::mxc_uri!("mxc://example.org/video").into(),
            ),
        ))
        .expect("video");
        assert!(video.contains("[attachment:m.video]"));
    }

    #[test]
    fn test_is_bot_mentioned_in_mentions() {
        let bot_user_id = "@bot:example.org";
        let mention_user_id = bot_user_id.parse().expect("user id");
        let mentions = Mentions::with_user_ids(vec![mention_user_id]);
        assert!(is_bot_mentioned_in_mentions(Some(&mentions), bot_user_id));
        assert!(!is_bot_mentioned_in_mentions(
            Some(&mentions),
            "@other:example.org"
        ));
        assert!(!is_bot_mentioned_in_mentions(None, bot_user_id));
    }

    #[tokio::test]
    async fn test_matrix_sdk_client_registry_roundtrip() {
        let client = MatrixSdkClient::builder()
            .homeserver_url("http://localhost:8008")
            .build()
            .await
            .expect("sdk client");
        let client = Arc::new(client);

        let key = "test.matrix.registry".to_string();
        {
            let mut clients = matrix_sdk_clients().write().await;
            clients.insert(key.clone(), client.clone());
        }

        let got = matrix_sdk_clients().read().await.get(&key).cloned();
        assert!(got.is_some());

        matrix_sdk_clients().write().await.remove(&key);
    }

    #[test]
    fn test_matrix_channel_slug_sanitizes_name() {
        assert_eq!(matrix_channel_slug("matrix"), "matrix");
        assert_eq!(matrix_channel_slug("matrix.primary"), "matrix_primary");
        assert_eq!(matrix_channel_slug("matrix/tenant#1"), "matrix_tenant_1");
    }

    #[test]
    fn test_matrix_backup_key_candidates_normalize_common_formats() {
        let candidates = matrix_backup_key_candidates("C1E7-44EC-DE73-7A4B");
        assert!(candidates.contains(&"C1E7-44EC-DE73-7A4B".to_string()));
        assert!(candidates.contains(&"C1E7 44EC DE73 7A4B".to_string()));
        assert!(candidates.contains(&"C1E744ECDE737A4B".to_string()));
    }
}
