use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock};

use axum::http::HeaderMap;
use axum::{Json, Router};
use serde::Deserialize;
use tracing::{error, info};

use crate::agent_engine::process_with_agent_with_events;
use crate::agent_engine::{AgentEvent, AgentRequestContext};
use crate::channels::startup_guard::{
    mark_channel_started, parse_epoch_ms_from_seconds_str, parse_epoch_ms_from_str,
    should_drop_pre_start_message, should_drop_recent_duplicate_message,
};
use crate::chat_commands::{handle_chat_command, is_slash_command, unknown_command_response};
use crate::runtime::AppState;
use crate::setup_def::{ChannelFieldDef, DynamicChannelDef};
use microclaw_channels::channel::ConversationKind;
use microclaw_channels::channel_adapter::ChannelAdapter;
use microclaw_storage::db::{call_blocking, StoredMessage};

const CHANNEL_KEY: &str = "openclaw-weixin";

pub const SETUP_DEF: DynamicChannelDef = DynamicChannelDef {
    name: CHANNEL_KEY,
    presence_keys: &["send_command"],
    fields: &[
        ChannelFieldDef {
            yaml_key: "send_command",
            label: "OpenClaw Weixin send command (env MICROCLAW_WEIXIN_*)",
            default: "",
            secret: false,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "webhook_path",
            label: "OpenClaw Weixin webhook path (default /openclaw-weixin/messages)",
            default: "/openclaw-weixin/messages",
            secret: false,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "webhook_token",
            label: "OpenClaw Weixin webhook token (optional)",
            default: "",
            secret: true,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "allowed_user_ids",
            label: "OpenClaw Weixin allowed user ids csv (optional)",
            default: "",
            secret: false,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "bot_username",
            label: "OpenClaw Weixin bot username override (optional)",
            default: "",
            secret: false,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "model",
            label: "OpenClaw Weixin bot model override (optional)",
            default: "",
            secret: false,
            required: false,
        },
    ],
};

fn default_enabled() -> bool {
    true
}

fn default_webhook_path() -> String {
    "/openclaw-weixin/messages".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct WeixinAccountConfig {
    #[serde(default)]
    pub send_command: String,
    #[serde(default)]
    pub allowed_user_ids: String,
    #[serde(default)]
    pub webhook_token: String,
    #[serde(default)]
    pub bot_username: String,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WeixinChannelConfig {
    #[serde(default)]
    pub send_command: String,
    #[serde(default)]
    pub allowed_user_ids: String,
    #[serde(default = "default_webhook_path")]
    pub webhook_path: String,
    #[serde(default)]
    pub webhook_token: String,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub accounts: HashMap<String, WeixinAccountConfig>,
    #[serde(default)]
    pub default_account: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct WeixinWebhookPayload {
    #[serde(default)]
    account_id: String,
    #[serde(default)]
    from_user_id: String,
    #[serde(default)]
    text: String,
    #[serde(default)]
    message_id: Option<FlexibleId>,
    #[serde(default)]
    timestamp_ms: Option<i64>,
    #[serde(default)]
    timestamp: Option<String>,
    #[serde(default)]
    context_token: String,
    #[serde(default)]
    item_list: Vec<WeixinWebhookMessageItem>,
    #[serde(default)]
    message: Option<WeixinWebhookMessage>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum FlexibleId {
    String(String),
    Integer(i64),
    Unsigned(u64),
}

impl FlexibleId {
    fn as_string(&self) -> String {
        match self {
            Self::String(value) => value.clone(),
            Self::Integer(value) => value.to_string(),
            Self::Unsigned(value) => value.to_string(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
struct WeixinWebhookTextItem {
    #[serde(default)]
    text: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct WeixinWebhookVoiceItem {
    #[serde(default)]
    text: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct WeixinWebhookFileItem {
    #[serde(default)]
    file_name: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct WeixinWebhookMessageItem {
    #[serde(default)]
    r#type: i32,
    #[serde(default)]
    text_item: Option<WeixinWebhookTextItem>,
    #[serde(default)]
    voice_item: Option<WeixinWebhookVoiceItem>,
    #[serde(default)]
    file_item: Option<WeixinWebhookFileItem>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct WeixinWebhookMessage {
    #[serde(default)]
    from_user_id: String,
    #[serde(default)]
    message_id: Option<FlexibleId>,
    #[serde(default)]
    create_time_ms: Option<i64>,
    #[serde(default)]
    context_token: String,
    #[serde(default)]
    item_list: Vec<WeixinWebhookMessageItem>,
}

#[derive(Debug, Clone)]
struct NormalizedWeixinInbound {
    sender: String,
    text: String,
    message_id: String,
    timestamp_ms: Option<i64>,
    timestamp: Option<String>,
    context_token: String,
}

#[derive(Debug, Clone)]
pub struct WeixinRuntimeContext {
    pub channel_name: String,
    pub account_id: String,
    pub send_command: String,
    pub allowed_user_ids: Vec<String>,
    pub webhook_token: String,
    pub bot_username: String,
    pub model: Option<String>,
}

static WEIXIN_CONTEXT_TOKENS: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();

fn context_token_registry() -> &'static Mutex<HashMap<String, String>> {
    WEIXIN_CONTEXT_TOKENS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn context_token_key(channel_name: &str, external_chat_id: &str) -> String {
    format!("{channel_name}:{external_chat_id}")
}

fn cache_context_token(channel_name: &str, external_chat_id: &str, context_token: &str) {
    let token = context_token.trim();
    if token.is_empty() {
        return;
    }
    if let Ok(mut guard) = context_token_registry().lock() {
        guard.insert(
            context_token_key(channel_name, external_chat_id),
            token.to_string(),
        );
    }
}

fn get_context_token(channel_name: &str, external_chat_id: &str) -> Option<String> {
    context_token_registry().lock().ok().and_then(|guard| {
        guard
            .get(&context_token_key(channel_name, external_chat_id))
            .cloned()
    })
}

fn pick_default_account_id(
    configured: Option<&str>,
    accounts: &HashMap<String, WeixinAccountConfig>,
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

fn parse_csv(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn summarize_weixin_item(item: &WeixinWebhookMessageItem) -> Option<String> {
    match item.r#type {
        1 => item
            .text_item
            .as_ref()
            .map(|text| text.text.trim().to_string())
            .filter(|text| !text.is_empty()),
        2 => Some("[image]".to_string()),
        3 => item
            .voice_item
            .as_ref()
            .map(|voice| voice.text.trim().to_string())
            .filter(|text| !text.is_empty())
            .or_else(|| Some("[voice]".to_string())),
        4 => item
            .file_item
            .as_ref()
            .map(|file| file.file_name.trim().to_string())
            .filter(|name| !name.is_empty())
            .map(|name| format!("[file: {name}]"))
            .or_else(|| Some("[file]".to_string())),
        5 => Some("[video]".to_string()),
        _ => None,
    }
}

fn summarize_weixin_items(items: &[WeixinWebhookMessageItem]) -> String {
    items
        .iter()
        .filter_map(summarize_weixin_item)
        .collect::<Vec<_>>()
        .join("\n")
}

fn normalize_weixin_inbound(payload: &WeixinWebhookPayload) -> Option<NormalizedWeixinInbound> {
    let nested = payload.message.as_ref();
    let sender = payload
        .from_user_id
        .trim()
        .to_string()
        .if_empty_then(|| Some(nested?.from_user_id.trim().to_string()))?;
    let text = {
        let direct = payload.text.trim();
        if !direct.is_empty() {
            direct.to_string()
        } else if !payload.item_list.is_empty() {
            summarize_weixin_items(&payload.item_list)
        } else if let Some(message) = nested {
            summarize_weixin_items(&message.item_list)
        } else {
            String::new()
        }
    };
    if text.trim().is_empty() {
        return None;
    }
    let message_id = payload
        .message_id
        .as_ref()
        .map(FlexibleId::as_string)
        .or_else(|| {
            nested.and_then(|message| message.message_id.as_ref().map(FlexibleId::as_string))
        })
        .unwrap_or_default();
    let timestamp_ms = payload
        .timestamp_ms
        .or_else(|| nested.and_then(|message| message.create_time_ms));
    let context_token = if !payload.context_token.trim().is_empty() {
        payload.context_token.trim().to_string()
    } else {
        nested
            .map(|message| message.context_token.trim().to_string())
            .filter(|token| !token.is_empty())
            .unwrap_or_default()
    };
    Some(NormalizedWeixinInbound {
        sender,
        text,
        message_id,
        timestamp_ms,
        timestamp: payload.timestamp.clone(),
        context_token,
    })
}

fn provided_weixin_webhook_token(headers: &HeaderMap) -> String {
    if let Some(token) = headers
        .get("x-openclaw-weixin-webhook-token")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        return token.to_string();
    }
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .unwrap_or("")
        .to_string()
}

trait EmptyStringFallback {
    fn if_empty_then<F>(self, fallback: F) -> Option<String>
    where
        F: FnOnce() -> Option<String>;
}

impl EmptyStringFallback for String {
    fn if_empty_then<F>(self, fallback: F) -> Option<String>
    where
        F: FnOnce() -> Option<String>,
    {
        if self.trim().is_empty() {
            fallback()
        } else {
            Some(self)
        }
    }
}

pub fn build_weixin_runtime_contexts(config: &crate::config::Config) -> Vec<WeixinRuntimeContext> {
    let Some(wx_cfg) = config.channel_config::<WeixinChannelConfig>(CHANNEL_KEY) else {
        return Vec::new();
    };

    let mut runtimes = Vec::new();
    let default_account =
        pick_default_account_id(wx_cfg.default_account.as_deref(), &wx_cfg.accounts);
    let mut account_ids: Vec<String> = wx_cfg.accounts.keys().cloned().collect();
    account_ids.sort();
    for account_id in account_ids {
        let Some(account_cfg) = wx_cfg.accounts.get(&account_id) else {
            continue;
        };
        if !account_cfg.enabled {
            continue;
        }
        let is_default = default_account
            .as_deref()
            .map(|v| v == account_id.as_str())
            .unwrap_or(false);
        let channel_name = if is_default {
            CHANNEL_KEY.to_string()
        } else {
            format!("{CHANNEL_KEY}.{account_id}")
        };
        let send_command = if account_cfg.send_command.trim().is_empty() {
            wx_cfg.send_command.trim().to_string()
        } else {
            account_cfg.send_command.trim().to_string()
        };
        let webhook_token = if account_cfg.webhook_token.trim().is_empty() {
            wx_cfg.webhook_token.trim().to_string()
        } else {
            account_cfg.webhook_token.trim().to_string()
        };
        let bot_username = if account_cfg.bot_username.trim().is_empty() {
            config.bot_username_for_channel(&channel_name)
        } else {
            account_cfg.bot_username.trim().to_string()
        };
        let model = account_cfg
            .model
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(ToOwned::to_owned);
        runtimes.push(WeixinRuntimeContext {
            channel_name,
            account_id,
            send_command,
            allowed_user_ids: parse_csv(&account_cfg.allowed_user_ids),
            webhook_token,
            bot_username,
            model,
        });
    }

    if runtimes.is_empty() {
        runtimes.push(WeixinRuntimeContext {
            channel_name: CHANNEL_KEY.to_string(),
            account_id: String::new(),
            send_command: wx_cfg.send_command.trim().to_string(),
            allowed_user_ids: parse_csv(&wx_cfg.allowed_user_ids),
            webhook_token: wx_cfg.webhook_token.trim().to_string(),
            bot_username: config.bot_username_for_channel(CHANNEL_KEY),
            model: wx_cfg
                .model
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(ToOwned::to_owned),
        });
    }

    runtimes
}

fn select_runtime_context(
    runtimes: &[WeixinRuntimeContext],
    account_id: &str,
) -> Option<WeixinRuntimeContext> {
    let requested = account_id.trim();
    if !requested.is_empty() {
        if let Some(runtime) = runtimes
            .iter()
            .find(|runtime| runtime.account_id == requested || runtime.channel_name == requested)
        {
            return Some(runtime.clone());
        }
        if let Some(runtime) = runtimes
            .iter()
            .find(|runtime| runtime.channel_name == format!("{CHANNEL_KEY}.{requested}"))
        {
            return Some(runtime.clone());
        }
        return None;
    }
    runtimes
        .iter()
        .find(|runtime| runtime.channel_name == CHANNEL_KEY)
        .cloned()
        .or_else(|| runtimes.first().cloned())
}

pub struct WeixinAdapter {
    name: String,
    account_id: String,
    send_command: String,
}

impl WeixinAdapter {
    pub fn new(name: String, account_id: String, send_command: String) -> Self {
        Self {
            name,
            account_id,
            send_command,
        }
    }

    fn run_send_command(
        &self,
        external_chat_id: &str,
        text: &str,
        attachment_path: Option<&Path>,
        caption: Option<&str>,
    ) -> Result<String, String> {
        if self.send_command.trim().is_empty() {
            return Err("openclaw-weixin.send_command is empty".to_string());
        }
        let context_token = get_context_token(&self.name, external_chat_id).ok_or_else(|| {
            format!(
                "openclaw-weixin requires a cached context_token for target '{}'; wait for an inbound message before replying",
                external_chat_id
            )
        })?;
        let action = if attachment_path.is_some() {
            "send_attachment"
        } else {
            "send_text"
        };
        let attachment_path_str = attachment_path
            .and_then(|path| path.to_str())
            .unwrap_or("")
            .to_string();
        let caption = caption.unwrap_or("").to_string();
        let payload = serde_json::json!({
            "action": action,
            "channel_name": self.name,
            "account_id": self.account_id,
            "target": external_chat_id,
            "text": text,
            "context_token": context_token,
            "attachment_path": attachment_path_str,
            "attachment_caption": caption,
        })
        .to_string();

        let output = Command::new("sh")
            .arg("-lc")
            .arg(self.send_command.trim())
            .env("MICROCLAW_WEIXIN_ACTION", action)
            .env("MICROCLAW_WEIXIN_CHANNEL_NAME", &self.name)
            .env("MICROCLAW_WEIXIN_ACCOUNT_ID", &self.account_id)
            .env("MICROCLAW_WEIXIN_TARGET", external_chat_id)
            .env("MICROCLAW_WEIXIN_TEXT", text)
            .env("MICROCLAW_WEIXIN_CONTEXT_TOKEN", &context_token)
            .env("MICROCLAW_WEIXIN_ATTACHMENT_PATH", attachment_path_str)
            .env("MICROCLAW_WEIXIN_ATTACHMENT_CAPTION", caption)
            .env("MICROCLAW_WEIXIN_PAYLOAD", payload)
            .output()
            .map_err(|e| format!("Failed running openclaw-weixin send command: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "openclaw-weixin send command failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }
}

#[async_trait::async_trait]
impl ChannelAdapter for WeixinAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn chat_type_routes(&self) -> Vec<(&str, ConversationKind)> {
        vec![("weixin_dm", ConversationKind::Private)]
    }

    async fn send_text(&self, external_chat_id: &str, text: &str) -> Result<(), String> {
        self.run_send_command(external_chat_id, text, None, None)
            .map(|_| ())
    }

    async fn send_attachment(
        &self,
        external_chat_id: &str,
        file_path: &Path,
        caption: Option<&str>,
    ) -> Result<String, String> {
        self.run_send_command(external_chat_id, "", Some(file_path), caption)
    }
}

pub async fn start_weixin_bot(_app_state: Arc<AppState>, runtime: WeixinRuntimeContext) {
    mark_channel_started(&runtime.channel_name);
    info!(
        "OpenClaw Weixin adapter '{}' is ready",
        runtime.channel_name
    );
}

pub fn register_weixin_webhook(router: Router, app_state: Arc<AppState>) -> Router {
    let Some(cfg) = app_state
        .config
        .channel_config::<WeixinChannelConfig>(CHANNEL_KEY)
    else {
        return router;
    };
    if !app_state.config.channel_enabled(CHANNEL_KEY) {
        return router;
    }
    let path = cfg.webhook_path.trim();
    if path.is_empty() {
        return router;
    }
    let state_for_post = app_state.clone();
    router.route(
        path,
        axum::routing::post(
            move |headers: HeaderMap, Json(payload): Json<WeixinWebhookPayload>| {
                let state = state_for_post.clone();
                async move { weixin_webhook_handler(state, headers, payload).await }
            },
        ),
    )
}

async fn weixin_webhook_handler(
    app_state: Arc<AppState>,
    headers: HeaderMap,
    payload: WeixinWebhookPayload,
) -> impl axum::response::IntoResponse {
    let runtime_contexts = build_weixin_runtime_contexts(&app_state.config);
    let Some(runtime_ctx) = select_runtime_context(&runtime_contexts, &payload.account_id) else {
        return axum::http::StatusCode::NOT_FOUND;
    };
    let provided_token = provided_weixin_webhook_token(&headers);
    if !runtime_ctx.webhook_token.trim().is_empty()
        && runtime_ctx.webhook_token.trim() != provided_token
    {
        return axum::http::StatusCode::FORBIDDEN;
    }

    let Some(normalized) = normalize_weixin_inbound(&payload) else {
        return axum::http::StatusCode::BAD_REQUEST;
    };
    let sender = normalized.sender.trim();
    let text = normalized.text.trim();
    if !runtime_ctx.allowed_user_ids.is_empty()
        && !runtime_ctx.allowed_user_ids.iter().any(|id| id == sender)
    {
        return axum::http::StatusCode::FORBIDDEN;
    }

    cache_context_token(&runtime_ctx.channel_name, sender, &normalized.context_token);

    let external_chat_id = sender.to_string();
    let chat_id = call_blocking(app_state.db.clone(), {
        let channel_name = runtime_ctx.channel_name.clone();
        let title = format!("openclaw-weixin-{external_chat_id}");
        let external_chat_id = external_chat_id.clone();
        move |db| {
            db.resolve_or_create_chat_id(
                &channel_name,
                &external_chat_id,
                Some(&title),
                "weixin_dm",
            )
        }
    })
    .await
    .unwrap_or(0);
    if chat_id == 0 {
        return axum::http::StatusCode::INTERNAL_SERVER_ERROR;
    }

    let inbound_message_id = if normalized.message_id.trim().is_empty() {
        uuid::Uuid::new_v4().to_string()
    } else {
        normalized.message_id.clone()
    };
    let inbound_ts_ms = normalized.timestamp_ms.or_else(|| {
        normalized
            .timestamp
            .as_deref()
            .and_then(parse_epoch_ms_from_str)
            .or_else(|| {
                normalized
                    .timestamp
                    .as_deref()
                    .and_then(parse_epoch_ms_from_seconds_str)
            })
    });
    if should_drop_pre_start_message(
        &runtime_ctx.channel_name,
        &inbound_message_id,
        inbound_ts_ms,
    ) {
        return axum::http::StatusCode::OK;
    }
    if should_drop_recent_duplicate_message(&runtime_ctx.channel_name, &inbound_message_id) {
        return axum::http::StatusCode::OK;
    }

    if is_slash_command(text) {
        if let Some(reply) = handle_chat_command(
            &app_state,
            chat_id,
            &runtime_ctx.channel_name,
            text,
            Some(sender),
        )
        .await
        {
            let adapter = WeixinAdapter::new(
                runtime_ctx.channel_name.clone(),
                runtime_ctx.account_id.clone(),
                runtime_ctx.send_command.clone(),
            );
            let _ = adapter.send_text(sender, &reply).await;
            return axum::http::StatusCode::OK;
        }
        let adapter = WeixinAdapter::new(
            runtime_ctx.channel_name.clone(),
            runtime_ctx.account_id.clone(),
            runtime_ctx.send_command.clone(),
        );
        let _ = adapter.send_text(sender, &unknown_command_response()).await;
        return axum::http::StatusCode::OK;
    }

    let stored = StoredMessage {
        id: inbound_message_id.clone(),
        chat_id,
        sender_name: sender.to_string(),
        content: text.to_string(),
        is_from_bot: false,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };
    let inserted = call_blocking(app_state.db.clone(), move |db| {
        db.store_message_if_new(&stored)
    })
    .await
    .unwrap_or(false);
    if !inserted {
        info!(
            "OpenClaw Weixin: skipping duplicate message chat_id={} message_id={}",
            chat_id, inbound_message_id
        );
        return axum::http::StatusCode::OK;
    }

    let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel::<AgentEvent>();
    match process_with_agent_with_events(
        &app_state,
        AgentRequestContext {
            caller_channel: &runtime_ctx.channel_name,
            chat_id,
            chat_type: "private",
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
                if let AgentEvent::ToolStart { name, .. } = event {
                    if name == "send_message" {
                        used_send_message_tool = true;
                    }
                }
            }
            let adapter = WeixinAdapter::new(
                runtime_ctx.channel_name.clone(),
                runtime_ctx.account_id.clone(),
                runtime_ctx.send_command.clone(),
            );
            if used_send_message_tool {
                if !response.is_empty() {
                    info!(
                        "OpenClaw Weixin: suppressing final response for chat {} because send_message already delivered output",
                        chat_id
                    );
                }
            } else if !response.is_empty() {
                if let Err(e) = adapter.send_text(sender, &response).await {
                    error!("OpenClaw Weixin: failed to send response: {e}");
                }
                let bot_msg = StoredMessage {
                    id: uuid::Uuid::new_v4().to_string(),
                    chat_id,
                    sender_name: runtime_ctx.bot_username.clone(),
                    content: response,
                    is_from_bot: true,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                };
                let _ =
                    call_blocking(app_state.db.clone(), move |db| db.store_message(&bot_msg)).await;
            } else {
                let _ = adapter
                    .send_text(
                        sender,
                        "I couldn't produce a visible reply after an automatic retry. Please try again.",
                    )
                    .await;
            }
        }
        Err(e) => {
            error!("OpenClaw Weixin: error processing message: {e}");
        }
    }

    axum::http::StatusCode::OK
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{
        build_weixin_runtime_contexts, cache_context_token, normalize_weixin_inbound,
        provided_weixin_webhook_token, select_runtime_context, FlexibleId, WeixinAdapter,
        WeixinWebhookMessage, WeixinWebhookMessageItem, WeixinWebhookPayload,
        WeixinWebhookTextItem, WeixinWebhookVoiceItem, CHANNEL_KEY,
    };
    use crate::config::Config;
    use axum::http::{HeaderMap, HeaderValue};
    use microclaw_channels::channel_adapter::ChannelAdapter;

    #[test]
    fn test_build_weixin_runtime_contexts_with_default_account() {
        let mut cfg = Config::test_defaults();
        cfg.bot_username = "assistant".to_string();
        cfg.channels = serde_yaml::from_str(
            r#"
openclaw-weixin:
  enabled: true
  send_command: "root-send"
  default_account: ops
  accounts:
    main:
      enabled: true
      send_command: "main-send"
      allowed_user_ids: "alice,bob"
    ops:
      enabled: true
      send_command: "ops-send"
      bot_username: "ops-bot"
      model: "gpt-4.1"
"#,
        )
        .unwrap();

        let runtimes = build_weixin_runtime_contexts(&cfg);
        assert_eq!(runtimes.len(), 2);

        let default_runtime = runtimes
            .iter()
            .find(|runtime| runtime.channel_name == CHANNEL_KEY)
            .unwrap();
        assert_eq!(default_runtime.account_id, "ops");
        assert_eq!(default_runtime.send_command, "ops-send");
        assert_eq!(default_runtime.bot_username, "ops-bot");
        assert_eq!(default_runtime.model.as_deref(), Some("gpt-4.1"));

        let secondary = runtimes
            .iter()
            .find(|runtime| runtime.channel_name == "openclaw-weixin.main")
            .unwrap();
        assert_eq!(secondary.account_id, "main");
        assert_eq!(secondary.allowed_user_ids, vec!["alice", "bob"]);
    }

    #[test]
    fn test_select_runtime_context_uses_payload_account_id() {
        let mut cfg = Config::test_defaults();
        cfg.channels = serde_yaml::from_str(
            r#"
openclaw-weixin:
  enabled: true
  default_account: main
  accounts:
    main:
      enabled: true
      send_command: "main-send"
    side:
      enabled: true
      send_command: "side-send"
"#,
        )
        .unwrap();
        let runtimes = build_weixin_runtime_contexts(&cfg);
        let selected = select_runtime_context(&runtimes, "side").unwrap();
        assert_eq!(selected.channel_name, "openclaw-weixin.side");
        assert!(select_runtime_context(&runtimes, "missing").is_none());
    }

    #[tokio::test]
    async fn test_weixin_adapter_rejects_missing_context_token() {
        let adapter = WeixinAdapter::new(
            "openclaw-weixin.test-missing".to_string(),
            "acc".to_string(),
            "true".to_string(),
        );
        let err = adapter
            .send_text("user@im.wechat", "hello")
            .await
            .unwrap_err();
        assert!(err.contains("context_token"));
    }

    #[tokio::test]
    async fn test_weixin_adapter_exports_payload_env() {
        let root = std::env::temp_dir().join(format!("mc_weixin_test_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let output_path = root.join("payload.json");
        cache_context_token(
            "openclaw-weixin.test-send",
            "user@im.wechat",
            "ctx-token-123",
        );
        let command = format!(
            "printf '%s' \"$MICROCLAW_WEIXIN_PAYLOAD\" > '{}'",
            output_path.display()
        );
        let adapter = WeixinAdapter::new(
            "openclaw-weixin.test-send".to_string(),
            "acc-1".to_string(),
            command,
        );
        adapter.send_text("user@im.wechat", "hello").await.unwrap();

        let payload = fs::read_to_string(&output_path).unwrap();
        assert!(payload.contains("\"action\":\"send_text\""));
        assert!(payload.contains("\"account_id\":\"acc-1\""));
        assert!(payload.contains("\"target\":\"user@im.wechat\""));
        assert!(payload.contains("\"context_token\":\"ctx-token-123\""));
        assert!(payload.contains("\"text\":\"hello\""));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn test_normalize_weixin_inbound_accepts_nested_upstream_message() {
        let payload = WeixinWebhookPayload {
            account_id: "main".to_string(),
            from_user_id: String::new(),
            text: String::new(),
            message_id: None,
            timestamp_ms: None,
            timestamp: None,
            context_token: String::new(),
            item_list: Vec::new(),
            message: Some(WeixinWebhookMessage {
                from_user_id: "alice@im.wechat".to_string(),
                message_id: Some(FlexibleId::Integer(42)),
                create_time_ms: Some(123_456),
                context_token: "ctx-nested".to_string(),
                item_list: vec![
                    WeixinWebhookMessageItem {
                        r#type: 2,
                        ..Default::default()
                    },
                    WeixinWebhookMessageItem {
                        r#type: 3,
                        voice_item: Some(WeixinWebhookVoiceItem {
                            text: "voice transcript".to_string(),
                        }),
                        ..Default::default()
                    },
                    WeixinWebhookMessageItem {
                        r#type: 1,
                        text_item: Some(WeixinWebhookTextItem {
                            text: "hello".to_string(),
                        }),
                        ..Default::default()
                    },
                ],
            }),
        };

        let normalized = normalize_weixin_inbound(&payload).unwrap();
        assert_eq!(normalized.sender, "alice@im.wechat");
        assert_eq!(normalized.message_id, "42");
        assert_eq!(normalized.timestamp_ms, Some(123_456));
        assert_eq!(normalized.context_token, "ctx-nested");
        assert_eq!(normalized.text, "[image]\nvoice transcript\nhello");
    }

    #[test]
    fn test_normalize_weixin_inbound_prefers_explicit_root_fields() {
        let payload = WeixinWebhookPayload {
            account_id: "main".to_string(),
            from_user_id: "root@im.wechat".to_string(),
            text: "root text".to_string(),
            message_id: Some(FlexibleId::String("msg-root".to_string())),
            timestamp_ms: Some(777),
            timestamp: Some("2026-03-22T12:00:00Z".to_string()),
            context_token: "ctx-root".to_string(),
            item_list: Vec::new(),
            message: Some(WeixinWebhookMessage {
                from_user_id: "nested@im.wechat".to_string(),
                message_id: Some(FlexibleId::Unsigned(100)),
                create_time_ms: Some(1000),
                context_token: "ctx-nested".to_string(),
                item_list: vec![WeixinWebhookMessageItem {
                    r#type: 1,
                    text_item: Some(WeixinWebhookTextItem {
                        text: "nested text".to_string(),
                    }),
                    ..Default::default()
                }],
            }),
        };

        let normalized = normalize_weixin_inbound(&payload).unwrap();
        assert_eq!(normalized.sender, "root@im.wechat");
        assert_eq!(normalized.text, "root text");
        assert_eq!(normalized.message_id, "msg-root");
        assert_eq!(normalized.timestamp_ms, Some(777));
        assert_eq!(normalized.context_token, "ctx-root");
    }

    #[test]
    fn test_provided_weixin_webhook_token_accepts_bearer_fallback() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer bridge-token"),
        );
        assert_eq!(provided_weixin_webhook_token(&headers), "bridge-token");

        headers.insert(
            "x-openclaw-weixin-webhook-token",
            HeaderValue::from_static("header-token"),
        );
        assert_eq!(provided_weixin_webhook_token(&headers), "header-token");
    }
}
