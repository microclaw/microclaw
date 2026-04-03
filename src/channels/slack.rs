use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tracing::{error, info, warn};

use crate::agent_engine::maybe_rerun_for_pending;
use crate::agent_engine::process_with_agent_with_events_guarded;
use crate::agent_engine::should_suppress_user_error;
use crate::agent_engine::AgentEvent;
use crate::agent_engine::AgentRequestContext;
use crate::chat_turn_queue::PendingMessage;
use crate::channels::startup_guard::{
    mark_channel_started, parse_epoch_ms_from_seconds_fraction, should_drop_pre_start_message,
    should_drop_recent_duplicate_message,
};
use crate::chat_commands::maybe_handle_plugin_command;
use crate::chat_commands::{handle_chat_command, is_slash_command, unknown_command_response};
use crate::runtime::AppState;
use crate::setup_def::{ChannelFieldDef, DynamicChannelDef};
use crate::tools::ToolAuthContext;
use microclaw_channels::channel::ConversationKind;
use microclaw_channels::channel_adapter::ChannelAdapter;
use microclaw_core::text::split_text;
use microclaw_storage::db::call_blocking;
use microclaw_storage::db::StoredMessage;

pub const SETUP_DEF: DynamicChannelDef = DynamicChannelDef {
    name: "slack",
    presence_keys: &["bot_token", "app_token"],
    fields: &[
        ChannelFieldDef {
            yaml_key: "bot_token",
            label: "Slack bot token (OAuth, xoxb-...)",
            default: "",
            secret: true,
            required: true,
        },
        ChannelFieldDef {
            yaml_key: "app_token",
            label: "Slack app token (xapp-...)",
            default: "",
            secret: true,
            required: true,
        },
        ChannelFieldDef {
            yaml_key: "bot_username",
            label: "Slack bot username override (optional)",
            default: "",
            secret: false,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "model",
            label: "Slack bot model override (optional)",
            default: "",
            secret: false,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "capture_unmentioned_images",
            label: "Capture images without mention (true/false)",
            default: "false",
            secret: false,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "inbound_image_max_mb",
            label: "Max inbound image size in MB (optional)",
            default: "20",
            secret: false,
            required: false,
        },
    ],
};

#[derive(Debug, Clone, Deserialize)]
pub struct SlackAccountConfig {
    pub bot_token: String,
    pub app_token: String,
    #[serde(default)]
    pub allowed_channels: Vec<String>,
    #[serde(default)]
    pub bot_username: String,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub capture_unmentioned_images: Option<bool>,
    #[serde(default)]
    pub inbound_image_max_mb: Option<u64>,
    #[serde(default)]
    pub inbound_image_max_bytes: Option<u64>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

fn default_slack_capture_unmentioned_images() -> bool {
    false
}

fn default_slack_inbound_image_max_mb() -> u64 {
    20
}

fn mb_to_bytes(mb: u64) -> u64 {
    mb.saturating_mul(1024 * 1024)
}

fn normalize_slack_inbound_image_max_mb(max_mb: u64) -> u64 {
    if max_mb == 0 {
        return default_slack_inbound_image_max_mb();
    }
    max_mb
}

fn normalize_slack_inbound_image_max_bytes(max_bytes: u64) -> u64 {
    if max_bytes == 0 {
        return mb_to_bytes(default_slack_inbound_image_max_mb());
    }
    max_bytes
}

#[derive(Debug, Clone, Deserialize)]
pub struct SlackChannelConfig {
    #[serde(default)]
    pub bot_token: String,
    #[serde(default)]
    pub app_token: String,
    #[serde(default)]
    pub allowed_channels: Vec<String>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default = "default_slack_capture_unmentioned_images")]
    pub capture_unmentioned_images: bool,
    #[serde(default = "default_slack_inbound_image_max_mb")]
    pub inbound_image_max_mb: u64,
    #[serde(default)]
    pub inbound_image_max_bytes: Option<u64>,
    #[serde(default)]
    pub accounts: HashMap<String, SlackAccountConfig>,
    #[serde(default)]
    pub default_account: Option<String>,
}

fn pick_default_account_id(
    configured: Option<&str>,
    accounts: &HashMap<String, SlackAccountConfig>,
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

pub fn build_slack_runtime_contexts(config: &crate::config::Config) -> Vec<SlackRuntimeContext> {
    let Some(slack_cfg) = config.channel_config::<SlackChannelConfig>("slack") else {
        return Vec::new();
    };

    let default_account =
        pick_default_account_id(slack_cfg.default_account.as_deref(), &slack_cfg.accounts);
    let mut runtimes = Vec::new();
    let mut account_ids: Vec<String> = slack_cfg.accounts.keys().cloned().collect();
    account_ids.sort();
    for account_id in account_ids {
        let Some(account_cfg) = slack_cfg.accounts.get(&account_id) else {
            continue;
        };
        if !account_cfg.enabled
            || account_cfg.bot_token.trim().is_empty()
            || account_cfg.app_token.trim().is_empty()
        {
            continue;
        }
        let is_default = default_account
            .as_deref()
            .map(|v| v == account_id.as_str())
            .unwrap_or(false);
        let channel_name = if is_default {
            "slack".to_string()
        } else {
            format!("slack.{account_id}")
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
        let capture_unmentioned_images = account_cfg
            .capture_unmentioned_images
            .unwrap_or(slack_cfg.capture_unmentioned_images);
        let inbound_image_max_bytes = if let Some(mb) = account_cfg.inbound_image_max_mb {
            mb_to_bytes(normalize_slack_inbound_image_max_mb(mb))
        } else if let Some(bytes) = account_cfg.inbound_image_max_bytes {
            normalize_slack_inbound_image_max_bytes(bytes)
        } else if let Some(bytes) = slack_cfg.inbound_image_max_bytes {
            normalize_slack_inbound_image_max_bytes(bytes)
        } else {
            mb_to_bytes(normalize_slack_inbound_image_max_mb(
                slack_cfg.inbound_image_max_mb,
            ))
        };
        runtimes.push(SlackRuntimeContext {
            channel_name,
            app_token: account_cfg.app_token.clone(),
            bot_token: account_cfg.bot_token.clone(),
            allowed_channels: account_cfg.allowed_channels.clone(),
            bot_username,
            model,
            capture_unmentioned_images,
            inbound_image_max_bytes,
        });
    }

    if runtimes.is_empty()
        && !slack_cfg.bot_token.trim().is_empty()
        && !slack_cfg.app_token.trim().is_empty()
    {
        runtimes.push(SlackRuntimeContext {
            channel_name: "slack".to_string(),
            app_token: slack_cfg.app_token,
            bot_token: slack_cfg.bot_token,
            allowed_channels: slack_cfg.allowed_channels,
            bot_username: config.bot_username_for_channel("slack"),
            model: slack_cfg
                .model
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(ToOwned::to_owned),
            capture_unmentioned_images: slack_cfg.capture_unmentioned_images,
            inbound_image_max_bytes: slack_cfg
                .inbound_image_max_bytes
                .map(normalize_slack_inbound_image_max_bytes)
                .unwrap_or_else(|| {
                    mb_to_bytes(normalize_slack_inbound_image_max_mb(
                        slack_cfg.inbound_image_max_mb,
                    ))
                }),
        });
    }

    runtimes
}

pub struct SlackAdapter {
    name: String,
    bot_token: String,
    http_client: reqwest::Client,
}

async fn maybe_plugin_slash_response(
    config: &crate::config::Config,
    text: &str,
    chat_id: i64,
    channel_name: &str,
) -> Option<String> {
    maybe_handle_plugin_command(config, text, chat_id, channel_name).await
}

static SLACK_ASSISTANT_THREADS: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();

fn slack_assistant_key(channel: &str, user: &str) -> String {
    format!("{channel}:{user}")
}

fn normalize_non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|v| !v.is_empty())
}

fn remember_assistant_thread(channel: &str, user: &str, thread_ts: &str) {
    let Some(thread_ts) = normalize_non_empty(Some(thread_ts)) else {
        return;
    };
    let cache = SLACK_ASSISTANT_THREADS.get_or_init(|| Mutex::new(HashMap::new()));
    let Ok(mut guard) = cache.lock() else {
        return;
    };
    guard.insert(slack_assistant_key(channel, user), thread_ts.to_string());
}

fn resolve_assistant_thread(channel: &str, user: &str) -> Option<String> {
    let cache = SLACK_ASSISTANT_THREADS.get_or_init(|| Mutex::new(HashMap::new()));
    let Ok(guard) = cache.lock() else {
        return None;
    };
    guard.get(&slack_assistant_key(channel, user)).cloned()
}

fn normalize_slack_thread_ts(thread_ts: Option<&str>) -> Option<&str> {
    thread_ts.map(str::trim).filter(|v| !v.is_empty())
}

fn extract_slack_thread_ts(event: &serde_json::Value) -> Option<String> {
    [
        event.get("thread_ts").and_then(|v| v.as_str()),
        event
            .pointer("/assistant_thread/thread_ts")
            .and_then(|v| v.as_str()),
        event
            .pointer("/assistant_thread/channel_thread_ts")
            .and_then(|v| v.as_str()),
        event.pointer("/message/thread_ts").and_then(|v| v.as_str()),
    ]
    .into_iter()
    .flatten()
    .find_map(|v| normalize_non_empty(Some(v)).map(ToOwned::to_owned))
}

fn should_handle_assistant_event(event_type: &str) -> bool {
    matches!(
        event_type,
        "assistant_thread_started" | "assistant_thread_context_changed"
    )
}

fn extract_assistant_event_channel_user(event: &serde_json::Value) -> Option<(String, String)> {
    let channel = [
        event.get("channel").and_then(|v| v.as_str()),
        event
            .pointer("/assistant_thread/channel_id")
            .and_then(|v| v.as_str()),
    ]
    .into_iter()
    .flatten()
    .find_map(|v| normalize_non_empty(Some(v)).map(ToOwned::to_owned))?;

    let user = [
        event.get("user").and_then(|v| v.as_str()),
        event
            .pointer("/assistant_thread/user_id")
            .and_then(|v| v.as_str()),
    ]
    .into_iter()
    .flatten()
    .find_map(|v| normalize_non_empty(Some(v)).map(ToOwned::to_owned))?;

    Some((channel, user))
}

fn slack_external_chat_id(channel: &str, thread_ts: Option<&str>) -> String {
    match normalize_slack_thread_ts(thread_ts) {
        Some(thread_ts) => format!("{channel}:{thread_ts}"),
        None => channel.to_string(),
    }
}

fn split_slack_external_chat_id(external_chat_id: &str) -> (&str, Option<&str>) {
    let normalized = external_chat_id.trim();
    if let Some((channel, thread_ts)) = normalized.split_once(':') {
        let channel = channel.trim();
        let thread_ts = thread_ts.trim();
        if !channel.is_empty() && !thread_ts.is_empty() {
            return (channel, Some(thread_ts));
        }
    }
    (normalized, None)
}

fn slack_chat_title(channel: &str, thread_ts: Option<&str>) -> String {
    match normalize_slack_thread_ts(thread_ts) {
        Some(thread_ts) => format!("slack-{channel}-thread-{thread_ts}"),
        None => format!("slack-{channel}"),
    }
}

fn should_skip_slack_message_subtype(subtype: Option<&str>) -> bool {
    match subtype {
        None => false,
        Some("thread_broadcast") | Some("reply_broadcast") => false,
        Some("file_share") => false, // file/image attachments from users
        Some(_) => true,
    }
}

impl SlackAdapter {
    pub fn new(name: String, bot_token: String) -> Self {
        SlackAdapter {
            name,
            bot_token,
            http_client: reqwest::Client::new(),
        }
    }
}

#[async_trait::async_trait]
impl ChannelAdapter for SlackAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn chat_type_routes(&self) -> Vec<(&str, ConversationKind)> {
        vec![
            ("slack", ConversationKind::Group),
            ("slack_dm", ConversationKind::Private),
        ]
    }

    async fn send_text(&self, external_chat_id: &str, text: &str) -> Result<(), String> {
        let (channel, thread_ts) = split_slack_external_chat_id(external_chat_id);
        if channel.is_empty() {
            return Err("Invalid Slack external_chat_id: empty channel".to_string());
        }
        for chunk in split_text(text, 4000) {
            let mut body = serde_json::json!({
                "channel": channel,
                "text": chunk,
            });
            if let Some(ts) = thread_ts {
                body["thread_ts"] = serde_json::Value::String(ts.to_string());
            }
            let resp = self
                .http_client
                .post("https://slack.com/api/chat.postMessage")
                .header(
                    reqwest::header::AUTHORIZATION,
                    format!("Bearer {}", self.bot_token),
                )
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .json(&body)
                .send()
                .await
                .map_err(|e| format!("Failed to send Slack message: {e}"))?;

            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                return Err(format!(
                    "Failed to send Slack message: HTTP {status} {}",
                    body.chars().take(300).collect::<String>()
                ));
            }

            let resp_json: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| format!("Failed to parse Slack response: {e}"))?;
            if resp_json.get("ok").and_then(|v| v.as_bool()) != Some(true) {
                let err = resp_json
                    .get("error")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                return Err(format!("Slack API error: {err}"));
            }
        }
        Ok(())
    }

    async fn send_attachment(
        &self,
        external_chat_id: &str,
        file_path: &Path,
        caption: Option<&str>,
    ) -> Result<String, String> {
        let (channel, thread_ts) = split_slack_external_chat_id(external_chat_id);
        if channel.is_empty() {
            return Err("Invalid Slack external_chat_id: empty channel".to_string());
        }
        let filename = file_path
            .file_name()
            .and_then(|v| v.to_str())
            .unwrap_or("attachment.bin")
            .to_string();
        let bytes = tokio::fs::read(file_path)
            .await
            .map_err(|e| format!("Failed to read attachment file: {e}"))?;

        let mut form = reqwest::multipart::Form::new()
            .text("channels", channel.to_string())
            .text("initial_comment", caption.unwrap_or_default().to_string())
            .part(
                "file",
                reqwest::multipart::Part::bytes(bytes).file_name(filename),
            );
        if let Some(ts) = thread_ts {
            form = form.text("thread_ts", ts.to_string());
        }

        let resp = self
            .http_client
            .post("https://slack.com/api/files.upload")
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {}", self.bot_token),
            )
            .multipart(form)
            .send()
            .await
            .map_err(|e| format!("Failed to upload Slack file: {e}"))?;

        let resp_json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse Slack upload response: {e}"))?;

        if resp_json.get("ok").and_then(|v| v.as_bool()) != Some(true) {
            let err = resp_json
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            return Err(format!("Slack files.upload error: {err}"));
        }

        Ok(match caption {
            Some(c) => format!("[attachment:{}] {}", file_path.display(), c),
            None => format!("[attachment:{}]", file_path.display()),
        })
    }
}

/// Request a WebSocket URL from Slack's apps.connections.open endpoint.
async fn open_socket_mode_connection(app_token: &str) -> Result<String, String> {
    let client = reqwest::Client::new();
    let resp = client
        .post("https://slack.com/api/apps.connections.open")
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {app_token}"),
        )
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .send()
        .await
        .map_err(|e| format!("Failed to call apps.connections.open: {e}"))?;

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse connections.open response: {e}"))?;

    if body.get("ok").and_then(|v| v.as_bool()) != Some(true) {
        let err = body
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        return Err(format!("apps.connections.open failed: {err}"));
    }

    body.get("url")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "apps.connections.open response missing url".to_string())
}

/// Resolve the bot's own Slack user ID via auth.test.
async fn resolve_bot_user_id(bot_token: &str) -> Result<String, String> {
    let client = reqwest::Client::new();
    let resp = client
        .post("https://slack.com/api/auth.test")
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {bot_token}"),
        )
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .send()
        .await
        .map_err(|e| format!("auth.test failed: {e}"))?;

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse auth.test response: {e}"))?;
    info!("Slack auth.test response: {}", body);

    if body.get("ok").and_then(|v| v.as_bool()) != Some(true) {
        let err = body
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        return Err(format!("auth.test failed: {err}"));
    }

    body.get("user_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "auth.test response missing user_id".to_string())
}

/// Send a text response to a Slack channel, splitting at 4000 chars.
/// Download the first image from a Slack `files` array and return it as (base64, media_type).
/// Slack requires the bot token as a Bearer header to access `url_private`.
async fn download_first_slack_image(
    bot_token: &str,
    files: &[serde_json::Value],
    max_bytes: u64,
) -> Option<(String, String)> {
    for file in files {
        let mimetype = file.get("mimetype").and_then(|v| v.as_str()).unwrap_or("");
        if !mimetype.starts_with("image/") {
            continue;
        }
        let url = file
            .get("url_private")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if url.is_empty() {
            continue;
        }
        let client = reqwest::Client::new();
        match client
            .get(url)
            .header("Authorization", format!("Bearer {bot_token}"))
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                if let Some(content_length) = resp.content_length() {
                    if content_length > max_bytes {
                        warn!(
                            "Slack: skipping image download; content-length={} exceeds max_bytes={}",
                            content_length, max_bytes
                        );
                        continue;
                    }
                }
                match resp.bytes().await {
                    Ok(bytes) => {
                        if bytes.len() as u64 > max_bytes {
                            warn!(
                                "Slack: skipping image; size={} exceeds max_bytes={}",
                                bytes.len(),
                                max_bytes
                            );
                            continue;
                        }
                        use base64::Engine;
                        let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
                        let media_type = guess_slack_image_media_type(&bytes, mimetype);
                        return Some((b64, media_type));
                    }
                    Err(e) => {
                        warn!("Slack: failed to read image bytes: {e}");
                    }
                }
            }
            Ok(resp) => {
                warn!("Slack: image download returned HTTP {}", resp.status());
            }
            Err(e) => {
                warn!("Slack: failed to download image: {e}");
            }
        }
    }
    None
}

fn guess_slack_image_media_type(data: &[u8], mimetype: &str) -> String {
    if data.starts_with(&[0x89, 0x50, 0x4E, 0x47]) {
        "image/png".into()
    } else if data.starts_with(&[0xFF, 0xD8]) {
        "image/jpeg".into()
    } else if data.starts_with(b"GIF") {
        "image/gif".into()
    } else if data.starts_with(b"RIFF") && data.len() >= 12 && &data[8..12] == b"WEBP" {
        "image/webp".into()
    } else if !mimetype.is_empty() {
        mimetype.into()
    } else {
        "image/jpeg".into()
    }
}

async fn send_slack_response(
    bot_token: &str,
    channel: &str,
    thread_ts: Option<&str>,
    text: &str,
) -> Result<(), String> {
    let client = reqwest::Client::new();
    const MAX_LEN: usize = 4000;

    let chunks = split_text(text, MAX_LEN);
    for chunk in chunks {
        let mut body = serde_json::json!({
            "channel": channel,
            "text": chunk,
        });
        if let Some(thread_ts) = thread_ts {
            if !thread_ts.trim().is_empty() {
                body["thread_ts"] = serde_json::Value::String(thread_ts.to_string());
            }
        }
        let resp = client
            .post("https://slack.com/api/chat.postMessage")
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {bot_token}"),
            )
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("Failed to send Slack message: {e}"))?;

        let resp_json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse Slack chat.postMessage response: {e}"))?;

        if resp_json.get("ok").and_then(|v| v.as_bool()) != Some(true) {
            let err = resp_json
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            return Err(format!("Slack chat.postMessage error: {err}"));
        }
    }
    Ok(())
}

/// Start the Slack bot using Socket Mode.
#[derive(Clone)]
pub struct SlackRuntimeContext {
    pub channel_name: String,
    pub app_token: String,
    pub bot_token: String,
    pub allowed_channels: Vec<String>,
    pub bot_username: String,
    pub model: Option<String>,
    pub capture_unmentioned_images: bool,
    pub inbound_image_max_bytes: u64,
}

pub async fn start_slack_bot(app_state: Arc<AppState>, runtime: SlackRuntimeContext) {
    mark_channel_started(&runtime.channel_name);
    let app_token = runtime.app_token.clone();
    let bot_token = runtime.bot_token.clone();

    let bot_user_id = match resolve_bot_user_id(&bot_token).await {
        Ok(id) => {
            info!("Slack bot user ID: {id}");
            id
        }
        Err(e) => {
            error!("Failed to resolve Slack bot user ID: {e}");
            return;
        }
    };

    loop {
        if let Err(e) = run_socket_mode(
            app_state.clone(),
            runtime.clone(),
            &app_token,
            &bot_token,
            &bot_user_id,
        )
        .await
        {
            warn!("Slack Socket Mode disconnected: {e}");
        }
        info!("Slack: reconnecting in 5 seconds...");
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

async fn run_socket_mode(
    app_state: Arc<AppState>,
    runtime: SlackRuntimeContext,
    app_token: &str,
    bot_token: &str,
    bot_user_id: &str,
) -> Result<(), String> {
    let ws_url = open_socket_mode_connection(app_token).await?;
    info!("Slack Socket Mode: connecting to WebSocket...");

    crate::tls::ensure_rustls_crypto_provider()
        .map_err(|e| format!("WebSocket TLS init failed: {e}"))?;

    let (ws_stream, _) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .map_err(|e| format!("WebSocket connect failed: {e}"))?;

    info!("Slack Socket Mode: connected");

    let (mut write, mut read) = ws_stream.split();

    while let Some(msg_result) = read.next().await {
        let msg = match msg_result {
            Ok(m) => m,
            Err(e) => {
                return Err(format!("WebSocket read error: {e}"));
            }
        };

        match msg {
            WsMessage::Text(text) => {
                let envelope: serde_json::Value = match serde_json::from_str(&text) {
                    Ok(v) => v,
                    Err(e) => {
                        warn!("Slack: failed to parse envelope: {e}");
                        continue;
                    }
                };

                // Acknowledge the envelope immediately
                if let Some(envelope_id) = envelope.get("envelope_id").and_then(|v| v.as_str()) {
                    let ack = serde_json::json!({ "envelope_id": envelope_id });
                    if let Err(e) = write.send(WsMessage::Text(ack.to_string())).await {
                        warn!("Slack: failed to send ack: {e}");
                    }
                }

                let envelope_type = envelope.get("type").and_then(|v| v.as_str()).unwrap_or("");

                if envelope_type == "events_api" {
                    let event_type = envelope
                        .pointer("/payload/event/type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();

                    if should_handle_assistant_event(&event_type) {
                        let event = &envelope["payload"]["event"];
                        let assistant_thread_ts = extract_slack_thread_ts(event);
                        if let Some((assistant_channel, assistant_user)) =
                            extract_assistant_event_channel_user(event)
                        {
                            if let Some(thread_ts) = assistant_thread_ts {
                                remember_assistant_thread(
                                    &assistant_channel,
                                    &assistant_user,
                                    &thread_ts,
                                );
                            }
                        }
                        continue;
                    }

                    if event_type == "message" || event_type == "app_mention" {
                        let event = &envelope["payload"]["event"];

                        // Skip system/edit variants, but keep user-visible thread broadcasts.
                        let subtype = event.get("subtype").and_then(|v| v.as_str());
                        if should_skip_slack_message_subtype(subtype) {
                            continue;
                        }
                        // Skip messages from ourselves
                        let user = event
                            .get("user")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        if user == bot_user_id || user.is_empty() {
                            continue;
                        }

                        let channel = event
                            .get("channel")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let text_content = event
                            .get("text")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let channel_type = event
                            .get("channel_type")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let is_dm = channel_type == "im";
                        let is_app_mention = event_type == "app_mention";
                        let mut thread_ts = extract_slack_thread_ts(event);
                        let ts = event
                            .get("ts")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();

                        // Extract inbound file attachments (images)
                        let files: Vec<serde_json::Value> = event
                            .get("files")
                            .and_then(|f| f.as_array())
                            .cloned()
                            .unwrap_or_default();

                        info!(
                            "Slack event: channel={} text={:?} files={} subtype={:?} event_type={}",
                            channel,
                            text_content,
                            files.len(),
                            subtype,
                            event_type
                        );

                        if channel.is_empty() || (text_content.is_empty() && files.is_empty()) {
                            continue;
                        }
                        if thread_ts.is_none() && is_dm {
                            thread_ts = resolve_assistant_thread(&channel, &user);
                        } else if let Some(thread_ts) = thread_ts.as_deref() {
                            remember_assistant_thread(&channel, &user, thread_ts);
                        }

                        let state = app_state.clone();
                        let bot_token = bot_token.to_string();
                        let bot_user_id = bot_user_id.to_string();
                        let runtime_ctx = runtime.clone();
                        tokio::spawn(async move {
                            handle_slack_message(
                                state,
                                runtime_ctx,
                                &bot_token,
                                &bot_user_id,
                                &channel,
                                &user,
                                &text_content,
                                is_dm,
                                is_app_mention,
                                thread_ts.as_deref(),
                                &ts,
                                files,
                            )
                            .await;
                        });
                    }
                }
            }
            WsMessage::Close(_) => {
                return Err("WebSocket closed by server".to_string());
            }
            WsMessage::Ping(data) => {
                if let Err(e) = write.send(WsMessage::Pong(data)).await {
                    warn!("Slack: failed to send pong: {e}");
                }
            }
            _ => {}
        }
    }

    Err("WebSocket stream ended".to_string())
}

#[allow(clippy::too_many_arguments)]
async fn handle_slack_message(
    app_state: Arc<AppState>,
    runtime: SlackRuntimeContext,
    bot_token: &str,
    bot_user_id: &str,
    channel: &str,
    user: &str,
    text: &str,
    is_dm: bool,
    is_app_mention: bool,
    thread_ts: Option<&str>,
    ts: &str,
    files: Vec<serde_json::Value>,
) {
    let normalized_thread_ts = normalize_slack_thread_ts(thread_ts);
    let external_chat_id = slack_external_chat_id(channel, normalized_thread_ts);
    let chat_type = if is_dm { "slack_dm" } else { "slack" };
    let title = slack_chat_title(channel, normalized_thread_ts);

    let chat_id = call_blocking(app_state.db.clone(), {
        let external_chat_id = external_chat_id.clone();
        let title = title.clone();
        let chat_type = chat_type.to_string();
        let channel_name = runtime.channel_name.clone();
        move |db| {
            db.resolve_or_create_chat_id(&channel_name, &external_chat_id, Some(&title), &chat_type)
        }
    })
    .await
    .unwrap_or(0);

    if chat_id == 0 {
        error!("Slack: failed to resolve chat ID for channel {channel}");
        return;
    }

    // Check allowed channels filter
    if !runtime.allowed_channels.is_empty()
        && !runtime.allowed_channels.iter().any(|c| c == channel)
    {
        return;
    }

    let inbound_message_id = if ts.is_empty() {
        uuid::Uuid::new_v4().to_string()
    } else {
        ts.to_string()
    };
    if should_drop_pre_start_message(
        &runtime.channel_name,
        &inbound_message_id,
        parse_epoch_ms_from_seconds_fraction(ts),
    ) {
        return;
    }
    if should_drop_recent_duplicate_message(&runtime.channel_name, &inbound_message_id) {
        return;
    }

    let trimmed = text.trim();
    let mention_tag = format!("<@{bot_user_id}>");
    let should_respond = is_dm || is_app_mention || text.contains(&mention_tag);

    let is_slash = is_slash_command(trimmed);

    // In group chats, only addressed messages should enter session history.
    // Otherwise old non-mention chatter leaks into context once a later mention arrives.
    if !should_respond && !is_slash {
        let allow_unmentioned_image_capture =
            runtime.capture_unmentioned_images && !files.is_empty() && !is_dm;
        if !allow_unmentioned_image_capture {
            return;
        }
    }

    if is_slash {
        if !should_respond && !app_state.config.allow_group_slash_without_mention {
            return;
        }
        if let Some(reply) = handle_chat_command(
            &app_state,
            chat_id,
            &runtime.channel_name,
            trimmed,
            Some(user),
        )
        .await
        {
            let _ = send_slack_response(bot_token, channel, normalized_thread_ts, &reply).await;
            return;
        }
        if let Some(plugin_response) =
            maybe_plugin_slash_response(&app_state.config, trimmed, chat_id, &runtime.channel_name)
                .await
        {
            let _ = send_slack_response(bot_token, channel, normalized_thread_ts, &plugin_response)
                .await;
            return;
        }
        let _ = send_slack_response(
            bot_token,
            channel,
            normalized_thread_ts,
            &unknown_command_response(),
        )
        .await;
        return;
    }

    // Download the first image attachment (if any) for vision input.
    // For group messages without mention, this is gated by `capture_unmentioned_images`.
    let should_download_image =
        !files.is_empty() && (should_respond || is_dm || runtime.capture_unmentioned_images);
    let image_data = if should_download_image {
        download_first_slack_image(bot_token, &files, runtime.inbound_image_max_bytes).await
    } else {
        None
    };

    // Store incoming message
    let stored = StoredMessage {
        id: inbound_message_id.clone(),
        chat_id,
        sender_name: user.to_string(),
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
            "Slack: skipping duplicate message chat_id={} message_id={}",
            chat_id, inbound_message_id
        );
        return;
    }

    info!(
        "Slack message from {} in {}: {}",
        user,
        channel,
        text.chars().take(100).collect::<String>()
    );

    if app_state.config.subagents.thread_bound_routing_enabled {
        let focused = match call_blocking(app_state.db.clone(), move |db| {
            db.get_subagent_focus(chat_id)
        })
        .await
        {
            Ok(v) => v,
            Err(e) => {
                warn!(
                    "Slack focused-run lookup failed for chat {}: {}",
                    chat_id, e
                );
                None
            }
        };
        if focused.is_some() {
            let auth = ToolAuthContext {
                caller_channel: runtime.channel_name.clone(),
                caller_chat_id: chat_id,
                control_chat_ids: app_state.config.control_chat_ids.clone(),
                env_files: Vec::new(),
            };
            let routed = app_state
                .tools
                .execute_with_auth(
                    "subagents_send",
                    serde_json::json!({
                        "message": text,
                        "chat_id": chat_id
                    }),
                    &auth,
                )
                .await;
            if !routed.is_error {
                let route_ack = serde_json::from_str::<serde_json::Value>(&routed.content)
                    .ok()
                    .and_then(|v| {
                        v.get("run_id")
                            .and_then(|id| id.as_str())
                            .map(|id| format!("Routed to focused subagent run `{id}`."))
                    })
                    .unwrap_or_else(|| "Routed to focused subagent continuation run.".to_string());
                let _ =
                    send_slack_response(bot_token, channel, normalized_thread_ts, &route_ack).await;
                let bot_msg = StoredMessage {
                    id: uuid::Uuid::new_v4().to_string(),
                    chat_id,
                    sender_name: runtime.bot_username.clone(),
                    content: route_ack,
                    is_from_bot: true,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                };
                let _ =
                    call_blocking(app_state.db.clone(), move |db| db.store_message(&bot_msg)).await;
                return;
            }
            warn!(
                "Slack focused subagent routing failed for chat {}: {}",
                chat_id, routed.content
            );
        }
    }

    let slack_chat_type = if is_dm { "private" } else { "group" };
    let turn_guard = match app_state
        .chat_turn_queue
        .try_start_or_enqueue(
            &runtime.channel_name,
            chat_id,
            PendingMessage {
                sender_name: user.to_string(),
                content: text.to_string(),
                message_id: inbound_message_id.clone(),
                timestamp: chrono::Utc::now().to_rfc3339(),
            },
        )
        .await
    {
        Some(guard) => guard,
        None => {
            info!(
                "Slack: message queued (chat busy): chat_id={}, message_id={}",
                chat_id, inbound_message_id
            );
            return;
        }
    };

    let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel::<AgentEvent>();

    match process_with_agent_with_events_guarded(
        &app_state,
        AgentRequestContext {
            caller_channel: &runtime.channel_name,
            chat_id,
            chat_type: slack_chat_type,
        },
        None,
        image_data,
        Some(&event_tx),
        Some(turn_guard),
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

            if used_send_message_tool {
                if !response.is_empty() {
                    info!(
                        "Slack: suppressing final response for chat {} because send_message already delivered output",
                        chat_id
                    );
                }
            } else if !response.is_empty() {
                if let Err(e) =
                    send_slack_response(bot_token, channel, normalized_thread_ts, &response).await
                {
                    error!("Slack: failed to send response: {e}");
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
                let fallback = "I couldn't produce a visible reply after an automatic retry. Please try again.";
                let _ =
                    send_slack_response(bot_token, channel, normalized_thread_ts, fallback).await;

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
            error!("Error processing Slack message: {e}");
            if !should_suppress_user_error(&e) {
                let _ = send_slack_response(
                    bot_token,
                    channel,
                    normalized_thread_ts,
                    &format!("Error: {e}"),
                )
                .await;
            }
        }
    }

    // If messages were queued during this run, re-dispatch to process them.
    maybe_rerun_for_pending(app_state, &runtime.channel_name, chat_id, slack_chat_type);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_slack_plugin_slash_dispatch_helper() {
        let root = std::env::temp_dir().join(format!("mc_slack_plugin_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("plugin.yaml"),
            r#"
name: slackplug
enabled: true
commands:
  - command: /slackplug
    response: "slack-ok"
"#,
        )
        .unwrap();

        let mut cfg = crate::config::Config::test_defaults();
        cfg.plugins.enabled = true;
        cfg.plugins.dir = Some(root.to_string_lossy().to_string());

        let out = maybe_plugin_slash_response(&cfg, "/slackplug", 1, "slack").await;
        assert_eq!(out.as_deref(), Some("slack-ok"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn test_slack_chat_id_and_title_use_thread_ts() {
        assert_eq!(
            slack_external_chat_id("D123", Some("1740659112.001200")),
            "D123:1740659112.001200"
        );
        assert_eq!(
            slack_chat_title("D123", Some("1740659112.001200")),
            "slack-D123-thread-1740659112.001200"
        );
    }

    #[test]
    fn test_slack_chat_id_and_title_ignore_blank_thread_ts() {
        assert_eq!(slack_external_chat_id("D123", Some("   ")), "D123");
        assert_eq!(slack_chat_title("D123", Some("   ")), "slack-D123");
    }

    #[test]
    fn test_split_slack_external_chat_id() {
        assert_eq!(
            split_slack_external_chat_id("D123:1740659112.001200"),
            ("D123", Some("1740659112.001200"))
        );
        assert_eq!(split_slack_external_chat_id("D123"), ("D123", None));
    }

    #[test]
    fn test_should_skip_slack_message_subtype_allows_thread_broadcast_variants() {
        assert!(!should_skip_slack_message_subtype(None));
        assert!(!should_skip_slack_message_subtype(Some("thread_broadcast")));
        assert!(!should_skip_slack_message_subtype(Some("reply_broadcast")));
    }

    #[test]
    fn test_should_skip_slack_message_subtype_skips_other_variants() {
        assert!(should_skip_slack_message_subtype(Some("message_changed")));
        assert!(should_skip_slack_message_subtype(Some("bot_message")));
    }

    #[test]
    fn test_should_skip_slack_message_subtype_allows_file_share() {
        assert!(!should_skip_slack_message_subtype(Some("file_share")));
    }

    #[test]
    fn test_guess_slack_image_media_type_from_magic_bytes() {
        // PNG magic bytes
        assert_eq!(
            guess_slack_image_media_type(&[0x89, 0x50, 0x4E, 0x47, 0x0D], "image/png"),
            "image/png"
        );
        // JPEG magic bytes
        assert_eq!(
            guess_slack_image_media_type(&[0xFF, 0xD8, 0x00], "image/jpeg"),
            "image/jpeg"
        );
        // Falls back to mimetype for unknown bytes
        assert_eq!(
            guess_slack_image_media_type(&[0x00, 0x01, 0x02], "image/webp"),
            "image/webp"
        );
        // Falls back to jpeg for truly unknown
        assert_eq!(
            guess_slack_image_media_type(&[0x00, 0x01, 0x02], ""),
            "image/jpeg"
        );
    }

    #[test]
    fn test_slack_channel_config_defaults_for_image_capture_settings() {
        let cfg: SlackChannelConfig = serde_yaml::from_str("{}").unwrap();
        assert!(!cfg.capture_unmentioned_images);
        assert_eq!(cfg.inbound_image_max_mb, 20);
    }

    #[test]
    fn test_build_slack_runtime_contexts_account_overrides_image_capture_settings() {
        let mut cfg = crate::config::Config::test_defaults();
        cfg.channels.insert(
            "slack".to_string(),
            serde_yaml::from_str(
                r#"
capture_unmentioned_images: false
inbound_image_max_mb: 1
accounts:
  default:
    bot_token: xoxb-account
    app_token: xapp-account
    capture_unmentioned_images: true
    inbound_image_max_mb: 2
"#,
            )
            .unwrap(),
        );

        let runtimes = build_slack_runtime_contexts(&cfg);
        assert_eq!(runtimes.len(), 1);
        assert!(runtimes[0].capture_unmentioned_images);
        assert_eq!(runtimes[0].inbound_image_max_bytes, 2 * 1024 * 1024);
    }

    #[test]
    fn test_build_slack_runtime_contexts_image_limit_uses_default_when_zero() {
        let mut cfg = crate::config::Config::test_defaults();
        cfg.channels.insert(
            "slack".to_string(),
            serde_yaml::from_str(
                r#"
bot_token: xoxb-top
app_token: xapp-top
capture_unmentioned_images: false
inbound_image_max_mb: 0
"#,
            )
            .unwrap(),
        );

        let runtimes = build_slack_runtime_contexts(&cfg);
        assert_eq!(runtimes.len(), 1);
        assert_eq!(runtimes[0].inbound_image_max_bytes, 20 * 1024 * 1024);
    }

    #[test]
    fn test_extract_slack_thread_ts_prefers_top_level_then_assistant() {
        let event = serde_json::json!({
            "thread_ts": "111.222",
            "assistant_thread": {
                "thread_ts": "333.444",
                "channel_thread_ts": "555.666"
            },
            "message": { "thread_ts": "777.888" }
        });
        assert_eq!(extract_slack_thread_ts(&event).as_deref(), Some("111.222"));
    }

    #[test]
    fn test_extract_slack_thread_ts_uses_assistant_fallbacks() {
        let event = serde_json::json!({
            "assistant_thread": {
                "thread_ts": "333.444"
            }
        });
        assert_eq!(extract_slack_thread_ts(&event).as_deref(), Some("333.444"));
    }

    #[test]
    fn test_extract_assistant_event_channel_user_from_assistant_payload() {
        let event = serde_json::json!({
            "assistant_thread": {
                "channel_id": "D123",
                "user_id": "U456"
            }
        });
        assert_eq!(
            extract_assistant_event_channel_user(&event),
            Some(("D123".to_string(), "U456".to_string()))
        );
    }
}
