use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::sync::RwLock;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tracing::{error, info, warn};

use crate::agent_engine::process_with_agent_with_events;
use crate::agent_engine::should_suppress_user_error;
use crate::agent_engine::AgentEvent;
use crate::agent_engine::AgentRequestContext;
use crate::channels::startup_guard::should_drop_recent_duplicate_message;
use crate::chat_commands::maybe_handle_plugin_command;
use crate::chat_commands::{handle_chat_command, is_slash_command, unknown_command_response};
use crate::runtime::AppState;
use crate::setup_def::{ChannelFieldDef, DynamicChannelDef};
use microclaw_channels::channel::ConversationKind;
use microclaw_channels::channel_adapter::ChannelAdapter;
use microclaw_storage::db::call_blocking;
use microclaw_storage::db::StoredMessage;

type WsSink = Arc<
    tokio::sync::Mutex<
        futures_util::stream::SplitSink<
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
            WsMessage,
        >,
    >,
>;
use microclaw_core::text::split_text;

pub const SETUP_DEF: DynamicChannelDef = DynamicChannelDef {
    name: "feishu",
    presence_keys: &["app_id", "app_secret"],
    fields: &[
        ChannelFieldDef {
            yaml_key: "app_id",
            label: "Feishu app ID",
            default: "",
            secret: false,
            required: true,
        },
        ChannelFieldDef {
            yaml_key: "app_secret",
            label: "Feishu app secret",
            default: "",
            secret: true,
            required: true,
        },
        ChannelFieldDef {
            yaml_key: "domain",
            label: "Feishu domain (feishu/lark/custom)",
            default: "feishu",
            secret: false,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "bot_username",
            label: "Feishu bot username override (optional)",
            default: "",
            secret: false,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "model",
            label: "Feishu bot model override (optional)",
            default: "",
            secret: false,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "topic_mode",
            label: "Feishu topic mode (true/false, optional)",
            default: "false",
            secret: false,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "show_progress",
            label: "Feishu topic progress updates (true/false, optional)",
            default: "false",
            secret: false,
            required: false,
        },
    ],
};

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

fn default_connection_mode() -> String {
    "websocket".into()
}
fn default_domain() -> String {
    "feishu".into()
}
fn default_webhook_path() -> String {
    "/feishu/events".into()
}

#[derive(Debug, Clone, Deserialize)]
pub struct FeishuAccountConfig {
    pub app_id: String,
    pub app_secret: String,
    #[serde(default = "default_connection_mode")]
    pub connection_mode: String,
    #[serde(default = "default_domain")]
    pub domain: String,
    #[serde(default)]
    pub allowed_chats: Vec<String>,
    #[serde(default = "default_webhook_path")]
    pub webhook_path: String,
    #[serde(default)]
    pub verification_token: Option<String>,
    #[serde(default)]
    pub encrypt_key: Option<String>,
    #[serde(default)]
    pub bot_username: String,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub topic_mode: bool,
    #[serde(default)]
    pub show_progress: bool,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
pub struct FeishuChannelConfig {
    #[serde(default)]
    pub app_id: String,
    #[serde(default)]
    pub app_secret: String,
    #[serde(default = "default_connection_mode")]
    pub connection_mode: String,
    #[serde(default = "default_domain")]
    pub domain: String,
    #[serde(default)]
    pub allowed_chats: Vec<String>,
    #[serde(default = "default_webhook_path")]
    pub webhook_path: String,
    #[serde(default)]
    pub verification_token: Option<String>,
    #[serde(default)]
    pub encrypt_key: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub topic_mode: bool,
    #[serde(default)]
    pub show_progress: bool,
    #[serde(default)]
    pub accounts: HashMap<String, FeishuAccountConfig>,
    #[serde(default)]
    pub default_account: Option<String>,
}

fn pick_default_account_id(
    configured: Option<&str>,
    accounts: &HashMap<String, FeishuAccountConfig>,
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

pub fn build_feishu_runtime_contexts(config: &crate::config::Config) -> Vec<FeishuRuntimeContext> {
    let Some(feishu_cfg) = config.channel_config::<FeishuChannelConfig>("feishu") else {
        return Vec::new();
    };

    let default_account =
        pick_default_account_id(feishu_cfg.default_account.as_deref(), &feishu_cfg.accounts);
    let mut runtimes = Vec::new();

    let mut account_ids: Vec<String> = feishu_cfg.accounts.keys().cloned().collect();
    account_ids.sort();
    for account_id in account_ids {
        let Some(account_cfg) = feishu_cfg.accounts.get(&account_id) else {
            continue;
        };
        if !account_cfg.enabled
            || account_cfg.app_id.trim().is_empty()
            || account_cfg.app_secret.trim().is_empty()
        {
            continue;
        }
        let is_default = default_account
            .as_deref()
            .map(|v| v == account_id.as_str())
            .unwrap_or(false);
        let channel_name = if is_default {
            "feishu".to_string()
        } else {
            format!("feishu.{account_id}")
        };
        let account_feishu_cfg = FeishuChannelConfig {
            app_id: account_cfg.app_id.clone(),
            app_secret: account_cfg.app_secret.clone(),
            connection_mode: account_cfg.connection_mode.clone(),
            domain: account_cfg.domain.clone(),
            allowed_chats: account_cfg.allowed_chats.clone(),
            webhook_path: account_cfg.webhook_path.clone(),
            verification_token: account_cfg.verification_token.clone(),
            encrypt_key: account_cfg.encrypt_key.clone(),
            model: account_cfg.model.clone(),
            topic_mode: account_cfg.topic_mode,
            show_progress: account_cfg.show_progress,
            accounts: HashMap::new(),
            default_account: None,
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
        runtimes.push(FeishuRuntimeContext {
            channel_name,
            bot_username,
            model,
            config: account_feishu_cfg,
        });
    }

    if runtimes.is_empty()
        && !feishu_cfg.app_id.trim().is_empty()
        && !feishu_cfg.app_secret.trim().is_empty()
    {
        runtimes.push(FeishuRuntimeContext {
            channel_name: "feishu".to_string(),
            bot_username: config.bot_username_for_channel("feishu"),
            model: feishu_cfg
                .model
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(ToOwned::to_owned),
            config: feishu_cfg,
        });
    }

    runtimes
}

async fn maybe_plugin_slash_response(
    config: &crate::config::Config,
    text: &str,
    chat_id: i64,
    channel_name: &str,
) -> Option<String> {
    maybe_handle_plugin_command(config, text, chat_id, channel_name).await
}

static FEISHU_CHAT_LOCKS: OnceLock<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>> =
    OnceLock::new();
static FEISHU_RUNTIME_START_MS: OnceLock<Mutex<HashMap<String, i64>>> = OnceLock::new();
static FEISHU_RUNTIME_BOT_OPEN_ID: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();

fn runtime_start_registry() -> &'static Mutex<HashMap<String, i64>> {
    FEISHU_RUNTIME_START_MS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn runtime_bot_id_registry() -> &'static Mutex<HashMap<String, String>> {
    FEISHU_RUNTIME_BOT_OPEN_ID.get_or_init(|| Mutex::new(HashMap::new()))
}

fn mark_runtime_started(channel_name: &str) {
    let start_ms = chrono::Utc::now().timestamp_millis();
    if let Ok(mut map) = runtime_start_registry().lock() {
        map.insert(channel_name.to_string(), start_ms);
    }
}

fn runtime_start_ms(channel_name: &str) -> Option<i64> {
    runtime_start_registry()
        .lock()
        .ok()
        .and_then(|map| map.get(channel_name).copied())
}

fn set_runtime_bot_open_id(channel_name: &str, bot_open_id: &str) {
    if bot_open_id.trim().is_empty() {
        return;
    }
    if let Ok(mut map) = runtime_bot_id_registry().lock() {
        map.insert(channel_name.to_string(), bot_open_id.to_string());
    }
}

fn runtime_bot_open_id(channel_name: &str) -> Option<String> {
    runtime_bot_id_registry()
        .lock()
        .ok()
        .and_then(|map| map.get(channel_name).cloned())
}

fn feishu_chat_lock(channel_name: &str, external_chat_id: &str) -> Arc<tokio::sync::Mutex<()>> {
    let key = format!("{channel_name}:{external_chat_id}");
    let cache = FEISHU_CHAT_LOCKS.get_or_init(|| Mutex::new(HashMap::new()));
    let Ok(mut guard) = cache.lock() else {
        return Arc::new(tokio::sync::Mutex::new(()));
    };
    guard
        .entry(key)
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}

// ---------------------------------------------------------------------------
// Domain resolution
// ---------------------------------------------------------------------------

fn resolve_domain(domain: &str) -> String {
    match domain {
        "feishu" => "https://open.feishu.cn".into(),
        "lark" => "https://open.larksuite.com".into(),
        other => other.trim_end_matches('/').to_string(),
    }
}

// ---------------------------------------------------------------------------
// Token management
// ---------------------------------------------------------------------------

struct TokenState {
    token: String,
    expires_at: Instant,
}

pub struct FeishuAdapter {
    name: String,
    app_id: String,
    app_secret: String,
    base_url: String,
    http_client: reqwest::Client,
    token: Arc<RwLock<TokenState>>,
}

impl FeishuAdapter {
    pub fn new(name: String, app_id: String, app_secret: String, domain: String) -> Self {
        let base_url = resolve_domain(&domain);
        FeishuAdapter {
            name,
            app_id,
            app_secret,
            base_url,
            http_client: reqwest::Client::new(),
            token: Arc::new(RwLock::new(TokenState {
                token: String::new(),
                expires_at: Instant::now(),
            })),
        }
    }

    async fn ensure_token(&self) -> Result<String, String> {
        {
            let state = self.token.read().await;
            if !state.token.is_empty() && Instant::now() < state.expires_at {
                return Ok(state.token.clone());
            }
        }

        let url = format!(
            "{}/open-apis/auth/v3/tenant_access_token/internal",
            self.base_url
        );
        let body = serde_json::json!({
            "app_id": self.app_id,
            "app_secret": self.app_secret,
        });
        let resp = self
            .http_client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("Failed to get tenant_access_token: {e}"))?;

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse token response: {e}"))?;

        let code = json.get("code").and_then(|v| v.as_i64()).unwrap_or(-1);
        if code != 0 {
            let msg = json
                .get("msg")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            return Err(format!("tenant_access_token error: code={code} msg={msg}"));
        }

        let token = json
            .get("tenant_access_token")
            .and_then(|v| v.as_str())
            .ok_or("Missing tenant_access_token in response")?
            .to_string();

        let expire_secs = json.get("expire").and_then(|v| v.as_u64()).unwrap_or(7200);
        // Refresh 5 minutes before expiry
        let ttl = Duration::from_secs(expire_secs.saturating_sub(300));

        let mut state = self.token.write().await;
        state.token = token.clone();
        state.expires_at = Instant::now() + ttl;

        Ok(token)
    }
}

#[async_trait::async_trait]
impl ChannelAdapter for FeishuAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn chat_type_routes(&self) -> Vec<(&str, ConversationKind)> {
        vec![
            ("feishu_group", ConversationKind::Group),
            ("feishu_dm", ConversationKind::Private),
        ]
    }

    async fn send_text(&self, external_chat_id: &str, text: &str) -> Result<(), String> {
        let token = self.ensure_token().await?;
        for chunk in split_text(text, 4000) {
            let content = serde_json::json!({ "text": chunk }).to_string();
            let body = serde_json::json!({
                "receive_id": external_chat_id,
                "msg_type": "text",
                "content": content,
            });
            let url = format!(
                "{}/open-apis/im/v1/messages?receive_id_type=chat_id",
                self.base_url
            );
            let resp = self
                .http_client
                .post(&url)
                .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .json(&body)
                .send()
                .await
                .map_err(|e| format!("Failed to send Feishu message: {e}"))?;

            let resp_json: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| format!("Failed to parse Feishu send response: {e}"))?;
            let code = resp_json.get("code").and_then(|v| v.as_i64()).unwrap_or(-1);
            if code != 0 {
                let msg = resp_json
                    .get("msg")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                return Err(format!("Feishu send_message error: code={code} msg={msg}"));
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
        let token = self.ensure_token().await?;
        let filename = file_path
            .file_name()
            .and_then(|v| v.to_str())
            .unwrap_or("attachment.bin")
            .to_string();
        let bytes = tokio::fs::read(file_path)
            .await
            .map_err(|e| format!("Failed to read attachment: {e}"))?;

        let ext = file_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        let is_image = matches!(
            ext.as_str(),
            "png" | "jpg" | "jpeg" | "gif" | "bmp" | "webp"
        );

        if is_image {
            // Upload image
            let form = reqwest::multipart::Form::new()
                .text("image_type", "message")
                .part(
                    "image",
                    reqwest::multipart::Part::bytes(bytes).file_name(filename),
                );
            let upload_url = format!("{}/open-apis/im/v1/images", self.base_url);
            let resp = self
                .http_client
                .post(&upload_url)
                .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
                .multipart(form)
                .send()
                .await
                .map_err(|e| format!("Failed to upload Feishu image: {e}"))?;
            let resp_json: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| format!("Failed to parse Feishu image upload response: {e}"))?;
            let code = resp_json.get("code").and_then(|v| v.as_i64()).unwrap_or(-1);
            if code != 0 {
                let msg = resp_json
                    .get("msg")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                return Err(format!("Feishu image upload error: code={code} msg={msg}"));
            }
            let image_key = resp_json
                .pointer("/data/image_key")
                .and_then(|v| v.as_str())
                .ok_or("Missing image_key in upload response")?;

            // Send image message
            let content = serde_json::json!({ "image_key": image_key }).to_string();
            let body = serde_json::json!({
                "receive_id": external_chat_id,
                "msg_type": "image",
                "content": content,
            });
            let send_url = format!(
                "{}/open-apis/im/v1/messages?receive_id_type=chat_id",
                self.base_url
            );
            let resp = self
                .http_client
                .post(&send_url)
                .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
                .json(&body)
                .send()
                .await
                .map_err(|e| format!("Failed to send Feishu image message: {e}"))?;
            let resp_json: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| format!("Failed to parse Feishu image send response: {e}"))?;
            let code = resp_json.get("code").and_then(|v| v.as_i64()).unwrap_or(-1);
            if code != 0 {
                let msg = resp_json
                    .get("msg")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                return Err(format!(
                    "Feishu send image message error: code={code} msg={msg}"
                ));
            }
        } else {
            // Upload file
            let form = reqwest::multipart::Form::new()
                .text("file_type", "stream")
                .text("file_name", filename.clone())
                .part(
                    "file",
                    reqwest::multipart::Part::bytes(bytes).file_name(filename),
                );
            let upload_url = format!("{}/open-apis/im/v1/files", self.base_url);
            let resp = self
                .http_client
                .post(&upload_url)
                .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
                .multipart(form)
                .send()
                .await
                .map_err(|e| format!("Failed to upload Feishu file: {e}"))?;
            let resp_json: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| format!("Failed to parse Feishu file upload response: {e}"))?;
            let code = resp_json.get("code").and_then(|v| v.as_i64()).unwrap_or(-1);
            if code != 0 {
                let msg = resp_json
                    .get("msg")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                return Err(format!("Feishu file upload error: code={code} msg={msg}"));
            }
            let file_key = resp_json
                .pointer("/data/file_key")
                .and_then(|v| v.as_str())
                .ok_or("Missing file_key in upload response")?;

            // Send file message
            let content = serde_json::json!({ "file_key": file_key }).to_string();
            let body = serde_json::json!({
                "receive_id": external_chat_id,
                "msg_type": "file",
                "content": content,
            });
            let send_url = format!(
                "{}/open-apis/im/v1/messages?receive_id_type=chat_id",
                self.base_url
            );
            let resp = self
                .http_client
                .post(&send_url)
                .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
                .json(&body)
                .send()
                .await
                .map_err(|e| format!("Failed to send Feishu file message: {e}"))?;
            let resp_json: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| format!("Failed to parse Feishu file send response: {e}"))?;
            let code = resp_json.get("code").and_then(|v| v.as_i64()).unwrap_or(-1);
            if code != 0 {
                let msg = resp_json
                    .get("msg")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                return Err(format!(
                    "Feishu send file message error: code={code} msg={msg}"
                ));
            }
        }

        // Send caption as a separate text message if provided
        if let Some(cap) = caption {
            if !cap.is_empty() {
                let _ = self.send_text(external_chat_id, cap).await;
            }
        }

        Ok(match caption {
            Some(c) => format!("[attachment:{}] {}", file_path.display(), c),
            None => format!("[attachment:{}]", file_path.display()),
        })
    }
}

// ---------------------------------------------------------------------------
// Minimal protobuf codec for Feishu WebSocket Frame
// ---------------------------------------------------------------------------
// Frame proto:
//   1: uint64  seq_id
//   2: uint64  log_id
//   3: int32   service
//   4: int32   method       (0=control, 1=data)
//   5: repeated Header headers  { 1: string key, 2: string value }
//   6: string  payload_encoding
//   7: string  payload_type
//   8: bytes   payload
//   9: string  log_id_new

mod pb {
    pub struct Header {
        pub key: String,
        pub value: String,
    }

    pub struct Frame {
        pub seq_id: u64,
        pub log_id: u64,
        pub service: i32,
        pub method: i32,
        pub headers: Vec<Header>,
        pub payload_encoding: String,
        pub payload_type: String,
        pub payload: Vec<u8>,
        pub log_id_new: String,
    }

    impl Frame {
        pub fn header(&self, key: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|h| h.key == key)
                .map(|h| h.value.as_str())
        }
    }

    // --- encoding helpers ---

    fn encode_varint(mut val: u64, buf: &mut Vec<u8>) {
        loop {
            let byte = (val & 0x7F) as u8;
            val >>= 7;
            if val == 0 {
                buf.push(byte);
                break;
            }
            buf.push(byte | 0x80);
        }
    }

    fn encode_tag(field: u32, wire_type: u8, buf: &mut Vec<u8>) {
        encode_varint(((field as u64) << 3) | wire_type as u64, buf);
    }

    fn encode_varint_field(field: u32, val: u64, buf: &mut Vec<u8>) {
        if val != 0 {
            encode_tag(field, 0, buf);
            encode_varint(val, buf);
        }
    }

    fn encode_sint32_field(field: u32, val: i32, buf: &mut Vec<u8>) {
        if val != 0 {
            encode_tag(field, 0, buf);
            encode_varint(val as u32 as u64, buf);
        }
    }

    fn encode_bytes_field(field: u32, data: &[u8], buf: &mut Vec<u8>) {
        if !data.is_empty() {
            encode_tag(field, 2, buf);
            encode_varint(data.len() as u64, buf);
            buf.extend_from_slice(data);
        }
    }

    fn encode_string_field(field: u32, s: &str, buf: &mut Vec<u8>) {
        encode_bytes_field(field, s.as_bytes(), buf);
    }

    impl Header {
        fn encode(&self, buf: &mut Vec<u8>) {
            let mut inner = Vec::new();
            encode_string_field(1, &self.key, &mut inner);
            encode_string_field(2, &self.value, &mut inner);
            encode_tag(5, 2, buf);
            encode_varint(inner.len() as u64, buf);
            buf.extend_from_slice(&inner);
        }
    }

    impl Frame {
        pub fn encode(&self) -> Vec<u8> {
            let mut buf = Vec::new();
            encode_varint_field(1, self.seq_id, &mut buf);
            encode_varint_field(2, self.log_id, &mut buf);
            encode_sint32_field(3, self.service, &mut buf);
            encode_sint32_field(4, self.method, &mut buf);
            for h in &self.headers {
                h.encode(&mut buf);
            }
            encode_string_field(6, &self.payload_encoding, &mut buf);
            encode_string_field(7, &self.payload_type, &mut buf);
            encode_bytes_field(8, &self.payload, &mut buf);
            encode_string_field(9, &self.log_id_new, &mut buf);
            buf
        }
    }

    // --- decoding helpers ---

    fn decode_varint(data: &[u8], pos: &mut usize) -> Result<u64, String> {
        let mut result: u64 = 0;
        let mut shift = 0u32;
        loop {
            if *pos >= data.len() {
                return Err("unexpected EOF in varint".into());
            }
            let byte = data[*pos];
            *pos += 1;
            result |= ((byte & 0x7F) as u64) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift >= 64 {
                return Err("varint too long".into());
            }
        }
        Ok(result)
    }

    fn decode_bytes<'a>(data: &'a [u8], pos: &mut usize) -> Result<&'a [u8], String> {
        let len = decode_varint(data, pos)? as usize;
        if *pos + len > data.len() {
            return Err("unexpected EOF in length-delimited field".into());
        }
        let slice = &data[*pos..*pos + len];
        *pos += len;
        Ok(slice)
    }

    fn decode_header(data: &[u8]) -> Result<Header, String> {
        let mut pos = 0;
        let mut key = String::new();
        let mut value = String::new();
        while pos < data.len() {
            let tag = decode_varint(data, &mut pos)?;
            let field = (tag >> 3) as u32;
            let wire = (tag & 0x07) as u8;
            match (field, wire) {
                (1, 2) => {
                    let b = decode_bytes(data, &mut pos)?;
                    key = String::from_utf8_lossy(b).into_owned();
                }
                (2, 2) => {
                    let b = decode_bytes(data, &mut pos)?;
                    value = String::from_utf8_lossy(b).into_owned();
                }
                (_, 0) => {
                    decode_varint(data, &mut pos)?;
                }
                (_, 2) => {
                    decode_bytes(data, &mut pos)?;
                }
                _ => {
                    return Err(format!("unexpected wire type {wire} in Header"));
                }
            }
        }
        Ok(Header { key, value })
    }

    impl Frame {
        pub fn decode(data: &[u8]) -> Result<Frame, String> {
            let mut pos = 0;
            let mut frame = Frame {
                seq_id: 0,
                log_id: 0,
                service: 0,
                method: 0,
                headers: Vec::new(),
                payload_encoding: String::new(),
                payload_type: String::new(),
                payload: Vec::new(),
                log_id_new: String::new(),
            };
            while pos < data.len() {
                let tag = decode_varint(data, &mut pos)?;
                let field = (tag >> 3) as u32;
                let wire = (tag & 0x07) as u8;
                match (field, wire) {
                    (1, 0) => frame.seq_id = decode_varint(data, &mut pos)?,
                    (2, 0) => frame.log_id = decode_varint(data, &mut pos)?,
                    (3, 0) => frame.service = decode_varint(data, &mut pos)? as i32,
                    (4, 0) => frame.method = decode_varint(data, &mut pos)? as i32,
                    (5, 2) => {
                        let b = decode_bytes(data, &mut pos)?;
                        frame.headers.push(decode_header(b)?);
                    }
                    (6, 2) => {
                        let b = decode_bytes(data, &mut pos)?;
                        frame.payload_encoding = String::from_utf8_lossy(b).into_owned();
                    }
                    (7, 2) => {
                        let b = decode_bytes(data, &mut pos)?;
                        frame.payload_type = String::from_utf8_lossy(b).into_owned();
                    }
                    (8, 2) => {
                        let b = decode_bytes(data, &mut pos)?;
                        frame.payload = b.to_vec();
                    }
                    (9, 2) => {
                        let b = decode_bytes(data, &mut pos)?;
                        frame.log_id_new = String::from_utf8_lossy(b).into_owned();
                    }
                    (_, 0) => {
                        decode_varint(data, &mut pos)?;
                    }
                    (_, 2) => {
                        decode_bytes(data, &mut pos)?;
                    }
                    (_, 5) => {
                        // 32-bit fixed
                        if pos + 4 > data.len() {
                            return Err("unexpected EOF in fixed32".into());
                        }
                        pos += 4;
                    }
                    (_, 1) => {
                        // 64-bit fixed
                        if pos + 8 > data.len() {
                            return Err("unexpected EOF in fixed64".into());
                        }
                        pos += 8;
                    }
                    _ => {
                        return Err(format!("unexpected wire type {wire} for field {field}"));
                    }
                }
            }
            Ok(frame)
        }
    }
}

// Frame constants
const FRAME_METHOD_CONTROL: i32 = 0;
const FRAME_METHOD_DATA: i32 = 1;
const MSG_TYPE_EVENT: &str = "event";
const MSG_TYPE_PING: &str = "ping";

// ---------------------------------------------------------------------------
// Standalone helpers
// ---------------------------------------------------------------------------

/// Send a text response to a Feishu chat, splitting at 4000 chars.
///
/// When `topic_mode` is `true`, replies to the original message in a thread.
/// When `false` (default), sends a new message directly to the chat.
async fn send_feishu_response(
    http_client: &reqwest::Client,
    base_url: &str,
    token: &str,
    chat_id: &str,
    text: &str,
    message_id: &str,
    topic_mode: bool,
) -> Result<(), String> {
    for chunk in split_text(text, 4000) {
        let content = serde_json::json!({ "text": chunk }).to_string();

        let (url, body) = if topic_mode {
            let body = serde_json::json!({
                "msg_type": "text",
                "content": content,
                "reply_in_thread": true,
            });
            let url = format!("{base_url}/open-apis/im/v1/messages/{message_id}/reply");
            (url, body)
        } else {
            let body = serde_json::json!({
                "receive_id": chat_id,
                "msg_type": "text",
                "content": content,
            });
            let url = format!("{base_url}/open-apis/im/v1/messages?receive_id_type=chat_id");
            (url, body)
        };

        let resp = http_client
            .post(&url)
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("Failed to send Feishu message: {e}"))?;

        let resp_json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse Feishu send response: {e}"))?;
        let code = resp_json.get("code").and_then(|v| v.as_i64()).unwrap_or(-1);
        if code != 0 {
            let msg = resp_json
                .get("msg")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            return Err(format!("Feishu send error: code={code} msg={msg}"));
        }
    }
    Ok(())
}

async fn reply_feishu_thread(
    http_client: &reqwest::Client,
    base_url: &str,
    token: &str,
    reply_to_message_id: &str,
    text: &str,
) -> Result<String, String> {
    let content = serde_json::json!({ "text": text }).to_string();
    let url = format!("{base_url}/open-apis/im/v1/messages/{reply_to_message_id}/reply");
    let body = serde_json::json!({
        "msg_type": "text",
        "content": content,
        "reply_in_thread": true,
    });

    let resp = http_client
        .post(&url)
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Feishu reply_thread send failed: {e}"))?;

    let resp_json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("Feishu reply_thread parse failed: {e}"))?;
    let code = resp_json.get("code").and_then(|v| v.as_i64()).unwrap_or(-1);
    if code != 0 {
        let msg = resp_json
            .get("msg")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        return Err(format!("Feishu reply_thread error: code={code} msg={msg}"));
    }

    resp_json
        .pointer("/data/message_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .ok_or_else(|| "Feishu reply_thread: missing message_id".into())
}

async fn update_feishu_message(
    http_client: &reqwest::Client,
    base_url: &str,
    token: &str,
    message_id: &str,
    text: &str,
) -> Result<(), String> {
    let url = format!("{base_url}/open-apis/im/v1/messages/{message_id}");
    let content = serde_json::json!({ "text": text }).to_string();
    let body = serde_json::json!({
        "msg_type": "text",
        "content": content,
    });

    let resp = http_client
        .put(&url)
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Feishu update_message failed: {e}"))?;

    let resp_json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("Feishu update_message parse failed: {e}"))?;
    let code = resp_json.get("code").and_then(|v| v.as_i64()).unwrap_or(-1);
    if code != 0 {
        let msg = resp_json
            .get("msg")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        return Err(format!(
            "Feishu update_message error: code={code} msg={msg}"
        ));
    }
    Ok(())
}

fn format_tool_input_summary(name: &str, input: &serde_json::Value) -> String {
    match name {
        "bash" => {
            let cmd = input.get("command").and_then(|v| v.as_str()).unwrap_or("");
            if cmd.is_empty() {
                "bash".into()
            } else if cmd.len() > 200 {
                format!("bash: {}...", &cmd[..200])
            } else {
                format!("bash: {}", cmd)
            }
        }
        "read_file" => {
            let path = input
                .get("file_path")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            format!("read_file: {}", path)
        }
        "write_file" => {
            let path = input
                .get("file_path")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            format!("write_file: {}", path)
        }
        "edit_file" => {
            let path = input
                .get("file_path")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            format!("edit_file: {}", path)
        }
        "glob" => {
            let pattern = input.get("pattern").and_then(|v| v.as_str()).unwrap_or("?");
            format!("glob: {}", pattern)
        }
        "grep" => {
            let pattern = input.get("pattern").and_then(|v| v.as_str()).unwrap_or("?");
            format!("grep: {}", pattern)
        }
        "web_search" => {
            let query = input.get("query").and_then(|v| v.as_str()).unwrap_or("?");
            format!("web_search: {}", query)
        }
        "web_fetch" => {
            let url = input.get("url").and_then(|v| v.as_str()).unwrap_or("?");
            format!("web_fetch: {}", url)
        }
        _ => {
            let compact = serde_json::to_string(input).unwrap_or_default();
            if compact.len() > 200 {
                format!("{}: {}...", name, &compact[..200])
            } else if compact == "{}" || compact == "null" {
                name.to_string()
            } else {
                format!("{}: {}", name, compact)
            }
        }
    }
}

/// Parse Feishu message content JSON. Text messages have `{"text":"..."}`.
fn parse_message_content(content: &str, message_type: &str) -> String {
    match message_type {
        "text" => {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(content) {
                v.get("text")
                    .and_then(|t| t.as_str())
                    .unwrap_or(content)
                    .to_string()
            } else {
                content.to_string()
            }
        }
        "post" => {
            // Rich text: try to extract plain text from the post structure
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(content) {
                // Post content has locale keys (zh_cn, en_us, etc.) with title + content array
                let mut texts = Vec::new();
                if let Some(obj) = v.as_object() {
                    // Use first locale only
                    if let Some((_lang, post)) = obj.iter().next() {
                        if let Some(title) = post.get("title").and_then(|t| t.as_str()) {
                            if !title.is_empty() {
                                texts.push(title.to_string());
                            }
                        }
                        if let Some(content_arr) = post.get("content").and_then(|c| c.as_array()) {
                            for line in content_arr {
                                if let Some(elements) = line.as_array() {
                                    for elem in elements {
                                        if let Some(text) =
                                            elem.get("text").and_then(|t| t.as_str())
                                        {
                                            texts.push(text.to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if texts.is_empty() {
                    content.to_string()
                } else {
                    texts.join("\n")
                }
            } else {
                content.to_string()
            }
        }
        _ => content.to_string(),
    }
}

#[derive(Debug, Clone, Copy)]
struct MentionFlags {
    bot_mentioned: bool,
    at_all: bool,
}

fn parse_feishu_mentions(
    mentions: Option<&Vec<serde_json::Value>>,
    bot_open_id: &str,
) -> MentionFlags {
    let Some(mentions) = mentions else {
        return MentionFlags {
            bot_mentioned: false,
            at_all: false,
        };
    };

    let mut flags = MentionFlags {
        bot_mentioned: false,
        at_all: false,
    };

    for mention in mentions {
        let key = mention.get("key").and_then(|v| v.as_str()).unwrap_or("");
        let open_id = mention
            .pointer("/id/open_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if !bot_open_id.is_empty() && open_id == bot_open_id {
            flags.bot_mentioned = true;
        }
        if key == "@_all" || open_id == "all" {
            flags.at_all = true;
        }
    }

    flags
}

fn text_has_at_all_marker(text: &str, content_raw: &str) -> bool {
    text.contains("@_all")
        || content_raw.contains("@_all")
        || content_raw.contains("user_id\":\"all\"")
        || content_raw.contains("user_id=\\\"all\\\"")
}

/// Download a resource (image or file) from Feishu via GET /open-apis/im/v1/messages/{message_id}/resources/{key}?type={type}
async fn download_feishu_resource(
    http_client: &reqwest::Client,
    base_url: &str,
    token: &str,
    message_id: &str,
    resource_key: &str,
    resource_type: &str,
) -> Result<Vec<u8>, String> {
    let url = format!(
        "{}/open-apis/im/v1/messages/{}/resources/{}?type={}",
        base_url, message_id, resource_key, resource_type
    );
    let resp = http_client
        .get(&url)
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .await
        .map_err(|e| format!("Failed to download Feishu resource: {e}"))?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Feishu resource download HTTP {status}: {body}"));
    }

    resp.bytes()
        .await
        .map(|b| b.to_vec())
        .map_err(|e| format!("Failed to read Feishu resource bytes: {e}"))
}

fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn guess_image_media_type(data: &[u8]) -> String {
    if data.starts_with(&[0x89, 0x50, 0x4E, 0x47]) {
        "image/png".into()
    } else if data.starts_with(&[0xFF, 0xD8]) {
        "image/jpeg".into()
    } else if data.starts_with(b"GIF") {
        "image/gif".into()
    } else if data.starts_with(b"RIFF") && data.len() >= 12 && &data[8..12] == b"WEBP" {
        "image/webp".into()
    } else {
        "image/jpeg".into()
    }
}

/// Resolve the bot's own open_id via GET /open-apis/bot/v3/info.
async fn resolve_bot_open_id(
    http_client: &reqwest::Client,
    base_url: &str,
    token: &str,
) -> Result<String, String> {
    let url = format!("{base_url}/open-apis/bot/v3/info");
    let resp = http_client
        .get(&url)
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .await
        .map_err(|e| format!("Failed to get bot info: {e}"))?;

    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse bot info: {e}"))?;
    let code = json.get("code").and_then(|v| v.as_i64()).unwrap_or(-1);
    if code != 0 {
        let msg = json
            .get("msg")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        return Err(format!("bot/v3/info error: code={code} msg={msg}"));
    }

    json.pointer("/bot/open_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "bot/v3/info: missing bot.open_id".to_string())
}

/// Get the WebSocket endpoint URL from Feishu.
async fn get_ws_endpoint(
    http_client: &reqwest::Client,
    base_url: &str,
    app_id: &str,
    app_secret: &str,
) -> Result<(String, Option<u64>), String> {
    let url = format!("{base_url}/callback/ws/endpoint");
    let body = serde_json::json!({
        "AppID": app_id,
        "AppSecret": app_secret,
    });
    let resp = http_client
        .post(&url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Failed to get WS endpoint: {e}"))?;

    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse WS endpoint response: {e}"))?;

    let code = json.get("code").and_then(|v| v.as_i64()).unwrap_or(-1);
    if code != 0 {
        let msg = json
            .get("msg")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        return Err(format!("WS endpoint error: code={code} msg={msg}"));
    }

    let ws_url = json
        .pointer("/data/URL")
        .or_else(|| json.pointer("/data/url"))
        .and_then(|v| v.as_str())
        .ok_or("WS endpoint response missing URL")?
        .to_string();

    let ping_interval = json
        .pointer("/data/ClientConfig/PingInterval")
        .or_else(|| json.pointer("/data/client_config/ping_interval"))
        .and_then(|v| v.as_u64());

    Ok((ws_url, ping_interval))
}

/// Extract service_id from the WebSocket URL query parameters.
fn extract_service_id(url: &str) -> i32 {
    url.split('?')
        .nth(1)
        .and_then(|qs| {
            qs.split('&')
                .find(|p| p.starts_with("service_id="))
                .and_then(|p| p.strip_prefix("service_id="))
                .and_then(|v| v.parse::<i32>().ok())
        })
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Ensure token helper for standalone functions
// ---------------------------------------------------------------------------

async fn get_token(
    http_client: &reqwest::Client,
    base_url: &str,
    app_id: &str,
    app_secret: &str,
) -> Result<String, String> {
    let url = format!("{base_url}/open-apis/auth/v3/tenant_access_token/internal");
    let body = serde_json::json!({
        "app_id": app_id,
        "app_secret": app_secret,
    });
    let resp = http_client
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Failed to get token: {e}"))?;
    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse token response: {e}"))?;
    let code = json.get("code").and_then(|v| v.as_i64()).unwrap_or(-1);
    if code != 0 {
        let msg = json
            .get("msg")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        return Err(format!("token error: code={code} msg={msg}"));
    }
    json.get("tenant_access_token")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "Missing tenant_access_token".to_string())
}

// ---------------------------------------------------------------------------
// WebSocket mode
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct FeishuRuntimeContext {
    pub channel_name: String,
    pub bot_username: String,
    pub model: Option<String>,
    pub config: FeishuChannelConfig,
}

pub async fn start_feishu_bot(app_state: Arc<AppState>, runtime: FeishuRuntimeContext) {
    let feishu_cfg = runtime.config.clone();
    mark_runtime_started(&runtime.channel_name);

    let base_url = resolve_domain(&feishu_cfg.domain);
    let http_client = reqwest::Client::new();

    // Resolve bot identity
    let token = match get_token(
        &http_client,
        &base_url,
        &feishu_cfg.app_id,
        &feishu_cfg.app_secret,
    )
    .await
    {
        Ok(t) => t,
        Err(e) => {
            error!("Feishu: failed to get initial token: {e}");
            return;
        }
    };

    let bot_open_id = match resolve_bot_open_id(&http_client, &base_url, &token).await {
        Ok(id) => {
            info!("Feishu bot open_id: {id}");
            set_runtime_bot_open_id(&runtime.channel_name, &id);
            id
        }
        Err(e) => {
            error!("Feishu: failed to resolve bot open_id: {e}");
            return;
        }
    };

    if feishu_cfg.connection_mode == "webhook" {
        info!(
            "Feishu: webhook mode — waiting for events on {}",
            feishu_cfg.webhook_path
        );
        // In webhook mode the web server handles events; we just keep running.
        // The webhook route is registered separately via register_feishu_webhook().
        // Park this task forever.
        std::future::pending::<()>().await;
        return;
    }

    // WebSocket mode (default)
    info!("Feishu: starting WebSocket long connection");
    loop {
        if let Err(e) = run_ws_connection(
            app_state.clone(),
            runtime.clone(),
            &feishu_cfg,
            &base_url,
            &http_client,
            &bot_open_id,
        )
        .await
        {
            warn!("Feishu WebSocket disconnected: {e}");
        }
        info!("Feishu: reconnecting in 5 seconds...");
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

async fn run_ws_connection(
    app_state: Arc<AppState>,
    runtime: FeishuRuntimeContext,
    feishu_cfg: &FeishuChannelConfig,
    base_url: &str,
    http_client: &reqwest::Client,
    bot_open_id: &str,
) -> Result<(), String> {
    let (ws_url, ping_interval) = get_ws_endpoint(
        http_client,
        base_url,
        &feishu_cfg.app_id,
        &feishu_cfg.app_secret,
    )
    .await?;

    let service_id = extract_service_id(&ws_url);
    let ping_secs = ping_interval.unwrap_or(120);

    info!("Feishu WS: connecting (service_id={service_id}, ping_interval={ping_secs}s)");

    let (ws_stream, _) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .map_err(|e| format!("WebSocket connect failed: {e}"))?;

    info!("Feishu WS: connected");

    let (write, mut read) = ws_stream.split();
    let write = Arc::new(tokio::sync::Mutex::new(write));

    // Spawn ping loop
    let ping_write = write.clone();
    let ping_handle = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(ping_secs)).await;
            let ping_frame = pb::Frame {
                seq_id: 0,
                log_id: 0,
                service: service_id,
                method: FRAME_METHOD_CONTROL,
                headers: vec![pb::Header {
                    key: "type".into(),
                    value: MSG_TYPE_PING.into(),
                }],
                payload_encoding: String::new(),
                payload_type: String::new(),
                payload: Vec::new(),
                log_id_new: String::new(),
            };
            let data = ping_frame.encode();
            let mut w = ping_write.lock().await;
            if let Err(e) = w.send(WsMessage::Binary(data)).await {
                warn!("Feishu WS: ping send failed: {e}");
                break;
            }
        }
    });

    while let Some(msg_result) = read.next().await {
        let msg = match msg_result {
            Ok(m) => m,
            Err(e) => {
                ping_handle.abort();
                return Err(format!("WebSocket read error: {e}"));
            }
        };

        match msg {
            WsMessage::Binary(data) => {
                let frame = match pb::Frame::decode(&data) {
                    Ok(f) => f,
                    Err(e) => {
                        warn!("Feishu WS: failed to decode frame: {e}");
                        continue;
                    }
                };

                let msg_type = frame.header("type").unwrap_or("").to_string();

                if frame.method == FRAME_METHOD_DATA {
                    // ACK every DATA frame immediately to avoid server retries.
                    send_ack(&write, &frame).await;

                    if msg_type == MSG_TYPE_EVENT {
                        // Parse event payload
                        let payload_str = String::from_utf8_lossy(&frame.payload).to_string();
                        let event: serde_json::Value = match serde_json::from_str(&payload_str) {
                            Ok(v) => v,
                            Err(e) => {
                                warn!("Feishu WS: failed to parse event payload: {e}");
                                continue;
                            }
                        };

                        // Dispatch message handling
                        let state = app_state.clone();
                        let bot_id = bot_open_id.to_string();
                        let cfg = feishu_cfg.clone();
                        let base = base_url.to_string();
                        let runtime_ctx = runtime.clone();
                        let client_clone = http_client.clone();
                        tokio::spawn(async move {
                            handle_feishu_event(
                                state,
                                client_clone,
                                runtime_ctx,
                                &cfg,
                                &base,
                                &bot_id,
                                &event,
                            )
                            .await;
                        });
                    }
                } else if frame.method == FRAME_METHOD_CONTROL {
                    // pong or other control frames — no action needed
                }
            }
            WsMessage::Close(_) => {
                ping_handle.abort();
                return Err("WebSocket closed by server".to_string());
            }
            WsMessage::Ping(data) => {
                let mut w = write.lock().await;
                if let Err(e) = w.send(WsMessage::Pong(data)).await {
                    warn!("Feishu WS: pong send failed: {e}");
                }
            }
            _ => {}
        }
    }

    ping_handle.abort();
    Err("WebSocket stream ended".to_string())
}

async fn send_ack(write: &WsSink, request_frame: &pb::Frame) {
    // Feishu long-connection ACK payload follows HTTP semantics in official SDKs:
    // {"code":200}. Returning {"code":0} can be treated as failed delivery.
    let resp_payload = serde_json::json!({ "code": 200 }).to_string();
    let headers: Vec<pb::Header> = request_frame
        .headers
        .iter()
        .map(|h| pb::Header {
            key: h.key.clone(),
            value: h.value.clone(),
        })
        .collect();
    let ack_frame = pb::Frame {
        seq_id: request_frame.seq_id,
        log_id: request_frame.log_id,
        service: request_frame.service,
        method: request_frame.method,
        headers,
        payload_encoding: request_frame.payload_encoding.clone(),
        payload_type: request_frame.payload_type.clone(),
        payload: resp_payload.into_bytes(),
        log_id_new: request_frame.log_id_new.clone(),
    };
    let data = ack_frame.encode();
    let mut w = write.lock().await;
    if let Err(e) = w.send(WsMessage::Binary(data)).await {
        warn!("Feishu WS: failed to send ACK: {e}");
    }
}

// ---------------------------------------------------------------------------
// Event handling (shared by WS and webhook)
// ---------------------------------------------------------------------------

/// Handle a Feishu event envelope. Dispatches im.message.receive_v1 events.
async fn handle_feishu_event(
    app_state: Arc<AppState>,
    http_client: reqwest::Client,
    runtime: FeishuRuntimeContext,
    feishu_cfg: &FeishuChannelConfig,
    base_url: &str,
    bot_open_id: &str,
    event: &serde_json::Value,
) {
    // The event structure for im.message.receive_v1:
    // {
    //   "schema": "2.0",
    //   "header": { "event_type": "im.message.receive_v1", ... },
    //   "event": {
    //     "sender": { "sender_id": { "open_id": "..." }, "sender_type": "user" },
    //     "message": {
    //       "message_id": "...",
    //       "chat_id": "...",
    //       "chat_type": "p2p" | "group",
    //       "message_type": "text",
    //       "content": "{\"text\":\"hello\"}",
    //       "mentions": [{ "key": "@_user_1", "id": { "open_id": "..." } }]
    //     }
    //   }
    // }

    let event_type = event
        .pointer("/header/event_type")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if event_type != "im.message.receive_v1" {
        return;
    }

    let evt = &event["event"];
    let sender_open_id = evt
        .pointer("/sender/sender_id/open_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let sender_type = evt
        .pointer("/sender/sender_type")
        .and_then(|v| v.as_str())
        .unwrap_or("user");

    // Skip bot's own messages
    if sender_open_id == bot_open_id || sender_type == "bot" {
        return;
    }

    let message = &evt["message"];
    let chat_id_str = message
        .get("chat_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let chat_type_raw = message
        .get("chat_type")
        .and_then(|v| v.as_str())
        .unwrap_or("p2p");
    let message_type = message
        .get("message_type")
        .and_then(|v| v.as_str())
        .unwrap_or("text");
    let content_raw = message
        .get("content")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let message_id = message
        .get("message_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let message_create_time_ms = message.get("create_time").and_then(|v| {
        v.as_str()
            .and_then(|s| s.parse::<i64>().ok())
            .or_else(|| v.as_i64())
    });
    info!(
        "Feishu: received message chat_id={} message_id={} sender_open_id={} type={} content={}",
        chat_id_str, message_id, sender_open_id, message_type, content_raw
    );
    if should_drop_recent_duplicate_message(&runtime.channel_name, message_id) {
        return;
    }

    if let (Some(create_time_ms), Some(start_ms)) = (
        message_create_time_ms,
        runtime_start_ms(&runtime.channel_name),
    ) {
        if create_time_ms < start_ms {
            info!(
                "Feishu: dropping pre-start message channel={} message_id={} create_time_ms={} startup_ms={}",
                runtime.channel_name.as_str(),
                message_id,
                create_time_ms,
                start_ms
            );
            return;
        }
    }

    if chat_id_str.is_empty() || content_raw.is_empty() {
        return;
    }

    let is_dm = chat_type_raw == "p2p";
    let text = parse_message_content(content_raw, message_type);

    if text.trim().is_empty() {
        return;
    }

    // Check allowed_chats filter
    if !feishu_cfg.allowed_chats.is_empty()
        && !feishu_cfg.allowed_chats.iter().any(|c| c == chat_id_str)
    {
        return;
    }

    // Group mentions: direct @bot and @all are treated as mention signals.
    let mention_flags = if !is_dm {
        let mut flags = parse_feishu_mentions(
            message.get("mentions").and_then(|v| v.as_array()),
            bot_open_id,
        );
        if text_has_at_all_marker(&text, content_raw) {
            flags.at_all = true;
        }
        flags
    } else {
        MentionFlags {
            bot_mentioned: false,
            at_all: false,
        }
    };

    handle_feishu_message(
        app_state,
        http_client,
        runtime,
        feishu_cfg,
        base_url,
        bot_open_id,
        chat_id_str,
        sender_open_id,
        &text,
        is_dm,
        mention_flags.bot_mentioned,
        mention_flags.at_all,
        message_id,
        message_type,
        content_raw,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn handle_feishu_message(
    app_state: Arc<AppState>,
    http_client: reqwest::Client,
    runtime: FeishuRuntimeContext,
    feishu_cfg: &FeishuChannelConfig,
    base_url: &str,
    _bot_open_id: &str,
    external_chat_id: &str,
    user: &str,
    text: &str,
    is_dm: bool,
    is_mentioned: bool,
    is_at_all: bool,
    message_id: &str,
    message_type: &str,
    content_raw: &str,
) {
    let chat_type = if is_dm { "feishu_dm" } else { "feishu_group" };
    let title = format!("feishu-{external_chat_id}");

    let chat_id = call_blocking(app_state.db.clone(), {
        let external = external_chat_id.to_string();
        let title = title.clone();
        let chat_type = chat_type.to_string();
        let channel_name = runtime.channel_name.clone();
        move |db| db.resolve_or_create_chat_id(&channel_name, &external, Some(&title), &chat_type)
    })
    .await
    .unwrap_or(0);

    if chat_id == 0 {
        error!("Feishu: failed to resolve chat ID for {external_chat_id}");
        return;
    }

    // Handle slash commands
    let token = match get_token(
        &http_client,
        base_url,
        &feishu_cfg.app_id,
        &feishu_cfg.app_secret,
    )
    .await
    {
        Ok(t) => t,
        Err(e) => {
            error!("Feishu: failed to get token for response: {e}");
            return;
        }
    };

    let mut text = text.to_string();
    let mut image_data: Option<(String, String)> = None;

    match message_type {
        "image" => {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(content_raw) {
                if let Some(image_key) = v.get("image_key").and_then(|k| k.as_str()) {
                    match download_feishu_resource(
                        &http_client,
                        base_url,
                        &token,
                        message_id,
                        image_key,
                        "image",
                    )
                    .await
                    {
                        Ok(bytes) => {
                            let media_type = guess_image_media_type(&bytes);
                            image_data = Some((base64_encode(&bytes), media_type));
                            if text.trim().is_empty() || text.trim().starts_with('{') {
                                text = "[image]".to_string();
                            }
                        }
                        Err(e) => {
                            error!("Feishu: failed to download image {image_key}: {e}");
                        }
                    }
                }
            }
        }
        "file" => {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(content_raw) {
                let file_key = v.get("file_key").and_then(|k| k.as_str()).unwrap_or("");
                let file_name = v
                    .get("file_name")
                    .and_then(|k| k.as_str())
                    .unwrap_or("feishu-file.bin");

                if !file_key.is_empty() {
                    match download_feishu_resource(
                        &http_client,
                        base_url,
                        &token,
                        message_id,
                        file_key,
                        "file",
                    )
                    .await
                    {
                        Ok(bytes) => {
                            let max_bytes = app_state
                                .config
                                .max_document_size_mb
                                .saturating_mul(1024)
                                .saturating_mul(1024);
                            if (bytes.len() as u64) > max_bytes {
                                let _ = send_feishu_response(
                                    &http_client,
                                    base_url,
                                    &token,
                                    external_chat_id,
                                    &format!(
                                        "File is too large ({} bytes). Max allowed is {} MB.",
                                        bytes.len(),
                                        app_state.config.max_document_size_mb
                                    ),
                                    message_id,
                                    feishu_cfg.topic_mode,
                                )
                                .await;
                                return;
                            }

                            let safe_name: String = file_name
                                .chars()
                                .map(|c| match c {
                                    'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '-' | '_' => c,
                                    _ => '_',
                                })
                                .collect();

                            let dir = std::path::Path::new(&app_state.config.working_dir)
                                .join("uploads")
                                .join(runtime.channel_name.replace('/', "_"))
                                .join(external_chat_id);
                            let mut document_saved_path: Option<String> = None;
                            if let Err(e) = std::fs::create_dir_all(&dir) {
                                error!("Failed to create upload dir {}: {e}", dir.display());
                            } else {
                                let ts = chrono::Utc::now().format("%Y%m%d-%H%M%S");
                                let path = dir.join(format!("{}-{}", ts, safe_name));
                                match tokio::fs::write(&path, &bytes).await {
                                    Ok(()) => {
                                        document_saved_path = Some(path.display().to_string());
                                    }
                                    Err(e) => {
                                        error!(
                                            "Failed to save feishu file {}: {e}",
                                            path.display()
                                        );
                                    }
                                }
                            }

                            let file_note = format!(
                                "[document] filename={} bytes={}{}",
                                file_name,
                                bytes.len(),
                                document_saved_path
                                    .as_ref()
                                    .map(|p| format!(" saved_path={}", p))
                                    .unwrap_or_default(),
                            );

                            if text.trim().is_empty() || text.trim().starts_with('{') {
                                text = file_note;
                            } else {
                                text = format!("{}\n\n{}", text.trim(), file_note);
                            }
                        }
                        Err(e) => {
                            error!("Feishu: failed to download file {file_key}: {e}");
                            if text.trim().is_empty() || text.trim().starts_with('{') {
                                text = format!("[document] download failed: {e}");
                            }
                        }
                    }
                }
            }
        }
        "audio" => {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(content_raw) {
                if let Some(file_key) = v.get("file_key").and_then(|k| k.as_str()) {
                    text = format!(
                        "[audio message] file_key={} (audio transcription not yet supported for Feishu)",
                        file_key
                    );
                }
            }
        }
        "media" | "sticker" => {
            if text.trim().is_empty() || text.trim().starts_with('{') {
                text = format!("[{}]", message_type);
            }
        }
        _ => {}
    }

    let inbound_text = if !is_dm && is_at_all {
        format!("[Feishu metadata] This group message included @all.\n{text}")
    } else {
        text.to_string()
    };
    let trimmed = inbound_text.trim();
    let should_respond = is_dm || is_mentioned || is_at_all;
    let topic_mode = feishu_cfg.topic_mode;
    let show_progress = feishu_cfg.show_progress;
    let inbound_message_id = if message_id.is_empty() {
        uuid::Uuid::new_v4().to_string()
    } else {
        message_id.to_string()
    };
    let stored = StoredMessage {
        id: inbound_message_id.clone(),
        chat_id,
        sender_name: user.to_string(),
        content: inbound_text.clone(),
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
            "Feishu: skipping duplicate message chat_id={} message_id={}",
            chat_id, inbound_message_id
        );
        return;
    }

    if is_slash_command(trimmed) {
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
            let _ = send_feishu_response(
                &http_client,
                base_url,
                &token,
                external_chat_id,
                &reply,
                message_id,
                topic_mode,
            )
            .await;
            return;
        }
        if let Some(plugin_response) =
            maybe_plugin_slash_response(&app_state.config, trimmed, chat_id, &runtime.channel_name)
                .await
        {
            let _ = send_feishu_response(
                &http_client,
                base_url,
                &token,
                external_chat_id,
                &plugin_response,
                message_id,
                topic_mode,
            )
            .await;
            return;
        }
        let _ = send_feishu_response(
            &http_client,
            base_url,
            &token,
            external_chat_id,
            &unknown_command_response(),
            message_id,
            topic_mode,
        )
        .await;
        return;
    }

    let chat_lock = feishu_chat_lock(&runtime.channel_name, external_chat_id);
    let _guard = chat_lock.lock().await;

    // Determine if we should respond
    if !should_respond {
        info!(
            "Feishu: skip reply chat_id={} reason=not_addressed is_dm={} is_mentioned={} is_at_all={}",
            chat_id, is_dm, is_mentioned, is_at_all
        );
        return;
    }

    info!(
        "Feishu message from {} in {}: {}",
        user,
        external_chat_id,
        inbound_text.chars().take(100).collect::<String>()
    );

    let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel::<AgentEvent>();

    if topic_mode && show_progress && !message_id.is_empty() {
        let progress_http = http_client.clone();
        let progress_base = base_url.to_string();
        let progress_token = token.clone();
        let progress_reply_to = message_id.to_string();

        struct ProgressState {
            used_send_message_tool: bool,
        }

        let (progress_done_tx, progress_done_rx) = tokio::sync::oneshot::channel::<ProgressState>();

        let progress_handle = tokio::spawn(async move {
            let mut status_msg_id: Option<String> = None;
            let mut lines: Vec<String> = Vec::new();
            let mut dirty = false;
            let mut used_send_message_tool = false;
            // Feishu: max 20 edits per message; reserve 1 for the final status
            const MAX_EDITS: u32 = 19;
            let mut edit_count: u32 = 0;

            let debounce = Duration::from_millis(1500);
            let mut last_flush = Instant::now();

            loop {
                let event = tokio::time::timeout(debounce, event_rx.recv()).await;

                match event {
                    Ok(Some(AgentEvent::ToolStart { name, input })) => {
                        if name == "send_message" {
                            used_send_message_tool = true;
                        }
                        let summary = format_tool_input_summary(&name, &input);
                        lines.push(format!("▶ Executing tool: {}", summary));
                        dirty = true;
                    }
                    Ok(Some(AgentEvent::ToolResult {
                        name,
                        is_error,
                        preview,
                        duration_ms,
                        ..
                    })) => {
                        if is_error {
                            lines.push(format!(
                                "✗ Tool '{}' failed ({}ms): {}",
                                name, duration_ms, preview
                            ));
                        } else {
                            lines.push(format!("✓ {} ({}ms)", name, duration_ms));
                        }
                        dirty = true;
                    }
                    Ok(Some(AgentEvent::Iteration { iteration })) => {
                        if iteration > 1 {
                            lines.push(format!("── iteration {} ──", iteration));
                            dirty = true;
                        }
                    }
                    Ok(Some(_)) => {}
                    Ok(None) => break,
                    Err(_) => {}
                }

                if dirty && last_flush.elapsed() >= debounce {
                    let text = format!("⏳ Processing...\n{}", lines.join("\n"));

                    if let Some(ref mid) = status_msg_id {
                        if edit_count < MAX_EDITS {
                            if let Err(e) = update_feishu_message(
                                &progress_http,
                                &progress_base,
                                &progress_token,
                                mid,
                                &text,
                            )
                            .await
                            {
                                warn!("Feishu: progress update failed: {e}");
                            } else {
                                edit_count += 1;
                            }
                        }
                    } else {
                        match reply_feishu_thread(
                            &progress_http,
                            &progress_base,
                            &progress_token,
                            &progress_reply_to,
                            &text,
                        )
                        .await
                        {
                            Ok(mid) => {
                                status_msg_id = Some(mid);
                                edit_count = 0;
                            }
                            Err(e) => {
                                warn!("Feishu: failed to create status message: {e}");
                            }
                        }
                    }

                    dirty = false;
                    last_flush = Instant::now();
                }
            }

            if let Some(ref mid) = status_msg_id {
                let text = format!("✅ Done\n{}", lines.join("\n"));
                if edit_count < MAX_EDITS {
                    let _ = update_feishu_message(
                        &progress_http,
                        &progress_base,
                        &progress_token,
                        mid,
                        &text,
                    )
                    .await;
                }
            }

            let _ = progress_done_tx.send(ProgressState {
                used_send_message_tool,
            });
        });

        match process_with_agent_with_events(
            &app_state,
            AgentRequestContext {
                caller_channel: &runtime.channel_name,
                chat_id,
                chat_type: if is_dm { "private" } else { "group" },
            },
            None,
            image_data,
            Some(&event_tx),
        )
        .await
        {
            Ok(response) => {
                drop(event_tx);
                let _ = progress_handle.await;
                let used_send_message_tool = progress_done_rx
                    .await
                    .map(|s| s.used_send_message_tool)
                    .unwrap_or(false);

                if used_send_message_tool {
                    if !response.is_empty() {
                        info!(
                            "Feishu: suppressing final response for chat {} because send_message already delivered output",
                            chat_id
                        );
                    } else {
                        info!(
                            "Feishu: no final response for chat {} because send_message tool handled output",
                            chat_id
                        );
                    }
                } else if !response.is_empty() {
                    if let Err(e) = send_feishu_response(
                        &http_client,
                        base_url,
                        &token,
                        external_chat_id,
                        &response,
                        message_id,
                        topic_mode,
                    )
                    .await
                    {
                        error!("Feishu: failed to send response: {e}");
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
                        call_blocking(app_state.db.clone(), move |db| db.store_message(&bot_msg))
                            .await;
                } else {
                    info!(
                        "Feishu: agent returned empty response for chat {}, sending fallback",
                        chat_id
                    );
                    let fallback =
                        "I couldn't produce a visible reply after an automatic retry. Please try again.";
                    let _ = send_feishu_response(
                        &http_client,
                        base_url,
                        &token,
                        external_chat_id,
                        fallback,
                        message_id,
                        topic_mode,
                    )
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
                        call_blocking(app_state.db.clone(), move |db| db.store_message(&bot_msg))
                            .await;
                }
            }
            Err(e) => {
                drop(event_tx);
                let _ = progress_handle.await;
                error!("Error processing Feishu message: {e}");
                if !should_suppress_user_error(&e) {
                    let _ = send_feishu_response(
                        &http_client,
                        base_url,
                        &token,
                        external_chat_id,
                        &format!("Error: {e}"),
                        message_id,
                        topic_mode,
                    )
                    .await;
                }
            }
        }
    } else {
        match process_with_agent_with_events(
            &app_state,
            AgentRequestContext {
                caller_channel: &runtime.channel_name,
                chat_id,
                chat_type: if is_dm { "private" } else { "group" },
            },
            None,
            image_data,
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

                if used_send_message_tool {
                    if !response.is_empty() {
                        info!(
                            "Feishu: suppressing final response for chat {} because send_message already delivered output",
                            chat_id
                        );
                    } else {
                        info!(
                            "Feishu: no final response for chat {} because send_message tool handled output",
                            chat_id
                        );
                    }
                } else if !response.is_empty() {
                    if let Err(e) = send_feishu_response(
                        &http_client,
                        base_url,
                        &token,
                        external_chat_id,
                        &response,
                        message_id,
                        topic_mode,
                    )
                    .await
                    {
                        error!("Feishu: failed to send response: {e}");
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
                        call_blocking(app_state.db.clone(), move |db| db.store_message(&bot_msg))
                            .await;
                } else {
                    info!(
                        "Feishu: agent returned empty response for chat {}, sending fallback",
                        chat_id
                    );
                    let fallback =
                        "I couldn't produce a visible reply after an automatic retry. Please try again.";
                    let _ = send_feishu_response(
                        &http_client,
                        base_url,
                        &token,
                        external_chat_id,
                        fallback,
                        message_id,
                        topic_mode,
                    )
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
                        call_blocking(app_state.db.clone(), move |db| db.store_message(&bot_msg))
                            .await;
                }
            }
            Err(e) => {
                error!("Error processing Feishu message: {e}");
                if !should_suppress_user_error(&e) {
                    let _ = send_feishu_response(
                        &http_client,
                        base_url,
                        &token,
                        external_chat_id,
                        &format!("Error: {e}"),
                        message_id,
                        topic_mode,
                    )
                    .await;
                }
            }
        }
    }
}

#[cfg(test)]
mod mention_tests {
    use super::{parse_feishu_mentions, text_has_at_all_marker};

    #[test]
    fn test_parse_feishu_mentions_detects_bot_and_all() {
        let mentions = vec![
            serde_json::json!({"key":"@_all"}),
            serde_json::json!({"id":{"open_id":"ou_bot_1"}}),
        ];
        let flags = parse_feishu_mentions(Some(&mentions), "ou_bot_1");
        assert!(flags.at_all);
        assert!(flags.bot_mentioned);
    }

    #[test]
    fn test_parse_feishu_mentions_handles_missing_mentions() {
        let flags = parse_feishu_mentions(None, "ou_bot_1");
        assert!(!flags.at_all);
        assert!(!flags.bot_mentioned);
    }

    #[test]
    fn test_text_has_at_all_marker() {
        assert!(text_has_at_all_marker(
            "@_all hello",
            r#"{"text":"@_all hello"}"#
        ));
        assert!(text_has_at_all_marker(
            "hello",
            r#"{"text":"<at user_id=\"all\">all</at> hello"}"#
        ));
        assert!(!text_has_at_all_marker("hello", r#"{"text":"hello"}"#));
    }
}

// ---------------------------------------------------------------------------
// Webhook mode
// ---------------------------------------------------------------------------

/// Register Feishu webhook routes on the given axum Router.
/// Called when connection_mode is "webhook".
pub fn register_feishu_webhook(router: axum::Router, app_state: Arc<AppState>) -> axum::Router {
    let runtimes = build_feishu_runtime_contexts(&app_state.config);
    if runtimes.is_empty() {
        return router;
    }

    let mut router = router;
    for runtime in runtimes {
        let cfg = runtime.config.clone();
        mark_runtime_started(&runtime.channel_name);
        if cfg.connection_mode != "webhook" {
            continue;
        }
        let path = cfg.webhook_path.clone();
        let verification_token = cfg.verification_token.clone();
        let state_for_handler = app_state.clone();
        let runtime_for_handler = runtime.clone();
        let cfg_for_handler = cfg.clone();
        let base_url = resolve_domain(&cfg.domain);

        router = router.route(
            &path,
            axum::routing::post(move |body: axum::extract::Json<serde_json::Value>| {
                let state = state_for_handler.clone();
                let runtime_ctx = runtime_for_handler.clone();
                let cfg = cfg_for_handler.clone();
                let base = base_url.clone();
                let vtoken = verification_token.clone();
                async move {
                    // Handle URL verification challenge
                    if let Some(challenge) = body.get("challenge").and_then(|v| v.as_str()) {
                        // Optionally verify token
                        if let Some(ref expected) = vtoken {
                            if !expected.is_empty() {
                                let token =
                                    body.get("token").and_then(|v| v.as_str()).unwrap_or("");
                                if token != expected {
                                    return axum::Json(
                                        serde_json::json!({"error": "invalid token"}),
                                    );
                                }
                            }
                        }
                        return axum::Json(serde_json::json!({ "challenge": challenge }));
                    }

                    let bot_id = runtime_bot_open_id(&runtime_ctx.channel_name).unwrap_or_default();
                    let http_client = reqwest::Client::new();

                    // Process the event
                    let event = body.0;
                    tokio::spawn(async move {
                        handle_feishu_event(
                            state,
                            http_client,
                            runtime_ctx,
                            &cfg,
                            &base,
                            &bot_id,
                            &event,
                        )
                        .await;
                    });

                    axum::Json(serde_json::json!({"code": 0}))
                }
            }),
        );
    }
    router
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_feishu_plugin_slash_dispatch_helper() {
        let root = std::env::temp_dir().join(format!("mc_feishu_plugin_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("plugin.yaml"),
            r#"
name: feishuplug
enabled: true
commands:
  - command: /feishuplug
    response: "feishu-ok"
"#,
        )
        .unwrap();

        let mut cfg = crate::config::Config::test_defaults();
        cfg.plugins.enabled = true;
        cfg.plugins.dir = Some(root.to_string_lossy().to_string());

        let out = maybe_plugin_slash_response(&cfg, "/feishuplug", 1, "feishu").await;
        assert_eq!(out.as_deref(), Some("feishu-ok"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn test_build_runtime_inherits_channel_topic_mode_when_account_not_set() {
        let mut cfg = crate::config::Config::test_defaults();
        cfg.channels.insert(
            "feishu".into(),
            serde_yaml::from_str(
                r#"
enabled: true
accounts:
  main:
    enabled: true
    app_id: "a"
    app_secret: "b"
    topic_mode: true
"#,
            )
            .unwrap(),
        );

        let runtimes = build_feishu_runtime_contexts(&cfg);
        assert_eq!(runtimes.len(), 1);
        assert!(runtimes[0].config.topic_mode);
    }
}
