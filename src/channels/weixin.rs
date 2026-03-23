use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyInit};
use aes::Aes128;
use axum::http::HeaderMap;
use axum::{Json, Router};
use base64::Engine as _;
use ecb::Encryptor as EcbEncryptor;
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::agent_engine::process_with_agent_with_events;
use crate::agent_engine::should_suppress_final_channel_response;
use crate::agent_engine::{AgentEvent, AgentRequestContext};
use crate::channels::startup_guard::{
    mark_channel_started, parse_epoch_ms_from_seconds_str, parse_epoch_ms_from_str,
    should_drop_pre_start_message, should_drop_recent_duplicate_message,
};
use crate::chat_commands::{handle_chat_command, is_slash_command, unknown_command_response};
use crate::config::Config;
use crate::runtime::AppState;
use crate::setup_def::{ChannelFieldDef, DynamicChannelDef};
use microclaw_channels::channel::ConversationKind;
use microclaw_channels::channel_adapter::ChannelAdapter;
use microclaw_storage::db::{call_blocking, StoredMessage};

const CHANNEL_KEY: &str = "weixin";
const DEFAULT_BASE_URL: &str = "https://ilinkai.weixin.qq.com";
const DEFAULT_CDN_BASE_URL: &str = "https://novac2c.cdn.weixin.qq.com/c2c";
const DEFAULT_WEBHOOK_PATH: &str = "/weixin/messages";
const BOT_TYPE: &str = "3";
const LONG_POLL_TIMEOUT_MS: u64 = 35_000;
const QR_POLL_TIMEOUT_MS: u64 = 35_000;
const DEFAULT_API_TIMEOUT_MS: u64 = 15_000;
const RETRY_DELAY_MS: u64 = 2_000;
const BACKOFF_DELAY_MS: u64 = 30_000;
const MAX_CONSECUTIVE_FAILURES: usize = 3;
const CONFIG_CACHE_TTL_MS: u64 = 24 * 60 * 60 * 1000;
const CONFIG_CACHE_INITIAL_RETRY_MS: u64 = 2_000;
const CONFIG_CACHE_MAX_RETRY_MS: u64 = 60 * 60 * 1000;
const TYPING_KEEPALIVE_MS: u64 = 5_000;
const SESSION_EXPIRED_ERRCODE: i64 = -14;
const MSG_TYPE_USER: i32 = 1;
const MSG_TYPE_BOT: i32 = 2;
const MSG_STATE_FINISH: i32 = 2;
const MSG_ITEM_TEXT: i32 = 1;
const TYPING_STATUS_TYPING: i32 = 1;
const TYPING_STATUS_CANCEL: i32 = 2;

pub const SETUP_DEF: DynamicChannelDef = DynamicChannelDef {
    name: CHANNEL_KEY,
    presence_keys: &["base_url", "cdn_base_url"],
    fields: &[
        ChannelFieldDef {
            yaml_key: "base_url",
            label: "OpenClaw Weixin API base URL",
            default: DEFAULT_BASE_URL,
            secret: false,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "cdn_base_url",
            label: "OpenClaw Weixin CDN base URL",
            default: DEFAULT_CDN_BASE_URL,
            secret: false,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "webhook_path",
            label: "OpenClaw Weixin webhook path (default /weixin/messages)",
            default: DEFAULT_WEBHOOK_PATH,
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

fn default_base_url() -> String {
    DEFAULT_BASE_URL.to_string()
}

fn default_cdn_base_url() -> String {
    DEFAULT_CDN_BASE_URL.to_string()
}

fn default_webhook_path() -> String {
    DEFAULT_WEBHOOK_PATH.to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct WeixinAccountConfig {
    #[serde(default)]
    pub allowed_user_ids: String,
    #[serde(default)]
    pub webhook_token: String,
    #[serde(default)]
    pub bot_username: String,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub base_url: String,
    #[serde(default)]
    pub cdn_base_url: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WeixinChannelConfig {
    #[serde(default)]
    pub allowed_user_ids: String,
    #[serde(default = "default_webhook_path")]
    pub webhook_path: String,
    #[serde(default)]
    pub webhook_token: String,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default = "default_base_url")]
    pub base_url: String,
    #[serde(default = "default_cdn_base_url")]
    pub cdn_base_url: String,
    #[serde(default)]
    pub accounts: HashMap<String, WeixinAccountConfig>,
    #[serde(default)]
    pub default_account: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
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

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
struct WeixinWebhookTextItem {
    #[serde(default)]
    text: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
struct WeixinWebhookVoiceItem {
    #[serde(default)]
    text: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
struct WeixinWebhookFileItem {
    #[serde(default)]
    file_name: String,
    #[serde(default)]
    len: String,
    #[serde(default)]
    media: Option<WeixinCdnMedia>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
struct WeixinCdnMedia {
    #[serde(default)]
    encrypt_query_param: String,
    #[serde(default)]
    aes_key: String,
    #[serde(default)]
    encrypt_type: i32,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
struct WeixinWebhookImageItem {
    #[serde(default)]
    media: Option<WeixinCdnMedia>,
    #[serde(default)]
    mid_size: Option<u64>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
struct WeixinWebhookVideoItem {
    #[serde(default)]
    media: Option<WeixinCdnMedia>,
    #[serde(default)]
    video_size: Option<u64>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
struct WeixinWebhookRefMessage {
    #[serde(default)]
    title: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
struct WeixinWebhookMessageItem {
    #[serde(default)]
    r#type: i32,
    #[serde(default)]
    text_item: Option<WeixinWebhookTextItem>,
    #[serde(default)]
    voice_item: Option<WeixinWebhookVoiceItem>,
    #[serde(default)]
    file_item: Option<WeixinWebhookFileItem>,
    #[serde(default)]
    image_item: Option<WeixinWebhookImageItem>,
    #[serde(default)]
    video_item: Option<WeixinWebhookVideoItem>,
    #[serde(default)]
    ref_msg: Option<WeixinWebhookRefMessage>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
struct WeixinWireMessage {
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
    #[serde(default)]
    message_type: Option<i32>,
    #[serde(default)]
    message_state: Option<i32>,
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
    message: Option<WeixinWireMessage>,
}

#[derive(Debug, Clone, Deserialize)]
struct QrCodeResponse {
    qrcode: String,
    qrcode_img_content: String,
}

#[derive(Debug, Clone, Deserialize)]
struct QrStatusResponse {
    status: String,
    #[serde(default)]
    bot_token: String,
    #[serde(default)]
    ilink_bot_id: String,
    #[serde(default)]
    baseurl: String,
    #[serde(default)]
    ilink_user_id: String,
}

#[derive(Debug, Clone, Deserialize)]
struct WeixinGetUpdatesResp {
    #[serde(default)]
    ret: i64,
    #[serde(default)]
    errcode: Option<i64>,
    #[serde(default)]
    errmsg: Option<String>,
    #[serde(default)]
    msgs: Vec<WeixinWireMessage>,
    #[serde(default)]
    get_updates_buf: String,
    #[serde(default)]
    longpolling_timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
struct WeixinGetUploadUrlResp {
    #[serde(default)]
    upload_param: String,
    #[serde(default)]
    thumb_upload_param: String,
}

#[derive(Debug, Clone, Deserialize)]
struct WeixinGetConfigResp {
    #[serde(default)]
    ret: i64,
    #[serde(default)]
    errmsg: Option<String>,
    #[serde(default)]
    typing_ticket: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct StoredWeixinAccount {
    #[serde(default)]
    token: String,
    #[serde(default = "default_base_url")]
    base_url: String,
    #[serde(default)]
    remote_account_id: String,
    #[serde(default)]
    user_id: String,
    #[serde(default)]
    saved_at: String,
    #[serde(default)]
    context_tokens: HashMap<String, String>,
}

#[derive(Debug, Clone)]
struct NativeWeixinAccount {
    token: String,
    base_url: String,
    cdn_base_url: String,
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
    pub local_account_key: String,
    pub allowed_user_ids: Vec<String>,
    pub webhook_token: String,
    pub bot_username: String,
    pub model: Option<String>,
    pub base_url: String,
    pub cdn_base_url: String,
    pub state_root: PathBuf,
}

static WEIXIN_CONTEXT_TOKENS: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
static WEIXIN_TYPING_TICKETS: OnceLock<Mutex<HashMap<String, TypingTicketCacheEntry>>> =
    OnceLock::new();

#[derive(Debug, Clone)]
struct TypingTicketCacheEntry {
    typing_ticket: String,
    next_fetch_at_ms: u64,
    retry_delay_ms: u64,
}

fn context_token_registry() -> &'static Mutex<HashMap<String, String>> {
    WEIXIN_CONTEXT_TOKENS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn typing_ticket_registry() -> &'static Mutex<HashMap<String, TypingTicketCacheEntry>> {
    WEIXIN_TYPING_TICKETS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn now_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
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

fn get_cached_context_token(channel_name: &str, external_chat_id: &str) -> Option<String> {
    context_token_registry().lock().ok().and_then(|guard| {
        guard
            .get(&context_token_key(channel_name, external_chat_id))
            .cloned()
    })
}

fn parse_csv(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned)
        .collect()
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

fn local_account_key(account_id: &str) -> String {
    let trimmed = account_id.trim();
    if trimmed.is_empty() {
        "default".to_string()
    } else {
        trimmed.to_string()
    }
}

fn sanitize_account_key(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "default".to_string()
    } else {
        out
    }
}

fn weixin_state_root(data_root: &Path) -> PathBuf {
    data_root.join(CHANNEL_KEY)
}

fn account_file_path(state_root: &Path, local_account_key: &str) -> PathBuf {
    state_root
        .join("accounts")
        .join(format!("{}.json", sanitize_account_key(local_account_key)))
}

fn sync_buf_file_path(state_root: &Path, local_account_key: &str) -> PathBuf {
    state_root
        .join("sync")
        .join(format!("{}.txt", sanitize_account_key(local_account_key)))
}

fn resolve_context_token_from_store(
    state_root: &Path,
    local_account_key: &str,
    channel_name: &str,
    external_chat_id: &str,
) -> Option<String> {
    if let Some(token) = get_cached_context_token(channel_name, external_chat_id) {
        return Some(token);
    }
    let account = load_account_data(state_root, local_account_key)?;
    let token = account
        .context_tokens
        .get(external_chat_id)
        .cloned()
        .filter(|token| !token.trim().is_empty())?;
    cache_context_token(channel_name, external_chat_id, &token);
    Some(token)
}

fn hydrate_context_token_cache(runtime: &WeixinRuntimeContext) {
    let Some(account) = load_account_data(&runtime.state_root, &runtime.local_account_key) else {
        return;
    };
    for (external_chat_id, token) in account.context_tokens {
        cache_context_token(&runtime.channel_name, &external_chat_id, &token);
    }
}

fn persist_context_token(
    runtime: &WeixinRuntimeContext,
    external_chat_id: &str,
    context_token: &str,
) -> Result<(), String> {
    let token = context_token.trim();
    if token.is_empty() {
        return Ok(());
    }
    cache_context_token(&runtime.channel_name, external_chat_id, token);

    let mut account = load_account_data(&runtime.state_root, &runtime.local_account_key)
        .unwrap_or_else(|| StoredWeixinAccount {
            base_url: runtime.base_url.clone(),
            ..StoredWeixinAccount::default()
        });
    account
        .context_tokens
        .insert(external_chat_id.to_string(), token.to_string());
    if account.base_url.trim().is_empty() {
        account.base_url = runtime.base_url.clone();
    }
    save_account_data(&runtime.state_root, &runtime.local_account_key, &account)
}

fn load_account_data(state_root: &Path, local_account_key: &str) -> Option<StoredWeixinAccount> {
    let path = account_file_path(state_root, local_account_key);
    let raw = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

fn save_account_data(
    state_root: &Path,
    local_account_key: &str,
    account: &StoredWeixinAccount,
) -> Result<(), String> {
    let path = account_file_path(state_root, local_account_key);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create Weixin account dir: {e}"))?;
    }
    let raw = serde_json::to_string_pretty(account)
        .map_err(|e| format!("Failed to serialize Weixin account state: {e}"))?;
    std::fs::write(&path, raw).map_err(|e| format!("Failed to write Weixin account state: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn delete_account_data(state_root: &Path, local_account_key: &str) -> Result<(), String> {
    let path = account_file_path(state_root, local_account_key);
    if path.exists() {
        std::fs::remove_file(&path)
            .map_err(|e| format!("Failed to remove Weixin account state: {e}"))?;
    }
    let sync_path = sync_buf_file_path(state_root, local_account_key);
    if sync_path.exists() {
        std::fs::remove_file(&sync_path)
            .map_err(|e| format!("Failed to remove Weixin sync state: {e}"))?;
    }
    Ok(())
}

fn load_sync_buf(state_root: &Path, local_account_key: &str) -> String {
    std::fs::read_to_string(sync_buf_file_path(state_root, local_account_key)).unwrap_or_default()
}

fn save_sync_buf(
    state_root: &Path,
    local_account_key: &str,
    get_updates_buf: &str,
) -> Result<(), String> {
    let path = sync_buf_file_path(state_root, local_account_key);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create Weixin sync dir: {e}"))?;
    }
    std::fs::write(path, get_updates_buf)
        .map_err(|e| format!("Failed to write Weixin sync buf: {e}"))
}

fn stored_account_exists(state_root: &Path, local_account_key: &str) -> bool {
    account_file_path(state_root, local_account_key).exists()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WeixinAttachmentKind {
    Image,
    Video,
    File,
}

#[derive(Debug, Clone)]
struct UploadedWeixinMedia {
    download_encrypted_query_param: String,
    aes_key: Vec<u8>,
    file_size: u64,
    file_size_ciphertext: u64,
}

struct GetUploadUrlRequest<'a> {
    filekey: &'a str,
    media_type: i32,
    to_user_id: &'a str,
    rawsize: u64,
    rawfilemd5: &'a str,
    filesize: u64,
    aeskey_hex: &'a str,
}

fn infer_attachment_kind(file_path: &Path) -> WeixinAttachmentKind {
    let ext = file_path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "bmp" => WeixinAttachmentKind::Image,
        "mp4" | "mov" | "webm" | "mkv" | "avi" => WeixinAttachmentKind::Video,
        _ => WeixinAttachmentKind::File,
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn aes_ecb_padded_size(plaintext_size: usize) -> usize {
    ((plaintext_size + 1).div_ceil(16)) * 16
}

fn encrypt_aes_ecb(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = EcbEncryptor::<Aes128>::new_from_slice(key)
        .map_err(|e| format!("Failed to initialize AES-128-ECB cipher: {e}"))?;
    Ok(cipher.encrypt_padded_vec_mut::<Pkcs7>(plaintext))
}

fn build_cdn_upload_url(cdn_base_url: &str, upload_param: &str, filekey: &str) -> String {
    format!(
        "{}/upload?encrypted_query_param={}&filekey={}",
        ensure_trailing_slash(cdn_base_url).trim_end_matches('/'),
        urlencoding::encode(upload_param),
        urlencoding::encode(filekey)
    )
}

fn typing_ticket_cache_key(channel_name: &str, external_chat_id: &str) -> String {
    format!("{channel_name}:{external_chat_id}")
}

async fn get_cached_typing_ticket(
    client: &reqwest::Client,
    runtime: &WeixinRuntimeContext,
    account: &NativeWeixinAccount,
    external_chat_id: &str,
    context_token: Option<&str>,
) -> Option<String> {
    let cache_key = typing_ticket_cache_key(&runtime.channel_name, external_chat_id);
    let now_ms = now_epoch_ms();

    if let Ok(guard) = typing_ticket_registry().lock() {
        if let Some(entry) = guard.get(&cache_key) {
            if now_ms < entry.next_fetch_at_ms && !entry.typing_ticket.trim().is_empty() {
                return Some(entry.typing_ticket.clone());
            }
        }
    }

    match get_config(client, account, external_chat_id, context_token).await {
        Ok(response) if response.ret == 0 => {
            let typing_ticket = response.typing_ticket.trim().to_string();
            let next_fetch_at_ms = now_ms + CONFIG_CACHE_TTL_MS;
            if let Ok(mut guard) = typing_ticket_registry().lock() {
                guard.insert(
                    cache_key,
                    TypingTicketCacheEntry {
                        typing_ticket: typing_ticket.clone(),
                        next_fetch_at_ms,
                        retry_delay_ms: CONFIG_CACHE_INITIAL_RETRY_MS,
                    },
                );
            }
            if typing_ticket.is_empty() {
                None
            } else {
                Some(typing_ticket)
            }
        }
        Ok(response) => {
            if let Ok(mut guard) = typing_ticket_registry().lock() {
                let entry = guard.entry(cache_key).or_insert(TypingTicketCacheEntry {
                    typing_ticket: String::new(),
                    next_fetch_at_ms: now_ms + CONFIG_CACHE_INITIAL_RETRY_MS,
                    retry_delay_ms: CONFIG_CACHE_INITIAL_RETRY_MS,
                });
                entry.next_fetch_at_ms = now_ms + entry.retry_delay_ms;
                entry.retry_delay_ms =
                    (entry.retry_delay_ms.saturating_mul(2)).min(CONFIG_CACHE_MAX_RETRY_MS);
            }
            warn!(
                "OpenClaw Weixin getconfig returned ret={} for '{}': {}",
                response.ret,
                runtime.channel_name,
                response.errmsg.unwrap_or_default()
            );
            None
        }
        Err(err) => {
            if let Ok(mut guard) = typing_ticket_registry().lock() {
                let entry = guard.entry(cache_key).or_insert(TypingTicketCacheEntry {
                    typing_ticket: String::new(),
                    next_fetch_at_ms: now_ms + CONFIG_CACHE_INITIAL_RETRY_MS,
                    retry_delay_ms: CONFIG_CACHE_INITIAL_RETRY_MS,
                });
                entry.next_fetch_at_ms = now_ms + entry.retry_delay_ms;
                entry.retry_delay_ms =
                    (entry.retry_delay_ms.saturating_mul(2)).min(CONFIG_CACHE_MAX_RETRY_MS);
            }
            warn!(
                "OpenClaw Weixin getconfig failed for '{}'/{}: {}",
                runtime.channel_name, external_chat_id, err
            );
            None
        }
    }
}

fn ensure_trailing_slash(base_url: &str) -> String {
    if base_url.ends_with('/') {
        base_url.to_string()
    } else {
        format!("{base_url}/")
    }
}

fn build_post_headers(token: Option<&str>, body: Option<&str>) -> Vec<(String, String)> {
    let uuid = uuid::Uuid::new_v4();
    let bytes = uuid.as_bytes();
    let wechat_uin = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let mut headers = vec![
        ("Content-Type".to_string(), "application/json".to_string()),
        (
            "AuthorizationType".to_string(),
            "ilink_bot_token".to_string(),
        ),
        (
            "X-WECHAT-UIN".to_string(),
            base64::engine::general_purpose::STANDARD.encode(wechat_uin.to_string()),
        ),
    ];
    if let Some(body) = body {
        headers.push(("Content-Length".to_string(), body.len().to_string()));
    }
    if let Some(token) = token.map(str::trim).filter(|token| !token.is_empty()) {
        headers.push(("Authorization".to_string(), format!("Bearer {token}")));
    }
    headers
}

async fn api_post(
    client: &reqwest::Client,
    base_url: &str,
    endpoint: &str,
    body: String,
    token: Option<&str>,
    timeout_ms: u64,
) -> Result<String, String> {
    let url = format!("{}{}", ensure_trailing_slash(base_url), endpoint);
    let mut request = client.post(url).timeout(Duration::from_millis(timeout_ms));
    for (key, value) in build_post_headers(token, Some(&body)) {
        request = request.header(&key, value);
    }
    let response = request
        .body(body)
        .send()
        .await
        .map_err(|e| format!("Weixin request failed: {e}"))?;
    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|e| format!("Failed reading Weixin response: {e}"))?;
    if !status.is_success() {
        return Err(format!("Weixin HTTP {}: {}", status.as_u16(), text));
    }
    Ok(text)
}

async fn api_get(
    client: &reqwest::Client,
    url: &str,
    headers: &[(&str, &str)],
    timeout_ms: u64,
) -> Result<String, String> {
    let mut request = client.get(url).timeout(Duration::from_millis(timeout_ms));
    for (key, value) in headers {
        request = request.header(*key, *value);
    }
    let response = request
        .send()
        .await
        .map_err(|e| format!("Weixin GET request failed: {e}"))?;
    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|e| format!("Failed reading Weixin GET response: {e}"))?;
    if !status.is_success() {
        return Err(format!("Weixin HTTP {}: {}", status.as_u16(), text));
    }
    Ok(text)
}

async fn upload_cdn_ciphertext(
    client: &reqwest::Client,
    cdn_base_url: &str,
    upload_param: &str,
    filekey: &str,
    plaintext: &[u8],
    aes_key: &[u8],
) -> Result<String, String> {
    let ciphertext = encrypt_aes_ecb(plaintext, aes_key)?;
    let cdn_url = build_cdn_upload_url(cdn_base_url, upload_param, filekey);
    let mut last_error = String::new();

    for attempt in 1..=3 {
        let response = client
            .post(&cdn_url)
            .timeout(Duration::from_millis(DEFAULT_API_TIMEOUT_MS))
            .header("Content-Type", "application/octet-stream")
            .body(ciphertext.clone())
            .send()
            .await;

        match response {
            Ok(response) => {
                let status = response.status();
                let headers = response.headers().clone();
                let body = response.text().await.unwrap_or_default();
                if status.is_success() {
                    if let Some(value) = headers
                        .get("x-encrypted-param")
                        .and_then(|value| value.to_str().ok())
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                    {
                        return Ok(value.to_string());
                    }
                    return Err("CDN upload response missing x-encrypted-param header".to_string());
                }

                let error_message = headers
                    .get("x-error-message")
                    .and_then(|value| value.to_str().ok())
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .unwrap_or(body.trim());
                last_error = format!(
                    "CDN upload failed with HTTP {}: {}",
                    status.as_u16(),
                    error_message
                );
                if status.is_client_error() {
                    return Err(last_error);
                }
            }
            Err(err) => {
                last_error = format!("CDN upload request failed: {err}");
            }
        }

        if attempt < 3 {
            tokio::time::sleep(Duration::from_millis(RETRY_DELAY_MS)).await;
        }
    }

    Err(last_error)
}

async fn fetch_qrcode(client: &reqwest::Client, base_url: &str) -> Result<QrCodeResponse, String> {
    let url = format!(
        "{}ilink/bot/get_bot_qrcode?bot_type={}",
        ensure_trailing_slash(base_url),
        BOT_TYPE
    );
    let raw = api_get(client, &url, &[], DEFAULT_API_TIMEOUT_MS).await?;
    serde_json::from_str(&raw).map_err(|e| format!("Failed to parse QR response: {e}"))
}

async fn poll_qr_status(
    client: &reqwest::Client,
    base_url: &str,
    qrcode: &str,
) -> Result<QrStatusResponse, String> {
    let url = format!(
        "{}ilink/bot/get_qrcode_status?qrcode={}",
        ensure_trailing_slash(base_url),
        urlencoding::encode(qrcode)
    );
    api_get(
        client,
        &url,
        &[("iLink-App-ClientVersion", "1")],
        QR_POLL_TIMEOUT_MS,
    )
    .await
    .and_then(|raw| {
        serde_json::from_str(&raw).map_err(|e| format!("Failed to parse QR status response: {e}"))
    })
}

async fn get_updates(
    client: &reqwest::Client,
    account: &NativeWeixinAccount,
    get_updates_buf: &str,
    timeout_ms: u64,
) -> Result<WeixinGetUpdatesResp, String> {
    let body = serde_json::json!({
        "get_updates_buf": get_updates_buf,
        "base_info": {
            "channel_version": env!("CARGO_PKG_VERSION")
        }
    })
    .to_string();
    let raw = api_post(
        client,
        &account.base_url,
        "ilink/bot/getupdates",
        body,
        Some(&account.token),
        timeout_ms,
    )
    .await?;
    serde_json::from_str(&raw).map_err(|e| format!("Failed to parse getupdates response: {e}"))
}

async fn get_upload_url(
    client: &reqwest::Client,
    account: &NativeWeixinAccount,
    request: GetUploadUrlRequest<'_>,
) -> Result<WeixinGetUploadUrlResp, String> {
    let body = serde_json::json!({
        "filekey": request.filekey,
        "media_type": request.media_type,
        "to_user_id": request.to_user_id,
        "rawsize": request.rawsize,
        "rawfilemd5": request.rawfilemd5,
        "filesize": request.filesize,
        "no_need_thumb": true,
        "aeskey": request.aeskey_hex,
        "base_info": {
            "channel_version": env!("CARGO_PKG_VERSION")
        }
    })
    .to_string();
    let raw = api_post(
        client,
        &account.base_url,
        "ilink/bot/getuploadurl",
        body,
        Some(&account.token),
        DEFAULT_API_TIMEOUT_MS,
    )
    .await?;
    serde_json::from_str(&raw).map_err(|e| format!("Failed to parse getuploadurl response: {e}"))
}

async fn get_config(
    client: &reqwest::Client,
    account: &NativeWeixinAccount,
    ilink_user_id: &str,
    context_token: Option<&str>,
) -> Result<WeixinGetConfigResp, String> {
    let body = serde_json::json!({
        "ilink_user_id": ilink_user_id,
        "context_token": context_token.filter(|value| !value.trim().is_empty()),
        "base_info": {
            "channel_version": env!("CARGO_PKG_VERSION")
        }
    })
    .to_string();
    let raw = api_post(
        client,
        &account.base_url,
        "ilink/bot/getconfig",
        body,
        Some(&account.token),
        DEFAULT_API_TIMEOUT_MS,
    )
    .await?;
    serde_json::from_str(&raw).map_err(|e| format!("Failed to parse getconfig response: {e}"))
}

async fn send_typing(
    client: &reqwest::Client,
    account: &NativeWeixinAccount,
    ilink_user_id: &str,
    typing_ticket: &str,
    status: i32,
) -> Result<(), String> {
    let body = serde_json::json!({
        "ilink_user_id": ilink_user_id,
        "typing_ticket": typing_ticket,
        "status": status,
        "base_info": {
            "channel_version": env!("CARGO_PKG_VERSION")
        }
    })
    .to_string();
    let _ = api_post(
        client,
        &account.base_url,
        "ilink/bot/sendtyping",
        body,
        Some(&account.token),
        DEFAULT_API_TIMEOUT_MS,
    )
    .await?;
    Ok(())
}

fn generate_client_id() -> String {
    format!("microclaw-weixin:{}", uuid::Uuid::new_v4())
}

async fn send_text_message_native(
    client: &reqwest::Client,
    account: &NativeWeixinAccount,
    to_user_id: &str,
    text: &str,
    context_token: &str,
) -> Result<String, String> {
    let client_id = generate_client_id();
    let body = serde_json::json!({
        "msg": {
            "from_user_id": "",
            "to_user_id": to_user_id,
            "client_id": client_id,
            "message_type": MSG_TYPE_BOT,
            "message_state": MSG_STATE_FINISH,
            "item_list": [
                {
                    "type": MSG_ITEM_TEXT,
                    "text_item": { "text": text }
                }
            ],
            "context_token": context_token,
        },
        "base_info": {
            "channel_version": env!("CARGO_PKG_VERSION")
        }
    })
    .to_string();
    let _ = api_post(
        client,
        &account.base_url,
        "ilink/bot/sendmessage",
        body,
        Some(&account.token),
        DEFAULT_API_TIMEOUT_MS,
    )
    .await?;
    Ok(client_id)
}

async fn send_single_item_message_native(
    client: &reqwest::Client,
    account: &NativeWeixinAccount,
    to_user_id: &str,
    item: WeixinWebhookMessageItem,
    context_token: &str,
) -> Result<String, String> {
    let client_id = generate_client_id();
    let body = serde_json::json!({
        "msg": {
            "from_user_id": "",
            "to_user_id": to_user_id,
            "client_id": client_id,
            "message_type": MSG_TYPE_BOT,
            "message_state": MSG_STATE_FINISH,
            "item_list": [item],
            "context_token": context_token,
        },
        "base_info": {
            "channel_version": env!("CARGO_PKG_VERSION")
        }
    })
    .to_string();
    let _ = api_post(
        client,
        &account.base_url,
        "ilink/bot/sendmessage",
        body,
        Some(&account.token),
        DEFAULT_API_TIMEOUT_MS,
    )
    .await?;
    Ok(client_id)
}

async fn upload_media_native(
    client: &reqwest::Client,
    account: &NativeWeixinAccount,
    to_user_id: &str,
    file_path: &Path,
    kind: WeixinAttachmentKind,
) -> Result<UploadedWeixinMedia, String> {
    let plaintext = fs::read(file_path)
        .map_err(|e| format!("Failed to read attachment '{}': {e}", file_path.display()))?;
    let rawsize = plaintext.len() as u64;
    let rawfilemd5 = format!("{:x}", md5::compute(&plaintext));
    let file_size_ciphertext = aes_ecb_padded_size(plaintext.len()) as u64;
    let filekey_uuid = uuid::Uuid::new_v4();
    let filekey = hex_encode(filekey_uuid.as_bytes());
    let aes_key = *uuid::Uuid::new_v4().as_bytes();
    let aeskey_hex = hex_encode(&aes_key);
    let media_type = match kind {
        WeixinAttachmentKind::Image => 1,
        WeixinAttachmentKind::Video => 2,
        WeixinAttachmentKind::File => 3,
    };

    let upload_url = get_upload_url(
        client,
        account,
        GetUploadUrlRequest {
            filekey: &filekey,
            media_type,
            to_user_id,
            rawsize,
            rawfilemd5: &rawfilemd5,
            filesize: file_size_ciphertext,
            aeskey_hex: &aeskey_hex,
        },
    )
    .await?;
    if upload_url.upload_param.trim().is_empty() {
        return Err("Weixin getuploadurl returned empty upload_param".to_string());
    }
    let _ = upload_url.thumb_upload_param;

    let download_encrypted_query_param = upload_cdn_ciphertext(
        client,
        &account.cdn_base_url,
        &upload_url.upload_param,
        &filekey,
        &plaintext,
        &aes_key,
    )
    .await?;

    Ok(UploadedWeixinMedia {
        download_encrypted_query_param,
        aes_key: aes_key.to_vec(),
        file_size: rawsize,
        file_size_ciphertext,
    })
}

async fn send_attachment_native(
    client: &reqwest::Client,
    account: &NativeWeixinAccount,
    to_user_id: &str,
    file_path: &Path,
    caption: Option<&str>,
    context_token: &str,
) -> Result<String, String> {
    let kind = infer_attachment_kind(file_path);
    let uploaded = upload_media_native(client, account, to_user_id, file_path, kind).await?;
    let media = WeixinCdnMedia {
        encrypt_query_param: uploaded.download_encrypted_query_param,
        aes_key: base64::engine::general_purpose::STANDARD.encode(uploaded.aes_key),
        encrypt_type: 1,
    };

    if let Some(text) = caption.map(str::trim).filter(|value| !value.is_empty()) {
        let _ = send_text_message_native(client, account, to_user_id, text, context_token).await?;
    }

    let item = match kind {
        WeixinAttachmentKind::Image => WeixinWebhookMessageItem {
            r#type: 2,
            image_item: Some(WeixinWebhookImageItem {
                media: Some(media),
                mid_size: Some(uploaded.file_size_ciphertext),
            }),
            ..Default::default()
        },
        WeixinAttachmentKind::Video => WeixinWebhookMessageItem {
            r#type: 5,
            video_item: Some(WeixinWebhookVideoItem {
                media: Some(media),
                video_size: Some(uploaded.file_size_ciphertext),
            }),
            ..Default::default()
        },
        WeixinAttachmentKind::File => WeixinWebhookMessageItem {
            r#type: 4,
            file_item: Some(WeixinWebhookFileItem {
                file_name: file_path
                    .file_name()
                    .and_then(|value| value.to_str())
                    .unwrap_or("attachment")
                    .to_string(),
                len: uploaded.file_size.to_string(),
                media: Some(media),
            }),
            ..Default::default()
        },
    };

    send_single_item_message_native(client, account, to_user_id, item, context_token).await
}

fn summarize_weixin_item(item: &WeixinWebhookMessageItem) -> Option<String> {
    match item.r#type {
        1 => {
            let text = item
                .text_item
                .as_ref()
                .map(|text| text.text.trim().to_string())
                .filter(|text| !text.is_empty())?;
            if let Some(reference) = item
                .ref_msg
                .as_ref()
                .map(|reference| reference.title.trim().to_string())
                .filter(|title| !title.is_empty())
            {
                return Some(format!("[引用: {reference}]\n{text}"));
            }
            Some(text)
        }
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

fn normalize_polled_message(message: &WeixinWireMessage) -> Option<NormalizedWeixinInbound> {
    if message.message_type != Some(MSG_TYPE_USER) {
        return None;
    }
    let sender = message.from_user_id.trim();
    if sender.is_empty() {
        return None;
    }
    let text = summarize_weixin_items(&message.item_list);
    if text.trim().is_empty() {
        return None;
    }
    Some(NormalizedWeixinInbound {
        sender: sender.to_string(),
        text,
        message_id: message
            .message_id
            .as_ref()
            .map(FlexibleId::as_string)
            .unwrap_or_default(),
        timestamp_ms: message.create_time_ms,
        timestamp: None,
        context_token: message.context_token.trim().to_string(),
    })
}

fn provided_weixin_webhook_token(headers: &HeaderMap) -> String {
    if let Some(token) = headers
        .get("x-weixin-webhook-token")
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

fn state_root_for_runtime_config(config: &Config) -> PathBuf {
    weixin_state_root(&config.data_root_dir())
}

pub fn build_weixin_runtime_contexts(config: &crate::config::Config) -> Vec<WeixinRuntimeContext> {
    let state_root = state_root_for_runtime_config(config);
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
        let base_url = if account_cfg.base_url.trim().is_empty() {
            wx_cfg.base_url.trim().to_string()
        } else {
            account_cfg.base_url.trim().to_string()
        };
        let cdn_base_url = if account_cfg.cdn_base_url.trim().is_empty() {
            wx_cfg.cdn_base_url.trim().to_string()
        } else {
            account_cfg.cdn_base_url.trim().to_string()
        };
        runtimes.push(WeixinRuntimeContext {
            channel_name,
            account_id: account_id.clone(),
            local_account_key: local_account_key(&account_id),
            allowed_user_ids: parse_csv(&account_cfg.allowed_user_ids),
            webhook_token,
            bot_username,
            model,
            base_url: if base_url.is_empty() {
                DEFAULT_BASE_URL.to_string()
            } else {
                base_url
            },
            cdn_base_url: if cdn_base_url.is_empty() {
                DEFAULT_CDN_BASE_URL.to_string()
            } else {
                cdn_base_url
            },
            state_root: state_root.clone(),
        });
    }

    if runtimes.is_empty() {
        runtimes.push(WeixinRuntimeContext {
            channel_name: CHANNEL_KEY.to_string(),
            account_id: String::new(),
            local_account_key: local_account_key(""),
            allowed_user_ids: parse_csv(&wx_cfg.allowed_user_ids),
            webhook_token: wx_cfg.webhook_token.trim().to_string(),
            bot_username: config.bot_username_for_channel(CHANNEL_KEY),
            model: wx_cfg
                .model
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(ToOwned::to_owned),
            base_url: if wx_cfg.base_url.trim().is_empty() {
                DEFAULT_BASE_URL.to_string()
            } else {
                wx_cfg.base_url.trim().to_string()
            },
            cdn_base_url: if wx_cfg.cdn_base_url.trim().is_empty() {
                DEFAULT_CDN_BASE_URL.to_string()
            } else {
                wx_cfg.cdn_base_url.trim().to_string()
            },
            state_root,
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

fn build_default_runtime_context(
    config: &Config,
    account_id: Option<&str>,
) -> WeixinRuntimeContext {
    let configured_account = account_id.unwrap_or("").trim();
    let is_default = configured_account.is_empty();
    let channel_name = if is_default {
        CHANNEL_KEY.to_string()
    } else {
        format!("{CHANNEL_KEY}.{configured_account}")
    };
    let account_id = configured_account.to_string();
    WeixinRuntimeContext {
        channel_name,
        local_account_key: local_account_key(&account_id),
        account_id,
        allowed_user_ids: Vec::new(),
        webhook_token: String::new(),
        bot_username: config.bot_username_for_channel(CHANNEL_KEY),
        model: None,
        base_url: DEFAULT_BASE_URL.to_string(),
        cdn_base_url: DEFAULT_CDN_BASE_URL.to_string(),
        state_root: weixin_state_root(Path::new(&config.runtime_data_dir())),
    }
}

fn resolve_weixin_runtime_for_cli(
    config: &Config,
    account_id: Option<&str>,
    base_url_override: Option<&str>,
) -> Result<WeixinRuntimeContext, String> {
    let mut runtime = if let Some(runtime) = select_runtime_context(
        &build_weixin_runtime_contexts(config),
        account_id.unwrap_or(""),
    ) {
        runtime
    } else {
        build_default_runtime_context(config, account_id)
    };
    if let Some(base_url) = base_url_override
        .map(str::trim)
        .filter(|base_url| !base_url.is_empty())
    {
        runtime.base_url = base_url.to_string();
    }
    Ok(runtime)
}

pub struct WeixinAdapter {
    name: String,
    local_account_key: String,
    base_url: String,
    cdn_base_url: String,
    state_root: PathBuf,
    http_client: reqwest::Client,
}

impl WeixinAdapter {
    pub fn from_runtime(runtime: &WeixinRuntimeContext) -> Self {
        Self {
            name: runtime.channel_name.clone(),
            local_account_key: runtime.local_account_key.clone(),
            base_url: runtime.base_url.clone(),
            cdn_base_url: runtime.cdn_base_url.clone(),
            state_root: runtime.state_root.clone(),
            http_client: reqwest::Client::new(),
        }
    }

    fn resolve_context_token(&self, external_chat_id: &str) -> Option<String> {
        resolve_context_token_from_store(
            &self.state_root,
            &self.local_account_key,
            &self.name,
            external_chat_id,
        )
    }

    fn load_native_account(&self) -> Result<NativeWeixinAccount, String> {
        let stored =
            load_account_data(&self.state_root, &self.local_account_key).ok_or_else(|| {
                format!(
                    "No Weixin credentials found for '{}'. Run `microclaw weixin login{}` first.",
                    self.name,
                    if self.local_account_key == "default" {
                        "".to_string()
                    } else {
                        format!(" --account {}", self.local_account_key)
                    }
                )
            })?;
        let token = stored.token.trim();
        if token.is_empty() {
            return Err(format!(
                "Stored Weixin credentials for '{}' are incomplete. Run login again.",
                self.name
            ));
        }
        let base_url = if stored.base_url.trim().is_empty() {
            self.base_url.clone()
        } else {
            stored.base_url.trim().to_string()
        };
        Ok(NativeWeixinAccount {
            token: token.to_string(),
            base_url,
            cdn_base_url: self.cdn_base_url.clone(),
        })
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
        let context_token = self.resolve_context_token(external_chat_id).ok_or_else(|| {
            format!(
                "weixin requires a cached context_token for target '{}'; wait for an inbound message before replying",
                external_chat_id
            )
        })?;
        let account = self.load_native_account()?;
        send_text_message_native(
            &self.http_client,
            &account,
            external_chat_id,
            text,
            &context_token,
        )
        .await
        .map(|_| ())
    }

    async fn send_attachment(
        &self,
        external_chat_id: &str,
        file_path: &Path,
        caption: Option<&str>,
    ) -> Result<String, String> {
        let context_token = self.resolve_context_token(external_chat_id).ok_or_else(|| {
            format!(
                "weixin requires a cached context_token for target '{}'; wait for an inbound message before replying",
                external_chat_id
            )
        })?;
        let account = self.load_native_account()?;
        send_attachment_native(
            &self.http_client,
            &account,
            external_chat_id,
            file_path,
            caption,
            &context_token,
        )
        .await
    }
}

async fn process_weixin_inbound_message(
    app_state: Arc<AppState>,
    runtime_ctx: WeixinRuntimeContext,
    normalized: NormalizedWeixinInbound,
) {
    let sender = normalized.sender.trim();
    let text = normalized.text.trim();
    if sender.is_empty() || text.is_empty() {
        return;
    }
    if !runtime_ctx.allowed_user_ids.is_empty()
        && !runtime_ctx.allowed_user_ids.iter().any(|id| id == sender)
    {
        return;
    }

    if let Err(err) = persist_context_token(&runtime_ctx, sender, &normalized.context_token) {
        warn!(
            "OpenClaw Weixin: failed to persist context token for {}: {}",
            sender, err
        );
    }

    let external_chat_id = sender.to_string();
    let chat_id = call_blocking(app_state.db.clone(), {
        let channel_name = runtime_ctx.channel_name.clone();
        let title = format!("weixin-{external_chat_id}");
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
        error!(
            "OpenClaw Weixin: failed to resolve chat id for {}",
            external_chat_id
        );
        return;
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
        return;
    }
    if should_drop_recent_duplicate_message(&runtime_ctx.channel_name, &inbound_message_id) {
        return;
    }

    if is_slash_command(text) {
        let adapter = WeixinAdapter::from_runtime(&runtime_ctx);
        if let Some(reply) = handle_chat_command(
            &app_state,
            chat_id,
            &runtime_ctx.channel_name,
            text,
            Some(sender),
        )
        .await
        {
            let _ = adapter.send_text(sender, &reply).await;
            return;
        }
        let _ = adapter.send_text(sender, &unknown_command_response()).await;
        return;
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
        return;
    }

    let typing_account = WeixinAdapter::from_runtime(&runtime_ctx)
        .load_native_account()
        .ok();
    let typing_ticket = if let Some(account) = typing_account.as_ref() {
        get_cached_typing_ticket(
            &reqwest::Client::new(),
            &runtime_ctx,
            account,
            sender,
            Some(&normalized.context_token),
        )
        .await
    } else {
        None
    };
    let typing_state = if let (Some(account), Some(typing_ticket)) = (typing_account, typing_ticket)
    {
        let task_account = account.clone();
        let task_ticket = typing_ticket.clone();
        let client = reqwest::Client::new();
        let sender_id = sender.to_string();
        let runtime_channel = runtime_ctx.channel_name.clone();
        let task = tokio::spawn(async move {
            let _ = send_typing(
                &client,
                &task_account,
                &sender_id,
                &task_ticket,
                TYPING_STATUS_TYPING,
            )
            .await;
            loop {
                tokio::time::sleep(Duration::from_millis(TYPING_KEEPALIVE_MS)).await;
                if let Err(err) = send_typing(
                    &client,
                    &task_account,
                    &sender_id,
                    &task_ticket,
                    TYPING_STATUS_TYPING,
                )
                .await
                {
                    warn!(
                        "OpenClaw Weixin typing keepalive failed for '{}' / '{}': {}",
                        runtime_channel, sender_id, err
                    );
                    break;
                }
            }
        });
        Some((task, account, typing_ticket))
    } else {
        None
    };

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
            if let Some((task, account, typing_ticket)) = typing_state {
                task.abort();
                let _ = send_typing(
                    &reqwest::Client::new(),
                    &account,
                    sender,
                    &typing_ticket,
                    TYPING_STATUS_CANCEL,
                )
                .await;
            }
            drop(event_tx);
            let mut tool_delivered_user_output = false;
            while let Some(event) = event_rx.recv().await {
                if let AgentEvent::ToolResult {
                    delivered_user_output,
                    is_error,
                    ..
                } = event
                {
                    if delivered_user_output && !is_error {
                        tool_delivered_user_output = true;
                    }
                }
            }
            let adapter = WeixinAdapter::from_runtime(&runtime_ctx);
            if should_suppress_final_channel_response(&response, tool_delivered_user_output) {
                info!(
                    "OpenClaw Weixin: no final response for chat {} because a tool already delivered the user-visible output",
                    chat_id
                );
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
            if let Some((task, account, typing_ticket)) = typing_state {
                task.abort();
                let _ = send_typing(
                    &reqwest::Client::new(),
                    &account,
                    sender,
                    &typing_ticket,
                    TYPING_STATUS_CANCEL,
                )
                .await;
            }
            error!("OpenClaw Weixin: error processing message: {e}");
        }
    }
}

async fn start_native_poll_loop(
    app_state: Arc<AppState>,
    runtime: WeixinRuntimeContext,
    account: NativeWeixinAccount,
) {
    let client = reqwest::Client::new();
    let mut get_updates_buf = load_sync_buf(&runtime.state_root, &runtime.local_account_key);
    let mut next_timeout_ms = LONG_POLL_TIMEOUT_MS;
    let mut consecutive_failures = 0usize;

    hydrate_context_token_cache(&runtime);
    info!(
        "OpenClaw Weixin native polling started for '{}' (account_key={}, base_url={})",
        runtime.channel_name, runtime.local_account_key, account.base_url
    );

    loop {
        match get_updates(&client, &account, &get_updates_buf, next_timeout_ms).await {
            Ok(response) => {
                let errcode = response.errcode.unwrap_or(0);
                if response.ret != 0 || errcode != 0 {
                    if response.ret == SESSION_EXPIRED_ERRCODE || errcode == SESSION_EXPIRED_ERRCODE
                    {
                        error!(
                            "OpenClaw Weixin session expired for '{}'; run `microclaw weixin login{}` again",
                            runtime.channel_name,
                            if runtime.local_account_key == "default" {
                                "".to_string()
                            } else {
                                format!(" --account {}", runtime.local_account_key)
                            }
                        );
                        tokio::time::sleep(Duration::from_millis(BACKOFF_DELAY_MS)).await;
                        continue;
                    }
                    consecutive_failures += 1;
                    warn!(
                        "OpenClaw Weixin getupdates failed for '{}': ret={} errcode={} errmsg={}",
                        runtime.channel_name,
                        response.ret,
                        errcode,
                        response.errmsg.unwrap_or_default()
                    );
                    let sleep_ms = if consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
                        consecutive_failures = 0;
                        BACKOFF_DELAY_MS
                    } else {
                        RETRY_DELAY_MS
                    };
                    tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
                    continue;
                }

                consecutive_failures = 0;
                if !response.get_updates_buf.is_empty() {
                    get_updates_buf = response.get_updates_buf.clone();
                    if let Err(err) = save_sync_buf(
                        &runtime.state_root,
                        &runtime.local_account_key,
                        &get_updates_buf,
                    ) {
                        warn!("OpenClaw Weixin: failed to save sync buf: {err}");
                    }
                }
                if let Some(timeout_ms) = response
                    .longpolling_timeout_ms
                    .filter(|timeout_ms| *timeout_ms > 0)
                {
                    next_timeout_ms = timeout_ms;
                }
                for message in response.msgs {
                    if let Some(normalized) = normalize_polled_message(&message) {
                        process_weixin_inbound_message(
                            app_state.clone(),
                            runtime.clone(),
                            normalized,
                        )
                        .await;
                    }
                }
            }
            Err(err) => {
                consecutive_failures += 1;
                warn!(
                    "OpenClaw Weixin polling error for '{}': {}",
                    runtime.channel_name, err
                );
                let sleep_ms = if consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
                    consecutive_failures = 0;
                    BACKOFF_DELAY_MS
                } else {
                    RETRY_DELAY_MS
                };
                tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
            }
        }
    }
}

pub async fn start_weixin_bot(app_state: Arc<AppState>, runtime: WeixinRuntimeContext) {
    mark_channel_started(&runtime.channel_name);
    info!(
        "OpenClaw Weixin adapter '{}' is ready",
        runtime.channel_name
    );

    let adapter = WeixinAdapter::from_runtime(&runtime);
    match adapter.load_native_account() {
        Ok(account) => {
            start_native_poll_loop(app_state, runtime, account).await;
        }
        Err(err) => {
            warn!(
                "OpenClaw Weixin '{}' polling disabled until login completes: {}",
                runtime.channel_name, err
            );
        }
    }
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
    process_weixin_inbound_message(app_state, runtime_ctx, normalized).await;
    axum::http::StatusCode::OK
}

async fn do_qr_login(runtime: &WeixinRuntimeContext) -> Result<StoredWeixinAccount, String> {
    let client = reqwest::Client::new();
    let qr = fetch_qrcode(&client, &runtime.base_url).await?;
    eprintln!();
    eprintln!("使用微信扫描以下二维码完成连接：");
    eprintln!();
    eprintln!("{}", qr.qrcode_img_content);
    eprintln!();
    eprintln!(
        "若终端无法直接显示二维码图片，请将上面的内容复制到浏览器打开，或用其他设备展示后再扫码。"
    );
    eprintln!();

    let deadline = std::time::Instant::now() + Duration::from_secs(480);
    let mut scanned_logged = false;
    while std::time::Instant::now() < deadline {
        let status = poll_qr_status(&client, &runtime.base_url, &qr.qrcode).await?;
        match status.status.as_str() {
            "wait" => {}
            "scaned" => {
                if !scanned_logged {
                    eprintln!("已扫码，请在微信中确认。");
                    scanned_logged = true;
                }
            }
            "expired" => {
                return Err("二维码已过期，请重新执行登录。".to_string());
            }
            "confirmed" => {
                if status.bot_token.trim().is_empty() || status.ilink_bot_id.trim().is_empty() {
                    return Err("登录确认后未返回完整 bot 凭据。".to_string());
                }
                return Ok(StoredWeixinAccount {
                    token: status.bot_token.trim().to_string(),
                    base_url: if status.baseurl.trim().is_empty() {
                        runtime.base_url.clone()
                    } else {
                        status.baseurl.trim().to_string()
                    },
                    remote_account_id: status.ilink_bot_id.trim().to_string(),
                    user_id: status.ilink_user_id.trim().to_string(),
                    saved_at: chrono::Utc::now().to_rfc3339(),
                    context_tokens: load_account_data(
                        &runtime.state_root,
                        &runtime.local_account_key,
                    )
                    .map(|stored| stored.context_tokens)
                    .unwrap_or_default(),
                });
            }
            other => {
                warn!("Unexpected Weixin QR status '{}'", other);
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Err("登录超时。".to_string())
}

pub async fn login_via_cli(
    config: &Config,
    account_id: Option<&str>,
    base_url_override: Option<&str>,
) -> Result<String, String> {
    let runtime = resolve_weixin_runtime_for_cli(config, account_id, base_url_override)?;
    let account = do_qr_login(&runtime).await?;
    save_account_data(&runtime.state_root, &runtime.local_account_key, &account)?;
    let mut summary = String::new();
    let _ = writeln!(
        summary,
        "OpenClaw Weixin login succeeded for '{}'.",
        runtime.channel_name
    );
    let _ = writeln!(summary, "Local account key: {}", runtime.local_account_key);
    let _ = writeln!(summary, "Remote account id: {}", account.remote_account_id);
    let _ = writeln!(summary, "Base URL: {}", account.base_url);
    let _ = writeln!(summary, "CDN Base URL: {}", runtime.cdn_base_url);
    if !account.user_id.trim().is_empty() {
        let _ = writeln!(summary, "Linked user id: {}", account.user_id);
    }
    Ok(summary.trim().to_string())
}

pub fn status_via_cli(config: &Config, account_id: Option<&str>) -> Result<String, String> {
    let runtime = resolve_weixin_runtime_for_cli(config, account_id, None)?;
    let stored = load_account_data(&runtime.state_root, &runtime.local_account_key);
    let sync_buf = load_sync_buf(&runtime.state_root, &runtime.local_account_key);
    let mut out = String::new();
    let _ = writeln!(out, "Channel: {}", runtime.channel_name);
    let _ = writeln!(out, "Base URL: {}", runtime.base_url);
    let _ = writeln!(out, "CDN Base URL: {}", runtime.cdn_base_url);
    let _ = writeln!(
        out,
        "Native polling active when started: {}",
        stored_account_exists(&runtime.state_root, &runtime.local_account_key)
    );
    match stored {
        Some(account) => {
            let _ = writeln!(out, "Credentials: yes");
            let _ = writeln!(
                out,
                "Remote account id: {}",
                if account.remote_account_id.trim().is_empty() {
                    "(unknown)"
                } else {
                    account.remote_account_id.trim()
                }
            );
            let _ = writeln!(
                out,
                "Saved at: {}",
                if account.saved_at.trim().is_empty() {
                    "(unknown)"
                } else {
                    account.saved_at.trim()
                }
            );
            let _ = writeln!(
                out,
                "Cached context tokens: {}",
                account.context_tokens.len()
            );
        }
        None => {
            let _ = writeln!(out, "Credentials: no");
        }
    }
    let _ = writeln!(out, "Sync buf bytes: {}", sync_buf.len());
    Ok(out.trim().to_string())
}

pub fn logout_via_cli(config: &Config, account_id: Option<&str>) -> Result<String, String> {
    let runtime = resolve_weixin_runtime_for_cli(config, account_id, None)?;
    delete_account_data(&runtime.state_root, &runtime.local_account_key)?;
    Ok(format!(
        "Removed OpenClaw Weixin credentials for '{}'.",
        runtime.channel_name
    ))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::config::Config;
    use axum::http::{HeaderMap, HeaderValue};
    use microclaw_channels::channel_adapter::ChannelAdapter;

    fn unique_temp_dir() -> PathBuf {
        let root = std::env::temp_dir().join(format!("mc_weixin_test_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn test_build_weixin_runtime_contexts_with_default_account() {
        let mut cfg: Config = serde_yaml::from_str("{}").unwrap();
        cfg.bot_username = "assistant".to_string();
        cfg.data_dir = unique_temp_dir().to_string_lossy().to_string();
        cfg.channels = serde_yaml::from_str(
            r#"
weixin:
  enabled: true
  base_url: https://example.invalid
  default_account: ops
  accounts:
    main:
      enabled: true
      allowed_user_ids: "alice,bob"
    ops:
      enabled: true
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
        assert_eq!(default_runtime.bot_username, "ops-bot");
        assert_eq!(default_runtime.model.as_deref(), Some("gpt-4.1"));
        assert_eq!(default_runtime.cdn_base_url, DEFAULT_CDN_BASE_URL);

        let secondary = runtimes
            .iter()
            .find(|runtime| runtime.channel_name == "weixin.main")
            .unwrap();
        assert_eq!(secondary.account_id, "main");
        assert_eq!(secondary.allowed_user_ids, vec!["alice", "bob"]);

        let _ = fs::remove_dir_all(cfg.data_dir);
    }

    #[test]
    fn test_select_runtime_context_uses_payload_account_id() {
        let mut cfg: Config = serde_yaml::from_str("{}").unwrap();
        cfg.data_dir = unique_temp_dir().to_string_lossy().to_string();
        cfg.channels = serde_yaml::from_str(
            r#"
weixin:
  enabled: true
  default_account: main
  accounts:
    main:
      enabled: true
    side:
      enabled: true
"#,
        )
        .unwrap();
        let runtimes = build_weixin_runtime_contexts(&cfg);
        let selected = select_runtime_context(&runtimes, "side").unwrap();
        assert_eq!(selected.channel_name, "weixin.side");
        assert!(select_runtime_context(&runtimes, "missing").is_none());
        let _ = fs::remove_dir_all(cfg.data_dir);
    }

    #[tokio::test]
    async fn test_weixin_adapter_rejects_missing_context_token() {
        let root = unique_temp_dir();
        let runtime = WeixinRuntimeContext {
            channel_name: "weixin.test".to_string(),
            account_id: String::new(),
            local_account_key: "default".to_string(),
            allowed_user_ids: Vec::new(),
            webhook_token: String::new(),
            bot_username: "bot".to_string(),
            model: None,
            base_url: DEFAULT_BASE_URL.to_string(),
            cdn_base_url: DEFAULT_CDN_BASE_URL.to_string(),
            state_root: root.clone(),
        };
        let adapter = WeixinAdapter::from_runtime(&runtime);
        let err = adapter
            .send_text("user@im.wechat", "hello")
            .await
            .unwrap_err();
        assert!(err.contains("context_token"));
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
            message: Some(WeixinWireMessage {
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
                message_type: Some(MSG_TYPE_USER),
                message_state: None,
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
    fn test_normalize_polled_message_filters_non_user_messages() {
        let message = WeixinWireMessage {
            from_user_id: "bot@im.wechat".to_string(),
            message_id: Some(FlexibleId::Integer(5)),
            create_time_ms: Some(1),
            context_token: "ctx".to_string(),
            item_list: vec![WeixinWebhookMessageItem {
                r#type: 1,
                text_item: Some(WeixinWebhookTextItem {
                    text: "ignored".to_string(),
                }),
                ..Default::default()
            }],
            message_type: Some(MSG_TYPE_BOT),
            message_state: Some(MSG_STATE_FINISH),
        };
        assert!(normalize_polled_message(&message).is_none());
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
            "x-weixin-webhook-token",
            HeaderValue::from_static("header-token"),
        );
        assert_eq!(provided_weixin_webhook_token(&headers), "header-token");
    }

    #[test]
    fn test_account_state_roundtrip_persists_context_tokens() {
        let root = unique_temp_dir();
        let runtime = WeixinRuntimeContext {
            channel_name: CHANNEL_KEY.to_string(),
            account_id: String::new(),
            local_account_key: "default".to_string(),
            allowed_user_ids: Vec::new(),
            webhook_token: String::new(),
            bot_username: "bot".to_string(),
            model: None,
            base_url: DEFAULT_BASE_URL.to_string(),
            cdn_base_url: DEFAULT_CDN_BASE_URL.to_string(),
            state_root: root.clone(),
        };
        persist_context_token(&runtime, "alice@im.wechat", "ctx-a").unwrap();
        persist_context_token(&runtime, "bob@im.wechat", "ctx-b").unwrap();

        let stored = load_account_data(&root, "default").unwrap();
        assert_eq!(
            stored
                .context_tokens
                .get("alice@im.wechat")
                .map(String::as_str),
            Some("ctx-a")
        );
        assert_eq!(
            resolve_context_token_from_store(&root, "default", CHANNEL_KEY, "bob@im.wechat")
                .as_deref(),
            Some("ctx-b")
        );

        let _ = fs::remove_dir_all(root);
    }
}
