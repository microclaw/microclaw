use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use serde::Deserialize;
use serde_json::Value;
use tracing::{error, info, warn};

use crate::agent_engine::archive_conversation;
use crate::agent_engine::process_with_agent_with_events;
use crate::agent_engine::AgentEvent;
use crate::agent_engine::AgentRequestContext;
use crate::runtime::AppState;
use microclaw_channels::channel::ConversationKind;
use microclaw_channels::channel_adapter::ChannelAdapter;
use microclaw_core::llm_types::Message as LlmMessage;
use microclaw_core::text::split_text;
use microclaw_storage::db::call_blocking;
use microclaw_storage::db::StoredMessage;
use microclaw_storage::usage::build_usage_report;

fn default_enabled() -> bool {
    true
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
    pub bot_username: String,
    #[serde(default = "default_matrix_mention_required")]
    pub mention_required: bool,
    #[serde(default = "default_matrix_sync_timeout_ms")]
    pub sync_timeout_ms: u64,
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
    pub bot_username: String,
    #[serde(default = "default_matrix_mention_required")]
    pub mention_required: bool,
    #[serde(default = "default_matrix_sync_timeout_ms")]
    pub sync_timeout_ms: u64,
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
    pub mention_required: bool,
    pub sync_timeout_ms: u64,
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

    fn should_process_room(&self, room_id: &str) -> bool {
        self.allowed_room_ids.is_empty() || self.allowed_room_ids.iter().any(|v| v == room_id)
    }

    fn bot_localpart(&self) -> String {
        let user = self.bot_user_id.trim();
        if let Some(rest) = user.strip_prefix('@') {
            return rest.split(':').next().unwrap_or(rest).to_string();
        }
        user.to_string()
    }

    fn should_respond(&self, text: &str, mentioned: bool) -> bool {
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
            mention_required: account_cfg.mention_required,
            sync_timeout_ms: account_cfg.sync_timeout_ms,
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
            mention_required: matrix_cfg.mention_required,
            sync_timeout_ms: matrix_cfg.sync_timeout_ms,
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
        send_matrix_text(
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
        send_matrix_attachment(
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
        sender: String,
        event_id: String,
        body: String,
        mentioned_bot: bool,
    },
    Reaction {
        room_id: String,
        sender: String,
        event_id: String,
        relates_to_event_id: String,
        key: String,
    },
}

pub async fn start_matrix_bot(app_state: Arc<AppState>, runtime: MatrixRuntimeContext) {
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
                                sender,
                                event_id,
                                body,
                                mentioned_bot,
                            } => {
                                let msg = MatrixIncomingMessage {
                                    room_id,
                                    sender,
                                    event_id,
                                    body,
                                    mentioned_bot,
                                };
                                handle_matrix_message(state, runtime_ctx, msg).await;
                            }
                            MatrixIncomingEvent::Reaction {
                                room_id,
                                sender,
                                event_id,
                                relates_to_event_id,
                                key,
                            } => {
                                handle_matrix_reaction(
                                    state,
                                    runtime_ctx,
                                    room_id,
                                    sender,
                                    event_id,
                                    relates_to_event_id,
                                    key,
                                )
                                .await;
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

    let joined_rooms = payload
        .pointer("/rooms/join")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();

    for (room_id, room_data) in joined_rooms {
        if !runtime.should_process_room(&room_id) {
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
                    sender,
                    event_id,
                    body,
                    mentioned_bot,
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
                    sender,
                    event_id,
                    relates_to_event_id,
                    key,
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

struct MatrixIncomingMessage {
    room_id: String,
    sender: String,
    event_id: String,
    body: String,
    mentioned_bot: bool,
}

async fn resolve_matrix_chat_id(
    app_state: Arc<AppState>,
    runtime: &MatrixRuntimeContext,
    room_id: &str,
) -> i64 {
    call_blocking(app_state.db.clone(), {
        let room = room_id.to_string();
        let title = format!("matrix-{}", room_id);
        let chat_type = "matrix".to_string();
        let channel_name = runtime.channel_name.clone();
        move |db| db.resolve_or_create_chat_id(&channel_name, &room, Some(&title), &chat_type)
    })
    .await
    .unwrap_or(0)
}

async fn handle_matrix_reaction(
    app_state: Arc<AppState>,
    runtime: MatrixRuntimeContext,
    room_id: String,
    sender: String,
    event_id: String,
    relates_to_event_id: String,
    key: String,
) {
    let chat_id = resolve_matrix_chat_id(app_state.clone(), &runtime, &room_id).await;
    if chat_id == 0 {
        error!("Matrix: failed to resolve chat ID for room {}", room_id);
        return;
    }

    let reaction_text = format!(
        "[reaction] {} reacted {} to {}",
        sender, key, relates_to_event_id
    );
    let incoming = StoredMessage {
        id: if event_id.trim().is_empty() {
            uuid::Uuid::new_v4().to_string()
        } else {
            event_id
        },
        chat_id,
        sender_name: sender,
        content: reaction_text,
        is_from_bot: false,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };
    let _ = call_blocking(app_state.db.clone(), move |db| db.store_message(&incoming)).await;
}

async fn handle_matrix_message(
    app_state: Arc<AppState>,
    runtime: MatrixRuntimeContext,
    msg: MatrixIncomingMessage,
) {
    let chat_id = resolve_matrix_chat_id(app_state.clone(), &runtime, &msg.room_id).await;

    if chat_id == 0 {
        error!("Matrix: failed to resolve chat ID for room {}", msg.room_id);
        return;
    }

    let client = reqwest::Client::new();

    let incoming = StoredMessage {
        id: if msg.event_id.trim().is_empty() {
            uuid::Uuid::new_v4().to_string()
        } else {
            msg.event_id.clone()
        },
        chat_id,
        sender_name: msg.sender.clone(),
        content: msg.body.clone(),
        is_from_bot: false,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };
    let _ = call_blocking(app_state.db.clone(), move |db| db.store_message(&incoming)).await;

    let trimmed = msg.body.trim();
    let should_respond = runtime.should_respond(&msg.body, msg.mentioned_bot);
    if trimmed == "/reset" {
        let _ = call_blocking(app_state.db.clone(), move |db| {
            db.clear_chat_context(chat_id)
        })
        .await;
        let _ = send_matrix_text(
            &client,
            &runtime.homeserver_url,
            &runtime.access_token,
            &msg.room_id,
            "Context cleared (session + chat history).",
        )
        .await;
        return;
    }

    if trimmed == "/skills" {
        let formatted = app_state.skills.list_skills_formatted();
        let _ = send_matrix_text(
            &client,
            &runtime.homeserver_url,
            &runtime.access_token,
            &msg.room_id,
            &formatted,
        )
        .await;
        return;
    }

    if trimmed == "/reload-skills" {
        let reloaded = app_state.skills.reload();
        let text = format!("Reloaded {} skills from disk.", reloaded.len());
        let _ = send_matrix_text(
            &client,
            &runtime.homeserver_url,
            &runtime.access_token,
            &msg.room_id,
            &text,
        )
        .await;
        return;
    }

    if trimmed == "/archive" {
        if let Ok(Some((json, _))) =
            call_blocking(app_state.db.clone(), move |db| db.load_session(chat_id)).await
        {
            let messages: Vec<LlmMessage> = serde_json::from_str(&json).unwrap_or_default();
            if messages.is_empty() {
                let _ = send_matrix_text(
                    &client,
                    &runtime.homeserver_url,
                    &runtime.access_token,
                    &msg.room_id,
                    "No session to archive.",
                )
                .await;
            } else {
                archive_conversation(
                    &app_state.config.data_dir,
                    &runtime.channel_name,
                    chat_id,
                    &messages,
                );
                let _ = send_matrix_text(
                    &client,
                    &runtime.homeserver_url,
                    &runtime.access_token,
                    &msg.room_id,
                    &format!("Archived {} messages.", messages.len()),
                )
                .await;
            }
        } else {
            let _ = send_matrix_text(
                &client,
                &runtime.homeserver_url,
                &runtime.access_token,
                &msg.room_id,
                "No session to archive.",
            )
            .await;
        }
        return;
    }

    if trimmed == "/usage" {
        match build_usage_report(app_state.db.clone(), chat_id).await {
            Ok(report) => {
                let _ = send_matrix_text(
                    &client,
                    &runtime.homeserver_url,
                    &runtime.access_token,
                    &msg.room_id,
                    &report,
                )
                .await;
            }
            Err(e) => {
                let _ = send_matrix_text(
                    &client,
                    &runtime.homeserver_url,
                    &runtime.access_token,
                    &msg.room_id,
                    &format!("Failed to query usage statistics: {e}"),
                )
                .await;
            }
        }
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
            chat_type: "group",
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

            if !response.is_empty() {
                if let Some(reaction_key) = looks_like_reaction_token(&response) {
                    if !msg.event_id.trim().is_empty() {
                        if let Err(e) = send_matrix_reaction(
                            &client,
                            &runtime.homeserver_url,
                            &runtime.access_token,
                            &msg.room_id,
                            &msg.event_id,
                            &reaction_key,
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

                if let Err(e) = send_matrix_text(
                    &client,
                    &runtime.homeserver_url,
                    &runtime.access_token,
                    &msg.room_id,
                    &response,
                )
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
            } else if !used_send_message_tool {
                let fallback =
                    "I couldn't produce a visible reply after an automatic retry. Please try again.";
                let _ = send_matrix_text(
                    &client,
                    &runtime.homeserver_url,
                    &runtime.access_token,
                    &msg.room_id,
                    fallback,
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
                    call_blocking(app_state.db.clone(), move |db| db.store_message(&bot_msg)).await;
            }
        }
        Err(e) => {
            error!("Error processing Matrix message: {e}");
            let _ = send_matrix_text(
                &client,
                &runtime.homeserver_url,
                &runtime.access_token,
                &msg.room_id,
                &format!("Error: {e}"),
            )
            .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        extract_matrix_user_ids, looks_like_reaction_token, matrix_message_payload_for_text,
        normalize_matrix_message_body, MatrixRuntimeContext,
    };
    use serde_json::json;

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
            mention_required: true,
            sync_timeout_ms: 30_000,
        };

        assert!(runtime.should_respond("hello there", true));
        assert!(!runtime.should_respond("hello there", false));
    }
}
