use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tracing::{error, info, warn};

use crate::agent_engine::process_with_agent_with_events;
use crate::agent_engine::AgentEvent;
use crate::agent_engine::AgentRequestContext;
use crate::chat_commands::handle_chat_command;
use crate::chat_commands::maybe_handle_plugin_command;
use crate::runtime::AppState;
use crate::setup_def::{ChannelFieldDef, DynamicChannelDef};
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
            label: "Slack bot token (xoxb-...)",
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
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
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
        runtimes.push(SlackRuntimeContext {
            channel_name,
            app_token: account_cfg.app_token.clone(),
            bot_token: account_cfg.bot_token.clone(),
            allowed_channels: account_cfg.allowed_channels.clone(),
            bot_username,
            model,
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
        for chunk in split_text(text, 4000) {
            let body = serde_json::json!({
                "channel": external_chat_id,
                "text": chunk,
            });
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
        let filename = file_path
            .file_name()
            .and_then(|v| v.to_str())
            .unwrap_or("attachment.bin")
            .to_string();
        let bytes = tokio::fs::read(file_path)
            .await
            .map_err(|e| format!("Failed to read attachment file: {e}"))?;

        let form = reqwest::multipart::Form::new()
            .text("channels", external_chat_id.to_string())
            .text("initial_comment", caption.unwrap_or_default().to_string())
            .part(
                "file",
                reqwest::multipart::Part::bytes(bytes).file_name(filename),
            );

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
async fn send_slack_response(bot_token: &str, channel: &str, text: &str) -> Result<(), String> {
    let client = reqwest::Client::new();
    const MAX_LEN: usize = 4000;

    let chunks = split_text(text, MAX_LEN);
    for chunk in chunks {
        let body = serde_json::json!({
            "channel": channel,
            "text": chunk,
        });
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
}

pub async fn start_slack_bot(app_state: Arc<AppState>, runtime: SlackRuntimeContext) {
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

                    if event_type == "message" || event_type == "app_mention" {
                        let event = &envelope["payload"]["event"];

                        // Skip bot messages, message_changed, etc.
                        if event.get("subtype").is_some() {
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
                        let ts = event
                            .get("ts")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();

                        if channel.is_empty() || text_content.is_empty() {
                            continue;
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
                                &ts,
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
    ts: &str,
) {
    let chat_type = if is_dm { "slack_dm" } else { "slack" };
    let title = format!("slack-{channel}");

    let chat_id = call_blocking(app_state.db.clone(), {
        let channel = channel.to_string();
        let title = title.clone();
        let chat_type = chat_type.to_string();
        let channel_name = runtime.channel_name.clone();
        move |db| db.resolve_or_create_chat_id(&channel_name, &channel, Some(&title), &chat_type)
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
        None
    } else {
        Some(ts.to_string())
    };
    if let Some(inbound_message_id) = inbound_message_id.as_deref() {
        let already_seen = call_blocking(app_state.db.clone(), {
            let inbound_message_id = inbound_message_id.to_string();
            move |db| db.message_exists(chat_id, &inbound_message_id)
        })
        .await
        .unwrap_or(false);
        if already_seen {
            info!(
                "Slack: skipping duplicate message chat_id={} message_id={}",
                chat_id, inbound_message_id
            );
            return;
        }
    }

    // Store incoming message
    let stored = StoredMessage {
        id: if let Some(inbound_message_id) = inbound_message_id {
            inbound_message_id
        } else {
            uuid::Uuid::new_v4().to_string()
        },
        chat_id,
        sender_name: user.to_string(),
        content: text.to_string(),
        is_from_bot: false,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };
    let _ = call_blocking(app_state.db.clone(), move |db| db.store_message(&stored)).await;

    let trimmed = text.trim();
    if trimmed.starts_with('/') {
        if let Some(reply) =
            handle_chat_command(&app_state, chat_id, &runtime.channel_name, trimmed).await
        {
            let _ = send_slack_response(bot_token, channel, &reply).await;
            return;
        }
    }
    if let Some(plugin_response) =
        maybe_plugin_slash_response(&app_state.config, trimmed, chat_id, &runtime.channel_name)
            .await
    {
        let _ = send_slack_response(bot_token, channel, &plugin_response).await;
        return;
    }

    // Determine if we should respond
    let mention_tag = format!("<@{bot_user_id}>");
    let should_respond = is_dm || is_app_mention || text.contains(&mention_tag);

    if !should_respond {
        return;
    }

    info!(
        "Slack message from {} in {}: {}",
        user,
        channel,
        text.chars().take(100).collect::<String>()
    );

    let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel::<AgentEvent>();

    match process_with_agent_with_events(
        &app_state,
        AgentRequestContext {
            caller_channel: &runtime.channel_name,
            chat_id,
            chat_type: if is_dm { "private" } else { "group" },
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
                        "Slack: suppressing final response for chat {} because send_message already delivered output",
                        chat_id
                    );
                }
            } else if !response.is_empty() {
                if let Err(e) = send_slack_response(bot_token, channel, &response).await {
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
                let _ = send_slack_response(bot_token, channel, fallback).await;

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
            let _ = send_slack_response(bot_token, channel, &format!("Error: {e}")).await;
        }
    }
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
}
