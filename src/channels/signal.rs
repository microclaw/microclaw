use std::collections::HashMap;
use std::process::Command;
use std::sync::Arc;

use axum::http::HeaderMap;
use axum::{Json, Router};
use serde::Deserialize;
use tracing::{error, info};

use crate::agent_engine::process_with_agent_with_events;
use crate::agent_engine::{AgentEvent, AgentRequestContext};
use crate::channels::startup_guard::{
    mark_channel_started, parse_epoch_ms_from_seconds_str, parse_epoch_ms_from_str,
    should_drop_pre_start_message,
};
use crate::chat_commands::{handle_chat_command, is_slash_command, unknown_command_response};
use crate::runtime::AppState;
use crate::setup_def::{ChannelFieldDef, DynamicChannelDef};
use microclaw_channels::channel::ConversationKind;
use microclaw_channels::channel_adapter::ChannelAdapter;
use microclaw_storage::db::{call_blocking, StoredMessage};

pub const SETUP_DEF: DynamicChannelDef = DynamicChannelDef {
    name: "signal",
    presence_keys: &["send_command"],
    fields: &[
        ChannelFieldDef {
            yaml_key: "send_command",
            label: "Signal send command (env MICROCLAW_SIGNAL_TARGET/TEXT)",
            default: "",
            secret: false,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "webhook_path",
            label: "Signal webhook path (default /signal/messages)",
            default: "/signal/messages",
            secret: false,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "webhook_token",
            label: "Signal webhook token (optional)",
            default: "",
            secret: true,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "allowed_numbers",
            label: "Signal allowed numbers csv (optional)",
            default: "",
            secret: false,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "bot_username",
            label: "Signal bot username override (optional)",
            default: "",
            secret: false,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "model",
            label: "Signal bot model override (optional)",
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
    "/signal/messages".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct SignalAccountConfig {
    #[serde(default)]
    pub send_command: String,
    #[serde(default)]
    pub allowed_numbers: String,
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
pub struct SignalChannelConfig {
    #[serde(default)]
    pub send_command: String,
    #[serde(default)]
    pub allowed_numbers: String,
    #[serde(default = "default_webhook_path")]
    pub webhook_path: String,
    #[serde(default)]
    pub webhook_token: String,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub accounts: HashMap<String, SignalAccountConfig>,
    #[serde(default)]
    pub default_account: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct SignalWebhookPayload {
    sender: String,
    text: String,
    #[serde(default)]
    message_id: String,
    #[serde(default)]
    timestamp_ms: Option<i64>,
    #[serde(default)]
    timestamp: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SignalRuntimeContext {
    pub channel_name: String,
    pub send_command: String,
    pub allowed_numbers: Vec<String>,
    pub webhook_token: String,
    pub bot_username: String,
    pub model: Option<String>,
}

fn pick_default_account_id(
    configured: Option<&str>,
    accounts: &HashMap<String, SignalAccountConfig>,
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

pub fn build_signal_runtime_contexts(config: &crate::config::Config) -> Vec<SignalRuntimeContext> {
    let Some(sig_cfg) = config.channel_config::<SignalChannelConfig>("signal") else {
        return Vec::new();
    };
    let mut runtimes = Vec::new();
    let default_account =
        pick_default_account_id(sig_cfg.default_account.as_deref(), &sig_cfg.accounts);
    let mut account_ids: Vec<String> = sig_cfg.accounts.keys().cloned().collect();
    account_ids.sort();
    for account_id in account_ids {
        let Some(account_cfg) = sig_cfg.accounts.get(&account_id) else {
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
            "signal".to_string()
        } else {
            format!("signal.{account_id}")
        };
        let send_command = if account_cfg.send_command.trim().is_empty() {
            sig_cfg.send_command.trim().to_string()
        } else {
            account_cfg.send_command.trim().to_string()
        };
        let webhook_token = if account_cfg.webhook_token.trim().is_empty() {
            sig_cfg.webhook_token.trim().to_string()
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
        runtimes.push(SignalRuntimeContext {
            channel_name,
            send_command,
            allowed_numbers: parse_csv(&account_cfg.allowed_numbers),
            webhook_token,
            bot_username,
            model,
        });
    }
    if runtimes.is_empty() {
        runtimes.push(SignalRuntimeContext {
            channel_name: "signal".to_string(),
            send_command: sig_cfg.send_command.trim().to_string(),
            allowed_numbers: parse_csv(&sig_cfg.allowed_numbers),
            webhook_token: sig_cfg.webhook_token.trim().to_string(),
            bot_username: config.bot_username_for_channel("signal"),
            model: sig_cfg
                .model
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(ToOwned::to_owned),
        });
    }
    runtimes
}

pub struct SignalAdapter {
    name: String,
    send_command: String,
}

impl SignalAdapter {
    pub fn new(name: String, send_command: String) -> Self {
        Self { name, send_command }
    }
}

#[async_trait::async_trait]
impl ChannelAdapter for SignalAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn chat_type_routes(&self) -> Vec<(&str, ConversationKind)> {
        vec![("signal_dm", ConversationKind::Private)]
    }

    async fn send_text(&self, external_chat_id: &str, text: &str) -> Result<(), String> {
        if self.send_command.trim().is_empty() {
            return Err("signal.send_command is empty".to_string());
        }
        let output = Command::new("sh")
            .arg("-lc")
            .arg(self.send_command.trim())
            .env("MICROCLAW_SIGNAL_TARGET", external_chat_id)
            .env("MICROCLAW_SIGNAL_TEXT", text)
            .output()
            .map_err(|e| format!("Failed running signal send command: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "signal send command failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        Ok(())
    }
}

pub async fn start_signal_bot(_app_state: Arc<AppState>, runtime: SignalRuntimeContext) {
    mark_channel_started(&runtime.channel_name);
    info!("Signal adapter '{}' is ready", runtime.channel_name);
}

pub fn register_signal_webhook(router: Router, app_state: Arc<AppState>) -> Router {
    let Some(cfg) = app_state
        .config
        .channel_config::<SignalChannelConfig>("signal")
    else {
        return router;
    };
    if !app_state.config.channel_enabled("signal") {
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
            move |headers: HeaderMap, Json(payload): Json<SignalWebhookPayload>| {
                let state = state_for_post.clone();
                async move { signal_webhook_handler(state, headers, payload).await }
            },
        ),
    )
}

async fn signal_webhook_handler(
    app_state: Arc<AppState>,
    headers: HeaderMap,
    payload: SignalWebhookPayload,
) -> impl axum::response::IntoResponse {
    let runtime_contexts = build_signal_runtime_contexts(&app_state.config);
    let Some(runtime_ctx) = runtime_contexts.first().cloned() else {
        return axum::http::StatusCode::NOT_FOUND;
    };
    let provided_token = headers
        .get("x-signal-webhook-token")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .unwrap_or("");
    if !runtime_ctx.webhook_token.trim().is_empty()
        && runtime_ctx.webhook_token.trim() != provided_token
    {
        return axum::http::StatusCode::FORBIDDEN;
    }
    let sender = payload.sender.trim();
    let text = payload.text.trim();
    if sender.is_empty() || text.is_empty() {
        return axum::http::StatusCode::BAD_REQUEST;
    }
    if !runtime_ctx.allowed_numbers.is_empty()
        && !runtime_ctx.allowed_numbers.iter().any(|n| n == sender)
    {
        return axum::http::StatusCode::FORBIDDEN;
    }
    tokio::spawn({
        let state = app_state.clone();
        let runtime = runtime_ctx.clone();
        let payload = payload.clone();
        async move {
            process_signal_webhook_message(state, runtime, payload).await;
        }
    });
    axum::http::StatusCode::OK
}

async fn process_signal_webhook_message(
    app_state: Arc<AppState>,
    runtime_ctx: SignalRuntimeContext,
    payload: SignalWebhookPayload,
) {
    let sender = payload.sender.trim().to_string();
    let text = payload.text.trim().to_string();
    let external_chat_id = sender.to_string();
    let chat_id = call_blocking(app_state.db.clone(), {
        let channel_name = runtime_ctx.channel_name.clone();
        let title = format!("signal-{external_chat_id}");
        let external_chat_id = external_chat_id.clone();
        move |db| {
            db.resolve_or_create_chat_id(
                &channel_name,
                &external_chat_id,
                Some(&title),
                "signal_dm",
            )
        }
    })
    .await
    .unwrap_or(0);
    if chat_id == 0 {
        error!("Signal: failed to resolve chat ID for {external_chat_id}");
        return;
    }
    if is_slash_command(&text) {
        if let Some(reply) =
            handle_chat_command(&app_state, chat_id, &runtime_ctx.channel_name, &text).await
        {
            let adapter = SignalAdapter::new(
                runtime_ctx.channel_name.clone(),
                runtime_ctx.send_command.clone(),
            );
            let _ = adapter.send_text(&sender, &reply).await;
            return;
        }
        let adapter = SignalAdapter::new(
            runtime_ctx.channel_name.clone(),
            runtime_ctx.send_command.clone(),
        );
        let _ = adapter
            .send_text(&sender, &unknown_command_response())
            .await;
        return;
    }
    let inbound_message_id = if payload.message_id.trim().is_empty() {
        uuid::Uuid::new_v4().to_string()
    } else {
        payload.message_id.clone()
    };
    let inbound_ts_ms = payload.timestamp_ms.or_else(|| {
        payload
            .timestamp
            .as_deref()
            .and_then(parse_epoch_ms_from_str)
            .or_else(|| {
                payload
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
            "Signal: skipping duplicate message chat_id={} message_id={}",
            chat_id, inbound_message_id
        );
        return;
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
                if let AgentEvent::ToolStart { name } = event {
                    if name == "send_message" {
                        used_send_message_tool = true;
                    }
                }
            }
            let adapter = SignalAdapter::new(
                runtime_ctx.channel_name.clone(),
                runtime_ctx.send_command.clone(),
            );
            if used_send_message_tool {
                if !response.is_empty() {
                    info!(
                        "Signal: suppressing final response for chat {} because send_message already delivered output",
                        chat_id
                    );
                }
            } else if !response.is_empty() {
                if let Err(e) = adapter.send_text(&sender, &response).await {
                    error!("Signal: failed to send response: {e}");
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
                        &sender,
                        "I couldn't produce a visible reply after an automatic retry. Please try again.",
                    )
                    .await;
            }
        }
        Err(e) => {
            error!("Signal: error processing message: {e}");
        }
    }
}
