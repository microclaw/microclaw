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
    should_drop_pre_start_message, should_drop_recent_duplicate_message,
};
use crate::chat_commands::{handle_chat_command, is_slash_command, unknown_command_response};
use crate::runtime::AppState;
use crate::setup_def::{ChannelFieldDef, DynamicChannelDef};
use microclaw_channels::channel::ConversationKind;
use microclaw_channels::channel_adapter::ChannelAdapter;
use microclaw_storage::db::{call_blocking, StoredMessage};

pub const SETUP_DEF: DynamicChannelDef = DynamicChannelDef {
    name: "qq",
    presence_keys: &["send_command"],
    fields: &[
        ChannelFieldDef {
            yaml_key: "send_command",
            label: "QQ send command (env MICROCLAW_QQ_TARGET/TEXT)",
            default: "",
            secret: false,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "webhook_path",
            label: "QQ webhook path (default /qq/events)",
            default: "/qq/events",
            secret: false,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "webhook_token",
            label: "QQ webhook token (optional)",
            default: "",
            secret: true,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "allowed_user_ids",
            label: "QQ allowed user ids csv (optional)",
            default: "",
            secret: false,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "bot_username",
            label: "QQ bot username override (optional)",
            default: "",
            secret: false,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "model",
            label: "QQ bot model override (optional)",
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
    "/qq/events".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct QQAccountConfig {
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
pub struct QQChannelConfig {
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
    pub accounts: HashMap<String, QQAccountConfig>,
    #[serde(default)]
    pub default_account: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct QQWebhookPayload {
    user_id: String,
    text: String,
    #[serde(default)]
    message_id: String,
    #[serde(default)]
    timestamp: Option<String>,
    #[serde(default)]
    timestamp_ms: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct QQRuntimeContext {
    pub channel_name: String,
    pub send_command: String,
    pub allowed_user_ids: Vec<String>,
    pub webhook_token: String,
    pub bot_username: String,
    pub model: Option<String>,
}

fn pick_default_account_id(
    configured: Option<&str>,
    accounts: &HashMap<String, QQAccountConfig>,
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

pub fn build_qq_runtime_contexts(config: &crate::config::Config) -> Vec<QQRuntimeContext> {
    let Some(qq_cfg) = config.channel_config::<QQChannelConfig>("qq") else {
        return Vec::new();
    };
    let mut runtimes = Vec::new();
    let default_account =
        pick_default_account_id(qq_cfg.default_account.as_deref(), &qq_cfg.accounts);
    let mut account_ids: Vec<String> = qq_cfg.accounts.keys().cloned().collect();
    account_ids.sort();
    for account_id in account_ids {
        let Some(account_cfg) = qq_cfg.accounts.get(&account_id) else {
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
            "qq".to_string()
        } else {
            format!("qq.{account_id}")
        };
        let send_command = if account_cfg.send_command.trim().is_empty() {
            qq_cfg.send_command.trim().to_string()
        } else {
            account_cfg.send_command.trim().to_string()
        };
        let webhook_token = if account_cfg.webhook_token.trim().is_empty() {
            qq_cfg.webhook_token.trim().to_string()
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
        runtimes.push(QQRuntimeContext {
            channel_name,
            send_command,
            allowed_user_ids: parse_csv(&account_cfg.allowed_user_ids),
            webhook_token,
            bot_username,
            model,
        });
    }
    if runtimes.is_empty() {
        runtimes.push(QQRuntimeContext {
            channel_name: "qq".to_string(),
            send_command: qq_cfg.send_command.trim().to_string(),
            allowed_user_ids: parse_csv(&qq_cfg.allowed_user_ids),
            webhook_token: qq_cfg.webhook_token.trim().to_string(),
            bot_username: config.bot_username_for_channel("qq"),
            model: qq_cfg
                .model
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(ToOwned::to_owned),
        });
    }
    runtimes
}

pub struct QQAdapter {
    name: String,
    send_command: String,
}

impl QQAdapter {
    pub fn new(name: String, send_command: String) -> Self {
        Self { name, send_command }
    }
}

#[async_trait::async_trait]
impl ChannelAdapter for QQAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn chat_type_routes(&self) -> Vec<(&str, ConversationKind)> {
        vec![("qq_dm", ConversationKind::Private)]
    }

    async fn send_text(&self, external_chat_id: &str, text: &str) -> Result<(), String> {
        if self.send_command.trim().is_empty() {
            return Err("qq.send_command is empty".to_string());
        }
        let output = Command::new("sh")
            .arg("-lc")
            .arg(self.send_command.trim())
            .env("MICROCLAW_QQ_TARGET", external_chat_id)
            .env("MICROCLAW_QQ_TEXT", text)
            .output()
            .map_err(|e| format!("Failed running qq send command: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "qq send command failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        Ok(())
    }
}

pub async fn start_qq_bot(_app_state: Arc<AppState>, runtime: QQRuntimeContext) {
    mark_channel_started(&runtime.channel_name);
    info!("QQ adapter '{}' is ready", runtime.channel_name);
}

pub fn register_qq_webhook(router: Router, app_state: Arc<AppState>) -> Router {
    let Some(cfg) = app_state.config.channel_config::<QQChannelConfig>("qq") else {
        return router;
    };
    if !app_state.config.channel_enabled("qq") {
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
            move |headers: HeaderMap, Json(payload): Json<QQWebhookPayload>| {
                let state = state_for_post.clone();
                async move { qq_webhook_handler(state, headers, payload).await }
            },
        ),
    )
}

async fn qq_webhook_handler(
    app_state: Arc<AppState>,
    headers: HeaderMap,
    payload: QQWebhookPayload,
) -> impl axum::response::IntoResponse {
    let runtime_contexts = build_qq_runtime_contexts(&app_state.config);
    let Some(runtime_ctx) = runtime_contexts.first().cloned() else {
        return axum::http::StatusCode::NOT_FOUND;
    };
    let provided_token = headers
        .get("x-qq-webhook-token")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .unwrap_or("");
    if !runtime_ctx.webhook_token.trim().is_empty()
        && runtime_ctx.webhook_token.trim() != provided_token
    {
        return axum::http::StatusCode::FORBIDDEN;
    }
    let user_id = payload.user_id.trim();
    let text = payload.text.trim();
    if user_id.is_empty() || text.is_empty() {
        return axum::http::StatusCode::BAD_REQUEST;
    }
    if !runtime_ctx.allowed_user_ids.is_empty()
        && !runtime_ctx.allowed_user_ids.iter().any(|n| n == user_id)
    {
        return axum::http::StatusCode::FORBIDDEN;
    }
    let external_chat_id = user_id.to_string();
    let chat_id = call_blocking(app_state.db.clone(), {
        let channel_name = runtime_ctx.channel_name.clone();
        let title = format!("qq-{external_chat_id}");
        let external_chat_id = external_chat_id.clone();
        move |db| {
            db.resolve_or_create_chat_id(&channel_name, &external_chat_id, Some(&title), "qq_dm")
        }
    })
    .await
    .unwrap_or(0);
    if chat_id == 0 {
        return axum::http::StatusCode::INTERNAL_SERVER_ERROR;
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
            Some(user_id),
        )
        .await
        {
            let adapter = QQAdapter::new(
                runtime_ctx.channel_name.clone(),
                runtime_ctx.send_command.clone(),
            );
            let _ = adapter.send_text(user_id, &reply).await;
            return axum::http::StatusCode::OK;
        }
        let adapter = QQAdapter::new(
            runtime_ctx.channel_name.clone(),
            runtime_ctx.send_command.clone(),
        );
        let _ = adapter
            .send_text(user_id, &unknown_command_response())
            .await;
        return axum::http::StatusCode::OK;
    }
    let stored = StoredMessage {
        id: inbound_message_id.clone(),
        chat_id,
        sender_name: user_id.to_string(),
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
            "QQ: skipping duplicate message chat_id={} message_id={}",
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
                if let AgentEvent::ToolStart { name } = event {
                    if name == "send_message" {
                        used_send_message_tool = true;
                    }
                }
            }
            let adapter = QQAdapter::new(
                runtime_ctx.channel_name.clone(),
                runtime_ctx.send_command.clone(),
            );
            if used_send_message_tool {
                if !response.is_empty() {
                    info!(
                        "QQ: suppressing final response for chat {} because send_message already delivered output",
                        chat_id
                    );
                }
            } else if !response.is_empty() {
                if let Err(e) = adapter.send_text(user_id, &response).await {
                    error!("QQ: failed to send response: {e}");
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
                        user_id,
                        "I couldn't produce a visible reply after an automatic retry. Please try again.",
                    )
                    .await;
            }
        }
        Err(e) => {
            error!("QQ: error processing message: {e}");
        }
    }
    axum::http::StatusCode::OK
}
