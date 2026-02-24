use std::collections::HashMap;
use std::sync::Arc;

use axum::http::HeaderMap;
use axum::{Json, Router};
use serde::Deserialize;
use tracing::{error, info};

use crate::agent_engine::process_with_agent_with_events;
use crate::agent_engine::{AgentEvent, AgentRequestContext};
use crate::chat_commands::{handle_chat_command, is_slash_command, unknown_command_response};
use crate::runtime::AppState;
use crate::setup_def::{ChannelFieldDef, DynamicChannelDef};
use microclaw_channels::channel::ConversationKind;
use microclaw_channels::channel_adapter::ChannelAdapter;
use microclaw_storage::db::{call_blocking, StoredMessage};

pub const SETUP_DEF: DynamicChannelDef = DynamicChannelDef {
    name: "dingtalk",
    presence_keys: &["robot_webhook_url"],
    fields: &[
        ChannelFieldDef {
            yaml_key: "robot_webhook_url",
            label: "DingTalk robot webhook URL",
            default: "",
            secret: true,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "webhook_path",
            label: "DingTalk webhook path (default /dingtalk/events)",
            default: "/dingtalk/events",
            secret: false,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "webhook_token",
            label: "DingTalk webhook token (optional)",
            default: "",
            secret: true,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "allowed_chat_ids",
            label: "DingTalk allowed chat ids csv (optional)",
            default: "",
            secret: false,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "bot_username",
            label: "DingTalk bot username override (optional)",
            default: "",
            secret: false,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "model",
            label: "DingTalk bot model override (optional)",
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
    "/dingtalk/events".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct DingTalkAccountConfig {
    #[serde(default)]
    pub robot_webhook_url: String,
    #[serde(default)]
    pub allowed_chat_ids: String,
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
pub struct DingTalkChannelConfig {
    #[serde(default)]
    pub robot_webhook_url: String,
    #[serde(default)]
    pub allowed_chat_ids: String,
    #[serde(default = "default_webhook_path")]
    pub webhook_path: String,
    #[serde(default)]
    pub webhook_token: String,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub accounts: HashMap<String, DingTalkAccountConfig>,
    #[serde(default)]
    pub default_account: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct DingTalkWebhookPayload {
    chat_id: String,
    sender_id: String,
    text: String,
    #[serde(default)]
    message_id: String,
}

#[derive(Debug, Clone)]
pub struct DingTalkRuntimeContext {
    pub channel_name: String,
    pub robot_webhook_url: String,
    pub allowed_chat_ids: Vec<String>,
    pub webhook_token: String,
    pub bot_username: String,
    pub model: Option<String>,
}

fn pick_default_account_id(
    configured: Option<&str>,
    accounts: &HashMap<String, DingTalkAccountConfig>,
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

pub fn build_dingtalk_runtime_contexts(
    config: &crate::config::Config,
) -> Vec<DingTalkRuntimeContext> {
    let Some(dt_cfg) = config.channel_config::<DingTalkChannelConfig>("dingtalk") else {
        return Vec::new();
    };
    let mut runtimes = Vec::new();
    let default_account =
        pick_default_account_id(dt_cfg.default_account.as_deref(), &dt_cfg.accounts);
    let mut account_ids: Vec<String> = dt_cfg.accounts.keys().cloned().collect();
    account_ids.sort();
    for account_id in account_ids {
        let Some(account_cfg) = dt_cfg.accounts.get(&account_id) else {
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
            "dingtalk".to_string()
        } else {
            format!("dingtalk.{account_id}")
        };
        let robot_webhook_url = if account_cfg.robot_webhook_url.trim().is_empty() {
            dt_cfg.robot_webhook_url.trim().to_string()
        } else {
            account_cfg.robot_webhook_url.trim().to_string()
        };
        let webhook_token = if account_cfg.webhook_token.trim().is_empty() {
            dt_cfg.webhook_token.trim().to_string()
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
        runtimes.push(DingTalkRuntimeContext {
            channel_name,
            robot_webhook_url,
            allowed_chat_ids: parse_csv(&account_cfg.allowed_chat_ids),
            webhook_token,
            bot_username,
            model,
        });
    }
    if runtimes.is_empty() {
        runtimes.push(DingTalkRuntimeContext {
            channel_name: "dingtalk".to_string(),
            robot_webhook_url: dt_cfg.robot_webhook_url.trim().to_string(),
            allowed_chat_ids: parse_csv(&dt_cfg.allowed_chat_ids),
            webhook_token: dt_cfg.webhook_token.trim().to_string(),
            bot_username: config.bot_username_for_channel("dingtalk"),
            model: dt_cfg
                .model
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(ToOwned::to_owned),
        });
    }
    runtimes
}

pub struct DingTalkAdapter {
    name: String,
    robot_webhook_url: String,
    http_client: reqwest::Client,
}

impl DingTalkAdapter {
    pub fn new(name: String, robot_webhook_url: String) -> Self {
        Self {
            name,
            robot_webhook_url,
            http_client: reqwest::Client::new(),
        }
    }
}

#[async_trait::async_trait]
impl ChannelAdapter for DingTalkAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn chat_type_routes(&self) -> Vec<(&str, ConversationKind)> {
        vec![("dingtalk_group", ConversationKind::Group)]
    }

    async fn send_text(&self, _external_chat_id: &str, text: &str) -> Result<(), String> {
        if self.robot_webhook_url.trim().is_empty() {
            return Err("dingtalk.robot_webhook_url is empty".to_string());
        }
        let body = serde_json::json!({
            "msgtype": "text",
            "text": { "content": text }
        });
        let resp = self
            .http_client
            .post(self.robot_webhook_url.trim())
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("DingTalk send failed: {e}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("DingTalk send error {status}: {body}"));
        }
        Ok(())
    }
}

pub async fn start_dingtalk_bot(_app_state: Arc<AppState>, runtime: DingTalkRuntimeContext) {
    info!("DingTalk adapter '{}' is ready", runtime.channel_name);
}

pub fn register_dingtalk_webhook(router: Router, app_state: Arc<AppState>) -> Router {
    let Some(cfg) = app_state
        .config
        .channel_config::<DingTalkChannelConfig>("dingtalk")
    else {
        return router;
    };
    if !app_state.config.channel_enabled("dingtalk") {
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
            move |headers: HeaderMap, Json(payload): Json<DingTalkWebhookPayload>| {
                let state = state_for_post.clone();
                async move { dingtalk_webhook_handler(state, headers, payload).await }
            },
        ),
    )
}

async fn dingtalk_webhook_handler(
    app_state: Arc<AppState>,
    headers: HeaderMap,
    payload: DingTalkWebhookPayload,
) -> impl axum::response::IntoResponse {
    let runtime_contexts = build_dingtalk_runtime_contexts(&app_state.config);
    let Some(runtime_ctx) = runtime_contexts.first().cloned() else {
        return axum::http::StatusCode::NOT_FOUND;
    };
    let provided_token = headers
        .get("x-dingtalk-webhook-token")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .unwrap_or("");
    if !runtime_ctx.webhook_token.trim().is_empty()
        && runtime_ctx.webhook_token.trim() != provided_token
    {
        return axum::http::StatusCode::FORBIDDEN;
    }
    let chat_id_external = payload.chat_id.trim();
    let text = payload.text.trim();
    if chat_id_external.is_empty() || text.is_empty() {
        return axum::http::StatusCode::BAD_REQUEST;
    }
    if !runtime_ctx.allowed_chat_ids.is_empty()
        && !runtime_ctx
            .allowed_chat_ids
            .iter()
            .any(|c| c == chat_id_external)
    {
        return axum::http::StatusCode::FORBIDDEN;
    }
    let external_chat_id = chat_id_external.to_string();
    let chat_id = call_blocking(app_state.db.clone(), {
        let channel_name = runtime_ctx.channel_name.clone();
        let title = format!("dingtalk-{external_chat_id}");
        let external_chat_id = external_chat_id.clone();
        move |db| {
            db.resolve_or_create_chat_id(
                &channel_name,
                &external_chat_id,
                Some(&title),
                "dingtalk_group",
            )
        }
    })
    .await
    .unwrap_or(0);
    if chat_id == 0 {
        return axum::http::StatusCode::INTERNAL_SERVER_ERROR;
    }
    if is_slash_command(text) {
        if let Some(reply) =
            handle_chat_command(&app_state, chat_id, &runtime_ctx.channel_name, text).await
        {
            let adapter = DingTalkAdapter::new(
                runtime_ctx.channel_name.clone(),
                runtime_ctx.robot_webhook_url.clone(),
            );
            let _ = adapter.send_text(chat_id_external, &reply).await;
            return axum::http::StatusCode::OK;
        }
        let adapter = DingTalkAdapter::new(
            runtime_ctx.channel_name.clone(),
            runtime_ctx.robot_webhook_url.clone(),
        );
        let _ = adapter
            .send_text(chat_id_external, &unknown_command_response())
            .await;
        return axum::http::StatusCode::OK;
    }
    let inbound_message_id = if payload.message_id.trim().is_empty() {
        uuid::Uuid::new_v4().to_string()
    } else {
        payload.message_id.clone()
    };
    let stored = StoredMessage {
        id: inbound_message_id.clone(),
        chat_id,
        sender_name: payload.sender_id.clone(),
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
            "DingTalk: skipping duplicate message chat_id={} message_id={}",
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
            let adapter = DingTalkAdapter::new(
                runtime_ctx.channel_name.clone(),
                runtime_ctx.robot_webhook_url.clone(),
            );
            if used_send_message_tool {
                if !response.is_empty() {
                    info!(
                        "DingTalk: suppressing final response for chat {} because send_message already delivered output",
                        chat_id
                    );
                }
            } else if !response.is_empty() {
                if let Err(e) = adapter.send_text(chat_id_external, &response).await {
                    error!("DingTalk: failed to send response: {e}");
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
                        chat_id_external,
                        "I couldn't produce a visible reply after an automatic retry. Please try again.",
                    )
                    .await;
            }
        }
        Err(e) => {
            error!("DingTalk: error processing message: {e}");
        }
    }
    axum::http::StatusCode::OK
}
