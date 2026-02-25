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
    mark_channel_started, parse_epoch_ms_from_seconds_str, should_drop_pre_start_message,
    should_drop_recent_duplicate_message,
};
use crate::chat_commands::{handle_chat_command, is_slash_command, unknown_command_response};
use crate::runtime::AppState;
use crate::setup_def::{ChannelFieldDef, DynamicChannelDef};
use microclaw_channels::channel::ConversationKind;
use microclaw_channels::channel_adapter::ChannelAdapter;
use microclaw_storage::db::{call_blocking, StoredMessage};

pub const SETUP_DEF: DynamicChannelDef = DynamicChannelDef {
    name: "nostr",
    presence_keys: &["publish_command"],
    fields: &[
        ChannelFieldDef {
            yaml_key: "publish_command",
            label: "Nostr publish command (reads env MICROCLAW_NOSTR_TARGET/TEXT)",
            default: "",
            secret: false,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "webhook_path",
            label: "Nostr webhook path (default /nostr/events)",
            default: "/nostr/events",
            secret: false,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "webhook_token",
            label: "Nostr webhook token (optional)",
            default: "",
            secret: true,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "allowed_pubkeys",
            label: "Nostr allowed pubkeys csv (optional)",
            default: "",
            secret: false,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "bot_username",
            label: "Nostr bot username override (optional)",
            default: "",
            secret: false,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "model",
            label: "Nostr bot model override (optional)",
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
    "/nostr/events".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct NostrAccountConfig {
    #[serde(default)]
    pub allowed_pubkeys: String,
    #[serde(default)]
    pub publish_command: String,
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
pub struct NostrChannelConfig {
    #[serde(default)]
    pub allowed_pubkeys: String,
    #[serde(default)]
    pub publish_command: String,
    #[serde(default = "default_webhook_path")]
    pub webhook_path: String,
    #[serde(default)]
    pub webhook_token: String,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub accounts: HashMap<String, NostrAccountConfig>,
    #[serde(default)]
    pub default_account: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct NostrWebhookPayload {
    pubkey: String,
    content: String,
    #[serde(default)]
    event_id: String,
    #[serde(default)]
    kind: u64,
    #[serde(default)]
    created_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NostrRuntimeContext {
    pub channel_name: String,
    pub allowed_pubkeys: Vec<String>,
    pub publish_command: String,
    pub webhook_token: String,
    pub bot_username: String,
    pub model: Option<String>,
}

fn pick_default_account_id(
    configured: Option<&str>,
    accounts: &HashMap<String, NostrAccountConfig>,
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

pub fn build_nostr_runtime_contexts(config: &crate::config::Config) -> Vec<NostrRuntimeContext> {
    let Some(nostr_cfg) = config.channel_config::<NostrChannelConfig>("nostr") else {
        return Vec::new();
    };
    let mut runtimes = Vec::new();
    let default_account =
        pick_default_account_id(nostr_cfg.default_account.as_deref(), &nostr_cfg.accounts);
    let mut account_ids: Vec<String> = nostr_cfg.accounts.keys().cloned().collect();
    account_ids.sort();

    for account_id in account_ids {
        let Some(account_cfg) = nostr_cfg.accounts.get(&account_id) else {
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
            "nostr".to_string()
        } else {
            format!("nostr.{account_id}")
        };
        let publish_command = if account_cfg.publish_command.trim().is_empty() {
            nostr_cfg.publish_command.trim().to_string()
        } else {
            account_cfg.publish_command.trim().to_string()
        };
        let webhook_token = if account_cfg.webhook_token.trim().is_empty() {
            nostr_cfg.webhook_token.trim().to_string()
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
        runtimes.push(NostrRuntimeContext {
            channel_name,
            allowed_pubkeys: parse_csv(&account_cfg.allowed_pubkeys),
            publish_command,
            webhook_token,
            bot_username,
            model,
        });
    }

    if runtimes.is_empty() {
        runtimes.push(NostrRuntimeContext {
            channel_name: "nostr".to_string(),
            allowed_pubkeys: parse_csv(&nostr_cfg.allowed_pubkeys),
            publish_command: nostr_cfg.publish_command.trim().to_string(),
            webhook_token: nostr_cfg.webhook_token.trim().to_string(),
            bot_username: config.bot_username_for_channel("nostr"),
            model: nostr_cfg
                .model
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(ToOwned::to_owned),
        });
    }

    runtimes
}

pub struct NostrAdapter {
    name: String,
    publish_command: String,
}

impl NostrAdapter {
    pub fn new(name: String, publish_command: String) -> Self {
        Self {
            name,
            publish_command,
        }
    }
}

#[async_trait::async_trait]
impl ChannelAdapter for NostrAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn chat_type_routes(&self) -> Vec<(&str, ConversationKind)> {
        vec![
            ("nostr_dm", ConversationKind::Private),
            ("nostr", ConversationKind::Group),
        ]
    }

    async fn send_text(&self, external_chat_id: &str, text: &str) -> Result<(), String> {
        if self.publish_command.trim().is_empty() {
            return Err(
                "nostr.publish_command is empty; configure a publish bridge command".to_string(),
            );
        }
        let output = Command::new("sh")
            .arg("-lc")
            .arg(self.publish_command.trim())
            .env("MICROCLAW_NOSTR_TARGET", external_chat_id)
            .env("MICROCLAW_NOSTR_TEXT", text)
            .output()
            .map_err(|e| format!("Failed running nostr publish command: {e}"))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("nostr publish command failed: {stderr}"));
        }
        Ok(())
    }
}

pub async fn start_nostr_bot(_app_state: Arc<AppState>, runtime: NostrRuntimeContext) {
    mark_channel_started(&runtime.channel_name);
    info!(
        "Nostr adapter '{}' is ready (webhook ingress + publish command bridge)",
        runtime.channel_name
    );
}

pub fn register_nostr_webhook(router: Router, app_state: Arc<AppState>) -> Router {
    let Some(cfg) = app_state
        .config
        .channel_config::<NostrChannelConfig>("nostr")
    else {
        return router;
    };
    if !app_state.config.channel_enabled("nostr") {
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
            move |headers: HeaderMap, Json(payload): Json<NostrWebhookPayload>| {
                let state = state_for_post.clone();
                async move { nostr_webhook_handler(state, headers, payload).await }
            },
        ),
    )
}

async fn nostr_webhook_handler(
    app_state: Arc<AppState>,
    headers: HeaderMap,
    payload: NostrWebhookPayload,
) -> impl axum::response::IntoResponse {
    let runtime_contexts = build_nostr_runtime_contexts(&app_state.config);
    if runtime_contexts.is_empty() {
        return axum::http::StatusCode::NOT_FOUND;
    }
    let runtime_ctx = runtime_contexts
        .first()
        .cloned()
        .unwrap_or(NostrRuntimeContext {
            channel_name: "nostr".to_string(),
            allowed_pubkeys: Vec::new(),
            publish_command: String::new(),
            webhook_token: String::new(),
            bot_username: String::new(),
            model: None,
        });
    let provided_token = headers
        .get("x-nostr-webhook-token")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .unwrap_or("");
    if !runtime_ctx.webhook_token.trim().is_empty()
        && runtime_ctx.webhook_token.trim() != provided_token
    {
        return axum::http::StatusCode::FORBIDDEN;
    }

    let pubkey = payload.pubkey.trim();
    let content = payload.content.trim();
    if pubkey.is_empty() || content.is_empty() {
        return axum::http::StatusCode::BAD_REQUEST;
    }
    if !runtime_ctx.allowed_pubkeys.is_empty()
        && !runtime_ctx
            .allowed_pubkeys
            .iter()
            .any(|p| p.eq_ignore_ascii_case(pubkey))
    {
        return axum::http::StatusCode::FORBIDDEN;
    }

    let chat_type = if payload.kind == 4 {
        "nostr_dm"
    } else {
        "nostr"
    };
    let external_chat_id = pubkey.to_string();
    let chat_id = call_blocking(app_state.db.clone(), {
        let channel_name = runtime_ctx.channel_name.clone();
        let title = format!("nostr-{external_chat_id}");
        let external_chat_id = external_chat_id.clone();
        let chat_type = chat_type.to_string();
        move |db| {
            db.resolve_or_create_chat_id(&channel_name, &external_chat_id, Some(&title), &chat_type)
        }
    })
    .await
    .unwrap_or(0);
    if chat_id == 0 {
        return axum::http::StatusCode::INTERNAL_SERVER_ERROR;
    }

    let inbound_event_id = if payload.event_id.trim().is_empty() {
        uuid::Uuid::new_v4().to_string()
    } else {
        payload.event_id.clone()
    };
    let inbound_ts_ms = payload
        .created_at
        .as_deref()
        .and_then(parse_epoch_ms_from_seconds_str);
    if should_drop_pre_start_message(&runtime_ctx.channel_name, &inbound_event_id, inbound_ts_ms) {
        return axum::http::StatusCode::OK;
    }
    if should_drop_recent_duplicate_message(&runtime_ctx.channel_name, &inbound_event_id) {
        return axum::http::StatusCode::OK;
    }
    if is_slash_command(content) {
        if let Some(reply) =
            handle_chat_command(&app_state, chat_id, &runtime_ctx.channel_name, content).await
        {
            let adapter = NostrAdapter::new(
                runtime_ctx.channel_name.clone(),
                runtime_ctx.publish_command.clone(),
            );
            let _ = adapter.send_text(pubkey, &reply).await;
            return axum::http::StatusCode::OK;
        }
        let adapter = NostrAdapter::new(
            runtime_ctx.channel_name.clone(),
            runtime_ctx.publish_command.clone(),
        );
        let _ = adapter.send_text(pubkey, &unknown_command_response()).await;
        return axum::http::StatusCode::OK;
    }
    let stored = StoredMessage {
        id: inbound_event_id.clone(),
        chat_id,
        sender_name: pubkey.to_string(),
        content: content.to_string(),
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
            "Nostr: skipping duplicate message chat_id={} event_id={}",
            chat_id, inbound_event_id
        );
        return axum::http::StatusCode::OK;
    }

    let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel::<AgentEvent>();
    match process_with_agent_with_events(
        &app_state,
        AgentRequestContext {
            caller_channel: &runtime_ctx.channel_name,
            chat_id,
            chat_type: if payload.kind == 4 {
                "private"
            } else {
                "group"
            },
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
                        "Nostr: suppressing final response for chat {} because send_message already delivered output",
                        chat_id
                    );
                }
            } else if !response.is_empty() {
                let adapter = NostrAdapter::new(
                    runtime_ctx.channel_name.clone(),
                    runtime_ctx.publish_command.clone(),
                );
                if let Err(e) = adapter.send_text(pubkey, &response).await {
                    error!("Nostr: failed to publish response: {e}");
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
                let adapter = NostrAdapter::new(
                    runtime_ctx.channel_name.clone(),
                    runtime_ctx.publish_command.clone(),
                );
                let _ = adapter
                    .send_text(
                        pubkey,
                        "I couldn't produce a visible reply after an automatic retry. Please try again.",
                    )
                    .await;
            }
        }
        Err(e) => {
            error!("Nostr: error processing message: {e}");
        }
    }

    axum::http::StatusCode::OK
}
