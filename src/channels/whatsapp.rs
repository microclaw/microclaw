use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::Query;
use axum::response::IntoResponse;
use axum::{Json, Router};
use serde::Deserialize;
use tracing::{error, info};

use crate::agent_engine::process_with_agent_with_events;
use crate::agent_engine::{should_suppress_user_error, AgentEvent, AgentRequestContext};
use crate::channels::startup_guard::{
    mark_channel_started, parse_epoch_ms_from_seconds_str, should_drop_pre_start_message,
    should_drop_recent_duplicate_message,
};
use crate::chat_commands::{handle_chat_command, is_slash_command, unknown_command_response};
use crate::runtime::AppState;
use crate::setup_def::{ChannelFieldDef, DynamicChannelDef};
use microclaw_channels::channel::ConversationKind;
use microclaw_channels::channel_adapter::ChannelAdapter;
use microclaw_core::text::split_text;
use microclaw_storage::db::{call_blocking, StoredMessage};

pub const SETUP_DEF: DynamicChannelDef = DynamicChannelDef {
    name: "whatsapp",
    presence_keys: &["access_token", "phone_number_id"],
    fields: &[
        ChannelFieldDef {
            yaml_key: "access_token",
            label: "WhatsApp Cloud API access token",
            default: "",
            secret: true,
            required: true,
        },
        ChannelFieldDef {
            yaml_key: "phone_number_id",
            label: "WhatsApp phone number ID",
            default: "",
            secret: false,
            required: true,
        },
        ChannelFieldDef {
            yaml_key: "webhook_verify_token",
            label: "WhatsApp webhook verify token (optional)",
            default: "",
            secret: true,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "api_version",
            label: "WhatsApp Graph API version (default v21.0)",
            default: "v21.0",
            secret: false,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "webhook_path",
            label: "WhatsApp webhook path (default /whatsapp/webhook)",
            default: "/whatsapp/webhook",
            secret: false,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "allowed_user_ids",
            label: "WhatsApp allowed user ids csv (optional)",
            default: "",
            secret: false,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "bot_username",
            label: "WhatsApp bot username override (optional)",
            default: "",
            secret: false,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "model",
            label: "WhatsApp bot model override (optional)",
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
    "/whatsapp/webhook".to_string()
}

fn default_api_version() -> String {
    "v21.0".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct WhatsAppAccountConfig {
    pub access_token: String,
    pub phone_number_id: String,
    #[serde(default)]
    pub allowed_user_ids: String,
    #[serde(default)]
    pub webhook_verify_token: String,
    #[serde(default)]
    pub bot_username: String,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WhatsAppChannelConfig {
    #[serde(default)]
    pub access_token: String,
    #[serde(default)]
    pub phone_number_id: String,
    #[serde(default)]
    pub allowed_user_ids: String,
    #[serde(default)]
    pub webhook_verify_token: String,
    #[serde(default = "default_webhook_path")]
    pub webhook_path: String,
    #[serde(default = "default_api_version")]
    pub api_version: String,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub accounts: HashMap<String, WhatsAppAccountConfig>,
    #[serde(default)]
    pub default_account: Option<String>,
}

#[derive(Debug, Clone)]
pub struct WhatsAppRuntimeContext {
    pub channel_name: String,
    pub access_token: String,
    pub phone_number_id: String,
    pub api_version: String,
    pub allowed_user_ids: Vec<String>,
    pub webhook_verify_token: String,
    pub bot_username: String,
    pub model: Option<String>,
}

fn pick_default_account_id(
    configured: Option<&str>,
    accounts: &HashMap<String, WhatsAppAccountConfig>,
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

pub fn build_whatsapp_runtime_contexts(
    config: &crate::config::Config,
) -> Vec<WhatsAppRuntimeContext> {
    let Some(wa_cfg) = config.channel_config::<WhatsAppChannelConfig>("whatsapp") else {
        return Vec::new();
    };

    let mut runtimes = Vec::new();
    let api_version = wa_cfg.api_version.trim().to_string();
    let api_version = if api_version.is_empty() {
        default_api_version()
    } else {
        api_version
    };

    let default_account =
        pick_default_account_id(wa_cfg.default_account.as_deref(), &wa_cfg.accounts);
    let mut account_ids: Vec<String> = wa_cfg.accounts.keys().cloned().collect();
    account_ids.sort();
    for account_id in account_ids {
        let Some(account_cfg) = wa_cfg.accounts.get(&account_id) else {
            continue;
        };
        if !account_cfg.enabled
            || account_cfg.access_token.trim().is_empty()
            || account_cfg.phone_number_id.trim().is_empty()
        {
            continue;
        }
        let is_default = default_account
            .as_deref()
            .map(|v| v == account_id.as_str())
            .unwrap_or(false);
        let channel_name = if is_default {
            "whatsapp".to_string()
        } else {
            format!("whatsapp.{account_id}")
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
        let verify_token = if account_cfg.webhook_verify_token.trim().is_empty() {
            wa_cfg.webhook_verify_token.trim().to_string()
        } else {
            account_cfg.webhook_verify_token.trim().to_string()
        };

        runtimes.push(WhatsAppRuntimeContext {
            channel_name,
            access_token: account_cfg.access_token.clone(),
            phone_number_id: account_cfg.phone_number_id.clone(),
            api_version: api_version.clone(),
            allowed_user_ids: parse_csv(&account_cfg.allowed_user_ids),
            webhook_verify_token: verify_token,
            bot_username,
            model,
        });
    }

    if runtimes.is_empty()
        && !wa_cfg.access_token.trim().is_empty()
        && !wa_cfg.phone_number_id.trim().is_empty()
    {
        runtimes.push(WhatsAppRuntimeContext {
            channel_name: "whatsapp".to_string(),
            access_token: wa_cfg.access_token,
            phone_number_id: wa_cfg.phone_number_id,
            api_version,
            allowed_user_ids: parse_csv(&wa_cfg.allowed_user_ids),
            webhook_verify_token: wa_cfg.webhook_verify_token,
            bot_username: config.bot_username_for_channel("whatsapp"),
            model: wa_cfg
                .model
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(ToOwned::to_owned),
        });
    }

    runtimes
}

pub struct WhatsAppAdapter {
    name: String,
    access_token: String,
    phone_number_id: String,
    api_version: String,
    http_client: reqwest::Client,
}

impl WhatsAppAdapter {
    pub fn new(
        name: String,
        access_token: String,
        phone_number_id: String,
        api_version: String,
    ) -> Self {
        Self {
            name,
            access_token,
            phone_number_id,
            api_version,
            http_client: reqwest::Client::new(),
        }
    }
}

#[async_trait::async_trait]
impl ChannelAdapter for WhatsAppAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn chat_type_routes(&self) -> Vec<(&str, ConversationKind)> {
        vec![
            ("whatsapp_dm", ConversationKind::Private),
            ("whatsapp_group", ConversationKind::Group),
        ]
    }

    async fn send_text(&self, external_chat_id: &str, text: &str) -> Result<(), String> {
        send_whatsapp_text(
            &self.http_client,
            &self.access_token,
            &self.phone_number_id,
            &self.api_version,
            external_chat_id,
            text,
        )
        .await
    }
}

async fn send_whatsapp_text(
    http_client: &reqwest::Client,
    access_token: &str,
    phone_number_id: &str,
    api_version: &str,
    to: &str,
    text: &str,
) -> Result<(), String> {
    let url = format!(
        "https://graph.facebook.com/{}/{}/messages",
        api_version.trim(),
        phone_number_id.trim()
    );
    for chunk in split_text(text, 3000) {
        let body = serde_json::json!({
            "messaging_product": "whatsapp",
            "to": to,
            "type": "text",
            "text": {
                "body": chunk
            }
        });
        let response = http_client
            .post(&url)
            .bearer_auth(access_token.trim())
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("WhatsApp API request failed: {e}"))?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!("WhatsApp API error {status}: {body}"));
        }
    }
    Ok(())
}

pub async fn start_whatsapp_bot(_app_state: Arc<AppState>, runtime: WhatsAppRuntimeContext) {
    mark_channel_started(&runtime.channel_name);
    info!(
        "WhatsApp adapter '{}' is ready (webhook ingress via web server, phone_number_id={})",
        runtime.channel_name, runtime.phone_number_id
    );
}

#[derive(Debug, Deserialize)]
struct WhatsAppVerifyQuery {
    #[serde(rename = "hub.mode")]
    hub_mode: Option<String>,
    #[serde(rename = "hub.verify_token")]
    hub_verify_token: Option<String>,
    #[serde(rename = "hub.challenge")]
    hub_challenge: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WhatsAppWebhookPayload {
    #[serde(default)]
    entry: Vec<WhatsAppWebhookEntry>,
}

#[derive(Debug, Deserialize)]
struct WhatsAppWebhookEntry {
    #[serde(default)]
    changes: Vec<WhatsAppWebhookChange>,
}

#[derive(Debug, Deserialize)]
struct WhatsAppWebhookChange {
    value: WhatsAppWebhookValue,
}

#[derive(Debug, Deserialize)]
struct WhatsAppWebhookValue {
    #[serde(default)]
    metadata: Option<WhatsAppWebhookMetadata>,
    #[serde(default)]
    messages: Vec<WhatsAppInboundMessage>,
}

#[derive(Debug, Deserialize)]
struct WhatsAppWebhookMetadata {
    #[serde(default)]
    phone_number_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WhatsAppInboundMessage {
    id: String,
    from: String,
    #[serde(default)]
    timestamp: String,
    #[serde(rename = "type")]
    message_type: String,
    #[serde(default)]
    text: Option<WhatsAppInboundText>,
}

#[derive(Debug, Deserialize)]
struct WhatsAppInboundText {
    body: String,
}

fn verify_token_allowed(runtime_contexts: &[WhatsAppRuntimeContext], token: &str) -> bool {
    let mut has_configured_token = false;
    for runtime in runtime_contexts {
        let expected = runtime.webhook_verify_token.trim();
        if expected.is_empty() {
            continue;
        }
        has_configured_token = true;
        if expected == token {
            return true;
        }
    }
    !has_configured_token
}

async fn whatsapp_verify_handler(
    app_state: Arc<AppState>,
    query: WhatsAppVerifyQuery,
) -> impl IntoResponse {
    if query.hub_mode.as_deref() != Some("subscribe") {
        return axum::http::StatusCode::BAD_REQUEST.into_response();
    }

    let Some(challenge) = query.hub_challenge else {
        return axum::http::StatusCode::BAD_REQUEST.into_response();
    };
    let provided_token = query.hub_verify_token.unwrap_or_default();
    let runtime_contexts = build_whatsapp_runtime_contexts(&app_state.config);
    if runtime_contexts.is_empty() {
        return axum::http::StatusCode::NOT_FOUND.into_response();
    }
    if !verify_token_allowed(&runtime_contexts, provided_token.trim()) {
        return axum::http::StatusCode::FORBIDDEN.into_response();
    }

    (axum::http::StatusCode::OK, challenge).into_response()
}

pub fn register_whatsapp_webhook(router: Router, app_state: Arc<AppState>) -> Router {
    let Some(cfg) = app_state
        .config
        .channel_config::<WhatsAppChannelConfig>("whatsapp")
    else {
        return router;
    };
    if !app_state.config.channel_enabled("whatsapp") {
        return router;
    }
    let path = cfg.webhook_path.trim();
    if path.is_empty() {
        return router;
    }

    let verify_state = app_state.clone();
    let post_state = app_state.clone();
    router.route(
        path,
        axum::routing::get(move |Query(query): Query<WhatsAppVerifyQuery>| {
            let state = verify_state.clone();
            async move { whatsapp_verify_handler(state, query).await }
        })
        .post(move |Json(payload): Json<WhatsAppWebhookPayload>| {
            let state = post_state.clone();
            async move { whatsapp_webhook_handler(state, payload).await }
        }),
    )
}

async fn whatsapp_webhook_handler(
    app_state: Arc<AppState>,
    payload: WhatsAppWebhookPayload,
) -> impl IntoResponse {
    let runtime_contexts = build_whatsapp_runtime_contexts(&app_state.config);
    if runtime_contexts.is_empty() {
        return axum::http::StatusCode::NOT_FOUND;
    }

    for entry in payload.entry {
        for change in entry.changes {
            let phone_number_id = change
                .value
                .metadata
                .as_ref()
                .and_then(|m| m.phone_number_id.as_deref())
                .map(str::trim)
                .unwrap_or("");

            let Some(runtime_ctx) = runtime_contexts
                .iter()
                .find(|ctx| ctx.phone_number_id.trim() == phone_number_id)
                .cloned()
                .or_else(|| runtime_contexts.first().cloned())
            else {
                continue;
            };

            for message in change.value.messages {
                if message.message_type != "text" {
                    continue;
                }
                let text = message
                    .text
                    .as_ref()
                    .map(|t| t.body.trim().to_string())
                    .unwrap_or_default();
                if text.is_empty() {
                    continue;
                }
                let state = app_state.clone();
                let runtime = runtime_ctx.clone();
                let from = message.from.clone();
                let message_id = message.id.clone();
                let timestamp = message.timestamp.clone();
                tokio::spawn(async move {
                    handle_whatsapp_message(state, runtime, &from, &text, &message_id, &timestamp)
                        .await;
                });
            }
        }
    }

    axum::http::StatusCode::OK
}

async fn handle_whatsapp_message(
    app_state: Arc<AppState>,
    runtime: WhatsAppRuntimeContext,
    from: &str,
    text: &str,
    message_id: &str,
    timestamp: &str,
) {
    if !runtime.allowed_user_ids.is_empty() && !runtime.allowed_user_ids.iter().any(|u| u == from) {
        return;
    }

    let external_chat_id = from.trim();
    if external_chat_id.is_empty() {
        return;
    }

    let chat_id = call_blocking(app_state.db.clone(), {
        let external_chat_id = external_chat_id.to_string();
        let title = format!("whatsapp-{external_chat_id}");
        let channel_name = runtime.channel_name.clone();
        move |db| {
            db.resolve_or_create_chat_id(
                &channel_name,
                &external_chat_id,
                Some(&title),
                "whatsapp_dm",
            )
        }
    })
    .await
    .unwrap_or(0);

    if chat_id == 0 {
        error!("WhatsApp: failed to resolve chat ID for {external_chat_id}");
        return;
    }

    let inbound_message_id = if message_id.trim().is_empty() {
        uuid::Uuid::new_v4().to_string()
    } else {
        message_id.to_string()
    };
    if should_drop_pre_start_message(
        &runtime.channel_name,
        &inbound_message_id,
        parse_epoch_ms_from_seconds_str(timestamp),
    ) {
        return;
    }
    if should_drop_recent_duplicate_message(&runtime.channel_name, &inbound_message_id) {
        return;
    }

    let trimmed = text.trim();
    if is_slash_command(trimmed) {
        if let Some(reply) =
            handle_chat_command(&app_state, chat_id, &runtime.channel_name, trimmed).await
        {
            let _ = send_whatsapp_text(
                &reqwest::Client::new(),
                &runtime.access_token,
                &runtime.phone_number_id,
                &runtime.api_version,
                external_chat_id,
                &reply,
            )
            .await;
            return;
        }
        let _ = send_whatsapp_text(
            &reqwest::Client::new(),
            &runtime.access_token,
            &runtime.phone_number_id,
            &runtime.api_version,
            external_chat_id,
            &unknown_command_response(),
        )
        .await;
        return;
    }
    let stored = StoredMessage {
        id: inbound_message_id.clone(),
        chat_id,
        sender_name: external_chat_id.to_string(),
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
            "WhatsApp: skipping duplicate message chat_id={} message_id={}",
            chat_id, inbound_message_id
        );
        return;
    }

    info!(
        "WhatsApp message from {} in {}: {}",
        external_chat_id,
        runtime.channel_name,
        text.chars().take(120).collect::<String>()
    );

    let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel::<AgentEvent>();
    match process_with_agent_with_events(
        &app_state,
        AgentRequestContext {
            caller_channel: &runtime.channel_name,
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

            if used_send_message_tool {
                if !response.is_empty() {
                    info!(
                        "WhatsApp: suppressing final response for chat {} because send_message already delivered output",
                        chat_id
                    );
                }
            } else if !response.is_empty() {
                if let Err(e) = send_whatsapp_text(
                    &reqwest::Client::new(),
                    &runtime.access_token,
                    &runtime.phone_number_id,
                    &runtime.api_version,
                    external_chat_id,
                    &response,
                )
                .await
                {
                    error!("WhatsApp: failed to send response: {e}");
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
                let fallback =
                    "I couldn't produce a visible reply after an automatic retry. Please try again.";
                let _ = send_whatsapp_text(
                    &reqwest::Client::new(),
                    &runtime.access_token,
                    &runtime.phone_number_id,
                    &runtime.api_version,
                    external_chat_id,
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
            error!("WhatsApp: error processing message: {e}");
            if !should_suppress_user_error(&e) {
                let _ = send_whatsapp_text(
                    &reqwest::Client::new(),
                    &runtime.access_token,
                    &runtime.phone_number_id,
                    &runtime.api_version,
                    external_chat_id,
                    &format!("Error: {e}"),
                )
                .await;
            }
        }
    }
}
