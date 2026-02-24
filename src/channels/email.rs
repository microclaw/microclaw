use std::collections::HashMap;
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Arc;

use axum::response::IntoResponse;
use axum::{http::HeaderMap, Json, Router};
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
use microclaw_core::text::split_text;
use microclaw_storage::db::{call_blocking, StoredMessage};

pub const SETUP_DEF: DynamicChannelDef = DynamicChannelDef {
    name: "email",
    presence_keys: &["from_address"],
    fields: &[
        ChannelFieldDef {
            yaml_key: "from_address",
            label: "Email from address",
            default: "",
            secret: false,
            required: true,
        },
        ChannelFieldDef {
            yaml_key: "sendmail_path",
            label: "sendmail path (default /usr/sbin/sendmail)",
            default: "/usr/sbin/sendmail",
            secret: false,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "webhook_path",
            label: "Email webhook path (default /email/webhook)",
            default: "/email/webhook",
            secret: false,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "webhook_token",
            label: "Email webhook token (optional)",
            default: "",
            secret: true,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "allowed_senders",
            label: "Email allowed senders csv (optional)",
            default: "",
            secret: false,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "bot_username",
            label: "Email bot username override (optional)",
            default: "",
            secret: false,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "model",
            label: "Email bot model override (optional)",
            default: "",
            secret: false,
            required: false,
        },
    ],
};

fn default_enabled() -> bool {
    true
}

fn default_sendmail_path() -> String {
    "/usr/sbin/sendmail".to_string()
}

fn default_webhook_path() -> String {
    "/email/webhook".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct EmailAccountConfig {
    pub from_address: String,
    #[serde(default = "default_sendmail_path")]
    pub sendmail_path: String,
    #[serde(default)]
    pub allowed_senders: String,
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
pub struct EmailChannelConfig {
    #[serde(default)]
    pub from_address: String,
    #[serde(default = "default_sendmail_path")]
    pub sendmail_path: String,
    #[serde(default)]
    pub allowed_senders: String,
    #[serde(default = "default_webhook_path")]
    pub webhook_path: String,
    #[serde(default)]
    pub webhook_token: String,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub accounts: HashMap<String, EmailAccountConfig>,
    #[serde(default)]
    pub default_account: Option<String>,
}

#[derive(Debug, Clone)]
pub struct EmailRuntimeContext {
    pub channel_name: String,
    pub from_address: String,
    pub sendmail_path: String,
    pub allowed_senders: Vec<String>,
    pub webhook_token: String,
    pub bot_username: String,
    pub model: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct EmailWebhookPayload {
    from: String,
    #[serde(default)]
    reply_to: String,
    #[serde(default)]
    subject: String,
    text: String,
    #[serde(default)]
    message_id: String,
    #[serde(default)]
    timestamp: Option<String>,
    #[serde(default)]
    timestamp_ms: Option<i64>,
    #[serde(default)]
    sent_at: Option<String>,
}

fn pick_default_account_id(
    configured: Option<&str>,
    accounts: &HashMap<String, EmailAccountConfig>,
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

pub fn build_email_runtime_contexts(config: &crate::config::Config) -> Vec<EmailRuntimeContext> {
    let Some(email_cfg) = config.channel_config::<EmailChannelConfig>("email") else {
        return Vec::new();
    };

    let mut runtimes = Vec::new();
    let default_account =
        pick_default_account_id(email_cfg.default_account.as_deref(), &email_cfg.accounts);
    let mut account_ids: Vec<String> = email_cfg.accounts.keys().cloned().collect();
    account_ids.sort();

    for account_id in account_ids {
        let Some(account_cfg) = email_cfg.accounts.get(&account_id) else {
            continue;
        };
        if !account_cfg.enabled || account_cfg.from_address.trim().is_empty() {
            continue;
        }
        let is_default = default_account
            .as_deref()
            .map(|v| v == account_id.as_str())
            .unwrap_or(false);
        let channel_name = if is_default {
            "email".to_string()
        } else {
            format!("email.{account_id}")
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
        let sendmail_path = if account_cfg.sendmail_path.trim().is_empty() {
            default_sendmail_path()
        } else {
            account_cfg.sendmail_path.trim().to_string()
        };
        let webhook_token = if account_cfg.webhook_token.trim().is_empty() {
            email_cfg.webhook_token.trim().to_string()
        } else {
            account_cfg.webhook_token.trim().to_string()
        };
        runtimes.push(EmailRuntimeContext {
            channel_name,
            from_address: account_cfg.from_address.trim().to_string(),
            sendmail_path,
            allowed_senders: parse_csv(&account_cfg.allowed_senders),
            webhook_token,
            bot_username,
            model,
        });
    }

    if runtimes.is_empty() && !email_cfg.from_address.trim().is_empty() {
        runtimes.push(EmailRuntimeContext {
            channel_name: "email".to_string(),
            from_address: email_cfg.from_address.trim().to_string(),
            sendmail_path: if email_cfg.sendmail_path.trim().is_empty() {
                default_sendmail_path()
            } else {
                email_cfg.sendmail_path.trim().to_string()
            },
            allowed_senders: parse_csv(&email_cfg.allowed_senders),
            webhook_token: email_cfg.webhook_token.trim().to_string(),
            bot_username: config.bot_username_for_channel("email"),
            model: email_cfg
                .model
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(ToOwned::to_owned),
        });
    }

    runtimes
}

pub struct EmailAdapter {
    name: String,
    from_address: String,
    sendmail_path: String,
}

impl EmailAdapter {
    pub fn new(name: String, from_address: String, sendmail_path: String) -> Self {
        Self {
            name,
            from_address,
            sendmail_path,
        }
    }
}

#[async_trait::async_trait]
impl ChannelAdapter for EmailAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn chat_type_routes(&self) -> Vec<(&str, ConversationKind)> {
        vec![("email_dm", ConversationKind::Private)]
    }

    async fn send_text(&self, external_chat_id: &str, text: &str) -> Result<(), String> {
        let to = external_chat_id.trim();
        if to.is_empty() {
            return Err("Email target is empty".to_string());
        }
        send_email_via_sendmail(
            &self.sendmail_path,
            &self.from_address,
            to,
            "MicroClaw reply",
            text,
        )
    }
}

fn send_email_via_sendmail(
    sendmail_path: &str,
    from: &str,
    to: &str,
    subject: &str,
    body: &str,
) -> Result<(), String> {
    let mut child = Command::new(sendmail_path)
        .arg("-t")
        .arg("-i")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn sendmail at '{}': {e}", sendmail_path))?;

    let mut input = String::new();
    input.push_str(&format!("To: {to}\n"));
    input.push_str(&format!("From: {from}\n"));
    input.push_str(&format!("Subject: {subject}\n"));
    input.push_str("Content-Type: text/plain; charset=UTF-8\n");
    input.push('\n');
    input.push_str(body);
    input.push('\n');

    let Some(mut stdin) = child.stdin.take() else {
        return Err("sendmail stdin is not available".to_string());
    };
    stdin
        .write_all(input.as_bytes())
        .map_err(|e| format!("Failed writing sendmail input: {e}"))?;
    drop(stdin);

    let output = child
        .wait_with_output()
        .map_err(|e| format!("Failed waiting for sendmail: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("sendmail failed: {stderr}"));
    }
    Ok(())
}

pub async fn start_email_bot(_app_state: Arc<AppState>, runtime: EmailRuntimeContext) {
    mark_channel_started(&runtime.channel_name);
    info!(
        "Email adapter '{}' is ready (webhook ingress + sendmail egress from={})",
        runtime.channel_name, runtime.from_address
    );
}

pub fn register_email_webhook(router: Router, app_state: Arc<AppState>) -> Router {
    let Some(cfg) = app_state
        .config
        .channel_config::<EmailChannelConfig>("email")
    else {
        return router;
    };
    if !app_state.config.channel_enabled("email") {
        return router;
    }
    let path = cfg.webhook_path.trim();
    if path.is_empty() {
        return router;
    }

    router.route(
        path,
        axum::routing::post(
            move |headers: HeaderMap, Json(payload): Json<EmailWebhookPayload>| {
                let state = app_state.clone();
                async move { email_webhook_handler(state, headers, payload).await }
            },
        ),
    )
}

async fn email_webhook_handler(
    app_state: Arc<AppState>,
    headers: HeaderMap,
    payload: EmailWebhookPayload,
) -> impl IntoResponse {
    let runtime_contexts = build_email_runtime_contexts(&app_state.config);
    if runtime_contexts.is_empty() {
        return axum::http::StatusCode::NOT_FOUND;
    }

    let provided_token = headers
        .get("x-email-webhook-token")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .unwrap_or("");

    let runtime_ctx = runtime_contexts
        .first()
        .cloned()
        .unwrap_or(EmailRuntimeContext {
            channel_name: "email".to_string(),
            from_address: String::new(),
            sendmail_path: default_sendmail_path(),
            allowed_senders: Vec::new(),
            webhook_token: String::new(),
            bot_username: String::new(),
            model: None,
        });

    if !runtime_ctx.webhook_token.trim().is_empty()
        && runtime_ctx.webhook_token.trim() != provided_token
    {
        return axum::http::StatusCode::FORBIDDEN;
    }

    let from = payload.from.trim();
    if from.is_empty() || payload.text.trim().is_empty() {
        return axum::http::StatusCode::BAD_REQUEST;
    }

    if !runtime_ctx.allowed_senders.is_empty()
        && !runtime_ctx
            .allowed_senders
            .iter()
            .any(|sender| sender.eq_ignore_ascii_case(from))
    {
        return axum::http::StatusCode::FORBIDDEN;
    }
    tokio::spawn({
        let state = app_state.clone();
        let runtime = runtime_ctx.clone();
        let payload = payload.clone();
        async move {
            process_email_webhook_message(state, runtime, payload).await;
        }
    });
    axum::http::StatusCode::OK
}

async fn process_email_webhook_message(
    app_state: Arc<AppState>,
    runtime_ctx: EmailRuntimeContext,
    payload: EmailWebhookPayload,
) {
    let from = payload.from.trim().to_string();
    let trimmed_text = payload.text.trim().to_string();

    let external_chat_id = from.to_string();
    let chat_id = call_blocking(app_state.db.clone(), {
        let channel_name = runtime_ctx.channel_name.clone();
        let title = format!("email-{external_chat_id}");
        let external_chat_id = external_chat_id.clone();
        move |db| {
            db.resolve_or_create_chat_id(&channel_name, &external_chat_id, Some(&title), "email_dm")
        }
    })
    .await
    .unwrap_or(0);
    if chat_id == 0 {
        error!("Email: failed to resolve chat ID for {external_chat_id}");
        return;
    }

    let trimmed = trimmed_text.trim();
    if is_slash_command(trimmed) {
        if let Some(reply) =
            handle_chat_command(&app_state, chat_id, &runtime_ctx.channel_name, trimmed).await
        {
            let target = if payload.reply_to.trim().is_empty() {
                from.to_string()
            } else {
                payload.reply_to.trim().to_string()
            };
            let _ = send_email_via_sendmail(
                &runtime_ctx.sendmail_path,
                &runtime_ctx.from_address,
                &target,
                "MicroClaw command reply",
                &reply,
            );
            return;
        }
        let target = if payload.reply_to.trim().is_empty() {
            from.to_string()
        } else {
            payload.reply_to.trim().to_string()
        };
        let _ = send_email_via_sendmail(
            &runtime_ctx.sendmail_path,
            &runtime_ctx.from_address,
            &target,
            "MicroClaw command reply",
            &unknown_command_response(),
        );
        return;
    }

    let inbound_message_id = if payload.message_id.trim().is_empty() {
        uuid::Uuid::new_v4().to_string()
    } else {
        payload.message_id.clone()
    };
    let inbound_ts_ms = payload.timestamp_ms.or_else(|| {
        payload
            .sent_at
            .as_deref()
            .and_then(parse_epoch_ms_from_str)
            .or_else(|| {
                payload
                    .timestamp
                    .as_deref()
                    .and_then(parse_epoch_ms_from_str)
            })
            .or_else(|| {
                payload
                    .sent_at
                    .as_deref()
                    .and_then(parse_epoch_ms_from_seconds_str)
            })
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
        sender_name: from.to_string(),
        content: payload.text.clone(),
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
            "Email: skipping duplicate message chat_id={} message_id={}",
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
            let target = if payload.reply_to.trim().is_empty() {
                from.to_string()
            } else {
                payload.reply_to.trim().to_string()
            };
            if used_send_message_tool {
                if !response.is_empty() {
                    info!(
                        "Email: suppressing final response for chat {} because send_message already delivered output",
                        chat_id
                    );
                }
            } else if !response.is_empty() {
                let mut email_body = String::new();
                if !payload.subject.trim().is_empty() {
                    email_body.push_str(&format!("Re: {}\n\n", payload.subject.trim()));
                }
                for chunk in split_text(&response, 8_000) {
                    email_body.push_str(&chunk);
                    email_body.push('\n');
                }
                if let Err(e) = send_email_via_sendmail(
                    &runtime_ctx.sendmail_path,
                    &runtime_ctx.from_address,
                    &target,
                    "MicroClaw reply",
                    &email_body,
                ) {
                    error!("Email: failed to send response: {e}");
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
                let fallback =
                    "I couldn't produce a visible reply after an automatic retry. Please try again.";
                let _ = send_email_via_sendmail(
                    &runtime_ctx.sendmail_path,
                    &runtime_ctx.from_address,
                    &target,
                    "MicroClaw reply",
                    fallback,
                );
            }
        }
        Err(e) => {
            error!("Email: error processing message: {e}");
        }
    }
}
