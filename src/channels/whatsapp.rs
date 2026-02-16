use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use tracing::{error, info};

use crate::db::call_blocking;
use crate::db::StoredMessage;
use crate::slash_commands::{parse as parse_slash_command, SlashCommand};
use crate::telegram::{AgentRequestContext, AppState};

// --- Webhook query params for verification ---

#[derive(Debug, Deserialize)]
struct WebhookQuery {
    #[serde(rename = "hub.mode", default)]
    hub_mode: Option<String>,
    #[serde(rename = "hub.verify_token", default)]
    hub_verify_token: Option<String>,
    #[serde(rename = "hub.challenge", default)]
    hub_challenge: Option<String>,
}

// --- WhatsApp Cloud API webhook payload types ---

#[derive(Debug, Deserialize)]
struct WebhookPayload {
    #[serde(default)]
    entry: Vec<WebhookEntry>,
}

#[derive(Debug, Deserialize)]
struct WebhookEntry {
    #[serde(default)]
    changes: Vec<WebhookChange>,
}

#[derive(Debug, Deserialize)]
struct WebhookChange {
    value: Option<WebhookValue>,
}

#[derive(Debug, Deserialize)]
struct WebhookValue {
    #[serde(default)]
    messages: Vec<WhatsAppMessage>,
    #[serde(default)]
    contacts: Vec<WhatsAppContact>,
}

#[derive(Debug, Deserialize)]
struct WhatsAppMessage {
    from: String,
    id: String,
    #[serde(rename = "type")]
    msg_type: String,
    text: Option<WhatsAppText>,
    #[allow(dead_code)]
    timestamp: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WhatsAppText {
    body: String,
}

#[derive(Debug, Deserialize)]
struct WhatsAppContact {
    profile: Option<WhatsAppProfile>,
    wa_id: String,
}

#[derive(Debug, Deserialize)]
struct WhatsAppProfile {
    name: Option<String>,
}

// --- Shared state for WhatsApp handlers ---

struct WhatsAppState {
    app_state: Arc<AppState>,
    access_token: String,
    phone_number_id: String,
    verify_token: String,
    http_client: reqwest::Client,
}

// --- Webhook verification (GET /webhook) ---

async fn verify_webhook(
    Query(params): Query<WebhookQuery>,
    State(state): State<Arc<WhatsAppState>>,
) -> impl IntoResponse {
    if params.hub_mode.as_deref() == Some("subscribe")
        && params.hub_verify_token.as_deref() == Some(&state.verify_token)
    {
        if let Some(challenge) = params.hub_challenge {
            info!("WhatsApp webhook verified");
            return (StatusCode::OK, challenge);
        }
    }
    (StatusCode::FORBIDDEN, "Verification failed".to_string())
}

// --- Incoming messages (POST /webhook) ---

async fn handle_webhook(
    State(state): State<Arc<WhatsAppState>>,
    Json(payload): Json<WebhookPayload>,
) -> impl IntoResponse {
    // Respond immediately (WhatsApp requires fast 200 response)
    tokio::spawn(async move {
        if let Err(e) = process_webhook(&state, payload).await {
            error!("WhatsApp webhook processing error: {e}");
        }
    });
    StatusCode::OK
}

async fn process_webhook(state: &WhatsAppState, payload: WebhookPayload) -> anyhow::Result<()> {
    for entry in payload.entry {
        for change in entry.changes {
            let value = match change.value {
                Some(v) => v,
                None => continue,
            };

            for message in &value.messages {
                if message.msg_type != "text" {
                    // Only handle text messages for now
                    continue;
                }

                let text = match &message.text {
                    Some(t) => t.body.clone(),
                    None => continue,
                };

                // Use phone number as chat_id
                let chat_id: i64 = message.from.parse().unwrap_or(0);
                if chat_id == 0 {
                    error!("Invalid WhatsApp phone number: {}", message.from);
                    continue;
                }

                // Single entry point: parse slash command first. If command, run backend handler and return — never send to LLM.
                if let Some(cmd) = parse_slash_command(&text) {
                    match cmd {
                        SlashCommand::Reset => {
                            let pid = call_blocking(state.app_state.db.clone(), move |db| db.get_or_create_default_persona(chat_id)).await.unwrap_or(0);
                            if pid > 0 {
                                let _ = call_blocking(state.app_state.db.clone(), move |db| db.delete_session(chat_id, pid)).await;
                            }
                            send_whatsapp_message(
                                &state.http_client,
                                &state.access_token,
                                &state.phone_number_id,
                                &message.from,
                                "Conversation cleared. Principles and per-persona memory are unchanged.",
                            )
                            .await;
                        }
                        SlashCommand::Skills => {
                            let formatted = state.app_state.skills.list_skills_formatted();
                            send_whatsapp_message(
                                &state.http_client,
                                &state.access_token,
                                &state.phone_number_id,
                                &message.from,
                                &formatted,
                            )
                            .await;
                        }
                        SlashCommand::Persona => {
                            let resp = crate::persona::handle_persona_command(state.app_state.db.clone(), chat_id, text.trim()).await;
                            send_whatsapp_message(
                                &state.http_client,
                                &state.access_token,
                                &state.phone_number_id,
                                &message.from,
                                &resp,
                            )
                            .await;
                        }
                        SlashCommand::Archive => {
                            let pid = call_blocking(state.app_state.db.clone(), move |db| db.get_or_create_default_persona(chat_id)).await.unwrap_or(0);
                            if pid == 0 {
                                send_whatsapp_message(
                                    &state.http_client,
                                    &state.access_token,
                                    &state.phone_number_id,
                                    &message.from,
                                    "No session to archive.",
                                )
                                .await;
                            } else {
                                let pid_f = pid;
                                if let Ok(Some((json, _))) = call_blocking(state.app_state.db.clone(), move |db| {
                                    db.load_session(chat_id, pid_f)
                                })
                                .await
                                {
                                    let messages: Vec<crate::claude::Message> = serde_json::from_str(&json).unwrap_or_default();
                                    if messages.is_empty() {
                                        send_whatsapp_message(
                                            &state.http_client,
                                            &state.access_token,
                                            &state.phone_number_id,
                                            &message.from,
                                            "No session to archive.",
                                        )
                                        .await;
                                    } else {
                                        crate::telegram::archive_conversation(
                                            &state.app_state.config.runtime_data_dir(),
                                            chat_id,
                                            &messages,
                                        );
                                        send_whatsapp_message(
                                            &state.http_client,
                                            &state.access_token,
                                            &state.phone_number_id,
                                            &message.from,
                                            &format!("Archived {} messages.", messages.len()),
                                        )
                                        .await;
                                    }
                                } else {
                                    send_whatsapp_message(
                                        &state.http_client,
                                        &state.access_token,
                                        &state.phone_number_id,
                                        &message.from,
                                        "No session to archive.",
                                    )
                                    .await;
                                }
                            }
                        }
                    }
                    continue;
                }

                // Find sender name from contacts
                let sender_name = value
                    .contacts
                    .iter()
                    .find(|c| c.wa_id == message.from)
                    .and_then(|c| c.profile.as_ref())
                    .and_then(|p| p.name.clone())
                    .unwrap_or_else(|| message.from.clone());

                // Resolve persona
                let persona_id = call_blocking(state.app_state.db.clone(), move |db| db.get_or_create_default_persona(chat_id)).await.unwrap_or(0);
                if persona_id == 0 {
                    continue;
                }

                // Store message in DB
                let sender_name_for_chat = sender_name.clone();
                let _ = call_blocking(state.app_state.db.clone(), move |db| {
                    db.upsert_chat(chat_id, Some(&sender_name_for_chat), "whatsapp")
                })
                .await;
                let stored = StoredMessage {
                    id: message.id.clone(),
                    chat_id,
                    persona_id,
                    sender_name: sender_name.clone(),
                    content: text.clone(),
                    is_from_bot: false,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                };
                let _ = call_blocking(state.app_state.db.clone(), move |db| {
                    db.store_message(&stored)
                })
                .await;

                info!(
                    "WhatsApp message from {} ({}): {}",
                    sender_name,
                    message.from,
                    text.chars().take(100).collect::<String>()
                );

                // Process with Claude (reuses the same agentic loop as Telegram)
                match crate::telegram::process_with_agent(
                    &state.app_state,
                    AgentRequestContext {
                        caller_channel: "whatsapp",
                        chat_id,
                        chat_type: "private",
                        persona_id,
                    },
                    None,
                    None,
                )
                .await
                {
                    Ok(response) => {
                        if !response.is_empty() {
                            send_whatsapp_message(
                                &state.http_client,
                                &state.access_token,
                                &state.phone_number_id,
                                &message.from,
                                &response,
                            )
                            .await;

                            // Store bot response
                            let bot_msg = StoredMessage {
                                id: uuid::Uuid::new_v4().to_string(),
                                chat_id,
                                persona_id,
                                sender_name: state.app_state.config.bot_username.clone(),
                                content: response,
                                is_from_bot: true,
                                timestamp: chrono::Utc::now().to_rfc3339(),
                            };
                            let _ = call_blocking(state.app_state.db.clone(), move |db| {
                                db.store_message(&bot_msg)
                            })
                            .await;
                        }
                    }
                    Err(e) => {
                        error!("Error processing WhatsApp message: {e}");
                        send_whatsapp_message(
                            &state.http_client,
                            &state.access_token,
                            &state.phone_number_id,
                            &message.from,
                            &format!("Error: {e}"),
                        )
                        .await;
                    }
                }
            }
        }
    }

    Ok(())
}

// --- Send message via WhatsApp Cloud API ---

async fn send_whatsapp_message(
    client: &reqwest::Client,
    access_token: &str,
    phone_number_id: &str,
    to: &str,
    text: &str,
) {
    let url = format!("https://graph.facebook.com/v21.0/{phone_number_id}/messages");

    // Split long messages (WhatsApp limit ~4096 chars)
    const MAX_LEN: usize = 4096;
    let chunks = split_text(text, MAX_LEN);

    for chunk in chunks {
        let body = serde_json::json!({
            "messaging_product": "whatsapp",
            "to": to,
            "text": { "body": chunk }
        });

        match client
            .post(&url)
            .header("Authorization", format!("Bearer {access_token}"))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
        {
            Ok(resp) => {
                if !resp.status().is_success() {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    error!("WhatsApp API error {status}: {body}");
                }
            }
            Err(e) => {
                error!("Failed to send WhatsApp message: {e}");
            }
        }
    }
}

fn split_text(text: &str, max_len: usize) -> Vec<String> {
    if text.len() <= max_len {
        return vec![text.to_string()];
    }

    let mut chunks = Vec::new();
    let mut remaining = text;
    while !remaining.is_empty() {
        let chunk_len = if remaining.len() <= max_len {
            remaining.len()
        } else {
            remaining[..max_len].rfind('\n').unwrap_or(max_len)
        };
        chunks.push(remaining[..chunk_len].to_string());
        remaining = &remaining[chunk_len..];
        if remaining.starts_with('\n') {
            remaining = &remaining[1..];
        }
    }
    chunks
}

// --- Start the WhatsApp webhook server ---

pub async fn start_whatsapp_server(
    app_state: Arc<AppState>,
    access_token: String,
    phone_number_id: String,
    verify_token: String,
    port: u16,
) {
    let wa_state = Arc::new(WhatsAppState {
        app_state,
        access_token,
        phone_number_id,
        verify_token,
        http_client: reqwest::Client::new(),
    });

    let app = Router::new()
        .route("/webhook", get(verify_webhook))
        .route("/webhook", post(handle_webhook))
        .with_state(wa_state);

    let addr = format!("0.0.0.0:{port}");
    info!("WhatsApp webhook server listening on {addr}");

    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind WhatsApp webhook server on {addr}: {e}");
            return;
        }
    };

    if let Err(e) = axum::serve(listener, app).await {
        error!("WhatsApp webhook server error: {e}");
    }
}
