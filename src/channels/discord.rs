use std::error::Error;
use std::path::Path;
use std::sync::Arc;

use serde::Deserialize;
use serde_json::json;
use serenity::async_trait;
use serenity::model::channel::Message as DiscordMessage;
use serenity::model::gateway::Ready;
use serenity::model::id::ChannelId;
use serenity::prelude::*;
use tracing::{error, info, warn};

use crate::agent_engine::archive_conversation;
use crate::agent_engine::process_with_agent_with_events;
use crate::agent_engine::AgentEvent;
use crate::agent_engine::AgentRequestContext;
use crate::channel::ConversationKind;
use crate::channel_adapter::ChannelAdapter;
use crate::db::call_blocking;
use crate::db::StoredMessage;
use crate::llm_types::Message as LlmMessage;
use crate::runtime::AppState;
use crate::text::{floor_char_boundary, split_text};
use crate::usage::build_usage_report;

#[derive(Debug, Clone, Deserialize)]
pub struct DiscordChannelConfig {
    pub bot_token: String,
    #[serde(default)]
    pub allowed_channels: Vec<u64>,
}

pub struct DiscordAdapter {
    token: String,
    http_client: reqwest::Client,
}

fn format_reqwest_error(prefix: &str, err: &reqwest::Error) -> String {
    let mut details = Vec::new();
    if err.is_timeout() {
        details.push("timeout");
    }
    if err.is_connect() {
        details.push("connect");
    }
    if err.is_request() {
        details.push("request");
    }
    if err.is_body() {
        details.push("body");
    }
    if err.is_decode() {
        details.push("decode");
    }
    if err.is_status() {
        details.push("status");
    }

    let mut source_chain = Vec::new();
    let mut source = err.source();
    while let Some(s) = source {
        source_chain.push(s.to_string());
        source = s.source();
    }

    let url = err
        .url()
        .map(|u| u.as_str().to_string())
        .unwrap_or_default();
    let class = if details.is_empty() {
        "unknown".to_string()
    } else {
        details.join("|")
    };
    if source_chain.is_empty() {
        format!("{prefix}: {err} [class={class}, url={url}]")
    } else {
        format!(
            "{prefix}: {err} [class={class}, url={url}, source_chain={}]",
            source_chain.join(" -> ")
        )
    }
}

impl DiscordAdapter {
    pub fn new(token: String) -> Self {
        DiscordAdapter {
            token,
            http_client: reqwest::Client::new(),
        }
    }
}

#[async_trait::async_trait]
impl ChannelAdapter for DiscordAdapter {
    fn name(&self) -> &str {
        "discord"
    }

    fn chat_type_routes(&self) -> Vec<(&str, ConversationKind)> {
        vec![("discord", ConversationKind::Private)]
    }

    async fn send_text(&self, external_chat_id: &str, text: &str) -> Result<(), String> {
        let discord_chat_id = external_chat_id
            .parse::<u64>()
            .map_err(|_| format!("Invalid Discord external_chat_id '{}'", external_chat_id))?;

        let url = format!("https://discord.com/api/v10/channels/{discord_chat_id}/messages");

        for chunk in split_text(text, 2000) {
            let body = json!({ "content": chunk });
            let resp = self
                .http_client
                .post(&url)
                .header(
                    reqwest::header::AUTHORIZATION,
                    format!("Bot {}", self.token),
                )
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .json(&body)
                .send()
                .await
                .map_err(|e| format_reqwest_error("Failed to send Discord message", &e))?;

            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                return Err(format!(
                    "Failed to send Discord message: HTTP {status} {}",
                    body.chars().take(300).collect::<String>()
                ));
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
        let discord_chat_id = external_chat_id
            .parse::<u64>()
            .map_err(|_| format!("Invalid Discord external_chat_id '{}'", external_chat_id))?;

        let filename = file_path
            .file_name()
            .and_then(|v| v.to_str())
            .unwrap_or("attachment.bin")
            .to_string();
        let bytes = tokio::fs::read(file_path)
            .await
            .map_err(|e| format!("Failed to read attachment file: {e}"))?;

        let payload = json!({ "content": caption.unwrap_or_default() });
        let form = reqwest::multipart::Form::new()
            .text("payload_json", payload.to_string())
            .part(
                "files[0]",
                reqwest::multipart::Part::bytes(bytes).file_name(filename),
            );

        let url = format!("https://discord.com/api/v10/channels/{discord_chat_id}/messages");
        let resp = self
            .http_client
            .post(url)
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bot {}", self.token),
            )
            .multipart(form)
            .send()
            .await
            .map_err(|e| format_reqwest_error("Failed to send Discord attachment", &e))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!(
                "Failed to send Discord attachment: HTTP {status} {}",
                body.chars().take(300).collect::<String>()
            ));
        }

        Ok(match caption {
            Some(c) => format!("[attachment:{}] {}", file_path.display(), c),
            None => format!("[attachment:{}]", file_path.display()),
        })
    }
}

struct Handler {
    app_state: Arc<AppState>,
}

#[async_trait]
impl EventHandler for Handler {
    async fn message(&self, ctx: Context, msg: DiscordMessage) {
        // Ignore messages from bots (including ourselves)
        if msg.author.bot {
            return;
        }

        let text = msg.content.clone();
        let external_channel_id = msg.channel_id.get();
        let channel_id = {
            let external_chat_id = external_channel_id.to_string();
            let chat_type = "discord".to_string();
            let title = format!("discord-{external_channel_id}");
            call_blocking(self.app_state.db.clone(), move |db| {
                db.resolve_or_create_chat_id("discord", &external_chat_id, Some(&title), &chat_type)
            })
            .await
            .unwrap_or(external_channel_id as i64)
        };
        let sender_name = msg.author.name.clone();

        // Check allowed channels (empty = all)
        if !self.app_state.config.discord_allowed_channels.is_empty()
            && !self
                .app_state
                .config
                .discord_allowed_channels
                .contains(&external_channel_id)
        {
            return;
        }

        // Handle /reset command
        if text.trim() == "/reset" {
            let _ = call_blocking(self.app_state.db.clone(), move |db| {
                db.clear_chat_context(channel_id)
            })
            .await;
            let _ = msg
                .channel_id
                .say(&ctx.http, "Context cleared (session + chat history).")
                .await;
            return;
        }

        // Handle /skills command
        if text.trim() == "/skills" {
            let formatted = self.app_state.skills.list_skills_formatted();
            let _ = msg.channel_id.say(&ctx.http, &formatted).await;
            return;
        }

        // Handle /archive command
        if text.trim() == "/archive" {
            if let Ok(Some((json, _))) = call_blocking(self.app_state.db.clone(), move |db| {
                db.load_session(channel_id)
            })
            .await
            {
                let messages: Vec<LlmMessage> = serde_json::from_str(&json).unwrap_or_default();
                if messages.is_empty() {
                    let _ = msg
                        .channel_id
                        .say(&ctx.http, "No session to archive.")
                        .await;
                } else {
                    archive_conversation(
                        &self.app_state.config.data_dir,
                        "discord",
                        channel_id,
                        &messages,
                    );
                    let _ = msg
                        .channel_id
                        .say(&ctx.http, format!("Archived {} messages.", messages.len()))
                        .await;
                }
            } else {
                let _ = msg
                    .channel_id
                    .say(&ctx.http, "No session to archive.")
                    .await;
            }
            return;
        }

        // Handle /usage command
        if text.trim() == "/usage" {
            match build_usage_report(
                self.app_state.db.clone(),
                &self.app_state.config,
                channel_id,
            )
            .await
            {
                Ok(text) => {
                    let _ = msg.channel_id.say(&ctx.http, text).await;
                }
                Err(e) => {
                    let _ = msg
                        .channel_id
                        .say(&ctx.http, format!("Failed to query usage statistics: {e}"))
                        .await;
                }
            }
            return;
        }

        if text.is_empty() {
            if msg.guild_id.is_some() {
                info!(
                    "Discord message content is empty in guild channel {}. If this persists, enable Message Content Intent in Discord Developer Portal (Bot -> Privileged Gateway Intents).",
                    channel_id
                );
            }
            return;
        }

        // Store the chat and message
        let title = format!("discord-{external_channel_id}");
        let _ = call_blocking(self.app_state.db.clone(), move |db| {
            db.upsert_chat(channel_id, Some(&title), "discord")
        })
        .await;

        let stored = StoredMessage {
            id: msg.id.get().to_string(),
            chat_id: channel_id,
            sender_name: sender_name.clone(),
            content: text.clone(),
            is_from_bot: false,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        let _ = call_blocking(self.app_state.db.clone(), move |db| {
            db.store_message(&stored)
        })
        .await;

        // Determine if we should respond
        let should_respond = if msg.guild_id.is_some() {
            // In a guild: only respond to @mentions
            let cache = &ctx.cache;
            let bot_id = cache.current_user().id;
            msg.mentions.iter().any(|u| u.id == bot_id)
        } else {
            // DM: respond to all messages
            true
        };

        if !should_respond {
            return;
        }

        info!(
            "Discord message from {} in channel {}: {}",
            sender_name,
            channel_id,
            text.chars().take(100).collect::<String>()
        );

        // Start typing indicator
        let typing = msg.channel_id.start_typing(&ctx.http);

        let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel::<AgentEvent>();
        // Process with shared agent engine (reuses the same loop as Telegram)
        match process_with_agent_with_events(
            &self.app_state,
            AgentRequestContext {
                caller_channel: "discord",
                chat_id: channel_id,
                chat_type: if msg.guild_id.is_some() {
                    "group"
                } else {
                    "private"
                },
            },
            None,
            None,
            Some(&event_tx),
        )
        .await
        {
            Ok(response) => {
                drop(typing);
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
                    send_discord_response(&ctx, msg.channel_id, &response).await;

                    // Store bot response
                    let bot_msg = StoredMessage {
                        id: uuid::Uuid::new_v4().to_string(),
                        chat_id: channel_id,
                        sender_name: self.app_state.config.bot_username.clone(),
                        content: response,
                        is_from_bot: true,
                        timestamp: chrono::Utc::now().to_rfc3339(),
                    };
                    let _ = call_blocking(self.app_state.db.clone(), move |db| {
                        db.store_message(&bot_msg)
                    })
                    .await;
                } else if !used_send_message_tool {
                    let fallback = "I couldn't produce a visible reply after an automatic retry. Please try again.".to_string();
                    send_discord_response(&ctx, msg.channel_id, &fallback).await;

                    let bot_msg = StoredMessage {
                        id: uuid::Uuid::new_v4().to_string(),
                        chat_id: channel_id,
                        sender_name: self.app_state.config.bot_username.clone(),
                        content: fallback,
                        is_from_bot: true,
                        timestamp: chrono::Utc::now().to_rfc3339(),
                    };
                    let _ = call_blocking(self.app_state.db.clone(), move |db| {
                        db.store_message(&bot_msg)
                    })
                    .await;
                }
            }
            Err(e) => {
                drop(typing);
                error!("Error processing Discord message: {e}");
                let _ = msg.channel_id.say(&ctx.http, format!("Error: {e}")).await;
            }
        }
    }

    async fn ready(&self, _ctx: Context, ready: Ready) {
        info!("Discord bot connected as {}", ready.user.name);
    }
}

/// Split and send long messages (Discord limit is 2000 chars).
async fn send_discord_response(ctx: &Context, channel_id: ChannelId, text: &str) {
    const MAX_LEN: usize = 2000;

    if text.len() <= MAX_LEN {
        let _ = channel_id.say(&ctx.http, text).await;
        return;
    }

    let mut remaining = text;
    while !remaining.is_empty() {
        let chunk_len = if remaining.len() <= MAX_LEN {
            remaining.len()
        } else {
            let boundary = floor_char_boundary(remaining, MAX_LEN.min(remaining.len()));
            remaining[..boundary].rfind('\n').unwrap_or(boundary)
        };

        let chunk = &remaining[..chunk_len];
        let _ = channel_id.say(&ctx.http, chunk).await;
        remaining = &remaining[chunk_len..];

        if remaining.starts_with('\n') {
            remaining = &remaining[1..];
        }
    }
}

async fn run_discord_client(
    app_state: Arc<AppState>,
    token: &str,
    intents: GatewayIntents,
) -> Result<(), serenity::Error> {
    let handler = Handler { app_state };
    let mut client = Client::builder(token, intents)
        .event_handler(handler)
        .await?;
    client.start().await
}

fn is_disallowed_gateway_intents(err: &serenity::Error) -> bool {
    let text = err.to_string().to_ascii_lowercase();
    text.contains("disallowed gateway intents")
        || text.contains("disallowed intent")
        || text.contains("4014")
}

/// Start the Discord bot. Called from run_bot() if discord_bot_token is configured.
pub async fn start_discord_bot(app_state: Arc<AppState>, token: &str) {
    let base_intents = GatewayIntents::GUILD_MESSAGES | GatewayIntents::DIRECT_MESSAGES;
    let full_intents = base_intents | GatewayIntents::MESSAGE_CONTENT;

    info!("Starting Discord bot (requesting MESSAGE_CONTENT intent)...");
    match run_discord_client(app_state.clone(), token, full_intents).await {
        Ok(()) => {}
        Err(e) if is_disallowed_gateway_intents(&e) => {
            warn!(
                "Discord rejected MESSAGE_CONTENT intent (4014). Falling back to non-privileged intents. Enable Message Content Intent in Discord Developer Portal for full behavior."
            );
            if let Err(e2) = run_discord_client(app_state, token, base_intents).await {
                error!("Discord bot error (fallback intents): {e2}");
            }
        }
        Err(e) => {
            error!("Discord bot error: {e}");
        }
    }
}
