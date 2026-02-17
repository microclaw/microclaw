use std::sync::Arc;

use serenity::async_trait;
use serenity::model::channel::Message as DiscordMessage;
use serenity::model::gateway::Ready;
use serenity::model::id::ChannelId;
use serenity::prelude::*;
use tracing::{error, info};

use crate::claude::Message as ClaudeMessage;
use crate::db::call_blocking;
use crate::db::StoredMessage;
use crate::slash_commands::{parse as parse_slash_command, SlashCommand};
use crate::telegram::{archive_conversation, AgentRequestContext, AppState};

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
        let channel_id = msg.channel_id.get() as i64;
        let sender_name = msg.author.name.clone();

        // Check allowed channels (empty = all)
        if !self.app_state.config.discord_allowed_channels.is_empty()
            && !self
                .app_state
                .config
                .discord_allowed_channels
                .contains(&(channel_id as u64))
        {
            return;
        }

        // Single entry point: parse slash command first. If command, run backend handler and return — never send to LLM.
        if let Some(cmd) = parse_slash_command(&text) {
            match cmd {
                SlashCommand::Reset => {
                    let pid = call_blocking(self.app_state.db.clone(), move |db| db.get_current_persona_id(channel_id)).await.unwrap_or(0);
                    if pid > 0 {
                        let _ = call_blocking(self.app_state.db.clone(), move |db| db.delete_session(channel_id, pid)).await;
                    }
                    let _ = msg
                        .channel_id
                        .say(
                            &ctx.http,
                            "Conversation cleared. Principles and per-persona memory are unchanged.",
                        )
                        .await;
                }
                SlashCommand::Skills => {
                    let formatted = self.app_state.skills.list_skills_formatted();
                    let _ = msg.channel_id.say(&ctx.http, &formatted).await;
                }
                SlashCommand::Persona => {
                    let resp = crate::persona::handle_persona_command(self.app_state.db.clone(), channel_id, text.trim(), Some(&self.app_state.config)).await;
                    let _ = msg.channel_id.say(&ctx.http, resp).await;
                }
                SlashCommand::Schedule => {
                    let tasks = call_blocking(self.app_state.db.clone(), move |db| db.get_tasks_for_chat(channel_id)).await;
                    let text = match &tasks {
                        Ok(t) => crate::tools::schedule::format_tasks_list(t),
                        Err(e) => format!("Error listing tasks: {e}"),
                    };
                    let _ = msg.channel_id.say(&ctx.http, &text).await;
                }
                SlashCommand::Archive => {
                    let pid = call_blocking(self.app_state.db.clone(), move |db| db.get_current_persona_id(channel_id)).await.unwrap_or(0);
                    if pid == 0 {
                        let _ = msg.channel_id.say(&ctx.http, "No session to archive.").await;
                    } else {
                        let pid_f = pid;
                        if let Ok(Some((json, _))) = call_blocking(self.app_state.db.clone(), move |db| {
                            db.load_session(channel_id, pid_f)
                        })
                        .await
                        {
                            let messages: Vec<ClaudeMessage> = serde_json::from_str(&json).unwrap_or_default();
                            if messages.is_empty() {
                                let _ = msg.channel_id.say(&ctx.http, "No session to archive.").await;
                            } else {
                                archive_conversation(&self.app_state.config.runtime_data_dir(), channel_id, &messages);
                                let _ = msg
                                    .channel_id
                                    .say(&ctx.http, format!("Archived {} messages.", messages.len()))
                                    .await;
                            }
                        } else {
                            let _ = msg.channel_id.say(&ctx.http, "No session to archive.").await;
                        }
                    }
                }
            }
            return;
        }

        if text.is_empty() {
            return;
        }

        // Resolve persona
        let persona_id = call_blocking(self.app_state.db.clone(), move |db| db.get_current_persona_id(channel_id)).await.unwrap_or(0);
        if persona_id == 0 {
            return;
        }

        // Store the chat and message
        let title = format!("discord-{}", msg.channel_id.get());
        let _ = call_blocking(self.app_state.db.clone(), move |db| {
            db.upsert_chat(channel_id, Some(&title), "discord")
        })
        .await;

        let stored = StoredMessage {
            id: msg.id.get().to_string(),
            chat_id: channel_id,
            persona_id,
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

        // Process with Claude (reuses the same agentic loop as Telegram)
        match crate::telegram::process_with_agent(
            &self.app_state,
            AgentRequestContext {
                caller_channel: "discord",
                chat_id: channel_id,
                chat_type: if msg.guild_id.is_some() {
                    "group"
                } else {
                    "private"
                },
                persona_id,
            },
            None,
            None,
        )
        .await
        {
            Ok(response) => {
                drop(typing);
                if !response.is_empty() {
                    send_discord_response(&ctx, msg.channel_id, &response).await;

                    // Store bot response
                    let bot_msg = StoredMessage {
                        id: uuid::Uuid::new_v4().to_string(),
                        chat_id: channel_id,
                        persona_id,
                        sender_name: self.app_state.config.bot_username.clone(),
                        content: response,
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
            remaining[..MAX_LEN].rfind('\n').unwrap_or(MAX_LEN)
        };

        let chunk = &remaining[..chunk_len];
        let _ = channel_id.say(&ctx.http, chunk).await;
        remaining = &remaining[chunk_len..];

        if remaining.starts_with('\n') {
            remaining = &remaining[1..];
        }
    }
}

/// Start the Discord bot. Called from run_bot() if discord_bot_token is configured.
pub async fn start_discord_bot(app_state: Arc<AppState>, token: &str) {
    let intents = GatewayIntents::GUILD_MESSAGES
        | GatewayIntents::DIRECT_MESSAGES
        | GatewayIntents::MESSAGE_CONTENT;

    let handler = Handler { app_state };

    let mut client = match Client::builder(token, intents).event_handler(handler).await {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to create Discord client: {e}");
            return;
        }
    };

    info!("Starting Discord bot...");
    if let Err(e) = client.start().await {
        error!("Discord bot error: {e}");
    }
}
