use std::sync::Arc;

use crate::channel_adapter::ChannelRegistry;
use microclaw_storage::db::{call_blocking, Database, StoredMessage};

#[derive(Clone, Debug)]
struct ToolAuthContext {
    caller_chat_id: i64,
}

fn auth_context_from_input(input: &serde_json::Value) -> Option<ToolAuthContext> {
    let ctx = input.get("__microclaw_auth")?;
    let caller_chat_id = ctx.get("caller_chat_id")?.as_i64()?;
    Some(ToolAuthContext { caller_chat_id })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversationKind {
    Private,
    Group,
}

impl ConversationKind {
    pub fn as_agent_chat_type(self) -> &'static str {
        match self {
            ConversationKind::Private => "private",
            ConversationKind::Group => "group",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatRouting {
    pub channel_name: String,
    pub conversation: ConversationKind,
}

pub fn parse_chat_routing(registry: &ChannelRegistry, db_chat_type: &str) -> Option<ChatRouting> {
    let (channel_name, kind) = registry.resolve_routing(db_chat_type)?;
    Some(ChatRouting {
        channel_name: channel_name.to_string(),
        conversation: kind,
    })
}

pub async fn get_chat_type_raw(db: Arc<Database>, chat_id: i64) -> Result<Option<String>, String> {
    call_blocking(db, move |d| d.get_chat_type(chat_id))
        .await
        .map_err(|e| format!("Failed to read chat type for chat {chat_id}: {e}"))
}

pub async fn get_chat_routing(
    registry: &ChannelRegistry,
    db: Arc<Database>,
    chat_id: i64,
) -> Result<Option<ChatRouting>, String> {
    let chat_type = get_chat_type_raw(db, chat_id).await?;
    Ok(chat_type
        .as_deref()
        .and_then(|ct| parse_chat_routing(registry, ct)))
}

pub async fn get_required_chat_routing(
    registry: &ChannelRegistry,
    db: Arc<Database>,
    chat_id: i64,
) -> Result<ChatRouting, String> {
    let chat_type = get_chat_type_raw(db, chat_id)
        .await?
        .ok_or_else(|| format!("target chat {chat_id} not found"))?;
    parse_chat_routing(registry, &chat_type)
        .ok_or_else(|| format!("unsupported chat type '{chat_type}' for chat {chat_id}"))
}

pub fn session_source_for_chat(
    registry: &ChannelRegistry,
    chat_type: &str,
    chat_title: Option<&str>,
) -> String {
    // Legacy discord detection: some old records have generic types like "private"
    // but a title starting with "discord-"
    if matches!(chat_type, "private" | "group" | "supergroup" | "channel")
        && chat_title.is_some_and(|t| t.starts_with("discord-"))
    {
        return "discord".to_string();
    }

    if let Some((channel_name, _)) = registry.resolve_routing(chat_type) {
        return channel_name.to_string();
    }

    chat_type.to_string()
}

pub async fn is_web_chat(registry: &ChannelRegistry, db: Arc<Database>, chat_id: i64) -> bool {
    get_chat_routing(registry, db, chat_id)
        .await
        .ok()
        .flatten()
        .map(|r| r.channel_name == "web")
        .unwrap_or(false)
}

pub async fn enforce_channel_policy(
    registry: &ChannelRegistry,
    db: Arc<Database>,
    input: &serde_json::Value,
    target_chat_id: i64,
) -> Result<(), String> {
    let Some(auth) = auth_context_from_input(input) else {
        return Ok(());
    };

    // Check if the caller's channel disallows cross-chat operations
    if let Ok(Some(routing)) = get_chat_routing(registry, db.clone(), auth.caller_chat_id).await {
        if let Some(adapter) = registry.get(&routing.channel_name) {
            if !adapter.allows_cross_chat() && auth.caller_chat_id != target_chat_id {
                return Err(format!(
                    "Permission denied: {} chats cannot operate on other chats",
                    routing.channel_name
                ));
            }
        }
    }

    Ok(())
}

pub async fn deliver_and_store_bot_message(
    registry: &ChannelRegistry,
    db: Arc<Database>,
    bot_username: &str,
    chat_id: i64,
    text: &str,
) -> Result<(), String> {
    let routing = get_required_chat_routing(registry, db.clone(), chat_id).await?;
    let external_chat_id = call_blocking(db.clone(), move |d| d.get_chat_external_id(chat_id))
        .await
        .map_err(|e| format!("Failed to read external chat id for chat {chat_id}: {e}"))?
        .unwrap_or_else(|| chat_id.to_string());

    if let Some(adapter) = registry.get(&routing.channel_name) {
        if !adapter.is_local_only() {
            adapter.send_text(&external_chat_id, text).await?;
        }
    } else {
        return Err(format!(
            "No adapter registered for channel '{}'",
            routing.channel_name
        ));
    }

    let msg = StoredMessage {
        id: uuid::Uuid::new_v4().to_string(),
        chat_id,
        sender_name: bot_username.to_string(),
        content: text.to_string(),
        is_from_bot: true,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };
    call_blocking(db.clone(), move |d| d.store_message(&msg))
        .await
        .map_err(|e| format!("Failed to store sent message: {e}"))
}
