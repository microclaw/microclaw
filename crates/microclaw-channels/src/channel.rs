use std::sync::Arc;

use crate::channel_adapter::ChannelRegistry;
use microclaw_core::text::{sanitize_user_visible_text, split_text};
use microclaw_storage::db::{call_blocking, Database, OutboxMessageRecord, StoredMessage};

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

fn infer_channel_from_chat_type(chat_type: &str) -> Option<&'static str> {
    if chat_type.starts_with("telegram_") {
        return Some("telegram");
    }
    if chat_type.starts_with("discord_") {
        return Some("discord");
    }
    if chat_type.starts_with("slack_") {
        return Some("slack");
    }
    if chat_type.starts_with("feishu_") {
        return Some("feishu");
    }
    if chat_type.starts_with("matrix_") {
        return Some("matrix");
    }
    if chat_type.starts_with("whatsapp_") {
        return Some("whatsapp");
    }
    if chat_type.starts_with("imessage_") {
        return Some("imessage");
    }
    if chat_type.starts_with("email_") {
        return Some("email");
    }
    if chat_type.starts_with("nostr_") {
        return Some("nostr");
    }
    if chat_type.starts_with("signal_") {
        return Some("signal");
    }
    if chat_type.starts_with("dingtalk_") {
        return Some("dingtalk");
    }
    if chat_type.starts_with("qq_") {
        return Some("qq");
    }
    if chat_type.starts_with("weixin_") {
        return Some("weixin");
    }
    if chat_type.starts_with("irc_") {
        return Some("irc");
    }
    None
}

pub async fn get_chat_type_raw(db: Arc<Database>, chat_id: i64) -> Result<Option<String>, String> {
    call_blocking(db, move |d| d.get_chat_type(chat_id))
        .await
        .map_err(|e| format!("Failed to read chat type for chat {chat_id}: {e}"))
}

pub async fn get_chat_channel_raw(
    db: Arc<Database>,
    chat_id: i64,
) -> Result<Option<String>, String> {
    call_blocking(db, move |d| d.get_chat_channel(chat_id))
        .await
        .map_err(|e| format!("Failed to read chat channel for chat {chat_id}: {e}"))
}

pub async fn get_chat_routing(
    registry: &ChannelRegistry,
    db: Arc<Database>,
    chat_id: i64,
) -> Result<Option<ChatRouting>, String> {
    let chat_type = get_chat_type_raw(db.clone(), chat_id).await?;
    let Some(chat_type) = chat_type else {
        return Ok(None);
    };

    let kind = registry
        .resolve_routing(&chat_type)
        .map(|(_, k)| k)
        .unwrap_or(ConversationKind::Group);

    if let Some(channel_name) = get_chat_channel_raw(db, chat_id).await? {
        let normalized = channel_name.trim();
        if !normalized.is_empty() && registry.get(normalized).is_some() {
            return Ok(Some(ChatRouting {
                channel_name: normalized.to_string(),
                conversation: kind,
            }));
        }
    }

    Ok(parse_chat_routing(registry, &chat_type))
}

pub async fn get_required_chat_routing(
    registry: &ChannelRegistry,
    db: Arc<Database>,
    chat_id: i64,
) -> Result<ChatRouting, String> {
    let chat_type = get_chat_type_raw(db.clone(), chat_id)
        .await?
        .ok_or_else(|| format!("target chat {chat_id} not found"))?;
    if let Some(routing) = get_chat_routing(registry, db.clone(), chat_id).await? {
        return Ok(routing);
    }

    let hinted_channel = get_chat_channel_raw(db, chat_id)
        .await?
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .or_else(|| infer_channel_from_chat_type(&chat_type).map(ToOwned::to_owned));

    if let Some(channel_name) = hinted_channel {
        if registry.get(&channel_name).is_none() {
            return Err(format!(
                "channel '{channel_name}' is not enabled for chat {chat_id} (chat_type='{chat_type}')"
            ));
        }
    }

    Err(format!(
        "unsupported chat type '{chat_type}' for chat {chat_id}"
    ))
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryOutcome {
    Delivered,
    Queued {
        delivery_id: String,
        failed_chunk: usize,
        total_chunks: usize,
    },
}

pub async fn deliver_and_store_bot_message(
    registry: &ChannelRegistry,
    db: Arc<Database>,
    bot_username: &str,
    chat_id: i64,
    text: &str,
) -> Result<(), String> {
    deliver_and_store_bot_message_with_status(registry, db, bot_username, chat_id, text)
        .await
        .map(|_| ())
}

pub async fn deliver_and_store_bot_message_with_status(
    registry: &ChannelRegistry,
    db: Arc<Database>,
    bot_username: &str,
    chat_id: i64,
    text: &str,
) -> Result<DeliveryOutcome, String> {
    let routing = get_required_chat_routing(registry, db.clone(), chat_id).await?;
    let external_chat_id = call_blocking(db.clone(), move |d| d.get_chat_external_id(chat_id))
        .await
        .map_err(|e| format!("Failed to read external chat id for chat {chat_id}: {e}"))?
        .unwrap_or_else(|| chat_id.to_string());

    // This choke point is the final defense against model/runtime protocol
    // details leaking into any user-facing channel.
    let visible = sanitize_user_visible_text(text);
    if visible.is_empty() && !text.trim().is_empty() {
        return Err("outbound message contained no user-visible text".to_string());
    }

    // Outbound guardrail: scan for credential-like strings before delivery.
    let guarded =
        microclaw_core::redact::apply_output_guardrail(&visible, registry.output_guardrail());
    if let Some(outcome) = &guarded {
        tracing::warn!(
            target: "output_guardrail",
            chat_id,
            blocked = outcome.blocked,
            categories = ?outcome.categories,
            "outbound message tripped the output guardrail"
        );
    }
    let text: &str = guarded
        .as_ref()
        .map(|o| o.text.as_str())
        .unwrap_or(&visible);

    if let Some(adapter) = registry.get(&routing.channel_name) {
        if adapter.is_local_only() {
            store_bot_message(db, bot_username, chat_id, text).await?;
            return Ok(DeliveryOutcome::Delivered);
        }

        let chunks = adapter
            .text_chunk_limit_bytes()
            .map(|limit| split_text(text, limit))
            .unwrap_or_else(|| vec![text.to_string()]);
        let delivery_id = format!("delivery-{}", uuid::Uuid::new_v4());
        let delivery_id_for_create = delivery_id.clone();
        let channel_for_create = routing.channel_name.clone();
        let full_text = text.to_string();
        let chunks_for_create = chunks.clone();
        let chunk_ids = call_blocking(db.clone(), move |d| {
            d.create_outbound_delivery(
                &delivery_id_for_create,
                chat_id,
                &channel_for_create,
                &full_text,
                &chunks_for_create,
            )
        })
        .await
        .map_err(|e| format!("Failed to persist outbound delivery: {e}"))?;

        for (index, (chunk_id, chunk)) in chunk_ids.iter().zip(chunks.iter()).enumerate() {
            let chunk_id = *chunk_id;
            let claimed = call_blocking(db.clone(), move |d| d.mark_outbox_sending(chunk_id))
                .await
                .map_err(|e| format!("Failed to claim outbound chunk: {e}"))?;
            if !claimed {
                continue;
            }
            let idempotency_key = format!("{delivery_id}:{}", index + 1);
            if let Err(err) = adapter
                .send_text_chunk(&external_chat_id, chunk, &idempotency_key)
                .await
            {
                let retry_at = chrono::Utc::now().to_rfc3339();
                let error_for_db = err.clone();
                call_blocking(db.clone(), move |d| {
                    d.mark_outbox_retry(chunk_id, 1, Some(&retry_at), &error_for_db, false)
                })
                .await
                .map_err(|e| format!("{err}; failed to queue chunk retry: {e}"))?;
                tracing::warn!(
                    delivery_id,
                    failed_chunk = index + 1,
                    total_chunks = chunks.len(),
                    error = %err,
                    "outbound delivery accepted durably and queued for retry"
                );
                return Ok(DeliveryOutcome::Queued {
                    delivery_id,
                    failed_chunk: index + 1,
                    total_chunks: chunks.len(),
                });
            }
            call_blocking(db.clone(), move |d| d.mark_outbox_delivered(chunk_id))
                .await
                .map_err(|e| format!("Chunk sent but delivery ledger update failed: {e}"))?;
            if index + 1 < chunks.len() {
                if let Some(delay) = adapter.text_chunk_delay() {
                    tokio::time::sleep(delay).await;
                }
            }
        }

        let delivery_for_finalize = delivery_id.clone();
        let sender = bot_username.to_string();
        call_blocking(db.clone(), move |d| {
            d.finalize_outbound_delivery(&delivery_for_finalize, &sender)
                .map(|_| ())
        })
        .await
        .map_err(|e| format!("Delivery completed but message persistence failed: {e}"))?;
        Ok(DeliveryOutcome::Delivered)
    } else {
        Err(format!(
            "No adapter registered for channel '{}'",
            routing.channel_name
        ))
    }
}

async fn store_bot_message(
    db: Arc<Database>,
    bot_username: &str,
    chat_id: i64,
    text: &str,
) -> Result<(), String> {
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

/// Send one persisted outbox chunk. The caller owns retry/backoff policy.
pub async fn send_persisted_outbox_chunk(
    registry: &ChannelRegistry,
    db: Arc<Database>,
    bot_username: &str,
    row: &OutboxMessageRecord,
) -> Result<bool, String> {
    let row_id = row.id;
    let claimed = call_blocking(db.clone(), move |d| d.mark_outbox_sending(row_id))
        .await
        .map_err(|e| format!("Failed to claim outbox chunk: {e}"))?;
    if !claimed {
        return Ok(false);
    }
    let routing = get_required_chat_routing(registry, db.clone(), row.chat_id).await?;
    if routing.channel_name != row.channel {
        return Err(format!(
            "delivery channel changed from '{}' to '{}'",
            row.channel, routing.channel_name
        ));
    }
    let chat_id = row.chat_id;
    let external_chat_id = call_blocking(db.clone(), move |d| d.get_chat_external_id(chat_id))
        .await
        .map_err(|e| format!("Failed to read external chat id for chat {chat_id}: {e}"))?
        .unwrap_or_else(|| chat_id.to_string());
    let adapter = registry.get(&routing.channel_name).ok_or_else(|| {
        format!(
            "No adapter registered for channel '{}'",
            routing.channel_name
        )
    })?;
    adapter
        .send_text_chunk(&external_chat_id, &row.payload_text, &row.idempotency_key)
        .await?;
    let chunk_id = row.id;
    call_blocking(db.clone(), move |d| d.mark_outbox_delivered(chunk_id))
        .await
        .map_err(|e| format!("Chunk sent but ledger update failed: {e}"))?;
    let delivery_id = row.delivery_id.clone();
    let sender = bot_username.to_string();
    call_blocking(db, move |d| {
        d.finalize_outbound_delivery(&delivery_id, &sender)
    })
    .await
    .map_err(|e| format!("Failed to finalize outbound delivery: {e}"))
}

#[cfg(test)]
mod tests {
    use super::infer_channel_from_chat_type;

    #[test]
    fn test_infer_channel_from_prefixed_chat_type() {
        assert_eq!(
            infer_channel_from_chat_type("telegram_private"),
            Some("telegram")
        );
        assert_eq!(infer_channel_from_chat_type("discord_dm"), Some("discord"));
        assert_eq!(infer_channel_from_chat_type("weixin_dm"), Some("weixin"));
    }

    #[test]
    fn test_infer_channel_from_unknown_chat_type() {
        assert_eq!(infer_channel_from_chat_type("private"), None);
        assert_eq!(infer_channel_from_chat_type("group"), None);
    }
}
