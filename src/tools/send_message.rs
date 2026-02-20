use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::json;
use tracing::{info, warn};

use super::{authorize_chat_access, schema_object, Tool, ToolResult};
use microclaw_channels::channel::{
    deliver_and_store_bot_message, enforce_channel_policy, get_required_chat_routing,
};
use microclaw_channels::channel_adapter::ChannelRegistry;
use microclaw_core::llm_types::ToolDefinition;
use microclaw_storage::db::{call_blocking, Database, StoredMessage};

pub struct SendMessageTool {
    registry: Arc<ChannelRegistry>,
    db: Arc<Database>,
    default_bot_username: String,
    channel_bot_usernames: std::collections::HashMap<String, String>,
}

impl SendMessageTool {
    pub fn new(
        registry: Arc<ChannelRegistry>,
        db: Arc<Database>,
        default_bot_username: String,
        channel_bot_usernames: std::collections::HashMap<String, String>,
    ) -> Self {
        SendMessageTool {
            registry,
            db,
            default_bot_username,
            channel_bot_usernames,
        }
    }

    fn bot_username_for_channel(&self, channel_name: &str) -> String {
        self.channel_bot_usernames
            .get(channel_name)
            .cloned()
            .unwrap_or_else(|| self.default_bot_username.clone())
    }

    async fn store_bot_message(
        &self,
        chat_id: i64,
        sender_name: String,
        content: String,
    ) -> Result<(), String> {
        let msg = StoredMessage {
            id: uuid::Uuid::new_v4().to_string(),
            chat_id,
            sender_name,
            content,
            is_from_bot: true,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        call_blocking(self.db.clone(), move |db| db.store_message(&msg))
            .await
            .map_err(|e| format!("Failed to store sent message: {e}"))
    }

    async fn resolve_external_chat_id(&self, chat_id: i64) -> Result<String, String> {
        let external = call_blocking(self.db.clone(), move |db| db.get_chat_external_id(chat_id))
            .await
            .map_err(|e| format!("Failed to resolve external chat id: {e}"))?;
        Ok(external.unwrap_or_else(|| chat_id.to_string()))
    }
}

#[async_trait]
impl Tool for SendMessageTool {
    fn name(&self) -> &str {
        "send_message"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "send_message".into(),
            description: "Send a message mid-conversation. Supports text for all channels, and attachments for Telegram/Discord/Slack via attachment_path.".into(),
            input_schema: schema_object(
                json!({
                    "chat_id": {
                        "type": "integer",
                        "description": "The target chat ID"
                    },
                    "text": {
                        "type": "string",
                        "description": "The message text to send"
                    },
                    "attachment_path": {
                        "type": "string",
                        "description": "Optional local file path to send as an attachment"
                    },
                    "caption": {
                        "type": "string",
                        "description": "Optional caption used when sending attachment"
                    }
                }),
                &["chat_id"],
            ),
        }
    }

    async fn execute(&self, input: serde_json::Value) -> ToolResult {
        let chat_id = match input.get("chat_id").and_then(|v| v.as_i64()) {
            Some(id) => id,
            None => return ToolResult::error("Missing required parameter: chat_id".into()),
        };
        let text = input
            .get("text")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        let attachment_path = input
            .get("attachment_path")
            .and_then(|v| v.as_str())
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());
        let caption = input
            .get("caption")
            .and_then(|v| v.as_str())
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());

        if text.is_empty() && attachment_path.is_none() {
            return ToolResult::error("Provide text and/or attachment_path".into());
        }
        info!(
            "send_message start: chat_id={}, has_text={}, has_attachment={}",
            chat_id,
            !text.is_empty(),
            attachment_path.is_some()
        );

        if let Err(e) = authorize_chat_access(&input, chat_id) {
            return ToolResult::error(e);
        }

        if let Err(e) =
            enforce_channel_policy(&self.registry, self.db.clone(), &input, chat_id).await
        {
            return ToolResult::error(e);
        }

        if let Some(path) = attachment_path {
            let routing =
                match get_required_chat_routing(&self.registry, self.db.clone(), chat_id).await {
                    Ok(v) => v,
                    Err(e) => return ToolResult::error(e),
                };
            info!(
                "send_message attachment routing: chat_id={}, channel={}, path={}",
                chat_id, routing.channel_name, path
            );

            let file_path = PathBuf::from(&path);
            if !file_path.is_file() {
                warn!(
                    "send_message attachment missing: chat_id={}, path={}, current_dir={}",
                    chat_id,
                    file_path.display(),
                    std::env::current_dir()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|_| "<unknown>".to_string())
                );
                return ToolResult::error(format!(
                    "attachment_path not found or not a file: {path}"
                ));
            }

            let used_caption = caption.or_else(|| {
                if text.is_empty() {
                    None
                } else {
                    Some(text.clone())
                }
            });

            let adapter = match self.registry.get(&routing.channel_name) {
                Some(a) => a,
                None => {
                    return ToolResult::error(format!(
                        "No adapter registered for channel '{}'",
                        routing.channel_name
                    ))
                }
            };

            let external_chat_id = match self.resolve_external_chat_id(chat_id).await {
                Ok(v) => v,
                Err(e) => return ToolResult::error(e),
            };

            let send_result = adapter
                .send_attachment(&external_chat_id, &file_path, used_caption.as_deref())
                .await;

            match send_result {
                Ok(content) => {
                    info!(
                        "send_message attachment sent: chat_id={}, path={}",
                        chat_id,
                        file_path.display()
                    );
                    let sender_name = self.bot_username_for_channel(&routing.channel_name);
                    if let Err(e) = self.store_bot_message(chat_id, sender_name, content).await {
                        warn!(
                            "send_message store_bot_message failed: chat_id={}, error={}",
                            chat_id, e
                        );
                        return ToolResult::error(e);
                    }
                    ToolResult::success("Attachment sent successfully.".into())
                }
                Err(e) => {
                    warn!(
                        "send_message attachment delivery failed: chat_id={}, path={}, error={}",
                        chat_id,
                        file_path.display(),
                        e
                    );
                    ToolResult::error(e)
                }
            }
        } else {
            let sender_name =
                match get_required_chat_routing(&self.registry, self.db.clone(), chat_id).await {
                    Ok(routing) => self.bot_username_for_channel(&routing.channel_name),
                    Err(_) => self.default_bot_username.clone(),
                };
            match deliver_and_store_bot_message(
                &self.registry,
                self.db.clone(),
                &sender_name,
                chat_id,
                &text,
            )
            .await
            {
                Ok(_) => {
                    info!("send_message text sent: chat_id={}", chat_id);
                    ToolResult::success("Message sent successfully.".into())
                }
                Err(e) => {
                    warn!(
                        "send_message text delivery failed: chat_id={}, error={}",
                        chat_id, e
                    );
                    ToolResult::error(e)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::WebAdapter;
    use microclaw_channels::channel::ConversationKind;
    use microclaw_channels::channel_adapter::ChannelAdapter;
    use microclaw_channels::channel_adapter::ChannelRegistry;
    use serde_json::json;
    use std::path::Path;

    fn test_db() -> (Arc<Database>, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("microclaw_sendmsg_{}", uuid::Uuid::new_v4()));
        let db = Arc::new(Database::new(dir.to_str().unwrap()).unwrap());
        (db, dir)
    }

    fn cleanup(dir: &std::path::Path) {
        let _ = std::fs::remove_dir_all(dir);
    }

    fn test_registry() -> Arc<ChannelRegistry> {
        let mut registry = ChannelRegistry::new();
        registry.register(Arc::new(WebAdapter));
        Arc::new(registry)
    }

    struct LocalOnlyAdapter {
        name: String,
    }

    #[async_trait::async_trait]
    impl ChannelAdapter for LocalOnlyAdapter {
        fn name(&self) -> &str {
            &self.name
        }

        fn chat_type_routes(&self) -> Vec<(&str, ConversationKind)> {
            vec![("private", ConversationKind::Private)]
        }

        fn is_local_only(&self) -> bool {
            true
        }

        async fn send_text(&self, _external_chat_id: &str, _text: &str) -> Result<(), String> {
            Ok(())
        }

        async fn send_attachment(
            &self,
            _external_chat_id: &str,
            _file_path: &Path,
            _caption: Option<&str>,
        ) -> Result<String, String> {
            Ok("attachment".to_string())
        }
    }

    #[tokio::test]
    async fn test_send_message_permission_denied_before_network() {
        let (db, dir) = test_db();
        let tool = SendMessageTool::new(
            test_registry(),
            db,
            "bot".into(),
            std::collections::HashMap::new(),
        );
        let result = tool
            .execute(json!({
                "chat_id": 200,
                "text": "hello",
                "__microclaw_auth": {
                    "caller_chat_id": 100,
                    "control_chat_ids": []
                }
            }))
            .await;
        assert!(result.is_error);
        assert!(result.content.contains("Permission denied"));
        cleanup(&dir);
    }

    #[tokio::test]
    async fn test_send_message_web_target_writes_to_db() {
        let (db, dir) = test_db();
        db.upsert_chat(999, Some("web-main"), "web").unwrap();

        let tool = SendMessageTool::new(
            test_registry(),
            db.clone(),
            "bot".into(),
            std::collections::HashMap::new(),
        );
        let result = tool
            .execute(json!({
                "chat_id": 999,
                "text": "hello web",
                "__microclaw_auth": {
                    "caller_chat_id": 999,
                    "control_chat_ids": []
                }
            }))
            .await;
        assert!(!result.is_error, "{}", result.content);

        let all = db.get_all_messages(999).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].content, "hello web");
        assert!(all[0].is_from_bot);
        cleanup(&dir);
    }

    #[tokio::test]
    async fn test_send_message_uses_channel_account_sender_name() {
        let (db, dir) = test_db();
        let chat_id = db
            .resolve_or_create_chat_id("telegram.sales", "9001", Some("sales"), "private")
            .unwrap();

        let mut registry = ChannelRegistry::new();
        registry.register(Arc::new(LocalOnlyAdapter {
            name: "telegram.sales".to_string(),
        }));
        let registry = Arc::new(registry);

        let mut channel_usernames = std::collections::HashMap::new();
        channel_usernames.insert("telegram.sales".to_string(), "sales_bot".to_string());
        let tool = SendMessageTool::new(
            registry,
            db.clone(),
            "default_bot".into(),
            channel_usernames,
        );
        let result = tool
            .execute(json!({
                "chat_id": chat_id,
                "text": "hello",
                "__microclaw_auth": {
                    "caller_chat_id": chat_id,
                    "control_chat_ids": []
                }
            }))
            .await;
        assert!(!result.is_error, "{}", result.content);
        let all = db.get_all_messages(chat_id).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].sender_name, "sales_bot");
        assert_eq!(all[0].content, "hello");
        cleanup(&dir);
    }

    #[tokio::test]
    async fn test_send_message_web_caller_cross_chat_denied() {
        let (db, dir) = test_db();
        db.upsert_chat(100, Some("web-main"), "web").unwrap();
        db.upsert_chat(200, Some("tg"), "private").unwrap();

        // Need telegram adapter registered for "private" chat type
        let mut registry = ChannelRegistry::new();
        registry.register(Arc::new(WebAdapter));
        // Register a minimal telegram adapter to resolve "private" chat type
        use crate::channels::telegram::TelegramChannelConfig;
        use crate::channels::TelegramAdapter;
        let tg_adapter = TelegramAdapter::new(
            "telegram".into(),
            teloxide::Bot::new("123456:TEST_TOKEN"),
            TelegramChannelConfig {
                bot_token: "123456:TEST_TOKEN".into(),
                bot_username: "bot".into(),
                allowed_groups: vec![],
                accounts: std::collections::HashMap::new(),
                default_account: None,
            },
        );
        registry.register(Arc::new(tg_adapter));
        let registry = Arc::new(registry);

        let tool =
            SendMessageTool::new(registry, db, "bot".into(), std::collections::HashMap::new());
        let result = tool
            .execute(json!({
                "chat_id": 200,
                "text": "hello",
                "__microclaw_auth": {
                    "caller_chat_id": 100,
                    "control_chat_ids": [100]
                }
            }))
            .await;
        assert!(result.is_error);
        assert!(result
            .content
            .contains("web chats cannot operate on other chats"));
        cleanup(&dir);
    }

    #[tokio::test]
    async fn test_send_message_requires_text_or_attachment() {
        let (db, dir) = test_db();
        let tool = SendMessageTool::new(
            test_registry(),
            db,
            "bot".into(),
            std::collections::HashMap::new(),
        );
        let result = tool
            .execute(json!({
                "chat_id": 999,
                "text": "   "
            }))
            .await;
        assert!(result.is_error);
        assert!(result
            .content
            .contains("Provide text and/or attachment_path"));
        cleanup(&dir);
    }

    #[tokio::test]
    async fn test_send_attachment_non_telegram_rejected_without_network() {
        let (db, dir) = test_db();
        db.upsert_chat(999, Some("web-main"), "web").unwrap();

        let attachment = dir.join("sample.txt");
        std::fs::write(&attachment, "hello").unwrap();

        let tool = SendMessageTool::new(
            test_registry(),
            db,
            "bot".into(),
            std::collections::HashMap::new(),
        );
        let result = tool
            .execute(json!({
                "chat_id": 999,
                "attachment_path": attachment.to_string_lossy(),
                "caption": "test"
            }))
            .await;
        assert!(result.is_error);
        assert!(result.content.contains("not supported for web"));
        cleanup(&dir);
    }
}
