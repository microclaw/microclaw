use std::sync::Arc;

use async_trait::async_trait;
use serde_json::json;

use super::{authorize_chat_access, schema_object, Tool, ToolResult};
use microclaw_core::llm_types::ToolDefinition;
use microclaw_storage::db::{call_blocking, Database};

pub struct ExportChatTool {
    db: Arc<Database>,
    data_dir: String,
}

impl ExportChatTool {
    pub fn new(db: Arc<Database>, data_dir: &str) -> Self {
        ExportChatTool {
            db,
            data_dir: data_dir.to_string(),
        }
    }
}

#[async_trait]
impl Tool for ExportChatTool {
    fn name(&self) -> &str {
        "export_chat"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "export_chat".into(),
            description: "Export chat history to a markdown file. Returns the file path.".into(),
            input_schema: schema_object(
                json!({
                    "chat_id": {
                        "type": "integer",
                        "description": "The chat ID to export"
                    },
                    "path": {
                        "type": "string",
                        "description": "Optional output file path. Defaults to data/exports/{chat_id}_{timestamp}.md"
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
        if let Err(e) = authorize_chat_access(&input, chat_id) {
            return ToolResult::error(e);
        }

        let messages =
            match call_blocking(self.db.clone(), move |db| db.get_all_messages(chat_id)).await {
                Ok(msgs) => msgs,
                Err(e) => return ToolResult::error(format!("Failed to load messages: {e}")),
            };

        if messages.is_empty() {
            return ToolResult::error(format!("No messages found for chat {chat_id}."));
        }

        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
        let default_path = format!("{}/exports/{}_{}.md", self.data_dir, chat_id, timestamp);
        let path = input
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or(&default_path);

        // Build markdown
        let mut md = format!("# Chat Export: {chat_id}\n\n");
        md.push_str(&format!(
            "Exported at: {}\n\n---\n\n",
            chrono::Utc::now().to_rfc3339()
        ));

        for msg in &messages {
            let sender = if msg.is_from_bot {
                "**Bot**"
            } else {
                &msg.sender_name
            };
            md.push_str(&format!(
                "**{}** ({})\n\n{}\n\n---\n\n",
                sender, msg.timestamp, msg.content
            ));
        }

        // Write file
        let path = std::path::Path::new(path);
        if let Some(parent) = path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                return ToolResult::error(format!("Failed to create directory: {e}"));
            }
        }
        match std::fs::write(path, &md) {
            Ok(_) => ToolResult::success(format!(
                "Exported {} messages to {}",
                messages.len(),
                path.display()
            )),
            Err(e) => ToolResult::error(format!("Failed to write file: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use microclaw_storage::db::{Database, StoredMessage};

    fn test_db() -> (Arc<Database>, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("microclaw_export_{}", uuid::Uuid::new_v4()));
        let db = Arc::new(Database::new(dir.to_str().unwrap()).unwrap());
        (db, dir)
    }

    fn cleanup(dir: &std::path::Path) {
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn test_export_empty_chat() {
        let (db, dir) = test_db();
        let tool = ExportChatTool::new(db, dir.to_str().unwrap());
        let result = tool.execute(json!({"chat_id": 999})).await;
        assert!(result.is_error);
        assert!(result.content.contains("No messages"));
        cleanup(&dir);
    }

    #[tokio::test]
    async fn test_export_chat_success() {
        let (db, dir) = test_db();
        db.store_message(&StoredMessage {
            id: "m1".into(),
            chat_id: 100,
            sender_name: "alice".into(),
            content: "hello".into(),
            is_from_bot: false,
            timestamp: "2024-01-01T00:00:01Z".into(),
        })
        .unwrap();
        db.store_message(&StoredMessage {
            id: "m2".into(),
            chat_id: 100,
            sender_name: "bot".into(),
            content: "hi there!".into(),
            is_from_bot: true,
            timestamp: "2024-01-01T00:00:02Z".into(),
        })
        .unwrap();

        let out_path = dir.join("test_export.md");
        let tool = ExportChatTool::new(db, dir.to_str().unwrap());
        let result = tool
            .execute(json!({"chat_id": 100, "path": out_path.to_str().unwrap()}))
            .await;
        assert!(!result.is_error, "Error: {}", result.content);
        assert!(result.content.contains("2 messages"));

        let content = std::fs::read_to_string(&out_path).unwrap();
        assert!(content.contains("alice"));
        assert!(content.contains("hello"));
        assert!(content.contains("**Bot**"));
        assert!(content.contains("hi there!"));
        cleanup(&dir);
    }

    #[tokio::test]
    async fn test_export_chat_permission_denied() {
        let (db, dir) = test_db();
        db.store_message(&StoredMessage {
            id: "m1".into(),
            chat_id: 200,
            sender_name: "alice".into(),
            content: "hello".into(),
            is_from_bot: false,
            timestamp: "2024-01-01T00:00:01Z".into(),
        })
        .unwrap();

        let tool = ExportChatTool::new(db, dir.to_str().unwrap());
        let result = tool
            .execute(json!({
                "chat_id": 200,
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
    async fn test_export_chat_allowed_for_control_chat_cross_chat() {
        let (db, dir) = test_db();
        db.store_message(&StoredMessage {
            id: "m1".into(),
            chat_id: 200,
            sender_name: "alice".into(),
            content: "hello".into(),
            is_from_bot: false,
            timestamp: "2024-01-01T00:00:01Z".into(),
        })
        .unwrap();
        let out_path = dir.join("control_export.md");
        let tool = ExportChatTool::new(db, dir.to_str().unwrap());
        let result = tool
            .execute(json!({
                "chat_id": 200,
                "path": out_path.to_str().unwrap(),
                "__microclaw_auth": {
                    "caller_chat_id": 100,
                    "control_chat_ids": [100]
                }
            }))
            .await;
        assert!(!result.is_error, "{}", result.content);
        let content = std::fs::read_to_string(out_path).unwrap();
        assert!(content.contains("hello"));
        cleanup(&dir);
    }
}
