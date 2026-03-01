use async_trait::async_trait;
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;

use crate::memory_backend::MemoryBackend;
use microclaw_core::llm_types::ToolDefinition;
use microclaw_storage::db::Database;
use microclaw_storage::memory_quality;

use super::{auth_context_from_input, authorize_chat_access, schema_object, Tool, ToolResult};

pub struct ReadMemoryTool {
    groups_dir: PathBuf,
    db: Arc<Database>,
}

impl ReadMemoryTool {
    pub fn new(data_dir: &str, db: Arc<Database>) -> Self {
        ReadMemoryTool {
            groups_dir: PathBuf::from(data_dir).join("groups"),
            db,
        }
    }
}

fn memory_channel_from_auth(input: &serde_json::Value) -> String {
    auth_context_from_input(input)
        .map(|a| a.caller_channel)
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "web".to_string())
}

fn chat_id_from_input_or_auth(input: &serde_json::Value) -> Option<i64> {
    input
        .get("chat_id")
        .and_then(|v| v.as_i64())
        .or_else(|| auth_context_from_input(input).map(|a| a.caller_chat_id))
}

fn memory_channel_for_chat(
    db: &Database,
    input: &serde_json::Value,
    chat_id: i64,
) -> Result<String, String> {
    if let Some(channel) = db
        .get_chat_channel(chat_id)
        .map_err(|e| format!("Failed to resolve chat channel for {chat_id}: {e}"))?
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        Ok(channel)
    } else {
        Ok(memory_channel_from_auth(input))
    }
}

#[async_trait]
impl Tool for ReadMemoryTool {
    fn name(&self) -> &str {
        "read_memory"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "read_memory".into(),
            description: "Read the AGENTS.md memory file. Use scope 'global' for memories shared across all chats, or 'chat' for chat-specific memories.".into(),
            input_schema: schema_object(
                json!({
                    "scope": {
                        "type": "string",
                        "description": "Memory scope: 'global' or 'chat'",
                        "enum": ["global", "chat"]
                    },
                    "chat_id": {
                        "type": "integer",
                        "description": "Chat ID (required for scope 'chat')"
                    }
                }),
                &["scope"],
            ),
        }
    }

    async fn execute(&self, input: serde_json::Value) -> ToolResult {
        let scope = match input.get("scope").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return ToolResult::error("Missing 'scope' parameter".into()),
        };

        let path = match scope {
            "global" => self.groups_dir.join("AGENTS.md"),
            "chat" => {
                let chat_id = match chat_id_from_input_or_auth(&input) {
                    Some(id) => id,
                    None => return ToolResult::error("Missing 'chat_id' for chat scope".into()),
                };
                if let Err(e) = authorize_chat_access(&input, chat_id) {
                    return ToolResult::error(e);
                }
                let channel = match memory_channel_for_chat(&self.db, &input, chat_id) {
                    Ok(v) => v,
                    Err(e) => return ToolResult::error(e),
                };
                self.groups_dir
                    .join(channel)
                    .join(chat_id.to_string())
                    .join("AGENTS.md")
            }
            _ => return ToolResult::error("scope must be 'global' or 'chat'".into()),
        };

        info!("Reading memory: {}", path.display());

        match std::fs::read_to_string(&path) {
            Ok(content) => {
                if content.trim().is_empty() {
                    ToolResult::success("Memory file is empty.".into())
                } else {
                    ToolResult::success(content)
                }
            }
            Err(_) => ToolResult::success("No memory file found (not yet created).".into()),
        }
    }
}

pub struct WriteMemoryTool {
    groups_dir: PathBuf,
    db: Arc<Database>,
    memory_backend: Arc<MemoryBackend>,
}

impl WriteMemoryTool {
    pub fn new(data_dir: &str, db: Arc<Database>, memory_backend: Arc<MemoryBackend>) -> Self {
        WriteMemoryTool {
            groups_dir: PathBuf::from(data_dir).join("groups"),
            db,
            memory_backend,
        }
    }
}

#[async_trait]
impl Tool for WriteMemoryTool {
    fn name(&self) -> &str {
        "write_memory"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "write_memory".into(),
            description: "Write to the AGENTS.md memory file. Use this to remember important information about the user or conversation. Use scope 'global' for memories shared across all chats, or 'chat' for chat-specific memories.".into(),
            input_schema: schema_object(
                json!({
                    "scope": {
                        "type": "string",
                        "description": "Memory scope: 'global' or 'chat'",
                        "enum": ["global", "chat"]
                    },
                    "chat_id": {
                        "type": "integer",
                        "description": "Chat ID (required for scope 'chat')"
                    },
                    "content": {
                        "type": "string",
                        "description": "The content to write to the memory file (replaces existing content)"
                    }
                }),
                &["scope", "content"],
            ),
        }
    }

    async fn execute(&self, input: serde_json::Value) -> ToolResult {
        let scope = match input.get("scope").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return ToolResult::error("Missing 'scope' parameter".into()),
        };
        let content = match input.get("content").and_then(|v| v.as_str()) {
            Some(c) => c,
            None => return ToolResult::error("Missing 'content' parameter".into()),
        };

        let (path, memory_chat_id) = match scope {
            "global" => {
                if let Some(auth) = auth_context_from_input(&input) {
                    if !auth.is_control_chat() {
                        return ToolResult::error(format!(
                            "Permission denied: chat {} cannot write global memory",
                            auth.caller_chat_id
                        ));
                    }
                }
                (self.groups_dir.join("AGENTS.md"), None)
            }
            "chat" => {
                let chat_id = match chat_id_from_input_or_auth(&input) {
                    Some(id) => id,
                    None => return ToolResult::error("Missing 'chat_id' for chat scope".into()),
                };
                if let Err(e) = authorize_chat_access(&input, chat_id) {
                    return ToolResult::error(e);
                }
                let channel = match memory_channel_for_chat(&self.db, &input, chat_id) {
                    Ok(v) => v,
                    Err(e) => return ToolResult::error(e),
                };
                (
                    self.groups_dir
                        .join(channel)
                        .join(chat_id.to_string())
                        .join("AGENTS.md"),
                    Some(chat_id),
                )
            }
            _ => return ToolResult::error("scope must be 'global' or 'chat'".into()),
        };

        info!("Writing memory: {}", path.display());

        if let Some(parent) = path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                return ToolResult::error(format!("Failed to create directory: {e}"));
            }
        }

        match std::fs::write(&path, content) {
            Ok(()) => {
                let memory_content = content.trim().to_string();
                if !memory_content.is_empty() {
                    if let Some(normalized) =
                        memory_quality::normalize_memory_content(&memory_content, 180)
                    {
                        if memory_quality::memory_quality_ok(&normalized) {
                            let chat_id = memory_chat_id;
                            let _ = self
                                .memory_backend
                                .insert_memory_with_metadata(
                                    chat_id,
                                    &normalized,
                                    "KNOWLEDGE",
                                    "write_memory_tool",
                                    0.85,
                                )
                                .await;
                        }
                    }
                }

                ToolResult::success(format!("Memory saved to {} scope.", scope))
            }
            Err(e) => ToolResult::error(format!("Failed to write memory: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Arc;

    use microclaw_storage::db::Database;

    fn test_dir() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("microclaw_memtool_{}", uuid::Uuid::new_v4()))
    }

    fn test_db(dir: &std::path::Path) -> Arc<Database> {
        let runtime = dir.join("runtime");
        std::fs::create_dir_all(&runtime).unwrap();
        Arc::new(Database::new(runtime.to_str().unwrap()).unwrap())
    }

    fn test_backend(db: Arc<Database>) -> Arc<MemoryBackend> {
        Arc::new(MemoryBackend::local_only(db))
    }

    #[tokio::test]
    async fn test_read_memory_global_not_exists() {
        let dir = test_dir();
        let db = test_db(&dir);
        let tool = ReadMemoryTool::new(dir.to_str().unwrap(), db);
        let result = tool.execute(json!({"scope": "global"})).await;
        assert!(!result.is_error);
        assert!(result.content.contains("No memory file found"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_write_and_read_memory_global() {
        let dir = test_dir();
        let db = test_db(&dir);
        let write_tool =
            WriteMemoryTool::new(dir.to_str().unwrap(), db.clone(), test_backend(db.clone()));
        let read_tool = ReadMemoryTool::new(dir.to_str().unwrap(), db.clone());

        let result = write_tool
            .execute(json!({"scope": "global", "content": "user prefers Rust"}))
            .await;
        assert!(!result.is_error);
        assert!(result.content.contains("Memory saved"));

        let result = read_tool.execute(json!({"scope": "global"})).await;
        assert!(!result.is_error);
        assert_eq!(result.content, "user prefers Rust");
        let mems = db.get_all_memories_for_chat(None).unwrap();
        assert_eq!(mems.len(), 1);
        assert_eq!(mems[0].content, "user prefers Rust");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_write_and_read_memory_chat() {
        let dir = test_dir();
        let db = test_db(&dir);
        db.resolve_or_create_chat_id("web", "42", Some("web-42"), "web")
            .unwrap();
        let write_tool =
            WriteMemoryTool::new(dir.to_str().unwrap(), db.clone(), test_backend(db.clone()));
        let read_tool = ReadMemoryTool::new(dir.to_str().unwrap(), db.clone());

        let result = write_tool
            .execute(json!({"scope": "chat", "chat_id": 42, "content": "chat 42 notes"}))
            .await;
        assert!(!result.is_error);

        let result = read_tool
            .execute(json!({"scope": "chat", "chat_id": 42}))
            .await;
        assert!(!result.is_error);
        assert_eq!(result.content, "chat 42 notes");
        let mems = db.get_all_memories_for_chat(Some(42)).unwrap();
        assert_eq!(mems.len(), 1);
        assert_eq!(mems[0].content, "chat 42 notes");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_read_memory_chat_missing_chat_id() {
        let dir = test_dir();
        let db = test_db(&dir);
        let tool = ReadMemoryTool::new(dir.to_str().unwrap(), db);
        let result = tool.execute(json!({"scope": "chat"})).await;
        assert!(result.is_error);
        assert!(result.content.contains("Missing 'chat_id'"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_write_memory_chat_uses_auth_chat_id_when_missing() {
        let dir = test_dir();
        let db = test_db(&dir);
        db.resolve_or_create_chat_id("web", "42", Some("web-42"), "web")
            .unwrap();
        let tool =
            WriteMemoryTool::new(dir.to_str().unwrap(), db.clone(), test_backend(db.clone()));
        let result = tool
            .execute(json!({
                "scope": "chat",
                "content": "from auth chat id",
                "__microclaw_auth": {
                    "caller_channel": "web",
                    "caller_chat_id": 42,
                    "control_chat_ids": []
                }
            }))
            .await;
        assert!(!result.is_error, "{}", result.content);
        let content =
            std::fs::read_to_string(dir.join("groups").join("web").join("42").join("AGENTS.md"))
                .unwrap();
        assert_eq!(content, "from auth chat id");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_write_memory_missing_scope() {
        let dir = test_dir();
        let db = test_db(&dir);
        let tool = WriteMemoryTool::new(dir.to_str().unwrap(), db.clone(), test_backend(db));
        let result = tool.execute(json!({"content": "data"})).await;
        assert!(result.is_error);
        assert!(result.content.contains("Missing 'scope'"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_read_memory_invalid_scope() {
        let dir = test_dir();
        let db = test_db(&dir);
        let tool = ReadMemoryTool::new(dir.to_str().unwrap(), db);
        let result = tool.execute(json!({"scope": "invalid"})).await;
        assert!(result.is_error);
        assert!(result.content.contains("must be 'global' or 'chat'"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_read_memory_empty_file() {
        let dir = test_dir();
        let db = test_db(&dir);
        let write_tool = WriteMemoryTool::new(dir.to_str().unwrap(), db.clone(), test_backend(db));
        let db2 = test_db(&dir);
        let read_tool = ReadMemoryTool::new(dir.to_str().unwrap(), db2);

        write_tool
            .execute(json!({"scope": "global", "content": "   "}))
            .await;

        let result = read_tool.execute(json!({"scope": "global"})).await;
        assert!(!result.is_error);
        assert!(result.content.contains("empty"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_write_memory_global_denied_for_non_control_chat() {
        let dir = test_dir();
        let db = test_db(&dir);
        let tool = WriteMemoryTool::new(dir.to_str().unwrap(), db.clone(), test_backend(db));
        let result = tool
            .execute(json!({
                "scope": "global",
                "content": "secret",
                "__microclaw_auth": {
                    "caller_chat_id": 100,
                    "control_chat_ids": []
                }
            }))
            .await;
        assert!(result.is_error);
        assert!(result.content.contains("Permission denied"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_write_memory_global_allowed_for_control_chat() {
        let dir = test_dir();
        let db = test_db(&dir);
        let tool = WriteMemoryTool::new(dir.to_str().unwrap(), db.clone(), test_backend(db));
        let result = tool
            .execute(json!({
                "scope": "global",
                "content": "global ok",
                "__microclaw_auth": {
                    "caller_chat_id": 100,
                    "control_chat_ids": [100]
                }
            }))
            .await;
        assert!(!result.is_error, "{}", result.content);
        let content = std::fs::read_to_string(dir.join("groups").join("AGENTS.md")).unwrap();
        assert_eq!(content, "global ok");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_read_memory_chat_permission_denied() {
        let dir = test_dir();
        let db = test_db(&dir);
        let tool = ReadMemoryTool::new(dir.to_str().unwrap(), db);
        let result = tool
            .execute(json!({
                "scope": "chat",
                "chat_id": 200,
                "__microclaw_auth": {
                    "caller_chat_id": 100,
                    "control_chat_ids": []
                }
            }))
            .await;
        assert!(result.is_error);
        assert!(result.content.contains("Permission denied"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_read_memory_chat_allowed_for_control_chat_cross_chat() {
        let dir = test_dir();
        let db = test_db(&dir);
        db.resolve_or_create_chat_id("web", "200", Some("web-200"), "web")
            .unwrap();
        let write_tool = WriteMemoryTool::new(dir.to_str().unwrap(), db.clone(), test_backend(db));
        let db2 = test_db(&dir);
        let read_tool = ReadMemoryTool::new(dir.to_str().unwrap(), db2);
        write_tool
            .execute(json!({"scope": "chat", "chat_id": 200, "content": "chat200"}))
            .await;
        let result = read_tool
            .execute(json!({
                "scope": "chat",
                "chat_id": 200,
                "__microclaw_auth": {
                    "caller_chat_id": 100,
                    "control_chat_ids": [100]
                }
            }))
            .await;
        assert!(!result.is_error, "{}", result.content);
        assert_eq!(result.content, "chat200");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
