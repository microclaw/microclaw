use async_trait::async_trait;
use chrono::Utc;
use serde_json::json;
use std::io::Write;
use std::path::PathBuf;
use tracing::info;

use crate::claude::ToolDefinition;

use super::{auth_context_from_input, authorize_chat_persona_access, schema_object, Tool, ToolResult};

pub struct ReadMemoryTool {
    groups_dir: PathBuf,
    /// Principles file: workspace_dir/AGENTS.md (read-only for "global" scope).
    workspace_agents_path: PathBuf,
}

impl ReadMemoryTool {
    pub fn new(data_dir: &str, working_dir: &str) -> Self {
        let groups_dir = PathBuf::from(data_dir).join("groups");
        ReadMemoryTool {
            workspace_agents_path: PathBuf::from(working_dir).join("AGENTS.md"),
            groups_dir,
        }
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
            description: "Read memory. Use scope 'global' to read principles (AGENTS.md at workspace root, read-only), or 'chat' to read this persona's full MEMORY.md. For tiered read/write use read_tiered_memory and write_tiered_memory.".into(),
            input_schema: schema_object(
                json!({
                    "scope": {
                        "type": "string",
                        "description": "Memory scope: 'global' (principles) or 'chat' (persona MEMORY.md)",
                        "enum": ["global", "chat"]
                    },
                    "chat_id": {
                        "type": "integer",
                        "description": "Chat ID (required for scope 'chat'; can default from context)"
                    },
                    "persona_id": {
                        "type": "integer",
                        "description": "Persona ID (required for scope 'chat'; can default from context)"
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
            "global" => self.workspace_agents_path.clone(),
            "chat" => {
                let auth = match auth_context_from_input(&input) {
                    Some(a) => a,
                    None => return ToolResult::error("Missing auth context".into()),
                };
                let chat_id = input
                    .get("chat_id")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(auth.caller_chat_id);
                let persona_id = input
                    .get("persona_id")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(auth.caller_persona_id);
                if let Err(e) = authorize_chat_persona_access(&input, chat_id, persona_id) {
                    return ToolResult::error(e);
                }
                self.groups_dir
                    .join(chat_id.to_string())
                    .join(persona_id.to_string())
                    .join("MEMORY.md")
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
}

impl WriteMemoryTool {
    pub fn new(data_dir: &str, _working_dir: &str) -> Self {
        WriteMemoryTool {
            groups_dir: PathBuf::from(data_dir).join("groups"),
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
            description: "Write memory. Use scope 'chat' to replace this persona's full MEMORY.md, or 'chat_daily' to append to the daily log (today/yesterday are injected at session start). Principles (AGENTS.md at workspace root) are read-only. For tiered updates use write_tiered_memory.".into(),
            input_schema: schema_object(
                json!({
                    "scope": {
                        "type": "string",
                        "description": "Memory scope: 'chat' (replaces persona MEMORY.md) or 'chat_daily' (appends)",
                        "enum": ["chat", "chat_daily"]
                    },
                    "chat_id": {
                        "type": "integer",
                        "description": "Chat ID (required for scope 'chat' or 'chat_daily')"
                    },
                    "persona_id": {
                        "type": "integer",
                        "description": "Persona ID (required for scope 'chat'; for 'chat_daily' defaults from context)"
                    },
                    "date": {
                        "type": "string",
                        "description": "Date for scope 'chat_daily' only (YYYY-MM-DD, default: today UTC)"
                    },
                    "content": {
                        "type": "string",
                        "description": "The content to write (replaces for chat; appends for chat_daily)"
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

        if scope == "chat_daily" {
            let auth = match auth_context_from_input(&input) {
                Some(a) => a,
                None => return ToolResult::error("Missing auth context for chat_daily scope".into()),
            };
            let chat_id = input
                .get("chat_id")
                .and_then(|v| v.as_i64())
                .unwrap_or(auth.caller_chat_id);
            let persona_id = input
                .get("persona_id")
                .and_then(|v| v.as_i64())
                .unwrap_or(auth.caller_persona_id);
            if let Err(e) = authorize_chat_persona_access(&input, chat_id, persona_id) {
                return ToolResult::error(e);
            }
            let date = input
                .get("date")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| Utc::now().format("%Y-%m-%d").to_string());
            let path = self
                .groups_dir
                .join(chat_id.to_string())
                .join(persona_id.to_string())
                .join("memory")
                .join(format!("{date}.md"));
            info!("Appending to daily log: {}", path.display());
            if let Some(parent) = path.parent() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    return ToolResult::error(format!("Failed to create directory: {e}"));
                }
            }
            return match std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
            {
                Ok(mut f) => {
                    if !content.ends_with('\n') {
                        let _ = f.write_all(b"\n");
                    }
                    match f.write_all(content.as_bytes()) {
                        Ok(()) => ToolResult::success(format!(
                            "Appended to daily log for {date} (chat_daily scope)."
                        )),
                        Err(e) => ToolResult::error(format!("Failed to append to daily log: {e}")),
                    }
                }
                Err(e) => ToolResult::error(format!("Failed to open daily log: {e}")),
            };
        }

        if scope == "global" {
            return ToolResult::error(
                "Writing to global scope is not allowed. Principles are in AGENTS.md at workspace root (read-only). Use write_tiered_memory for per-persona memory.".into(),
            );
        }

        let path = match scope {
            "chat" => {
                let auth = match auth_context_from_input(&input) {
                    Some(a) => a,
                    None => return ToolResult::error("Missing auth context".into()),
                };
                let chat_id = input
                    .get("chat_id")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(auth.caller_chat_id);
                let persona_id = input
                    .get("persona_id")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(auth.caller_persona_id);
                if let Err(e) = authorize_chat_persona_access(&input, chat_id, persona_id) {
                    return ToolResult::error(e);
                }
                self.groups_dir
                    .join(chat_id.to_string())
                    .join(persona_id.to_string())
                    .join("MEMORY.md")
            }
            _ => return ToolResult::error("scope must be 'chat' or 'chat_daily'".into()),
        };

        info!("Writing memory: {}", path.display());

        if let Some(parent) = path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                return ToolResult::error(format!("Failed to create directory: {e}"));
            }
        }

        match std::fs::write(&path, content) {
            Ok(()) => ToolResult::success(format!("Memory saved to {} scope.", scope)),
            Err(e) => ToolResult::error(format!("Failed to write memory: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_dir() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("microclaw_memtool_{}", uuid::Uuid::new_v4()))
    }

    fn test_tools(dir: &std::path::Path) -> (ReadMemoryTool, WriteMemoryTool) {
        let s = dir.to_str().unwrap();
        (
            ReadMemoryTool::new(s, s),
            WriteMemoryTool::new(s, s),
        )
    }

    #[tokio::test]
    async fn test_read_memory_global_not_exists() {
        let dir = test_dir();
        let (tool, _) = test_tools(&dir);
        let result = tool.execute(json!({"scope": "global"})).await;
        assert!(!result.is_error);
        assert!(result.content.contains("No memory file found"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_read_memory_global_from_workspace_agents_md() {
        let dir = test_dir();
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(dir.join("AGENTS.md"), "user prefers Rust").unwrap();
        let (tool, _) = test_tools(&dir);
        let result = tool.execute(json!({"scope": "global"})).await;
        assert!(!result.is_error);
        assert_eq!(result.content, "user prefers Rust");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_write_memory_global_not_allowed() {
        let dir = test_dir();
        let (_, tool) = test_tools(&dir);
        let result = tool
            .execute(json!({
                "scope": "global",
                "content": "user prefers Rust",
                "__microclaw_auth": {
                    "caller_chat_id": 100,
                    "caller_persona_id": 1,
                    "control_chat_ids": [100]
                }
            }))
            .await;
        assert!(result.is_error);
        assert!(result.content.contains("not allowed"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_write_and_read_memory_chat() {
        let dir = test_dir();
        let (read_tool, write_tool) = test_tools(&dir);
        let auth = json!({
            "__microclaw_auth": {
                "caller_chat_id": 42,
                "caller_persona_id": 1,
                "control_chat_ids": []
            }
        });

        let mut write_input = json!({"scope": "chat", "chat_id": 42, "persona_id": 1, "content": "chat 42 persona 1 notes"});
        if let (Some(obj), Some(auth_obj)) = (write_input.as_object_mut(), auth.get("__microclaw_auth")) {
            obj.insert("__microclaw_auth".to_string(), auth_obj.clone());
        }
        let result = write_tool.execute(write_input).await;
        assert!(!result.is_error);

        let mut read_input = json!({"scope": "chat", "chat_id": 42, "persona_id": 1});
        if let (Some(obj), Some(auth_obj)) = (read_input.as_object_mut(), auth.get("__microclaw_auth")) {
            obj.insert("__microclaw_auth".to_string(), auth_obj.clone());
        }
        let result = read_tool.execute(read_input).await;
        assert!(!result.is_error);
        assert_eq!(result.content, "chat 42 persona 1 notes");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_read_memory_chat_missing_auth() {
        let dir = test_dir();
        let (tool, _) = test_tools(&dir);
        let result = tool.execute(json!({"scope": "chat", "chat_id": 42})).await;
        assert!(result.is_error);
        assert!(result.content.contains("auth"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_write_memory_missing_scope() {
        let dir = test_dir();
        let (_, tool) = test_tools(&dir);
        let result = tool.execute(json!({"content": "data"})).await;
        assert!(result.is_error);
        assert!(result.content.contains("Missing 'scope'"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_read_memory_invalid_scope() {
        let dir = test_dir();
        let (tool, _) = test_tools(&dir);
        let result = tool.execute(json!({"scope": "invalid"})).await;
        assert!(result.is_error);
        assert!(result.content.contains("must be 'global' or 'chat'"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_read_memory_empty_file() {
        let dir = test_dir();
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(dir.join("AGENTS.md"), "   ").unwrap();
        let (read_tool, _) = test_tools(&dir);
        let result = read_tool.execute(json!({"scope": "global"})).await;
        assert!(!result.is_error);
        assert!(result.content.contains("empty"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_read_memory_chat_permission_denied() {
        let dir = test_dir();
        let (tool, _) = test_tools(&dir);
        let result = tool
            .execute(json!({
                "scope": "chat",
                "chat_id": 200,
                "persona_id": 2,
                "__microclaw_auth": {
                    "caller_chat_id": 100,
                    "caller_persona_id": 1,
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
        let (read_tool, write_tool) = test_tools(&dir);
        write_tool
            .execute(json!({
                "scope": "chat",
                "chat_id": 200,
                "persona_id": 2,
                "content": "chat200",
                "__microclaw_auth": {
                    "caller_chat_id": 100,
                    "caller_persona_id": 1,
                    "control_chat_ids": [100]
                }
            }))
            .await;
        let result = read_tool
            .execute(json!({
                "scope": "chat",
                "chat_id": 200,
                "persona_id": 2,
                "__microclaw_auth": {
                    "caller_chat_id": 100,
                    "caller_persona_id": 1,
                    "control_chat_ids": [100]
                }
            }))
            .await;
        assert!(!result.is_error, "{}", result.content);
        assert_eq!(result.content, "chat200");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
