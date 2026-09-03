use async_trait::async_trait;
use serde_json::json;
use std::sync::Arc;
use tracing::info;

use crate::memory_backend::MemoryBackend;
use microclaw_core::llm_types::ToolDefinition;
use microclaw_storage::db::Database;
use microclaw_storage::db::Memory;

use super::{auth_context_from_input, authorize_chat_access, schema_object, Tool, ToolResult};

// ── Search ────────────────────────────────────────────────────────────────────

pub struct StructuredMemorySearchTool {
    memory_backend: Arc<MemoryBackend>,
}

impl StructuredMemorySearchTool {
    pub fn new(db: Arc<Database>, memory_backend: Arc<MemoryBackend>) -> Self {
        let _ = db;
        Self { memory_backend }
    }

    fn filter_visible_memories(chat_id: i64, memories: Vec<Memory>) -> Vec<Memory> {
        memories
            .into_iter()
            .filter(|m| m.chat_id.is_none() || m.chat_id == Some(chat_id))
            .collect()
    }
}

#[async_trait]
impl Tool for StructuredMemorySearchTool {
    fn name(&self) -> &str {
        "structured_memory_search"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "structured_memory_search".into(),
            description: "Search structured memories extracted from past conversations. Returns memories whose content contains the query string. Leave query empty to list recent visible memories.".into(),
            input_schema: schema_object(
                json!({
                    "query": {
                        "type": "string",
                        "description": "Keyword(s) to search for in memory content; leave empty to list recent visible memories"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of results to return (default 10, max 50)"
                    },
                    "include_archived": {
                        "type": "boolean",
                        "description": "Whether to include archived memories in results (default false)"
                    }
                }),
                &[],
            ),
        }
    }

    async fn execute(&self, input: serde_json::Value) -> ToolResult {
        let query = input
            .get("query")
            .and_then(|v| v.as_str())
            .map(|q| q.trim().to_string())
            .unwrap_or_default();
        let limit = input
            .get("limit")
            .and_then(|v| v.as_u64())
            .map(|n| n.min(50) as usize)
            .unwrap_or(10);
        let include_archived = input
            .get("include_archived")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let chat_id = auth_context_from_input(&input)
            .map(|a| a.caller_chat_id)
            .unwrap_or(0);

        info!(
            "structured_memory_search: query={query:?} chat_id={chat_id} limit={limit} include_archived={include_archived}"
        );

        let result = if query.is_empty() {
            let mut memories = match self
                .memory_backend
                .get_all_memories_for_chat(Some(chat_id))
                .await
            {
                Ok(m) => m,
                Err(e) => return ToolResult::error(format!("Search failed: {e}")),
            };
            let mut global = match self.memory_backend.get_all_memories_for_chat(None).await {
                Ok(m) => m,
                Err(e) => return ToolResult::error(format!("Search failed: {e}")),
            };
            memories.append(&mut global);
            memories.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
            if !include_archived {
                memories.retain(|m| !m.is_archived);
            }
            memories.truncate(limit);
            Ok(memories)
        } else {
            self.memory_backend
                .search_memories_with_options(chat_id, &query, limit, include_archived, true)
                .await
        };

        match result {
            Ok(memories) if memories.is_empty() => {
                let message = if query.is_empty() {
                    "No visible memories found.".to_string()
                } else {
                    "No memories found matching that query.".to_string()
                };
                ToolResult::success(message)
            }
            Ok(memories) => {
                let original_count = memories.len();
                let memories = Self::filter_visible_memories(chat_id, memories);
                if memories.is_empty() {
                    let message = if query.is_empty() {
                        "No visible memories found.".to_string()
                    } else {
                        "No visible memories found matching that query.".to_string()
                    };
                    return ToolResult::success(message);
                }
                let filtered_count = original_count.saturating_sub(memories.len());
                if filtered_count > 0 {
                    info!(
                        "structured_memory_search: filtered {} cross-chat memories for chat_id={}",
                        filtered_count, chat_id
                    );
                }
                let lines: Vec<String> = memories
                    .iter()
                    .map(|m| {
                        let scope = if m.chat_id.is_none() {
                            "global"
                        } else {
                            "chat"
                        };
                        format!("[id={}] [{}] [{}] {}", m.id, m.category, scope, m.content)
                    })
                    .collect();
                ToolResult::success(lines.join("\n"))
            }
            Err(e) => ToolResult::error(format!("Search failed: {e}")),
        }
    }
}

// ── Delete ────────────────────────────────────────────────────────────────────

pub struct StructuredMemoryDeleteTool {
    memory_backend: Arc<MemoryBackend>,
}

impl StructuredMemoryDeleteTool {
    pub fn new(db: Arc<Database>, memory_backend: Arc<MemoryBackend>) -> Self {
        let _ = db;
        Self { memory_backend }
    }
}

#[async_trait]
impl Tool for StructuredMemoryDeleteTool {
    fn name(&self) -> &str {
        "structured_memory_delete"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "structured_memory_delete".into(),
            description: "Archive a structured memory by its id (soft delete). Use structured_memory_search first to find the id. You can only archive memories that belong to the current chat or global memories if you are a control chat.".into(),
            input_schema: schema_object(
                json!({
                    "id": {
                        "type": "integer",
                        "description": "The id of the memory to delete"
                    }
                }),
                &["id"],
            ),
        }
    }

    async fn execute(&self, input: serde_json::Value) -> ToolResult {
        let id = match input.get("id").and_then(|v| v.as_i64()) {
            Some(id) => id,
            None => return ToolResult::error("Missing 'id' parameter".into()),
        };

        // Load memory first to check ownership
        let mem = match self.memory_backend.get_memory_by_id(id).await {
            Ok(Some(m)) => m,
            Ok(None) => return ToolResult::error(format!("Memory id={id} not found")),
            Err(e) => return ToolResult::error(format!("DB error: {e}")),
        };

        // Authorize: caller must own the chat or be a control chat; global memories only by control
        if let Some(auth) = auth_context_from_input(&input) {
            match mem.chat_id {
                Some(mem_chat_id) => {
                    if let Err(e) = authorize_chat_access(&input, mem_chat_id) {
                        return ToolResult::error(format!(
                            "{e} (memory id={id}, owner_chat_id={mem_chat_id})"
                        ));
                    }
                }
                None => {
                    // Global memory — requires control chat
                    if !auth.is_control_chat() {
                        return ToolResult::error(format!(
                            "Permission denied: only control chats can delete global memories (caller: {}, memory id={id}, owner_scope=global)",
                            auth.caller_chat_id
                        ));
                    }
                }
            }
        }

        info!("structured_memory_delete: id={id}");

        match self.memory_backend.archive_memory(id).await {
            Ok(true) => ToolResult::success(format!("Memory id={id} archived.")),
            Ok(false) => ToolResult::error(format!("Memory id={id} not found")),
            Err(e) => ToolResult::error(format!("Delete failed: {e}")),
        }
    }
}

// ── Update ────────────────────────────────────────────────────────────────────

pub struct StructuredMemoryUpdateTool {
    memory_backend: Arc<MemoryBackend>,
}

impl StructuredMemoryUpdateTool {
    pub fn new(db: Arc<Database>, memory_backend: Arc<MemoryBackend>) -> Self {
        let _ = db;
        Self { memory_backend }
    }
}

#[async_trait]
impl Tool for StructuredMemoryUpdateTool {
    fn name(&self) -> &str {
        "structured_memory_update"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "structured_memory_update".into(),
            description: "Update the content or category of an existing structured memory. Use this to correct outdated or wrong memories instead of creating a duplicate.".into(),
            input_schema: schema_object(
                json!({
                    "id": {
                        "type": "integer",
                        "description": "The id of the memory to update"
                    },
                    "content": {
                        "type": "string",
                        "description": "New content for the memory (max 300 characters)"
                    },
                    "category": {
                        "type": "string",
                        "description": "Category: PROFILE, KNOWLEDGE, or EVENT",
                        "enum": ["PROFILE", "KNOWLEDGE", "EVENT"]
                    }
                }),
                &["id", "content"],
            ),
        }
    }

    async fn execute(&self, input: serde_json::Value) -> ToolResult {
        let id = match input.get("id").and_then(|v| v.as_i64()) {
            Some(id) => id,
            None => return ToolResult::error("Missing 'id' parameter".into()),
        };
        let content = match input.get("content").and_then(|v| v.as_str()) {
            Some(c) if !c.trim().is_empty() => c.trim().to_string(),
            _ => return ToolResult::error("Missing or empty 'content' parameter".into()),
        };
        if content.len() > 300 {
            return ToolResult::error("Content exceeds 300 character limit".into());
        }

        // Load memory first to check ownership and get current category
        let mem = match self.memory_backend.get_memory_by_id(id).await {
            Ok(Some(m)) => m,
            Ok(None) => return ToolResult::error(format!("Memory id={id} not found")),
            Err(e) => return ToolResult::error(format!("DB error: {e}")),
        };

        // Authorize same as delete
        if let Some(auth) = auth_context_from_input(&input) {
            match mem.chat_id {
                Some(mem_chat_id) => {
                    if let Err(e) = authorize_chat_access(&input, mem_chat_id) {
                        return ToolResult::error(format!(
                            "{e} (memory id={id}, owner_chat_id={mem_chat_id})"
                        ));
                    }
                }
                None => {
                    if !auth.is_control_chat() {
                        return ToolResult::error(format!(
                            "Permission denied: only control chats can update global memories (caller: {}, memory id={id}, owner_scope=global)",
                            auth.caller_chat_id
                        ));
                    }
                }
            }
        }

        let category = input
            .get("category")
            .and_then(|v| v.as_str())
            .unwrap_or(&mem.category)
            .to_string();

        let valid_categories = ["PROFILE", "KNOWLEDGE", "EVENT"];
        if !valid_categories.contains(&category.as_str()) {
            return ToolResult::error(format!(
                "Invalid category '{category}'. Must be one of: PROFILE, KNOWLEDGE, EVENT"
            ));
        }

        info!("structured_memory_update: id={id}");

        match self
            .memory_backend
            .update_memory_content(id, &content, &category)
            .await
        {
            Ok(true) => ToolResult::success(format!("Memory id={id} updated.")),
            Ok(false) => ToolResult::error(format!("Memory id={id} not found")),
            Err(e) => ToolResult::error(format!("Update failed: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_db() -> Arc<Database> {
        let dir = std::env::temp_dir().join(format!("mc_smem_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        Arc::new(Database::new(dir.to_str().unwrap()).unwrap())
    }

    fn test_backend(db: Arc<Database>) -> Arc<MemoryBackend> {
        Arc::new(MemoryBackend::local_only(db))
    }

    #[tokio::test]
    async fn test_search_returns_results() {
        let db = test_db();
        db.insert_memory(Some(100), "User loves Rust programming", "PROFILE")
            .unwrap();
        db.insert_memory(Some(100), "User likes coffee", "PROFILE")
            .unwrap();
        let tool = StructuredMemorySearchTool::new(db.clone(), test_backend(db));
        let result = tool
            .execute(json!({
                "query": "rust",
                "__microclaw_auth": {"caller_chat_id": 100, "control_chat_ids": []}
            }))
            .await;
        assert!(!result.is_error);
        assert!(result.content.contains("Rust"));
        assert!(!result.content.contains("coffee"));
    }

    #[tokio::test]
    async fn test_search_empty_query_lists_no_visible_memories() {
        let db = test_db();
        let tool = StructuredMemorySearchTool::new(db.clone(), test_backend(db));
        let result = tool.execute(json!({"query": "  "})).await;
        assert!(!result.is_error);
        assert!(result.content.contains("No visible memories"));
    }

    #[tokio::test]
    async fn test_delete_own_chat_memory() {
        let db = test_db();
        let id = db.insert_memory(Some(100), "to delete", "EVENT").unwrap();
        let tool = StructuredMemoryDeleteTool::new(db.clone(), test_backend(db.clone()));
        let result = tool
            .execute(json!({
                "id": id,
                "__microclaw_auth": {"caller_chat_id": 100, "control_chat_ids": []}
            }))
            .await;
        assert!(!result.is_error, "{}", result.content);
        let mem = db.get_memory_by_id(id).unwrap().unwrap();
        assert!(mem.is_archived);
    }

    #[tokio::test]
    async fn test_delete_other_chat_denied() {
        let db = test_db();
        let id = db.insert_memory(Some(200), "other chat", "EVENT").unwrap();
        let tool = StructuredMemoryDeleteTool::new(db.clone(), test_backend(db));
        let result = tool
            .execute(json!({
                "id": id,
                "__microclaw_auth": {"caller_chat_id": 100, "control_chat_ids": []}
            }))
            .await;
        assert!(result.is_error);
        assert!(result.content.contains("Permission denied"));
    }

    #[tokio::test]
    async fn test_search_empty_query_lists_recent_visible_memories() {
        let db = test_db();
        db.insert_memory(Some(100), "chat memory", "PROFILE")
            .unwrap();
        db.insert_memory(None, "global memory", "KNOWLEDGE")
            .unwrap();
        let tool = StructuredMemorySearchTool::new(db.clone(), test_backend(db));
        let result = tool
            .execute(json!({
                "limit": 10,
                "__microclaw_auth": {"caller_chat_id": 100, "control_chat_ids": []}
            }))
            .await;
        assert!(!result.is_error, "{}", result.content);
        assert!(result.content.contains("chat memory"));
        assert!(result.content.contains("global memory"));
    }

    #[tokio::test]
    async fn test_update_memory() {
        let db = test_db();
        let id = db
            .insert_memory(Some(100), "User lives in Tokyo", "PROFILE")
            .unwrap();
        let tool = StructuredMemoryUpdateTool::new(db.clone(), test_backend(db.clone()));
        let result = tool
            .execute(json!({
                "id": id,
                "content": "User lives in Osaka",
                "__microclaw_auth": {"caller_chat_id": 100, "control_chat_ids": []}
            }))
            .await;
        assert!(!result.is_error, "{}", result.content);
        let mem = db.get_memory_by_id(id).unwrap().unwrap();
        assert_eq!(mem.content, "User lives in Osaka");
    }

    #[tokio::test]
    async fn test_update_content_too_long() {
        let db = test_db();
        let id = db.insert_memory(Some(100), "short", "EVENT").unwrap();
        let tool = StructuredMemoryUpdateTool::new(db.clone(), test_backend(db));
        let long = "x".repeat(301);
        let result = tool
            .execute(json!({
                "id": id,
                "content": long,
                "__microclaw_auth": {"caller_chat_id": 100, "control_chat_ids": []}
            }))
            .await;
        assert!(result.is_error);
        assert!(result.content.contains("300 character"));
    }
}
