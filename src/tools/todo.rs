use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::{Path, PathBuf};
use tracing::info;

use crate::claude::ToolDefinition;

use super::{authorize_chat_access, schema_object, Tool, ToolResult};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TodoItem {
    pub task: String,
    pub status: String, // "pending", "in_progress", "completed"
}

fn todo_path(groups_dir: &Path, chat_id: i64) -> PathBuf {
    groups_dir.join(chat_id.to_string()).join("TODO.json")
}

fn read_todos(groups_dir: &Path, chat_id: i64) -> Vec<TodoItem> {
    let path = todo_path(groups_dir, chat_id);
    match std::fs::read_to_string(&path) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

fn write_todos(groups_dir: &Path, chat_id: i64, todos: &[TodoItem]) -> std::io::Result<()> {
    let path = todo_path(groups_dir, chat_id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(todos).map_err(std::io::Error::other)?;
    std::fs::write(path, json)
}

fn format_todos(todos: &[TodoItem]) -> String {
    if todos.is_empty() {
        return "No tasks in the todo list.".into();
    }
    let mut out = String::new();
    for (i, item) in todos.iter().enumerate() {
        let icon = match item.status.as_str() {
            "completed" => "[x]",
            "in_progress" => "[~]",
            _ => "[ ]",
        };
        out.push_str(&format!("{}. {} {}\n", i + 1, icon, item.task));
    }
    out
}

// --- TodoReadTool ---

pub struct TodoReadTool {
    groups_dir: PathBuf,
}

impl TodoReadTool {
    pub fn new(data_dir: &str) -> Self {
        TodoReadTool {
            groups_dir: PathBuf::from(data_dir).join("groups"),
        }
    }
}

#[async_trait]
impl Tool for TodoReadTool {
    fn name(&self) -> &str {
        "todo_read"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "todo_read".into(),
            description: "Read the current todo/plan list for this chat. Returns all tasks with their status (pending, in_progress, completed).".into(),
            input_schema: schema_object(
                json!({
                    "chat_id": {
                        "type": "integer",
                        "description": "The chat ID"
                    }
                }),
                &["chat_id"],
            ),
        }
    }

    async fn execute(&self, input: serde_json::Value) -> ToolResult {
        let chat_id = match input.get("chat_id").and_then(|v| v.as_i64()) {
            Some(id) => id,
            None => return ToolResult::error("Missing 'chat_id' parameter".into()),
        };
        if let Err(e) = authorize_chat_access(&input, chat_id) {
            return ToolResult::error(e);
        }

        info!("Reading todo list for chat {}", chat_id);
        let todos = read_todos(&self.groups_dir, chat_id);
        ToolResult::success(format_todos(&todos))
    }
}

// --- TodoWriteTool ---

pub struct TodoWriteTool {
    groups_dir: PathBuf,
}

impl TodoWriteTool {
    pub fn new(data_dir: &str) -> Self {
        TodoWriteTool {
            groups_dir: PathBuf::from(data_dir).join("groups"),
        }
    }
}

#[async_trait]
impl Tool for TodoWriteTool {
    fn name(&self) -> &str {
        "todo_write"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "todo_write".into(),
            description: "Write/update the todo list for this chat. Replaces the entire list. Use this to create a plan, update task statuses, or reorganize tasks. Each task has a 'task' (description) and 'status' (pending, in_progress, or completed).".into(),
            input_schema: schema_object(
                json!({
                    "chat_id": {
                        "type": "integer",
                        "description": "The chat ID"
                    },
                    "todos": {
                        "type": "array",
                        "description": "The complete todo list",
                        "items": {
                            "type": "object",
                            "properties": {
                                "task": {
                                    "type": "string",
                                    "description": "Task description"
                                },
                                "status": {
                                    "type": "string",
                                    "enum": ["pending", "in_progress", "completed"],
                                    "description": "Task status"
                                }
                            },
                            "required": ["task", "status"]
                        }
                    }
                }),
                &["chat_id", "todos"],
            ),
        }
    }

    async fn execute(&self, input: serde_json::Value) -> ToolResult {
        let chat_id = match input.get("chat_id").and_then(|v| v.as_i64()) {
            Some(id) => id,
            None => return ToolResult::error("Missing 'chat_id' parameter".into()),
        };
        if let Err(e) = authorize_chat_access(&input, chat_id) {
            return ToolResult::error(e);
        }

        let todos_val = match input.get("todos") {
            Some(v) => v,
            None => return ToolResult::error("Missing 'todos' parameter".into()),
        };

        let todos: Vec<TodoItem> = match serde_json::from_value(todos_val.clone()) {
            Ok(t) => t,
            Err(e) => return ToolResult::error(format!("Invalid todos format: {e}")),
        };

        info!("Writing {} todo items for chat {}", todos.len(), chat_id);

        match write_todos(&self.groups_dir, chat_id, &todos) {
            Ok(()) => ToolResult::success(format!(
                "Todo list updated ({} tasks).\n\n{}",
                todos.len(),
                format_todos(&todos)
            )),
            Err(e) => ToolResult::error(format!("Failed to write todo list: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_dir() -> PathBuf {
        std::env::temp_dir().join(format!("microclaw_todo_test_{}", uuid::Uuid::new_v4()))
    }

    fn cleanup(dir: &std::path::Path) {
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn test_todo_item_serde() {
        let item = TodoItem {
            task: "Do something".into(),
            status: "pending".into(),
        };
        let json = serde_json::to_string(&item).unwrap();
        let parsed: TodoItem = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.task, "Do something");
        assert_eq!(parsed.status, "pending");
    }

    #[test]
    fn test_format_todos_empty() {
        assert_eq!(format_todos(&[]), "No tasks in the todo list.");
    }

    #[test]
    fn test_format_todos() {
        let todos = vec![
            TodoItem {
                task: "Plan".into(),
                status: "completed".into(),
            },
            TodoItem {
                task: "Build".into(),
                status: "in_progress".into(),
            },
            TodoItem {
                task: "Test".into(),
                status: "pending".into(),
            },
        ];
        let formatted = format_todos(&todos);
        assert!(formatted.contains("1. [x] Plan"));
        assert!(formatted.contains("2. [~] Build"));
        assert!(formatted.contains("3. [ ] Test"));
    }

    #[test]
    fn test_read_todos_empty() {
        let dir = test_dir();
        let groups_dir = dir.join("groups");
        let todos = read_todos(&groups_dir, 123);
        assert!(todos.is_empty());
        cleanup(&dir);
    }

    #[test]
    fn test_write_and_read_todos() {
        let dir = test_dir();
        let groups_dir = dir.join("groups");
        let todos = vec![
            TodoItem {
                task: "Step 1".into(),
                status: "pending".into(),
            },
            TodoItem {
                task: "Step 2".into(),
                status: "pending".into(),
            },
        ];
        write_todos(&groups_dir, 42, &todos).unwrap();
        let loaded = read_todos(&groups_dir, 42);
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].task, "Step 1");
        assert_eq!(loaded[1].task, "Step 2");
        cleanup(&dir);
    }

    #[test]
    fn test_todo_read_tool_name_and_definition() {
        let dir = test_dir();
        let tool = TodoReadTool::new(dir.to_str().unwrap());
        assert_eq!(tool.name(), "todo_read");
        let def = tool.definition();
        assert_eq!(def.name, "todo_read");
        assert!(def.input_schema["properties"]["chat_id"].is_object());
        cleanup(&dir);
    }

    #[test]
    fn test_todo_write_tool_name_and_definition() {
        let dir = test_dir();
        let tool = TodoWriteTool::new(dir.to_str().unwrap());
        assert_eq!(tool.name(), "todo_write");
        let def = tool.definition();
        assert_eq!(def.name, "todo_write");
        assert!(def.input_schema["properties"]["chat_id"].is_object());
        assert!(def.input_schema["properties"]["todos"].is_object());
        cleanup(&dir);
    }

    #[tokio::test]
    async fn test_todo_read_empty() {
        let dir = test_dir();
        let tool = TodoReadTool::new(dir.to_str().unwrap());
        let result = tool.execute(json!({"chat_id": 100})).await;
        assert!(!result.is_error);
        assert!(result.content.contains("No tasks"));
        cleanup(&dir);
    }

    #[tokio::test]
    async fn test_todo_read_missing_chat_id() {
        let dir = test_dir();
        let tool = TodoReadTool::new(dir.to_str().unwrap());
        let result = tool.execute(json!({})).await;
        assert!(result.is_error);
        assert!(result.content.contains("Missing"));
        cleanup(&dir);
    }

    #[tokio::test]
    async fn test_todo_write_and_read() {
        let dir = test_dir();
        let write_tool = TodoWriteTool::new(dir.to_str().unwrap());
        let read_tool = TodoReadTool::new(dir.to_str().unwrap());

        let result = write_tool
            .execute(json!({
                "chat_id": 42,
                "todos": [
                    {"task": "Research", "status": "completed"},
                    {"task": "Implement", "status": "in_progress"},
                    {"task": "Test", "status": "pending"}
                ]
            }))
            .await;
        assert!(!result.is_error);
        assert!(result.content.contains("3 tasks"));

        let result = read_tool.execute(json!({"chat_id": 42})).await;
        assert!(!result.is_error);
        assert!(result.content.contains("[x] Research"));
        assert!(result.content.contains("[~] Implement"));
        assert!(result.content.contains("[ ] Test"));
        cleanup(&dir);
    }

    #[tokio::test]
    async fn test_todo_write_missing_params() {
        let dir = test_dir();
        let tool = TodoWriteTool::new(dir.to_str().unwrap());

        let result = tool.execute(json!({})).await;
        assert!(result.is_error);

        let result = tool.execute(json!({"chat_id": 1})).await;
        assert!(result.is_error);
        cleanup(&dir);
    }

    #[tokio::test]
    async fn test_todo_write_invalid_format() {
        let dir = test_dir();
        let tool = TodoWriteTool::new(dir.to_str().unwrap());
        let result = tool
            .execute(json!({
                "chat_id": 1,
                "todos": "not an array"
            }))
            .await;
        assert!(result.is_error);
        assert!(result.content.contains("Invalid todos format"));
        cleanup(&dir);
    }

    #[tokio::test]
    async fn test_todo_write_overwrites() {
        let dir = test_dir();
        let write_tool = TodoWriteTool::new(dir.to_str().unwrap());
        let read_tool = TodoReadTool::new(dir.to_str().unwrap());

        write_tool
            .execute(json!({
                "chat_id": 1,
                "todos": [{"task": "Old task", "status": "pending"}]
            }))
            .await;

        write_tool
            .execute(json!({
                "chat_id": 1,
                "todos": [{"task": "New task", "status": "in_progress"}]
            }))
            .await;

        let result = read_tool.execute(json!({"chat_id": 1})).await;
        assert!(result.content.contains("New task"));
        assert!(!result.content.contains("Old task"));
        cleanup(&dir);
    }

    #[tokio::test]
    async fn test_todo_read_permission_denied() {
        let dir = test_dir();
        let tool = TodoReadTool::new(dir.to_str().unwrap());
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
    async fn test_todo_write_permission_denied() {
        let dir = test_dir();
        let tool = TodoWriteTool::new(dir.to_str().unwrap());
        let result = tool
            .execute(json!({
                "chat_id": 200,
                "todos": [{"task": "x", "status": "pending"}],
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
    async fn test_todo_write_and_read_allowed_for_control_chat_cross_chat() {
        let dir = test_dir();
        let write_tool = TodoWriteTool::new(dir.to_str().unwrap());
        let read_tool = TodoReadTool::new(dir.to_str().unwrap());
        let result = write_tool
            .execute(json!({
                "chat_id": 200,
                "todos": [{"task": "cross", "status": "pending"}],
                "__microclaw_auth": {
                    "caller_chat_id": 100,
                    "control_chat_ids": [100]
                }
            }))
            .await;
        assert!(!result.is_error, "{}", result.content);
        let result = read_tool
            .execute(json!({
                "chat_id": 200,
                "__microclaw_auth": {
                    "caller_chat_id": 100,
                    "control_chat_ids": [100]
                }
            }))
            .await;
        assert!(!result.is_error, "{}", result.content);
        assert!(result.content.contains("cross"));
        cleanup(&dir);
    }
}
