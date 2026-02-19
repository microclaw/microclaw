use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TodoItem {
    pub task: String,
    pub status: String, // "pending", "in_progress", "completed"
}

pub fn todo_path(groups_dir: &Path, chat_id: i64) -> PathBuf {
    groups_dir.join(chat_id.to_string()).join("TODO.json")
}

pub fn read_todos(groups_dir: &Path, chat_id: i64) -> Vec<TodoItem> {
    let path = todo_path(groups_dir, chat_id);
    match std::fs::read_to_string(&path) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

pub fn write_todos(groups_dir: &Path, chat_id: i64, todos: &[TodoItem]) -> std::io::Result<()> {
    let path = todo_path(groups_dir, chat_id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(todos).map_err(std::io::Error::other)?;
    std::fs::write(path, json)
}

pub fn format_todos(todos: &[TodoItem]) -> String {
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
