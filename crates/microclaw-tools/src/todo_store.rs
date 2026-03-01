use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TodoItem {
    pub task: String,
    pub status: String, // "pending", "in_progress", "completed"
}

pub fn todo_path(groups_dir: &Path, channel: &str, chat_id: i64) -> PathBuf {
    groups_dir
        .join(channel.trim())
        .join(chat_id.to_string())
        .join("TODO.json")
}

pub fn read_todos(groups_dir: &Path, channel: &str, chat_id: i64) -> Vec<TodoItem> {
    let path = todo_path(groups_dir, channel, chat_id);
    match std::fs::read_to_string(&path) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

pub fn write_todos(
    groups_dir: &Path,
    channel: &str,
    chat_id: i64,
    todos: &[TodoItem],
) -> std::io::Result<()> {
    let path = todo_path(groups_dir, channel, chat_id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(todos).map_err(std::io::Error::other)?;
    std::fs::write(path, json)
}

pub fn clear_todos(groups_dir: &Path, channel: &str, chat_id: i64) -> std::io::Result<bool> {
    let path = todo_path(groups_dir, channel, chat_id);
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
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

#[cfg(test)]
mod tests {
    use super::{clear_todos, read_todos, write_todos, TodoItem};
    use std::path::{Path, PathBuf};

    fn test_dir() -> PathBuf {
        std::env::temp_dir().join(format!(
            "microclaw_todo_store_test_{}",
            uuid::Uuid::new_v4()
        ))
    }

    fn cleanup(dir: &Path) {
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn test_clear_todos_removes_file() {
        let dir = test_dir();
        let groups_dir = dir.join("groups");
        write_todos(
            &groups_dir,
            "telegram",
            123,
            &[TodoItem {
                task: "task".into(),
                status: "pending".into(),
            }],
        )
        .unwrap();

        let cleared = clear_todos(&groups_dir, "telegram", 123).unwrap();
        assert!(cleared);
        assert!(read_todos(&groups_dir, "telegram", 123).is_empty());
        cleanup(&dir);
    }

    #[test]
    fn test_clear_todos_not_found_is_ok() {
        let dir = test_dir();
        let groups_dir = dir.join("groups");
        let cleared = clear_todos(&groups_dir, "telegram", 999).unwrap();
        assert!(!cleared);
        cleanup(&dir);
    }
}
