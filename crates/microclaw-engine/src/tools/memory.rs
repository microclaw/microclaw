use async_trait::async_trait;
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;

use crate::internal::storage::db::Database;
use crate::internal::storage::memory_quality;
use crate::memory_backend::MemoryBackend;
use microclaw_core::llm_types::ToolDefinition;

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

fn latest_sender_for_chat(db: &Database, chat_id: i64) -> Option<String> {
    db.get_recent_messages(chat_id, 20)
        .ok()?
        .into_iter()
        .rev()
        .find(|m| !m.is_from_bot && !m.content.trim_start().starts_with('/'))
        .map(|m| m.sender_name.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn find_person_section_range(lines: &[&str], header: &str) -> Option<(usize, usize)> {
    let start = lines.iter().position(|line| line.trim() == header)?;
    let end = lines
        .iter()
        .enumerate()
        .skip(start + 1)
        .find(|(_, line)| line.trim_start().starts_with("## Person:"))
        .map(|(idx, _)| idx)
        .unwrap_or(lines.len());
    Some((start, end))
}

fn upsert_chat_person_memory(existing: &str, sender: &str, content: &str) -> String {
    let sender = sender.trim();
    let content = content.trim();
    if sender.is_empty() || content.is_empty() {
        return content.to_string();
    }

    let section_header = format!("## Person: {sender}");
    let section_block = format!("{section_header}\n{content}\n");
    let existing_trimmed = existing.trim();
    if existing_trimmed.is_empty() {
        return section_block;
    }

    let lines: Vec<&str> = existing_trimmed.lines().collect();
    if let Some((start, end)) = find_person_section_range(&lines, &section_header) {
        let mut out = String::new();
        for line in &lines[..start] {
            out.push_str(line);
            out.push('\n');
        }
        out.push_str(&section_block);
        for line in &lines[end..] {
            out.push_str(line);
            out.push('\n');
        }
        return out;
    }

    let mut out = String::new();
    out.push_str(existing_trimmed);
    if !existing_trimmed.ends_with('\n') {
        out.push('\n');
    }
    out.push('\n');
    out.push_str(&section_block);
    out
}

#[async_trait]
impl Tool for ReadMemoryTool {
    fn name(&self) -> &str {
        "read_memory"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "read_memory".into(),
            description: "Read internal AGENTS.md memory context for reasoning. Use scope 'global' for memories shared across all chats, 'bot' for the current bot/account, or 'chat' for chat-specific memories. Do not echo raw memory blocks/IDs directly to users; summarize in natural language.".into(),
            input_schema: schema_object(
                json!({
                    "scope": {
                        "type": "string",
                        "description": "Memory scope: 'global', 'bot', or 'chat'",
                        "enum": ["global", "bot", "chat"]
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
            "bot" => {
                let channel = memory_channel_from_auth(&input);
                self.groups_dir.join(channel).join("AGENTS.md")
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
                self.groups_dir
                    .join(channel)
                    .join(chat_id.to_string())
                    .join("AGENTS.md")
            }
            _ => return ToolResult::error("scope must be 'global', 'bot', or 'chat'".into()),
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

impl WriteMemoryTool {
    /// Mirror a write into the structured memory store. The row holds the
    /// normalized (180-char) digest of the content, and global/bot writes
    /// resend the whole file, so the digest repeats across saves; an existing
    /// live row with the same digest is refreshed instead of appending a
    /// duplicate (#505). Returns the row id and whether it was refreshed.
    async fn upsert_memory_row(
        &self,
        chat_id: Option<i64>,
        normalized: &str,
    ) -> Option<(i64, bool)> {
        let existing = self
            .memory_backend
            .get_all_memories_for_chat(chat_id)
            .await
            .unwrap_or_default();
        if let Some(dup) = existing
            .iter()
            .find(|m| !m.is_archived && m.content.eq_ignore_ascii_case(normalized))
        {
            let updated = self
                .memory_backend
                .update_memory_with_metadata(
                    dup.id,
                    normalized,
                    &dup.category,
                    dup.confidence.max(WRITE_MEMORY_CONFIDENCE),
                    &dup.source,
                )
                .await;
            return matches!(updated, Ok(true)).then_some((dup.id, true));
        }
        self.memory_backend
            .insert_memory_with_metadata(
                chat_id,
                normalized,
                "KNOWLEDGE",
                "write_memory_tool",
                WRITE_MEMORY_CONFIDENCE,
            )
            .await
            .ok()
            .map(|id| (id, false))
    }
}

const WRITE_MEMORY_CONFIDENCE: f64 = 0.85;

#[async_trait]
impl Tool for WriteMemoryTool {
    fn name(&self) -> &str {
        "write_memory"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "write_memory".into(),
            description: "Write to the AGENTS.md memory file. Use this to remember important information about the user or conversation. Use scope 'global' for memories shared across all chats, 'bot' for the current bot/account, or 'chat' for chat-specific memories. In chat scope, memory is stored per person when sender identity is available. Pass `ttl_days` for facts that should expire (e.g. \"working from Tokyo this week\", \"travel until 2026-05-20\") so the memory is auto-pruned later.".into(),
            input_schema: schema_object(
                json!({
                    "scope": {
                        "type": "string",
                        "description": "Memory scope: 'global', 'bot', or 'chat'",
                        "enum": ["global", "bot", "chat"]
                    },
                    "chat_id": {
                        "type": "integer",
                        "description": "Chat ID (required for scope 'chat')"
                    },
                    "content": {
                        "type": "string",
                        "description": "The content to write to the memory file (global/bot replace full file; chat updates the latest sender section when sender identity is available)"
                    },
                    "ttl_days": {
                        "type": "number",
                        "description": "Optional. If set, the structured memory row is auto-pruned after this many days. Use for time-bounded facts; omit for durable knowledge."
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
            "bot" => {
                let channel = memory_channel_from_auth(&input);
                (self.groups_dir.join(channel).join("AGENTS.md"), None)
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
            _ => return ToolResult::error("scope must be 'global', 'bot', or 'chat'".into()),
        };

        info!("Writing memory: {}", path.display());

        if let Some(parent) = path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                return ToolResult::error(format!("Failed to create directory: {e}"));
            }
        }

        let write_content = if scope == "chat" {
            let chat_id = memory_chat_id.unwrap_or_default();
            let sender = latest_sender_for_chat(&self.db, chat_id);
            let existing = std::fs::read_to_string(&path).unwrap_or_default();
            if let Some(sender) = sender {
                upsert_chat_person_memory(&existing, &sender, content)
            } else {
                content.to_string()
            }
        } else {
            content.to_string()
        };

        match std::fs::write(&path, &write_content) {
            Ok(()) => {
                let memory_content = content.trim().to_string();
                let ttl_days = input
                    .get("ttl_days")
                    .and_then(|v| v.as_f64())
                    .filter(|v| v.is_finite() && *v > 0.0);
                if !memory_content.is_empty() {
                    if let Some(normalized) =
                        memory_quality::normalize_memory_content(&memory_content, 180)
                    {
                        if memory_quality::memory_quality_ok(&normalized) {
                            if let Some((memory_id, refreshed)) =
                                self.upsert_memory_row(memory_chat_id, &normalized).await
                            {
                                let expires_at = ttl_days.map(|days| {
                                    let secs = (days * 86_400.0) as i64;
                                    (chrono::Utc::now() + chrono::Duration::seconds(secs))
                                        .to_rfc3339()
                                });
                                // A re-save without ttl_days re-asserts the fact as
                                // durable, so a refreshed row drops its old expiry.
                                if expires_at.is_some() || refreshed {
                                    let _ = self
                                        .db
                                        .set_memory_expires_at(memory_id, expires_at.as_deref());
                                }
                            }
                        }
                    }
                }

                let suffix = match ttl_days {
                    Some(d) => format!(" (expires in {d} day(s))"),
                    None => String::new(),
                };
                ToolResult::success(format!("Memory saved to {} scope.{}", scope, suffix))
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

    use crate::internal::storage::db::{Database, StoredMessage};

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

    fn store_user_message(db: &Database, chat_id: i64, sender_name: &str, content: &str) {
        let msg = StoredMessage {
            id: format!("{}-{}", sender_name, uuid::Uuid::new_v4()),
            chat_id,
            sender_name: sender_name.to_string(),
            content: content.to_string(),
            is_from_bot: false,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        db.store_message(&msg).unwrap();
    }

    fn live_rows(db: &Database, chat_id: Option<i64>) -> Vec<crate::internal::storage::db::Memory> {
        db.get_all_memories_for_chat(chat_id)
            .unwrap()
            .into_iter()
            .filter(|m| !m.is_archived)
            .collect()
    }

    #[tokio::test]
    async fn test_write_memory_repeat_global_doc_keeps_one_row() {
        let dir = test_dir();
        let db = test_db(&dir);
        let tool =
            WriteMemoryTool::new(dir.to_str().unwrap(), db.clone(), test_backend(db.clone()));
        // Whole-document rewrites that only change past the 180-char digest.
        let header = "# Household memory\n\nThe family prefers vegetarian dinners on weekdays, \
                      chores rotate weekly between the two kids, and the shared calendar is the \
                      source of truth for appointments and school events.";
        for tail in [
            "",
            "\n- bins go out on Tuesday",
            "\n- bins go out on Wednesday",
        ] {
            let result = tool
                .execute(json!({"scope": "global", "content": format!("{header}{tail}")}))
                .await;
            assert!(!result.is_error, "{}", result.content);
        }
        assert_eq!(live_rows(&db, None).len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_write_memory_distinct_facts_and_chats_stay_separate() {
        let dir = test_dir();
        let db = test_db(&dir);
        let tool =
            WriteMemoryTool::new(dir.to_str().unwrap(), db.clone(), test_backend(db.clone()));
        for (chat_id, content) in [
            (300, "User prefers concise answers in English"),
            (300, "User is learning Rust and async programming"),
            (300, "User prefers concise answers in English"),
            (301, "User prefers concise answers in English"),
        ] {
            tool.execute(json!({"scope": "chat", "chat_id": chat_id, "content": content}))
                .await;
        }
        assert_eq!(live_rows(&db, Some(300)).len(), 2);
        assert_eq!(live_rows(&db, Some(301)).len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_write_memory_does_not_revive_archived_row() {
        let dir = test_dir();
        let db = test_db(&dir);
        let tool =
            WriteMemoryTool::new(dir.to_str().unwrap(), db.clone(), test_backend(db.clone()));
        let input = json!({"scope": "chat", "chat_id": 302, "content": "User works night shifts on weekends"});
        tool.execute(input.clone()).await;
        let first = live_rows(&db, Some(302))[0].id;
        db.archive_memory(first).unwrap();
        tool.execute(input).await;
        let live = live_rows(&db, Some(302));
        assert_eq!(live.len(), 1);
        assert_ne!(live[0].id, first);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_write_memory_resave_updates_expiry() {
        let dir = test_dir();
        let db = test_db(&dir);
        let tool =
            WriteMemoryTool::new(dir.to_str().unwrap(), db.clone(), test_backend(db.clone()));
        let content = "User is working from Tokyo this week";
        tool.execute(json!({"scope": "chat", "chat_id": 303, "content": content, "ttl_days": 7}))
            .await;
        assert!(live_rows(&db, Some(303))[0].expires_at.is_some());
        tool.execute(json!({"scope": "chat", "chat_id": 303, "content": content}))
            .await;
        let live = live_rows(&db, Some(303));
        assert_eq!(live.len(), 1);
        assert!(live[0].expires_at.is_none());
        let _ = std::fs::remove_dir_all(&dir);
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
    async fn test_write_memory_chat_upserts_per_sender() {
        let dir = test_dir();
        let db = test_db(&dir);
        db.resolve_or_create_chat_id("web", "42", Some("web-42"), "web")
            .unwrap();
        let tool =
            WriteMemoryTool::new(dir.to_str().unwrap(), db.clone(), test_backend(db.clone()));

        store_user_message(&db, 42, "alice", "remember profile");
        let r1 = tool
            .execute(json!({"scope": "chat", "chat_id": 42, "content": "昵称: 老板"}))
            .await;
        assert!(!r1.is_error, "{}", r1.content);

        store_user_message(&db, 42, "bob", "remember profile");
        let r2 = tool
            .execute(json!({"scope": "chat", "chat_id": 42, "content": "昵称: Bob哥"}))
            .await;
        assert!(!r2.is_error, "{}", r2.content);

        store_user_message(&db, 42, "alice", "update profile");
        let r3 = tool
            .execute(json!({"scope": "chat", "chat_id": 42, "content": "昵称: 大老板"}))
            .await;
        assert!(!r3.is_error, "{}", r3.content);

        let content =
            std::fs::read_to_string(dir.join("groups").join("web").join("42").join("AGENTS.md"))
                .unwrap();
        assert!(content.contains("## Person: alice"));
        assert!(content.contains("## Person: bob"));
        assert!(content.contains("昵称: 大老板"));
        assert!(content.contains("昵称: Bob哥"));
        assert!(!content.contains("昵称: 老板"));

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
        assert!(result
            .content
            .contains("must be 'global', 'bot', or 'chat'"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_write_and_read_memory_bot_scope() {
        let dir = test_dir();
        let db = test_db(&dir);
        let write_tool =
            WriteMemoryTool::new(dir.to_str().unwrap(), db.clone(), test_backend(db.clone()));
        let read_tool = ReadMemoryTool::new(dir.to_str().unwrap(), db);

        let write = write_tool
            .execute(json!({
                "scope": "bot",
                "content": "bot identity",
                "__microclaw_auth": {
                    "caller_channel": "feishu.ops",
                    "caller_chat_id": 42,
                    "control_chat_ids": []
                }
            }))
            .await;
        assert!(!write.is_error, "{}", write.content);

        let read = read_tool
            .execute(json!({
                "scope": "bot",
                "__microclaw_auth": {
                    "caller_channel": "feishu.ops",
                    "caller_chat_id": 42,
                    "control_chat_ids": []
                }
            }))
            .await;
        assert!(!read.is_error, "{}", read.content);
        assert_eq!(read.content, "bot identity");
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
