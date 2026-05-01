use async_trait::async_trait;
use serde_json::json;
use std::sync::Arc;

use microclaw_core::llm_types::ToolDefinition;
use microclaw_storage::db::Database;

use super::{authorize_chat_access, auth_context_from_input, schema_object, Tool, ToolResult};

/// Session search tool — full-text search over the chatbot's stored messages.
///
/// Exposes SQLite FTS5 queries against the `messages` table. Returns the
/// top-ranked matches with enough context (chat title, sender, timestamp,
/// snippet) for the agent to reason about them without loading whole
/// transcripts. Modeled after `session_search_tool.py` in
/// `nousresearch/hermes-agent`, adapted to microclaw's SQLite schema.
///
/// Access model:
/// - By default the search is scoped to the caller's own chat. The tool
///   participates in `should_inject_default_chat_id`, so when the agent
///   omits `chat_id` the runtime injects the caller's.
/// - Explicit `chat_id = N` is gated by `authorize_chat_access` — only the
///   caller or a control chat may search another chat's messages.
/// - `all_chats = true` opts in to cross-chat search and is only honored for
///   control chats. This keeps multi-tenant deployments (multiple DMs,
///   groups, channels, SOUL-per-chat personalities) from leaking messages
///   across conversations.
pub struct SessionSearchTool {
    db: Arc<Database>,
}

impl SessionSearchTool {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }
}

fn trim_snippet(content: &str, max_chars: usize) -> String {
    if content.chars().count() <= max_chars {
        return content.to_string();
    }
    let truncated: String = content.chars().take(max_chars).collect();
    format!("{truncated}…")
}

#[async_trait]
impl Tool for SessionSearchTool {
    fn name(&self) -> &str {
        "session_search"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: self.name().into(),
            description: "Search past conversation messages using SQLite FTS5. \
                Use when the user references an earlier conversation, asks 'did we \
                talk about X?', or you need cross-session recall. Returns ranked \
                message snippets with chat metadata. Supports FTS5 syntax — simple \
                words, quoted phrases, `NEAR`, `AND/OR/NOT`, and column prefix \
                filters (e.g. `sender_name:alice content:refund`). \
                By default the search is scoped to the current chat; \
                pass `chat_id` to target a different chat the caller can access, \
                or `all_chats: true` (control chats only) to search every chat."
                .into(),
            input_schema: schema_object(
                json!({
                    "query": {
                        "type": "string",
                        "description": "FTS5 query string. Plain words are OR-joined; quote phrases for exact match."
                    },
                    "chat_id": {
                        "type": "integer",
                        "description": "Optional chat scope. Defaults to the caller's chat. Accessing other chats requires either the same caller_chat_id or a control chat."
                    },
                    "all_chats": {
                        "type": "boolean",
                        "description": "Control-chat-only opt-in to search every chat. Ignored for non-control callers."
                    },
                    "since": {
                        "type": "string",
                        "description": "Optional RFC3339 timestamp; only messages at or after this time are returned."
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum rows to return (default 10, max 50)."
                    },
                    "snippet_chars": {
                        "type": "integer",
                        "description": "Maximum characters of message content to include per result (default 240)."
                    }
                }),
                &["query"],
            ),
        }
    }

    async fn execute(&self, input: serde_json::Value) -> ToolResult {
        let query = match input.get("query").and_then(|v| v.as_str()) {
            Some(q) if !q.trim().is_empty() => q.trim().to_string(),
            _ => return ToolResult::error("Missing or empty required parameter: query".into()),
        };

        let Some(auth) = auth_context_from_input(&input) else {
            return ToolResult::error(
                "session_search requires an auth context (caller_chat_id) on the input".into(),
            );
        };

        let all_chats = input
            .get("all_chats")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let explicit_chat_id = input.get("chat_id").and_then(|v| v.as_i64());

        // Resolve the scope based on access policy.
        //   1. all_chats=true is a control-only escape hatch → no chat_id filter.
        //   2. explicit chat_id is gated by authorize_chat_access.
        //   3. default → caller's own chat (runtime may have already injected this).
        let scope_chat_id: Option<i64> = if all_chats {
            if !auth.is_control_chat() {
                return ToolResult::error(
                    "all_chats=true is only available for control chats".into(),
                );
            }
            None
        } else {
            let target = explicit_chat_id.unwrap_or(auth.caller_chat_id);
            if let Err(e) = authorize_chat_access(&input, target) {
                return ToolResult::error(e);
            }
            Some(target)
        };

        let since = input
            .get("since")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let max_results = input
            .get("max_results")
            .and_then(|v| v.as_u64())
            .map(|n| n as usize)
            .unwrap_or(10)
            .clamp(1, 50);
        let snippet_chars = input
            .get("snippet_chars")
            .and_then(|v| v.as_u64())
            .map(|n| n as usize)
            .unwrap_or(240)
            .clamp(40, 2_000);

        let db = self.db.clone();
        let query_for_task = query.clone();
        let since_for_task = since.clone();
        let search = tokio::task::spawn_blocking(move || {
            db.search_messages_fts(
                &query_for_task,
                scope_chat_id,
                since_for_task.as_deref(),
                max_results,
            )
        })
        .await;

        let results = match search {
            Ok(Ok(rows)) => rows,
            Ok(Err(e)) => {
                return ToolResult::error(format!("session_search failed: {e}"));
            }
            Err(e) => {
                return ToolResult::error(format!("session_search task join error: {e}"));
            }
        };

        let scope_label = match scope_chat_id {
            Some(cid) => format!("chat {cid}"),
            None => "all chats".to_string(),
        };

        if results.is_empty() {
            return ToolResult::success(format!(
                "No messages matched FTS5 query {query:?} in {scope_label}"
            ));
        }

        let mut lines = Vec::with_capacity(results.len() + 1);
        lines.push(format!(
            "{} match(es) for FTS5 query {query:?} in {scope_label}",
            results.len()
        ));
        for m in &results {
            let role = if m.is_from_bot { "bot" } else { "user" };
            lines.push(format!(
                "- [chat {chat}] {ts} ({role}={sender}): {snippet}",
                chat = m.chat_id,
                ts = m.timestamp,
                sender = m.sender_name,
                snippet = trim_snippet(&m.content, snippet_chars),
            ));
        }
        ToolResult::success(lines.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trim_snippet_truncates_long_content() {
        let long = "a".repeat(1000);
        let out = trim_snippet(&long, 50);
        assert!(out.ends_with('…'));
        assert_eq!(out.chars().count(), 51);
    }

    #[test]
    fn trim_snippet_passes_short_content() {
        let text = "hello";
        assert_eq!(trim_snippet(text, 100), text);
    }

    fn auth_input(caller_chat_id: i64, control_chat_ids: Vec<i64>) -> serde_json::Value {
        json!({
            "query": "anything",
            "__microclaw_auth": {
                "caller_channel": "telegram",
                "caller_chat_id": caller_chat_id,
                "control_chat_ids": control_chat_ids,
                "env_files": [],
            }
        })
    }

    struct ScopedDir(std::path::PathBuf);
    impl Drop for ScopedDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn make_tmp_db() -> (Arc<Database>, ScopedDir) {
        let dir = std::env::temp_dir().join(format!("microclaw_test_{}", uuid::Uuid::new_v4()));
        let db = Database::new(dir.to_str().unwrap()).expect("open db");
        (Arc::new(db), ScopedDir(dir))
    }

    #[tokio::test]
    async fn cross_chat_without_permission_is_rejected() {
        let (db, _dir) = make_tmp_db();
        let tool = SessionSearchTool::new(db);
        let mut input = auth_input(100, vec![]);
        input["chat_id"] = json!(200);
        let result = tool.execute(input).await;
        assert!(result.is_error, "expected permission error, got ok");
        assert!(
            result.content.contains("Permission denied"),
            "expected permission-denied message, got: {}",
            result.content
        );
    }

    #[tokio::test]
    async fn all_chats_denied_for_non_control_caller() {
        let (db, _dir) = make_tmp_db();
        let tool = SessionSearchTool::new(db);
        let mut input = auth_input(100, vec![]);
        input["all_chats"] = json!(true);
        let result = tool.execute(input).await;
        assert!(result.is_error);
        assert!(
            result.content.contains("control chats"),
            "expected control-only message, got: {}",
            result.content
        );
    }

    #[tokio::test]
    async fn all_chats_allowed_for_control_caller() {
        let (db, _dir) = make_tmp_db();
        let tool = SessionSearchTool::new(db);
        let mut input = auth_input(100, vec![100]);
        input["all_chats"] = json!(true);
        let result = tool.execute(input).await;
        assert!(
            !result.is_error,
            "expected ok for control chat, got: {}",
            result.content
        );
    }

    #[tokio::test]
    async fn default_scope_is_caller_chat() {
        let (db, _dir) = make_tmp_db();
        let tool = SessionSearchTool::new(db);
        let input = auth_input(100, vec![]);
        let result = tool.execute(input).await;
        assert!(!result.is_error, "expected ok, got: {}", result.content);
        assert!(
            result.content.contains("chat 100") || result.content.contains("No messages matched"),
            "expected scope label 'chat 100', got: {}",
            result.content
        );
    }
}
