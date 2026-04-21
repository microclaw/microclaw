use async_trait::async_trait;
use serde_json::json;
use std::sync::Arc;

use microclaw_core::llm_types::ToolDefinition;
use microclaw_storage::db::Database;

use super::{schema_object, Tool, ToolResult};

/// Session search tool — full-text search over the chatbot's stored messages.
///
/// Exposes SQLite FTS5 queries against the `messages` table. Returns the
/// top-ranked matches with enough context (chat title, sender, timestamp,
/// snippet) for the agent to reason about them without loading whole
/// transcripts. Modeled after `session_search_tool.py` in
/// `nousresearch/hermes-agent`, adapted to microclaw's SQLite schema.
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
                filters (e.g. `sender_name:alice content:refund`)."
                .into(),
            input_schema: schema_object(
                json!({
                    "query": {
                        "type": "string",
                        "description": "FTS5 query string. Plain words are OR-joined; quote phrases for exact match."
                    },
                    "chat_id": {
                        "type": "integer",
                        "description": "Optional chat scope. When omitted, searches across all chats the caller can access."
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
        let chat_id = input.get("chat_id").and_then(|v| v.as_i64());
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
                chat_id,
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

        if results.is_empty() {
            return ToolResult::success(format!("No messages matched FTS5 query: {query}"));
        }

        let mut lines = Vec::with_capacity(results.len() + 1);
        lines.push(format!(
            "{} match(es) for FTS5 query: {query}",
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
}
