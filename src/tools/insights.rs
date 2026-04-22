use async_trait::async_trait;
use serde_json::{json, Value};
use std::sync::Arc;

use microclaw_core::llm_types::ToolDefinition;
use microclaw_storage::db::{call_blocking, Database};

use super::{authorize_chat_access, auth_context_from_input, schema_object, Tool, ToolResult};

/// Insights tool — compact usage / activity summary over a trailing window.
///
/// Aggregates `llm_usage_logs` and message counts to produce a markdown
/// summary of recent activity. Use-cases: daily report, spend check,
/// "which model did I burn tokens on this week". Modeled after
/// hermes-agent's `/insights [days]` command.
///
/// Access model: scoped to caller's chat by default (like `session_search`);
/// control chats may pass `all_chats: true` for a tenant-wide view.
pub struct InsightsTool {
    db: Arc<Database>,
}

impl InsightsTool {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }
}

#[async_trait]
impl Tool for InsightsTool {
    fn name(&self) -> &str {
        "insights"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: self.name().into(),
            description: "Summarize recent chat activity and LLM usage — requests, \
                input/output tokens, breakdown by model. Use for `/insights` style \
                reports, spend checks, or end-of-day digests. Scoped to the \
                caller's chat by default; `all_chats: true` requires a control chat."
                .into(),
            input_schema: schema_object(
                json!({
                    "days": {
                        "type": "integer",
                        "description": "Trailing window in days (default 7, max 90)."
                    },
                    "chat_id": {
                        "type": "integer",
                        "description": "Optional explicit chat (requires access)."
                    },
                    "all_chats": {
                        "type": "boolean",
                        "description": "Control-chat opt-in for tenant-wide aggregation."
                    }
                }),
                &[],
            ),
        }
    }

    async fn execute(&self, input: Value) -> ToolResult {
        let Some(auth) = auth_context_from_input(&input) else {
            return ToolResult::error(
                "insights requires an auth context (caller_chat_id)".into(),
            );
        };
        let days = input
            .get("days")
            .and_then(|v| v.as_u64())
            .unwrap_or(7)
            .clamp(1, 90);
        let all_chats = input
            .get("all_chats")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let explicit_chat = input.get("chat_id").and_then(|v| v.as_i64());

        let scope: Option<i64> = if all_chats {
            if !auth.is_control_chat() {
                return ToolResult::error(
                    "all_chats=true requires a control chat".into(),
                );
            }
            None
        } else {
            let target = explicit_chat.unwrap_or(auth.caller_chat_id);
            if let Err(e) = authorize_chat_access(&input, target) {
                return ToolResult::error(e);
            }
            Some(target)
        };

        let since = (chrono::Utc::now() - chrono::Duration::days(days as i64)).to_rfc3339();
        let db = self.db.clone();
        let since_owned = since.clone();
        let fetch = call_blocking(db.clone(), move |d| {
            let summary = d.get_llm_usage_summary_since(scope, Some(&since_owned))?;
            let by_model = d.get_llm_usage_by_model(scope, Some(&since_owned), Some(20))?;
            Ok::<_, microclaw_core::error::MicroClawError>((summary, by_model))
        })
        .await;

        let (summary, by_model) = match fetch {
            Ok(v) => v,
            Err(e) => return ToolResult::error(format!("insights query failed: {e}")),
        };

        let scope_label = match scope {
            Some(cid) => format!("chat {cid}"),
            None => "all chats".to_string(),
        };
        let mut lines = Vec::new();
        lines.push(format!(
            "# Insights — last {days} day(s), {scope_label}"
        ));
        lines.push(String::new());
        lines.push(format!("- requests: **{}**", summary.requests));
        lines.push(format!("- input tokens:  **{}**", summary.input_tokens));
        lines.push(format!("- output tokens: **{}**", summary.output_tokens));
        lines.push(format!("- total tokens:  **{}**", summary.total_tokens));
        if let Some(ts) = summary.last_request_at.as_deref() {
            lines.push(format!("- last request: {ts}"));
        }
        if !by_model.is_empty() {
            lines.push(String::new());
            lines.push("## By model".into());
            for entry in &by_model {
                lines.push(format!(
                    "- `{}`: {} req, {} in + {} out = {} tok",
                    entry.model,
                    entry.requests,
                    entry.input_tokens,
                    entry.output_tokens,
                    entry.total_tokens,
                ));
            }
        }

        ToolResult::success(lines.join("\n"))
    }
}
