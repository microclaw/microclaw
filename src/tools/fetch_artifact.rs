use async_trait::async_trait;
use serde_json::json;
use std::sync::Arc;

use microclaw_core::llm_types::ToolDefinition;
use microclaw_storage::db::Database;

use super::{auth_context_from_input, schema_object, Tool, ToolResult};

/// Read a slice of a tool-result artifact created when an oversized tool
/// response was spilled out of the message history.
///
/// Companion to the truncation logic in `tool_executor::maybe_spill_to_artifact`:
/// when a tool returns more characters than `tool_result_truncation_threshold_chars`,
/// the head + tail are kept in the message history and the full body is
/// stashed in `tool_result_artifacts` with a TTL. The agent uses this tool
/// to read further into the body without paying the token cost on every turn.
///
/// Access model: artifacts are scoped to the chat that produced them. The
/// caller must either own that chat or be a control chat — same gate as
/// `session_search`.
pub struct FetchArtifactTool {
    db: Arc<Database>,
}

impl FetchArtifactTool {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }
}

const DEFAULT_LENGTH: usize = 4000;
const MAX_LENGTH: usize = 16_000;

#[async_trait]
impl Tool for FetchArtifactTool {
    fn name(&self) -> &str {
        "fetch_artifact"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: self.name().into(),
            description: "Read a character range from a tool-result artifact \
                created when a previous tool response was truncated. The \
                truncation marker in the inline result tells you the \
                artifact_id; pass it here with offset/length (in Unicode \
                code points) to read more. Default length 4000, max 16000."
                .into(),
            input_schema: schema_object(
                json!({
                    "artifact_id": {
                        "type": "string",
                        "description": "Artifact id from the truncation marker (e.g. \"art_…\")."
                    },
                    "offset": {
                        "type": "integer",
                        "description": "Starting character offset (default 0)."
                    },
                    "length": {
                        "type": "integer",
                        "description": "Number of characters to return (default 4000, max 16000)."
                    }
                }),
                &["artifact_id"],
            ),
        }
    }

    async fn execute(&self, input: serde_json::Value) -> ToolResult {
        let artifact_id = match input.get("artifact_id").and_then(|v| v.as_str()) {
            Some(s) if !s.trim().is_empty() => s.trim().to_string(),
            _ => return ToolResult::error("Missing or empty required parameter: artifact_id".into()),
        };
        let offset = input
            .get("offset")
            .and_then(|v| v.as_i64())
            .unwrap_or(0)
            .max(0) as usize;
        let length = input
            .get("length")
            .and_then(|v| v.as_i64())
            .unwrap_or(DEFAULT_LENGTH as i64)
            .max(1) as usize;
        let length = length.min(MAX_LENGTH);

        let Some(auth) = auth_context_from_input(&input) else {
            return ToolResult::error(
                "fetch_artifact requires an auth context (caller_chat_id) on the input".into(),
            );
        };

        let db = self.db.clone();
        let artifact_id_for_db = artifact_id.clone();
        let now = chrono::Utc::now().to_rfc3339();
        let lookup = microclaw_storage::db::call_blocking(db, move |db| {
            db.get_tool_artifact_slice(&artifact_id_for_db, offset, length, &now)
        })
        .await;

        match lookup {
            Ok(Some((meta, slice))) => {
                if meta.chat_id != auth.caller_chat_id && !auth.is_control_chat() {
                    return ToolResult::error(format!(
                        "Permission denied: artifact `{artifact_id}` belongs to a different chat."
                    ))
                    .with_error_type("forbidden");
                }
                let returned: usize = slice.chars().count();
                let total = meta.total_chars as usize;
                let next_offset = offset + returned;
                let has_more = next_offset < total;
                let header = format!(
                    "artifact_id: {}\ntool: {}\ntotal_chars: {}\noffset: {}\nreturned: {}\nhas_more: {}",
                    meta.artifact_id, meta.tool_name, total, offset, returned, has_more
                );
                let body = if returned == 0 {
                    "(no content in this range)".to_string()
                } else {
                    slice
                };
                ToolResult::success(format!("{header}\n---\n{body}"))
            }
            Ok(None) => ToolResult::error(format!(
                "Artifact `{artifact_id}` not found or expired."
            ))
            .with_error_type("artifact_missing"),
            Err(e) => ToolResult::error(format!("Failed to read artifact: {e}")),
        }
    }
}
