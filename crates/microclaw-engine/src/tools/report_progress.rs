use std::sync::Arc;

use async_trait::async_trait;
use serde_json::json;

use super::{schema_object, Tool, ToolResult};
use crate::config::Config;
use microclaw_channels::channel::deliver_and_store_bot_message;
use microclaw_channels::channel_adapter::ChannelRegistry;
use microclaw_core::llm_types::ToolDefinition;
use microclaw_storage::db::{call_blocking, Database};
use microclaw_tools::runtime::auth_context_from_input;

/// Lets a running sub-agent push a short progress update to its chat while it
/// works, like a colleague giving a quick status. Records the update on the run
/// timeline and (when not throttled) delivers a `📊 [label]: ...` message.
pub struct ReportProgressTool {
    config: Config,
    registry: Arc<ChannelRegistry>,
    db: Arc<Database>,
}

impl ReportProgressTool {
    pub fn new(config: &Config, registry: Arc<ChannelRegistry>, db: Arc<Database>) -> Self {
        ReportProgressTool {
            config: config.clone(),
            registry,
            db,
        }
    }
}

#[async_trait]
impl Tool for ReportProgressTool {
    fn name(&self) -> &str {
        "report_progress"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "report_progress".into(),
            description: "Post a short progress update to the chat while you work on a long task (e.g. \"checked 3/5 sources, two left\"). Use it at meaningful milestones so the user gets a colleague-style status; keep each update to one line. Updates are throttled to avoid spam. Only available inside a sub-agent run.".into(),
            input_schema: schema_object(
                json!({
                    "progress": {
                        "type": "string",
                        "description": "One-line status update on what's done and what's left."
                    },
                    "pct": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 100,
                        "description": "Optional rough completion percentage (0-100)."
                    }
                }),
                &["progress"],
            ),
        }
    }

    async fn execute(&self, input: serde_json::Value) -> ToolResult {
        let run_id = input
            .get("__subagent_runtime")
            .and_then(|v| v.get("run_id"))
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let Some(run_id) = run_id else {
            return ToolResult::error(
                "report_progress is only available inside a sub-agent run".into(),
            );
        };

        let progress = input
            .get("progress")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        if progress.is_empty() {
            return ToolResult::error("Missing required parameter: progress".into());
        }
        let pct = input
            .get("pct")
            .and_then(|v| v.as_i64())
            .map(|p| p.clamp(0, 100));

        let Some(auth) = auth_context_from_input(&input) else {
            return ToolResult::error("report_progress requires caller auth context".into());
        };
        let chat_id = auth.caller_chat_id;

        // Record the progress snapshot + timeline event; get the previous
        // delivery time so we can throttle chat spam.
        let run_id_for_record = run_id.clone();
        let progress_for_record = progress.clone();
        let prev_progress_at = match call_blocking(self.db.clone(), move |db| {
            db.record_subagent_progress(&run_id_for_record, &progress_for_record)
        })
        .await
        {
            Ok(v) => v,
            Err(e) => return ToolResult::error(format!("Failed recording progress: {e}")),
        };

        // Progress is always recorded on the run timeline (so subagents_list /
        // standup can show it); delivery to chat is what the toggle controls.
        if !self.config.subagents.progress_reports
            || auth.caller_channel == "weixin"
            || auth.caller_channel.starts_with("weixin.")
        {
            return ToolResult::success(
                json!({"status": "recorded", "delivered": false, "reason": "disabled"}).to_string(),
            );
        }

        let min_interval = self.config.subagents.progress_min_interval_secs as i64;
        let throttled = prev_progress_at
            .as_deref()
            .and_then(|ts| chrono::DateTime::parse_from_rfc3339(ts).ok())
            .map(|prev| {
                (chrono::Utc::now() - prev.with_timezone(&chrono::Utc)).num_seconds() < min_interval
            })
            .unwrap_or(false);

        if throttled {
            return ToolResult::success(
                json!({"status": "recorded", "delivered": false, "reason": "throttled"})
                    .to_string(),
            );
        }

        // Look up the human-friendly label for a nicer header.
        let run_id_for_label = run_id.clone();
        let label = call_blocking(self.db.clone(), move |db| {
            db.get_subagent_run(&run_id_for_label, chat_id)
        })
        .await
        .ok()
        .flatten()
        .and_then(|r| r.label);

        let header = match label {
            Some(l) => format!("📊 [{l}]"),
            None => "📊 progress".to_string(),
        };
        let pct_str = pct.map(|p| format!(" ({p}%)")).unwrap_or_default();
        let message = format!("{header}{pct_str}: {progress}");

        let bot_username = self.config.bot_username_for_channel(&auth.caller_channel);
        match deliver_and_store_bot_message(
            self.registry.as_ref(),
            self.db.clone(),
            &bot_username,
            chat_id,
            &message,
        )
        .await
        {
            Ok(_) => {
                ToolResult::success(json!({"status": "recorded", "delivered": true}).to_string())
            }
            // The progress is already recorded on the timeline; a delivery hiccup
            // shouldn't fail the sub-agent's turn.
            Err(e) => ToolResult::success(
                json!({"status": "recorded", "delivered": false, "error": e}).to_string(),
            ),
        }
    }
}
