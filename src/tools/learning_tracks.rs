use std::sync::Arc;

use async_trait::async_trait;
use serde_json::json;

use super::{authorize_chat_access, schema_object, Tool, ToolResult};
use microclaw_core::llm_types::ToolDefinition;
use microclaw_storage::db::{call_blocking, Database};

pub struct LearningTracksTool {
    db: Arc<Database>,
    default_timezone: String,
}

impl LearningTracksTool {
    pub fn new(db: Arc<Database>, default_timezone: String) -> Self {
        Self {
            db,
            default_timezone,
        }
    }
}

#[async_trait]
impl Tool for LearningTracksTool {
    fn name(&self) -> &str {
        "learning_tracks"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: self.name().into(),
            description: "Create and manage governed background learning tracks. A track researches a user-selected direction on its cron schedule, using explicit source and cost boundaries. It produces inert, source-backed skill candidates for operator review; it never silently activates them.".into(),
            input_schema: schema_object(
                json!({
                    "action": {
                        "type": "string",
                        "enum": ["create", "list", "pause", "resume", "archive", "run_now"]
                    },
                    "chat_id": {"type": "integer"},
                    "track_id": {"type": "string"},
                    "name": {"type": "string", "maxLength": 96},
                    "objective": {"type": "string", "maxLength": 8000},
                    "directions": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Concrete capabilities or questions the track should prioritize"
                    },
                    "allowed_sources": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Allowed domains, repositories, or source classes such as official_docs and peer_reviewed_papers"
                    },
                    "schedule": {
                        "type": "string",
                        "description": "6-field cron expression; defaults to daily at 03:00"
                    },
                    "timezone": {"type": "string"},
                    "token_budget": {"type": "integer", "minimum": 1000, "maximum": 2000000},
                    "max_sources": {"type": "integer", "minimum": 1, "maximum": 100},
                    "promotion_mode": {
                        "type": "string",
                        "enum": ["propose", "manual"],
                        "description": "Both modes require explicit operator promotion; propose is the recommended default"
                    }
                }),
                &["action", "chat_id"],
            ),
        }
    }

    async fn execute(&self, input: serde_json::Value) -> ToolResult {
        let chat_id = match input.get("chat_id").and_then(|value| value.as_i64()) {
            Some(chat_id) => chat_id,
            None => return ToolResult::error("missing chat_id".into()),
        };
        if let Err(error) = authorize_chat_access(&input, chat_id) {
            return ToolResult::error(error);
        }
        let action = input
            .get("action")
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .to_string();
        match action.as_str() {
            "create" => self.create(input, chat_id).await,
            "list" => match call_blocking(self.db.clone(), move |db| {
                db.list_learning_tracks(Some(chat_id))
            })
            .await
            {
                Ok(tracks) => ToolResult::success(
                    serde_json::to_string_pretty(&tracks).unwrap_or_else(|_| "[]".into()),
                ),
                Err(error) => ToolResult::error(error.to_string()),
            },
            "pause" | "resume" | "archive" | "run_now" => {
                self.change_status(input, chat_id, &action).await
            }
            _ => ToolResult::error("invalid learning_tracks action".into()),
        }
    }
}

impl LearningTracksTool {
    async fn create(&self, input: serde_json::Value, chat_id: i64) -> ToolResult {
        let Some(name) = input.get("name").and_then(|value| value.as_str()) else {
            return ToolResult::error("create requires name".into());
        };
        let Some(objective) = input.get("objective").and_then(|value| value.as_str()) else {
            return ToolResult::error("create requires objective".into());
        };
        let directions = input
            .get("directions")
            .cloned()
            .unwrap_or_else(|| json!([]));
        let sources = input
            .get("allowed_sources")
            .cloned()
            .unwrap_or_else(|| json!(["official_docs", "peer_reviewed_papers"]));
        if !directions.is_array() || !sources.is_array() {
            return ToolResult::error("directions and allowed_sources must be arrays".into());
        }
        let schedule = input
            .get("schedule")
            .and_then(|value| value.as_str())
            .unwrap_or("0 0 3 * * *");
        let timezone = input
            .get("timezone")
            .and_then(|value| value.as_str())
            .unwrap_or(&self.default_timezone);
        let next_run = match crate::learning_foundry::compute_next_learning_run(schedule, timezone)
        {
            Ok(next_run) => next_run,
            Err(error) => return ToolResult::error(error),
        };
        let token_budget = input
            .get("token_budget")
            .and_then(|value| value.as_i64())
            .unwrap_or(80_000);
        let max_sources = input
            .get("max_sources")
            .and_then(|value| value.as_i64())
            .unwrap_or(20);
        let promotion_mode = input
            .get("promotion_mode")
            .and_then(|value| value.as_str())
            .unwrap_or("propose");
        let name = name.to_string();
        let objective = objective.to_string();
        let schedule = schedule.to_string();
        let timezone = timezone.to_string();
        let promotion_mode = promotion_mode.to_string();
        let persisted_next_run = next_run.clone();
        match call_blocking(self.db.clone(), move |db| {
            db.create_learning_track(
                chat_id,
                &name,
                &objective,
                &directions,
                &sources,
                &schedule,
                &timezone,
                token_budget,
                max_sources,
                &promotion_mode,
                &persisted_next_run,
            )
        })
        .await
        {
            Ok(track_id) => ToolResult::success(format!(
                "Learning track created: {track_id}. It will run at {next_run} and produce review-only candidates."
            )),
            Err(error) => ToolResult::error(error.to_string()),
        }
    }

    async fn change_status(
        &self,
        input: serde_json::Value,
        chat_id: i64,
        action: &str,
    ) -> ToolResult {
        let Some(track_id) = input.get("track_id").and_then(|value| value.as_str()) else {
            return ToolResult::error(format!("{action} requires track_id"));
        };
        let track_id = track_id.to_string();
        let belongs = call_blocking(self.db.clone(), {
            let track_id = track_id.clone();
            move |db| db.learning_track_belongs_to_chat(&track_id, chat_id)
        })
        .await;
        if !matches!(belongs, Ok(true)) {
            return ToolResult::error("learning track not found in this chat".into());
        }
        let (status, next_run) = match action {
            "pause" => ("paused", None),
            "archive" => ("archived", None),
            "resume" => ("active", None),
            "run_now" => ("active", Some(chrono::Utc::now().to_rfc3339())),
            _ => unreachable!(),
        };
        let status = status.to_string();
        match call_blocking(self.db.clone(), move |db| {
            db.update_learning_track_status(&track_id, &status, next_run.as_deref())
        })
        .await
        {
            Ok(true) => ToolResult::success(format!("Learning track {action} accepted.")),
            Ok(false) => ToolResult::error("learning track not found".into()),
            Err(error) => ToolResult::error(error.to_string()),
        }
    }
}
