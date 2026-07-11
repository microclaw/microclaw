//! Scheduled-task management endpoints for the web panel.
//!
//! Read side exposes the same lifecycle picture as the `list_scheduled_tasks`
//! chat tool (cadence description, run progress, deadline, contract flag,
//! humanized countdown); write side supports pause / resume / cancel with
//! explicit status-transition validation so the panel can never wedge the
//! scheduler into an unknown state.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::web::{middleware::AuthScope, require_scope, WebState};
use microclaw_storage::db::{call_blocking, ScheduledTask};

#[derive(Debug, Deserialize)]
pub struct ListTasksQuery {
    /// Filter to one status ("active", "paused", "completed", "cancelled",
    /// "failed", "running"). Omit for all.
    pub status: Option<String>,
    pub chat_id: Option<i64>,
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
struct TaskView {
    id: i64,
    chat_id: i64,
    prompt: String,
    schedule_type: String,
    schedule_value: String,
    timezone: String,
    status: String,
    next_run: String,
    next_run_in: Option<String>,
    last_run: Option<String>,
    created_at: String,
    cadence: String,
    run_count: i64,
    max_runs: Option<i64>,
    not_after: Option<String>,
    has_contract: bool,
}

fn task_view(task: ScheduledTask, now: chrono::DateTime<chrono::Utc>) -> TaskView {
    let cadence =
        crate::schedule_lifecycle::describe_schedule(&task.schedule_type, &task.schedule_value);
    let next_run_in = if task.status == "active" {
        crate::schedule_lifecycle::humanize_until(now, &task.next_run)
    } else {
        None
    };
    TaskView {
        id: task.id,
        chat_id: task.chat_id,
        prompt: task.prompt,
        schedule_type: task.schedule_type,
        schedule_value: task.schedule_value,
        timezone: task.timezone,
        status: task.status,
        next_run: task.next_run,
        next_run_in,
        last_run: task.last_run,
        created_at: task.created_at,
        cadence,
        run_count: task.run_count,
        max_runs: task.max_runs,
        not_after: task.not_after,
        has_contract: task
            .exit_criteria
            .as_deref()
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false),
    }
}

pub async fn api_list_tasks(
    headers: HeaderMap,
    Query(query): Query<ListTasksQuery>,
    State(state): State<WebState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    require_scope(&state, &headers, AuthScope::Read).await?;

    let limit = query.limit.unwrap_or(200).min(1000);
    let status = query.status.clone();
    let chat_id = query.chat_id;
    let tasks = call_blocking(state.app_state.db.clone(), move |db| {
        db.list_scheduled_tasks(status.as_deref(), limit)
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let now = chrono::Utc::now();
    let views: Vec<TaskView> = tasks
        .into_iter()
        .filter(|t| chat_id.is_none_or(|c| t.chat_id == c))
        .map(|t| task_view(t, now))
        .collect();

    Ok(Json(json!({ "ok": true, "tasks": views })))
}

pub async fn api_task_runs(
    headers: HeaderMap,
    Path(task_id): Path<i64>,
    State(state): State<WebState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    require_scope(&state, &headers, AuthScope::Read).await?;

    let (task, logs) = call_blocking(state.app_state.db.clone(), move |db| {
        let task = db.get_scheduled_task(task_id)?;
        let logs = db.get_task_run_logs(task_id, 50)?;
        Ok::<_, microclaw_core::error::MicroClawError>((task, logs))
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let Some(task) = task else {
        return Err((StatusCode::NOT_FOUND, "Task not found".into()));
    };

    let runs: Vec<serde_json::Value> = logs
        .into_iter()
        .map(|l| {
            json!({
                "id": l.id,
                "started_at": l.started_at,
                "finished_at": l.finished_at,
                "duration_ms": l.duration_ms,
                "success": l.success,
                "result_summary": l.result_summary,
            })
        })
        .collect();

    Ok(Json(json!({
        "ok": true,
        "task": task_view(task, chrono::Utc::now()),
        "runs": runs,
    })))
}

/// Allowed panel-driven status transitions. Everything else is rejected so
/// the web UI cannot resurrect retired tasks or fight the scheduler over a
/// task it has already claimed (`running` rows are only touched by the
/// scheduler and crash recovery).
fn validate_transition(current: &str, action: &str) -> Result<&'static str, String> {
    match (current, action) {
        ("active", "pause") => Ok("paused"),
        ("paused", "resume") => Ok("active"),
        ("active", "cancel") | ("paused", "cancel") => Ok("cancelled"),
        _ => Err(format!("cannot {action} a task in status '{current}'")),
    }
}

pub async fn api_task_action(
    headers: HeaderMap,
    Path((task_id, action)): Path<(i64, String)>,
    State(state): State<WebState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    require_scope(&state, &headers, AuthScope::Write).await?;

    if !matches!(action.as_str(), "pause" | "resume" | "cancel") {
        return Err((StatusCode::NOT_FOUND, "Unknown task action".into()));
    }

    let action_for_db = action.clone();
    let outcome = call_blocking(state.app_state.db.clone(), move |db| {
        let Some(task) = db.get_scheduled_task(task_id)? else {
            return Ok::<_, microclaw_core::error::MicroClawError>(None);
        };
        match validate_transition(&task.status, &action_for_db) {
            Ok(new_status) => {
                db.update_task_status(task_id, new_status)?;
                Ok(Some(Ok(new_status.to_string())))
            }
            Err(reason) => Ok(Some(Err(reason))),
        }
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    match outcome {
        None => Err((StatusCode::NOT_FOUND, "Task not found".into())),
        Some(Err(reason)) => Err((StatusCode::CONFLICT, reason)),
        Some(Ok(new_status)) => Ok(Json(json!({
            "ok": true,
            "task_id": task_id,
            "status": new_status,
        }))),
    }
}

#[cfg(test)]
mod tests {
    use super::validate_transition;

    #[test]
    fn transitions_follow_lifecycle_rules() {
        assert_eq!(validate_transition("active", "pause"), Ok("paused"));
        assert_eq!(validate_transition("paused", "resume"), Ok("active"));
        assert_eq!(validate_transition("active", "cancel"), Ok("cancelled"));
        assert_eq!(validate_transition("paused", "cancel"), Ok("cancelled"));
    }

    #[test]
    fn retired_and_scheduler_owned_states_are_immutable() {
        for status in ["completed", "cancelled", "failed", "running"] {
            for action in ["pause", "resume", "cancel"] {
                assert!(
                    validate_transition(status, action).is_err(),
                    "{action} must be rejected for status {status}"
                );
            }
        }
        // Redundant/no-op transitions are also rejected explicitly.
        assert!(validate_transition("active", "resume").is_err());
        assert!(validate_transition("paused", "pause").is_err());
    }
}
