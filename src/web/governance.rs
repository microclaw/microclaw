//! Governance snapshot for the web panel.
//!
//! Read-only view over the operator-facing safety rails: tool policy,
//! per-chat token budget, proactive heartbeat, progress heartbeats, plus the
//! live health signals that already back the `insights` chat tool
//! (supervised-loop restart counts, scheduled-task run summary, DLQ depth).
//! Editing stays in config.yaml / the existing config endpoints — this view
//! is for seeing at a glance what is actually enforced right now.

use axum::{extract::State, http::HeaderMap, http::StatusCode, Json};
use serde_json::json;

use crate::web::{middleware::AuthScope, require_scope, WebState};
use microclaw_storage::db::call_blocking;

pub async fn api_governance(
    headers: HeaderMap,
    State(state): State<WebState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    require_scope(&state, &headers, AuthScope::Read).await?;

    let config = &state.app_state.config;

    let tool_policy = &config.tool_policy;
    let token_budget = &config.token_budget;
    let heartbeat = &config.heartbeat;

    // Progress heartbeat settings per non-web channel (Phase 3/4 of the
    // progress-events plan). Only channels with edit-in-place wiring.
    let progress: serde_json::Value = ["telegram", "discord", "slack"]
        .iter()
        .map(|name| {
            let s = crate::channels::event_tap::progress_updates_settings(config, name);
            (
                name.to_string(),
                json!({
                    "enabled": s.enabled,
                    "groups": s.groups,
                    "min_turn_seconds": s.config.min_turn_secs,
                    "update_interval_seconds": s.config.interval_secs,
                }),
            )
        })
        .collect::<serde_json::Map<_, _>>()
        .into();

    let restarts: Vec<serde_json::Value> = crate::supervision::restart_counts()
        .into_iter()
        .map(|(name, count)| json!({ "loop": name, "restarts": count }))
        .collect();

    let since = (chrono::Utc::now() - chrono::Duration::hours(24)).to_rfc3339();
    let (runs_24h, contract_tasks, dlq_pending) =
        call_blocking(state.app_state.db.clone(), move |db| {
            let (total, success) = db.get_task_run_summary_since(Some(&since))?;
            let contract_tasks = db
                .list_scheduled_tasks(None, 1000)?
                .into_iter()
                .filter(|t| {
                    t.exit_criteria
                        .as_deref()
                        .map(|s| !s.trim().is_empty())
                        .unwrap_or(false)
                })
                .count();
            let dlq_pending = db.list_scheduled_task_dlq(None, None, false, 100)?.len();
            Ok::<_, microclaw_core::error::MicroClawError>((
                (total, success),
                contract_tasks,
                dlq_pending,
            ))
        })
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(json!({
        "ok": true,
        "tool_policy": {
            "mode": tool_policy.mode,
            "deny_tools": tool_policy.deny_tools,
            "allow_tools": tool_policy.allow_tools,
            "max_risk": tool_policy.max_risk,
        },
        "token_budget": {
            "daily_per_chat": token_budget.daily_per_chat,
            "exempt_control_chats": token_budget.exempt_control_chats,
            "enabled": token_budget.daily_per_chat > 0,
        },
        "heartbeat": {
            "enabled": heartbeat.enabled,
            "interval_mins": heartbeat.interval_mins,
            "max_chars": heartbeat.max_chars,
        },
        "progress_updates": progress,
        "supervision": {
            "restarts": restarts,
        },
        "scheduled_tasks": {
            "runs_24h": runs_24h.0,
            "success_24h": runs_24h.1,
            "with_contract": contract_tasks,
            "dlq_pending": dlq_pending,
        },
    })))
}
