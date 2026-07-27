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
    let (runs_24h, contract_tasks, dlq_pending, outbox_pending, active_turns, recoveries) =
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
            let outbox_pending = db.count_outbox_pending()?;
            let active_turns = db.list_active_turns()?;
            let recoveries = db.list_audit_logs(Some("turn_recovery"), 20)?;
            Ok::<_, microclaw_core::error::MicroClawError>((
                (total, success),
                contract_tasks,
                dlq_pending,
                outbox_pending,
                active_turns,
                recoveries,
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
            "grants_mode": tool_policy.grants_mode,
            "control_chat_bypass": tool_policy.control_chat_bypass,
            "grants": tool_policy.grants,
        },
        "egress_policy": {
            "mode": config.egress_policy.mode,
            "allow_hosts": config.egress_policy.allow_hosts,
            "deny_hosts": config.egress_policy.deny_hosts,
            "block_private_ips": config.egress_policy.block_private_ips,
        },
        "sandbox_credentials": {
            "credential_env_allowlist": config.sandbox.credential_env_allowlist,
            "no_network": config.sandbox.no_network,
            "security_profile": config.sandbox.security_profile,
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
        "delivery": {
            "outbox_pending": outbox_pending,
        },
        "durable_runs": {
            "active": active_turns.into_iter().map(|turn| json!({
                "run_id": turn.run_id,
                "chat_id": turn.chat_id,
                "channel": turn.channel,
                "phase": turn.phase,
                "iteration": turn.iteration,
                "resumable": turn.resumable,
                "progress": turn.progress_text,
                "tool_summary": turn.tool_summary,
                "started_at": turn.started_at,
                "last_checkpoint_at": turn.last_checkpoint_at,
            })).collect::<Vec<_>>(),
            "recent_recoveries": recoveries.into_iter().map(|event| json!({
                "action": event.action,
                "status": event.status,
                "detail": event.detail,
                "created_at": event.created_at,
            })).collect::<Vec<_>>(),
        },
    })))
}
