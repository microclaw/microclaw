//! Opt-in periodic trust report.
//!
//! A digest of what the agent actually did over the reporting window —
//! task runs, completion-contract verdicts, token spend, guardrail
//! interventions, delivery/recovery health — delivered to every control
//! chat. Rendering is a pure function over a snapshot struct; the loop
//! only gathers, formats, delivers, and records the last-sent marker in
//! `db_meta` so cadence survives restarts. No LLM calls are involved.

use std::sync::Arc;
use std::time::Duration;

use tracing::{info, warn};

use crate::internal::channels::channel::deliver_and_store_bot_message;
use crate::internal::storage::db::call_blocking;
use crate::runtime::AppState;

const LAST_SENT_META_KEY: &str = "trust_report_last_sent_at";

/// Everything one report renders, gathered up front so formatting is pure.
#[derive(Debug, Clone, Default)]
pub struct TrustReportData {
    pub window_days: u64,
    pub task_runs: i64,
    pub task_successes: i64,
    pub contracts_verified: i64,
    pub contracts_failed: i64,
    pub llm_requests: i64,
    pub tokens_total: i64,
    pub egress_events: i64,
    pub hook_events: i64,
    pub alert_events: i64,
    pub recovery_events: i64,
    pub budget_refusals_since_start: u64,
    pub outbox_pending: i64,
    pub outbox_failed: i64,
    pub dlq_pending: i64,
    pub restarts_total: u64,
}

pub fn format_trust_report(d: &TrustReportData) -> String {
    let mut lines = vec![format!(
        "Trust report — last {} day(s)",
        d.window_days.max(1)
    )];
    lines.push(format!(
        "Tasks: {} run(s), {} succeeded",
        d.task_runs, d.task_successes
    ));
    lines.push(if d.contracts_verified + d.contracts_failed == 0 {
        "Contracts: no verdicts recorded".to_string()
    } else {
        format!(
            "Contracts: {} verified, {} failed",
            d.contracts_verified, d.contracts_failed
        )
    });
    lines.push(format!(
        "Tokens: {} across {} provider call(s)",
        d.tokens_total, d.llm_requests
    ));
    lines.push(format!(
        "Guardrail audit events: egress={} hooks={} alerts={}",
        d.egress_events, d.hook_events, d.alert_events
    ));
    lines.push(format!(
        "Reliability: {} recovery event(s), outbox pending={} failed={}, scheduler DLQ={}",
        d.recovery_events, d.outbox_pending, d.outbox_failed, d.dlq_pending
    ));
    lines.push(format!(
        "Since process start: {} budget refusal(s), {} supervised-loop restart(s)",
        d.budget_refusals_since_start, d.restarts_total
    ));
    lines.join("\n")
}

async fn gather(state: &Arc<AppState>, window_days: u64) -> TrustReportData {
    let since =
        (chrono::Utc::now() - chrono::Duration::days(window_days.max(1) as i64)).to_rfc3339();
    let db_side = call_blocking(state.db.clone(), move |db| {
        let (task_runs, task_successes) = db.get_task_run_summary_since(Some(&since))?;
        let (contracts_verified, contracts_failed) = db.contract_verdict_counts_since(&since)?;
        let usage = db.get_llm_usage_summary_since(None, Some(&since))?;
        let egress_events = db.count_audit_events_since("egress_policy", &since)?;
        let hook_events = db.count_audit_events_since("hook", &since)?;
        let alert_events = db.count_audit_events_since("alert", &since)?;
        let recovery_events = db.count_audit_events_since("turn_recovery", &since)?;
        let delivery = db.outbound_delivery_health()?;
        let dlq_pending = db.count_scheduled_task_dlq(false)?;
        Ok::<_, microclaw_core::error::MicroClawError>((
            task_runs,
            task_successes,
            contracts_verified,
            contracts_failed,
            usage,
            (egress_events, hook_events, alert_events, recovery_events),
            delivery,
            dlq_pending,
        ))
    })
    .await;

    let mut data = TrustReportData {
        window_days,
        budget_refusals_since_start: crate::alerts::budget_refusal_count(),
        restarts_total: crate::supervision::restart_counts()
            .into_iter()
            .map(|(_, count)| count)
            .sum(),
        ..Default::default()
    };
    match db_side {
        Ok((
            task_runs,
            task_successes,
            contracts_verified,
            contracts_failed,
            usage,
            (egress_events, hook_events, alert_events, recovery_events),
            delivery,
            dlq_pending,
        )) => {
            data.task_runs = task_runs;
            data.task_successes = task_successes;
            data.contracts_verified = contracts_verified;
            data.contracts_failed = contracts_failed;
            data.llm_requests = usage.requests;
            data.tokens_total = usage.total_tokens;
            data.egress_events = egress_events;
            data.hook_events = hook_events;
            data.alert_events = alert_events;
            data.recovery_events = recovery_events;
            data.outbox_pending = delivery.pending_chunks + delivery.retry_chunks;
            data.outbox_failed = delivery.failed_chunks;
            data.dlq_pending = dlq_pending;
        }
        Err(err) => warn!("trust report: failed to gather data: {err}"),
    }
    data
}

/// True when the persisted last-sent marker is at least `interval_days` old
/// (or absent/unparseable — a fresh install reports on the first tick).
pub fn report_due(
    last_sent: Option<&str>,
    interval_days: u64,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    match last_sent.and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok()) {
        Some(sent) => {
            now.signed_duration_since(sent.with_timezone(&chrono::Utc))
                >= chrono::Duration::days(interval_days.max(1) as i64)
        }
        None => true,
    }
}

/// One cadence check: send the report to every control chat when due.
/// Returns true when a report was delivered to at least one chat.
pub async fn run_trust_report_once(state: &Arc<AppState>) -> bool {
    let cfg = &state.config.trust_report;
    let last_sent = call_blocking(state.db.clone(), |db| {
        db.get_runtime_meta(LAST_SENT_META_KEY)
    })
    .await
    .unwrap_or_default();
    if !report_due(last_sent.as_deref(), cfg.interval_days, chrono::Utc::now()) {
        return false;
    }
    let control_chats = state.config.control_chat_ids.clone();
    if control_chats.is_empty() {
        warn!("trust report: enabled but no control_chat_ids configured; skipping");
        return false;
    }
    let message = format_trust_report(&gather(state, cfg.interval_days).await);
    let mut delivered = false;
    for chat_id in control_chats {
        let channel = call_blocking(state.db.clone(), move |db| db.get_chat_channel(chat_id))
            .await
            .ok()
            .flatten()
            .unwrap_or_default();
        let bot_username = state.config.bot_username_for_channel(&channel);
        match deliver_and_store_bot_message(
            &state.channel_registry,
            state.db.clone(),
            &bot_username,
            chat_id,
            &message,
        )
        .await
        {
            Ok(_) => delivered = true,
            Err(e) => warn!("trust report: delivery failed for chat {chat_id}: {e}"),
        }
    }
    if delivered {
        let now = chrono::Utc::now().to_rfc3339();
        let _ = call_blocking(state.db.clone(), move |db| {
            db.set_runtime_meta(LAST_SENT_META_KEY, &now)
        })
        .await;
    }
    delivered
}

pub fn spawn_trust_report(state: Arc<AppState>) {
    if !state.config.trust_report.enabled {
        return;
    }
    crate::supervision::spawn_supervised("trust_report", move || {
        let state = state.clone();
        async move {
            info!(
                "trust report: loop started (every {} day(s), to {} control chat(s))",
                state.config.trust_report.interval_days.max(1),
                state.config.control_chat_ids.len()
            );
            let mut ticker = tokio::time::interval(Duration::from_secs(3600));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                run_trust_report_once(&state).await;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_due_handles_missing_and_recent_markers() {
        let now = chrono::Utc::now();
        assert!(report_due(None, 7, now));
        assert!(report_due(Some("not a timestamp"), 7, now));

        let recent = (now - chrono::Duration::days(2)).to_rfc3339();
        assert!(!report_due(Some(&recent), 7, now));

        let stale = (now - chrono::Duration::days(8)).to_rfc3339();
        assert!(report_due(Some(&stale), 7, now));
    }

    #[test]
    fn format_covers_every_section() {
        let text = format_trust_report(&TrustReportData {
            window_days: 7,
            task_runs: 12,
            task_successes: 11,
            contracts_verified: 5,
            contracts_failed: 1,
            llm_requests: 89,
            tokens_total: 1_234_567,
            egress_events: 2,
            recovery_events: 1,
            dlq_pending: 3,
            ..Default::default()
        });
        assert!(text.contains("last 7 day(s)"));
        assert!(text.contains("12 run(s), 11 succeeded"));
        assert!(text.contains("5 verified, 1 failed"));
        assert!(text.contains("1234567 across 89"));
        assert!(text.contains("egress=2"));
        assert!(text.contains("DLQ=3"));
    }
}
