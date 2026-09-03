//! Opt-in operational webhook alerts.
//!
//! A supervised loop polls runtime health every `alerts.interval_secs` and
//! POSTs a JSON alert to the configured webhook when a condition trips:
//! scheduler DLQ growth, provider down, token-budget exhaustion, or a
//! supervised-loop restart storm. Threshold/dedupe decisions live in pure
//! functions over snapshots so they are testable without a runtime; every
//! delivery attempt is recorded in the tamper-evident audit chain
//! (`kind = "alert"`).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::json;
use tracing::{info, warn};

use crate::config::AlertsConfig;
use crate::runtime::AppState;
use microclaw_storage::db::call_blocking;

/// Turns refused because a chat exhausted its token budget, since process
/// start. Recorded by the agent engine at the single enforcement point.
static BUDGET_REFUSALS: AtomicU64 = AtomicU64::new(0);

pub fn note_budget_refusal() {
    BUDGET_REFUSALS.fetch_add(1, Ordering::Relaxed);
}

pub fn budget_refusal_count() -> u64 {
    BUDGET_REFUSALS.load(Ordering::Relaxed)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alert {
    pub class: &'static str,
    pub message: String,
}

/// One poll's worth of health numbers, gathered from the shared sources.
#[derive(Debug, Clone, Default)]
pub struct HealthSample {
    pub dlq_pending: i64,
    pub restarts_total: u64,
    pub budget_refusals: u64,
    pub provider_consecutive_failures: u64,
    pub provider_breaker_open: bool,
}

/// Mutable state carried between polls: the previous sample (deltas) and
/// per-class last-sent times (cooldown).
#[derive(Default)]
pub struct AlertLoopState {
    prev: Option<HealthSample>,
    last_sent: HashMap<&'static str, Instant>,
}

/// Consecutive provider failures that count as "provider down". Matches the
/// circuit-breaker threshold in `llm.rs`.
const PROVIDER_DOWN_FAILURES: u64 = 4;

/// Pure alert policy: compare the current sample against the previous one
/// and the per-class cooldowns. The first poll only establishes a baseline.
pub fn evaluate_alerts(
    loop_state: &mut AlertLoopState,
    sample: &HealthSample,
    cfg: &AlertsConfig,
    now: Instant,
) -> Vec<Alert> {
    let Some(prev) = loop_state.prev.replace(sample.clone()) else {
        return Vec::new();
    };

    let mut candidates = Vec::new();
    if sample.dlq_pending > prev.dlq_pending {
        candidates.push(Alert {
            class: "dlq_growth",
            message: format!(
                "Scheduler dead-letter queue grew from {} to {} unreplayed entries.",
                prev.dlq_pending, sample.dlq_pending
            ),
        });
    }
    if sample.provider_breaker_open
        || sample.provider_consecutive_failures >= PROVIDER_DOWN_FAILURES
    {
        candidates.push(Alert {
            class: "provider_down",
            message: format!(
                "LLM provider is failing: {} consecutive failure(s){}.",
                sample.provider_consecutive_failures,
                if sample.provider_breaker_open {
                    ", circuit breaker open"
                } else {
                    ""
                }
            ),
        });
    }
    if sample.budget_refusals > prev.budget_refusals {
        candidates.push(Alert {
            class: "budget_exhaustion",
            message: format!(
                "{} turn(s) refused since the last poll because a chat's daily token budget \
                 is exhausted.",
                sample.budget_refusals - prev.budget_refusals
            ),
        });
    }
    let restart_delta = sample.restarts_total.saturating_sub(prev.restarts_total);
    if cfg.restart_storm_threshold > 0 && restart_delta >= cfg.restart_storm_threshold {
        candidates.push(Alert {
            class: "restart_storm",
            message: format!(
                "{restart_delta} supervised-loop restart(s) within one poll interval."
            ),
        });
    }

    let cooldown = Duration::from_secs(cfg.cooldown_secs);
    // Filter by cooldown only — do NOT record last_sent here. The caller
    // records it after a successful delivery, so a failed webhook POST does
    // not start the cooldown and silently drop the alert.
    candidates
        .into_iter()
        .filter(|alert| match loop_state.last_sent.get(alert.class) {
            Some(sent) => now.duration_since(*sent) >= cooldown,
            None => true,
        })
        .collect()
}

impl AlertLoopState {
    /// Record that an alert class was successfully delivered at `now`,
    /// starting its cooldown window.
    fn mark_sent(&mut self, class: &'static str, now: Instant) {
        self.last_sent.insert(class, now);
    }
}

async fn gather_sample(state: &Arc<AppState>) -> HealthSample {
    let dlq_pending = call_blocking(state.db.clone(), |db| db.count_scheduled_task_dlq(false))
        .await
        .unwrap_or_else(|err| {
            warn!("alerts: failed to count scheduler DLQ: {err}");
            0
        });
    let restarts_total = crate::supervision::restart_counts()
        .into_iter()
        .map(|(_, count)| count)
        .sum();
    let provider = crate::llm::provider_failover_snapshot();
    HealthSample {
        dlq_pending,
        restarts_total,
        budget_refusals: budget_refusal_count(),
        provider_consecutive_failures: provider.consecutive_failures,
        provider_breaker_open: provider.breaker_open,
    }
}

/// Deliver one alert; returns true when the webhook accepted it. Every
/// attempt (success or failure) is recorded in the audit chain.
async fn deliver_alert(
    state: &Arc<AppState>,
    client: &reqwest::Client,
    url: &str,
    alert: &Alert,
) -> bool {
    let body = json!({
        "source": "microclaw",
        "class": alert.class,
        "message": alert.message,
        "generated_at": chrono::Utc::now().to_rfc3339(),
    });
    let outcome = match client
        .post(url)
        .json(&body)
        .timeout(Duration::from_secs(10))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => Ok(()),
        Ok(resp) => Err(format!("webhook returned HTTP {}", resp.status())),
        Err(err) => Err(format!("webhook POST failed: {err}")),
    };
    let (status, detail) = match &outcome {
        Ok(()) => ("sent", alert.message.clone()),
        Err(err) => {
            warn!("alerts: {err} (class {})", alert.class);
            ("error", format!("{}: {err}", alert.message))
        }
    };
    let class = alert.class;
    let status = status.to_string();
    let _ = call_blocking(state.db.clone(), move |db| {
        db.log_audit_event("alert", "alerts_loop", class, None, &status, Some(&detail))
    })
    .await;
    outcome.is_ok()
}

/// One poll: gather, evaluate, deliver. Extracted from the loop for
/// testability; returns how many alerts were delivered (or attempted).
pub async fn run_alerts_once(
    state: &Arc<AppState>,
    loop_state: &mut AlertLoopState,
    client: &reqwest::Client,
) -> usize {
    let cfg = &state.config.alerts;
    let sample = gather_sample(state).await;
    let now = Instant::now();
    let alerts = evaluate_alerts(loop_state, &sample, cfg, now);
    let mut delivered = 0usize;
    for alert in &alerts {
        // Start the cooldown only on a successful delivery: a webhook that
        // is briefly down must not suppress the alert for a full cooldown.
        if deliver_alert(state, client, &cfg.webhook_url, alert).await {
            loop_state.mark_sent(alert.class, now);
            delivered += 1;
        }
    }
    delivered
}

/// Spawn the supervised alerts loop; a no-op unless alerts are enabled
/// with a webhook configured.
pub fn spawn_alerts(state: Arc<AppState>) {
    let cfg = state.config.alerts.clone();
    if !cfg.enabled || cfg.webhook_url.trim().is_empty() {
        info!("alerts: disabled (alerts.enabled=false or no webhook_url)");
        return;
    }
    crate::supervision::spawn_supervised("alerts", move || {
        let state = state.clone();
        let interval_secs = cfg.interval_secs.max(10);
        async move {
            let client = reqwest::Client::builder()
                .user_agent(format!(
                    "{}/alerts",
                    crate::http_client::default_llm_user_agent()
                ))
                .redirect(microclaw_tools::url_safety::ssrf_redirect_policy(3))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new());
            let mut loop_state = AlertLoopState::default();
            let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            info!("alerts: loop started (every {interval_secs}s)");
            loop {
                ticker.tick().await;
                run_alerts_once(&state, &mut loop_state, &client).await;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> AlertsConfig {
        AlertsConfig {
            enabled: true,
            webhook_url: "https://alerts.example.com/hook".into(),
            interval_secs: 60,
            cooldown_secs: 900,
            restart_storm_threshold: 5,
        }
    }

    #[test]
    fn first_poll_is_baseline_only() {
        let mut state = AlertLoopState::default();
        let sample = HealthSample {
            dlq_pending: 10,
            provider_breaker_open: true,
            ..Default::default()
        };
        assert!(evaluate_alerts(&mut state, &sample, &cfg(), Instant::now()).is_empty());
    }

    #[test]
    fn dlq_growth_and_budget_delta_alert_once_within_cooldown() {
        let mut state = AlertLoopState::default();
        let now = Instant::now();
        let base = HealthSample::default();
        evaluate_alerts(&mut state, &base, &cfg(), now);

        let grown = HealthSample {
            dlq_pending: 3,
            budget_refusals: 2,
            ..Default::default()
        };
        let alerts = evaluate_alerts(&mut state, &grown, &cfg(), now);
        let classes: Vec<_> = alerts.iter().map(|a| a.class).collect();
        assert_eq!(classes, vec!["dlq_growth", "budget_exhaustion"]);
        // Simulate successful delivery starting the cooldown.
        for a in &alerts {
            state.mark_sent(a.class, now);
        }

        // Still growing, but inside the cooldown window → suppressed.
        let grown_again = HealthSample {
            dlq_pending: 5,
            budget_refusals: 4,
            ..Default::default()
        };
        assert!(evaluate_alerts(&mut state, &grown_again, &cfg(), now).is_empty());
    }

    #[test]
    fn unmarked_alert_is_not_suppressed_next_poll() {
        // Models a failed delivery: evaluate returns the alert but the caller
        // never calls mark_sent, so the next poll re-offers it.
        let mut state = AlertLoopState::default();
        let now = Instant::now();
        evaluate_alerts(&mut state, &HealthSample::default(), &cfg(), now);

        let grown = HealthSample {
            dlq_pending: 2,
            ..Default::default()
        };
        assert_eq!(evaluate_alerts(&mut state, &grown, &cfg(), now).len(), 1);
        // Delivery "failed" → no mark_sent. Growth continues; still offered.
        let grown_more = HealthSample {
            dlq_pending: 3,
            ..Default::default()
        };
        assert_eq!(
            evaluate_alerts(&mut state, &grown_more, &cfg(), now).len(),
            1
        );
    }

    #[test]
    fn provider_down_requires_breaker_or_threshold() {
        let mut state = AlertLoopState::default();
        let now = Instant::now();
        evaluate_alerts(&mut state, &HealthSample::default(), &cfg(), now);

        let flaky = HealthSample {
            provider_consecutive_failures: 2,
            ..Default::default()
        };
        assert!(evaluate_alerts(&mut state, &flaky, &cfg(), now).is_empty());

        let down = HealthSample {
            provider_consecutive_failures: PROVIDER_DOWN_FAILURES,
            ..Default::default()
        };
        let alerts = evaluate_alerts(&mut state, &down, &cfg(), now);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].class, "provider_down");
    }

    #[test]
    fn restart_storm_uses_delta_and_threshold() {
        let mut state = AlertLoopState::default();
        let now = Instant::now();
        evaluate_alerts(
            &mut state,
            &HealthSample {
                restarts_total: 100,
                ..Default::default()
            },
            &cfg(),
            now,
        );

        let calm = HealthSample {
            restarts_total: 103,
            ..Default::default()
        };
        assert!(evaluate_alerts(&mut state, &calm, &cfg(), now).is_empty());

        let storm = HealthSample {
            restarts_total: 109,
            ..Default::default()
        };
        let alerts = evaluate_alerts(&mut state, &storm, &cfg(), now);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].class, "restart_storm");
    }
}
