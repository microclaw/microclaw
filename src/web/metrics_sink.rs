use super::*;

pub(crate) async fn metrics_http_inc(state: &WebState) {
    let mut m = state.metrics.lock().await;
    m.http_requests += 1;
}

pub(crate) async fn metrics_llm_completion_inc(state: &WebState) {
    let mut m = state.metrics.lock().await;
    m.llm_completions += 1;
}

pub(crate) const METRICS_LATENCY_SAMPLE_CAP: usize = 4096;

pub(crate) async fn metrics_record_request_result(state: &WebState, ok: bool, latency_ms: i64) {
    let mut m = state.metrics.lock().await;
    if ok {
        m.request_ok += 1;
        m.request_latency_ms.push_back(latency_ms.max(0));
        if m.request_latency_ms.len() > METRICS_LATENCY_SAMPLE_CAP {
            let _ = m.request_latency_ms.pop_front();
        }
    } else {
        m.request_error += 1;
    }
}

pub(crate) async fn metrics_apply_agent_event(state: &WebState, evt: &AgentEvent) {
    let mut m = state.metrics.lock().await;
    match evt {
        AgentEvent::ToolStart { name, .. } => {
            m.tool_executions += 1;
            if name.starts_with("mcp") {
                m.mcp_calls += 1;
            }
        }
        AgentEvent::ToolResult {
            is_error,
            error_type,
            ..
        } => {
            if *is_error {
                if matches!(
                    error_type.as_deref(),
                    Some("approval_required" | "execution_policy_blocked")
                ) {
                    m.tool_policy_blocks += 1;
                } else {
                    m.tool_error += 1;
                }
            } else {
                m.tool_success += 1;
            }
        }
        _ => {}
    }
}

pub(crate) fn percentile_p95(values: &VecDeque<i64>) -> Option<i64> {
    if values.is_empty() {
        return None;
    }
    let mut sorted: Vec<i64> = values.iter().copied().collect();
    sorted.sort_unstable();
    let idx = ((sorted.len() - 1) * 95) / 100;
    sorted.get(idx).copied()
}

pub(crate) async fn persist_metrics_snapshot(state: &WebState) -> Result<(), (StatusCode, String)> {
    let snapshot = state.metrics.lock().await.clone();
    let active_sessions = state.request_hub.active_sessions().await as i64;
    let now = chrono::Utc::now();
    let bucket_ts_ms = (now.timestamp() / 60) * 60 * 1000;
    let point = MetricsHistoryPoint {
        timestamp_ms: bucket_ts_ms,
        llm_completions: snapshot.llm_completions,
        llm_input_tokens: snapshot.llm_input_tokens,
        llm_output_tokens: snapshot.llm_output_tokens,
        http_requests: snapshot.http_requests,
        tool_executions: snapshot.tool_executions,
        mcp_calls: snapshot.mcp_calls,
        mcp_rate_limited_rejections: snapshot.mcp_rate_limited_rejections,
        mcp_bulkhead_rejections: snapshot.mcp_bulkhead_rejections,
        mcp_circuit_open_rejections: snapshot.mcp_circuit_open_rejections,
        active_sessions,
    };
    call_blocking(state.app_state.db.clone(), move |db| {
        db.upsert_metrics_history(&point)
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let retention_days = metrics_history_retention_days(&state.app_state.config);
    let cutoff = chrono::Utc::now() - chrono::Duration::days(retention_days);
    let cutoff_ms = cutoff.timestamp_millis();
    let _ = call_blocking(state.app_state.db.clone(), move |db| {
        db.cleanup_metrics_history_before(cutoff_ms).map(|_| ())
    })
    .await;

    if let Some(exporter) = state.otlp.clone() {
        let metric_snapshot = OtlpMetricSnapshot {
            timestamp_unix_nano: now.timestamp_nanos_opt().unwrap_or(0) as u64,
            http_requests: snapshot.http_requests,
            llm_completions: snapshot.llm_completions,
            llm_input_tokens: snapshot.llm_input_tokens,
            llm_output_tokens: snapshot.llm_output_tokens,
            tool_executions: snapshot.tool_executions,
            mcp_calls: snapshot.mcp_calls,
            mcp_rate_limited_rejections: snapshot.mcp_rate_limited_rejections,
            mcp_bulkhead_rejections: snapshot.mcp_bulkhead_rejections,
            mcp_circuit_open_rejections: snapshot.mcp_circuit_open_rejections,
            active_sessions,
        };
        tokio::spawn(async move {
            if let Err(e) = exporter.enqueue_metrics(metric_snapshot) {
                tracing::warn!("otlp export failed: {}", e);
            }
        });
    }
    Ok(())
}

pub(crate) fn metrics_flush_interval(config: &Config) -> Duration {
    if let Some(map) = config.channels.get("web").and_then(|v| v.as_mapping()) {
        if let Some(n) = map
            .get(serde_yaml::Value::String(
                "metrics_flush_interval_seconds".to_string(),
            ))
            .and_then(|v| v.as_u64())
        {
            return Duration::from_secs(n.clamp(1, 300));
        }
    }
    Duration::from_secs(10)
}

pub(crate) fn metrics_history_retention_days(config: &Config) -> i64 {
    if let Some(map) = config.channels.get("web").and_then(|v| v.as_mapping()) {
        if let Some(n) = map
            .get(serde_yaml::Value::String(
                "metrics_history_retention_days".to_string(),
            ))
            .and_then(|v| v.as_i64())
        {
            return n.clamp(1, 3650);
        }
    }
    30
}

pub(crate) async fn audit_log(
    state: &WebState,
    kind: &str,
    actor: &str,
    action: &str,
    target: Option<&str>,
    status: &str,
    detail: Option<&str>,
) {
    let kind = kind.to_string();
    let actor = actor.to_string();
    let action = action.to_string();
    let target = target.map(str::to_string);
    let status = status.to_string();
    let detail = detail.map(str::to_string);
    let _ = call_blocking(state.app_state.db.clone(), move |db| {
        db.log_audit_event(
            &kind,
            &actor,
            &action,
            target.as_deref(),
            &status,
            detail.as_deref(),
        )
        .map(|_| ())
    })
    .await;
}
