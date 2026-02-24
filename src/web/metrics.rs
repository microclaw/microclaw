use super::*;

pub(super) async fn api_metrics(
    headers: HeaderMap,
    State(state): State<WebState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    require_scope(&state, &headers, AuthScope::Read).await?;
    persist_metrics_snapshot(&state).await?;

    let snapshot = state.metrics.lock().await.clone();
    let active_sessions = state.request_hub.active_sessions().await as i64;
    Ok(Json(json!({
        "ok": true,
        "metrics": {
            "http_requests": snapshot.http_requests,
            "request_ok": snapshot.request_ok,
            "request_error": snapshot.request_error,
            "llm_completions": snapshot.llm_completions,
            "llm_input_tokens": snapshot.llm_input_tokens,
            "llm_output_tokens": snapshot.llm_output_tokens,
            "tool_executions": snapshot.tool_executions,
            "tool_success": snapshot.tool_success,
            "tool_error": snapshot.tool_error,
            "tool_policy_blocks": snapshot.tool_policy_blocks,
            "mcp_calls": snapshot.mcp_calls,
            "mcp_rate_limited_rejections": snapshot.mcp_rate_limited_rejections,
            "mcp_bulkhead_rejections": snapshot.mcp_bulkhead_rejections,
            "mcp_circuit_open_rejections": snapshot.mcp_circuit_open_rejections,
            "active_sessions": active_sessions
        }
    })))
}

pub(super) async fn api_metrics_summary(
    headers: HeaderMap,
    State(state): State<WebState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    require_scope(&state, &headers, AuthScope::Read).await?;
    persist_metrics_snapshot(&state).await?;

    let snapshot = state.metrics.lock().await.clone();
    let active_sessions = state.request_hub.active_sessions().await as i64;
    let request_total = snapshot.request_ok + snapshot.request_error;
    let request_success_rate = if request_total > 0 {
        (snapshot.request_ok as f64) / (request_total as f64)
    } else {
        1.0
    };
    let request_latency_p95_ms = percentile_p95(&snapshot.request_latency_ms).unwrap_or(0);
    let tool_total_for_reliability = snapshot.tool_success + snapshot.tool_error;
    let tool_reliability = if tool_total_for_reliability > 0 {
        (snapshot.tool_success as f64) / (tool_total_for_reliability as f64)
    } else {
        1.0
    };

    let since_7d = (chrono::Utc::now() - chrono::Duration::days(7)).to_rfc3339();
    let (scheduler_runs_7d, scheduler_success_7d) =
        call_blocking(state.app_state.db.clone(), move |db| {
            db.get_task_run_summary_since(Some(&since_7d))
        })
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let scheduler_recoverability = if scheduler_runs_7d > 0 {
        (scheduler_success_7d as f64) / (scheduler_runs_7d as f64)
    } else {
        1.0
    };
    let mcp_rejections_total = snapshot.mcp_rate_limited_rejections
        + snapshot.mcp_bulkhead_rejections
        + snapshot.mcp_circuit_open_rejections;
    let mcp_rejection_ratio = if snapshot.mcp_calls > 0 {
        mcp_rejections_total as f64 / snapshot.mcp_calls as f64
    } else {
        0.0
    };

    Ok(Json(json!({
        "ok": true,
        "window": "runtime_process",
        "slo": {
            "request_success_rate": {
                "value": request_success_rate,
                "target": 0.995,
                "burn_alert": 0.99,
                "sample_size": request_total
            },
            "e2e_latency_p95_ms": {
                "value": request_latency_p95_ms,
                "target": 6000,
                "burn_alert": 10000,
                "sample_size": snapshot.request_latency_ms.len()
            },
            "tool_reliability": {
                "value": tool_reliability,
                "target": 0.985,
                "burn_alert": 0.97,
                "success": snapshot.tool_success,
                "error": snapshot.tool_error,
                "policy_block_excluded": snapshot.tool_policy_blocks
            },
            "scheduler_recoverability_7d": {
                "value": scheduler_recoverability,
                "target": 1.0,
                "burn_alert": 0.999,
                "runs_7d": scheduler_runs_7d,
                "success_7d": scheduler_success_7d
            }
        },
        "metrics": {
            "http_requests": snapshot.http_requests,
            "request_ok": snapshot.request_ok,
            "request_error": snapshot.request_error,
            "llm_completions": snapshot.llm_completions,
            "llm_input_tokens": snapshot.llm_input_tokens,
            "llm_output_tokens": snapshot.llm_output_tokens,
            "tool_executions": snapshot.tool_executions,
            "tool_success": snapshot.tool_success,
            "tool_error": snapshot.tool_error,
            "tool_policy_blocks": snapshot.tool_policy_blocks,
            "mcp_calls": snapshot.mcp_calls,
            "mcp_rate_limited_rejections": snapshot.mcp_rate_limited_rejections,
            "mcp_bulkhead_rejections": snapshot.mcp_bulkhead_rejections,
            "mcp_circuit_open_rejections": snapshot.mcp_circuit_open_rejections,
            "active_sessions": active_sessions
        },
        "summary": {
            "mcp_rejections_total": mcp_rejections_total,
            "mcp_rejection_ratio": mcp_rejection_ratio
        }
    })))
}

pub(super) async fn api_metrics_history(
    headers: HeaderMap,
    State(state): State<WebState>,
    Query(query): Query<MetricsHistoryQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    require_scope(&state, &headers, AuthScope::Read).await?;
    persist_metrics_snapshot(&state).await?;

    let minutes = query.minutes.unwrap_or(24 * 60).clamp(1, 24 * 60 * 30);
    let limit = query.limit.unwrap_or(2000).clamp(1, 20000);
    let since = (chrono::Utc::now() - chrono::Duration::minutes(minutes)).timestamp_millis();
    let rows = call_blocking(state.app_state.db.clone(), move |db| {
        db.get_metrics_history(since, limit)
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({
        "ok": true,
        "minutes": minutes,
        "points": rows.into_iter().map(|r| json!({
            "timestamp_ms": r.timestamp_ms,
            "llm_completions": r.llm_completions,
            "llm_input_tokens": r.llm_input_tokens,
            "llm_output_tokens": r.llm_output_tokens,
            "http_requests": r.http_requests,
            "tool_executions": r.tool_executions,
            "mcp_calls": r.mcp_calls,
            "mcp_rate_limited_rejections": r.mcp_rate_limited_rejections,
            "mcp_bulkhead_rejections": r.mcp_bulkhead_rejections,
            "mcp_circuit_open_rejections": r.mcp_circuit_open_rejections,
            "active_sessions": r.active_sessions
        })).collect::<Vec<_>>()
    })))
}
