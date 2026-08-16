use super::*;

pub(crate) async fn api_health(
    headers: HeaderMap,
    State(state): State<WebState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    let authenticated = require_scope(&state, &headers, AuthScope::Read)
        .await
        .is_ok();
    let basic = json!({
        "ok": true,
        "version": env!("CARGO_PKG_VERSION"),
        "web_enabled": state.app_state.config.web_enabled,
    });
    if !authenticated {
        return Ok(Json(basic));
    }
    let since_24h = (chrono::Utc::now() - chrono::Duration::hours(24)).to_rfc3339();
    let task_summary_24h = call_blocking(state.app_state.db.clone(), move |db| {
        db.get_task_run_summary_since(Some(&since_24h))
    })
    .await
    .ok();
    let reflector_summary = call_blocking(state.app_state.db.clone(), move |db| {
        db.get_memory_observability_summary(None)
    })
    .await
    .ok();

    let (task_runs_24h, task_success_24h) = task_summary_24h.unwrap_or((0, 0));
    let task_failed_24h = (task_runs_24h - task_success_24h).max(0);
    let reflector_runs_24h = reflector_summary
        .as_ref()
        .map(|s| s.reflector_runs_24h)
        .unwrap_or(0);
    let reflector_inserted_24h = reflector_summary
        .as_ref()
        .map(|s| s.reflector_inserted_24h)
        .unwrap_or(0);
    let reflector_updated_24h = reflector_summary
        .as_ref()
        .map(|s| s.reflector_updated_24h)
        .unwrap_or(0);
    let reflector_skipped_24h = reflector_summary
        .as_ref()
        .map(|s| s.reflector_skipped_24h)
        .unwrap_or(0);
    let memory_backend_health = state.app_state.memory_backend.provider_health_snapshot();

    Ok(Json(json!({
        "ok": true,
        "version": env!("CARGO_PKG_VERSION"),
        "web_enabled": state.app_state.config.web_enabled,
        "scheduler": {
            "task_runs_24h": task_runs_24h,
            "task_success_24h": task_success_24h,
            "task_failed_24h": task_failed_24h
        },
        "reflector": {
            "enabled": state.app_state.config.reflector_enabled,
            "interval_mins": state.app_state.config.reflector_interval_mins,
            "runs_24h": reflector_runs_24h,
            "inserted_24h": reflector_inserted_24h,
            "updated_24h": reflector_updated_24h,
            "skipped_24h": reflector_skipped_24h
        },
        "memory_backend": {
            "external_provider_enabled": memory_backend_health.external_provider_enabled,
            "primary_provider_name": memory_backend_health.primary_provider_name,
            "startup_probe_ok": memory_backend_health.startup_probe_ok,
            "startup_probe_message": memory_backend_health.startup_probe_message,
            "consecutive_primary_failures": memory_backend_health.consecutive_primary_failures,
            "total_fallbacks": memory_backend_health.total_fallbacks,
            "last_primary_success_ts": memory_backend_health.last_primary_success_ts,
            "last_primary_failure_ts": memory_backend_health.last_primary_failure_ts,
            "last_fallback_reason": memory_backend_health.last_fallback_reason,
            "reflector_paused": state.app_state.memory_backend.should_pause_reflector_writes()
        }
    })))
}

pub(crate) async fn api_health_root(State(state): State<WebState>) -> Json<serde_json::Value> {
    metrics_http_inc(&state).await;
    Json(json!({
        "ok": true,
        "version": env!("CARGO_PKG_VERSION"),
        "web_enabled": state.app_state.config.web_enabled,
    }))
}

pub(crate) async fn api_usage(
    headers: HeaderMap,
    State(state): State<WebState>,
    Query(query): Query<UsageQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    require_scope(&state, &headers, AuthScope::Read).await?;

    let session_key = normalize_session_key(query.session_key.as_deref());
    let chat_id = resolve_chat_id_for_session_key_read(&state, &session_key).await?;
    let report = build_usage_report(state.app_state.db.clone(), chat_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let memory_observability = call_blocking(state.app_state.db.clone(), move |db| {
        db.get_memory_observability_summary(Some(chat_id))
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(json!({
        "ok": true,
        "session_key": session_key,
        "chat_id": chat_id,
        "report": report,
        "memory_observability": {
            "total": memory_observability.total,
            "active": memory_observability.active,
            "archived": memory_observability.archived,
            "low_confidence": memory_observability.low_confidence,
            "avg_confidence": memory_observability.avg_confidence,
            "reflector_runs_24h": memory_observability.reflector_runs_24h,
            "reflector_inserted_24h": memory_observability.reflector_inserted_24h,
            "reflector_updated_24h": memory_observability.reflector_updated_24h,
            "reflector_skipped_24h": memory_observability.reflector_skipped_24h,
            "injection_events_24h": memory_observability.injection_events_24h,
            "injection_selected_24h": memory_observability.injection_selected_24h,
            "injection_candidates_24h": memory_observability.injection_candidates_24h,
        },
    })))
}

pub(crate) async fn api_memory_observability(
    headers: HeaderMap,
    State(state): State<WebState>,
    Query(query): Query<MemoryObservabilityQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    require_scope(&state, &headers, AuthScope::Read).await?;

    let scope = query
        .scope
        .as_deref()
        .unwrap_or("chat")
        .trim()
        .to_ascii_lowercase();
    let hours = query.hours.unwrap_or(24).clamp(1, 24 * 30);
    let limit = query.limit.unwrap_or(200).clamp(1, 2000);
    let offset = query.offset.unwrap_or(0);
    let since = (chrono::Utc::now() - chrono::Duration::hours(hours as i64)).to_rfc3339();

    let chat_id_filter = if scope == "global" {
        None
    } else {
        let session_key = normalize_session_key(query.session_key.as_deref());
        Some(resolve_chat_id_for_session_key_read(&state, &session_key).await?)
    };

    let summary = call_blocking(state.app_state.db.clone(), move |db| {
        db.get_memory_observability_summary(chat_id_filter)
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let since_for_reflector = since.clone();
    let reflector_runs = call_blocking(state.app_state.db.clone(), {
        move |db| {
            db.get_memory_reflector_runs(chat_id_filter, Some(&since_for_reflector), limit, offset)
        }
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let since_for_injection = since.clone();
    let injection_logs = call_blocking(state.app_state.db.clone(), move |db| {
        db.get_memory_injection_logs(chat_id_filter, Some(&since_for_injection), limit, offset)
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(json!({
        "ok": true,
        "scope": if scope == "global" { "global" } else { "chat" },
        "window_hours": hours,
        "pagination": {
            "limit": limit,
            "offset": offset
        },
        "summary": {
            "total": summary.total,
            "active": summary.active,
            "archived": summary.archived,
            "low_confidence": summary.low_confidence,
            "avg_confidence": summary.avg_confidence,
            "reflector_runs_24h": summary.reflector_runs_24h,
            "reflector_inserted_24h": summary.reflector_inserted_24h,
            "reflector_updated_24h": summary.reflector_updated_24h,
            "reflector_skipped_24h": summary.reflector_skipped_24h,
            "injection_events_24h": summary.injection_events_24h,
            "injection_selected_24h": summary.injection_selected_24h,
            "injection_candidates_24h": summary.injection_candidates_24h
        },
        "reflector_runs": reflector_runs.iter().map(|r| json!({
            "id": r.id,
            "chat_id": r.chat_id,
            "started_at": r.started_at,
            "finished_at": r.finished_at,
            "extracted_count": r.extracted_count,
            "inserted_count": r.inserted_count,
            "updated_count": r.updated_count,
            "skipped_count": r.skipped_count,
            "dedup_method": r.dedup_method,
            "parse_ok": r.parse_ok,
            "error_text": r.error_text,
        })).collect::<Vec<_>>(),
        "injection_logs": injection_logs.iter().map(|r| json!({
            "id": r.id,
            "chat_id": r.chat_id,
            "created_at": r.created_at,
            "retrieval_method": r.retrieval_method,
            "candidate_count": r.candidate_count,
            "selected_count": r.selected_count,
            "omitted_count": r.omitted_count,
            "tokens_est": r.tokens_est
        })).collect::<Vec<_>>(),
    })))
}

pub(crate) async fn api_audit_logs(
    headers: HeaderMap,
    State(state): State<WebState>,
    Query(query): Query<AuditQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    require_scope(&state, &headers, AuthScope::Admin).await?;
    let limit = query.limit.unwrap_or(200).clamp(1, 2000);
    let kind = query.kind.map(|k| k.trim().to_string());
    let rows = call_blocking(state.app_state.db.clone(), move |db| {
        db.list_audit_logs(kind.as_deref(), limit)
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let logs = rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.id,
                "kind": r.kind,
                "actor": r.actor,
                "action": r.action,
                "target": r.target,
                "status": r.status,
                "detail": r.detail,
                "created_at": r.created_at
            })
        })
        .collect::<Vec<_>>();
    Ok(Json(json!({"ok": true, "logs": logs})))
}
