use super::*;
use futures_util::FutureExt;

pub(super) async fn api_send_stream(
    headers: HeaderMap,
    State(state): State<WebState>,
    Json(body): Json<SendRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    let identity = require_scope(&state, &headers, AuthScope::Write).await?;
    start_stream_run_internal(state, body, identity.actor, "/api/send_stream").await
}

pub(super) async fn start_stream_run_with_actor(
    state: WebState,
    body: SendRequest,
    actor: String,
    endpoint: &'static str,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    start_stream_run_internal(state, body, actor, endpoint).await
}

async fn start_stream_run_internal(
    state: WebState,
    body: SendRequest,
    actor: String,
    endpoint: &'static str,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let start = Instant::now();

    let text = body.message.trim().to_string();
    if text.is_empty() {
        metrics_record_request_result(&state, false, start.elapsed().as_millis() as i64).await;
        return Err((StatusCode::BAD_REQUEST, "message is required".into()));
    }

    let session_key = normalize_session_key(body.session_key.as_deref());
    if let Err((status, msg)) = state
        .request_hub
        .begin(&session_key, &actor, &state.limits)
        .await
    {
        info!(
            target: "web",
            endpoint = endpoint,
            session_key = %session_key,
            status = status.as_u16(),
            reason = %msg,
            "Request rejected by limiter"
        );
        metrics_record_request_result(&state, false, start.elapsed().as_millis() as i64).await;
        return Err((status, msg));
    }

    let run_id = uuid::Uuid::new_v4().to_string();
    state.run_hub.create(&run_id, actor.clone()).await;

    // Register with chat_abort controller for abort support
    let abort_entry =
        chat_abort::register_chat_run(run_id.clone(), session_key.clone()).await;

    let state_for_task = state.clone();
    let run_id_for_task = run_id.clone();
    let lock = state
        .session_hub
        .lock_for(&session_key, &state.limits)
        .await;
    let limits = state.limits.clone();
    let session_key_for_release = session_key.clone();
    info!(
        target: "web",
        endpoint = endpoint,
        session_key = %session_key,
        run_id = %run_id,
        latency_ms = start.elapsed().as_millis(),
        "Accepted stream run"
    );

    tokio::spawn(async move {
        let run_start = Instant::now();
        let worker = async {
            let _guard = lock.lock().await;
            state_for_task
                .run_hub
                .publish(
                    &run_id_for_task,
                    "status",
                    json!({"message": "running"}).to_string(),
                    limits.run_history_limit,
                )
                .await;

            let (evt_tx, mut evt_rx) = tokio::sync::mpsc::unbounded_channel::<AgentEvent>();
            let run_hub = state_for_task.run_hub.clone();
            let state_for_events = state_for_task.clone();
            let run_id_for_events = run_id_for_task.clone();
            let run_history_limit = limits.run_history_limit;

            // Clone for forward task (moved into async move)
            let abort_entry_for_forward = abort_entry.clone();

            // Forward AgentEvents to run_hub, buffering text deltas
            let forward = tokio::spawn(async move {
                while let Some(evt) = evt_rx.recv().await {
                    match evt {
                        AgentEvent::Iteration { iteration } => {
                            run_hub
                                .publish(
                                    &run_id_for_events,
                                    "status",
                                    json!({"message": format!("iteration {iteration}")})
                                        .to_string(),
                                    run_history_limit,
                                )
                                .await;
                        }
                        AgentEvent::ToolStart { name, .. } => {
                            super::metrics_apply_agent_event(
                                &state_for_events,
                                &AgentEvent::ToolStart {
                                    name: name.clone(),
                                    input: serde_json::Value::Null,
                                },
                            )
                            .await;
                            run_hub
                                .publish(
                                    &run_id_for_events,
                                    "tool_start",
                                    json!({"name": name}).to_string(),
                                    run_history_limit,
                                )
                                .await;
                        }
                        AgentEvent::ToolResult {
                            name,
                            is_error,
                            preview,
                            duration_ms,
                            status_code,
                            bytes,
                            error_type,
                        } => {
                            super::metrics_apply_agent_event(
                                &state_for_events,
                                &AgentEvent::ToolResult {
                                    name: name.clone(),
                                    is_error,
                                    preview: preview.clone(),
                                    duration_ms,
                                    status_code,
                                    bytes,
                                    error_type: error_type.clone(),
                                },
                            )
                            .await;
                            run_hub
                                .publish(
                                    &run_id_for_events,
                                    "tool_result",
                                    json!({
                                        "name": name,
                                        "is_error": is_error,
                                        "preview": preview,
                                        "duration_ms": duration_ms,
                                        "status_code": status_code,
                                        "bytes": bytes,
                                        "error_type": error_type
                                    })
                                    .to_string(),
                                    run_history_limit,
                                )
                                .await;
                        }
                        AgentEvent::TextDelta { delta } => {
                            // Buffer the text delta for abort
                            {
                                let mut buffer = abort_entry_for_forward.buffer.write().await;
                                buffer.push_str(&delta);
                            }
                            run_hub
                                .publish(
                                    &run_id_for_events,
                                    "delta",
                                    json!({"delta": delta}).to_string(),
                                    run_history_limit,
                                )
                                .await;
                        }
                        AgentEvent::FinalResponse { .. } => {}
                        // Cancelled is handled below after send_and_store_response_with_events.
                        AgentEvent::Cancelled { .. } => {}
                    }
                }
            });

            let abort_entry = abort_entry.clone();

            match send_and_store_response_with_events(state_for_task.clone(), body, Some(&evt_tx))
                .await
            {
                Ok(resp) => {
                    metrics_llm_completion_inc(&state_for_task).await;
                    metrics_record_request_result(
                        &state_for_task,
                        true,
                        run_start.elapsed().as_millis() as i64,
                    )
                    .await;

                    // Check if the agent was aborted via run_control interrupt.
                    // When abort_runs is called, the agent loop returns STOPPED_TEXT.
                    let response_text = resp
                        .0
                        .get("response")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string();
                    let was_aborted = response_text == crate::run_control::STOPPED_TEXT;
                    if was_aborted {
                        info!(
                            target: "web",
                            endpoint = endpoint,
                            session_key = %session_key,
                            run_id = %run_id_for_task,
                            "stream run detected abort - response was STOPPED_TEXT"
                        );
                    }

                    if was_aborted {
                        // Agent was interrupted — collect buffered text and publish
                        // "aborted" event with partial content.
                        let partial = {
                            let buf = abort_entry.buffer.read().await;
                            let t = buf.trim();
                            if t.is_empty() { None } else { Some(t.to_string()) }
                        };
                        state_for_task
                            .run_hub
                            .publish(
                                &run_id_for_task,
                                "aborted",
                                json!({ "text": partial }).to_string(),
                                limits.run_history_limit,
                            )
                            .await;
                    } else {
                        state_for_task
                            .run_hub
                            .publish(
                                &run_id_for_task,
                                "done",
                                json!({"response": response_text}).to_string(),
                                limits.run_history_limit,
                            )
                            .await;
                    }
                }
                Err((_, err_msg)) => {
                    metrics_record_request_result(
                        &state_for_task,
                        false,
                        run_start.elapsed().as_millis() as i64,
                    )
                    .await;
                    state_for_task
                        .run_hub
                        .publish(
                            &run_id_for_task,
                            "error",
                            json!({"error": err_msg}).to_string(),
                            limits.run_history_limit,
                        )
                        .await;
                }
            }
            drop(evt_tx);
            let _ = forward.await;
        };

        let panicked = std::panic::AssertUnwindSafe(worker)
            .catch_unwind()
            .await
            .is_err();
        if panicked {
            metrics_record_request_result(
                &state_for_task,
                false,
                run_start.elapsed().as_millis() as i64,
            )
            .await;
            state_for_task
                .run_hub
                .publish(
                    &run_id_for_task,
                    "error",
                    json!({"error": "internal stream task failure"}).to_string(),
                    limits.run_history_limit,
                )
                .await;
            tracing::error!(
                target: "web",
                endpoint = endpoint,
                session_key = %session_key_for_release,
                run_id = %run_id_for_task,
                "stream task panicked"
            );
        }

        state_for_task
            .request_hub
            .end_with_limits(&session_key_for_release, &actor, &limits)
            .await;
        info!(
            target: "web",
            endpoint = endpoint,
            session_key = %session_key_for_release,
            run_id = %run_id_for_task,
            panicked = panicked,
            latency_ms = run_start.elapsed().as_millis(),
            "Stream run finished"
        );

        // Unregister from abort controller
        chat_abort::unregister_chat_run(&run_id_for_task).await;

        state_for_task
            .run_hub
            .remove_later(run_id_for_task, 300)
            .await;
    });

    Ok(Json(json!({
        "ok": true,
        "run_id": run_id,
    })))
}

pub(super) async fn api_stream(
    headers: HeaderMap,
    State(state): State<WebState>,
    Query(query): Query<StreamQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    let identity = require_scope(&state, &headers, AuthScope::Read).await?;
    let start = Instant::now();

    let (mut rx, replay, done, replay_truncated, oldest_event_id) = match state
        .run_hub
        .subscribe_with_replay(
            &query.run_id,
            query.last_event_id,
            &identity.actor,
            identity.allows(AuthScope::Admin),
        )
        .await
    {
        Ok(v) => v,
        Err(RunLookupError::NotFound) => {
            return Err((StatusCode::NOT_FOUND, "run not found".into()))
        }
        Err(RunLookupError::Forbidden) => return Err((StatusCode::FORBIDDEN, "forbidden".into())),
    };
    info!(
        target: "web",
        endpoint = "/api/stream",
        run_id = %query.run_id,
        last_event_id = ?query.last_event_id,
        replay_count = replay.len(),
        replay_truncated = replay_truncated,
        oldest_event_id = ?oldest_event_id,
        latency_ms = start.elapsed().as_millis(),
        "Stream subscription established"
    );

    let stream = async_stream::stream! {
        let meta = Event::default().event("replay_meta").data(
            json!({
                "replay_truncated": replay_truncated,
                "oldest_event_id": oldest_event_id,
                "requested_last_event_id": query.last_event_id,
            })
            .to_string()
        );
        yield Ok::<Event, std::convert::Infallible>(meta);

        let mut finished = false;
        for evt in replay {
            let is_done = evt.event == "done" || evt.event == "error";
            let event = Event::default()
                .id(evt.id.to_string())
                .event(evt.event)
                .data(evt.data);
            yield Ok::<Event, std::convert::Infallible>(event);
            if is_done {
                finished = true;
                break;
            }
        }

        if finished || done {
            return;
        }

        loop {
            match rx.recv().await {
                Ok(evt) => {
                    let done = evt.event == "done" || evt.event == "error";
                    let event = Event::default()
                        .id(evt.id.to_string())
                        .event(evt.event)
                        .data(evt.data);
                    yield Ok::<Event, std::convert::Infallible>(event);
                    if done {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    continue;
                }
                Err(broadcast::error::RecvError::Closed) => {
                    break;
                }
            }
        }
    };

    Ok(Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(std::time::Duration::from_secs(15))
            .text("keepalive"),
    ))
}

pub(super) async fn api_run_status(
    headers: HeaderMap,
    State(state): State<WebState>,
    Query(query): Query<RunStatusQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    let identity = require_scope(&state, &headers, AuthScope::Read).await?;
    let (done, last_event_id) = match state
        .run_hub
        .status(
            &query.run_id,
            &identity.actor,
            identity.allows(AuthScope::Admin),
        )
        .await
    {
        Ok(v) => v,
        Err(RunLookupError::NotFound) => {
            return Err((StatusCode::NOT_FOUND, "run not found".into()))
        }
        Err(RunLookupError::Forbidden) => return Err((StatusCode::FORBIDDEN, "forbidden".into())),
    };
    Ok(Json(json!({
        "ok": true,
        "run_id": query.run_id,
        "done": done,
        "last_event_id": last_event_id,
    })))
}
