use super::*;

pub(crate) fn normalize_session_key(session_key: Option<&str>) -> String {
    let key = session_key.unwrap_or("main").trim();
    if key.is_empty() {
        "main".into()
    } else {
        key.into()
    }
}

pub(crate) fn map_chat_to_session(registry: &ChannelRegistry, chat: ChatSummary) -> SessionItem {
    let source = session_source_for_chat(registry, &chat.chat_type, chat.chat_title.as_deref());

    let fallback = format!("{}:{}", source, chat.chat_id);
    let mut label = chat
        .session_label
        .clone()
        .or_else(|| chat.chat_title.clone())
        .unwrap_or_else(|| fallback.clone());

    if label.starts_with("private:")
        || label.starts_with("group:")
        || label.starts_with("supergroup:")
        || label.starts_with("channel:")
    {
        label = fallback.clone();
    }

    let session_key = if source == "web" {
        chat.chat_title
            .as_deref()
            .map(|t| normalize_session_key(Some(t)))
            .unwrap_or_else(|| format!("chat:{}", chat.chat_id))
    } else {
        format!("chat:{}", chat.chat_id)
    };

    SessionItem {
        session_key,
        label,
        chat_id: chat.chat_id,
        chat_type: source,
        last_message_time: chat.last_message_time,
        last_message_preview: chat.last_message_preview,
    }
}

pub(crate) fn parse_chat_id_from_session_key(session_key: &str) -> Option<i64> {
    session_key
        .strip_prefix("chat:")
        .and_then(|s| s.parse::<i64>().ok())
}

pub(crate) fn web_channel_value<'a>(cfg: &'a Config, key: &str) -> Option<&'a serde_yaml::Value> {
    cfg.channels
        .get("web")
        .and_then(|v| v.as_mapping())
        .and_then(|m| m.get(serde_yaml::Value::String(key.to_string())))
}

pub(crate) fn web_channel_string(cfg: &Config, key: &str) -> Option<String> {
    web_channel_value(cfg, key)
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

pub(crate) fn web_channel_bool(cfg: &Config, key: &str, default: bool) -> bool {
    web_channel_value(cfg, key)
        .and_then(|v| v.as_bool())
        .unwrap_or(default)
}

pub(crate) fn web_channel_string_list(cfg: &Config, key: &str) -> Vec<String> {
    web_channel_value(cfg, key)
        .and_then(|v| v.as_sequence())
        .map(|seq| {
            seq.iter()
                .filter_map(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

pub(crate) async fn ensure_web_writable_chat(
    state: &WebState,
    parsed_chat_id: Option<i64>,
) -> Result<(), (StatusCode, String)> {
    if let Some(explicit_chat_id) = parsed_chat_id {
        let is_web = get_chat_routing(
            &state.app_state.channel_registry,
            state.app_state.db.clone(),
            explicit_chat_id,
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?
        .map(|r| r.channel_name == "web")
        .unwrap_or(false);
        if !is_web {
            return Err((
                StatusCode::BAD_REQUEST,
                "this channel is read-only in Web UI; use source channel to send".into(),
            ));
        }
    }
    Ok(())
}

pub(crate) async fn resolve_chat_id_for_session_key_read(
    state: &WebState,
    session_key: &str,
) -> Result<i64, (StatusCode, String)> {
    if let Some(parsed) = parse_chat_id_from_session_key(session_key) {
        let exists = call_blocking(state.app_state.db.clone(), move |db| {
            db.get_chat_type(parsed)
        })
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .is_some();
        if exists {
            return Ok(parsed);
        }
        return Err((StatusCode::NOT_FOUND, "session not found".into()));
    }

    let key = session_key.to_string();
    let by_title = call_blocking(state.app_state.db.clone(), move |db| {
        db.get_chat_id_by_channel_and_title("web", &key)
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if let Some(cid) = by_title {
        return Ok(cid);
    }

    Err((StatusCode::NOT_FOUND, "session not found".into()))
}

pub(crate) async fn resolve_chat_id_for_session_key(
    state: &WebState,
    session_key: &str,
) -> Result<i64, (StatusCode, String)> {
    if let Some(parsed) = parse_chat_id_from_session_key(session_key) {
        return Ok(parsed);
    }

    let key = session_key.to_string();
    let by_title = call_blocking(state.app_state.db.clone(), move |db| {
        db.get_chat_id_by_channel_and_title("web", &key)
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if let Some(cid) = by_title {
        return Ok(cid);
    }

    let key = session_key.to_string();
    call_blocking(state.app_state.db.clone(), move |db| {
        db.resolve_or_create_chat_id("web", &key, Some(&key), "web")
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

pub(crate) async fn api_send(
    headers: HeaderMap,
    State(state): State<WebState>,
    Json(body): Json<SendRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    let identity = require_scope(&state, &headers, AuthScope::Write).await?;
    let start = Instant::now();
    let session_key = normalize_session_key(body.session_key.as_deref());
    if let Err((status, msg)) = state
        .request_hub
        .begin(&session_key, &identity.actor, &state.limits)
        .await
    {
        info!(
            target: "web",
            endpoint = "/api/send",
            session_key = %session_key,
            status = status.as_u16(),
            reason = %msg,
            "Request rejected by limiter"
        );
        metrics_record_request_result(&state, false, start.elapsed().as_millis() as i64).await;
        return Err((status, msg));
    }
    let result = send_and_store_response(state.clone(), body).await;
    if result.is_ok() {
        metrics_llm_completion_inc(&state).await;
    }
    metrics_record_request_result(&state, result.is_ok(), start.elapsed().as_millis() as i64).await;
    state
        .request_hub
        .end_with_limits(&session_key, &identity.actor, &state.limits)
        .await;
    info!(
        target: "web",
        endpoint = "/api/send",
        session_key = %session_key,
        ok = result.is_ok(),
        latency_ms = start.elapsed().as_millis(),
        "Completed request"
    );
    result
}

pub(crate) async fn send_and_store_response(
    state: WebState,
    body: SendRequest,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let session_key = normalize_session_key(body.session_key.as_deref());
    let lock = state
        .session_hub
        .lock_for(&session_key, &state.limits)
        .await;
    let _guard = lock.lock().await;
    send_and_store_response_with_events(state, body, None).await
}

pub(crate) async fn send_and_store_response_with_events(
    state: WebState,
    body: SendRequest,
    event_tx: Option<&tokio::sync::mpsc::UnboundedSender<AgentEvent>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let text = body.message.trim().to_string();
    if text.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "message is required".into()));
    }

    let session_key = normalize_session_key(body.session_key.as_deref());
    let parsed_chat_id = parse_chat_id_from_session_key(&session_key);
    let chat_id = if let Some(explicit_chat_id) = parsed_chat_id {
        explicit_chat_id
    } else {
        let session_key_for_lookup = session_key.clone();
        call_blocking(state.app_state.db.clone(), move |db| {
            db.resolve_or_create_chat_id(
                "web",
                &session_key_for_lookup,
                Some(&session_key_for_lookup),
                "web",
            )
        })
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    };
    let sender_name = body
        .sender_name
        .as_deref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("web-user")
        .to_string();

    let before_usage = call_blocking(state.app_state.db.clone(), move |db| {
        db.get_llm_usage_summary(Some(chat_id))
    })
    .await
    .ok();

    ensure_web_writable_chat(&state, parsed_chat_id).await?;

    if let Some(command_reply) =
        handle_chat_command(&state.app_state, chat_id, "web", &text, None).await
    {
        if let Some(tx) = event_tx {
            let _ = tx.send(AgentEvent::FinalResponse {
                text: command_reply.clone(),
            });
        }
        let bot_username = state.app_state.config.bot_username_for_channel("web");
        deliver_and_store_bot_message(
            &state.app_state.channel_registry,
            state.app_state.db.clone(),
            &bot_username,
            chat_id,
            &command_reply,
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
        return Ok(Json(json!({
            "ok": true,
            "session_key": session_key,
            "chat_id": chat_id,
            "response": command_reply,
        })));
    }

    let user_msg = StoredMessage {
        id: uuid::Uuid::new_v4().to_string(),
        chat_id,
        sender_name: sender_name.clone(),
        content: text,
        is_from_bot: false,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };
    call_blocking(state.app_state.db.clone(), move |db| {
        db.store_message(&user_msg)
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let request_ctx = AgentRequestContext {
        caller_channel: "web",
        chat_id,
        chat_type: "web",
    };
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<AgentEvent>();
    let saw_send_message_tool = Arc::new(AtomicBool::new(false));
    let saw_send_message_tool_forward = saw_send_message_tool.clone();
    let state_for_events = state.clone();
    let upstream_event_tx = event_tx.cloned();
    let forward_task = tokio::spawn(async move {
        while let Some(evt) = rx.recv().await {
            if matches!(&evt, AgentEvent::ToolStart { name, .. } if name == "send_message") {
                saw_send_message_tool_forward.store(true, Ordering::SeqCst);
            }
            if let Some(tx) = &upstream_event_tx {
                let _ = tx.send(evt);
            } else {
                metrics_apply_agent_event(&state_for_events, &evt).await;
            }
        }
    });
    let response =
        process_with_agent_with_events(&state.app_state, request_ctx, None, None, Some(&tx))
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()));
    drop(tx);
    let _ = forward_task.await;
    let response = response?;

    let after_usage = call_blocking(state.app_state.db.clone(), move |db| {
        db.get_llm_usage_summary(Some(chat_id))
    })
    .await
    .ok();
    if let (Some(before), Some(after)) = (before_usage, after_usage) {
        let mut m = state.metrics.lock().await;
        m.llm_input_tokens += (after.input_tokens - before.input_tokens).max(0);
        m.llm_output_tokens += (after.output_tokens - before.output_tokens).max(0);
    }

    if saw_send_message_tool.load(Ordering::SeqCst) {
        if !response.is_empty() {
            info!(
                target: "web",
                chat_id,
                "Web: suppressing final response storage because send_message already delivered output"
            );
        }
    } else if !response.is_empty() {
        let bot_username = state.app_state.config.bot_username_for_channel("web");
        deliver_and_store_bot_message(
            &state.app_state.channel_registry,
            state.app_state.db.clone(),
            &bot_username,
            chat_id,
            &response,
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    }

    Ok(Json(json!({
        "ok": true,
        "session_key": session_key,
        "chat_id": chat_id,
        "response": response,
    })))
}
