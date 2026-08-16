use super::*;

pub(crate) fn hook_token_from_headers(headers: &HeaderMap) -> Option<String> {
    auth_token_from_headers(headers).or_else(|| {
        headers
            .get("x-openclaw-token")
            .or_else(|| headers.get("x-microclaw-hook-token"))
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    })
}

pub(crate) fn resolve_hook_session_key(
    cfg: &Config,
    requested: Option<&str>,
) -> Result<String, (StatusCode, String)> {
    let requested = requested.map(str::trim).filter(|s| !s.is_empty());
    let allow_request = web_channel_bool(cfg, "hooks_allow_request_session_key", false);
    let default_key = web_channel_string(cfg, "hooks_default_session_key")
        .unwrap_or_else(|| "hook:ingress".to_string());
    if requested.is_some() && !allow_request {
        return Err((
            StatusCode::BAD_REQUEST,
            "session key override is disabled".into(),
        ));
    }
    if let Some(candidate) = requested {
        let prefixes = web_channel_string_list(cfg, "hooks_allowed_session_key_prefixes");
        if !prefixes.is_empty() && !prefixes.iter().any(|p| candidate.starts_with(p)) {
            return Err((
                StatusCode::BAD_REQUEST,
                "session key is not allowed by configured prefixes".into(),
            ));
        }
        return Ok(candidate.to_string());
    }
    Ok(default_key)
}

pub(crate) fn require_hook_auth(
    state: &WebState,
    headers: &HeaderMap,
) -> Result<(), (StatusCode, String)> {
    let expected = web_channel_string(&state.app_state.config, "hooks_token")
        .or_else(|| web_channel_string(&state.app_state.config, "hook_token"));
    let Some(expected) = expected else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "hooks token is not configured (set channels.web.hooks_token)".into(),
        ));
    };
    let Some(provided) = hook_token_from_headers(headers) else {
        return Err((StatusCode::UNAUTHORIZED, "unauthorized".into()));
    };
    if provided != expected {
        return Err((StatusCode::UNAUTHORIZED, "unauthorized".into()));
    }
    Ok(())
}

pub(crate) async fn enqueue_hook_message(
    state: &WebState,
    session_key: &str,
    sender_name: &str,
    message: &str,
) -> Result<i64, (StatusCode, String)> {
    let parsed_chat_id = parse_chat_id_from_session_key(session_key);
    ensure_web_writable_chat(state, parsed_chat_id).await?;
    let chat_id = resolve_chat_id_for_session_key(state, session_key).await?;
    let user_msg = StoredMessage {
        id: uuid::Uuid::new_v4().to_string(),
        chat_id,
        sender_name: sender_name.to_string(),
        content: message.to_string(),
        is_from_bot: false,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };
    call_blocking(state.app_state.db.clone(), move |db| {
        db.store_message(&user_msg)
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(chat_id)
}

pub(crate) async fn api_hook_agent(
    headers: HeaderMap,
    State(state): State<WebState>,
    Json(body): Json<HookAgentRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    require_hook_auth(&state, &headers)?;
    metrics_http_inc(&state).await;
    let session_key =
        resolve_hook_session_key(&state.app_state.config, body.session_key.as_deref())?;
    // OpenClaw-compatible webhook shape:
    // { message, sessionKey?, senderName?, name? }
    // `name` falls back to sender_name for simple integrations.
    let send = SendRequest {
        session_key: Some(session_key),
        sender_name: body.sender_name.or(body.name),
        message: body.message,
    };
    stream::start_stream_run_with_actor(state, send, "hook:token".to_string(), "/hooks/agent").await
}

pub(crate) async fn api_hook_wake(
    headers: HeaderMap,
    State(state): State<WebState>,
    Json(body): Json<HookWakeRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    require_hook_auth(&state, &headers)?;
    metrics_http_inc(&state).await;
    let text = body.text.trim();
    if text.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "text is required".into()));
    }
    let session_key =
        resolve_hook_session_key(&state.app_state.config, body.session_key.as_deref())?;
    let sender_name = body
        .sender_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("webhook-system")
        .to_string();
    let message = format!("System event: {text}");
    let mode = body
        .mode
        .as_deref()
        .unwrap_or("now")
        .trim()
        .to_ascii_lowercase();
    if mode == "next-heartbeat" {
        let chat_id = enqueue_hook_message(&state, &session_key, &sender_name, &message).await?;
        return Ok(Json(json!({
            "ok": true,
            "mode": "next-heartbeat",
            "queued": true,
            "session_key": session_key,
            "chat_id": chat_id
        })));
    }
    if mode != "now" {
        return Err((
            StatusCode::BAD_REQUEST,
            "mode must be one of: now, next-heartbeat".into(),
        ));
    }
    let send = SendRequest {
        session_key: Some(session_key),
        sender_name: Some(sender_name),
        message,
    };
    stream::start_stream_run_with_actor(state, send, "hook:token".to_string(), "/hooks/wake").await
}
