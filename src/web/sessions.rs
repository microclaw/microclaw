use super::*;

pub(super) async fn api_sessions(
    headers: HeaderMap,
    State(state): State<WebState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    require_scope(&state, &headers, AuthScope::Read).await?;

    let chats = call_blocking(state.app_state.db.clone(), |db| db.get_recent_chats(400))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let sessions = chats
        .into_iter()
        .map(|c| map_chat_to_session(&state.app_state.channel_registry, c))
        .collect::<Vec<_>>();
    Ok(Json(json!({ "ok": true, "sessions": sessions })))
}

pub(super) async fn api_history(
    headers: HeaderMap,
    State(state): State<WebState>,
    Query(query): Query<HistoryQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    require_scope(&state, &headers, AuthScope::Read).await?;

    let session_key = normalize_session_key(query.session_key.as_deref());
    let chat_id = resolve_chat_id_for_session_key_read(&state, &session_key).await?;

    let mut messages = call_blocking(state.app_state.db.clone(), move |db| {
        db.get_all_messages(chat_id)
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if let Some(limit) = query.limit {
        if messages.len() > limit {
            messages = messages[messages.len() - limit..].to_vec();
        }
    }

    let items: Vec<HistoryItem> = messages
        .into_iter()
        .map(|m| HistoryItem {
            id: m.id,
            sender_name: m.sender_name,
            content: m.content,
            is_from_bot: m.is_from_bot,
            timestamp: m.timestamp,
        })
        .collect();

    Ok(Json(json!({
        "ok": true,
        "session_key": session_key,
        "chat_id": chat_id,
        "messages": items,
    })))
}

pub(super) async fn api_reset(
    headers: HeaderMap,
    State(state): State<WebState>,
    Json(body): Json<ResetRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    let identity = require_scope(&state, &headers, AuthScope::Approvals).await?;

    let session_key = normalize_session_key(body.session_key.as_deref());
    let chat_id = resolve_chat_id_for_session_key(&state, &session_key).await?;

    let is_web = get_chat_routing(
        &state.app_state.channel_registry,
        state.app_state.db.clone(),
        chat_id,
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?
    .map(|r| r.channel_name == "web")
    .unwrap_or(false);

    let deleted = if is_web {
        let deleted = call_blocking(state.app_state.db.clone(), move |db| {
            db.delete_chat_data(chat_id)
        })
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let session_key_for_chat = session_key.clone();
        call_blocking(state.app_state.db.clone(), move |db| {
            db.upsert_chat(chat_id, Some(&session_key_for_chat), "web")
        })
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        deleted
    } else {
        call_blocking(state.app_state.db.clone(), move |db| {
            db.delete_session(chat_id)
        })
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    };

    audit_log(
        &state,
        "operator",
        &identity.actor,
        "session.reset",
        Some(&session_key),
        if deleted { "ok" } else { "miss" },
        None,
    )
    .await;
    Ok(Json(json!({ "ok": true, "deleted": deleted })))
}

pub(super) async fn api_delete_session(
    headers: HeaderMap,
    State(state): State<WebState>,
    Json(body): Json<ResetRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    let identity = require_scope(&state, &headers, AuthScope::Approvals).await?;

    let session_key = normalize_session_key(body.session_key.as_deref());
    let chat_id = resolve_chat_id_for_session_key(&state, &session_key).await?;

    let deleted = call_blocking(state.app_state.db.clone(), move |db| {
        db.delete_chat_data(chat_id)
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    audit_log(
        &state,
        "operator",
        &identity.actor,
        "session.delete",
        Some(&session_key),
        if deleted { "ok" } else { "miss" },
        None,
    )
    .await;
    Ok(Json(json!({ "ok": true, "deleted": deleted })))
}

pub(super) async fn api_sessions_fork(
    headers: HeaderMap,
    State(state): State<WebState>,
    Json(body): Json<ForkSessionRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    let identity = require_scope(&state, &headers, AuthScope::Approvals).await?;

    let source_session_key = normalize_session_key(Some(&body.source_session_key));
    let target_session_key = body
        .target_session_key
        .map(|v| normalize_session_key(Some(&v)))
        .unwrap_or_else(|| {
            let short = uuid::Uuid::new_v4().simple().to_string();
            format!("{source_session_key}-fork-{}", &short[..8])
        });
    if source_session_key == target_session_key {
        return Err((
            StatusCode::BAD_REQUEST,
            "target_session_key must differ from source_session_key".into(),
        ));
    }

    let source_chat_id = resolve_chat_id_for_session_key(&state, &source_session_key).await?;
    let source_messages = call_blocking(state.app_state.db.clone(), move |db| {
        db.get_all_messages(source_chat_id)
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let fork_point = body
        .fork_point
        .unwrap_or(source_messages.len())
        .min(source_messages.len());
    let fork_messages = source_messages[..fork_point].to_vec();
    let target_session_key_for_create = target_session_key.clone();
    let target_chat_id = call_blocking(state.app_state.db.clone(), move |db| {
        db.resolve_or_create_chat_id(
            "web",
            &target_session_key_for_create,
            Some(&target_session_key_for_create),
            "web",
        )
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let target_chat_id_for_delete = target_chat_id;
    call_blocking(state.app_state.db.clone(), move |db| {
        db.delete_chat_data(target_chat_id_for_delete)?;
        Ok(())
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let target_session_key_for_upsert = target_session_key.clone();
    call_blocking(state.app_state.db.clone(), move |db| {
        db.upsert_chat(target_chat_id, Some(&target_session_key_for_upsert), "web")
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    for msg in fork_messages {
        let copied = StoredMessage {
            id: uuid::Uuid::new_v4().to_string(),
            chat_id: target_chat_id,
            sender_name: msg.sender_name,
            content: msg.content,
            is_from_bot: msg.is_from_bot,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        call_blocking(state.app_state.db.clone(), move |db| {
            db.store_message(&copied)
        })
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    let source_session_key_for_save = source_session_key.clone();
    call_blocking(state.app_state.db.clone(), move |db| {
        db.save_session_with_meta(
            target_chat_id,
            "[]",
            Some(&source_session_key_for_save),
            Some(fork_point as i64),
        )
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    audit_log(
        &state,
        "operator",
        &identity.actor,
        "session.fork",
        Some(&target_session_key),
        "ok",
        Some(&source_session_key),
    )
    .await;
    Ok(Json(json!({
        "ok": true,
        "source_session_key": source_session_key,
        "source_chat_id": source_chat_id,
        "target_session_key": target_session_key,
        "target_chat_id": target_chat_id,
        "fork_point": fork_point
    })))
}

pub(super) async fn api_sessions_tree(
    headers: HeaderMap,
    State(state): State<WebState>,
    Query(query): Query<SessionTreeQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    require_scope(&state, &headers, AuthScope::Read).await?;
    let limit = query.limit.unwrap_or(1000).clamp(1, 5000);
    let rows = call_blocking(state.app_state.db.clone(), move |db| {
        db.list_session_meta(limit)
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut out = Vec::new();
    for (chat_id, parent_session_key, fork_point, updated_at) in rows {
        let session_key = call_blocking(state.app_state.db.clone(), move |db| {
            db.get_chat_external_id(chat_id)
        })
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .unwrap_or_else(|| format!("chat:{chat_id}"));

        out.push(json!({
            "chat_id": chat_id,
            "session_key": session_key,
            "parent_session_key": parent_session_key,
            "fork_point": fork_point,
            "updated_at": updated_at
        }));
    }
    Ok(Json(json!({"ok": true, "nodes": out})))
}
