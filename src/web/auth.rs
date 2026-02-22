use super::*;

pub(super) async fn api_auth_status(
    headers: HeaderMap,
    State(state): State<WebState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    let has_password = call_blocking(state.app_state.db.clone(), |db| db.get_auth_password_hash())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .is_some();
    let authenticated = require_scope(&state, &headers, AuthScope::Read)
        .await
        .is_ok();
    Ok(Json(json!({
        "ok": true,
        "authenticated": authenticated,
        "has_password": has_password
    })))
}

pub(super) async fn api_auth_set_password(
    headers: HeaderMap,
    State(state): State<WebState>,
    Json(body): Json<SetPasswordRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    let has_password = call_blocking(state.app_state.db.clone(), |db| db.get_auth_password_hash())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .is_some();
    let bootstrap_mode = state.legacy_auth_token.is_none() && !has_password;
    let actor = if bootstrap_mode {
        let provided = bootstrap_token_from_headers(&headers).ok_or((
            StatusCode::UNAUTHORIZED,
            "missing bootstrap token".to_string(),
        ))?;
        let expected = {
            let guard = state.bootstrap_token.lock().await;
            guard.clone()
        };
        if expected.as_deref() != Some(provided.as_str()) {
            return Err((StatusCode::UNAUTHORIZED, "invalid bootstrap token".into()));
        }
        "bootstrap-token".to_string()
    } else {
        require_scope(&state, &headers, AuthScope::Admin)
            .await?
            .actor
    };
    let password = body.password.trim();
    if password.len() < 8 {
        return Err((
            StatusCode::BAD_REQUEST,
            "password must be at least 8 chars".into(),
        ));
    }
    let hash = make_password_hash(password);
    call_blocking(state.app_state.db.clone(), move |db| {
        db.upsert_auth_password_hash(&hash)
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if bootstrap_mode {
        let mut guard = state.bootstrap_token.lock().await;
        *guard = None;
    }
    audit_log(
        &state,
        "operator",
        &actor,
        "auth.set_password",
        None,
        "ok",
        None,
    )
    .await;
    Ok(Json(json!({"ok": true})))
}

pub(super) async fn api_auth_login(
    headers: HeaderMap,
    State(state): State<WebState>,
    Json(body): Json<LoginRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    let client_key = client_key_from_headers(&headers);
    let allowed = state
        .auth_hub
        .allow_login_attempt(&client_key, 5, Duration::from_secs(60))
        .await;
    if !allowed {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            "too many login attempts".into(),
        ));
    }

    let maybe_hash = call_blocking(state.app_state.db.clone(), |db| db.get_auth_password_hash())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let Some(hash) = maybe_hash else {
        return Err((StatusCode::BAD_REQUEST, "password is not configured".into()));
    };
    if !verify_password_hash(&hash, &body.password) {
        return Err((StatusCode::UNAUTHORIZED, "invalid credentials".into()));
    }
    if hash.starts_with("v1$") {
        let upgraded = make_password_hash(&body.password);
        if !upgraded.is_empty() {
            let _ = call_blocking(state.app_state.db.clone(), move |db| {
                db.upsert_auth_password_hash(&upgraded)
            })
            .await;
        }
    }

    let session_id = uuid::Uuid::new_v4().to_string();
    let remember_days = body.remember_days.unwrap_or(30).clamp(1, 90);
    let expires_at = (chrono::Utc::now() + chrono::Duration::days(remember_days)).to_rfc3339();
    let expires_http = chrono::DateTime::parse_from_rfc3339(&expires_at)
        .map(|dt| {
            dt.with_timezone(&chrono::Utc)
                .format("%a, %d %b %Y %H:%M:%S GMT")
                .to_string()
        })
        .unwrap_or_else(|_| "Tue, 19 Jan 2038 03:14:07 GMT".to_string());

    let label = body.label.clone();
    let expires_clone = expires_at.clone();
    let session_clone = session_id.clone();
    call_blocking(state.app_state.db.clone(), move |db| {
        db.create_auth_session(&session_clone, label.as_deref(), &expires_clone)
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let csrf_token = uuid::Uuid::new_v4().to_string();
    let cookie = session_cookie_header(&session_id, &expires_http);
    let csrf_cookie = csrf_cookie_header(&csrf_token, &expires_http);
    audit_log(&state, "operator", "login", "auth.login", None, "ok", None).await;
    Ok((
        StatusCode::OK,
        [("set-cookie", cookie), ("set-cookie", csrf_cookie)],
        Json(json!({
            "ok": true,
            "expires_at": expires_at,
            "csrf_token": csrf_token,
            "session_id": session_id
        })),
    ))
}

pub(super) async fn api_auth_logout(
    headers: HeaderMap,
    State(state): State<WebState>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    if let Some(session_id) = parse_cookie(&headers, "mc_session") {
        let _ = call_blocking(state.app_state.db.clone(), move |db| {
            db.revoke_auth_session(&session_id)
        })
        .await;
    }
    Ok((
        StatusCode::OK,
        [
            ("set-cookie", clear_session_cookie_header()),
            ("set-cookie", clear_csrf_cookie_header()),
        ],
        Json(json!({"ok": true})),
    ))
}

pub(super) async fn api_auth_api_keys(
    headers: HeaderMap,
    State(state): State<WebState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    require_scope(&state, &headers, AuthScope::Admin).await?;
    let keys = call_blocking(state.app_state.db.clone(), |db| db.list_api_keys())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let keys_json = keys
        .into_iter()
        .map(|k| {
            json!({
                "id": k.id,
                "label": k.label,
                "prefix": k.prefix,
                "created_at": k.created_at,
                "revoked_at": k.revoked_at,
                "expires_at": k.expires_at,
                "last_used_at": k.last_used_at,
                "rotated_from_key_id": k.rotated_from_key_id,
                "scopes": k.scopes
            })
        })
        .collect::<Vec<_>>();
    Ok(Json(json!({"ok": true, "keys": keys_json})))
}

pub(super) async fn api_auth_create_api_key(
    headers: HeaderMap,
    State(state): State<WebState>,
    Json(body): Json<CreateApiKeyRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    let identity = require_scope(&state, &headers, AuthScope::Admin).await?;
    let label = body.label.trim().to_string();
    if label.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "label is required".into()));
    }
    if body.scopes.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "at least one scope is required".into(),
        ));
    }
    let raw_key = format!("mk_{}", uuid::Uuid::new_v4().simple());
    let prefix = raw_key.chars().take(10).collect::<String>();
    let hash = sha256_hex(&raw_key);
    let scopes = body
        .scopes
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();
    if scopes.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "at least one scope is required".into(),
        ));
    }
    let expires_at = body
        .expires_days
        .map(|d| d.clamp(1, 3650))
        .map(|d| (chrono::Utc::now() + chrono::Duration::days(d)).to_rfc3339());
    let prefix_for_save = prefix.clone();
    let scopes_for_save = scopes.clone();
    let expires_for_save = expires_at.clone();
    call_blocking(state.app_state.db.clone(), move |db| {
        db.create_api_key(
            &label,
            &hash,
            &prefix_for_save,
            &scopes_for_save,
            expires_for_save.as_deref(),
            None,
        )
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    audit_log(
        &state,
        "operator",
        &identity.actor,
        "auth.api_key.create",
        Some(&prefix),
        "ok",
        None,
    )
    .await;
    Ok(Json(
        json!({"ok": true, "api_key": raw_key, "prefix": prefix, "scopes": scopes, "expires_at": expires_at}),
    ))
}

pub(super) async fn api_auth_revoke_api_key(
    headers: HeaderMap,
    State(state): State<WebState>,
    Path(key_id): Path<i64>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    let identity = require_scope(&state, &headers, AuthScope::Approvals).await?;
    let revoked = call_blocking(state.app_state.db.clone(), move |db| {
        db.revoke_api_key(key_id)
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    audit_log(
        &state,
        "operator",
        &identity.actor,
        "auth.api_key.revoke",
        Some(&key_id.to_string()),
        if revoked { "ok" } else { "miss" },
        None,
    )
    .await;
    Ok(Json(json!({"ok": true, "revoked": revoked})))
}

pub(super) async fn api_auth_rotate_api_key(
    headers: HeaderMap,
    State(state): State<WebState>,
    Path(key_id): Path<i64>,
    Json(body): Json<RotateApiKeyRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    let identity = require_scope(&state, &headers, AuthScope::Approvals).await?;
    let keys = call_blocking(state.app_state.db.clone(), |db| db.list_api_keys())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let Some(old) = keys.into_iter().find(|k| k.id == key_id) else {
        return Err((StatusCode::NOT_FOUND, "api key not found".into()));
    };
    let scopes = body.scopes.unwrap_or(old.scopes);
    if scopes.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "at least one scope is required".into(),
        ));
    }
    let label = body
        .label
        .unwrap_or_else(|| format!("{} (rotated)", old.label));
    let raw_key = format!("mk_{}", uuid::Uuid::new_v4().simple());
    let prefix = raw_key.chars().take(10).collect::<String>();
    let hash = sha256_hex(&raw_key);
    let expires_at = body
        .expires_days
        .map(|d| d.clamp(1, 3650))
        .map(|d| (chrono::Utc::now() + chrono::Duration::days(d)).to_rfc3339());
    let scopes_for_save = scopes.clone();
    let expires_for_save = expires_at.clone();
    let prefix_for_save = prefix.clone();
    call_blocking(state.app_state.db.clone(), move |db| {
        let new_id = db.create_api_key(
            &label,
            &hash,
            &prefix_for_save,
            &scopes_for_save,
            expires_for_save.as_deref(),
            Some(key_id),
        )?;
        let _ = db.rotate_api_key_revoke_old(key_id)?;
        Ok(new_id)
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    audit_log(
        &state,
        "operator",
        &identity.actor,
        "auth.api_key.rotate",
        Some(&key_id.to_string()),
        "ok",
        Some(&prefix),
    )
    .await;
    Ok(Json(json!({
        "ok": true,
        "api_key": raw_key,
        "prefix": prefix,
        "scopes": scopes,
        "expires_at": expires_at
    })))
}
