use super::*;

pub(crate) async fn index() -> impl IntoResponse {
    match WEB_ASSETS.get_file("index.html") {
        Some(file) => Html(String::from_utf8_lossy(file.contents()).to_string()).into_response(),
        None => (StatusCode::NOT_FOUND, "index.html missing").into_response(),
    }
}

pub(crate) async fn index_or_ws(
    ws_upgrade: Result<
        axum::extract::ws::WebSocketUpgrade,
        axum::extract::ws::rejection::WebSocketUpgradeRejection,
    >,
    headers: HeaderMap,
    State(state): State<WebState>,
) -> impl IntoResponse {
    match ws_upgrade {
        Ok(ws_upgrade) => ws::api_ws(ws_upgrade, headers, State(state))
            .await
            .into_response(),
        Err(_) => index().await.into_response(),
    }
}

pub async fn start_web_server(state: Arc<AppState>) {
    let limits = WebLimits::from_config(&state.config);
    let flush_interval = metrics_flush_interval(&state.config);
    let mut has_password = call_blocking(state.db.clone(), |db| db.get_auth_password_hash())
        .await
        .ok()
        .flatten()
        .is_some();
    if !has_password {
        let default_hash = make_password_hash(DEFAULT_WEB_PASSWORD);
        let _ = call_blocking(state.db.clone(), move |db| {
            db.upsert_auth_password_hash(&default_hash)
        })
        .await;
        warn!(
            "web auth default password enabled: no operator password was configured. Temporary password is '{}'. Please change it in Web UI after sign in.",
            DEFAULT_WEB_PASSWORD
        );
        has_password = true;
    }
    let bootstrap_token = if has_password {
        None
    } else {
        let token = uuid::Uuid::new_v4().to_string();
        info!(
            "web auth bootstrap token generated: use header x-bootstrap-token={} to set operator password",
            token
        );
        Some(token)
    };
    let web_state = WebState {
        bootstrap_token: Arc::new(Mutex::new(bootstrap_token)),
        app_state: state.clone(),
        run_hub: RunHub::default(),
        session_hub: SessionHub::default(),
        request_hub: RequestHub::default(),
        auth_hub: AuthHub::default(),
        metrics: Arc::new(Mutex::new(WebMetrics::default())),
        otlp: state.metric_exporter.clone(),
        limits,
    };

    let flush_state = web_state.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(flush_interval);
        loop {
            ticker.tick().await;
            if let Err((status, err)) = persist_metrics_snapshot(&flush_state).await {
                tracing::warn!(
                    "metrics flush failed status={} error={}",
                    status.as_u16(),
                    err
                );
            }
        }
    });

    let mut router = build_router(web_state);
    router = crate::channels::feishu::register_feishu_webhook(router, state.clone());
    router = crate::channels::whatsapp::register_whatsapp_webhook(router, state.clone());
    router = crate::channels::email::register_email_webhook(router, state.clone());
    router = crate::channels::nostr::register_nostr_webhook(router, state.clone());
    router = crate::channels::signal::register_signal_webhook(router, state.clone());
    router = crate::channels::dingtalk::register_dingtalk_webhook(router, state.clone());
    router = crate::channels::qq::register_qq_webhook(router, state.clone());
    router = crate::channels::weixin::register_weixin_webhook(router, state.clone());

    let addr = format!("{}:{}", state.config.web_host, state.config.web_port);
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(listener) => listener,
        Err(e) => {
            error!("Failed to bind web server at {}: {}", addr, e);
            return;
        }
    };

    info!("Web UI available at http://{addr}");
    if let Err(e) = axum::serve(listener, router).await {
        error!("Web server error: {e}");
    }
}

pub(crate) async fn asset_file(Path(file): Path<String>) -> impl IntoResponse {
    let clean = file.replace("..", "");
    match WEB_ASSETS.get_file(format!("assets/{clean}")) {
        Some(file) => {
            let content_type = if clean.ends_with(".css") {
                "text/css; charset=utf-8"
            } else if clean.ends_with(".js") {
                "application/javascript; charset=utf-8"
            } else {
                "application/octet-stream"
            };
            ([("content-type", content_type)], file.contents().to_vec()).into_response()
        }
        None => (StatusCode::NOT_FOUND, "Not Found").into_response(),
    }
}

pub(crate) async fn icon_file() -> impl IntoResponse {
    match WEB_ASSETS.get_file("icon.png") {
        Some(file) => ([("content-type", "image/png")], file.contents().to_vec()).into_response(),
        None => (StatusCode::NOT_FOUND, "Not Found").into_response(),
    }
}

pub(crate) async fn favicon_file() -> impl IntoResponse {
    if let Some(file) = WEB_ASSETS.get_file("favicon.ico") {
        return ([("content-type", "image/x-icon")], file.contents().to_vec()).into_response();
    }
    if let Some(file) = WEB_ASSETS.get_file("icon.png") {
        return ([("content-type", "image/png")], file.contents().to_vec()).into_response();
    }
    (StatusCode::NOT_FOUND, "Not Found").into_response()
}

pub(crate) fn build_router(web_state: WebState) -> Router {
    Router::new()
        .route("/", get(index_or_ws))
        .route("/health", get(api_health_root))
        .route("/assets/*file", get(asset_file))
        .route("/icon.png", get(icon_file))
        .route("/favicon.ico", get(favicon_file))
        .route("/api/health", get(api_health))
        .route("/.well-known/agent.json", get(a2a::api_a2a_agent_card))
        .route("/api/auth/status", get(auth::api_auth_status))
        .route("/api/auth/password", post(auth::api_auth_set_password))
        .route("/api/auth/login", post(auth::api_auth_login))
        .route("/api/auth/logout", post(auth::api_auth_logout))
        .route(
            "/api/auth/api_keys",
            get(auth::api_auth_api_keys).post(auth::api_auth_create_api_key),
        )
        .route(
            "/api/auth/api_keys/:id",
            axum::routing::delete(auth::api_auth_revoke_api_key),
        )
        .route(
            "/api/auth/api_keys/:id/rotate",
            post(auth::api_auth_rotate_api_key),
        )
        .route(
            "/api/config",
            get(config::api_get_config).put(config::api_update_config),
        )
        .route("/api/config/self_check", get(config::api_config_self_check))
        .route("/api/sessions", get(sessions::api_sessions))
        .route("/api/sessions/tree", get(sessions::api_sessions_tree))
        .route("/api/sessions/fork", post(sessions::api_sessions_fork))
        .route("/api/audit", get(api_audit_logs))
        .route("/api/history", get(sessions::api_history))
        .route("/api/usage", get(api_usage))
        .route(
            "/api/learning_observability",
            get(api_learning_observability),
        )
        .route("/api/learning/feedback", post(api_learning_feedback))
        .route(
            "/api/learning/recovery_trial",
            post(api_learning_recovery_trial),
        )
        .route(
            "/api/learning/candidates",
            post(api_learning_create_candidate),
        )
        .route(
            "/api/learning/shadow_observations",
            post(api_learning_shadow_observation),
        )
        .route(
            "/api/learning/candidates/promote",
            post(api_learning_promote_candidate),
        )
        .route(
            "/api/learning/tracks/candidates/promote",
            post(api_learning_promote_track_candidate),
        )
        .route(
            "/api/learning/tracks/candidates/evaluate",
            post(api_learning_evaluate_track_candidate),
        )
        .route("/api/learning/archive", post(api_learning_archive_entity))
        .route("/api/learning/rollback", post(api_learning_rollback_skill))
        .route("/api/learning/experiences", get(api_learning_experiences))
        .route(
            "/api/learning/experiences/:run_id",
            get(api_learning_run_detail),
        )
        .route(
            "/api/learning/policy",
            get(api_learning_policy).put(api_update_learning_policy),
        )
        .route("/api/memory_observability", get(api_memory_observability))
        .route("/api/metrics", get(metrics::api_metrics))
        .route("/api/metrics/summary", get(metrics::api_metrics_summary))
        .route("/api/metrics/history", get(metrics::api_metrics_history))
        .route(
            "/api/subagents/observability",
            get(metrics::api_subagents_observability),
        )
        .route("/api/send", post(api_send))
        .route("/api/chat", post(api_send))
        .route("/api/a2a/agent-card", get(a2a::api_a2a_agent_card))
        .route("/api/a2a/message", post(a2a::api_a2a_message))
        .route("/api/hooks/agent", post(api_hook_agent))
        .route("/api/hooks/wake", post(api_hook_wake))
        .route("/api/send_stream", post(stream::api_send_stream))
        .route("/api/chat_stream", post(stream::api_send_stream))
        .route("/hooks/agent", post(api_hook_agent))
        .route("/hooks/wake", post(api_hook_wake))
        .route("/api/stream", get(stream::api_stream))
        .route("/api/run_status", get(stream::api_run_status))
        .route("/api/reset", post(sessions::api_reset))
        .route("/api/delete_session", post(sessions::api_delete_session))
        .route("/api/skills", get(skills::api_list_skills))
        .route("/api/skills/:name/enable", post(skills::api_enable_skill))
        .route("/api/skills/:name/disable", post(skills::api_disable_skill))
        .route("/api/governance", get(governance::api_governance))
        .route("/api/tasks", get(tasks::api_list_tasks))
        .route("/api/tasks/:id/runs", get(tasks::api_task_runs))
        .route("/api/tasks/:id/:action", post(tasks::api_task_action))
        .with_state(web_state)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use crate::web::test_prelude::*;

    #[test]
    fn test_web_assets_embedded() {
        assert!(
            WEB_ASSETS.get_file("index.html").is_some(),
            "embedded web asset missing: index.html"
        );
        assert!(
            WEB_ASSETS.get_file("icon.png").is_some(),
            "embedded web asset missing: icon.png"
        );
        let assets_dir = WEB_ASSETS.get_dir("assets");
        assert!(
            assets_dir.is_some(),
            "embedded web asset dir missing: assets"
        );
        assert!(
            assets_dir.unwrap().files().next().is_some(),
            "embedded web asset dir is empty: assets"
        );
    }

    #[tokio::test]
    async fn test_comparative_learning_candidate_shadow_and_promotion_api() {
        let web_state = test_web_state(Box::new(DummyLlm), WebLimits::default());
        let db = web_state.app_state.db.clone();
        call_blocking(db.clone(), |d| {
            d.upsert_chat(123, Some("main"), "web")?;
            d.register_skill_version("web-reflect", 1, "base", "built-in")?;
            for (run_id, verdict) in [("web-failure", "failed"), ("web-success", "passed")] {
                d.start_experience_run(
                    run_id,
                    None,
                    123,
                    "web",
                    "interactive",
                    "deploy service",
                    Some("os=linux"),
                )?;
                d.log_skill_activation("web-reflect", 123)?;
                d.finish_experience_run(run_id, "completed", Some(verdict), 10)?;
                d.record_verifier_result(
                    run_id,
                    "deterministic",
                    "health",
                    verdict,
                    1.0,
                    Some(verdict),
                    None,
                    None,
                )?;
            }
            Ok(())
        })
        .await
        .unwrap();
        let app = build_router(web_state);
        let observation = Request::builder()
            .method("GET")
            .uri("/api/learning_observability?session_key=main")
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(observation).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let claim_id = value["learning_claims"][0]["claim_id"]
            .as_str()
            .unwrap()
            .to_string();
        let create = Request::builder()
            .method("POST")
            .uri("/api/learning/candidates")
            .header("content-type", "application/json")
            .body(Body::from(json!({"claim_id": claim_id}).to_string()))
            .unwrap();
        let created = app.clone().oneshot(create).await.unwrap();
        assert_eq!(created.status(), StatusCode::OK);
        let created_body = axum::body::to_bytes(created.into_body(), usize::MAX)
            .await
            .unwrap();
        let created_value: serde_json::Value = serde_json::from_slice(&created_body).unwrap();
        let candidate_id = created_value["candidate"]["candidate_id"]
            .as_str()
            .unwrap()
            .to_string();
        for index in 0..3 {
            for (arm, run_id, verdict, cost) in [
                ("baseline", "web-failure", "failed", 1.0),
                ("candidate", "web-success", "passed", 0.8),
            ] {
                let request = Request::builder()
                    .method("POST")
                    .uri("/api/learning/shadow_observations")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "candidate_id": candidate_id,
                            "pair_key": format!("web-pair-{index}"),
                            "arm": arm,
                            "run_id": run_id,
                            "verdict": verdict,
                            "cost_usd": cost,
                            "duration_ms": 10
                        })
                        .to_string(),
                    ))
                    .unwrap();
                assert_eq!(
                    app.clone().oneshot(request).await.unwrap().status(),
                    StatusCode::OK
                );
            }
        }
        let promote = Request::builder()
            .method("POST")
            .uri("/api/learning/candidates/promote")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"candidate_id": candidate_id}).to_string(),
            ))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(promote).await.unwrap().status(),
            StatusCode::OK
        );
        let lifecycle = call_blocking(db, |d| d.get_skill_lifecycle("web-reflect"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(lifecycle.active_version, 2);
    }

    #[tokio::test]
    async fn test_ws_bridge_supports_mission_control_session_methods() {
        let web_state = test_web_state(Box::new(DummyLlm), WebLimits::default());
        seed_test_api_key(&web_state, "ws-session-secret").await;
        let (addr, server) = spawn_test_server(build_router(web_state.clone())).await;

        let app = build_router(web_state.clone());
        let req = Request::builder()
            .method("POST")
            .uri("/api/send")
            .header("authorization", "Bearer ws-session-secret")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"session_key":"main","sender_name":"u","message":"seed"}"#,
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/"))
            .await
            .unwrap();
        let _ = recv_ws_json(&mut ws).await;
        ws.send(tokio_tungstenite::tungstenite::Message::Text(
            json!({
                "type": "req",
                "id": "connect-1",
                "method": "connect",
                "params": {
                    "minProtocol": 3,
                    "maxProtocol": 3,
                    "auth": { "token": "ws-session-secret" }
                }
            })
            .to_string(),
        ))
        .await
        .unwrap();
        let _ = recv_ws_json(&mut ws).await;

        for (request_id, method, params) in [
            (
                "setting-1",
                "sessions.setLabel",
                json!({"key":"main","label":"Ops"}),
            ),
            (
                "send-1",
                "sessions.send",
                json!({"key":"main","message":"continue"}),
            ),
            (
                "spawn-1",
                "sessions.spawn",
                json!({"task":"spawn from mission control","label":"worker"}),
            ),
            ("delete-1", "sessions.delete", json!({"key":"main"})),
        ] {
            ws.send(tokio_tungstenite::tungstenite::Message::Text(
                json!({
                    "type": "req",
                    "id": request_id,
                    "method": method,
                    "params": params
                })
                .to_string(),
            ))
            .await
            .unwrap();
            let res = loop {
                let candidate = recv_ws_json(&mut ws).await;
                if candidate.get("type").and_then(|v| v.as_str()) != Some("res") {
                    continue;
                }
                if candidate.get("id").and_then(|v| v.as_str()) != Some(request_id) {
                    continue;
                }
                break candidate;
            };
            assert_eq!(
                res.get("ok").and_then(|v| v.as_bool()),
                Some(true),
                "{method}"
            );
            if method == "sessions.send" {
                let mut saw_final = false;
                for _ in 0..12 {
                    let candidate = recv_ws_json(&mut ws).await;
                    if candidate.get("type").and_then(|v| v.as_str()) != Some("event") {
                        continue;
                    }
                    if candidate.get("event").and_then(|v| v.as_str()) != Some("chat") {
                        continue;
                    }
                    if candidate.pointer("/payload/state").and_then(|v| v.as_str()) != Some("final")
                    {
                        continue;
                    }
                    assert_eq!(
                        candidate.pointer("/payload/key").and_then(|v| v.as_str()),
                        Some("main")
                    );
                    assert_eq!(
                        candidate
                            .pointer("/payload/sessionKey")
                            .and_then(|v| v.as_str()),
                        Some("main")
                    );
                    saw_final = true;
                    break;
                }
                assert!(saw_final, "sessions_send should emit a final chat event");
            }
        }

        server.abort();
    }

    #[tokio::test]
    async fn test_ws_sessions_list_returns_filtered_sessions() {
        let web_state = test_web_state(Box::new(DummyLlm), WebLimits::default());
        seed_test_api_key(&web_state, "ws-list-secret").await;
        let (addr, server) = spawn_test_server(build_router(web_state.clone())).await;

        let app = build_router(web_state.clone());

        // Seed a session that should NOT be returned
        let req1 = Request::builder()
            .method("POST")
            .uri("/api/send")
            .header("authorization", "Bearer ws-list-secret")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"session_key":"other:123","sender_name":"u","message":"seed"}"#,
            ))
            .unwrap();
        app.clone().oneshot(req1).await.unwrap();

        // Seed a session that SHOULD be returned
        let req2 = Request::builder()
            .method("POST")
            .uri("/api/send")
            .header("authorization", "Bearer ws-list-secret")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"session_key":"chatclaw:microclaw:456","sender_name":"u","message":"seed"}"#,
            ))
            .unwrap();
        app.clone().oneshot(req2).await.unwrap();

        let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/"))
            .await
            .unwrap();
        let _ = recv_ws_json(&mut ws).await;
        ws.send(tokio_tungstenite::tungstenite::Message::Text(
            json!({
                "type": "req",
                "id": "connect-1",
                "method": "connect",
                "params": {
                    "minProtocol": 3,
                    "maxProtocol": 3,
                    "auth": { "token": "ws-list-secret" }
                }
            })
            .to_string(),
        ))
        .await
        .unwrap();
        let _ = recv_ws_json(&mut ws).await;

        ws.send(tokio_tungstenite::tungstenite::Message::Text(
            json!({
                "type": "req",
                "id": "list-1",
                "method": "sessions.list",
                "params": {
                    "agentId": "chatclaw:microclaw"
                }
            })
            .to_string(),
        ))
        .await
        .unwrap();

        let res = loop {
            let candidate = recv_ws_json(&mut ws).await;
            if candidate.get("type").and_then(|v| v.as_str()) != Some("res") {
                continue;
            }
            if candidate.get("id").and_then(|v| v.as_str()) != Some("list-1") {
                continue;
            }
            break candidate;
        };

        assert_eq!(res.get("ok").and_then(|v| v.as_bool()), Some(true));

        let sessions = res
            .pointer("/payload/sessions")
            .and_then(|v| v.as_array())
            .unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(
            sessions[0].get("key").and_then(|v| v.as_str()),
            Some("chatclaw:microclaw:456")
        );
        assert_eq!(
            sessions[0].get("sessionKey").and_then(|v| v.as_str()),
            Some("chatclaw:microclaw:456")
        );
        assert_eq!(
            sessions[0].get("session_key").and_then(|v| v.as_str()),
            Some("chatclaw:microclaw:456")
        );

        // Test with search term
        ws.send(tokio_tungstenite::tungstenite::Message::Text(
            json!({
                "type": "req",
                "id": "list-search",
                "method": "sessions.list",
                "params": {
                    "search": "123"
                }
            })
            .to_string(),
        ))
        .await
        .unwrap();

        let res_search = loop {
            let candidate = recv_ws_json(&mut ws).await;
            if candidate.get("type").and_then(|v| v.as_str()) != Some("res") {
                continue;
            }
            if candidate.get("id").and_then(|v| v.as_str()) != Some("list-search") {
                continue;
            }
            break candidate;
        };

        assert_eq!(res_search.get("ok").and_then(|v| v.as_bool()), Some(true));

        let sessions_search = res_search
            .pointer("/payload/sessions")
            .and_then(|v| v.as_array())
            .unwrap();
        assert_eq!(sessions_search.len(), 1);
        assert_eq!(
            sessions_search[0]
                .get("session_key")
                .and_then(|v| v.as_str()),
            Some("other:123")
        );

        // Test without filter
        ws.send(tokio_tungstenite::tungstenite::Message::Text(
            json!({
                "type": "req",
                "id": "list-2",
                "method": "sessions.list",
                "params": {}
            })
            .to_string(),
        ))
        .await
        .unwrap();

        let res2 = loop {
            let candidate = recv_ws_json(&mut ws).await;
            if candidate.get("type").and_then(|v| v.as_str()) != Some("res") {
                continue;
            }
            if candidate.get("id").and_then(|v| v.as_str()) != Some("list-2") {
                continue;
            }
            break candidate;
        };

        assert_eq!(res2.get("ok").and_then(|v| v.as_bool()), Some(true));

        let sessions2 = res2
            .pointer("/payload/sessions")
            .and_then(|v| v.as_array())
            .unwrap();
        // Since we seeded two sessions, it should return both without filter
        assert_eq!(sessions2.len(), 2);

        server.abort();
    }

    #[tokio::test]
    async fn test_ws_session_settings_persist_and_enable_thinking_output() {
        let mut cfg = test_config_template();
        cfg.show_thinking = false;
        let web_state = test_web_state_from_app_state(
            test_state_with_config(Box::new(ThinkingLlm), cfg),
            WebLimits::default(),
        );
        seed_test_api_key(&web_state, "ws-settings-secret").await;
        let app = build_router(web_state.clone());
        let (addr, server) = spawn_test_server(build_router(web_state.clone())).await;

        let plain_req = Request::builder()
            .method("POST")
            .uri("/api/send")
            .header("authorization", "Bearer ws-settings-secret")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"session_key":"plain","sender_name":"u","message":"before"}"#,
            ))
            .unwrap();
        let plain_resp = app.clone().oneshot(plain_req).await.unwrap();
        assert_eq!(plain_resp.status(), StatusCode::OK);
        let plain_body = axum::body::to_bytes(plain_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let plain_json: serde_json::Value = serde_json::from_slice(&plain_body).unwrap();
        assert_eq!(
            plain_json.get("response").and_then(|v| v.as_str()),
            Some("Visible")
        );

        let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/"))
            .await
            .unwrap();
        let _ = recv_ws_json(&mut ws).await;
        ws.send(tokio_tungstenite::tungstenite::Message::Text(
            json!({
                "type": "req",
                "id": "connect-1",
                "method": "connect",
                "params": {
                    "minProtocol": 3,
                    "maxProtocol": 3,
                    "auth": { "token": "ws-settings-secret" }
                }
            })
            .to_string(),
        ))
        .await
        .unwrap();
        let _ = recv_ws_json(&mut ws).await;

        for (request_id, method, params) in [
            (
                "label-1",
                "sessions.setLabel",
                json!({"key":"main","label":"Ops"}),
            ),
            (
                "thinking-1",
                "sessions.setThinking",
                json!({"key":"main","level":"high"}),
            ),
        ] {
            ws.send(tokio_tungstenite::tungstenite::Message::Text(
                json!({
                    "type": "req",
                    "id": request_id,
                    "method": method,
                    "params": params
                })
                .to_string(),
            ))
            .await
            .unwrap();
            let res = loop {
                let candidate = recv_ws_json(&mut ws).await;
                if candidate.get("type").and_then(|v| v.as_str()) != Some("res") {
                    continue;
                }
                if candidate.get("id").and_then(|v| v.as_str()) != Some(request_id) {
                    continue;
                }
                break candidate;
            };
            assert_eq!(res.get("ok").and_then(|v| v.as_bool()), Some(true));
            assert_eq!(
                res.get("payload")
                    .and_then(|p| p.get("applied"))
                    .and_then(|v| v.as_bool()),
                Some(true)
            );
        }

        let send_req = Request::builder()
            .method("POST")
            .uri("/api/send")
            .header("authorization", "Bearer ws-settings-secret")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"session_key":"main","sender_name":"u","message":"after"}"#,
            ))
            .unwrap();
        let send_resp = app.clone().oneshot(send_req).await.unwrap();
        assert_eq!(send_resp.status(), StatusCode::OK);
        let send_body = axum::body::to_bytes(send_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let send_json: serde_json::Value = serde_json::from_slice(&send_body).unwrap();
        assert_eq!(
            send_json.get("response").and_then(|v| v.as_str()),
            Some("<thinking>internal</thinking>Visible")
        );

        let sessions_req = Request::builder()
            .method("GET")
            .uri("/api/sessions")
            .header("authorization", "Bearer ws-settings-secret")
            .body(Body::empty())
            .unwrap();
        let sessions_resp = app.oneshot(sessions_req).await.unwrap();
        assert_eq!(sessions_resp.status(), StatusCode::OK);
        let sessions_body = axum::body::to_bytes(sessions_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let sessions_json: serde_json::Value = serde_json::from_slice(&sessions_body).unwrap();
        let sessions = sessions_json
            .get("sessions")
            .and_then(|v| v.as_array())
            .unwrap();
        assert!(sessions.iter().any(|session| {
            session.get("session_key").and_then(|v| v.as_str()) == Some("main")
                && session.get("label").and_then(|v| v.as_str()) == Some("Ops")
        }));

        server.abort();
    }

    #[tokio::test]
    async fn test_ws_sessions_kill_aborts_active_stream_run() {
        let web_state = test_web_state(Box::new(SlowLlm { sleep_ms: 1_500 }), WebLimits::default());
        seed_test_api_key(&web_state, "ws-kill-secret").await;
        let app = build_router(web_state.clone());
        let (addr, server) = spawn_test_server(build_router(web_state.clone())).await;
        let chat_id = unique_test_chat_id();
        let session_key = format!("chat:{chat_id}");
        let session_key_for_db = session_key.clone();

        call_blocking(web_state.app_state.db.clone(), move |db| {
            db.upsert_chat(chat_id, Some(&session_key_for_db), "web")
        })
        .await
        .unwrap();

        let send_req = Request::builder()
            .method("POST")
            .uri("/api/send_stream")
            .header("authorization", "Bearer ws-kill-secret")
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"session_key":"{session_key}","sender_name":"u","message":"slow"}}"#
            )))
            .unwrap();
        let send_resp = app.oneshot(send_req).await.unwrap();
        assert_eq!(send_resp.status(), StatusCode::OK);
        let send_body = axum::body::to_bytes(send_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let send_json: serde_json::Value = serde_json::from_slice(&send_body).unwrap();
        let run_id = send_json
            .get("run_id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        tokio::time::sleep(Duration::from_millis(100)).await;

        let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/"))
            .await
            .unwrap();
        let _ = recv_ws_json(&mut ws).await;
        ws.send(tokio_tungstenite::tungstenite::Message::Text(
            json!({
                "type": "req",
                "id": "connect-1",
                "method": "connect",
                "params": {
                    "minProtocol": 3,
                    "maxProtocol": 3,
                    "auth": { "token": "ws-kill-secret" }
                }
            })
            .to_string(),
        ))
        .await
        .unwrap();
        let _ = recv_ws_json(&mut ws).await;
        ws.send(tokio_tungstenite::tungstenite::Message::Text(
            json!({
                "type": "req",
                "id": "kill-1",
                "method": "sessions.kill",
                "params": { "key": session_key }
            })
            .to_string(),
        ))
        .await
        .unwrap();
        let kill_res = loop {
            let candidate = recv_ws_json(&mut ws).await;
            if candidate.get("type").and_then(|v| v.as_str()) != Some("res") {
                continue;
            }
            if candidate.get("id").and_then(|v| v.as_str()) != Some("kill-1") {
                continue;
            }
            break candidate;
        };
        assert_eq!(
            kill_res
                .get("payload")
                .and_then(|p| p.get("terminated"))
                .and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            kill_res
                .get("payload")
                .and_then(|p| p.get("activeAborted"))
                .and_then(|v| v.as_u64()),
            Some(1)
        );

        for _ in 0..20 {
            let status = web_state.run_hub.status(&run_id, "", true).await.unwrap();
            if status.0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let (_, replay, done, _, _) = web_state
            .run_hub
            .subscribe_with_replay(&run_id, None, "", true)
            .await
            .unwrap();
        assert!(done);
        // When a run is aborted, replay should contain an "aborted" event (not "done").
        // The "aborted" event carries partial buffered text, which may be null if no
        // text was generated before the abort signal was processed.
        assert!(
            replay.iter().any(|evt| evt.event == "aborted"),
            "expected 'aborted' event in replay, got: {:?}",
            replay
        );

        server.abort();
    }
}
