//! `/api/code/*`: notifications and approval cards for MicroClaw Code.
//!
//! Callers authenticate like any other API client; a paired `mccode` uses
//! its device token (`operator.read` + `operator.write`). Sending needs the
//! write scope; an approval can only be read or cancelled by the actor that
//! created it (or an operator admin). See `crate::remote_approvals` for the
//! chat rules and how answers are routed back.

use super::*;
use crate::remote_approvals::{
    self as ra, ApprovalOption, RemoteApproval, RemoteApprovalHub, TargetError,
};

#[derive(Debug, Default, Deserialize)]
struct NotifyRequest {
    #[serde(default)]
    chat: String,
    #[serde(default)]
    text: String,
    #[serde(default)]
    title: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct OptionRequest {
    #[serde(default)]
    value: String,
    #[serde(default)]
    label: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct ApprovalRequest {
    #[serde(default)]
    chat: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    text: String,
    #[serde(default)]
    options: Vec<OptionRequest>,
    #[serde(default)]
    ttl_secs: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct CancelQuery {
    #[serde(default)]
    reason: Option<String>,
}

type ApiResult = Result<Json<serde_json::Value>, (StatusCode, String)>;

fn bad_request(message: impl Into<String>) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, message.into())
}

fn target_error(err: TargetError) -> (StatusCode, String) {
    let status = match &err {
        TargetError::Invalid(_) => StatusCode::BAD_REQUEST,
        TargetError::UnknownChat(_) => StatusCode::NOT_FOUND,
        TargetError::Forbidden(_) => StatusCode::FORBIDDEN,
    };
    (status, err.to_string())
}

fn parse_body<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, (StatusCode, String)> {
    serde_json::from_slice(body).map_err(|e| bad_request(format!("invalid JSON body: {e}")))
}

fn validate_options(raw: Vec<OptionRequest>) -> Result<Vec<ApprovalOption>, (StatusCode, String)> {
    if raw.is_empty() || raw.len() > ra::MAX_OPTIONS {
        return Err(bad_request(format!(
            "options must have 1 to {} entries",
            ra::MAX_OPTIONS
        )));
    }
    let mut options: Vec<ApprovalOption> = Vec::with_capacity(raw.len());
    for option in raw {
        let value = option.value.trim().to_string();
        if value.is_empty() || value.chars().count() > ra::MAX_VALUE_CHARS {
            return Err(bad_request(format!(
                "each option needs a value of 1 to {} characters",
                ra::MAX_VALUE_CHARS
            )));
        }
        let label = option
            .label
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .unwrap_or_else(|| value.clone());
        if label.chars().count() > ra::MAX_LABEL_CHARS {
            return Err(bad_request(format!(
                "option labels are limited to {} characters",
                ra::MAX_LABEL_CHARS
            )));
        }
        if options.iter().any(|o| o.value.eq_ignore_ascii_case(&value)) {
            return Err(bad_request(format!("duplicate option value '{value}'")));
        }
        options.push(ApprovalOption { value, label });
    }
    Ok(options)
}

fn approval_json(approval: &RemoteApproval) -> serde_json::Value {
    json!({
        "ok": true,
        "id": approval.id,
        "status": approval.status,
        "value": approval.value,
        "label": approval.label,
        "answered_by": approval.answered_by,
        "chat": format!("{}:{}", approval.channel, approval.external_chat_id),
        "created_at": approval.created_at.to_rfc3339(),
        "expires_at": approval.expires_at.to_rfc3339(),
        "finished_at": approval.finished_at.map(|t| t.to_rfc3339()),
    })
}

/// Look up an approval the caller may see. Unknown ids and other callers'
/// approvals both answer 404 so ids cannot be probed.
fn owned_approval(
    identity: &AuthIdentity,
    found: Option<(RemoteApproval, bool)>,
) -> Result<(RemoteApproval, bool), (StatusCode, String)> {
    match found {
        Some((approval, flag))
            if approval.owner == identity.actor || identity.allows(AuthScope::Admin) =>
        {
            Ok((approval, flag))
        }
        _ => Err((StatusCode::NOT_FOUND, "approval not found".into())),
    }
}

pub(super) async fn api_code_notify(
    headers: HeaderMap,
    State(state): State<WebState>,
    body: axum::body::Bytes,
) -> ApiResult {
    metrics_http_inc(&state).await;
    let identity = require_scope(&state, &headers, AuthScope::Write).await?;
    let request: NotifyRequest = parse_body(&body)?;
    let text = request.text.trim();
    if text.is_empty() {
        return Err(bad_request("text is required"));
    }
    if text.chars().count() > ra::MAX_TEXT_CHARS {
        return Err(bad_request(format!(
            "text is limited to {} characters",
            ra::MAX_TEXT_CHARS
        )));
    }
    if request
        .title
        .as_deref()
        .is_some_and(|t| t.chars().count() > ra::MAX_TITLE_CHARS)
    {
        return Err(bad_request(format!(
            "title is limited to {} characters",
            ra::MAX_TITLE_CHARS
        )));
    }
    let target = ra::resolve_chat_target(&state.app_state, &request.chat, false)
        .await
        .map_err(target_error)?;
    let chat = format!("{}:{}", target.channel, target.external_chat_id);
    let outcome =
        ra::deliver_notification(&state.app_state, &target, request.title.as_deref(), text).await;
    let (status, delivery) = match &outcome {
        Ok(microclaw_engine::channel::DeliveryOutcome::Delivered) => ("ok", "delivered"),
        Ok(microclaw_engine::channel::DeliveryOutcome::Queued { .. }) => ("queued", "queued"),
        Err(_) => ("error", "failed"),
    };
    audit_log(
        &state,
        "operator",
        &identity.actor,
        "code.notify",
        Some(&chat),
        status,
        outcome.as_ref().err().map(String::as_str),
    )
    .await;
    match outcome {
        Ok(_) => Ok(Json(
            json!({"ok": true, "chat": chat, "delivery": delivery}),
        )),
        Err(e) => Err((StatusCode::BAD_GATEWAY, format!("delivery failed: {e}"))),
    }
}

pub(super) async fn api_code_approval_create(
    headers: HeaderMap,
    State(state): State<WebState>,
    body: axum::body::Bytes,
) -> ApiResult {
    metrics_http_inc(&state).await;
    let identity = require_scope(&state, &headers, AuthScope::Write).await?;
    let request: ApprovalRequest = parse_body(&body)?;
    let title = request.title.trim().to_string();
    if title.is_empty() || title.chars().count() > ra::MAX_TITLE_CHARS {
        return Err(bad_request(format!(
            "title is required (at most {} characters)",
            ra::MAX_TITLE_CHARS
        )));
    }
    let text = request.text.trim().to_string();
    if text.chars().count() > ra::MAX_TEXT_CHARS {
        return Err(bad_request(format!(
            "text is limited to {} characters",
            ra::MAX_TEXT_CHARS
        )));
    }
    let options = validate_options(request.options)?;
    let ttl_secs = request
        .ttl_secs
        .unwrap_or(ra::DEFAULT_TTL_SECS)
        .clamp(ra::MIN_TTL_SECS, ra::MAX_TTL_SECS);
    let target = ra::resolve_chat_target(&state.app_state, &request.chat, true)
        .await
        .map_err(target_error)?;
    let hub = RemoteApprovalHub::global();
    let approval = hub.create(
        &identity.actor,
        &target,
        &title,
        &text,
        options,
        Duration::from_secs(ttl_secs),
    );
    let chat = format!("{}:{}", target.channel, target.external_chat_id);
    match ra::deliver_approval_card(&state.app_state, &approval).await {
        Ok(card) => {
            if let Some(card) = card {
                hub.set_card(&approval.id, card);
            }
        }
        Err(e) => {
            hub.remove(&approval.id);
            audit_log(
                &state,
                "operator",
                &identity.actor,
                "code.approval.create",
                Some(&chat),
                "error",
                Some(&e),
            )
            .await;
            return Err((StatusCode::BAD_GATEWAY, format!("delivery failed: {e}")));
        }
    }
    audit_log(
        &state,
        "operator",
        &identity.actor,
        "code.approval.create",
        Some(&chat),
        "ok",
        Some(&approval.id),
    )
    .await;
    Ok(Json(approval_json(&approval)))
}

pub(super) async fn api_code_approval_get(
    headers: HeaderMap,
    State(state): State<WebState>,
    Path(id): Path<String>,
) -> ApiResult {
    metrics_http_inc(&state).await;
    let identity = require_scope(&state, &headers, AuthScope::Read).await?;
    let (approval, just_expired) = owned_approval(&identity, RemoteApprovalHub::global().get(&id))?;
    if just_expired {
        ra::finish_card(&state.app_state, &approval).await;
    }
    Ok(Json(approval_json(&approval)))
}

pub(super) async fn api_code_approval_cancel(
    headers: HeaderMap,
    State(state): State<WebState>,
    Path(id): Path<String>,
    Query(query): Query<CancelQuery>,
) -> ApiResult {
    metrics_http_inc(&state).await;
    let identity = require_scope(&state, &headers, AuthScope::Write).await?;
    let hub = RemoteApprovalHub::global();
    // Ownership is checked before anything changes.
    owned_approval(&identity, hub.get(&id))?;
    let (approval, cancelled) = owned_approval(&identity, hub.cancel(&id))?;
    if cancelled {
        ra::finish_card(&state.app_state, &approval).await;
    }
    audit_log(
        &state,
        "operator",
        &identity.actor,
        "code.approval.cancel",
        Some(&approval.id),
        if cancelled { "ok" } else { "miss" },
        query.reason.as_deref(),
    )
    .await;
    let mut body = approval_json(&approval);
    body["cancelled"] = json!(cancelled);
    Ok(Json(body))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use crate::web::test_prelude::*;
    use axum::body::Body;
    use axum::http::Request;
    use microclaw_engine::channel::ConversationKind;
    use std::sync::Mutex as StdMutex;
    use tower::ServiceExt;

    /// A channel that records what it was asked to send.
    struct RecordingAdapter {
        name: String,
        sent: Arc<StdMutex<Vec<(String, String)>>>,
    }

    #[async_trait::async_trait]
    impl ChannelAdapter for RecordingAdapter {
        fn name(&self) -> &str {
            &self.name
        }
        fn chat_type_routes(&self) -> Vec<(&str, ConversationKind)> {
            vec![("feishu_dm", ConversationKind::Private)]
        }
        async fn send_text(&self, external_chat_id: &str, text: &str) -> Result<(), String> {
            self.sent
                .lock()
                .unwrap()
                .push((external_chat_id.to_string(), text.to_string()));
            Ok(())
        }
    }

    struct Fixture {
        app: Router,
        state: WebState,
        sent: Arc<StdMutex<Vec<(String, String)>>>,
        control_chat: i64,
        plain_chat: i64,
    }

    /// A Server with the web channel plus a recording "feishu" channel
    /// (approvals fall back to numbered text there), one control chat and
    /// one ordinary chat.
    async fn fixture() -> Fixture {
        let control_chat = unique_test_chat_id();
        let base = test_state(Box::new(DummyLlm));
        let sent = Arc::new(StdMutex::new(Vec::new()));
        let mut registry = ChannelRegistry::new();
        registry.register(Arc::new(crate::web::WebAdapter));
        registry.register(Arc::new(RecordingAdapter {
            name: "feishu".into(),
            sent: sent.clone(),
        }));
        let mut app_state = (*base).clone();
        app_state.channel_registry = Arc::new(registry);
        let state = test_web_state_from_app_state(Arc::new(app_state), WebLimits::default());
        seed_test_api_key(&state, "mk_admin").await;
        seed_test_api_key_with_scopes(&state, "mk_read", &["operator.read".to_string()]).await;
        seed_test_api_key_with_scopes(
            &state,
            "mk_other",
            &["operator.read".to_string(), "operator.write".to_string()],
        )
        .await;
        seed_test_api_key_with_scopes(
            &state,
            "mk_device",
            &["operator.read".to_string(), "operator.write".to_string()],
        )
        .await;
        let plain_chat = control_chat + 500_000;
        let control_ext = format!("oc_{control_chat}");
        let plain_ext = format!("oc_{plain_chat}");
        // Non-numeric chats get a fresh internal id; that one becomes the
        // control chat.
        let control_id = call_blocking(state.app_state.db.clone(), move |db| {
            db.resolve_or_create_chat_id("feishu", &plain_ext, Some("team"), "feishu_dm")?;
            db.resolve_or_create_chat_id("feishu", &control_ext, Some("ops"), "feishu_dm")
        })
        .await
        .unwrap();
        let mut app_state = (*state.app_state).clone();
        app_state.config.control_chat_ids = vec![control_id];
        let state = WebState {
            app_state: Arc::new(app_state),
            ..state
        };
        Fixture {
            app: build_router(state.clone()),
            state,
            sent,
            control_chat,
            plain_chat,
        }
    }

    fn req(
        method: &str,
        uri: &str,
        bearer: Option<&str>,
        body: Option<serde_json::Value>,
    ) -> Request<Body> {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(token) = bearer {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        match body {
            Some(b) => builder
                .header("content-type", "application/json")
                .body(Body::from(b.to_string()))
                .unwrap(),
            None => builder.body(Body::empty()).unwrap(),
        }
    }

    async fn call(app: &Router, request: Request<Body>) -> (StatusCode, serde_json::Value, String) {
        let resp = app.clone().oneshot(request).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&bytes).to_string();
        (
            status,
            serde_json::from_str(&text).unwrap_or(serde_json::Value::Null),
            text,
        )
    }

    fn approval_body(chat: &str) -> serde_json::Value {
        json!({
            "chat": chat,
            "title": "Run cargo test?",
            "text": "bash: cargo test --offline",
            "options": [
                {"value": "approve", "label": "Approve"},
                {"value": "deny", "label": "Deny"}
            ],
        })
    }

    #[tokio::test]
    async fn code_routes_require_auth_and_write_scope() {
        let f = fixture().await;
        let chat = format!("feishu:oc_{}", f.control_chat);
        for (method, uri, body) in [
            (
                "POST",
                "/api/code/notify",
                Some(json!({"chat": chat, "text": "hi"})),
            ),
            ("POST", "/api/code/approvals", Some(approval_body(&chat))),
            ("GET", "/api/code/approvals/abc", None),
            ("DELETE", "/api/code/approvals/abc", None),
        ] {
            let (status, _, _) = call(&f.app, req(method, uri, None, body.clone())).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {uri}");
            let (status, _, _) = call(&f.app, req(method, uri, Some("wrong"), body.clone())).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {uri}");
        }
        for (uri, body) in [
            ("/api/code/notify", json!({"chat": chat, "text": "hi"})),
            ("/api/code/approvals", approval_body(&chat)),
        ] {
            let (status, _, _) = call(&f.app, req("POST", uri, Some("mk_read"), Some(body))).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{uri}");
        }
        assert!(f.sent.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn paired_device_token_can_notify_and_own_its_approvals() {
        let f = fixture().await;
        let (status, code, _) = call(
            &f.app,
            req(
                "POST",
                "/api/pairing/codes",
                Some("mk_admin"),
                Some(json!({"label": "Mac"})),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, claimed, text) = call(
            &f.app,
            req(
                "POST",
                "/api/pairing/claim",
                None,
                Some(json!({"code": code["code"], "device_name": "mccode"})),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{text}");
        let token = claimed["device_token"].as_str().unwrap().to_string();
        let control = format!("feishu:oc_{}", f.control_chat);
        let (status, _, text) = call(
            &f.app,
            req(
                "POST",
                "/api/code/notify",
                Some(&token),
                Some(json!({"chat": control, "text": "done"})),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{text}");
        let (status, created, text) = call(
            &f.app,
            req(
                "POST",
                "/api/code/approvals",
                Some(&token),
                Some(approval_body(&control)),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{text}");
        let uri = format!("/api/code/approvals/{}", created["id"].as_str().unwrap());
        let (status, polled, _) = call(&f.app, req("GET", &uri, Some(&token), None)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(polled["status"], "pending");
        // Another write-scoped caller cannot see the device's approval.
        let (status, _, _) = call(&f.app, req("GET", &uri, Some("mk_other"), None)).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _, _) = call(&f.app, req("DELETE", &uri, Some(&token), None)).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn notify_validates_and_delivers() {
        let f = fixture().await;
        let cases = [
            (
                json!({"chat": "feishu", "text": "x"}),
                StatusCode::BAD_REQUEST,
            ),
            (
                json!({"chat": "telegram:1", "text": "x"}),
                StatusCode::BAD_REQUEST,
            ),
            (
                json!({"chat": "feishu:oc_nope", "text": "x"}),
                StatusCode::NOT_FOUND,
            ),
            (
                json!({"chat": format!("feishu:oc_{}", f.plain_chat), "text": "  "}),
                StatusCode::BAD_REQUEST,
            ),
        ];
        for (body, expected) in cases {
            let (status, _, text) = call(
                &f.app,
                req(
                    "POST",
                    "/api/code/notify",
                    Some("mk_device"),
                    Some(body.clone()),
                ),
            )
            .await;
            assert_eq!(status, expected, "{body} -> {text}");
        }
        let (status, _, text) = call(
            &f.app,
            req(
                "POST",
                "/api/code/notify",
                Some("mk_device"),
                Some(json!("not an object")),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");
        assert!(f.sent.lock().unwrap().is_empty());

        // Notifications may go to any known chat, control or not.
        let chat = format!("feishu:oc_{}", f.plain_chat);
        let (status, body, text) = call(
            &f.app,
            req(
                "POST",
                "/api/code/notify",
                Some("mk_device"),
                Some(json!({"chat": chat, "title": "Checks failed", "text": "cargo test: 2 failures"})),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{text}");
        assert_eq!(body["delivery"], "delivered");
        let sent = f.sent.lock().unwrap().clone();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, format!("oc_{}", f.plain_chat));
        assert!(sent[0].1.contains("Checks failed"));
        assert!(sent[0].1.contains("cargo test: 2 failures"));
    }

    #[tokio::test]
    async fn approval_lifecycle_text_answer_and_owner_scoping() {
        let f = fixture().await;
        let control = format!("feishu:oc_{}", f.control_chat);
        let plain = format!("feishu:oc_{}", f.plain_chat);

        // Validation.
        let mut no_options = approval_body(&control);
        no_options["options"] = json!([]);
        let mut dup = approval_body(&control);
        dup["options"] = json!([{"value": "a"}, {"value": "A"}]);
        let mut no_title = approval_body(&control);
        no_title["title"] = json!("");
        for body in [no_options, dup, no_title, approval_body("web:main")] {
            let (status, _, text) = call(
                &f.app,
                req(
                    "POST",
                    "/api/code/approvals",
                    Some("mk_device"),
                    Some(body.clone()),
                ),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body} -> {text}");
        }
        // Approvals only go to control chats.
        let (status, _, text) = call(
            &f.app,
            req(
                "POST",
                "/api/code/approvals",
                Some("mk_device"),
                Some(approval_body(&plain)),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{text}");
        assert!(text.contains("control_chat_ids"));
        assert!(f.sent.lock().unwrap().is_empty());

        // Create: the card falls back to numbered text on this channel.
        let (status, created, text) = call(
            &f.app,
            req(
                "POST",
                "/api/code/approvals",
                Some("mk_device"),
                Some(approval_body(&control)),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{text}");
        assert_eq!(created["status"], "pending");
        let id = created["id"].as_str().unwrap().to_string();
        {
            let sent = f.sent.lock().unwrap();
            assert_eq!(sent.len(), 1);
            assert!(sent[0].1.contains("1. Approve"));
            assert!(sent[0].1.contains("2. Deny"));
        }

        // Another caller can neither read nor cancel it.
        let uri = format!("/api/code/approvals/{id}");
        let (status, _, _) = call(&f.app, req("GET", &uri, Some("mk_other"), None)).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _, _) = call(&f.app, req("DELETE", &uri, Some("mk_other"), None)).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, polled, _) = call(&f.app, req("GET", &uri, Some("mk_device"), None)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(polled["status"], "pending");

        // A "2" in another chat is not an answer; in the card chat it is.
        let ext_control = format!("oc_{}", f.control_chat);
        let ext_plain = format!("oc_{}", f.plain_chat);
        assert!(
            !ra::intercept_text_reply(&f.state.app_state, "feishu", &ext_plain, "eve", "2").await
        );
        assert!(
            !ra::intercept_text_reply(&f.state.app_state, "feishu", &ext_control, "ann", "hello")
                .await
        );
        assert!(
            ra::intercept_text_reply(&f.state.app_state, "feishu", &ext_control, "ann", "2").await
        );
        let (_, polled, _) = call(&f.app, req("GET", &uri, Some("mk_device"), None)).await;
        assert_eq!(polled["status"], "answered");
        assert_eq!(polled["value"], "deny");
        assert_eq!(polled["answered_by"], "ann");
        assert!(f
            .sent
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .1
            .contains("Answered: Deny"));

        // Cancelling an answered approval changes nothing.
        let (status, cancelled, _) =
            call(&f.app, req("DELETE", &uri, Some("mk_device"), None)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(cancelled["cancelled"], false);
        assert_eq!(cancelled["status"], "answered");
    }

    #[tokio::test]
    async fn approval_cancel_notes_the_chat_and_admin_can_read() {
        let f = fixture().await;
        let control = format!("feishu:oc_{}", f.control_chat);
        let mut body = approval_body(&control);
        body["ttl_secs"] = json!(1);
        let (status, created, text) = call(
            &f.app,
            req("POST", "/api/code/approvals", Some("mk_device"), Some(body)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{text}");
        let id = created["id"].as_str().unwrap().to_string();
        let uri = format!("/api/code/approvals/{id}");
        // TTL is clamped up to the minimum, so it is still pending.
        let (_, polled, _) = call(&f.app, req("GET", &uri, Some("mk_admin"), None)).await;
        assert_eq!(polled["status"], "pending");
        let (status, cancelled, _) = call(
            &f.app,
            req(
                "DELETE",
                &format!("{uri}?reason=answered_locally"),
                Some("mk_device"),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(cancelled["cancelled"], true);
        assert_eq!(cancelled["status"], "cancelled");
        assert!(f
            .sent
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .1
            .contains("answered in the terminal"));
        // A late reply no longer resolves it and goes to the agent path.
        let ext = format!("oc_{}", f.control_chat);
        assert!(!ra::intercept_text_reply(&f.state.app_state, "feishu", &ext, "ann", "1").await);
        let (status, _, _) = call(
            &f.app,
            req(
                "GET",
                "/api/code/approvals/missing",
                Some("mk_device"),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}
