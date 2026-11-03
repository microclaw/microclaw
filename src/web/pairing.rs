//! Server device pairing for local MicroClaw clients.
//!
//! An operator mints a short-lived, single-use pairing code (Web console
//! Access tab or `POST /api/pairing/codes`). A client claims it once
//! with `POST /api/pairing/claim` and receives a device token that it then
//! presents as a Bearer token exactly like an API key. Device tokens carry
//! `operator.read` + `operator.write` only, are stored hashed in
//! `paired_devices`, and can be revoked at any time from the console.

use super::*;

/// Label used when the operator does not name the pairing code.
const DEFAULT_PAIRING_LABEL: &str = "MicroClaw client";

/// Characters used for pairing codes: no 0/O/1/I so the code survives being
/// read aloud or typed from a phone screen.
const PAIRING_CODE_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
pub(crate) const PAIRING_CODE_LEN: usize = 8;
const PAIRING_CODE_DEFAULT_MINUTES: i64 = 10;
const PAIRING_CODE_MAX_MINUTES: i64 = 60;
/// Server-wide cap on failed claim attempts per window.
const PAIRING_CLAIM_MAX_FAILURES: usize = 10;
const PAIRING_CLAIM_WINDOW: Duration = Duration::from_secs(60);
pub(crate) const DEVICE_SCOPES: [&str; 2] = ["operator.read", "operator.write"];

#[derive(Clone, Debug)]
pub(crate) struct PendingPairingCode {
    pub(crate) label: String,
    pub(crate) issued_by: String,
    pub(crate) expires_at: chrono::DateTime<chrono::Utc>,
}

/// In-memory pairing state. Codes are deliberately not persisted: a Server
/// restart invalidates any code that was not claimed, which is the safe
/// default for a credential that only exists to bootstrap a durable one.
#[derive(Clone, Default)]
pub(crate) struct PairingHub {
    pub(crate) codes: Arc<Mutex<HashMap<String, PendingPairingCode>>>,
    pub(crate) failed_claims: Arc<Mutex<VecDeque<Instant>>>,
}

impl PairingHub {
    pub(crate) async fn issue(
        &self,
        label: String,
        issued_by: String,
        ttl: chrono::Duration,
    ) -> (String, chrono::DateTime<chrono::Utc>) {
        let expires_at = chrono::Utc::now() + ttl;
        let mut guard = self.codes.lock().await;
        let now = chrono::Utc::now();
        guard.retain(|_, pending| pending.expires_at > now);
        let code = loop {
            let candidate = generate_pairing_code();
            if !guard.contains_key(&candidate) {
                break candidate;
            }
        };
        guard.insert(
            code.clone(),
            PendingPairingCode {
                label,
                issued_by,
                expires_at,
            },
        );
        (code, expires_at)
    }

    /// Atomically consume a code. Returns `None` for unknown or expired codes.
    pub(crate) async fn claim(&self, code: &str) -> Option<PendingPairingCode> {
        let mut guard = self.codes.lock().await;
        let pending = guard.remove(code)?;
        if pending.expires_at <= chrono::Utc::now() {
            return None;
        }
        Some(pending)
    }

    pub(crate) async fn pending_count(&self) -> usize {
        let mut guard = self.codes.lock().await;
        let now = chrono::Utc::now();
        guard.retain(|_, pending| pending.expires_at > now);
        guard.len()
    }

    /// Returns false once the failed-claim budget for the window is spent.
    pub(crate) async fn allow_claim_attempt(&self) -> bool {
        let mut guard = self.failed_claims.lock().await;
        let now = Instant::now();
        while guard
            .front()
            .is_some_and(|t| now.duration_since(*t) > PAIRING_CLAIM_WINDOW)
        {
            guard.pop_front();
        }
        guard.len() < PAIRING_CLAIM_MAX_FAILURES
    }

    pub(crate) async fn record_failed_claim(&self) {
        let mut guard = self.failed_claims.lock().await;
        guard.push_back(Instant::now());
    }
}

pub(crate) fn generate_pairing_code() -> String {
    // uuid v4 gives 16 random bytes; 256 is a multiple of 32, so masking a
    // byte to 5 bits keeps every alphabet character equally likely.
    let bytes = *uuid::Uuid::new_v4().as_bytes();
    bytes
        .iter()
        .take(PAIRING_CODE_LEN)
        .map(|b| PAIRING_CODE_ALPHABET[(b & 31) as usize] as char)
        .collect()
}

pub(crate) fn normalize_pairing_code(raw: &str) -> String {
    raw.trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

pub(crate) fn device_actor(device_id: &str) -> String {
    format!("device:{device_id}")
}

pub(super) async fn api_pairing_create_code(
    headers: HeaderMap,
    State(state): State<WebState>,
    Json(body): Json<CreatePairingCodeRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    let identity = require_scope(&state, &headers, AuthScope::Admin).await?;
    let label = body
        .label
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .unwrap_or_else(|| DEFAULT_PAIRING_LABEL.to_string());
    let minutes = body
        .expires_minutes
        .unwrap_or(PAIRING_CODE_DEFAULT_MINUTES)
        .clamp(1, PAIRING_CODE_MAX_MINUTES);
    let (code, expires_at) = state
        .pairing_hub
        .issue(
            label.clone(),
            identity.actor.clone(),
            chrono::Duration::minutes(minutes),
        )
        .await;
    audit_log(
        &state,
        "operator",
        &identity.actor,
        "pairing.code.create",
        Some(&label),
        "ok",
        None,
    )
    .await;
    Ok(Json(json!({
        "ok": true,
        "code": code,
        "label": label,
        "expires_at": expires_at.to_rfc3339(),
        "expires_minutes": minutes,
    })))
}

pub(super) async fn api_pairing_claim(
    State(state): State<WebState>,
    Json(body): Json<ClaimPairingCodeRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    let has_password = call_blocking(state.app_state.db.clone(), |db| db.get_auth_password_hash())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .is_some();
    if !has_password {
        // Pairing codes are only minted by an authenticated operator, which
        // cannot exist before the console password is set.
        return Err((
            StatusCode::UNAUTHORIZED,
            "set the console password before pairing devices".into(),
        ));
    }
    let code = normalize_pairing_code(&body.code);
    if code.len() != PAIRING_CODE_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            "pairing code must be 8 characters".into(),
        ));
    }
    let device_name = body.device_name.trim().to_string();
    if device_name.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "device_name is required".into()));
    }
    let device_name: String = device_name.chars().take(80).collect();
    let platform = body
        .platform
        .map(|p| p.trim().to_ascii_lowercase())
        .filter(|p| !p.is_empty())
        .map(|p| p.chars().take(32).collect::<String>());

    if !state.pairing_hub.allow_claim_attempt().await {
        audit_log(
            &state,
            "auth",
            "anonymous",
            "pairing.claim",
            None,
            "deny",
            Some("rate_limited"),
        )
        .await;
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            "too many pairing attempts".into(),
        ));
    }
    let Some(pending) = state.pairing_hub.claim(&code).await else {
        state.pairing_hub.record_failed_claim().await;
        audit_log(
            &state,
            "auth",
            "anonymous",
            "pairing.claim",
            None,
            "deny",
            Some("invalid_or_expired_code"),
        )
        .await;
        return Err((
            StatusCode::NOT_FOUND,
            "pairing code is invalid or expired".into(),
        ));
    };

    let device_id = uuid::Uuid::new_v4().to_string();
    let raw_token = format!("mcd_{}", uuid::Uuid::new_v4().simple());
    let prefix = raw_token.chars().take(10).collect::<String>();
    let token_hash = sha256_hex(&raw_token);
    let label = if pending.label.trim().is_empty() || pending.label == DEFAULT_PAIRING_LABEL {
        device_name.clone()
    } else {
        format!("{} · {}", pending.label, device_name)
    };
    let device_id_for_save = device_id.clone();
    let label_for_save = label.clone();
    let platform_for_save = platform.clone();
    let prefix_for_save = prefix.clone();
    call_blocking(state.app_state.db.clone(), move |db| {
        db.create_paired_device(
            &device_id_for_save,
            &label_for_save,
            platform_for_save.as_deref(),
            &token_hash,
            &prefix_for_save,
        )
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    audit_log(
        &state,
        "auth",
        &device_actor(&device_id),
        "pairing.claim",
        Some(&label),
        "ok",
        Some(&format!("issued_by={}", pending.issued_by)),
    )
    .await;
    Ok(Json(json!({
        "ok": true,
        "device_id": device_id,
        "device_token": raw_token,
        "prefix": prefix,
        "label": label,
        "platform": platform,
        "scopes": DEVICE_SCOPES,
        "server": { "version": env!("CARGO_PKG_VERSION") },
    })))
}

pub(super) async fn api_pairing_devices(
    headers: HeaderMap,
    State(state): State<WebState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    require_scope(&state, &headers, AuthScope::Admin).await?;
    let devices = call_blocking(state.app_state.db.clone(), |db| db.list_paired_devices())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let devices_json = devices
        .into_iter()
        .map(|d| {
            json!({
                "id": d.id,
                "device_id": d.device_id,
                "label": d.label,
                "platform": d.platform,
                "prefix": d.prefix,
                "created_at": d.created_at,
                "last_seen_at": d.last_seen_at,
                "revoked_at": d.revoked_at,
                "scopes": DEVICE_SCOPES,
            })
        })
        .collect::<Vec<_>>();
    let pending_codes = state.pairing_hub.pending_count().await;
    Ok(Json(json!({
        "ok": true,
        "devices": devices_json,
        "pending_codes": pending_codes,
    })))
}

pub(super) async fn api_pairing_revoke_device(
    headers: HeaderMap,
    State(state): State<WebState>,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    let identity = require_scope(&state, &headers, AuthScope::Admin).await?;
    let revoked = call_blocking(state.app_state.db.clone(), move |db| {
        db.revoke_paired_device(id)
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    audit_log(
        &state,
        "operator",
        &identity.actor,
        "pairing.device.revoke",
        Some(&id.to_string()),
        if revoked { "ok" } else { "miss" },
        None,
    )
    .await;
    Ok(Json(json!({"ok": true, "revoked": revoked})))
}

pub(super) async fn api_pairing_whoami(
    headers: HeaderMap,
    State(state): State<WebState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    let identity = require_scope(&state, &headers, AuthScope::Read).await?;
    let device = match identity.actor.strip_prefix("device:") {
        Some(device_id) => {
            let device_id = device_id.to_string();
            call_blocking(state.app_state.db.clone(), move |db| {
                db.get_paired_device_by_device_id(&device_id)
            })
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .map(|d| {
                json!({
                    "device_id": d.device_id,
                    "label": d.label,
                    "platform": d.platform,
                    "created_at": d.created_at,
                })
            })
        }
        None => None,
    };
    Ok(Json(json!({
        "ok": true,
        "actor": identity.actor,
        "scopes": identity.scopes,
        "device": device,
        "server": { "version": env!("CARGO_PKG_VERSION") },
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use crate::web::test_prelude::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    async fn json_body(resp: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    }

    fn req(method: &str, uri: &str, bearer: Option<&str>, body: Option<String>) -> Request<Body> {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(token) = bearer {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        match body {
            Some(b) => builder
                .header("content-type", "application/json")
                .body(Body::from(b))
                .unwrap(),
            None => builder.body(Body::empty()).unwrap(),
        }
    }

    async fn mint_code(app: &Router, admin: &str) -> String {
        let resp = app
            .clone()
            .oneshot(req(
                "POST",
                "/api/pairing/codes",
                Some(admin),
                Some(r#"{"label":"Laptop","expires_minutes":5}"#.into()),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = json_body(resp).await;
        assert_eq!(v["expires_minutes"], 5);
        v["code"].as_str().unwrap().to_string()
    }

    async fn claim(app: &Router, code: &str) -> (StatusCode, serde_json::Value) {
        let resp = app
            .clone()
            .oneshot(req(
                "POST",
                "/api/pairing/claim",
                None,
                Some(
                    json!({"code": code, "device_name": "Everett's Mac", "platform": "macOS"})
                        .to_string(),
                ),
            ))
            .await
            .unwrap();
        let status = resp.status();
        (status, json_body(resp).await)
    }

    #[tokio::test]
    async fn pairing_full_lifecycle_claim_use_list_revoke() {
        let web_state = test_web_state(Box::new(DummyLlm), WebLimits::default());
        seed_test_api_key(&web_state, "mk_admin").await;
        let app = build_router(web_state.clone());

        let code = mint_code(&app, "mk_admin").await;
        assert_eq!(code.len(), PAIRING_CODE_LEN);

        // Claim with separators and lowercase still works.
        let typed = format!("{}-{}", &code[..4].to_lowercase(), &code[4..]);
        let (status, claimed) = claim(&app, &typed).await;
        assert_eq!(status, StatusCode::OK, "{claimed}");
        let token = claimed["device_token"].as_str().unwrap().to_string();
        assert!(token.starts_with("mcd_"));
        let device_id = claimed["device_id"].as_str().unwrap().to_string();
        assert_eq!(claimed["label"], "Laptop · Everett's Mac");
        assert_eq!(claimed["platform"], "macos");
        assert_eq!(
            claimed["scopes"],
            json!(["operator.read", "operator.write"])
        );
        assert_eq!(claimed["server"]["version"], env!("CARGO_PKG_VERSION"));

        // A code is single use.
        let (status, _) = claim(&app, &code).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // The device token authenticates as device:<id> with read+write.
        let resp = app
            .clone()
            .oneshot(req("GET", "/api/pairing/whoami", Some(&token), None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let who = json_body(resp).await;
        assert_eq!(who["actor"], format!("device:{device_id}"));
        assert_eq!(who["device"]["label"], "Laptop · Everett's Mac");
        assert_eq!(who["scopes"], json!(["operator.read", "operator.write"]));

        // It can submit and follow a run.
        let resp = app
            .clone()
            .oneshot(req(
                "POST",
                "/api/send_stream",
                Some(&token),
                Some(r#"{"session_key":"work:s1","sender_name":"Mac","message":"hi"}"#.into()),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let run_id = json_body(resp).await["run_id"]
            .as_str()
            .unwrap()
            .to_string();
        let resp = app
            .clone()
            .oneshot(req(
                "GET",
                &format!("/api/stream?run_id={run_id}"),
                Some(&token),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&bytes).contains("event: done"));

        // But it is not an operator: no admin surface.
        for uri in ["/api/auth/api_keys", "/api/pairing/devices"] {
            let resp = app
                .clone()
                .oneshot(req("GET", uri, Some(&token), None))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{uri}");
        }
        let resp = app
            .clone()
            .oneshot(req(
                "POST",
                "/api/pairing/codes",
                Some(&token),
                Some("{}".into()),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // Operators see it listed, then revoke it.
        let resp = app
            .clone()
            .oneshot(req("GET", "/api/pairing/devices", Some("mk_admin"), None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let listed = json_body(resp).await;
        let devices = listed["devices"].as_array().unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0]["device_id"], device_id);
        assert!(devices[0]["last_seen_at"].is_string());
        assert!(devices[0]["revoked_at"].is_null());
        assert_eq!(listed["pending_codes"], 0);
        let row_id = devices[0]["id"].as_i64().unwrap();

        let resp = app
            .clone()
            .oneshot(req(
                "DELETE",
                &format!("/api/pairing/devices/{row_id}"),
                Some("mk_admin"),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(json_body(resp).await["revoked"], true);

        let resp = app
            .clone()
            .oneshot(req("GET", "/api/pairing/whoami", Some(&token), None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let resp = app
            .clone()
            .oneshot(req(
                "POST",
                "/api/send_stream",
                Some(&token),
                Some(r#"{"session_key":"work:s1","message":"hi"}"#.into()),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Audit trail records the claim under the device actor.
        let events = call_blocking(web_state.app_state.db.clone(), |db| {
            db.list_audit_logs(None, 50)
        })
        .await
        .unwrap();
        assert!(events.iter().any(|e| e.action == "pairing.claim"
            && e.actor == format!("device:{device_id}")
            && e.status == "ok"));
        assert!(events
            .iter()
            .any(|e| e.action == "pairing.device.revoke" && e.status == "ok"));
    }

    #[tokio::test]
    async fn pairing_claim_rejects_bad_codes_and_rate_limits() {
        let web_state = test_web_state(Box::new(DummyLlm), WebLimits::default());
        seed_test_api_key(&web_state, "mk_admin").await;
        let app = build_router(web_state.clone());

        let (status, _) = claim(&app, "short").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let resp = app
            .clone()
            .oneshot(req(
                "POST",
                "/api/pairing/claim",
                None,
                Some(r#"{"code":"ABCDEFGH","device_name":"   "}"#.into()),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        for _ in 0..PAIRING_CLAIM_MAX_FAILURES {
            let (status, _) = claim(&app, "ABCDEFGH").await;
            assert_eq!(status, StatusCode::NOT_FOUND);
        }
        let (status, _) = claim(&app, "ABCDEFGH").await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        // Even a valid code is refused while the budget is spent.
        let code = mint_code(&app, "mk_admin").await;
        let (status, _) = claim(&app, &code).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn pairing_claim_requires_console_password() {
        let web_state = test_web_state(Box::new(DummyLlm), WebLimits::default());
        let app = build_router(web_state);
        let (status, _) = claim(&app, "ABCDEFGH").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn pairing_code_requires_admin_scope() {
        let web_state = test_web_state(Box::new(DummyLlm), WebLimits::default());
        seed_test_api_key_with_scopes(
            &web_state,
            "mk_writer",
            &["operator.read".to_string(), "operator.write".to_string()],
        )
        .await;
        let app = build_router(web_state);
        let resp = app
            .oneshot(req(
                "POST",
                "/api/pairing/codes",
                Some("mk_writer"),
                Some("{}".into()),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn run_cancel_is_owner_scoped_and_aborts_active_run() {
        let web_state = test_web_state(Box::new(SlowLlm { sleep_ms: 1_500 }), WebLimits::default());
        seed_test_api_key(&web_state, "mk_admin").await;
        let app = build_router(web_state.clone());
        let chat_id = unique_test_chat_id();
        let session_key = format!("chat:{chat_id}");
        let session_key_for_db = session_key.clone();
        call_blocking(web_state.app_state.db.clone(), move |db| {
            db.upsert_chat(chat_id, Some(&session_key_for_db), "web")
        })
        .await
        .unwrap();

        let code = mint_code(&app, "mk_admin").await;
        let (_, claimed) = claim(&app, &code).await;
        let token_a = claimed["device_token"].as_str().unwrap().to_string();
        let code = mint_code(&app, "mk_admin").await;
        let (_, claimed) = claim(&app, &code).await;
        let token_b = claimed["device_token"].as_str().unwrap().to_string();

        let resp = app
            .clone()
            .oneshot(req(
                "POST",
                "/api/send_stream",
                Some(&token_a),
                Some(format!(
                    r#"{{"session_key":"{session_key}","sender_name":"a","message":"slow"}}"#
                )),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let run_id = json_body(resp).await["run_id"]
            .as_str()
            .unwrap()
            .to_string();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Another device cannot cancel it; unknown runs are 404.
        let resp = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/runs/{run_id}/cancel"),
                Some(&token_b),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let resp = app
            .clone()
            .oneshot(req("POST", "/api/runs/nope/cancel", Some(&token_a), None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        // The owner can.
        let resp = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/runs/{run_id}/cancel"),
                Some(&token_a),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = json_body(resp).await;
        assert_eq!(v["aborted"], true, "{v}");

        let mut finished = false;
        for _ in 0..40 {
            let (done, _) = web_state.run_hub.status(&run_id, "", true).await.unwrap();
            if done {
                finished = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(finished, "run should finish after cancel");
        let resp = app
            .clone()
            .oneshot(req(
                "GET",
                &format!("/api/stream?run_id={run_id}"),
                Some(&token_a),
                None,
            ))
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("event: aborted"), "{text}");

        // Cancelling a finished run is a no-op, not an error.
        let resp = app
            .oneshot(req(
                "POST",
                &format!("/api/runs/{run_id}/cancel"),
                Some(&token_a),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(json_body(resp).await["aborted"], false);
    }

    #[test]
    fn pairing_codes_use_the_unambiguous_alphabet() {
        for _ in 0..200 {
            let code = generate_pairing_code();
            assert_eq!(code.len(), PAIRING_CODE_LEN);
            assert!(
                code.bytes().all(|b| PAIRING_CODE_ALPHABET.contains(&b)),
                "{code}"
            );
            assert!(!code.contains(['0', 'O', '1', 'I']));
        }
    }

    #[test]
    fn normalize_pairing_code_strips_separators_and_case() {
        assert_eq!(normalize_pairing_code(" ab12-cd34 "), "AB12CD34");
        assert_eq!(normalize_pairing_code("AB12 CD34"), "AB12CD34");
    }

    #[tokio::test]
    async fn pairing_hub_codes_are_single_use_and_expire() {
        let hub = PairingHub::default();
        let (code, _) = hub
            .issue("lab".into(), "op".into(), chrono::Duration::minutes(5))
            .await;
        assert_eq!(hub.pending_count().await, 1);
        assert!(hub.claim(&code).await.is_some());
        assert!(hub.claim(&code).await.is_none(), "second claim must fail");
        assert_eq!(hub.pending_count().await, 0);

        let (expired, _) = hub
            .issue("lab".into(), "op".into(), chrono::Duration::seconds(-1))
            .await;
        assert!(hub.claim(&expired).await.is_none());
    }

    #[tokio::test]
    async fn pairing_hub_rate_limits_failed_claims() {
        let hub = PairingHub::default();
        for _ in 0..PAIRING_CLAIM_MAX_FAILURES {
            assert!(hub.allow_claim_attempt().await);
            hub.record_failed_claim().await;
        }
        assert!(!hub.allow_claim_attempt().await);
    }
}
