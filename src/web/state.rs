use super::*;

pub(crate) const DEFAULT_WEB_PASSWORD: &str = "helloworld";

pub struct WebAdapter;

#[async_trait::async_trait]
impl ChannelAdapter for WebAdapter {
    fn name(&self) -> &str {
        "web"
    }

    fn chat_type_routes(&self) -> Vec<(&str, ConversationKind)> {
        vec![("web", ConversationKind::Private)]
    }

    fn is_local_only(&self) -> bool {
        true
    }

    fn allows_cross_chat(&self) -> bool {
        false
    }

    async fn send_text(&self, _external_chat_id: &str, _text: &str) -> Result<(), String> {
        Ok(())
    }
}

#[derive(Clone)]
pub(crate) struct WebState {
    pub(crate) app_state: Arc<AppState>,
    pub(crate) bootstrap_token: Arc<Mutex<Option<String>>>,
    pub(crate) run_hub: RunHub,
    pub(crate) session_hub: SessionHub,
    pub(crate) request_hub: RequestHub,
    pub(crate) auth_hub: AuthHub,
    pub(crate) metrics: Arc<Mutex<WebMetrics>>,
    pub(crate) otlp: Option<Arc<OtlpMetricExporter>>,
    pub(crate) limits: WebLimits,
}

#[derive(Clone, Default)]
pub(crate) struct AuthHub {
    pub(crate) login_buckets: Arc<Mutex<HashMap<String, VecDeque<Instant>>>>,
    pub(crate) api_key_buckets: Arc<Mutex<HashMap<String, VecDeque<Instant>>>>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct WebMetrics {
    pub(crate) http_requests: i64,
    pub(crate) request_ok: i64,
    pub(crate) request_error: i64,
    pub(crate) request_latency_ms: VecDeque<i64>,
    pub(crate) llm_completions: i64,
    pub(crate) llm_input_tokens: i64,
    pub(crate) llm_output_tokens: i64,
    pub(crate) tool_executions: i64,
    pub(crate) tool_success: i64,
    pub(crate) tool_error: i64,
    pub(crate) tool_policy_blocks: i64,
    pub(crate) mcp_calls: i64,
    pub(crate) mcp_rate_limited_rejections: i64,
    pub(crate) mcp_bulkhead_rejections: i64,
    pub(crate) mcp_circuit_open_rejections: i64,
}

#[derive(Clone, Debug)]
pub(crate) struct RunEvent {
    pub(crate) id: u64,
    pub(crate) event: String,
    pub(crate) data: String,
}

#[derive(Clone, Default)]
pub(crate) struct RunHub {
    pub(crate) channels: Arc<Mutex<HashMap<String, RunChannel>>>,
}

#[derive(Clone, Default)]
pub(crate) struct SessionHub {
    pub(crate) locks: Arc<Mutex<HashMap<String, SessionLockEntry>>>,
}

#[derive(Clone, Debug)]
pub(crate) struct WebLimits {
    pub(crate) max_inflight_per_session: usize,
    pub(crate) max_requests_per_window: usize,
    pub(crate) rate_window: Duration,
    pub(crate) run_history_limit: usize,
    pub(crate) session_idle_ttl: Duration,
}

impl Default for WebLimits {
    fn default() -> Self {
        Self {
            max_inflight_per_session: 10,
            max_requests_per_window: 8,
            rate_window: Duration::from_secs(10),
            run_history_limit: 512,
            session_idle_ttl: Duration::from_secs(300),
        }
    }
}

impl WebLimits {
    pub(crate) fn from_config(cfg: &Config) -> Self {
        Self {
            max_inflight_per_session: cfg.web_max_inflight_per_session,
            max_requests_per_window: cfg.web_max_requests_per_window,
            rate_window: Duration::from_secs(cfg.web_rate_window_seconds),
            run_history_limit: cfg.web_run_history_limit,
            session_idle_ttl: Duration::from_secs(cfg.web_session_idle_ttl_seconds),
        }
    }
}

#[derive(Clone, Default)]
pub(crate) struct RequestHub {
    pub(crate) quotas: Arc<Mutex<RequestQuotas>>,
}

#[derive(Default)]
pub(crate) struct RequestQuotas {
    pub(crate) sessions: HashMap<String, SessionQuota>,
    pub(crate) actors: HashMap<String, SessionQuota>,
}

pub(crate) struct SessionQuota {
    pub(crate) inflight: usize,
    pub(crate) recent: VecDeque<Instant>,
    pub(crate) last_touch: Instant,
}

impl Default for SessionQuota {
    fn default() -> Self {
        Self {
            inflight: 0,
            recent: VecDeque::new(),
            last_touch: Instant::now(),
        }
    }
}

pub(crate) struct SessionLockEntry {
    pub(crate) lock: Arc<tokio::sync::Mutex<()>>,
    pub(crate) last_touch: Instant,
}

#[derive(Clone)]
pub(crate) struct RunChannel {
    pub(crate) sender: broadcast::Sender<RunEvent>,
    pub(crate) history: VecDeque<RunEvent>,
    pub(crate) next_id: u64,
    pub(crate) done: bool,
    pub(crate) aborted: bool,
    pub(crate) owner_actor: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RunLookupError {
    NotFound,
    Forbidden,
}

impl RunHub {
    pub(crate) async fn create(&self, run_id: &str, owner_actor: String) {
        let (tx, _) = broadcast::channel(512);
        let mut guard = self.channels.lock().await;
        guard.insert(
            run_id.to_string(),
            RunChannel {
                sender: tx,
                history: VecDeque::new(),
                next_id: 1,
                done: false,
                aborted: false,
                owner_actor,
            },
        );
    }

    pub(crate) async fn publish(
        &self,
        run_id: &str,
        event: &str,
        data: String,
        history_limit: usize,
    ) {
        let mut guard = self.channels.lock().await;
        let Some(channel) = guard.get_mut(run_id) else {
            return;
        };

        let evt = RunEvent {
            id: channel.next_id,
            event: event.to_string(),
            data,
        };
        channel.next_id = channel.next_id.saturating_add(1);
        if channel.history.len() >= history_limit {
            let _ = channel.history.pop_front();
        }
        channel.history.push_back(evt.clone());
        if evt.event == "done" || evt.event == "error" {
            channel.done = true;
        }
        if evt.event == "aborted" {
            channel.done = true;
            channel.aborted = true;
        }
        let _ = channel.sender.send(evt);
    }

    pub(crate) async fn subscribe_with_replay(
        &self,
        run_id: &str,
        last_event_id: Option<u64>,
        requester_actor: &str,
        is_admin: bool,
    ) -> Result<
        (
            broadcast::Receiver<RunEvent>,
            Vec<RunEvent>,
            bool,
            bool,
            Option<u64>,
        ),
        RunLookupError,
    > {
        let guard = self.channels.lock().await;
        let Some(channel) = guard.get(run_id) else {
            return Err(RunLookupError::NotFound);
        };
        if !is_admin && channel.owner_actor != requester_actor {
            return Err(RunLookupError::Forbidden);
        }
        let oldest_event_id = channel.history.front().map(|e| e.id);
        let replay_truncated = matches!(
            (last_event_id, oldest_event_id),
            (Some(last), Some(oldest)) if last.saturating_add(1) < oldest
        );
        let replay = channel
            .history
            .iter()
            .filter(|e| last_event_id.is_none_or(|id| e.id > id))
            .cloned()
            .collect::<Vec<_>>();
        Ok((
            channel.sender.subscribe(),
            replay,
            channel.done,
            replay_truncated,
            oldest_event_id,
        ))
    }

    pub(crate) async fn status(
        &self,
        run_id: &str,
        requester_actor: &str,
        is_admin: bool,
    ) -> Result<(bool, u64), RunLookupError> {
        let guard = self.channels.lock().await;
        let Some(channel) = guard.get(run_id) else {
            return Err(RunLookupError::NotFound);
        };
        if !is_admin && channel.owner_actor != requester_actor {
            return Err(RunLookupError::Forbidden);
        }
        Ok((channel.done, channel.next_id.saturating_sub(1)))
    }

    pub(crate) async fn remove_later(&self, run_id: String, after_seconds: u64) {
        let channels = self.channels.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(after_seconds)).await;
            let mut guard = channels.lock().await;
            guard.remove(&run_id);
        });
    }
}

impl SessionHub {
    pub(crate) async fn lock_for(
        &self,
        session_key: &str,
        limits: &WebLimits,
    ) -> Arc<tokio::sync::Mutex<()>> {
        let now = Instant::now();
        let mut guard = self.locks.lock().await;
        guard.retain(|key, entry| {
            if key == session_key {
                return true;
            }
            let stale = now.duration_since(entry.last_touch) > limits.session_idle_ttl;
            // Remove only stale + uncontended locks.
            !(stale && Arc::strong_count(&entry.lock) == 1 && entry.lock.try_lock().is_ok())
        });
        guard
            .entry(session_key.to_string())
            .and_modify(|entry| entry.last_touch = now)
            .or_insert_with(|| SessionLockEntry {
                lock: Arc::new(tokio::sync::Mutex::new(())),
                last_touch: now,
            })
            .lock
            .clone()
    }
}

impl RequestHub {
    const MAX_BUCKET_KEYS: usize = 4096;

    pub(crate) fn prune_quota(quota: &mut SessionQuota, now: Instant, limits: &WebLimits) {
        while let Some(ts) = quota.recent.front() {
            if now.duration_since(*ts) > limits.rate_window {
                let _ = quota.recent.pop_front();
            } else {
                break;
            }
        }
    }

    pub(crate) fn prune_map(
        map: &mut HashMap<String, SessionQuota>,
        now: Instant,
        limits: &WebLimits,
    ) {
        map.retain(|_, quota| {
            Self::prune_quota(quota, now, limits);
            quota.inflight != 0
                || (!quota.recent.is_empty()
                    && now.duration_since(quota.last_touch) <= limits.session_idle_ttl)
        });
    }

    pub(crate) async fn active_sessions(&self) -> usize {
        self.quotas.lock().await.sessions.len()
    }

    pub(crate) async fn begin(
        &self,
        session_key: &str,
        actor: &str,
        limits: &WebLimits,
    ) -> Result<(), (StatusCode, String)> {
        let now = Instant::now();
        let mut guard = self.quotas.lock().await;
        Self::prune_map(&mut guard.sessions, now, limits);
        Self::prune_map(&mut guard.actors, now, limits);

        if !guard.sessions.contains_key(session_key)
            && guard.sessions.len() >= Self::MAX_BUCKET_KEYS
        {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                "too many active session limiter buckets".into(),
            ));
        }
        if !guard.actors.contains_key(actor) && guard.actors.len() >= Self::MAX_BUCKET_KEYS {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                "too many active actor limiter buckets".into(),
            ));
        }

        {
            let session_quota = guard.sessions.entry(session_key.to_string()).or_default();
            Self::prune_quota(session_quota, now, limits);
            session_quota.last_touch = now;
            if session_quota.inflight >= limits.max_inflight_per_session {
                return Err((
                    StatusCode::TOO_MANY_REQUESTS,
                    "too many concurrent requests for session".into(),
                ));
            }
            if session_quota.recent.len() >= limits.max_requests_per_window {
                return Err((
                    StatusCode::TOO_MANY_REQUESTS,
                    "rate limit exceeded for session".into(),
                ));
            }
        }

        {
            let actor_quota = guard.actors.entry(actor.to_string()).or_default();
            Self::prune_quota(actor_quota, now, limits);
            actor_quota.last_touch = now;
            if actor_quota.inflight >= limits.max_inflight_per_session {
                return Err((
                    StatusCode::TOO_MANY_REQUESTS,
                    "too many concurrent requests for actor".into(),
                ));
            }
            if actor_quota.recent.len() >= limits.max_requests_per_window {
                return Err((
                    StatusCode::TOO_MANY_REQUESTS,
                    "rate limit exceeded for actor".into(),
                ));
            }
        }

        if let Some(session_quota) = guard.sessions.get_mut(session_key) {
            session_quota.inflight += 1;
            session_quota.recent.push_back(now);
        }
        if let Some(actor_quota) = guard.actors.get_mut(actor) {
            actor_quota.inflight += 1;
            actor_quota.recent.push_back(now);
        }
        Ok(())
    }

    pub(crate) async fn end_with_limits(&self, session_key: &str, actor: &str, limits: &WebLimits) {
        let now = Instant::now();
        let mut guard = self.quotas.lock().await;
        if let Some(quota) = guard.sessions.get_mut(session_key) {
            Self::prune_quota(quota, now, limits);
            quota.inflight = quota.inflight.saturating_sub(1);
            quota.last_touch = now;
        }
        if let Some(quota) = guard.actors.get_mut(actor) {
            Self::prune_quota(quota, now, limits);
            quota.inflight = quota.inflight.saturating_sub(1);
            quota.last_touch = now;
        }
        Self::prune_map(&mut guard.sessions, now, limits);
        Self::prune_map(&mut guard.actors, now, limits);
    }
}

impl AuthHub {
    const MAX_BUCKET_KEYS: usize = 4096;

    pub(crate) fn prune_buckets(
        buckets: &mut HashMap<String, VecDeque<Instant>>,
        now: Instant,
        window: Duration,
        max_keys: usize,
    ) {
        buckets.retain(|_, bucket| {
            while let Some(ts) = bucket.front() {
                if now.duration_since(*ts) > window {
                    let _ = bucket.pop_front();
                } else {
                    break;
                }
            }
            !bucket.is_empty()
        });
        if buckets.len() <= max_keys {
            return;
        }
        let mut by_oldest = buckets
            .iter()
            .filter_map(|(k, bucket)| bucket.back().copied().map(|ts| (k.clone(), ts)))
            .collect::<Vec<_>>();
        by_oldest.sort_by_key(|(_, ts)| *ts);
        let remove_n = buckets.len().saturating_sub(max_keys);
        for (k, _) in by_oldest.into_iter().take(remove_n) {
            let _ = buckets.remove(&k);
        }
    }

    pub(crate) async fn allow_login_attempt(
        &self,
        client_key: &str,
        max_attempts: usize,
        window: Duration,
    ) -> bool {
        let now = Instant::now();
        let mut guard = self.login_buckets.lock().await;
        Self::prune_buckets(&mut guard, now, window, Self::MAX_BUCKET_KEYS);
        if !guard.contains_key(client_key) && guard.len() >= Self::MAX_BUCKET_KEYS {
            return false;
        }
        let bucket = guard.entry(client_key.to_string()).or_default();
        while let Some(ts) = bucket.front() {
            if now.duration_since(*ts) > window {
                let _ = bucket.pop_front();
            } else {
                break;
            }
        }
        if bucket.len() >= max_attempts {
            return false;
        }
        bucket.push_back(now);
        true
    }

    pub(crate) async fn allow_api_key_request(
        &self,
        api_key_actor: &str,
        max_requests: usize,
        window: Duration,
    ) -> bool {
        let now = Instant::now();
        let mut guard = self.api_key_buckets.lock().await;
        Self::prune_buckets(&mut guard, now, window, Self::MAX_BUCKET_KEYS);
        if !guard.contains_key(api_key_actor) && guard.len() >= Self::MAX_BUCKET_KEYS {
            return false;
        }
        let bucket = guard.entry(api_key_actor.to_string()).or_default();
        while let Some(ts) = bucket.front() {
            if now.duration_since(*ts) > window {
                let _ = bucket.pop_front();
            } else {
                break;
            }
        }
        if bucket.len() >= max_requests {
            return false;
        }
        bucket.push_back(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use crate::web::test_prelude::*;

    #[tokio::test]
    async fn test_send_stream_then_stream_done() {
        let web_state = test_web_state(Box::new(DummyLlm), WebLimits::default());
        let app = build_router(web_state);

        let req = Request::builder()
            .method("POST")
            .uri("/api/send_stream")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"session_key":"main","sender_name":"u","message":"hi"}"#,
            ))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let run_id = v.get("run_id").and_then(|x| x.as_str()).unwrap();

        let req2 = Request::builder()
            .method("GET")
            .uri(format!("/api/stream?run_id={run_id}"))
            .body(Body::empty())
            .unwrap();
        let resp2 = app.oneshot(req2).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp2.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("event: delta"));
        assert!(text.contains("event: done"));
    }

    #[tokio::test]
    async fn test_send_stream_send_message_tool_does_not_store_final_response_twice() {
        let web_state = test_web_state(
            Box::new(SendMessageThenAnswerLlm {
                calls: AtomicUsize::new(0),
            }),
            WebLimits::default(),
        );
        let db = web_state.app_state.db.clone();
        let app = build_router(web_state);

        let req = Request::builder()
            .method("POST")
            .uri("/api/send_stream")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"session_key":"main","sender_name":"u","message":"hi"}"#,
            ))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let run_id = v.get("run_id").and_then(|x| x.as_str()).unwrap();

        let req2 = Request::builder()
            .method("GET")
            .uri(format!("/api/stream?run_id={run_id}"))
            .body(Body::empty())
            .unwrap();
        let resp2 = app.oneshot(req2).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::OK);
        let _ = axum::body::to_bytes(resp2.into_body(), usize::MAX)
            .await
            .unwrap();

        let rows = call_blocking(db, move |d| d.get_all_messages(1))
            .await
            .unwrap();
        let bot_rows: Vec<_> = rows.into_iter().filter(|m| m.is_from_bot).collect();
        assert_eq!(bot_rows.len(), 1);
        assert_eq!(bot_rows[0].content, "tool reply");
    }

    #[tokio::test]
    async fn test_chat_alias_matches_send_behavior() {
        let web_state = test_web_state(Box::new(DummyLlm), WebLimits::default());
        let app = build_router(web_state);

        let req = Request::builder()
            .method("POST")
            .uri("/api/chat")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"session_key":"main","sender_name":"u","message":"hi"}"#,
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v.get("ok").and_then(|x| x.as_bool()), Some(true));
        assert_eq!(v.get("session_key").and_then(|x| x.as_str()), Some("main"));
        assert_eq!(
            v.get("response").and_then(|x| x.as_str()),
            Some("hello from llm")
        );
    }

    #[tokio::test]
    async fn test_chat_stream_alias_works() {
        let web_state = test_web_state(Box::new(DummyLlm), WebLimits::default());
        let app = build_router(web_state);

        let req = Request::builder()
            .method("POST")
            .uri("/api/chat_stream")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"session_key":"main","sender_name":"u","message":"hi"}"#,
            ))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let run_id = v.get("run_id").and_then(|x| x.as_str()).unwrap();

        let req2 = Request::builder()
            .method("GET")
            .uri(format!("/api/stream?run_id={run_id}"))
            .body(Body::empty())
            .unwrap();
        let resp2 = app.oneshot(req2).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp2.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("event: done"));
    }

    #[tokio::test]
    async fn test_hooks_agent_accepts_openclaw_shape() {
        let cfg = with_hooks_token(test_config_template(), "hooks-secret");
        let web_state = test_web_state_from_app_state(
            test_state_with_config(Box::new(DummyLlm), cfg),
            WebLimits::default(),
        );
        let app = build_router(web_state);

        let req = Request::builder()
            .method("POST")
            .uri("/hooks/agent")
            .header("authorization", "Bearer hooks-secret")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"message":"hi","name":"Email"}"#))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let run_id = v.get("run_id").and_then(|x| x.as_str()).unwrap();

        let req2 = Request::builder()
            .method("GET")
            .uri(format!("/api/stream?run_id={run_id}"))
            .body(Body::empty())
            .unwrap();
        let resp2 = app.oneshot(req2).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp2.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("event: done"));
    }

    #[tokio::test]
    async fn test_hooks_agent_rejects_missing_or_invalid_token() {
        let cfg = with_hooks_token(test_config_template(), "hooks-secret");
        let web_state = test_web_state_from_app_state(
            test_state_with_config(Box::new(DummyLlm), cfg),
            WebLimits::default(),
        );
        let app = build_router(web_state);

        let no_token_req = Request::builder()
            .method("POST")
            .uri("/hooks/agent")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"message":"hi"}"#))
            .unwrap();
        let no_token_resp = app.clone().oneshot(no_token_req).await.unwrap();
        assert_eq!(no_token_resp.status(), StatusCode::UNAUTHORIZED);

        let bad_token_req = Request::builder()
            .method("POST")
            .uri("/hooks/agent")
            .header("x-openclaw-token", "wrong")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"message":"hi"}"#))
            .unwrap();
        let bad_token_resp = app.oneshot(bad_token_req).await.unwrap();
        assert_eq!(bad_token_resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_hooks_agent_session_key_override_policy() {
        let cfg = with_hooks_session_key_policy(
            with_hooks_token(test_config_template(), "hooks-secret"),
            false,
            &["hook:"],
        );
        let web_state = test_web_state_from_app_state(
            test_state_with_config(Box::new(DummyLlm), cfg),
            WebLimits::default(),
        );
        let app = build_router(web_state);

        let req = Request::builder()
            .method("POST")
            .uri("/hooks/agent")
            .header("authorization", "Bearer hooks-secret")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"message":"hi","sessionKey":"hook:explicit:1"}"#,
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_hooks_agent_session_key_prefix_allowlist() {
        let cfg = with_hooks_session_key_policy(
            with_hooks_token(test_config_template(), "hooks-secret"),
            true,
            &["hook:"],
        );
        let web_state = test_web_state_from_app_state(
            test_state_with_config(Box::new(DummyLlm), cfg),
            WebLimits::default(),
        );
        let app = build_router(web_state);

        let blocked = Request::builder()
            .method("POST")
            .uri("/hooks/agent")
            .header("authorization", "Bearer hooks-secret")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"message":"hi","sessionKey":"ops:1"}"#))
            .unwrap();
        let blocked_resp = app.clone().oneshot(blocked).await.unwrap();
        assert_eq!(blocked_resp.status(), StatusCode::BAD_REQUEST);

        let allowed = Request::builder()
            .method("POST")
            .uri("/hooks/agent")
            .header("authorization", "Bearer hooks-secret")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"message":"hi","sessionKey":"hook:ok:1"}"#))
            .unwrap();
        let allowed_resp = app.oneshot(allowed).await.unwrap();
        assert_eq!(allowed_resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_hooks_wake_next_heartbeat_queues_message() {
        let cfg = with_hooks_token(test_config_template(), "hooks-secret");
        let web_state = test_web_state_from_app_state(
            test_state_with_config(Box::new(DummyLlm), cfg),
            WebLimits::default(),
        );
        let db = web_state.app_state.db.clone();
        let app = build_router(web_state);

        let req = Request::builder()
            .method("POST")
            .uri("/hooks/wake")
            .header("authorization", "Bearer hooks-secret")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"text":"new email","mode":"next-heartbeat"}"#,
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            v.get("mode").and_then(|x| x.as_str()),
            Some("next-heartbeat")
        );
        let chat_id = v.get("chat_id").and_then(|x| x.as_i64()).unwrap();

        let rows = call_blocking(db, move |d| d.get_all_messages(chat_id))
            .await
            .unwrap();
        assert!(rows
            .iter()
            .any(|m| m.content.contains("System event: new email")));
    }

    #[tokio::test]
    async fn test_api_send_models_command_uses_live_models_for_non_preset_provider() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::mpsc;
        use std::time::Duration;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (path_tx, path_rx) = mpsc::channel::<String>();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut buf = [0u8; 8192];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let path = req
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or("")
                .to_string();
            let _ = path_tx.send(path);
            let body = r#"{"data":[{"id":"live-web-a"},{"id":"live-web-b"}]}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        });

        let mut cfg = test_config_template();
        cfg.llm_provider = "lab-local".into();
        cfg.api_key = "k".into();
        cfg.model = "custom-model".into();
        cfg.llm_base_url = Some(format!("http://{addr}/v1"));
        cfg.llm_providers.insert(
            "lab-local".to_string(),
            LlmProviderProfile {
                provider: Some("openai".to_string()),
                api_key: None,
                api_keys: Vec::new(),
                llm_base_url: Some(format!("http://{addr}/v1")),
                llm_user_agent: None,
                default_model: Some("custom-model".to_string()),
                models: vec!["custom-model".to_string()],
                show_thinking: None,
            },
        );
        let web_state = test_web_state_from_app_state(
            test_state_with_config(Box::new(DummyLlm), cfg),
            WebLimits::default(),
        );
        let app = build_router(web_state);

        let req = Request::builder()
            .method("POST")
            .uri("/api/send")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"session_key":"main","sender_name":"u","message":"/models"}"#,
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let text = v
            .get("response")
            .and_then(|x| x.as_str())
            .unwrap_or_default();
        let path = path_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        server.join().unwrap();
        assert_eq!(path, "/v1/models");
        assert!(text.contains("Live models for provider 'lab-local'"));
        assert!(text.contains("live-web-a"));
    }

    #[tokio::test]
    async fn test_api_health_is_public_but_minimal_without_auth() {
        let web_state = test_web_state(Box::new(DummyLlm), WebLimits::default());
        call_blocking(web_state.app_state.db.clone(), |db| {
            db.upsert_auth_password_hash(&make_password_hash("passw0rd!"))
        })
        .await
        .unwrap();
        let app = build_router(web_state);

        let req = Request::builder()
            .method("GET")
            .uri("/api/health")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.get("ok").and_then(|v| v.as_bool()), Some(true));
        assert!(json.get("scheduler").is_none());
        assert!(json.get("reflector").is_none());
    }

    #[tokio::test]
    async fn test_root_health_alias_is_public() {
        let web_state = test_web_state(Box::new(DummyLlm), WebLimits::default());
        call_blocking(web_state.app_state.db.clone(), |db| {
            db.upsert_auth_password_hash(&make_password_hash("passw0rd!"))
        })
        .await
        .unwrap();
        let app = build_router(web_state);

        let req = Request::builder()
            .method("GET")
            .uri("/health")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_api_health_includes_scheduler_and_reflector_status() {
        let web_state = test_web_state(Box::new(DummyLlm), WebLimits::default());
        let app = build_router(web_state);

        let req = Request::builder()
            .method("GET")
            .uri("/api/health")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert!(json.get("scheduler").and_then(|v| v.as_object()).is_some());
        assert!(json
            .get("scheduler")
            .and_then(|s| s.get("task_runs_24h"))
            .and_then(|v| v.as_i64())
            .is_some());
        assert!(json.get("reflector").and_then(|v| v.as_object()).is_some());
        assert!(json
            .get("reflector")
            .and_then(|s| s.get("enabled"))
            .and_then(|v| v.as_bool())
            .is_some());
    }

    #[tokio::test]
    async fn test_same_session_concurrency_limited() {
        let limits = WebLimits {
            max_inflight_per_session: 1,
            max_requests_per_window: 10,
            rate_window: Duration::from_secs(10),
            run_history_limit: 128,
            session_idle_ttl: Duration::from_secs(60),
        };
        let web_state = test_web_state(Box::new(SlowLlm { sleep_ms: 300 }), limits);
        let app = build_router(web_state);

        let req1 = Request::builder()
            .method("POST")
            .uri("/api/send")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"session_key":"main","sender_name":"u","message":"one"}"#,
            ))
            .unwrap();
        let req2 = Request::builder()
            .method("POST")
            .uri("/api/send")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"session_key":"main","sender_name":"u","message":"two"}"#,
            ))
            .unwrap();

        let app_a = app.clone();
        let first = tokio::spawn(async move { app_a.oneshot(req1).await.unwrap() });
        tokio::time::sleep(Duration::from_millis(40)).await;
        let resp2 = app.clone().oneshot(req2).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::TOO_MANY_REQUESTS);

        let resp1 = first.await.unwrap();
        assert_eq!(resp1.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_different_sessions_same_actor_concurrency_limited() {
        let limits = WebLimits {
            max_inflight_per_session: 1,
            max_requests_per_window: 10,
            rate_window: Duration::from_secs(10),
            run_history_limit: 128,
            session_idle_ttl: Duration::from_secs(60),
        };
        let web_state = test_web_state(Box::new(SlowLlm { sleep_ms: 300 }), limits);
        let app = build_router(web_state);

        let req1 = Request::builder()
            .method("POST")
            .uri("/api/send")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"session_key":"main-a","sender_name":"u","message":"one"}"#,
            ))
            .unwrap();
        let req2 = Request::builder()
            .method("POST")
            .uri("/api/send")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"session_key":"main-b","sender_name":"u","message":"two"}"#,
            ))
            .unwrap();

        let app_a = app.clone();
        let first = tokio::spawn(async move { app_a.oneshot(req1).await.unwrap() });
        tokio::time::sleep(Duration::from_millis(40)).await;
        let resp2 = app.clone().oneshot(req2).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::TOO_MANY_REQUESTS);

        let resp1 = first.await.unwrap();
        assert_eq!(resp1.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_stream_includes_tool_events_and_replay() {
        let web_state = test_web_state(
            Box::new(ToolFlowLlm {
                calls: AtomicUsize::new(0),
            }),
            WebLimits::default(),
        );
        let app = build_router(web_state);

        let req = Request::builder()
            .method("POST")
            .uri("/api/send_stream")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"session_key":"main","sender_name":"u","message":"do tool"}"#,
            ))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let run_id = v.get("run_id").and_then(|x| x.as_str()).unwrap();

        let req_stream = Request::builder()
            .method("GET")
            .uri(format!("/api/stream?run_id={run_id}"))
            .body(Body::empty())
            .unwrap();
        let resp_stream = app.clone().oneshot(req_stream).await.unwrap();
        assert_eq!(resp_stream.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp_stream.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("event: tool_start"));
        assert!(text.contains("event: tool_result"));
        assert!(text.contains("event: done"));

        let req_status = Request::builder()
            .method("GET")
            .uri(format!("/api/run_status?run_id={run_id}"))
            .body(Body::empty())
            .unwrap();
        let status_resp = app.clone().oneshot(req_status).await.unwrap();
        assert_eq!(status_resp.status(), StatusCode::OK);
        let status_body = axum::body::to_bytes(status_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let status_json: serde_json::Value = serde_json::from_slice(&status_body).unwrap();
        let last_event_id = status_json
            .get("last_event_id")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        assert!(last_event_id > 0);

        let req_replay = Request::builder()
            .method("GET")
            .uri(format!(
                "/api/stream?run_id={run_id}&last_event_id={last_event_id}"
            ))
            .body(Body::empty())
            .unwrap();
        let replay_resp = app.oneshot(req_replay).await.unwrap();
        assert_eq!(replay_resp.status(), StatusCode::OK);
        let replay_bytes = axum::body::to_bytes(replay_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let replay_text = String::from_utf8_lossy(&replay_bytes);
        // Nothing newer than last_event_id; only replay metadata should be present.
        assert!(replay_text.contains("event: replay_meta"));
        assert!(!replay_text.contains("event: delta"));
        assert!(!replay_text.contains("event: done"));
    }

    #[tokio::test]
    async fn test_reconnect_from_last_event_id_gets_non_empty_replay() {
        let web_state = test_web_state(Box::new(DummyLlm), WebLimits::default());
        let app = build_router(web_state);

        let req = Request::builder()
            .method("POST")
            .uri("/api/send_stream")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"session_key":"main","sender_name":"u","message":"reconnect"}"#,
            ))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let run_id = v.get("run_id").and_then(|x| x.as_str()).unwrap();

        let req_stream = Request::builder()
            .method("GET")
            .uri(format!("/api/stream?run_id={run_id}"))
            .body(Body::empty())
            .unwrap();
        let resp_stream = app.clone().oneshot(req_stream).await.unwrap();
        assert_eq!(resp_stream.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp_stream.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&bytes);

        let mut ids = Vec::new();
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("id: ") {
                if let Ok(id) = rest.trim().parse::<u64>() {
                    ids.push(id);
                }
            }
        }
        assert!(ids.len() >= 2);
        let reconnect_from = ids[0];

        let req_replay = Request::builder()
            .method("GET")
            .uri(format!(
                "/api/stream?run_id={run_id}&last_event_id={reconnect_from}"
            ))
            .body(Body::empty())
            .unwrap();
        let replay_resp = app.oneshot(req_replay).await.unwrap();
        assert_eq!(replay_resp.status(), StatusCode::OK);
        let replay_bytes = axum::body::to_bytes(replay_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let replay_text = String::from_utf8_lossy(&replay_bytes);
        assert!(replay_text.contains("event: delta") || replay_text.contains("event: done"));
    }

    #[tokio::test]
    async fn test_api_usage_returns_report() {
        let web_state = test_web_state(Box::new(DummyLlm), WebLimits::default());
        let db = web_state.app_state.db.clone();
        call_blocking(db, |d| {
            d.upsert_chat(123, Some("main"), "web")?;
            d.log_llm_usage(
                123,
                "web",
                "anthropic",
                "claude-test",
                1200,
                300,
                "agent_loop",
            )?;
            Ok(())
        })
        .await
        .unwrap();

        let app = build_router(web_state);
        let req = Request::builder()
            .method("GET")
            .uri("/api/usage?session_key=main")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v.get("ok").and_then(|x| x.as_bool()), Some(true));
        let report = v.get("report").and_then(|x| x.as_str()).unwrap_or_default();
        assert!(report.contains("Token Usage"));
        assert!(report.contains("This chat"));
        let mem = v.get("memory_observability").and_then(|x| x.as_object());
        assert!(mem.is_some());
        assert!(mem.unwrap().contains_key("total"));
    }

    #[tokio::test]
    async fn test_learning_observability_and_human_feedback() {
        let web_state = test_web_state(Box::new(DummyLlm), WebLimits::default());
        let db = web_state.app_state.db.clone();
        call_blocking(db, |d| {
            d.upsert_chat(123, Some("main"), "web")?;
            d.upsert_goal_state(
                "goal-web",
                123,
                "verify learning",
                "active",
                None,
                None,
                None,
            )?;
            d.start_experience_run(
                "run-web",
                Some("goal-web"),
                123,
                "web",
                "interactive",
                "verify learning",
                None,
            )?;
            d.finish_experience_run("run-web", "completed", Some("done"), 10)?;
            Ok(())
        })
        .await
        .unwrap();

        let app = build_router(web_state);
        let feedback = Request::builder()
            .method("POST")
            .uri("/api/learning/feedback")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "session_key": "main",
                    "run_id": "run-web",
                    "verdict": "passed",
                    "evidence": "user confirmed"
                })
                .to_string(),
            ))
            .unwrap();
        let feedback_response = app.clone().oneshot(feedback).await.unwrap();
        assert_eq!(feedback_response.status(), StatusCode::OK);

        let second_feedback = Request::builder()
            .method("POST")
            .uri("/api/learning/feedback")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "session_key": "main",
                    "run_id": "run-web",
                    "verdict": "failed",
                    "confidence": 0.1,
                    "feedback_id": "secondary-review",
                    "evidence": "low confidence concern"
                })
                .to_string(),
            ))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(second_feedback).await.unwrap().status(),
            StatusCode::OK
        );

        let request = Request::builder()
            .method("GET")
            .uri("/api/learning_observability?session_key=main")
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            value["active_goal"]["objective"].as_str(),
            Some("verify learning")
        );
        assert_eq!(
            value["experience_summary"]["verified_runs"].as_i64(),
            Some(1)
        );
        assert_eq!(value["recent_runs"][0]["run_id"].as_str(), Some("run-web"));
        assert_eq!(
            value["recent_runs"][0]["task_signature"]["task_family"].as_str(),
            Some("testing")
        );
        assert_eq!(
            value["governance_policy"]["trial_min_outcomes"].as_i64(),
            Some(3)
        );
        assert_eq!(
            value["governance_policy"]["utility_confidence_z"].as_f64(),
            Some(1.96)
        );
        assert_eq!(
            value["governance_policy"]["failure_pattern_min_failures"].as_i64(),
            Some(2)
        );
        assert!(value["skill_task_utilities"].is_array());
        assert!(value["skill_failure_patterns"].is_array());
        assert!(value["comparisons"].is_array());
        assert!(value["learning_claims"].is_array());
        assert!(value["skill_candidates"].is_array());
        assert!(value["shadow_evaluations"].is_array());
        assert!(value["learning_journal"].is_array());
        assert!(value["learning_tracks"].is_array());
        assert!(value["learning_epochs"].is_array());
        assert!(value["learning_track_candidates"].is_array());
        assert!(value["learning_candidate_evaluations"].is_array());

        let experience_request = Request::builder()
            .method("GET")
            .uri("/api/learning/experiences?session_key=main&query=verify")
            .body(Body::empty())
            .unwrap();
        let experience_response = app.clone().oneshot(experience_request).await.unwrap();
        assert_eq!(experience_response.status(), StatusCode::OK);
        let experience_body = axum::body::to_bytes(experience_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let experience_value: serde_json::Value = serde_json::from_slice(&experience_body).unwrap();
        assert_eq!(
            experience_value["experiences"][0]["run_id"].as_str(),
            Some("run-web")
        );

        let detail_request = Request::builder()
            .method("GET")
            .uri("/api/learning/experiences/run-web?session_key=main")
            .body(Body::empty())
            .unwrap();
        let detail_response = app.clone().oneshot(detail_request).await.unwrap();
        assert_eq!(detail_response.status(), StatusCode::OK);
        let detail_body = axum::body::to_bytes(detail_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let detail_value: serde_json::Value = serde_json::from_slice(&detail_body).unwrap();
        assert_eq!(
            detail_value["detail"]["feedback"].as_array().map(Vec::len),
            Some(2)
        );
        assert_eq!(
            detail_value["detail"]["outcomes"].as_array().map(Vec::len),
            Some(2)
        );
        assert_eq!(
            detail_value["detail"]["outcomes"][0]["schema_version"].as_i64(),
            Some(1)
        );

        let policy_request = Request::builder()
            .method("GET")
            .uri("/api/learning/policy")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(policy_request).await.unwrap().status(),
            StatusCode::OK
        );

        let update_policy = Request::builder()
            .method("PUT")
            .uri("/api/learning/policy")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "candidate_failures_to_degrade": 3,
                    "trial_min_outcomes": 4,
                    "trial_promote_rate": 0.85,
                    "trial_degrade_rate": 0.4,
                    "trusted_min_outcomes": 6,
                    "trusted_degrade_rate": 0.55
                })
                .to_string(),
            ))
            .unwrap();
        let update_response = app.clone().oneshot(update_policy).await.unwrap();
        assert_eq!(update_response.status(), StatusCode::OK);
        let updated_policy_request = Request::builder()
            .method("GET")
            .uri("/api/learning/policy")
            .body(Body::empty())
            .unwrap();
        let updated_policy_response = app.clone().oneshot(updated_policy_request).await.unwrap();
        let updated_policy_body =
            axum::body::to_bytes(updated_policy_response.into_body(), usize::MAX)
                .await
                .unwrap();
        let updated_policy_value: serde_json::Value =
            serde_json::from_slice(&updated_policy_body).unwrap();
        assert_eq!(
            updated_policy_value["policy"]["trial_min_outcomes"].as_i64(),
            Some(4)
        );

        let invalid_policy = Request::builder()
            .method("PUT")
            .uri("/api/learning/policy")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "candidate_failures_to_degrade": 0,
                    "trial_min_outcomes": 4,
                    "trial_promote_rate": 1.2,
                    "trial_degrade_rate": 0.4,
                    "trusted_min_outcomes": 6,
                    "trusted_degrade_rate": 0.55
                })
                .to_string(),
            ))
            .unwrap();
        assert_eq!(
            app.oneshot(invalid_policy).await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn test_api_memory_observability_returns_series() {
        let web_state = test_web_state(Box::new(DummyLlm), WebLimits::default());
        let db = web_state.app_state.db.clone();
        let started_at_dt = chrono::Utc::now() - chrono::Duration::minutes(1);
        let started_at = started_at_dt.to_rfc3339();
        let finished_at = (started_at_dt + chrono::Duration::seconds(1)).to_rfc3339();
        call_blocking(db, move |d| {
            d.upsert_chat(123, Some("main"), "web")?;
            d.insert_memory_with_metadata(
                Some(123),
                "prod db on 5433",
                "KNOWLEDGE",
                "explicit",
                0.95,
            )?;
            d.log_reflector_run(
                123,
                &started_at,
                &finished_at,
                2,
                1,
                0,
                1,
                "jaccard",
                true,
                None,
            )?;
            d.log_memory_injection(123, "keyword", 5, 2, 3, 80)?;
            Ok(())
        })
        .await
        .unwrap();

        let app = build_router(web_state);
        let req = Request::builder()
            .method("GET")
            .uri("/api/memory_observability?session_key=main&scope=chat&hours=24&limit=50")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v.get("ok").and_then(|x| x.as_bool()), Some(true));
        assert_eq!(v.get("scope").and_then(|x| x.as_str()), Some("chat"));
        assert!(v
            .get("reflector_runs")
            .and_then(|x| x.as_array())
            .map(|a| !a.is_empty())
            .unwrap_or(false));
        assert!(v
            .get("injection_logs")
            .and_then(|x| x.as_array())
            .map(|a| !a.is_empty())
            .unwrap_or(false));
    }

    #[tokio::test]
    async fn test_read_endpoints_unknown_session_return_404_without_creating_chat() {
        let web_state = test_web_state(Box::new(DummyLlm), WebLimits::default());
        let db = web_state.app_state.db.clone();
        let read_key = "mk_read_only";
        call_blocking(db.clone(), move |d| {
            d.upsert_auth_password_hash(&make_password_hash("passw0rd!"))?;
            d.create_api_key(
                "read-only",
                &sha256_hex(read_key),
                "mk_read_on",
                &["operator.read".to_string()],
                None,
                None,
            )?;
            Ok(())
        })
        .await
        .unwrap();
        let before = call_blocking(db.clone(), move |d| d.get_recent_chats(4000))
            .await
            .unwrap()
            .len();

        let app = build_router(web_state);
        for uri in [
            "/api/history?session_key=ghost",
            "/api/usage?session_key=ghost",
            "/api/memory_observability?scope=chat&session_key=ghost",
        ] {
            let req = Request::builder()
                .method("GET")
                .uri(uri)
                .header("authorization", format!("Bearer {read_key}"))
                .body(Body::empty())
                .unwrap();
            let resp = app.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        }

        let after = call_blocking(db, move |d| d.get_recent_chats(4000))
            .await
            .unwrap()
            .len();
        assert_eq!(after, before);
    }

    #[tokio::test]
    async fn test_read_endpoints_resolve_session_older_than_recent_limit() {
        let web_state = test_web_state(Box::new(DummyLlm), WebLimits::default());
        let db = web_state.app_state.db.clone();
        let read_key = "mk_read_old";
        call_blocking(db.clone(), move |d| {
            d.upsert_auth_password_hash(&make_password_hash("passw0rd!"))?;
            d.create_api_key(
                "read-old",
                &sha256_hex(read_key),
                "mk_read_ol",
                &["operator.read".to_string()],
                None,
                None,
            )?;
            for i in 0..5000 {
                d.resolve_or_create_chat_id(
                    "web",
                    &format!("ext-{i}"),
                    Some(&format!("title-{i}")),
                    "web",
                )?;
            }
            let legacy_chat =
                d.resolve_or_create_chat_id("web", "legacy-ext", Some("legacy-session"), "web")?;
            for i in 5000..9300 {
                d.resolve_or_create_chat_id(
                    "web",
                    &format!("ext-{i}"),
                    Some(&format!("title-{i}")),
                    "web",
                )?;
            }
            d.store_message(&StoredMessage {
                id: uuid::Uuid::new_v4().to_string(),
                chat_id: legacy_chat,
                sender_name: "user".to_string(),
                content: "hello".to_string(),
                is_from_bot: false,
                timestamp: chrono::Utc::now().to_rfc3339(),
            })?;
            Ok(())
        })
        .await
        .unwrap();

        let app = build_router(web_state);
        let req = Request::builder()
            .method("GET")
            .uri("/api/history?session_key=legacy-session")
            .header("authorization", format!("Bearer {read_key}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_web_session_key_resolves_to_channel_scoped_chat_id() {
        let web_state = test_web_state(Box::new(DummyLlm), WebLimits::default());
        let app = build_router(web_state.clone());

        let req = Request::builder()
            .method("POST")
            .uri("/api/send")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"session_key":"scoped-main","sender_name":"u","message":"hello"}"#,
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let db = web_state.app_state.db.clone();
        let chat_id = call_blocking(db.clone(), move |d| {
            d.resolve_or_create_chat_id("web", "scoped-main", Some("scoped-main"), "web")
        })
        .await
        .unwrap();
        let external = call_blocking(db.clone(), move |d| d.get_chat_external_id(chat_id))
            .await
            .unwrap();
        let test_registry = {
            let mut r = ChannelRegistry::new();
            r.register(Arc::new(WebAdapter));
            Arc::new(r)
        };
        let routing = get_chat_routing(&test_registry, db, chat_id).await.unwrap();

        assert_eq!(routing.map(|r| r.channel_name), Some("web".to_string()));
        assert_eq!(external.as_deref(), Some("scoped-main"));
    }

    #[tokio::test]
    async fn test_sessions_fork_copies_messages_and_meta() {
        let web_state = test_web_state(Box::new(DummyLlm), WebLimits::default());
        let app = build_router(web_state.clone());

        let seed_req = Request::builder()
            .method("POST")
            .uri("/api/send")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"session_key":"main","sender_name":"u","message":"seed"}"#,
            ))
            .unwrap();
        let seed_resp = app.clone().oneshot(seed_req).await.unwrap();
        assert_eq!(seed_resp.status(), StatusCode::OK);

        let fork_req = Request::builder()
            .method("POST")
            .uri("/api/sessions/fork")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"source_session_key":"main","target_session_key":"main-fork","fork_point":1}"#,
            ))
            .unwrap();
        let fork_resp = app.clone().oneshot(fork_req).await.unwrap();
        assert_eq!(fork_resp.status(), StatusCode::OK);
        let fork_body = axum::body::to_bytes(fork_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let fork_json: serde_json::Value = serde_json::from_slice(&fork_body).unwrap();
        let target_chat_id = fork_json
            .get("target_chat_id")
            .and_then(|v| v.as_i64())
            .unwrap_or_default();
        assert!(target_chat_id > 0);

        let hist_req = Request::builder()
            .method("GET")
            .uri("/api/history?session_key=main-fork")
            .body(Body::empty())
            .unwrap();
        let hist_resp = app.clone().oneshot(hist_req).await.unwrap();
        assert_eq!(hist_resp.status(), StatusCode::OK);
        let hist_body = axum::body::to_bytes(hist_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let hist_json: serde_json::Value = serde_json::from_slice(&hist_body).unwrap();
        let count = hist_json
            .get("messages")
            .and_then(|v| v.as_array())
            .map(|v| v.len())
            .unwrap_or(0);
        assert_eq!(count, 1);

        let db = web_state.app_state.db.clone();
        let meta = call_blocking(db, move |d| d.load_session_meta(target_chat_id))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(meta.2.as_deref(), Some("main"));
        assert_eq!(meta.3, Some(1));
    }

    #[tokio::test]
    async fn test_metrics_endpoints_return_data() {
        let web_state = test_web_state(Box::new(DummyLlm), WebLimits::default());
        let app = build_router(web_state);

        let send_req = Request::builder()
            .method("POST")
            .uri("/api/send")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"session_key":"metrics-main","sender_name":"u","message":"hello"}"#,
            ))
            .unwrap();
        let send_resp = app.clone().oneshot(send_req).await.unwrap();
        assert_eq!(send_resp.status(), StatusCode::OK);

        let metrics_req = Request::builder()
            .method("GET")
            .uri("/api/metrics")
            .body(Body::empty())
            .unwrap();
        let metrics_resp = app.clone().oneshot(metrics_req).await.unwrap();
        assert_eq!(metrics_resp.status(), StatusCode::OK);
        let metrics_body = axum::body::to_bytes(metrics_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let metrics_json: serde_json::Value = serde_json::from_slice(&metrics_body).unwrap();
        assert!(
            metrics_json
                .get("metrics")
                .and_then(|m| m.get("http_requests"))
                .and_then(|v| v.as_i64())
                .unwrap_or(0)
                > 0
        );
        assert!(metrics_json
            .get("metrics")
            .and_then(|m| m.get("mcp_rate_limited_rejections"))
            .and_then(|v| v.as_i64())
            .is_some());
        assert!(metrics_json
            .get("metrics")
            .and_then(|m| m.get("mcp_bulkhead_rejections"))
            .and_then(|v| v.as_i64())
            .is_some());
        assert!(metrics_json
            .get("metrics")
            .and_then(|m| m.get("mcp_circuit_open_rejections"))
            .and_then(|v| v.as_i64())
            .is_some());

        let summary_req = Request::builder()
            .method("GET")
            .uri("/api/metrics/summary")
            .body(Body::empty())
            .unwrap();
        let summary_resp = app.clone().oneshot(summary_req).await.unwrap();
        assert_eq!(summary_resp.status(), StatusCode::OK);
        let summary_body = axum::body::to_bytes(summary_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let summary_json: serde_json::Value = serde_json::from_slice(&summary_body).unwrap();
        assert!(summary_json
            .get("summary")
            .and_then(|m| m.get("mcp_rejections_total"))
            .and_then(|v| v.as_i64())
            .is_some());
        assert!(summary_json
            .get("summary")
            .and_then(|m| m.get("mcp_rejection_ratio"))
            .and_then(|v| v.as_f64())
            .is_some());

        let history_req = Request::builder()
            .method("GET")
            .uri("/api/metrics/history?minutes=60")
            .body(Body::empty())
            .unwrap();
        let history_resp = app.clone().oneshot(history_req).await.unwrap();
        assert_eq!(history_resp.status(), StatusCode::OK);
        let history_body = axum::body::to_bytes(history_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let history_json: serde_json::Value = serde_json::from_slice(&history_body).unwrap();
        let points = history_json
            .get("points")
            .and_then(|v| v.as_array())
            .map(|v| !v.is_empty())
            .unwrap_or(false);
        assert!(points);

        let summary_req = Request::builder()
            .method("GET")
            .uri("/api/metrics/summary")
            .body(Body::empty())
            .unwrap();
        let summary_resp = app.oneshot(summary_req).await.unwrap();
        assert_eq!(summary_resp.status(), StatusCode::OK);
        let summary_body = axum::body::to_bytes(summary_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let summary_json: serde_json::Value = serde_json::from_slice(&summary_body).unwrap();
        assert_eq!(summary_json.get("ok").and_then(|v| v.as_bool()), Some(true));
        assert!(
            summary_json
                .get("metrics")
                .and_then(|m| m.get("request_ok"))
                .and_then(|v| v.as_i64())
                .unwrap_or(0)
                >= 1
        );
        assert!(
            summary_json
                .get("slo")
                .and_then(|s| s.get("request_success_rate"))
                .and_then(|r| r.get("value"))
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0)
                >= 0.0
        );

        let points_vec = history_json
            .get("points")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        assert!(!points_vec.is_empty());
        let first = &points_vec[0];
        assert!(first
            .get("mcp_rate_limited_rejections")
            .and_then(|v| v.as_i64())
            .is_some());
        assert!(first
            .get("mcp_bulkhead_rejections")
            .and_then(|v| v.as_i64())
            .is_some());
        assert!(first
            .get("mcp_circuit_open_rejections")
            .and_then(|v| v.as_i64())
            .is_some());
    }

    #[tokio::test]
    async fn test_config_self_check_returns_warnings() {
        let web_state = test_web_state(Box::new(DummyLlm), WebLimits::default());
        let app = build_router(web_state);

        let req = Request::builder()
            .method("GET")
            .uri("/api/config/self_check")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.get("ok").and_then(|v| v.as_bool()), Some(true));
        assert!(
            json.get("warning_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                >= 1
        );
    }

    #[tokio::test]
    async fn test_config_self_check_detects_otlp_missing_endpoint() {
        let mut cfg = test_config_template();
        cfg.channels.insert(
            "observability".to_string(),
            serde_yaml::to_value(serde_json::json!({
                "otlp_enabled": true,
                "otlp_retry_max_attempts": 1
            }))
            .unwrap(),
        );
        let state = test_state_with_config(Box::new(DummyLlm), cfg);
        let web_state = test_web_state_from_app_state(state, WebLimits::default());
        let app = build_router(web_state);

        let req = Request::builder()
            .method("GET")
            .uri("/api/config/self_check")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let warnings = json
            .get("warnings")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let has_missing_endpoint = warnings.iter().any(|w| {
            w.get("code").and_then(|v| v.as_str()) == Some("otlp_enabled_without_endpoint")
        });
        let has_low_retry = warnings
            .iter()
            .any(|w| w.get("code").and_then(|v| v.as_str()) == Some("otlp_retry_attempts_too_low"));
        assert!(has_missing_endpoint);
        assert!(has_low_retry);
    }

    #[tokio::test]
    async fn test_config_self_check_warns_for_reflector_and_compaction_risks() {
        let mut cfg = test_config_template();
        cfg.reflector_enabled = false;
        cfg.max_session_messages = 20;
        cfg.compact_keep_recent = 20;
        cfg.memory_token_budget = 300;
        let state = test_state_with_config(Box::new(DummyLlm), cfg);
        let web_state = test_web_state_from_app_state(state, WebLimits::default());
        let app = build_router(web_state);

        let req = Request::builder()
            .method("GET")
            .uri("/api/config/self_check")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let warnings = json
            .get("warnings")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let has_reflector_disabled = warnings
            .iter()
            .any(|w| w.get("code").and_then(|v| v.as_str()) == Some("reflector_disabled"));
        let has_compaction_threshold = warnings.iter().any(|w| {
            w.get("code").and_then(|v| v.as_str()) == Some("compaction_threshold_not_effective")
        });
        let has_low_memory_budget = warnings
            .iter()
            .any(|w| w.get("code").and_then(|v| v.as_str()) == Some("memory_token_budget_low"));

        assert!(has_reflector_disabled);
        assert!(has_compaction_threshold);
        assert!(has_low_memory_budget);
    }

    #[tokio::test]
    async fn test_config_self_check_warns_for_risky_execution_defaults() {
        let mut cfg = test_config_template();
        cfg.high_risk_tool_user_confirmation_required = false;
        cfg.web_fetch_validation.enabled = false;
        cfg.web_fetch_url_validation.enabled = false;
        let state = test_state_with_config(Box::new(DummyLlm), cfg);
        let web_state = test_web_state_from_app_state(state, WebLimits::default());
        let app = build_router(web_state);

        let req = Request::builder()
            .method("GET")
            .uri("/api/config/self_check")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let warnings = json
            .get("warnings")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let has_auto_approve = warnings.iter().any(|w| {
            w.get("code").and_then(|v| v.as_str()) == Some("high_risk_tool_auto_approved")
        });
        let has_fetch_content_disabled = warnings.iter().any(|w| {
            w.get("code").and_then(|v| v.as_str()) == Some("web_fetch_content_validation_disabled")
        });
        let has_fetch_url_disabled = warnings.iter().any(|w| {
            w.get("code").and_then(|v| v.as_str()) == Some("web_fetch_url_validation_disabled")
        });

        assert!(has_auto_approve);
        assert!(has_fetch_content_disabled);
        assert!(has_fetch_url_disabled);
    }

    #[tokio::test]
    async fn test_config_self_check_warns_for_acp_runtime_risks() {
        let mut cfg = test_config_template();
        cfg.subagents.acp.default_target.enabled = true;
        cfg.subagents.acp.default_target.command = "definitely-missing-acp-command".into();
        cfg.subagents.acp.default_target.auto_approve = true;
        cfg.subagents.acp.default_target_name = Some("worker".into());
        cfg.subagents.acp.targets.insert(
            "worker".into(),
            crate::config::SubagentAcpTargetConfig {
                enabled: true,
                command: "also-missing-worker-command".into(),
                auto_approve: false,
                ..crate::config::SubagentAcpTargetConfig::default()
            },
        );
        let state = test_state_with_config(Box::new(DummyLlm), cfg);
        let web_state = test_web_state_from_app_state(state, WebLimits::default());
        let app = build_router(web_state);

        let req = Request::builder()
            .method("GET")
            .uri("/api/config/self_check")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let warnings = json
            .get("warnings")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        assert!(warnings.iter().any(|w| {
            w.get("code").and_then(|v| v.as_str()) == Some("acp_target_command_missing")
        }));
        assert!(warnings.iter().any(|w| {
            w.get("code").and_then(|v| v.as_str()) == Some("acp_named_target_command_missing")
        }));
    }

    #[tokio::test]
    async fn test_config_self_check_warns_for_non_strict_web_fetch_validation() {
        let mut cfg = test_config_template();
        cfg.web_fetch_validation.strict_mode = false;
        let state = test_state_with_config(Box::new(DummyLlm), cfg);
        let web_state = test_web_state_from_app_state(state, WebLimits::default());
        let app = build_router(web_state);

        let req = Request::builder()
            .method("GET")
            .uri("/api/config/self_check")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let warnings = json
            .get("warnings")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let has_non_strict_warning = warnings.iter().any(|w| {
            w.get("code").and_then(|v| v.as_str())
                == Some("web_fetch_content_validation_non_strict")
        });

        assert!(has_non_strict_warning);
    }

    #[tokio::test]
    async fn test_config_self_check_warns_scheduler_failures_and_reflector_idle() {
        let cfg = test_config_template();
        let state = test_state_with_config(Box::new(DummyLlm), cfg);
        let now = chrono::Utc::now().to_rfc3339();
        let db = state.db.clone();
        call_blocking(db, move |d| {
            for idx in 0..6 {
                d.log_task_run(
                    1000 + idx,
                    42,
                    &now,
                    &now,
                    1,
                    false,
                    Some("simulated failure"),
                )?;
            }
            Ok(())
        })
        .await
        .unwrap();
        let web_state = test_web_state_from_app_state(state, WebLimits::default());
        let app = build_router(web_state);

        let req = Request::builder()
            .method("GET")
            .uri("/api/config/self_check")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let warnings = json
            .get("warnings")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let has_scheduler_failure = warnings
            .iter()
            .any(|w| w.get("code").and_then(|v| v.as_str()) == Some("scheduler_failure_rate_high"));
        let has_reflector_idle = warnings
            .iter()
            .any(|w| w.get("code").and_then(|v| v.as_str()) == Some("reflector_no_recent_runs"));

        assert!(has_scheduler_failure);
        assert!(has_reflector_idle);
    }

    #[tokio::test]
    async fn test_sessions_tree_returns_fork_metadata() {
        let web_state = test_web_state(Box::new(DummyLlm), WebLimits::default());
        let app = build_router(web_state.clone());

        let seed_req = Request::builder()
            .method("POST")
            .uri("/api/send")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"session_key":"tree-main","sender_name":"u","message":"seed"}"#,
            ))
            .unwrap();
        let seed_resp = app.clone().oneshot(seed_req).await.unwrap();
        assert_eq!(seed_resp.status(), StatusCode::OK);

        let fork_req = Request::builder()
            .method("POST")
            .uri("/api/sessions/fork")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"source_session_key":"tree-main","target_session_key":"tree-branch","fork_point":1}"#,
            ))
            .unwrap();
        let fork_resp = app.clone().oneshot(fork_req).await.unwrap();
        assert_eq!(fork_resp.status(), StatusCode::OK);

        let tree_req = Request::builder()
            .method("GET")
            .uri("/api/sessions/tree?limit=100")
            .body(Body::empty())
            .unwrap();
        let tree_resp = app.oneshot(tree_req).await.unwrap();
        assert_eq!(tree_resp.status(), StatusCode::OK);
        let tree_body = axum::body::to_bytes(tree_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let tree_json: serde_json::Value = serde_json::from_slice(&tree_body).unwrap();
        let nodes = tree_json
            .get("nodes")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let found = nodes.iter().any(|n| {
            n.get("parent_session_key").and_then(|v| v.as_str()) == Some("tree-main")
                && n.get("fork_point").and_then(|v| v.as_i64()) == Some(1)
        });
        assert!(found);
    }

    #[tokio::test]
    async fn test_web_send_model_slash_command() {
        let web_state = test_web_state(Box::new(DummyLlm), WebLimits::default());
        let app = build_router(web_state);

        let req = Request::builder()
            .method("POST")
            .uri("/api/send")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"session_key":"slash-main","sender_name":"u","message":"/model"}"#,
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let response = v
            .get("response")
            .and_then(|x| x.as_str())
            .unwrap_or_default();
        assert!(response.contains("Current provider/model"));
    }

    #[tokio::test]
    async fn test_web_clear_slash_keeps_scheduled_tasks() {
        let web_state = test_web_state(Box::new(DummyLlm), WebLimits::default());
        let app = build_router(web_state.clone());
        let db = web_state.app_state.db.clone();
        call_blocking(db, move |d| {
            d.upsert_chat(4242, Some("chat:4242"), "web")?;
            d.save_session(4242, r#"[{"role":"user","content":"hi"}]"#)?;
            d.store_message(&StoredMessage {
                id: "m1".into(),
                chat_id: 4242,
                sender_name: "alice".into(),
                content: "hello".into(),
                is_from_bot: false,
                timestamp: "2024-01-01T00:00:01Z".into(),
            })?;
            d.create_scheduled_task(
                4242,
                "daily summary",
                "cron",
                "0 0 8 * * *",
                "2099-01-01T08:00:00Z",
            )?;
            Ok::<(), microclaw_core::error::MicroClawError>(())
        })
        .await
        .unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/api/send")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"session_key":"chat:4242","sender_name":"u","message":"/clear"}"#,
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            v.get("response").and_then(|x| x.as_str()),
            Some("Context cleared (session + chat history, scheduled tasks kept).")
        );

        let db = web_state.app_state.db.clone();
        let (session, messages, tasks_len) = call_blocking(db, move |d| {
            Ok::<
                (Option<(String, String)>, Vec<StoredMessage>, usize),
                microclaw_core::error::MicroClawError,
            >((
                d.load_session(4242)?,
                d.get_recent_messages(4242, 10)?,
                d.get_tasks_for_chat(4242)?.len(),
            ))
        })
        .await
        .unwrap();
        assert!(session.is_none());
        assert!(
            messages.iter().all(|m| m.content != "hello"),
            "old chat history should be removed by /clear"
        );
        assert_eq!(tasks_len, 1);
    }

    #[tokio::test]
    async fn test_web_tasks_endpoints_list_and_lifecycle_actions() {
        let web_state = test_web_state(Box::new(DummyLlm), WebLimits::default());
        let app = build_router(web_state.clone());
        let db = web_state.app_state.db.clone();
        let task_id = call_blocking(db, move |d| {
            d.upsert_chat(777, Some("chat:777"), "web")?;
            d.create_scheduled_task(
                777,
                "weekly digest",
                "cron",
                "0 0 8 * * 1",
                "2099-01-01T08:00:00Z",
            )
        })
        .await
        .unwrap();

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/tasks")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let tasks = v.get("tasks").and_then(|t| t.as_array()).unwrap();
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0]["id"].as_i64(), Some(task_id));
        assert_eq!(tasks[0]["status"].as_str(), Some("active"));
        assert_eq!(tasks[0]["has_contract"].as_bool(), Some(false));

        // pause → paused
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/tasks/{task_id}/pause"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // pause again → conflict (invalid transition)
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/tasks/{task_id}/pause"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);

        // resume → active, then cancel → cancelled
        for (action, expected) in [("resume", "active"), ("cancel", "cancelled")] {
            let resp = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/api/tasks/{task_id}/{action}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "{action} should succeed");
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(v["status"].as_str(), Some(expected));
        }

        // cancelled task is immutable and unknown actions 404
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/tasks/{task_id}/resume"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/tasks/{task_id}/explode"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        // runs endpoint returns the task and an empty run list
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/tasks/{task_id}/runs"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["task"]["id"].as_i64(), Some(task_id));
        assert_eq!(v["runs"].as_array().map(|r| r.len()), Some(0));
    }

    #[tokio::test]
    async fn test_web_governance_snapshot() {
        let web_state = test_web_state(Box::new(DummyLlm), WebLimits::default());
        let app = build_router(web_state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/governance")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["ok"].as_bool(), Some(true));
        assert_eq!(v["tool_policy"]["mode"].as_str(), Some("off"));
        assert!(v["token_budget"].is_object());
        assert!(v["heartbeat"].is_object());
        assert!(v["progress_updates"]["telegram"].is_object());
        assert!(v["scheduled_tasks"]["runs_24h"].is_i64());
    }

    #[tokio::test]
    async fn test_web_send_plugin_slash_command() {
        let mut cfg = test_config_template();
        let plugin_dir =
            std::env::temp_dir().join(format!("microclaw_web_plugin_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&plugin_dir).unwrap();
        std::fs::write(
            plugin_dir.join("webplug.yaml"),
            r#"
name: webplug
enabled: true
commands:
  - command: /webplug
    response: "webplug-ok"
"#,
        )
        .unwrap();
        cfg.plugins.enabled = true;
        cfg.plugins.dir = Some(plugin_dir.to_string_lossy().to_string());

        let state = test_state_with_config(Box::new(DummyLlm), cfg);
        let web_state = test_web_state_from_app_state(state, WebLimits::default());
        let app = build_router(web_state);

        let req = Request::builder()
            .method("POST")
            .uri("/api/send")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"session_key":"slash-main","sender_name":"u","message":"/webplug"}"#,
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            v.get("response").and_then(|x| x.as_str()),
            Some("webplug-ok")
        );

        let _ = std::fs::remove_dir_all(plugin_dir);
    }

    #[tokio::test]
    async fn test_cookie_write_requires_csrf_header() {
        let web_state = test_web_state(Box::new(DummyLlm), WebLimits::default());
        let app = build_router(web_state.clone());
        let hash = make_password_hash("passw0rd!");
        let db = web_state.app_state.db.clone();
        call_blocking(db, move |d| d.upsert_auth_password_hash(&hash))
            .await
            .unwrap();

        let login_req = Request::builder()
            .method("POST")
            .uri("/api/auth/login")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"password":"passw0rd!"}"#))
            .unwrap();
        let login_resp = app.clone().oneshot(login_req).await.unwrap();
        assert_eq!(login_resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(login_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let session_id = json
            .get("session_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let csrf = json
            .get("csrf_token")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let cookie_header = format!("mc_session={session_id}; mc_csrf={csrf}");
        assert!(!session_id.is_empty());
        assert!(!csrf.is_empty());

        let reset_without_csrf = Request::builder()
            .method("POST")
            .uri("/api/reset")
            .header("content-type", "application/json")
            .header("cookie", &cookie_header)
            .body(Body::from(r#"{"session_key":"main"}"#))
            .unwrap();
        let bad = app.clone().oneshot(reset_without_csrf).await.unwrap();
        assert_eq!(bad.status(), StatusCode::FORBIDDEN);

        let reset_with_csrf = Request::builder()
            .method("POST")
            .uri("/api/reset")
            .header("content-type", "application/json")
            .header("cookie", &cookie_header)
            .header("x-csrf-token", csrf)
            .body(Body::from(r#"{"session_key":"main"}"#))
            .unwrap();
        let ok = app.oneshot(reset_with_csrf).await.unwrap();
        assert_eq!(ok.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_stream_run_is_owner_isolated_for_api_keys() {
        let web_state = test_web_state(Box::new(DummyLlm), WebLimits::default());
        let db = web_state.app_state.db.clone();
        call_blocking(db, move |d| {
            let scopes = vec!["operator.read".to_string(), "operator.write".to_string()];
            d.upsert_auth_password_hash(&make_password_hash("passw0rd!"))?;
            d.create_api_key(
                "owner-a",
                &sha256_hex("mk_owner_a"),
                "mk_owner_a",
                &scopes,
                None,
                None,
            )?;
            d.create_api_key(
                "owner-b",
                &sha256_hex("mk_owner_b"),
                "mk_owner_b",
                &scopes,
                None,
                None,
            )?;
            Ok(())
        })
        .await
        .unwrap();
        let app = build_router(web_state);

        let send_req = Request::builder()
            .method("POST")
            .uri("/api/send_stream")
            .header("authorization", "Bearer mk_owner_a")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"session_key":"main","sender_name":"u","message":"hello"}"#,
            ))
            .unwrap();
        let send_resp = app.clone().oneshot(send_req).await.unwrap();
        assert_eq!(send_resp.status(), StatusCode::OK);
        let send_body = axum::body::to_bytes(send_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let send_json: serde_json::Value = serde_json::from_slice(&send_body).unwrap();
        let run_id = send_json
            .get("run_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        assert!(!run_id.is_empty());

        let foreign_stream_req = Request::builder()
            .method("GET")
            .uri(format!("/api/stream?run_id={run_id}"))
            .header("authorization", "Bearer mk_owner_b")
            .body(Body::empty())
            .unwrap();
        let foreign_stream_resp = app.clone().oneshot(foreign_stream_req).await.unwrap();
        assert_eq!(foreign_stream_resp.status(), StatusCode::FORBIDDEN);

        let foreign_status_req = Request::builder()
            .method("GET")
            .uri(format!("/api/run_status?run_id={run_id}"))
            .header("authorization", "Bearer mk_owner_b")
            .body(Body::empty())
            .unwrap();
        let foreign_status_resp = app.oneshot(foreign_status_req).await.unwrap();
        assert_eq!(foreign_status_resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_approvals_scoped_key_cannot_rotate_or_revoke_api_keys() {
        let web_state = test_web_state(Box::new(DummyLlm), WebLimits::default());
        let db = web_state.app_state.db.clone();
        let target_id = call_blocking(db, move |d| {
            d.upsert_auth_password_hash(&make_password_hash("passw0rd!"))?;
            d.create_api_key(
                "approvals",
                &sha256_hex("mk_approvals_only"),
                "mk_approve",
                &[
                    "operator.read".to_string(),
                    "operator.write".to_string(),
                    "operator.approvals".to_string(),
                ],
                None,
                None,
            )?;
            d.create_api_key(
                "target",
                &sha256_hex("mk_target_key"),
                "mk_target_",
                &["operator.read".to_string()],
                None,
                None,
            )
        })
        .await
        .unwrap();
        let app = build_router(web_state);

        let rotate_req = Request::builder()
            .method("POST")
            .uri(format!("/api/auth/api_keys/{target_id}/rotate"))
            .header("authorization", "Bearer mk_approvals_only")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"scopes":["operator.admin"]}"#))
            .unwrap();
        let rotate_resp = app.clone().oneshot(rotate_req).await.unwrap();
        assert_eq!(rotate_resp.status(), StatusCode::FORBIDDEN);

        let revoke_req = Request::builder()
            .method("DELETE")
            .uri(format!("/api/auth/api_keys/{target_id}"))
            .header("authorization", "Bearer mk_approvals_only")
            .body(Body::empty())
            .unwrap();
        let revoke_resp = app.oneshot(revoke_req).await.unwrap();
        assert_eq!(revoke_resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_password_bootstrap_token_is_required_and_one_time() {
        let web_state = test_web_state(Box::new(DummyLlm), WebLimits::default());
        {
            let mut guard = web_state.bootstrap_token.lock().await;
            *guard = Some("bootstrap-123".to_string());
        }
        let app = build_router(web_state.clone());

        let missing = Request::builder()
            .method("POST")
            .uri("/api/auth/password")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"password":"passw0rd!"}"#))
            .unwrap();
        let missing_resp = app.clone().oneshot(missing).await.unwrap();
        assert_eq!(missing_resp.status(), StatusCode::UNAUTHORIZED);

        let with_token = Request::builder()
            .method("POST")
            .uri("/api/auth/password")
            .header("content-type", "application/json")
            .header("x-bootstrap-token", "bootstrap-123")
            .body(Body::from(r#"{"password":"passw0rd!"}"#))
            .unwrap();
        let ok_resp = app.clone().oneshot(with_token).await.unwrap();
        assert_eq!(ok_resp.status(), StatusCode::OK);

        let db = web_state.app_state.db.clone();
        let has_password = call_blocking(db, |d| d.get_auth_password_hash())
            .await
            .unwrap()
            .is_some();
        assert!(has_password);

        let second_try = Request::builder()
            .method("POST")
            .uri("/api/auth/password")
            .header("content-type", "application/json")
            .header("x-bootstrap-token", "bootstrap-123")
            .body(Body::from(r#"{"password":"passw0rd!2"}"#))
            .unwrap();
        let second_resp = app.oneshot(second_try).await.unwrap();
        assert_eq!(second_resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_auth_hub_login_bucket_limit_caps_key_spray() {
        let hub = AuthHub::default();
        let window = Duration::from_secs(60);
        for i in 0..AuthHub::MAX_BUCKET_KEYS {
            let ok = hub.allow_login_attempt(&format!("k{i}"), 1, window).await;
            assert!(ok);
        }
        let blocked = hub.allow_login_attempt("overflow", 1, window).await;
        assert!(!blocked);
    }

    #[tokio::test]
    async fn test_a2a_agent_card_route_returns_configured_metadata() {
        let mut cfg = test_config_template();
        cfg.a2a.enabled = true;
        cfg.a2a.agent_name = Some("Planner".into());
        cfg.a2a.agent_description = Some("Plans work".into());
        cfg.a2a.public_base_url = Some("https://microclaw.example.com".into());
        let app = build_router(test_web_state_from_app_state(
            test_state_with_config(Box::new(DummyLlm), cfg),
            WebLimits::default(),
        ));

        let req = Request::builder()
            .method("GET")
            .uri("/api/a2a/agent-card")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            v.get("agent_name").and_then(|x| x.as_str()),
            Some("Planner")
        );
        assert_eq!(
            v.pointer("/endpoints/message").and_then(|x| x.as_str()),
            Some("https://microclaw.example.com/api/a2a/message")
        );
    }

    #[tokio::test]
    async fn test_a2a_message_rejects_invalid_token() {
        let mut cfg = test_config_template();
        cfg.a2a.enabled = true;
        cfg.a2a.shared_tokens = vec!["shared-secret".into()];
        let app = build_router(test_web_state_from_app_state(
            test_state_with_config(Box::new(DummyLlm), cfg),
            WebLimits::default(),
        ));

        let req = Request::builder()
            .method("POST")
            .uri("/api/a2a/message")
            .header("content-type", "application/json")
            .header("authorization", "Bearer wrong")
            .body(Body::from(r#"{"message":"hi","sourceAgent":"worker"}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_a2a_message_round_trip_works() {
        let mut cfg = test_config_template();
        cfg.a2a.enabled = true;
        cfg.a2a.agent_name = Some("Planner".into());
        cfg.a2a.shared_tokens = vec!["shared-secret".into()];
        let web_state = test_web_state_from_app_state(
            test_state_with_config(Box::new(DummyLlm), cfg),
            WebLimits::default(),
        );
        let app = build_router(web_state.clone());

        let req = Request::builder()
            .method("POST")
            .uri("/api/a2a/message")
            .header("content-type", "application/json")
            .header("authorization", "Bearer shared-secret")
            .body(Body::from(
                r#"{"message":"hi","sourceAgent":"worker","sourceUrl":"https://worker.example.com"}"#,
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            v.get("response").and_then(|x| x.as_str()),
            Some("hello from llm")
        );
        assert_eq!(
            v.get("session_key").and_then(|x| x.as_str()),
            Some("a2a:worker")
        );
    }

    #[tokio::test]
    async fn test_ws_connect_and_chat_send_emit_chat_events() {
        let web_state = test_web_state(Box::new(DummyLlm), WebLimits::default());
        seed_test_api_key(&web_state, "ws-secret").await;
        let (addr, server) = spawn_test_server(build_router(web_state.clone())).await;

        let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/"))
            .await
            .unwrap();

        let challenge = recv_ws_json(&mut ws).await;
        assert_eq!(
            challenge.get("type").and_then(|v| v.as_str()),
            Some("event")
        );
        assert_eq!(
            challenge.get("event").and_then(|v| v.as_str()),
            Some("connect.challenge")
        );

        ws.send(tokio_tungstenite::tungstenite::Message::Text(
            json!({
                "type": "req",
                "id": "connect-1",
                "method": "connect",
                "params": {
                    "minProtocol": 3,
                    "maxProtocol": 3,
                    "auth": { "token": "ws-secret" }
                }
            })
            .to_string(),
        ))
        .await
        .unwrap();

        let mut saw_hello = false;
        for _ in 0..4 {
            let msg = recv_ws_json(&mut ws).await;
            if msg.get("type").and_then(|v| v.as_str()) != Some("res") {
                continue;
            }
            if msg.pointer("/payload/type").and_then(|v| v.as_str()) != Some("hello-ok") {
                continue;
            }
            assert_eq!(msg.get("ok").and_then(|v| v.as_bool()), Some(true));
            saw_hello = true;
            break;
        }
        assert!(saw_hello, "expected websocket hello-ok response");

        ws.send(tokio_tungstenite::tungstenite::Message::Text(
            json!({
                "type": "req",
                "id": "send-1",
                "method": "chat.send",
                "params": {
                    "key": "main",
                    "message": "hello over ws",
                    "idempotencyKey": "idem-ws-1"
                }
            })
            .to_string(),
        ))
        .await
        .unwrap();

        let mut saw_ack = false;
        let mut saw_delta = false;
        let mut saw_final = false;
        for _ in 0..12 {
            let msg = recv_ws_json(&mut ws).await;
            match msg.get("type").and_then(|v| v.as_str()) {
                Some("res")
                    if msg.pointer("/payload/status").and_then(|v| v.as_str())
                        == Some("started") =>
                {
                    saw_ack = true;
                }
                Some("event") if msg.get("event").and_then(|v| v.as_str()) == Some("chat") => {
                    let state = msg.pointer("/payload/state").and_then(|v| v.as_str());
                    if state == Some("delta") {
                        saw_delta = true;
                    }
                    if state == Some("final") {
                        saw_final = true;
                        assert_eq!(
                            msg.pointer("/payload/key").and_then(|v| v.as_str()),
                            Some("main")
                        );
                    }
                }
                _ => {}
            }

            if saw_ack && saw_delta && saw_final {
                break;
            }
        }
        assert!(saw_ack, "expected websocket started response");
        assert!(saw_delta, "expected websocket delta event");
        assert!(saw_final, "expected websocket final event");

        server.abort();
    }

    #[tokio::test]
    async fn test_ws_chat_history_returns_session_messages() {
        let web_state = test_web_state(Box::new(DummyLlm), WebLimits::default());
        seed_test_api_key(&web_state, "ws-secret-2").await;
        let (addr, server) = spawn_test_server(build_router(web_state.clone())).await;

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
                    "auth": { "token": "ws-secret-2" }
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
                "id": "send-1",
                "method": "chat.send",
                "params": {
                    "key": "main",
                    "message": "history please",
                    "idempotencyKey": "idem-ws-2"
                }
            })
            .to_string(),
        ))
        .await
        .unwrap();
        let _ = recv_ws_json(&mut ws).await;
        for _ in 0..8 {
            let evt = recv_ws_json(&mut ws).await;
            if evt.pointer("/payload/state").and_then(|v| v.as_str()) == Some("final") {
                break;
            }
        }

        ws.send(tokio_tungstenite::tungstenite::Message::Text(
            json!({
                "type": "req",
                "id": "history-1",
                "method": "chat.history",
                "params": {
                    "key": "main",
                    "limit": 10
                }
            })
            .to_string(),
        ))
        .await
        .unwrap();

        let history = recv_ws_json(&mut ws).await;
        assert_eq!(history.get("ok").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(
            history.pointer("/payload/key").and_then(|v| v.as_str()),
            Some("main")
        );
        assert_eq!(
            history
                .pointer("/payload/sessionKey")
                .and_then(|v| v.as_str()),
            Some("main")
        );
        let messages = history
            .pointer("/payload/messages")
            .and_then(|v| v.as_array())
            .unwrap();
        assert!(messages.iter().any(|m| {
            m.get("role").and_then(|v| v.as_str()) == Some("user")
                && m.pointer("/content/0/text").and_then(|v| v.as_str()) == Some("history please")
        }));
        assert!(messages.iter().any(|m| {
            m.get("role").and_then(|v| v.as_str()) == Some("assistant")
                && m.pointer("/content/0/text").and_then(|v| v.as_str()) == Some("hello from llm")
        }));

        server.abort();
    }

    #[tokio::test]
    async fn test_ws_bridge_supports_agent_and_model_metadata_methods() {
        let web_state = test_web_state(Box::new(DummyLlm), WebLimits::default());
        seed_test_api_key(&web_state, "ws-meta-secret").await;
        let (addr, server) = spawn_test_server(build_router(web_state)).await;

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
                    "auth": { "token": "ws-meta-secret" }
                }
            })
            .to_string(),
        ))
        .await
        .unwrap();
        let _ = recv_ws_json(&mut ws).await;

        for (request_id, method) in [
            ("agents-1", "agents.list"),
            ("models-1", "models.list"),
            ("config-1", "config.get"),
            ("nodes-1", "node.list"),
        ] {
            ws.send(tokio_tungstenite::tungstenite::Message::Text(
                json!({
                    "type": "req",
                    "id": request_id,
                    "method": method,
                    "params": {}
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
                "method={method}"
            );
        }

        server.abort();
    }

    #[tokio::test]
    async fn test_ws_bridge_accepts_legacy_session_aliases() {
        let web_state = test_web_state(Box::new(DummyLlm), WebLimits::default());
        seed_test_api_key(&web_state, "ws-legacy-secret").await;
        let (addr, server) = spawn_test_server(build_router(web_state.clone())).await;

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
                    "auth": { "token": "ws-legacy-secret" }
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
                "session_setLabel",
                json!({"sessionKey":"main","label":"Legacy Ops"}),
            ),
            (
                "send-1",
                "sessions_send",
                json!({"sessionKey":"main","message":"legacy continue"}),
            ),
            ("delete-1", "session_delete", json!({"sessionKey":"main"})),
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
            assert_eq!(
                res.pointer("/payload/key").and_then(|v| v.as_str()),
                Some("main")
            );
            assert_eq!(
                res.pointer("/payload/sessionKey").and_then(|v| v.as_str()),
                Some("main")
            );

            if method == "sessions_send" {
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
                assert!(
                    saw_final,
                    "legacy sessions_send should emit a final chat event"
                );
            }
        }

        server.abort();
    }

    #[tokio::test]
    async fn test_ws_connect_invalid_token_returns_unauthorized() {
        let web_state = test_web_state(Box::new(DummyLlm), WebLimits::default());
        call_blocking(web_state.app_state.db.clone(), |db| {
            db.upsert_auth_password_hash(&make_password_hash("passw0rd!"))
        })
        .await
        .unwrap();
        let (addr, server) = spawn_test_server(build_router(web_state)).await;

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
                    "auth": { "token": "bad-token" }
                }
            })
            .to_string(),
        ))
        .await
        .unwrap();

        let res = recv_ws_json(&mut ws).await;
        assert_eq!(res.get("ok").and_then(|v| v.as_bool()), Some(false));
        assert_eq!(
            res.pointer("/error/code").and_then(|v| v.as_str()),
            Some("UNAUTHORIZED")
        );

        server.abort();
    }

    #[tokio::test]
    async fn test_root_route_accepts_websocket_upgrade() {
        let web_state = test_web_state(Box::new(DummyLlm), WebLimits::default());
        seed_test_api_key(&web_state, "ws-root-secret").await;
        let (addr, server) = spawn_test_server(build_router(web_state)).await;

        let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/"))
            .await
            .unwrap();
        let challenge = recv_ws_json(&mut ws).await;
        assert_eq!(
            challenge.get("event").and_then(|v| v.as_str()),
            Some("connect.challenge")
        );

        ws.send(tokio_tungstenite::tungstenite::Message::Text(
            json!({
                "type": "req",
                "id": "connect-1",
                "method": "connect",
                "params": {
                    "minProtocol": 3,
                    "maxProtocol": 3,
                    "auth": { "token": "ws-root-secret" }
                }
            })
            .to_string(),
        ))
        .await
        .unwrap();

        let res = recv_ws_json(&mut ws).await;
        assert_eq!(res.get("ok").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(
            res.pointer("/payload/protocol").and_then(|v| v.as_u64()),
            Some(3)
        );

        server.abort();
    }

    #[tokio::test]
    async fn test_ws_connect_scope_denied_returns_forbidden() {
        let web_state = test_web_state(Box::new(DummyLlm), WebLimits::default());
        seed_test_api_key_with_scopes(
            &web_state,
            "ws-secret-readless",
            &["operator.write".to_string()],
        )
        .await;
        let (addr, server) = spawn_test_server(build_router(web_state)).await;

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
                    "auth": { "token": "ws-secret-readless" }
                }
            })
            .to_string(),
        ))
        .await
        .unwrap();

        let res = recv_ws_json(&mut ws).await;
        assert_eq!(res.get("ok").and_then(|v| v.as_bool()), Some(false));
        assert_eq!(
            res.pointer("/error/code").and_then(|v| v.as_str()),
            Some("FORBIDDEN")
        );

        server.abort();
    }

    #[tokio::test]
    async fn test_ws_connect_protocol_mismatch_returns_unsupported_protocol() {
        let web_state = test_web_state(Box::new(DummyLlm), WebLimits::default());
        seed_test_api_key(&web_state, "ws-secret-3").await;
        let (addr, server) = spawn_test_server(build_router(web_state)).await;

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
                    "minProtocol": 4,
                    "maxProtocol": 4,
                    "auth": { "token": "ws-secret-3" }
                }
            })
            .to_string(),
        ))
        .await
        .unwrap();

        let res = recv_ws_json(&mut ws).await;
        assert_eq!(res.get("ok").and_then(|v| v.as_bool()), Some(false));
        assert_eq!(
            res.pointer("/error/code").and_then(|v| v.as_str()),
            Some("UNSUPPORTED_PROTOCOL")
        );

        server.abort();
    }
}
