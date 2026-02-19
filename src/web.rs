use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use include_dir::{include_dir, Dir};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::sync::{broadcast, Mutex};
use tracing::{error, info};

use crate::agent_engine::{
    process_with_agent, process_with_agent_with_events, AgentEvent, AgentRequestContext,
};
use crate::config::{Config, WorkingDirIsolation};
use crate::otlp::{OtlpExporter, OtlpMetricSnapshot};
use crate::runtime::AppState;
use microclaw_channels::channel::ConversationKind;
use microclaw_channels::channel::{
    deliver_and_store_bot_message, get_chat_routing, session_source_for_chat,
};
use microclaw_channels::channel_adapter::{ChannelAdapter, ChannelRegistry};
use microclaw_storage::db::{call_blocking, ChatSummary, MetricsHistoryPoint, StoredMessage};
use microclaw_storage::usage::build_usage_report;

static WEB_ASSETS: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/web/dist");

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
struct WebState {
    app_state: Arc<AppState>,
    legacy_auth_token: Option<String>,
    run_hub: RunHub,
    session_hub: SessionHub,
    request_hub: RequestHub,
    auth_hub: AuthHub,
    metrics: Arc<Mutex<WebMetrics>>,
    otlp: Option<Arc<OtlpExporter>>,
    otlp_last_export: Arc<Mutex<Option<Instant>>>,
    otlp_export_interval: Duration,
    limits: WebLimits,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
enum AuthScope {
    Read,
    Write,
    Admin,
    Approvals,
}

#[derive(Clone, Debug)]
struct AuthIdentity {
    scopes: Vec<String>,
    actor: String,
}

impl AuthIdentity {
    fn allows(&self, required: AuthScope) -> bool {
        let want = match required {
            AuthScope::Read => "operator.read",
            AuthScope::Write => "operator.write",
            AuthScope::Admin => "operator.admin",
            AuthScope::Approvals => "operator.approvals",
        };
        self.scopes.iter().any(|s| s == "operator.admin" || s == want)
    }
}

#[derive(Clone, Default)]
struct AuthHub {
    buckets: Arc<Mutex<HashMap<String, VecDeque<Instant>>>>,
}

#[derive(Clone, Debug, Default)]
struct WebMetrics {
    http_requests: i64,
    llm_completions: i64,
    llm_input_tokens: i64,
    llm_output_tokens: i64,
    tool_executions: i64,
    mcp_calls: i64,
}

#[derive(Clone, Debug)]
struct RunEvent {
    id: u64,
    event: String,
    data: String,
}

#[derive(Clone, Default)]
struct RunHub {
    channels: Arc<Mutex<HashMap<String, RunChannel>>>,
}

#[derive(Clone, Default)]
struct SessionHub {
    locks: Arc<Mutex<HashMap<String, SessionLockEntry>>>,
}

#[derive(Clone, Debug)]
struct WebLimits {
    max_inflight_per_session: usize,
    max_requests_per_window: usize,
    rate_window: Duration,
    run_history_limit: usize,
    session_idle_ttl: Duration,
}

impl Default for WebLimits {
    fn default() -> Self {
        Self {
            max_inflight_per_session: 2,
            max_requests_per_window: 8,
            rate_window: Duration::from_secs(10),
            run_history_limit: 512,
            session_idle_ttl: Duration::from_secs(300),
        }
    }
}

impl WebLimits {
    fn from_config(cfg: &Config) -> Self {
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
struct RequestHub {
    sessions: Arc<Mutex<HashMap<String, SessionQuota>>>,
}

struct SessionQuota {
    inflight: usize,
    recent: VecDeque<Instant>,
    last_touch: Instant,
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

struct SessionLockEntry {
    lock: Arc<tokio::sync::Mutex<()>>,
    last_touch: Instant,
}

#[derive(Clone)]
struct RunChannel {
    sender: broadcast::Sender<RunEvent>,
    history: VecDeque<RunEvent>,
    next_id: u64,
    done: bool,
}

impl RunHub {
    async fn create(&self, run_id: &str) {
        let (tx, _) = broadcast::channel(512);
        let mut guard = self.channels.lock().await;
        guard.insert(
            run_id.to_string(),
            RunChannel {
                sender: tx,
                history: VecDeque::new(),
                next_id: 1,
                done: false,
            },
        );
    }

    async fn publish(&self, run_id: &str, event: &str, data: String, history_limit: usize) {
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
        let _ = channel.sender.send(evt);
    }

    async fn subscribe_with_replay(
        &self,
        run_id: &str,
        last_event_id: Option<u64>,
    ) -> Option<(
        broadcast::Receiver<RunEvent>,
        Vec<RunEvent>,
        bool,
        bool,
        Option<u64>,
    )> {
        let guard = self.channels.lock().await;
        let channel = guard.get(run_id)?;
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
        Some((
            channel.sender.subscribe(),
            replay,
            channel.done,
            replay_truncated,
            oldest_event_id,
        ))
    }

    async fn status(&self, run_id: &str) -> Option<(bool, u64)> {
        let guard = self.channels.lock().await;
        let channel = guard.get(run_id)?;
        Some((channel.done, channel.next_id.saturating_sub(1)))
    }

    async fn remove_later(&self, run_id: String, after_seconds: u64) {
        let channels = self.channels.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(after_seconds)).await;
            let mut guard = channels.lock().await;
            guard.remove(&run_id);
        });
    }
}

impl SessionHub {
    async fn lock_for(&self, session_key: &str, limits: &WebLimits) -> Arc<tokio::sync::Mutex<()>> {
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
    async fn begin(
        &self,
        session_key: &str,
        limits: &WebLimits,
    ) -> Result<(), (StatusCode, String)> {
        let now = Instant::now();
        let mut guard = self.sessions.lock().await;
        let quota = guard.entry(session_key.to_string()).or_default();
        quota.last_touch = now;

        while let Some(ts) = quota.recent.front() {
            if now.duration_since(*ts) > limits.rate_window {
                let _ = quota.recent.pop_front();
            } else {
                break;
            }
        }

        if quota.inflight >= limits.max_inflight_per_session {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                "too many concurrent requests for session".into(),
            ));
        }
        if quota.recent.len() >= limits.max_requests_per_window {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                "rate limit exceeded for session".into(),
            ));
        }

        quota.inflight += 1;
        quota.recent.push_back(now);
        Ok(())
    }

    async fn end_with_limits(&self, session_key: &str, limits: &WebLimits) {
        let now = Instant::now();
        let mut guard = self.sessions.lock().await;
        if let Some(quota) = guard.get_mut(session_key) {
            while let Some(ts) = quota.recent.front() {
                if now.duration_since(*ts) > limits.rate_window {
                    let _ = quota.recent.pop_front();
                } else {
                    break;
                }
            }
            quota.inflight = quota.inflight.saturating_sub(1);
            quota.last_touch = now;
            if quota.inflight == 0 && quota.recent.is_empty() {
                guard.remove(session_key);
            }
        }
        guard.retain(|_, quota| {
            !(quota.inflight == 0 && now.duration_since(quota.last_touch) > limits.session_idle_ttl)
        });
    }
}

impl AuthHub {
    async fn allow_login_attempt(
        &self,
        client_key: &str,
        max_attempts: usize,
        window: Duration,
    ) -> bool {
        let now = Instant::now();
        let mut guard = self.buckets.lock().await;
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
}

async fn metrics_http_inc(state: &WebState) {
    let mut m = state.metrics.lock().await;
    m.http_requests += 1;
}

async fn metrics_llm_completion_inc(state: &WebState) {
    let mut m = state.metrics.lock().await;
    m.llm_completions += 1;
}

async fn persist_metrics_snapshot(state: &WebState) -> Result<(), (StatusCode, String)> {
    let snapshot = state.metrics.lock().await.clone();
    let active_sessions = state.request_hub.sessions.lock().await.len() as i64;
    let now = chrono::Utc::now();
    let bucket_ts_ms = (now.timestamp() / 60) * 60 * 1000;
    let point = MetricsHistoryPoint {
        timestamp_ms: bucket_ts_ms,
        llm_completions: snapshot.llm_completions,
        llm_input_tokens: snapshot.llm_input_tokens,
        llm_output_tokens: snapshot.llm_output_tokens,
        http_requests: snapshot.http_requests,
        tool_executions: snapshot.tool_executions,
        mcp_calls: snapshot.mcp_calls,
        active_sessions,
    };
    call_blocking(state.app_state.db.clone(), move |db| {
        db.upsert_metrics_history(&point)
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let retention_days = metrics_history_retention_days(&state.app_state.config);
    let cutoff = chrono::Utc::now() - chrono::Duration::days(retention_days);
    let cutoff_ms = cutoff.timestamp_millis();
    let _ = call_blocking(state.app_state.db.clone(), move |db| {
        db.cleanup_metrics_history_before(cutoff_ms).map(|_| ())
    })
    .await;

    if let Some(exporter) = state.otlp.clone() {
        let should_export = {
            let mut last = state.otlp_last_export.lock().await;
            let now_i = Instant::now();
            let due = last
                .as_ref()
                .map(|t| now_i.duration_since(*t) >= state.otlp_export_interval)
                .unwrap_or(true);
            if due {
                *last = Some(now_i);
            }
            due
        };
        if should_export {
            let metric_snapshot = OtlpMetricSnapshot {
                timestamp_unix_nano: now.timestamp_nanos_opt().unwrap_or(0) as u64,
                http_requests: snapshot.http_requests,
                llm_completions: snapshot.llm_completions,
                llm_input_tokens: snapshot.llm_input_tokens,
                llm_output_tokens: snapshot.llm_output_tokens,
                tool_executions: snapshot.tool_executions,
                mcp_calls: snapshot.mcp_calls,
                active_sessions,
            };
            tokio::spawn(async move {
                if let Err(e) = exporter.export_metrics(metric_snapshot).await {
                    tracing::warn!("otlp export failed: {}", e);
                }
            });
        }
    }
    Ok(())
}

fn otlp_export_interval(config: &Config) -> Duration {
    if let Some(map) = config
        .channels
        .get("observability")
        .and_then(|v| v.as_mapping())
    {
        if let Some(n) = map
            .get(serde_yaml::Value::String(
                "otlp_export_interval_seconds".to_string(),
            ))
            .and_then(|v| v.as_u64())
        {
            return Duration::from_secs(n.clamp(1, 3600));
        }
    }
    Duration::from_secs(15)
}

fn metrics_history_retention_days(config: &Config) -> i64 {
    if let Some(map) = config.channels.get("web").and_then(|v| v.as_mapping()) {
        if let Some(n) = map
            .get(serde_yaml::Value::String(
                "metrics_history_retention_days".to_string(),
            ))
            .and_then(|v| v.as_i64())
        {
            return n.clamp(1, 3650);
        }
    }
    30
}

async fn audit_log(
    state: &WebState,
    kind: &str,
    actor: &str,
    action: &str,
    target: Option<&str>,
    status: &str,
    detail: Option<&str>,
) {
    let kind = kind.to_string();
    let actor = actor.to_string();
    let action = action.to_string();
    let target = target.map(str::to_string);
    let status = status.to_string();
    let detail = detail.map(str::to_string);
    let _ = call_blocking(state.app_state.db.clone(), move |db| {
        db.log_audit_event(
            &kind,
            &actor,
            &action,
            target.as_deref(),
            &status,
            detail.as_deref(),
        )
        .map(|_| ())
    })
    .await;
}

fn auth_token_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|raw| raw.strip_prefix("Bearer "))
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn parse_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get("cookie")?.to_str().ok()?;
    for part in raw.split(';') {
        let mut kv = part.trim().splitn(2, '=');
        let k = kv.next()?.trim();
        let v = kv.next().unwrap_or("").trim();
        if k == name && !v.is_empty() {
            return Some(v.to_string());
        }
    }
    None
}

fn session_cookie_header(session_id: &str, expires_at: &str) -> String {
    let mut header = format!(
        "mc_session={session_id}; Path=/; HttpOnly; SameSite=Strict; Expires={expires_at}"
    );
    header.push_str("; Secure");
    header
}

fn csrf_cookie_header(csrf_token: &str, expires_at: &str) -> String {
    let mut header =
        format!("mc_csrf={csrf_token}; Path=/; SameSite=Strict; Expires={expires_at}");
    header.push_str("; Secure");
    header
}

fn clear_session_cookie_header() -> String {
    "mc_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0".to_string()
}

fn clear_csrf_cookie_header() -> String {
    "mc_csrf=; Path=/; SameSite=Strict; Max-Age=0".to_string()
}

fn make_password_hash(password: &str) -> String {
    let salt = SaltString::encode_b64(uuid::Uuid::new_v4().as_bytes())
        .unwrap_or_else(|_| SaltString::from_b64("AAAAAAAAAAAAAAAAAAAAAA").unwrap());
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .unwrap_or_default()
}

fn verify_password_hash(stored: &str, password: &str) -> bool {
    if let Ok(parsed) = PasswordHash::new(stored) {
        return Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok();
    }
    let mut parts = stored.split('$');
    let Some(ver) = parts.next() else {
        return false;
    };
    if ver != "v1" {
        return false;
    }
    let Some(salt) = parts.next() else {
        return false;
    };
    let Some(hash) = parts.next() else {
        return false;
    };
    sha256_hex(&format!("{salt}:{password}")) == hash
}

fn client_key_from_headers(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or("").trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "global".to_string())
}

async fn require_scope(
    state: &WebState,
    headers: &HeaderMap,
    required: AuthScope,
) -> Result<AuthIdentity, (StatusCode, String)> {
    let needs_csrf = matches!(
        required,
        AuthScope::Write | AuthScope::Admin | AuthScope::Approvals
    );
    let has_password = call_blocking(state.app_state.db.clone(), |db| db.get_auth_password_hash())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .is_some();
    if state.legacy_auth_token.is_none() && !has_password {
        let id = AuthIdentity {
            scopes: vec![
                "operator.read".to_string(),
                "operator.write".to_string(),
                "operator.admin".to_string(),
                "operator.approvals".to_string(),
            ],
            actor: "bootstrap".to_string(),
        };
        if id.allows(required) {
            return Ok(id);
        }
        return Err((StatusCode::FORBIDDEN, "forbidden".into()));
    }

    if let Some(provided) = auth_token_from_headers(headers) {
        if let Some(expected) = state.legacy_auth_token.as_deref() {
            if provided == expected {
                let id = AuthIdentity {
                    scopes: vec![
                        "operator.read".to_string(),
                        "operator.write".to_string(),
                        "operator.admin".to_string(),
                        "operator.approvals".to_string(),
                    ],
                    actor: "legacy-token".to_string(),
                };
                if id.allows(required) {
                    return Ok(id);
                }
            }
        }

        let key_hash = sha256_hex(&provided);
        if let Some((key_id, scopes)) =
            call_blocking(state.app_state.db.clone(), move |db| db.validate_api_key_hash(&key_hash))
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        {
            let id = AuthIdentity {
                scopes,
                actor: format!("api-key:{key_id}"),
            };
            if id.allows(required) {
                return Ok(id);
            }
            return Err((StatusCode::FORBIDDEN, "forbidden".into()));
        }
    }

    if let Some(session_id) = parse_cookie(headers, "mc_session") {
        let session_id_for_validate = session_id.clone();
        let valid = call_blocking(state.app_state.db.clone(), move |db| {
            db.validate_auth_session(&session_id_for_validate)
        })
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        if valid {
            if needs_csrf {
                let cookie_csrf = parse_cookie(headers, "mc_csrf");
                let header_csrf = headers
                    .get("x-csrf-token")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                if cookie_csrf.is_none() || header_csrf.is_none() || cookie_csrf != header_csrf {
                    return Err((StatusCode::FORBIDDEN, "missing or invalid csrf token".into()));
                }
            }
            let id = AuthIdentity {
                scopes: vec![
                    "operator.read".to_string(),
                    "operator.write".to_string(),
                    "operator.admin".to_string(),
                    "operator.approvals".to_string(),
                ],
                actor: format!("session:{session_id}"),
            };
            if id.allows(required) {
                return Ok(id);
            }
            return Err((StatusCode::FORBIDDEN, "forbidden".into()));
        }
    }

    Err((StatusCode::UNAUTHORIZED, "unauthorized".into()))
}

fn normalize_session_key(session_key: Option<&str>) -> String {
    let key = session_key.unwrap_or("main").trim();
    if key.is_empty() {
        "main".into()
    } else {
        key.into()
    }
}

#[derive(Debug, Serialize)]
struct SessionItem {
    session_key: String,
    label: String,
    chat_id: i64,
    chat_type: String,
    last_message_time: String,
    last_message_preview: Option<String>,
}

#[derive(Debug, Serialize)]
struct HistoryItem {
    id: String,
    sender_name: String,
    content: String,
    is_from_bot: bool,
    timestamp: String,
}

#[derive(Debug, Deserialize)]
struct HistoryQuery {
    session_key: Option<String>,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct SendRequest {
    session_key: Option<String>,
    sender_name: Option<String>,
    message: String,
}

#[derive(Debug, Deserialize)]
struct StreamQuery {
    run_id: String,
    last_event_id: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct ResetRequest {
    session_key: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RunStatusQuery {
    run_id: String,
}

#[derive(Debug, Deserialize)]
struct UsageQuery {
    session_key: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MemoryObservabilityQuery {
    session_key: Option<String>,
    scope: Option<String>, // chat | global
    hours: Option<u64>,
    limit: Option<usize>,
    offset: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct UpdateConfigRequest {
    llm_provider: Option<String>,
    api_key: Option<String>,
    model: Option<String>,
    llm_base_url: Option<Option<String>>,
    max_tokens: Option<u32>,
    max_tool_iterations: Option<usize>,
    max_document_size_mb: Option<u64>,
    memory_token_budget: Option<usize>,
    embedding_provider: Option<Option<String>>,
    embedding_api_key: Option<Option<String>>,
    embedding_base_url: Option<Option<String>>,
    embedding_model: Option<Option<String>>,
    embedding_dim: Option<Option<usize>>,
    working_dir_isolation: Option<WorkingDirIsolation>,

    telegram_bot_token: Option<String>,
    bot_username: Option<String>,
    discord_bot_token: Option<String>,
    discord_allowed_channels: Option<Vec<u64>>,

    /// Generic per-channel config updates. Keys are channel names (e.g. "slack", "feishu").
    /// Values are objects with channel-specific fields. Non-empty string values are merged
    /// into `cfg.channels[name]`; this avoids adding per-channel fields here.
    #[serde(default)]
    channel_configs: Option<HashMap<String, HashMap<String, serde_json::Value>>>,

    reflector_enabled: Option<bool>,
    reflector_interval_mins: Option<u64>,

    show_thinking: Option<bool>,
    web_enabled: Option<bool>,
    web_host: Option<String>,
    web_port: Option<u16>,
    web_auth_token: Option<Option<String>>,
    web_max_inflight_per_session: Option<usize>,
    web_max_requests_per_window: Option<usize>,
    web_rate_window_seconds: Option<u64>,
    web_run_history_limit: Option<usize>,
    web_session_idle_ttl_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    password: String,
    label: Option<String>,
    remember_days: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct SetPasswordRequest {
    password: String,
}

#[derive(Debug, Deserialize)]
struct CreateApiKeyRequest {
    label: String,
    scopes: Vec<String>,
    expires_days: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct RotateApiKeyRequest {
    label: Option<String>,
    scopes: Option<Vec<String>>,
    expires_days: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct ForkSessionRequest {
    source_session_key: String,
    target_session_key: Option<String>,
    fork_point: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct MetricsHistoryQuery {
    minutes: Option<i64>,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct SessionTreeQuery {
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct AuditQuery {
    kind: Option<String>,
    limit: Option<usize>,
}

/// Convert a serde_json::Value to a serde_yaml::Value for channel config merging.
fn json_to_yaml_value(v: &serde_json::Value) -> serde_yaml::Value {
    match v {
        serde_json::Value::Null => serde_yaml::Value::Null,
        serde_json::Value::Bool(b) => serde_yaml::Value::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                serde_yaml::Value::Number(i.into())
            } else if let Some(u) = n.as_u64() {
                serde_yaml::Value::Number(u.into())
            } else if let Some(f) = n.as_f64() {
                serde_yaml::Value::Number(serde_yaml::Number::from(f))
            } else {
                serde_yaml::Value::Null
            }
        }
        serde_json::Value::String(s) => serde_yaml::Value::String(s.clone()),
        serde_json::Value::Array(arr) => {
            serde_yaml::Value::Sequence(arr.iter().map(json_to_yaml_value).collect())
        }
        serde_json::Value::Object(obj) => {
            let mut map = serde_yaml::Mapping::new();
            for (k, v) in obj {
                map.insert(serde_yaml::Value::String(k.clone()), json_to_yaml_value(v));
            }
            serde_yaml::Value::Mapping(map)
        }
    }
}

/// Channel secret field names to redact in API responses.
/// Adding a new channel only requires adding an entry here.
const CHANNEL_SECRET_FIELDS: &[(&str, &[&str])] = &[
    ("slack", &["bot_token", "app_token"]),
    ("feishu", &["app_secret"]),
];

fn config_path_for_save() -> Result<PathBuf, (StatusCode, String)> {
    match Config::resolve_config_path() {
        Ok(Some(path)) => Ok(path),
        Ok(None) => Ok(PathBuf::from("./microclaw.config.yaml")),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

fn redact_config(config: &Config) -> serde_json::Value {
    let mut cfg = config.clone();
    if !cfg.telegram_bot_token.is_empty() {
        cfg.telegram_bot_token = "***".into();
    }
    if !cfg.api_key.is_empty() {
        cfg.api_key = "***".into();
    }
    if cfg.openai_api_key.is_some() {
        cfg.openai_api_key = Some("***".into());
    }
    if cfg.discord_bot_token.is_some() {
        cfg.discord_bot_token = Some("***".into());
    }
    if cfg.embedding_api_key.is_some() {
        cfg.embedding_api_key = Some("***".into());
    }
    if cfg.web_auth_token.is_some() {
        cfg.web_auth_token = Some("***".into());
    }

    // Redact secrets in channels map using declarative list
    for (channel_name, secret_fields) in CHANNEL_SECRET_FIELDS {
        if let Some(channel_val) = cfg.channels.get_mut(*channel_name) {
            if let Some(map) = channel_val.as_mapping_mut() {
                for field in *secret_fields {
                    let key = serde_yaml::Value::String((*field).to_string());
                    if map.contains_key(&key) {
                        map.insert(key, serde_yaml::Value::String("***".into()));
                    }
                }
            }
        }
    }

    json!(cfg)
}

async fn index() -> impl IntoResponse {
    match WEB_ASSETS.get_file("index.html") {
        Some(file) => Html(String::from_utf8_lossy(file.contents()).to_string()).into_response(),
        None => (StatusCode::NOT_FOUND, "index.html missing").into_response(),
    }
}

async fn api_health(
    headers: HeaderMap,
    State(state): State<WebState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    require_scope(&state, &headers, AuthScope::Read).await?;
    Ok(Json(json!({
        "ok": true,
        "version": env!("CARGO_PKG_VERSION"),
        "web_enabled": state.app_state.config.web_enabled,
    })))
}

async fn api_auth_status(
    headers: HeaderMap,
    State(state): State<WebState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    let has_password = call_blocking(state.app_state.db.clone(), |db| db.get_auth_password_hash())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .is_some();
    let authenticated = require_scope(&state, &headers, AuthScope::Read).await.is_ok();
    Ok(Json(json!({
        "ok": true,
        "authenticated": authenticated,
        "has_password": has_password
    })))
}

async fn api_auth_set_password(
    headers: HeaderMap,
    State(state): State<WebState>,
    Json(body): Json<SetPasswordRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    let identity = require_scope(&state, &headers, AuthScope::Admin).await?;
    let password = body.password.trim();
    if password.len() < 8 {
        return Err((StatusCode::BAD_REQUEST, "password must be at least 8 chars".into()));
    }
    let hash = make_password_hash(password);
    call_blocking(state.app_state.db.clone(), move |db| {
        db.upsert_auth_password_hash(&hash)
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    audit_log(
        &state,
        "operator",
        &identity.actor,
        "auth.set_password",
        None,
        "ok",
        None,
    )
    .await;
    Ok(Json(json!({"ok": true})))
}

async fn api_auth_login(
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
        return Err((StatusCode::TOO_MANY_REQUESTS, "too many login attempts".into()));
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
        .map(|dt| dt.with_timezone(&chrono::Utc).format("%a, %d %b %Y %H:%M:%S GMT").to_string())
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
    audit_log(
        &state,
        "operator",
        "login",
        "auth.login",
        None,
        "ok",
        None,
    )
    .await;
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

async fn api_auth_logout(
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

async fn api_auth_api_keys(
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

async fn api_auth_create_api_key(
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
        return Err((StatusCode::BAD_REQUEST, "at least one scope is required".into()));
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
        return Err((StatusCode::BAD_REQUEST, "at least one scope is required".into()));
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
    Ok(Json(json!({"ok": true, "api_key": raw_key, "prefix": prefix, "scopes": scopes, "expires_at": expires_at})))
}

async fn api_auth_revoke_api_key(
    headers: HeaderMap,
    State(state): State<WebState>,
    Path(key_id): Path<i64>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    let identity = require_scope(&state, &headers, AuthScope::Approvals).await?;
    let revoked = call_blocking(state.app_state.db.clone(), move |db| db.revoke_api_key(key_id))
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

async fn api_auth_rotate_api_key(
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
        return Err((StatusCode::BAD_REQUEST, "at least one scope is required".into()));
    }
    let label = body.label.unwrap_or_else(|| format!("{} (rotated)", old.label));
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

async fn api_get_config(
    headers: HeaderMap,
    State(state): State<WebState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    require_scope(&state, &headers, AuthScope::Admin).await?;

    let path = config_path_for_save()?;
    Ok(Json(json!({
        "ok": true,
        "path": path,
        "config": redact_config(&state.app_state.config),
        "requires_restart": true
    })))
}

async fn api_update_config(
    headers: HeaderMap,
    State(state): State<WebState>,
    Json(body): Json<UpdateConfigRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    let identity = require_scope(&state, &headers, AuthScope::Admin).await?;

    let mut cfg = state.app_state.config.clone();

    if let Some(v) = body.llm_provider {
        cfg.llm_provider = v;
    }
    if let Some(v) = body.api_key {
        cfg.api_key = v;
    }
    if let Some(v) = body.model {
        cfg.model = v;
    }
    if let Some(v) = body.llm_base_url {
        cfg.llm_base_url = v;
    }
    if let Some(v) = body.max_tokens {
        cfg.max_tokens = v;
    }
    if let Some(v) = body.max_tool_iterations {
        cfg.max_tool_iterations = v;
    }
    if let Some(v) = body.max_document_size_mb {
        cfg.max_document_size_mb = v;
    }
    if let Some(v) = body.memory_token_budget {
        cfg.memory_token_budget = v;
    }
    if let Some(v) = body.embedding_provider {
        cfg.embedding_provider = v;
    }
    if let Some(v) = body.embedding_api_key {
        cfg.embedding_api_key = v;
    }
    if let Some(v) = body.embedding_base_url {
        cfg.embedding_base_url = v;
    }
    if let Some(v) = body.embedding_model {
        cfg.embedding_model = v;
    }
    if let Some(v) = body.embedding_dim {
        cfg.embedding_dim = v;
    }
    if let Some(v) = body.working_dir_isolation {
        cfg.working_dir_isolation = v;
    }
    if let Some(v) = body.telegram_bot_token {
        cfg.telegram_bot_token = v;
    }
    if let Some(v) = body.bot_username {
        cfg.bot_username = v;
    }
    if let Some(v) = body.discord_bot_token {
        cfg.discord_bot_token = if v.trim().is_empty() { None } else { Some(v) };
    }
    if let Some(v) = body.discord_allowed_channels {
        cfg.discord_allowed_channels = v;
    }

    // Generic channel config merge — handles any channel (slack, feishu, future ones)
    if let Some(channel_configs) = body.channel_configs {
        for (channel_name, fields) in channel_configs {
            let entry = cfg
                .channels
                .entry(channel_name)
                .or_insert_with(|| serde_yaml::Value::Mapping(Default::default()));
            if let Some(map) = entry.as_mapping_mut() {
                for (field_key, json_val) in fields {
                    // Skip empty strings (treated as "no change")
                    if let Some(s) = json_val.as_str() {
                        if s.trim().is_empty() {
                            continue;
                        }
                    }
                    let yaml_val = json_to_yaml_value(&json_val);
                    map.insert(serde_yaml::Value::String(field_key), yaml_val);
                }
            }
        }
    }

    if let Some(v) = body.reflector_enabled {
        cfg.reflector_enabled = v;
    }
    if let Some(v) = body.reflector_interval_mins {
        cfg.reflector_interval_mins = v;
    }

    if let Some(v) = body.show_thinking {
        cfg.show_thinking = v;
    }
    if let Some(v) = body.web_enabled {
        cfg.web_enabled = v;
    }
    if let Some(v) = body.web_host {
        cfg.web_host = v;
    }
    if let Some(v) = body.web_port {
        cfg.web_port = v;
    }
    if let Some(v) = body.web_auth_token {
        cfg.web_auth_token = v;
    }
    if let Some(v) = body.web_max_inflight_per_session {
        cfg.web_max_inflight_per_session = v;
    }
    if let Some(v) = body.web_max_requests_per_window {
        cfg.web_max_requests_per_window = v;
    }
    if let Some(v) = body.web_rate_window_seconds {
        cfg.web_rate_window_seconds = v;
    }
    if let Some(v) = body.web_run_history_limit {
        cfg.web_run_history_limit = v;
    }
    if let Some(v) = body.web_session_idle_ttl_seconds {
        cfg.web_session_idle_ttl_seconds = v;
    }

    if let Err(e) = cfg.post_deserialize() {
        return Err((StatusCode::BAD_REQUEST, e.to_string()));
    }

    let path = config_path_for_save()?;
    cfg.save_yaml(&path.to_string_lossy())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    audit_log(
        &state,
        "operator",
        &identity.actor,
        "config.update",
        Some(&path.to_string_lossy()),
        "ok",
        None,
    )
    .await;

    Ok(Json(json!({
        "ok": true,
        "path": path,
        "requires_restart": true
    })))
}

fn map_chat_to_session(registry: &ChannelRegistry, chat: ChatSummary) -> SessionItem {
    let source = session_source_for_chat(registry, &chat.chat_type, chat.chat_title.as_deref());

    let fallback = format!("{}:{}", source, chat.chat_id);
    let mut label = chat.chat_title.clone().unwrap_or_else(|| fallback.clone());

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

fn parse_chat_id_from_session_key(session_key: &str) -> Option<i64> {
    session_key
        .strip_prefix("chat:")
        .and_then(|s| s.parse::<i64>().ok())
}

async fn resolve_chat_id_for_session_key(
    state: &WebState,
    session_key: &str,
) -> Result<i64, (StatusCode, String)> {
    if let Some(parsed) = parse_chat_id_from_session_key(session_key) {
        return Ok(parsed);
    }

    let key = session_key.to_string();
    let by_title = call_blocking(state.app_state.db.clone(), move |db| {
        db.get_recent_chats(4000)
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .into_iter()
    .find(|c| c.chat_title.as_deref() == Some(key.as_str()))
    .map(|c| c.chat_id);

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

async fn api_sessions(
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

async fn api_history(
    headers: HeaderMap,
    State(state): State<WebState>,
    Query(query): Query<HistoryQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    require_scope(&state, &headers, AuthScope::Read).await?;

    let session_key = normalize_session_key(query.session_key.as_deref());
    let chat_id = resolve_chat_id_for_session_key(&state, &session_key).await?;

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

async fn api_usage(
    headers: HeaderMap,
    State(state): State<WebState>,
    Query(query): Query<UsageQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    require_scope(&state, &headers, AuthScope::Read).await?;

    let session_key = normalize_session_key(query.session_key.as_deref());
    let chat_id = resolve_chat_id_for_session_key(&state, &session_key).await?;
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

async fn api_memory_observability(
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
        Some(resolve_chat_id_for_session_key(&state, &session_key).await?)
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

async fn api_send(
    headers: HeaderMap,
    State(state): State<WebState>,
    Json(body): Json<SendRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    require_scope(&state, &headers, AuthScope::Write).await?;
    let start = Instant::now();
    let session_key = normalize_session_key(body.session_key.as_deref());
    if let Err((status, msg)) = state.request_hub.begin(&session_key, &state.limits).await {
        info!(
            target: "web",
            endpoint = "/api/send",
            session_key = %session_key,
            status = status.as_u16(),
            reason = %msg,
            "Request rejected by limiter"
        );
        return Err((status, msg));
    }
    let result = send_and_store_response(state.clone(), body).await;
    if result.is_ok() {
        metrics_llm_completion_inc(&state).await;
    }
    let _ = persist_metrics_snapshot(&state).await;
    state
        .request_hub
        .end_with_limits(&session_key, &state.limits)
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

async fn api_send_stream(
    headers: HeaderMap,
    State(state): State<WebState>,
    Json(body): Json<SendRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    require_scope(&state, &headers, AuthScope::Write).await?;
    let start = Instant::now();

    let text = body.message.trim().to_string();
    if text.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "message is required".into()));
    }

    let session_key = normalize_session_key(body.session_key.as_deref());
    if let Err((status, msg)) = state.request_hub.begin(&session_key, &state.limits).await {
        info!(
            target: "web",
            endpoint = "/api/send_stream",
            session_key = %session_key,
            status = status.as_u16(),
            reason = %msg,
            "Request rejected by limiter"
        );
        return Err((status, msg));
    }

    let run_id = uuid::Uuid::new_v4().to_string();
    state.run_hub.create(&run_id).await;
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
        endpoint = "/api/send_stream",
        session_key = %session_key,
        run_id = %run_id,
        latency_ms = start.elapsed().as_millis(),
        "Accepted stream run"
    );

    tokio::spawn(async move {
        let run_start = Instant::now();
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
        let metrics_for_events = state_for_task.metrics.clone();
        let run_id_for_events = run_id_for_task.clone();
        let run_history_limit = limits.run_history_limit;
        let forward = tokio::spawn(async move {
            while let Some(evt) = evt_rx.recv().await {
                match evt {
                    AgentEvent::Iteration { iteration } => {
                        run_hub
                            .publish(
                                &run_id_for_events,
                                "status",
                                json!({"message": format!("iteration {iteration}")}).to_string(),
                                run_history_limit,
                            )
                            .await;
                    }
                    AgentEvent::ToolStart { name } => {
                        {
                            let mut m = metrics_for_events.lock().await;
                            m.tool_executions += 1;
                            if name.starts_with("mcp") {
                                m.mcp_calls += 1;
                            }
                        }
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
                }
            }
        });

        match send_and_store_response_with_events(state_for_task.clone(), body, Some(&evt_tx)).await
        {
            Ok(resp) => {
                metrics_llm_completion_inc(&state_for_task).await;
                let _ = persist_metrics_snapshot(&state_for_task).await;
                let response_text = resp
                    .0
                    .get("response")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();

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
            Err((_, err_msg)) => {
                let _ = persist_metrics_snapshot(&state_for_task).await;
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
        state_for_task
            .request_hub
            .end_with_limits(&session_key_for_release, &limits)
            .await;
        info!(
            target: "web",
            endpoint = "/api/send_stream",
            session_key = %session_key_for_release,
            run_id = %run_id_for_task,
            latency_ms = run_start.elapsed().as_millis(),
            "Stream run finished"
        );

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

async fn api_stream(
    headers: HeaderMap,
    State(state): State<WebState>,
    Query(query): Query<StreamQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    require_scope(&state, &headers, AuthScope::Read).await?;
    let start = Instant::now();

    let Some((mut rx, replay, done, replay_truncated, oldest_event_id)) = state
        .run_hub
        .subscribe_with_replay(&query.run_id, query.last_event_id)
        .await
    else {
        return Err((StatusCode::NOT_FOUND, "run not found".into()));
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

async fn api_run_status(
    headers: HeaderMap,
    State(state): State<WebState>,
    Query(query): Query<RunStatusQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    require_scope(&state, &headers, AuthScope::Read).await?;
    let Some((done, last_event_id)) = state.run_hub.status(&query.run_id).await else {
        return Err((StatusCode::NOT_FOUND, "run not found".into()));
    };
    Ok(Json(json!({
        "ok": true,
        "run_id": query.run_id,
        "done": done,
        "last_event_id": last_event_id,
    })))
}

async fn send_and_store_response(
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

async fn send_and_store_response_with_events(
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

    let response = if let Some(tx) = event_tx {
        process_with_agent_with_events(
            &state.app_state,
            AgentRequestContext {
                caller_channel: "web",
                chat_id,
                chat_type: "web",
            },
            None,
            None,
            Some(tx),
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    } else {
        process_with_agent(
            &state.app_state,
            AgentRequestContext {
                caller_channel: "web",
                chat_id,
                chat_type: "web",
            },
            None,
            None,
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    };

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

    deliver_and_store_bot_message(
        &state.app_state.channel_registry,
        state.app_state.db.clone(),
        &state.app_state.config.bot_username,
        chat_id,
        &response,
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(Json(json!({
        "ok": true,
        "session_key": session_key,
        "chat_id": chat_id,
        "response": response,
    })))
}

async fn api_reset(
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

        // Keep the web session entry in the session list after clearing context.
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

async fn api_delete_session(
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

async fn api_sessions_fork(
    headers: HeaderMap,
    State(state): State<WebState>,
    Json(body): Json<ForkSessionRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    let identity = require_scope(&state, &headers, AuthScope::Approvals).await?;

    let source_session_key = normalize_session_key(Some(&body.source_session_key));
    let target_session_key = body.target_session_key.map(|v| normalize_session_key(Some(&v))).unwrap_or_else(|| {
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
        call_blocking(state.app_state.db.clone(), move |db| db.store_message(&copied))
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

async fn api_metrics(
    headers: HeaderMap,
    State(state): State<WebState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    require_scope(&state, &headers, AuthScope::Read).await?;
    persist_metrics_snapshot(&state).await?;

    let snapshot = state.metrics.lock().await.clone();
    let active_sessions = state.request_hub.sessions.lock().await.len() as i64;
    Ok(Json(json!({
        "ok": true,
        "metrics": {
            "http_requests": snapshot.http_requests,
            "llm_completions": snapshot.llm_completions,
            "llm_input_tokens": snapshot.llm_input_tokens,
            "llm_output_tokens": snapshot.llm_output_tokens,
            "tool_executions": snapshot.tool_executions,
            "mcp_calls": snapshot.mcp_calls,
            "active_sessions": active_sessions
        }
    })))
}

async fn api_metrics_summary(
    headers: HeaderMap,
    State(state): State<WebState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    api_metrics(headers, State(state)).await
}

async fn api_metrics_history(
    headers: HeaderMap,
    State(state): State<WebState>,
    Query(query): Query<MetricsHistoryQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    require_scope(&state, &headers, AuthScope::Read).await?;
    persist_metrics_snapshot(&state).await?;

    let minutes = query.minutes.unwrap_or(24 * 60).clamp(1, 24 * 60 * 30);
    let limit = query.limit.unwrap_or(2000).clamp(1, 20000);
    let since = (chrono::Utc::now() - chrono::Duration::minutes(minutes)).timestamp_millis();
    let rows = call_blocking(state.app_state.db.clone(), move |db| {
        db.get_metrics_history(since, limit)
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({
        "ok": true,
        "minutes": minutes,
        "points": rows.into_iter().map(|r| json!({
            "timestamp_ms": r.timestamp_ms,
            "llm_completions": r.llm_completions,
            "llm_input_tokens": r.llm_input_tokens,
            "llm_output_tokens": r.llm_output_tokens,
            "http_requests": r.http_requests,
            "tool_executions": r.tool_executions,
            "mcp_calls": r.mcp_calls,
            "active_sessions": r.active_sessions
        })).collect::<Vec<_>>()
    })))
}

async fn api_sessions_tree(
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

async fn api_audit_logs(
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

pub async fn start_web_server(state: Arc<AppState>) {
    let limits = WebLimits::from_config(&state.config);
    let web_state = WebState {
        legacy_auth_token: state.config.web_auth_token.clone(),
        app_state: state.clone(),
        run_hub: RunHub::default(),
        session_hub: SessionHub::default(),
        request_hub: RequestHub::default(),
        auth_hub: AuthHub::default(),
        metrics: Arc::new(Mutex::new(WebMetrics::default())),
        otlp: OtlpExporter::from_config(&state.config),
        otlp_last_export: Arc::new(Mutex::new(None)),
        otlp_export_interval: otlp_export_interval(&state.config),
        limits,
    };

    let router = build_router(web_state);

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

async fn asset_file(Path(file): Path<String>) -> impl IntoResponse {
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

async fn icon_file() -> impl IntoResponse {
    match WEB_ASSETS.get_file("icon.png") {
        Some(file) => ([("content-type", "image/png")], file.contents().to_vec()).into_response(),
        None => (StatusCode::NOT_FOUND, "Not Found").into_response(),
    }
}

async fn favicon_file() -> impl IntoResponse {
    if let Some(file) = WEB_ASSETS.get_file("favicon.ico") {
        return ([("content-type", "image/x-icon")], file.contents().to_vec()).into_response();
    }
    if let Some(file) = WEB_ASSETS.get_file("icon.png") {
        return ([("content-type", "image/png")], file.contents().to_vec()).into_response();
    }
    (StatusCode::NOT_FOUND, "Not Found").into_response()
}

fn build_router(web_state: WebState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/assets/*file", get(asset_file))
        .route("/icon.png", get(icon_file))
        .route("/favicon.ico", get(favicon_file))
        .route("/api/health", get(api_health))
        .route("/api/auth/status", get(api_auth_status))
        .route("/api/auth/password", post(api_auth_set_password))
        .route("/api/auth/login", post(api_auth_login))
        .route("/api/auth/logout", post(api_auth_logout))
        .route(
            "/api/auth/api_keys",
            get(api_auth_api_keys).post(api_auth_create_api_key),
        )
        .route("/api/auth/api_keys/:id", axum::routing::delete(api_auth_revoke_api_key))
        .route("/api/auth/api_keys/:id/rotate", post(api_auth_rotate_api_key))
        .route("/api/config", get(api_get_config).put(api_update_config))
        .route("/api/sessions", get(api_sessions))
        .route("/api/sessions/tree", get(api_sessions_tree))
        .route("/api/sessions/fork", post(api_sessions_fork))
        .route("/api/audit", get(api_audit_logs))
        .route("/api/history", get(api_history))
        .route("/api/usage", get(api_usage))
        .route("/api/memory_observability", get(api_memory_observability))
        .route("/api/metrics", get(api_metrics))
        .route("/api/metrics/summary", get(api_metrics_summary))
        .route("/api/metrics/history", get(api_metrics_history))
        .route("/api/send", post(api_send))
        .route("/api/send_stream", post(api_send_stream))
        .route("/api/stream", get(api_stream))
        .route("/api/run_status", get(api_run_status))
        .route("/api/reset", post(api_reset))
        .route("/api/delete_session", post(api_delete_session))
        .with_state(web_state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, WorkingDirIsolation};
    use crate::llm::LlmProvider;
    use crate::{db::Database, memory::MemoryManager, skills::SkillManager, tools::ToolRegistry};
    use crate::{error::MicroClawError, llm_types::ResponseContentBlock};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use microclaw_channels::channel_adapter::ChannelRegistry;
    use microclaw_storage::db::call_blocking;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt;

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

    struct DummyLlm;

    #[async_trait::async_trait]
    impl LlmProvider for DummyLlm {
        async fn send_message(
            &self,
            _system: &str,
            _messages: Vec<microclaw_core::llm_types::Message>,
            _tools: Option<Vec<microclaw_core::llm_types::ToolDefinition>>,
        ) -> Result<
            microclaw_core::llm_types::MessagesResponse,
            microclaw_core::error::MicroClawError,
        > {
            Ok(microclaw_core::llm_types::MessagesResponse {
                content: vec![microclaw_core::llm_types::ResponseContentBlock::Text {
                    text: "hello from llm".into(),
                }],
                stop_reason: Some("end_turn".into()),
                usage: None,
            })
        }

        async fn send_message_stream(
            &self,
            _system: &str,
            _messages: Vec<microclaw_core::llm_types::Message>,
            _tools: Option<Vec<microclaw_core::llm_types::ToolDefinition>>,
            text_tx: Option<&tokio::sync::mpsc::UnboundedSender<String>>,
        ) -> Result<
            microclaw_core::llm_types::MessagesResponse,
            microclaw_core::error::MicroClawError,
        > {
            if let Some(tx) = text_tx {
                let _ = tx.send("hello ".into());
                let _ = tx.send("from llm".into());
            }
            self.send_message("", vec![], None).await
        }
    }

    struct SlowLlm {
        sleep_ms: u64,
    }

    #[async_trait::async_trait]
    impl LlmProvider for SlowLlm {
        async fn send_message(
            &self,
            _system: &str,
            _messages: Vec<microclaw_core::llm_types::Message>,
            _tools: Option<Vec<microclaw_core::llm_types::ToolDefinition>>,
        ) -> Result<microclaw_core::llm_types::MessagesResponse, MicroClawError> {
            tokio::time::sleep(Duration::from_millis(self.sleep_ms)).await;
            Ok(microclaw_core::llm_types::MessagesResponse {
                content: vec![ResponseContentBlock::Text {
                    text: "slow".into(),
                }],
                stop_reason: Some("end_turn".into()),
                usage: None,
            })
        }
    }

    struct ToolFlowLlm {
        calls: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl LlmProvider for ToolFlowLlm {
        async fn send_message(
            &self,
            _system: &str,
            _messages: Vec<microclaw_core::llm_types::Message>,
            _tools: Option<Vec<microclaw_core::llm_types::ToolDefinition>>,
        ) -> Result<microclaw_core::llm_types::MessagesResponse, MicroClawError> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                return Ok(microclaw_core::llm_types::MessagesResponse {
                    content: vec![ResponseContentBlock::ToolUse {
                        id: "tool_1".into(),
                        name: "glob".into(),
                        input: json!({"pattern": "*.rs", "path": "."}),
                    }],
                    stop_reason: Some("tool_use".into()),
                    usage: None,
                });
            }
            Ok(microclaw_core::llm_types::MessagesResponse {
                content: vec![ResponseContentBlock::Text {
                    text: "after tool".into(),
                }],
                stop_reason: Some("end_turn".into()),
                usage: None,
            })
        }
    }

    fn test_state(llm: Box<dyn LlmProvider>) -> Arc<AppState> {
        let mut cfg = Config {
            telegram_bot_token: "tok".into(),
            bot_username: "bot".into(),
            llm_provider: "anthropic".into(),
            api_key: "key".into(),
            model: "claude-sonnet-4-5-20250929".into(),
            llm_base_url: None,
            max_tokens: 8192,
            max_tool_iterations: 100,
            compaction_timeout_secs: 180,
            max_history_messages: 50,
            max_document_size_mb: 100,
            memory_token_budget: 1500,
            data_dir: "./microclaw.data".into(),
            working_dir: "./tmp".into(),
            working_dir_isolation: WorkingDirIsolation::Shared,
            sandbox: crate::config::SandboxConfig::default(),
            openai_api_key: None,
            timezone: "UTC".into(),
            allowed_groups: vec![],
            control_chat_ids: vec![],
            max_session_messages: 40,
            compact_keep_recent: 20,
            discord_bot_token: None,
            discord_allowed_channels: vec![],
            discord_no_mention: false,
            show_thinking: false,
            web_enabled: true,
            web_host: "127.0.0.1".into(),
            web_port: 3900,
            web_auth_token: None,
            web_max_inflight_per_session: 2,
            web_max_requests_per_window: 8,
            web_rate_window_seconds: 10,
            web_run_history_limit: 512,
            web_session_idle_ttl_seconds: 300,
            model_prices: vec![],
            embedding_provider: None,
            embedding_api_key: None,
            embedding_base_url: None,
            embedding_model: None,
            embedding_dim: None,
            reflector_enabled: true,
            reflector_interval_mins: 15,
            soul_path: None,
            channels: std::collections::HashMap::new(),
        };
        let dir = std::env::temp_dir().join(format!("microclaw_webtest_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        cfg.data_dir = dir.to_string_lossy().to_string();
        cfg.working_dir = dir.join("tmp").to_string_lossy().to_string();
        let runtime_dir = cfg.runtime_data_dir();
        std::fs::create_dir_all(&runtime_dir).unwrap();
        let db = Arc::new(Database::new(&runtime_dir).unwrap());
        let mut registry = ChannelRegistry::new();
        registry.register(Arc::new(WebAdapter));
        let channel_registry = Arc::new(registry);
        let state = AppState {
            config: cfg.clone(),
            channel_registry: channel_registry.clone(),
            db: db.clone(),
            memory: MemoryManager::new(&runtime_dir),
            skills: SkillManager::from_skills_dir(&cfg.skills_data_dir()),
            hooks: Arc::new(crate::hooks::HookManager::for_tests()),
            llm,
            embedding: None,
            tools: ToolRegistry::new(&cfg, channel_registry, db),
        };
        Arc::new(state)
    }

    fn test_web_state(
        llm: Box<dyn LlmProvider>,
        auth_token: Option<String>,
        limits: WebLimits,
    ) -> WebState {
        let state = test_state(llm);
        WebState {
            app_state: state,
            legacy_auth_token: auth_token,
            run_hub: RunHub::default(),
            session_hub: SessionHub::default(),
            request_hub: RequestHub::default(),
            auth_hub: AuthHub::default(),
            metrics: Arc::new(Mutex::new(WebMetrics::default())),
            otlp: None,
            otlp_last_export: Arc::new(Mutex::new(None)),
            otlp_export_interval: Duration::from_secs(1),
            limits,
        }
    }

    #[tokio::test]
    async fn test_send_stream_then_stream_done() {
        let web_state = test_web_state(Box::new(DummyLlm), None, WebLimits::default());
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
    async fn test_auth_failure_requires_header() {
        let web_state = test_web_state(
            Box::new(DummyLlm),
            Some("secret-token".into()),
            WebLimits::default(),
        );
        let app = build_router(web_state);

        let req = Request::builder()
            .method("GET")
            .uri("/api/health")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
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
        let web_state = test_web_state(Box::new(SlowLlm { sleep_ms: 300 }), None, limits);
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
    async fn test_stream_includes_tool_events_and_replay() {
        let web_state = test_web_state(
            Box::new(ToolFlowLlm {
                calls: AtomicUsize::new(0),
            }),
            None,
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
        let web_state = test_web_state(Box::new(DummyLlm), None, WebLimits::default());
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
    async fn test_rate_limit_window_recovers() {
        let limits = WebLimits {
            max_inflight_per_session: 2,
            max_requests_per_window: 1,
            rate_window: Duration::from_millis(200),
            run_history_limit: 128,
            session_idle_ttl: Duration::from_secs(60),
        };
        let web_state = test_web_state(Box::new(DummyLlm), None, limits);
        let app = build_router(web_state);

        let mk_req = |msg: &str| {
            Request::builder()
                .method("POST")
                .uri("/api/send")
                .header("content-type", "application/json")
                .body(Body::from(format!(
                    r#"{{"session_key":"main","sender_name":"u","message":"{}"}}"#,
                    msg
                )))
                .unwrap()
        };

        let resp1 = app.clone().oneshot(mk_req("r1")).await.unwrap();
        assert_eq!(resp1.status(), StatusCode::OK);

        let resp2 = app.clone().oneshot(mk_req("r2")).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::TOO_MANY_REQUESTS);

        tokio::time::sleep(Duration::from_millis(260)).await;
        let resp3 = app.oneshot(mk_req("r3")).await.unwrap();
        assert_eq!(resp3.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_api_usage_returns_report() {
        let web_state = test_web_state(Box::new(DummyLlm), None, WebLimits::default());
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
    async fn test_api_memory_observability_returns_series() {
        let web_state = test_web_state(Box::new(DummyLlm), None, WebLimits::default());
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
    async fn test_db_paths_use_call_blocking_in_web_flow() {
        let state = test_state(Box::new(DummyLlm));
        let chat_id = 12345_i64;
        let message_count = call_blocking(state.db.clone(), move |db| db.get_all_messages(chat_id))
            .await
            .unwrap()
            .len();
        assert_eq!(message_count, 0);
    }

    #[tokio::test]
    async fn test_web_session_key_resolves_to_channel_scoped_chat_id() {
        let web_state = test_web_state(Box::new(DummyLlm), None, WebLimits::default());
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
        let web_state = test_web_state(Box::new(DummyLlm), None, WebLimits::default());
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
        let web_state = test_web_state(Box::new(DummyLlm), None, WebLimits::default());
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
        assert!(metrics_json
            .get("metrics")
            .and_then(|m| m.get("http_requests"))
            .and_then(|v| v.as_i64())
            .unwrap_or(0)
            > 0);

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
        assert!(history_json
            .get("points")
            .and_then(|v| v.as_array())
            .map(|v| !v.is_empty())
            .unwrap_or(false));

    }

    #[tokio::test]
    async fn test_sessions_tree_returns_fork_metadata() {
        let web_state = test_web_state(Box::new(DummyLlm), None, WebLimits::default());
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
    async fn test_cookie_write_requires_csrf_header() {
        let web_state = test_web_state(Box::new(DummyLlm), None, WebLimits::default());
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
}
