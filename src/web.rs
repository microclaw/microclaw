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
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::{broadcast, Mutex};
use tracing::{error, info, warn};

use crate::agent_engine::{process_with_agent_with_events, AgentEvent, AgentRequestContext};
use crate::chat_commands::{
    build_model_response, build_status_response, maybe_handle_plugin_command,
};
use crate::config::{Config, WorkingDirIsolation};
use crate::otlp::{OtlpExporter, OtlpMetricSnapshot};
use crate::runtime::AppState;
use microclaw_channels::channel::ConversationKind;
use microclaw_channels::channel::{
    deliver_and_store_bot_message, get_chat_routing, session_source_for_chat,
};
use microclaw_channels::channel_adapter::{ChannelAdapter, ChannelRegistry};
use microclaw_core::llm_types::Message;
use microclaw_storage::db::{call_blocking, ChatSummary, MetricsHistoryPoint, StoredMessage};
use microclaw_storage::usage::build_usage_report;

mod auth;
mod config;
mod metrics;
mod middleware;
mod sessions;
mod stream;
use middleware::*;

static WEB_ASSETS: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/web/dist");
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
struct WebState {
    app_state: Arc<AppState>,
    legacy_auth_token: Option<String>,
    bootstrap_token: Arc<Mutex<Option<String>>>,
    run_hub: RunHub,
    session_hub: SessionHub,
    request_hub: RequestHub,
    auth_hub: AuthHub,
    metrics: Arc<Mutex<WebMetrics>>,
    otlp: Option<Arc<OtlpExporter>>,
    limits: WebLimits,
}

#[derive(Clone, Default)]
struct AuthHub {
    login_buckets: Arc<Mutex<HashMap<String, VecDeque<Instant>>>>,
    api_key_buckets: Arc<Mutex<HashMap<String, VecDeque<Instant>>>>,
}

#[derive(Clone, Debug, Default)]
struct WebMetrics {
    http_requests: i64,
    request_ok: i64,
    request_error: i64,
    request_latency_ms: VecDeque<i64>,
    llm_completions: i64,
    llm_input_tokens: i64,
    llm_output_tokens: i64,
    tool_executions: i64,
    tool_success: i64,
    tool_error: i64,
    tool_policy_blocks: i64,
    mcp_calls: i64,
    mcp_rate_limited_rejections: i64,
    mcp_bulkhead_rejections: i64,
    mcp_circuit_open_rejections: i64,
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
    quotas: Arc<Mutex<RequestQuotas>>,
}

#[derive(Default)]
struct RequestQuotas {
    sessions: HashMap<String, SessionQuota>,
    actors: HashMap<String, SessionQuota>,
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
    owner_actor: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RunLookupError {
    NotFound,
    Forbidden,
}

impl RunHub {
    async fn create(&self, run_id: &str, owner_actor: String) {
        let (tx, _) = broadcast::channel(512);
        let mut guard = self.channels.lock().await;
        guard.insert(
            run_id.to_string(),
            RunChannel {
                sender: tx,
                history: VecDeque::new(),
                next_id: 1,
                done: false,
                owner_actor,
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

    async fn status(
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
    const MAX_BUCKET_KEYS: usize = 4096;

    fn prune_quota(quota: &mut SessionQuota, now: Instant, limits: &WebLimits) {
        while let Some(ts) = quota.recent.front() {
            if now.duration_since(*ts) > limits.rate_window {
                let _ = quota.recent.pop_front();
            } else {
                break;
            }
        }
    }

    fn prune_map(map: &mut HashMap<String, SessionQuota>, now: Instant, limits: &WebLimits) {
        map.retain(|_, quota| {
            Self::prune_quota(quota, now, limits);
            quota.inflight != 0
                || (!quota.recent.is_empty()
                    && now.duration_since(quota.last_touch) <= limits.session_idle_ttl)
        });
    }

    async fn active_sessions(&self) -> usize {
        self.quotas.lock().await.sessions.len()
    }

    async fn begin(
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

    async fn end_with_limits(&self, session_key: &str, actor: &str, limits: &WebLimits) {
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

    fn prune_buckets(
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

    async fn allow_login_attempt(
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

    async fn allow_api_key_request(
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

async fn metrics_http_inc(state: &WebState) {
    let mut m = state.metrics.lock().await;
    m.http_requests += 1;
}

async fn metrics_llm_completion_inc(state: &WebState) {
    let mut m = state.metrics.lock().await;
    m.llm_completions += 1;
}

const METRICS_LATENCY_SAMPLE_CAP: usize = 4096;

async fn metrics_record_request_result(state: &WebState, ok: bool, latency_ms: i64) {
    let mut m = state.metrics.lock().await;
    if ok {
        m.request_ok += 1;
        m.request_latency_ms.push_back(latency_ms.max(0));
        if m.request_latency_ms.len() > METRICS_LATENCY_SAMPLE_CAP {
            let _ = m.request_latency_ms.pop_front();
        }
    } else {
        m.request_error += 1;
    }
}

async fn metrics_apply_agent_event(state: &WebState, evt: &AgentEvent) {
    let mut m = state.metrics.lock().await;
    match evt {
        AgentEvent::ToolStart { name } => {
            m.tool_executions += 1;
            if name.starts_with("mcp") {
                m.mcp_calls += 1;
            }
        }
        AgentEvent::ToolResult {
            is_error,
            error_type,
            ..
        } => {
            if *is_error {
                if matches!(
                    error_type.as_deref(),
                    Some("approval_required" | "execution_policy_blocked")
                ) {
                    m.tool_policy_blocks += 1;
                } else {
                    m.tool_error += 1;
                }
            } else {
                m.tool_success += 1;
            }
        }
        _ => {}
    }
}

fn percentile_p95(values: &VecDeque<i64>) -> Option<i64> {
    if values.is_empty() {
        return None;
    }
    let mut sorted: Vec<i64> = values.iter().copied().collect();
    sorted.sort_unstable();
    let idx = ((sorted.len() - 1) * 95) / 100;
    sorted.get(idx).copied()
}

async fn persist_metrics_snapshot(state: &WebState) -> Result<(), (StatusCode, String)> {
    let snapshot = state.metrics.lock().await.clone();
    let active_sessions = state.request_hub.active_sessions().await as i64;
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
        mcp_rate_limited_rejections: snapshot.mcp_rate_limited_rejections,
        mcp_bulkhead_rejections: snapshot.mcp_bulkhead_rejections,
        mcp_circuit_open_rejections: snapshot.mcp_circuit_open_rejections,
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
        let metric_snapshot = OtlpMetricSnapshot {
            timestamp_unix_nano: now.timestamp_nanos_opt().unwrap_or(0) as u64,
            http_requests: snapshot.http_requests,
            llm_completions: snapshot.llm_completions,
            llm_input_tokens: snapshot.llm_input_tokens,
            llm_output_tokens: snapshot.llm_output_tokens,
            tool_executions: snapshot.tool_executions,
            mcp_calls: snapshot.mcp_calls,
            mcp_rate_limited_rejections: snapshot.mcp_rate_limited_rejections,
            mcp_bulkhead_rejections: snapshot.mcp_bulkhead_rejections,
            mcp_circuit_open_rejections: snapshot.mcp_circuit_open_rejections,
            active_sessions,
        };
        tokio::spawn(async move {
            if let Err(e) = exporter.enqueue_metrics(metric_snapshot) {
                tracing::warn!("otlp export failed: {}", e);
            }
        });
    }
    Ok(())
}

fn metrics_flush_interval(config: &Config) -> Duration {
    if let Some(map) = config.channels.get("web").and_then(|v| v.as_mapping()) {
        if let Some(n) = map
            .get(serde_yaml::Value::String(
                "metrics_flush_interval_seconds".to_string(),
            ))
            .and_then(|v| v.as_u64())
        {
            return Duration::from_secs(n.clamp(1, 300));
        }
    }
    Duration::from_secs(10)
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
    openai_compat_body_overrides: Option<HashMap<String, serde_json::Value>>,
    openai_compat_body_overrides_by_provider:
        Option<HashMap<String, HashMap<String, serde_json::Value>>>,
    openai_compat_body_overrides_by_model:
        Option<HashMap<String, HashMap<String, serde_json::Value>>>,
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
    telegram_bot_username: Option<String>,
    discord_bot_token: Option<String>,
    discord_allowed_channels: Option<Vec<u64>>,
    discord_bot_username: Option<String>,
    slack_bot_username: Option<String>,
    feishu_bot_username: Option<String>,
    web_bot_username: Option<String>,

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

#[derive(Debug, Serialize)]
struct ConfigWarning {
    code: &'static str,
    severity: &'static str,
    message: String,
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

fn config_path_for_save() -> Result<PathBuf, (StatusCode, String)> {
    match Config::resolve_config_path() {
        Ok(Some(path)) => Ok(path),
        Ok(None) => Ok(PathBuf::from("./microclaw.config.yaml")),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

fn is_sensitive_config_key(key: &str) -> bool {
    let k = key.trim().to_ascii_lowercase();
    if k.is_empty() {
        return false;
    }
    let exact = [
        "api_key",
        "openai_api_key",
        "embedding_api_key",
        "web_auth_token",
        "telegram_bot_token",
        "discord_bot_token",
        "bot_token",
        "app_token",
        "auth_token",
        "token",
        "secret",
        "password",
        "app_secret",
        "clawhub_token",
    ];
    if exact.contains(&k.as_str()) {
        return true;
    }
    k.ends_with("_token")
        || k.ends_with("_secret")
        || k.ends_with("_password")
        || k.ends_with("_api_key")
}

fn redact_json_secrets(value: &mut serde_json::Value, parent_key: Option<&str>) {
    if parent_key.is_some_and(is_sensitive_config_key) {
        *value = serde_json::Value::String("***".to_string());
        return;
    }
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                redact_json_secrets(v, Some(k.as_str()));
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                redact_json_secrets(item, parent_key);
            }
        }
        _ => {}
    }
}

fn redact_config(config: &Config) -> serde_json::Value {
    let mut value = json!(config);
    redact_json_secrets(&mut value, None);
    value
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
    let since_24h = (chrono::Utc::now() - chrono::Duration::hours(24)).to_rfc3339();
    let task_summary_24h = call_blocking(state.app_state.db.clone(), move |db| {
        db.get_task_run_summary_since(Some(&since_24h))
    })
    .await
    .ok();
    let reflector_summary = call_blocking(state.app_state.db.clone(), move |db| {
        db.get_memory_observability_summary(None)
    })
    .await
    .ok();

    let (task_runs_24h, task_success_24h) = task_summary_24h.unwrap_or((0, 0));
    let task_failed_24h = (task_runs_24h - task_success_24h).max(0);
    let reflector_runs_24h = reflector_summary
        .as_ref()
        .map(|s| s.reflector_runs_24h)
        .unwrap_or(0);
    let reflector_inserted_24h = reflector_summary
        .as_ref()
        .map(|s| s.reflector_inserted_24h)
        .unwrap_or(0);
    let reflector_updated_24h = reflector_summary
        .as_ref()
        .map(|s| s.reflector_updated_24h)
        .unwrap_or(0);
    let reflector_skipped_24h = reflector_summary
        .as_ref()
        .map(|s| s.reflector_skipped_24h)
        .unwrap_or(0);

    Ok(Json(json!({
        "ok": true,
        "version": env!("CARGO_PKG_VERSION"),
        "web_enabled": state.app_state.config.web_enabled,
        "scheduler": {
            "task_runs_24h": task_runs_24h,
            "task_success_24h": task_success_24h,
            "task_failed_24h": task_failed_24h
        },
        "reflector": {
            "enabled": state.app_state.config.reflector_enabled,
            "interval_mins": state.app_state.config.reflector_interval_mins,
            "runs_24h": reflector_runs_24h,
            "inserted_24h": reflector_inserted_24h,
            "updated_24h": reflector_updated_24h,
            "skipped_24h": reflector_skipped_24h
        }
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

async fn resolve_chat_id_for_session_key_read(
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

async fn resolve_chat_id_for_session_key(
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

async fn api_usage(
    headers: HeaderMap,
    State(state): State<WebState>,
    Query(query): Query<UsageQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    require_scope(&state, &headers, AuthScope::Read).await?;

    let session_key = normalize_session_key(query.session_key.as_deref());
    let chat_id = resolve_chat_id_for_session_key_read(&state, &session_key).await?;
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
        Some(resolve_chat_id_for_session_key_read(&state, &session_key).await?)
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

    if let Some(command_response) = handle_web_slash_command(&state, &text, chat_id).await {
        let bot_username = state.app_state.config.bot_username_for_channel("web");
        deliver_and_store_bot_message(
            &state.app_state.channel_registry,
            state.app_state.db.clone(),
            &bot_username,
            chat_id,
            &command_response,
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
        return Ok(Json(json!({
            "ok": true,
            "session_key": session_key,
            "chat_id": chat_id,
            "response": command_response,
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
    let response = if let Some(tx) = event_tx {
        process_with_agent_with_events(&state.app_state, request_ctx, None, None, Some(tx))
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    } else {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<AgentEvent>();
        let result =
            process_with_agent_with_events(&state.app_state, request_ctx, None, None, Some(&tx))
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()));
        drop(tx);
        while let Some(evt) = rx.recv().await {
            metrics_apply_agent_event(&state, &evt).await;
        }
        result?
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

    Ok(Json(json!({
        "ok": true,
        "session_key": session_key,
        "chat_id": chat_id,
        "response": response,
    })))
}

async fn handle_web_slash_command(state: &WebState, text: &str, chat_id: i64) -> Option<String> {
    let trimmed = text.trim();
    if !trimmed.starts_with('/') {
        return None;
    }

    if trimmed == "/reset" {
        let _ = call_blocking(state.app_state.db.clone(), move |db| {
            db.clear_chat_context(chat_id)
        })
        .await;
        return Some("Context cleared (session + chat history).".to_string());
    }

    if trimmed == "/skills" {
        return Some(state.app_state.skills.list_skills_formatted());
    }

    if trimmed == "/reload-skills" {
        let reloaded = state.app_state.skills.reload();
        return Some(format!("Reloaded {} skills from disk.", reloaded.len()));
    }

    if trimmed == "/archive" {
        if let Ok(Some((json, _))) = call_blocking(state.app_state.db.clone(), move |db| {
            db.load_session(chat_id)
        })
        .await
        {
            let messages: Vec<Message> = serde_json::from_str(&json).unwrap_or_default();
            if messages.is_empty() {
                return Some("No session to archive.".to_string());
            }
            crate::agent_engine::archive_conversation(
                &state.app_state.config.data_dir,
                "web",
                chat_id,
                &messages,
            );
            return Some(format!("Archived {} messages.", messages.len()));
        }
        return Some("No session to archive.".to_string());
    }

    if trimmed == "/usage" {
        return match build_usage_report(state.app_state.db.clone(), chat_id).await {
            Ok(report) => Some(report),
            Err(e) => Some(format!("Failed to query usage statistics: {e}")),
        };
    }

    if trimmed == "/status" {
        let status = build_status_response(
            state.app_state.db.clone(),
            &state.app_state.config,
            &state.app_state.llm_model_overrides,
            chat_id,
            "web",
        )
        .await;
        return Some(status);
    }

    if trimmed == "/model" || trimmed.starts_with("/model ") {
        return Some(build_model_response(
            &state.app_state.config,
            &state.app_state.llm_model_overrides,
            "web",
            trimmed,
        ));
    }

    maybe_handle_plugin_command(&state.app_state.config, trimmed, chat_id, "web").await
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
    let flush_interval = metrics_flush_interval(&state.config);
    let has_password = call_blocking(state.db.clone(), |db| db.get_auth_password_hash())
        .await
        .ok()
        .flatten()
        .is_some();
    if state.config.web_auth_token.is_none() && !has_password {
        let default_hash = make_password_hash(DEFAULT_WEB_PASSWORD);
        let _ = call_blocking(state.db.clone(), move |db| {
            db.upsert_auth_password_hash(&default_hash)
        })
        .await;
        warn!(
            "web auth default password enabled: no operator password was configured. Temporary password is '{}'. Please change it in Web UI after sign in.",
            DEFAULT_WEB_PASSWORD
        );
    }
    let bootstrap_token = None;
    let web_state = WebState {
        legacy_auth_token: state.config.web_auth_token.clone(),
        bootstrap_token: Arc::new(Mutex::new(bootstrap_token)),
        app_state: state.clone(),
        run_hub: RunHub::default(),
        session_hub: SessionHub::default(),
        request_hub: RequestHub::default(),
        auth_hub: AuthHub::default(),
        metrics: Arc::new(Mutex::new(WebMetrics::default())),
        otlp: OtlpExporter::from_config(&state.config),
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
        .route("/api/memory_observability", get(api_memory_observability))
        .route("/api/metrics", get(metrics::api_metrics))
        .route("/api/metrics/summary", get(metrics::api_metrics_summary))
        .route("/api/metrics/history", get(metrics::api_metrics_history))
        .route("/api/send", post(api_send))
        .route("/api/send_stream", post(stream::api_send_stream))
        .route("/api/stream", get(stream::api_stream))
        .route("/api/run_status", get(stream::api_run_status))
        .route("/api/reset", post(sessions::api_reset))
        .route("/api/delete_session", post(sessions::api_delete_session))
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

    fn test_config_template() -> Config {
        let mut cfg = Config::test_defaults();
        cfg.working_dir_isolation = WorkingDirIsolation::Shared;
        cfg.web_port = 3900;
        cfg
    }

    fn test_state_with_config(llm: Box<dyn LlmProvider>, mut cfg: Config) -> Arc<AppState> {
        let dir = std::env::temp_dir().join(format!("microclaw_webtest_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        cfg.data_dir = dir.to_string_lossy().to_string();
        cfg.working_dir = dir.join("tmp").to_string_lossy().to_string();
        let runtime_dir = cfg.runtime_data_dir();
        std::fs::create_dir_all(&runtime_dir).unwrap();
        let db = Arc::new(Database::new(&runtime_dir).unwrap());
        let memory_backend = Arc::new(crate::memory_backend::MemoryBackend::local_only(db.clone()));
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
            llm_model_overrides: std::collections::HashMap::new(),
            embedding: None,
            memory_backend: memory_backend.clone(),
            tools: ToolRegistry::new(&cfg, channel_registry, db, memory_backend),
        };
        Arc::new(state)
    }

    fn test_state(llm: Box<dyn LlmProvider>) -> Arc<AppState> {
        test_state_with_config(llm, test_config_template())
    }

    fn test_web_state_from_app_state(
        state: Arc<AppState>,
        auth_token: Option<String>,
        limits: WebLimits,
    ) -> WebState {
        WebState {
            app_state: state,
            legacy_auth_token: auth_token,
            bootstrap_token: Arc::new(Mutex::new(None)),
            run_hub: RunHub::default(),
            session_hub: SessionHub::default(),
            request_hub: RequestHub::default(),
            auth_hub: AuthHub::default(),
            metrics: Arc::new(Mutex::new(WebMetrics::default())),
            otlp: None,
            limits,
        }
    }

    fn test_web_state(
        llm: Box<dyn LlmProvider>,
        auth_token: Option<String>,
        limits: WebLimits,
    ) -> WebState {
        test_web_state_from_app_state(test_state(llm), auth_token, limits)
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
    async fn test_api_health_includes_scheduler_and_reflector_status() {
        let web_state = test_web_state(Box::new(DummyLlm), None, WebLimits::default());
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
    async fn test_different_sessions_same_actor_concurrency_limited() {
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
    async fn test_read_endpoints_unknown_session_return_404_without_creating_chat() {
        let web_state = test_web_state(Box::new(DummyLlm), None, WebLimits::default());
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
        let web_state = test_web_state(Box::new(DummyLlm), None, WebLimits::default());
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
        let web_state = test_web_state(Box::new(DummyLlm), None, WebLimits::default());
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
        let web_state = test_web_state_from_app_state(state, None, WebLimits::default());
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
        let web_state = test_web_state_from_app_state(state, None, WebLimits::default());
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
        let web_state = test_web_state_from_app_state(state, None, WebLimits::default());
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
    async fn test_web_send_model_slash_command() {
        let web_state = test_web_state(Box::new(DummyLlm), None, WebLimits::default());
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
        let web_state = test_web_state_from_app_state(state, None, WebLimits::default());
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
    #[tokio::test]
    async fn test_stream_run_is_owner_isolated_for_api_keys() {
        let web_state = test_web_state(Box::new(DummyLlm), None, WebLimits::default());
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
        let web_state = test_web_state(Box::new(DummyLlm), None, WebLimits::default());
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

    #[test]
    fn test_redact_config_recursively_masks_nested_and_flattened_secrets() {
        let mut cfg = test_config_template();
        cfg.clawhub.token = Some("clawhub-secret".to_string());
        cfg.channels.insert(
            "discord".to_string(),
            serde_yaml::to_value(json!({
                "accounts": {
                    "main": {
                        "bot_token": "discord-secret-token"
                    }
                }
            }))
            .unwrap(),
        );
        cfg.channels.insert(
            "web".to_string(),
            serde_yaml::to_value(json!({
                "auth_token": "web-auth-secret"
            }))
            .unwrap(),
        );

        let redacted = redact_config(&cfg);
        assert_eq!(
            redacted.get("clawhub_token").and_then(|v| v.as_str()),
            Some("***")
        );
        assert_eq!(
            redacted
                .pointer("/channels/discord/accounts/main/bot_token")
                .and_then(|v| v.as_str()),
            Some("***")
        );
        assert_eq!(
            redacted
                .pointer("/channels/web/auth_token")
                .and_then(|v| v.as_str()),
            Some("***")
        );
        assert_eq!(
            redacted.get("max_tokens").and_then(|v| v.as_u64()),
            Some(cfg.max_tokens as u64)
        );
    }

    #[tokio::test]
    async fn test_password_bootstrap_token_is_required_and_one_time() {
        let web_state = test_web_state(Box::new(DummyLlm), None, WebLimits::default());
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

    #[test]
    fn test_client_key_ignores_xff_by_default() {
        let cfg = test_config_template();
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.10".parse().unwrap());
        let key = client_key_from_headers_with_config(&headers, &cfg);
        assert_eq!(key, "global");
    }

    #[test]
    fn test_client_key_uses_xff_when_trusted() {
        let mut cfg = test_config_template();
        cfg.channels.insert(
            "web".to_string(),
            serde_yaml::to_value(json!({"trust_x_forwarded_for": true})).unwrap(),
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "203.0.113.10, 198.51.100.2".parse().unwrap(),
        );
        let key = client_key_from_headers_with_config(&headers, &cfg);
        assert_eq!(key, "203.0.113.10");
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
}
