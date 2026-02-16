use std::collections::{hash_map::DefaultHasher, HashMap, VecDeque};
use std::hash::{Hash, Hasher};
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
use tracing::{error, info};

use crate::channel::deliver_and_store_bot_message;
use crate::config::Config;
use crate::db::{call_blocking, ChatSummary, Persona, StoredMessage};
use crate::social_oauth;
use crate::claude::Message;
use crate::slash_commands::{parse as parse_slash_command, SlashCommand};
use crate::telegram::{
    archive_conversation, process_with_agent,
    process_with_agent_with_events, AgentEvent, AgentRequestContext, AppState,
};

static WEB_ASSETS: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/web/dist");

#[derive(Clone)]
struct WebState {
    app_state: Arc<AppState>,
    auth_token: Option<String>,
    run_hub: RunHub,
    session_hub: SessionHub,
    request_hub: RequestHub,
    limits: WebLimits,
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

fn auth_token_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|raw| raw.strip_prefix("Bearer "))
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn require_auth(
    headers: &HeaderMap,
    expected_token: Option<&str>,
) -> Result<(), (StatusCode, String)> {
    let Some(expected) = expected_token else {
        return Ok(());
    };

    let provided = auth_token_from_headers(headers).unwrap_or_default();

    if provided == expected {
        Ok(())
    } else {
        Err((StatusCode::UNAUTHORIZED, "unauthorized".into()))
    }
}

fn normalize_session_key(session_key: Option<&str>) -> String {
    let key = session_key.unwrap_or("main").trim();
    if key.is_empty() {
        "main".into()
    } else {
        key.into()
    }
}

fn session_key_to_chat_id(session_key: &str) -> i64 {
    // Stable mapping into i64 space; we mark these chats with chat_type="web".
    let mut hasher = DefaultHasher::new();
    format!("web:{session_key}").hash(&mut hasher);
    let hash = hasher.finish();
    (hash & 0x3FFF_FFFF_FFFF_FFFF) as i64
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
struct PersonasQuery {
    session_key: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PersonasSwitchRequest {
    session_key: Option<String>,
    persona_name: String,
}

#[derive(Debug, Deserialize)]
struct RunStatusQuery {
    run_id: String,
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
    if cfg.whatsapp_access_token.is_some() {
        cfg.whatsapp_access_token = Some("***".into());
    }
    if cfg.whatsapp_verify_token.is_some() {
        cfg.whatsapp_verify_token = Some("***".into());
    }
    if cfg.discord_bot_token.is_some() {
        cfg.discord_bot_token = Some("***".into());
    }
    if cfg.web_auth_token.is_some() {
        cfg.web_auth_token = Some("***".into());
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
    require_auth(&headers, state.auth_token.as_deref())?;
    Ok(Json(json!({
        "ok": true,
        "version": env!("CARGO_PKG_VERSION"),
        "web_enabled": state.app_state.config.web_enabled,
    })))
}

async fn api_get_config(
    headers: HeaderMap,
    State(state): State<WebState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    require_auth(&headers, state.auth_token.as_deref())?;

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
    require_auth(&headers, state.auth_token.as_deref())?;

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

    Ok(Json(json!({
        "ok": true,
        "path": path,
        "requires_restart": true
    })))
}

fn map_chat_to_session(chat: ChatSummary) -> SessionItem {
    let source = match chat.chat_type.as_str() {
        "web" => "web",
        "discord" => "discord",
        "whatsapp" => "whatsapp",
        "telegram_private" | "telegram_group" | "telegram_supergroup" | "telegram_channel" => {
            "telegram"
        }
        // Backward compatibility for old rows written before source-specific chat_type.
        "private" | "group" | "supergroup" | "channel" => {
            if chat
                .chat_title
                .as_deref()
                .is_some_and(|t| t.starts_with("discord-"))
            {
                "discord"
            } else {
                "telegram"
            }
        }
        _ => chat.chat_type.as_str(),
    };

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
        chat_type: source.to_string(),
        last_message_time: chat.last_message_time,
        last_message_preview: chat.last_message_preview,
    }
}

fn parse_chat_id_from_session_key(session_key: &str) -> Option<i64> {
    session_key
        .strip_prefix("chat:")
        .and_then(|s| s.parse::<i64>().ok())
}

fn resolve_chat_id(session_key: &str) -> i64 {
    parse_chat_id_from_session_key(session_key)
        .unwrap_or_else(|| session_key_to_chat_id(session_key))
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

    Ok(by_title.unwrap_or_else(|| resolve_chat_id(session_key)))
}

async fn api_sessions(
    headers: HeaderMap,
    State(state): State<WebState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    require_auth(&headers, state.auth_token.as_deref())?;

    let chats = call_blocking(state.app_state.db.clone(), |db| db.get_recent_chats(400))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let sessions = chats
        .into_iter()
        .map(map_chat_to_session)
        .collect::<Vec<_>>();
    Ok(Json(json!({ "ok": true, "sessions": sessions })))
}

async fn api_history(
    headers: HeaderMap,
    State(state): State<WebState>,
    Query(query): Query<HistoryQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    require_auth(&headers, state.auth_token.as_deref())?;

    let session_key = normalize_session_key(query.session_key.as_deref());
    let chat_id = resolve_chat_id(&session_key);
    let cid = chat_id;

    let persona_id = call_blocking(state.app_state.db.clone(), move |db| db.get_or_create_default_persona(cid))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let cid2 = chat_id;
    let pid = persona_id;
    let mut messages = call_blocking(state.app_state.db.clone(), move |db| {
        db.get_all_messages(cid2, pid)
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

async fn api_send(
    headers: HeaderMap,
    State(state): State<WebState>,
    Json(body): Json<SendRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    require_auth(&headers, state.auth_token.as_deref())?;
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
    require_auth(&headers, state.auth_token.as_deref())?;
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
    require_auth(&headers, state.auth_token.as_deref())?;
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
    require_auth(&headers, state.auth_token.as_deref())?;
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

    // Single entry point: parse slash command first. If command, run backend handler and return — never send to LLM.
    if let Some(cmd) = parse_slash_command(&text) {
        let session_key = normalize_session_key(body.session_key.as_deref());
        let chat_id = resolve_chat_id(&session_key);
        let parsed_chat_id = parse_chat_id_from_session_key(&session_key);
        if let Some(explicit_chat_id) = parsed_chat_id {
            let chat_type = call_blocking(state.app_state.db.clone(), move |db| {
                db.get_chat_type(explicit_chat_id)
            })
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            if !matches!(chat_type.as_deref(), Some("web")) {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "this channel is read-only in Web UI; use source channel to send".into(),
                ));
            }
        } else {
            let session_key_for_chat = session_key.clone();
            call_blocking(state.app_state.db.clone(), move |db| {
                db.upsert_chat(chat_id, Some(&session_key_for_chat), "web")
            })
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        }
        let cid = chat_id;
        let persona_id = call_blocking(state.app_state.db.clone(), move |db| {
            db.get_or_create_default_persona(cid)
        })
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let resp = match cmd {
            SlashCommand::Reset => {
                let cid2 = chat_id;
                let _ = call_blocking(state.app_state.db.clone(), move |db| {
                    db.delete_session(cid2, persona_id)
                })
                .await;
                "Conversation cleared. Principles and per-persona memory are unchanged.".into()
            }
            SlashCommand::Skills => state.app_state.skills.list_skills_formatted(),
            SlashCommand::Persona => {
                crate::persona::handle_persona_command(state.app_state.db.clone(), chat_id, text.trim()).await
            }
            SlashCommand::Archive => {
                let cid2 = chat_id;
                let pid = persona_id;
                match call_blocking(state.app_state.db.clone(), move |db| {
                    db.load_session(cid2, pid)
                })
                .await
                {
                    Ok(Some((json_str, _))) => {
                        let messages: Vec<Message> =
                            serde_json::from_str(&json_str).unwrap_or_default();
                        if messages.is_empty() {
                            "No session to archive.".into()
                        } else {
                            archive_conversation(
                                &state.app_state.config.runtime_data_dir(),
                                chat_id,
                                &messages,
                            );
                            format!("Archived {} messages.", messages.len())
                        }
                    }
                    _ => "No session to archive.".into(),
                }
            }
        };

        deliver_and_store_bot_message(
            &state.app_state.bot,
            state.app_state.db.clone(),
            &state.app_state.config.bot_username,
            chat_id,
            persona_id,
            &resp,
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        return Ok(Json(json!({
            "ok": true,
            "session_key": session_key,
            "chat_id": chat_id,
            "response": resp,
        })));
    }

    // Not a slash command: normal flow — resolve, store message, run agent
    let session_key = normalize_session_key(body.session_key.as_deref());
    let chat_id = resolve_chat_id(&session_key);
    let parsed_chat_id = parse_chat_id_from_session_key(&session_key);
    let sender_name = body
        .sender_name
        .as_deref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("web-user")
        .to_string();

    if let Some(explicit_chat_id) = parsed_chat_id {
        let chat_type = call_blocking(state.app_state.db.clone(), move |db| {
            db.get_chat_type(explicit_chat_id)
        })
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        if !matches!(chat_type.as_deref(), Some("web")) {
            return Err((
                StatusCode::BAD_REQUEST,
                "this channel is read-only in Web UI; use source channel to send".into(),
            ));
        }
    } else {
        let session_key_for_chat = session_key.clone();
        call_blocking(state.app_state.db.clone(), move |db| {
            db.upsert_chat(chat_id, Some(&session_key_for_chat), "web")
        })
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    let cid = chat_id;
    let persona_id = call_blocking(state.app_state.db.clone(), move |db| {
        db.get_or_create_default_persona(cid)
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let user_msg = StoredMessage {
        id: uuid::Uuid::new_v4().to_string(),
        chat_id,
        persona_id,
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
                chat_type: "private",
                persona_id,
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
                chat_type: "private",
                persona_id,
            },
            None,
            None,
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    };

    deliver_and_store_bot_message(
        &state.app_state.bot,
        state.app_state.db.clone(),
        &state.app_state.config.bot_username,
        chat_id,
        persona_id,
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
    require_auth(&headers, state.auth_token.as_deref())?;

    let session_key = normalize_session_key(body.session_key.as_deref());
    let chat_id = resolve_chat_id_for_session_key(&state, &session_key).await?;

    let chat_type = call_blocking(state.app_state.db.clone(), move |db| {
        db.get_chat_type(chat_id)
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let deleted = if matches!(chat_type.as_deref(), Some("web")) {
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
        let cid = chat_id;
        let pid = call_blocking(state.app_state.db.clone(), move |db| db.get_or_create_default_persona(cid))
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let cid2 = chat_id;
        call_blocking(state.app_state.db.clone(), move |db| db.delete_session(cid2, pid))
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    };

    Ok(Json(json!({
        "ok": true,
        "deleted": deleted,
        "message": "Conversation cleared. Principles and per-persona memory are unchanged."
    })))
}

async fn api_delete_session(
    headers: HeaderMap,
    State(state): State<WebState>,
    Json(body): Json<ResetRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    require_auth(&headers, state.auth_token.as_deref())?;

    let session_key = normalize_session_key(body.session_key.as_deref());
    let chat_id = resolve_chat_id_for_session_key(&state, &session_key).await?;

    let deleted = call_blocking(state.app_state.db.clone(), move |db| {
        db.delete_chat_data(chat_id)
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(json!({
        "ok": true,
        "deleted": deleted,
        "message": "Conversation cleared. Principles and per-persona memory are unchanged."
    })))
}

async fn api_personas(
    headers: HeaderMap,
    State(state): State<WebState>,
    Query(query): Query<PersonasQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    require_auth(&headers, state.auth_token.as_deref())?;

    let session_key = normalize_session_key(query.session_key.as_deref());
    let chat_id = resolve_chat_id_for_session_key(&state, &session_key).await?;
    let cid = chat_id;

    let personas: Vec<Persona> = call_blocking(state.app_state.db.clone(), move |db| db.list_personas(cid))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let cid2 = chat_id;
    let active_id = call_blocking(state.app_state.db.clone(), move |db| db.get_active_persona_id(cid2))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let items: Vec<serde_json::Value> = personas
        .iter()
        .map(|p| {
            json!({
                "id": p.id,
                "name": p.name,
                "model_override": p.model_override,
                "is_active": active_id == Some(p.id),
            })
        })
        .collect();

    Ok(Json(json!({
        "ok": true,
        "session_key": session_key,
        "chat_id": chat_id,
        "personas": items,
    })))
}

async fn api_personas_switch(
    headers: HeaderMap,
    State(state): State<WebState>,
    Json(body): Json<PersonasSwitchRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    require_auth(&headers, state.auth_token.as_deref())?;

    let session_key = normalize_session_key(body.session_key.as_deref());
    let chat_id = resolve_chat_id_for_session_key(&state, &session_key).await?;
    let persona_name = body.persona_name.clone();
    let persona_name_for_msg = persona_name.clone();

    let persona = call_blocking(state.app_state.db.clone(), move |db| {
        db.get_persona_by_name(chat_id, &persona_name)
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let Some(persona) = persona else {
        return Err((
            StatusCode::NOT_FOUND,
            format!("Persona '{}' not found", persona_name_for_msg),
        ));
    };

    let ok = call_blocking(state.app_state.db.clone(), move |db| {
        db.set_active_persona(chat_id, persona.id)
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if !ok {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to switch persona".into(),
        ));
    }

    Ok(Json(json!({
        "ok": true,
        "message": format!("Switched to {}", persona_name_for_msg),
    })))
}

pub async fn start_web_server(state: Arc<AppState>) {
    let limits = WebLimits::from_config(&state.config);
    let web_state = WebState {
        auth_token: state.config.web_auth_token.clone(),
        app_state: state.clone(),
        run_hub: RunHub::default(),
        session_hub: SessionHub::default(),
        request_hub: RequestHub::default(),
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

#[derive(Debug, Deserialize)]
struct OAuthAuthorizeQuery {
    chat_id: Option<i64>,
    session_key: Option<String>,
}

async fn api_oauth_authorize(
    State(state): State<WebState>,
    Path(platform): Path<String>,
    Query(query): Query<OAuthAuthorizeQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let platform = platform.to_lowercase();
    if !["tiktok", "instagram", "linkedin"].contains(&platform.as_str()) {
        return Err((StatusCode::BAD_REQUEST, "Unknown platform".into()));
    }
    if state.app_state.config.social.as_ref().map_or(true, |s| !s.is_platform_enabled(&platform)) {
        return Err((StatusCode::BAD_REQUEST, "Platform not configured".into()));
    }

    let chat_id = match (query.chat_id, query.session_key) {
        (Some(id), _) => id,
        (_, Some(sk)) => {
            resolve_chat_id_for_session_key(&state, &normalize_session_key(Some(&sk))).await?
        }
        _ => return Err((StatusCode::BAD_REQUEST, "Provide chat_id or session_key".into())),
    };

    let state_token = uuid::Uuid::new_v4().simple().to_string();
    let expires_at = (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339();

    let platform_clone = platform.clone();
    let state_token_clone = state_token.clone();
    call_blocking(state.app_state.db.clone(), move |db| {
        db.create_oauth_pending_state(&state_token_clone, &platform_clone, chat_id, &expires_at)
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let auth_url = social_oauth::authorize_url(&state.app_state.config, &platform, &state_token)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "Failed to build authorize URL".into()))?;

    Ok(axum::response::Redirect::temporary(&auth_url))
}

#[derive(Debug, Deserialize)]
struct OAuthCallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

async fn api_oauth_callback(
    State(state): State<WebState>,
    Path(platform): Path<String>,
    Query(query): Query<OAuthCallbackQuery>,
) -> impl IntoResponse {
    let platform = platform.to_lowercase();

    if let (Some(err), desc) = (query.error, query.error_description.as_deref()) {
        let msg = desc.unwrap_or(&err);
        return (
            StatusCode::BAD_REQUEST,
            Html(format!(
                r#"<!DOCTYPE html><html><head><title>OAuth Error</title></head><body>
                <h1>Authorization failed</h1><p>{}</p></body></html>"#,
                msg.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
            )),
        )
            .into_response();
    }

    let (code, state_token) = match (query.code, query.state) {
        (Some(c), Some(s)) => (c, s),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Html(
                    r#"<!DOCTYPE html><html><head><title>OAuth Error</title></head><body>
                    <h1>Missing code or state</h1></body></html>"#,
                ),
            )
                .into_response();
        }
    };

    let Some((stored_platform, chat_id)) = call_blocking(state.app_state.db.clone(), move |db| {
        db.consume_oauth_pending_state(&state_token)
    })
    .await
    .ok()
    .flatten()
    else {
        return (
            StatusCode::BAD_REQUEST,
            Html(
                r#"<!DOCTYPE html><html><head><title>OAuth Error</title></head><body>
                <h1>Invalid or expired state</h1><p>Please try the authorization flow again.</p></body></html>"#,
            ),
        )
            .into_response();
    };

    if stored_platform != platform {
        return (
            StatusCode::BAD_REQUEST,
            Html(
                r#"<!DOCTYPE html><html><head><title>OAuth Error</title></head><body>
                <h1>Platform mismatch</h1></body></html>"#,
            ),
        )
            .into_response();
    }

    let base = social_oauth::oauth_base_url(&state.app_state.config).unwrap_or_default();
    let redirect_uri = format!("{}/api/oauth/callback/{}", base.trim_end_matches('/'), platform);

    let token_result = match social_oauth::exchange_code(
        &state.app_state.config,
        &platform,
        &code,
        &redirect_uri,
    )
    .await
    {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html(format!(
                    r#"<!DOCTYPE html><html><head><title>OAuth Error</title></head><body>
                    <h1>Token exchange failed</h1><p>{}</p></body></html>"#,
                    e.to_string().replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
                )),
            )
                .into_response();
        }
    };

    let platform_for_db = platform.clone();
    if let Err(e) = call_blocking(state.app_state.db.clone(), move |db| {
        db.upsert_social_token(
            &platform_for_db,
            chat_id,
            &token_result.access_token,
            token_result.refresh_token.as_deref(),
            token_result.expires_at.as_deref(),
        )
    })
    .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Html(format!(
                r#"<!DOCTYPE html><html><head><title>OAuth Error</title></head><body>
                <h1>Failed to store token</h1><p>{}</p></body></html>"#,
                html_escape::encode_text(&e.to_string()).to_string()
            )),
        )
            .into_response();
    }

    let platform_name = match platform.as_str() {
        "tiktok" => "TikTok",
        "instagram" => "Instagram",
        "linkedin" => "LinkedIn",
        _ => &platform,
    };

    (
        StatusCode::OK,
        Html(format!(
            r#"<!DOCTYPE html><html><head><title>Authorization successful</title></head><body>
            <h1>Authorization successful</h1>
            <p>{} has been connected. You can now ask the bot to fetch your feed.</p>
            <p><a href="/">Back to chat</a></p></body></html>"#,
            platform_name
        )),
    )
        .into_response()
}

fn build_router(web_state: WebState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/assets/*file", get(asset_file))
        .route("/icon.png", get(icon_file))
        .route("/favicon.ico", get(favicon_file))
        .route("/api/health", get(api_health))
        .route("/api/config", get(api_get_config).put(api_update_config))
        .route("/api/sessions", get(api_sessions))
        .route("/api/history", get(api_history))
        .route("/api/send", post(api_send))
        .route("/api/send_stream", post(api_send_stream))
        .route("/api/stream", get(api_stream))
        .route("/api/run_status", get(api_run_status))
        .route("/api/reset", post(api_reset))
        .route("/api/delete_session", post(api_delete_session))
        .route("/api/personas", get(api_personas))
        .route("/api/personas/switch", post(api_personas_switch))
        .route("/api/oauth/authorize/:platform", get(api_oauth_authorize))
        .route("/api/oauth/callback/:platform", get(api_oauth_callback))
        .with_state(web_state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::db::call_blocking;
    use crate::llm::LlmProvider;
    use crate::{claude::ResponseContentBlock, error::MicroClawError};
    use crate::{db::Database, memory::MemoryManager, skills::SkillManager, tools::ToolRegistry};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use teloxide::Bot;
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
            _messages: Vec<crate::claude::Message>,
            _tools: Option<Vec<crate::claude::ToolDefinition>>,
        ) -> Result<crate::claude::MessagesResponse, crate::error::MicroClawError> {
            Ok(crate::claude::MessagesResponse {
                content: vec![crate::claude::ResponseContentBlock::Text {
                    text: "hello from llm".into(),
                }],
                stop_reason: Some("end_turn".into()),
                usage: None,
            })
        }

        async fn send_message_stream(
            &self,
            _system: &str,
            _messages: Vec<crate::claude::Message>,
            _tools: Option<Vec<crate::claude::ToolDefinition>>,
            text_tx: Option<&tokio::sync::mpsc::UnboundedSender<String>>,
        ) -> Result<crate::claude::MessagesResponse, crate::error::MicroClawError> {
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
            _messages: Vec<crate::claude::Message>,
            _tools: Option<Vec<crate::claude::ToolDefinition>>,
        ) -> Result<crate::claude::MessagesResponse, MicroClawError> {
            tokio::time::sleep(Duration::from_millis(self.sleep_ms)).await;
            Ok(crate::claude::MessagesResponse {
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
            _messages: Vec<crate::claude::Message>,
            _tools: Option<Vec<crate::claude::ToolDefinition>>,
        ) -> Result<crate::claude::MessagesResponse, MicroClawError> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                return Ok(crate::claude::MessagesResponse {
                    content: vec![ResponseContentBlock::ToolUse {
                        id: "tool_1".into(),
                        name: "glob".into(),
                        input: json!({"pattern": "*.rs", "path": "."}),
                    }],
                    stop_reason: Some("tool_use".into()),
                    usage: None,
                });
            }
            Ok(crate::claude::MessagesResponse {
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
            max_history_messages: 50,
            max_document_size_mb: 100,
            workspace_dir: "./workspace".into(),
            openai_api_key: None,
            timezone: "UTC".into(),
            allowed_groups: vec![],
            control_chat_ids: vec![],
            max_session_messages: 40,
            compact_keep_recent: 20,
            whatsapp_access_token: None,
            whatsapp_phone_number_id: None,
            whatsapp_verify_token: None,
            whatsapp_webhook_port: 8080,
            discord_bot_token: None,
            discord_allowed_channels: vec![],
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
            browser_managed: false,
            browser_executable_path: None,
            browser_cdp_port_base: 9222,
            browser_idle_timeout_secs: None,
            browser_headless: false,
            agent_browser_path: None,
            cursor_agent_cli_path: "cursor-agent".into(),
            cursor_agent_model: String::new(),
            cursor_agent_timeout_secs: 600,
            social: None,
        };
        let dir = std::env::temp_dir().join(format!("microclaw_webtest_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        cfg.workspace_dir = dir.to_string_lossy().to_string();
        let runtime_dir = cfg.runtime_data_dir();
        std::fs::create_dir_all(&runtime_dir).unwrap();
        let db = Arc::new(Database::new(&runtime_dir).unwrap());
        let bot = Bot::new("123456:TEST_TOKEN");
        let state = AppState {
            config: cfg.clone(),
            bot: bot.clone(),
            db: db.clone(),
            memory: MemoryManager::new(&runtime_dir, cfg.working_dir()),
            skills: SkillManager::from_skills_dir(&cfg.skills_data_dir()),
            llm,
            tools: ToolRegistry::new(&cfg, bot, db),
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
            auth_token,
            run_hub: RunHub::default(),
            session_hub: SessionHub::default(),
            request_hub: RequestHub::default(),
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
    async fn test_db_paths_use_call_blocking_in_web_flow() {
        let state = test_state(Box::new(DummyLlm));
        let chat_id = 12345_i64;
        let cid = chat_id;
        let pid = call_blocking(state.db.clone(), move |db| db.get_or_create_default_persona(cid)).await.unwrap_or(0);
        let cid2 = chat_id;
        let message_count = call_blocking(state.db.clone(), move |db| db.get_all_messages(cid2, pid))
            .await
            .unwrap()
            .len();
        assert_eq!(message_count, 0);
    }
}
