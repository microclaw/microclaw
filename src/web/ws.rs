use super::*;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use futures_util::{SinkExt, StreamExt};
use microclaw_storage::db::SessionSettings;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex as TokioMutex;
use tracing::{debug, info, warn};

const PROTOCOL_VERSION: u64 = 3;
const TICK_INTERVAL_MS: u64 = 15_000;
const MAX_PAYLOAD_BYTES: usize = 1_000_000;
const MAX_BUFFERED_BYTES: usize = 1_000_000;

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum ClientFrame {
    #[serde(rename = "req")]
    Request {
        id: String,
        method: String,
        #[serde(default)]
        params: serde_json::Value,
    },
}

#[derive(Debug, Serialize)]
struct ErrorShape {
    code: String,
    message: String,
}

#[derive(Debug, Serialize)]
struct ResponseFrame<'a, T: Serialize> {
    #[serde(rename = "type")]
    kind: &'static str,
    id: &'a str,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<ErrorShape>,
}

#[derive(Debug, Serialize)]
struct EventFrame<T: Serialize> {
    #[serde(rename = "type")]
    kind: &'static str,
    event: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<T>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConnectParams {
    min_protocol: u64,
    max_protocol: u64,
    #[serde(default)]
    auth: Option<ConnectAuth>,
}

#[derive(Debug, Deserialize)]
struct ConnectAuth {
    #[serde(default)]
    token: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChatSendParams {
    #[serde(rename = "key")]
    session_key: String,
    message: String,
    #[serde(default)]
    idempotency_key: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChatHistoryParams {
    #[serde(rename = "key")]
    session_key: String,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionDeleteParams {
    #[serde(rename = "key")]
    session_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionsSendParams {
    #[serde(rename = "key")]
    session_key: String,
    message: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionsListParams {
    #[serde(default)]
    agent_id: Option<String>,
    #[serde(default)]
    search: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionSettingParams {
    #[serde(rename = "key")]
    session_key: String,
    #[serde(flatten)]
    extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionsSpawnParams {
    task: String,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    run_timeout_seconds: Option<u64>,
}

fn setting_value(
    extra: &serde_json::Map<String, serde_json::Value>,
    keys: &[&str],
) -> Option<String> {
    keys.iter().find_map(|key| {
        extra
            .get(*key)
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string)
    })
}

fn build_session_settings_update(method: &str, params: &SessionSettingParams) -> SessionSettings {
    let mut settings = SessionSettings::default();
    match method {
        "sessions.setLabel" => {
            settings.label = setting_value(&params.extra, &["label", "value"]);
        }
        "sessions.setThinking" => {
            settings.thinking_level = setting_value(&params.extra, &["level", "value"]);
        }
        "sessions.setVerbose" => {
            settings.verbose_level = setting_value(&params.extra, &["level", "value"]);
        }
        "sessions.setReasoning" => {
            settings.reasoning_level = setting_value(&params.extra, &["level", "value"]);
        }
        _ => {}
    }
    settings
}

fn session_settings_payload(settings: &SessionSettings) -> serde_json::Value {
    json!({
        "label": settings.label,
        "thinkingLevel": settings.thinking_level,
        "verboseLevel": settings.verbose_level,
        "reasoningLevel": settings.reasoning_level,
    })
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct HelloOkPayload {
    #[serde(rename = "type")]
    kind: &'static str,
    protocol: u64,
    server: HelloServer,
    features: HelloFeatures,
    snapshot: HelloSnapshot,
    policy: HelloPolicy,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct HelloServer {
    version: String,
    conn_id: String,
}

#[derive(Debug, Serialize)]
struct HelloFeatures {
    methods: Vec<&'static str>,
    events: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct HelloSnapshot {
    presence: Vec<serde_json::Value>,
    health: serde_json::Value,
    state_version: HelloStateVersion,
    uptime_ms: u64,
    auth_mode: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct HelloStateVersion {
    presence: u64,
    health: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct HelloPolicy {
    max_payload: usize,
    max_buffered_bytes: usize,
    tick_interval_ms: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ChatAckPayload {
    run_id: String,
    status: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ChatHistoryPayload {
    #[serde(rename = "key")]
    session_key: String,
    messages: Vec<ChatMessage>,
}

#[derive(Debug, Serialize)]
struct AgentsListPayload {
    agents: Vec<GatewayAgent>,
}

#[derive(Debug, Serialize)]
struct GatewayAgent {
    id: String,
    name: String,
    label: String,
    model: String,
    channel: &'static str,
    status: &'static str,
}

#[derive(Debug, Serialize)]
struct ModelsListPayload {
    models: Vec<GatewayModel>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GatewayModel {
    id: String,
    name: String,
    provider: String,
}

#[derive(Debug, Serialize)]
struct ConfigGetPayload {
    config: ConfigGetConfig,
}

#[derive(Debug, Serialize)]
struct ConfigGetConfig {
    agents: ConfigGetAgents,
}

#[derive(Debug, Serialize)]
struct ConfigGetAgents {
    defaults: ConfigGetDefaults,
}

#[derive(Debug, Serialize)]
struct ConfigGetDefaults {
    model: ConfigGetModel,
}

#[derive(Debug, Serialize)]
struct ConfigGetModel {
    primary: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ChatMessage {
    id: String,
    role: &'static str,
    content: Vec<ChatMessageContent>,
    timestamp: String,
}

#[derive(Debug, Serialize)]
struct ChatMessageContent {
    #[serde(rename = "type")]
    kind: &'static str,
    text: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ChatEventPayload {
    run_id: String,
    #[serde(rename = "key")]
    session_key: String,
    seq: u64,
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<ChatEventMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_message: Option<String>,
}

#[derive(Debug, Serialize)]
struct ChatEventMessage {
    role: &'static str,
    content: Vec<ChatEventContent>,
}

#[derive(Debug, Serialize)]
struct ChatEventContent {
    #[serde(rename = "type")]
    kind: &'static str,
    text: String,
}

type SharedSender = std::sync::Arc<TokioMutex<futures_util::stream::SplitSink<WebSocket, Message>>>;

pub(super) async fn api_ws(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    State(state): State<WebState>,
) -> impl IntoResponse {
    metrics_http_inc(&state).await;
    let client_key = client_key_from_headers_with_config(&headers, &state.app_state.config);
    ws.on_upgrade(move |socket| handle_ws_socket(state, socket, client_key))
}

async fn handle_ws_socket(state: WebState, socket: WebSocket, client_key: String) {
    let conn_id = uuid::Uuid::new_v4().to_string();
    let (sender, mut receiver) = socket.split();
    let sender = std::sync::Arc::new(TokioMutex::new(sender));
    let nonce = uuid::Uuid::new_v4().to_string();
    let challenge = EventFrame {
        kind: "event",
        event: "connect.challenge".to_string(),
        payload: Some(json!({
            "nonce": nonce,
            "ts": chrono::Utc::now().timestamp_millis(),
        })),
    };
    if send_json(&sender, &challenge).await.is_err() {
        return;
    }

    let connect = match receiver.next().await {
        Some(Ok(Message::Text(text))) => text,
        Some(Ok(Message::Close(_))) | None => return,
        _ => {
            let _ = send_error_response(
                &sender,
                "connect",
                "INVALID_REQUEST",
                "first frame must be a connect request",
            )
            .await;
            return;
        }
    };

    let (identity, is_admin) =
        match process_connect_frame(&state, &sender, &conn_id, &connect).await {
            Some(v) => v,
            None => return,
        };

    let tick_sender = sender.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(TICK_INTERVAL_MS));
        loop {
            interval.tick().await;
            let tick = EventFrame {
                kind: "event",
                event: "tick".to_string(),
                payload: Some(json!({"ts": chrono::Utc::now().timestamp_millis()})),
            };
            if send_json(&tick_sender, &tick).await.is_err() {
                break;
            }
        }
    });

    while let Some(msg) = receiver.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                if handle_request_frame(
                    &state,
                    &sender,
                    &identity,
                    is_admin,
                    &conn_id,
                    &client_key,
                    &text,
                )
                .await
                .is_err()
                {
                    break;
                }
            }
            Ok(Message::Ping(payload)) => {
                if sender
                    .lock()
                    .await
                    .send(Message::Pong(payload))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Ok(Message::Close(_)) | Err(_) => break,
            _ => {}
        }
    }
}

async fn process_connect_frame(
    state: &WebState,
    sender: &SharedSender,
    conn_id: &str,
    text: &str,
) -> Option<(AuthIdentity, bool)> {
    let frame = match serde_json::from_str::<ClientFrame>(text) {
        Ok(frame) => frame,
        Err(err) => {
            let _ = send_error_response(
                sender,
                "connect",
                "INVALID_REQUEST",
                &format!("invalid JSON: {err}"),
            )
            .await;
            return None;
        }
    };
    let ClientFrame::Request { id, method, params } = frame;
    if method != "connect" {
        let _ = send_error_response(
            sender,
            &id,
            "INVALID_REQUEST",
            "connect is only valid as the first request",
        )
        .await;
        return None;
    }
    let params = match serde_json::from_value::<ConnectParams>(params) {
        Ok(v) => v,
        Err(err) => {
            let _ = send_error_response(
                sender,
                &id,
                "INVALID_REQUEST",
                &format!("invalid connect params: {err}"),
            )
            .await;
            return None;
        }
    };
    if params.min_protocol > PROTOCOL_VERSION || params.max_protocol < PROTOCOL_VERSION {
        let _ = send_error_response(
            sender,
            &id,
            "UNSUPPORTED_PROTOCOL",
            "protocol version mismatch",
        )
        .await;
        return None;
    }
    let token = params.auth.and_then(|auth| auth.token).unwrap_or_default();
    let identity = match require_token_scope(state, &token, AuthScope::Read).await {
        Ok(identity) => identity,
        Err((status, msg)) => {
            let _ = send_error_response(sender, &id, ws_error_code_for_status(status), &msg).await;
            return None;
        }
    };
    let hello = ResponseFrame {
        kind: "res",
        id: &id,
        ok: true,
        payload: Some(HelloOkPayload {
            kind: "hello-ok",
            protocol: PROTOCOL_VERSION,
            server: HelloServer {
                version: env!("CARGO_PKG_VERSION").to_string(),
                conn_id: conn_id.to_string(),
            },
            features: HelloFeatures {
                methods: vec![
                    "health",
                    "status",
                    "chat.send",
                    "chat.history",
                    "sessions.delete",
                    "sessions.send",
                    "sessions.kill",
                    "sessions.spawn",
                    "sessions.setThinking",
                    "sessions.setVerbose",
                    "sessions.setReasoning",
                    "sessions.setLabel",
                    "sessions.list",
                    "agents.list",
                    "models.list",
                    "config.get",
                    "node.list",
                ],
                events: vec!["connect.challenge", "chat", "tick"],
            },
            snapshot: HelloSnapshot {
                presence: vec![],
                health: json!({
                    "ok": true,
                    "version": env!("CARGO_PKG_VERSION"),
                    "web_enabled": state.app_state.config.web_enabled,
                }),
                state_version: HelloStateVersion {
                    presence: 0,
                    health: 0,
                },
                uptime_ms: 0,
                auth_mode: "password",
            },
            policy: HelloPolicy {
                max_payload: MAX_PAYLOAD_BYTES,
                max_buffered_bytes: MAX_BUFFERED_BYTES,
                tick_interval_ms: TICK_INTERVAL_MS,
            },
        }),
        error: None,
    };
    if send_json(sender, &hello).await.is_err() {
        return None;
    }
    let is_admin = identity.allows(AuthScope::Admin);
    Some((identity, is_admin))
}

fn ws_error_code_for_status(status: StatusCode) -> &'static str {
    match status {
        StatusCode::UNAUTHORIZED => "UNAUTHORIZED",
        StatusCode::FORBIDDEN => "FORBIDDEN",
        StatusCode::TOO_MANY_REQUESTS => "RATE_LIMITED",
        StatusCode::NOT_FOUND => "NOT_FOUND",
        StatusCode::BAD_REQUEST => "INVALID_REQUEST",
        StatusCode::SERVICE_UNAVAILABLE => "UNAVAILABLE",
        _ => "INTERNAL_ERROR",
    }
}

async fn handle_request_frame(
    state: &WebState,
    sender: &SharedSender,
    identity: &AuthIdentity,
    is_admin: bool,
    _conn_id: &str,
    client_key: &str,
    text: &str,
) -> Result<(), ()> {
    let frame = serde_json::from_str::<ClientFrame>(text).map_err(|err| {
        warn!(target: "web", client_key = client_key, "invalid websocket frame: {err}");
    })?;
    let ClientFrame::Request { id, method, params } = frame;
    match method.as_str() {
        "connect" => {
            let _ = send_error_response(
                sender,
                &id,
                "INVALID_REQUEST",
                "connect is only valid as the first request",
            )
            .await;
        }
        "health" | "status" => {
            let payload = json!({
                "ok": true,
                "version": env!("CARGO_PKG_VERSION"),
                "web_enabled": state.app_state.config.web_enabled,
            });
            let res = ResponseFrame {
                kind: "res",
                id: &id,
                ok: true,
                payload: Some(payload),
                error: None,
            };
            let _ = send_json(sender, &res).await;
        }
        "agents.list" => {
            if !identity.allows(AuthScope::Read) {
                let _ = send_error_response(sender, &id, "FORBIDDEN", "forbidden").await;
                return Ok(());
            }
            let payload = AgentsListPayload {
                agents: bridge_agents(&state.app_state.config),
            };
            let res = ResponseFrame {
                kind: "res",
                id: &id,
                ok: true,
                payload: Some(payload),
                error: None,
            };
            let _ = send_json(sender, &res).await;
        }
        "models.list" => {
            if !identity.allows(AuthScope::Read) {
                let _ = send_error_response(sender, &id, "FORBIDDEN", "forbidden").await;
                return Ok(());
            }
            let payload = ModelsListPayload {
                models: bridge_models(&state.app_state.config),
            };
            let res = ResponseFrame {
                kind: "res",
                id: &id,
                ok: true,
                payload: Some(payload),
                error: None,
            };
            let _ = send_json(sender, &res).await;
        }
        "config.get" => {
            if !identity.allows(AuthScope::Read) {
                let _ = send_error_response(sender, &id, "FORBIDDEN", "forbidden").await;
                return Ok(());
            }
            let payload = ConfigGetPayload {
                config: ConfigGetConfig {
                    agents: ConfigGetAgents {
                        defaults: ConfigGetDefaults {
                            model: ConfigGetModel {
                                primary: bridge_primary_model(&state.app_state.config),
                            },
                        },
                    },
                },
            };
            let res = ResponseFrame {
                kind: "res",
                id: &id,
                ok: true,
                payload: Some(payload),
                error: None,
            };
            let _ = send_json(sender, &res).await;
        }
        "node.list" => {
            if !identity.allows(AuthScope::Read) {
                let _ = send_error_response(sender, &id, "FORBIDDEN", "forbidden").await;
                return Ok(());
            }
            let res = ResponseFrame {
                kind: "res",
                id: &id,
                ok: true,
                payload: Some(Vec::<serde_json::Value>::new()),
                error: None,
            };
            let _ = send_json(sender, &res).await;
        }
        "chat.history" => {
            if !identity.allows(AuthScope::Read) {
                let _ = send_error_response(sender, &id, "FORBIDDEN", "forbidden").await;
                return Ok(());
            }
            let params = match serde_json::from_value::<ChatHistoryParams>(params) {
                Ok(v) => v,
                Err(err) => {
                    let _ = send_error_response(
                        sender,
                        &id,
                        "INVALID_REQUEST",
                        &format!("invalid chat.history params: {err}"),
                    )
                    .await;
                    return Ok(());
                }
            };
            let session_key = normalize_session_key(Some(&params.session_key));
            let chat_id = match resolve_chat_id_for_session_key_read(state, &session_key).await {
                Ok(chat_id) => chat_id,
                Err((_, msg)) => {
                    let _ = send_error_response(sender, &id, "NOT_FOUND", &msg).await;
                    return Ok(());
                }
            };
            let mut messages = call_blocking(state.app_state.db.clone(), move |db| {
                db.get_all_messages(chat_id)
            })
            .await
            .map_err(|err| {
                warn!(target: "web", "chat.history db error: {err}");
            })?;
            if let Some(limit) = params.limit {
                if messages.len() > limit {
                    messages = messages[messages.len() - limit..].to_vec();
                }
            }
            let payload = ChatHistoryPayload {
                session_key,
                messages: messages
                    .into_iter()
                    .map(|m| ChatMessage {
                        id: m.id,
                        role: if m.is_from_bot { "assistant" } else { "user" },
                        content: vec![ChatMessageContent {
                            kind: "text",
                            text: m.content,
                        }],
                        timestamp: m.timestamp,
                    })
                    .collect(),
            };
            let res = ResponseFrame {
                kind: "res",
                id: &id,
                ok: true,
                payload: Some(payload),
                error: None,
            };
            let _ = send_json(sender, &res).await;
        }
        "chat.send" => {
            if !identity.allows(AuthScope::Write) {
                let _ = send_error_response(sender, &id, "FORBIDDEN", "forbidden").await;
                return Ok(());
            }
            let params = match serde_json::from_value::<ChatSendParams>(params) {
                Ok(v) => v,
                Err(err) => {
                    let _ = send_error_response(
                        sender,
                        &id,
                        "INVALID_REQUEST",
                        &format!("invalid chat.send params: {err}"),
                    )
                    .await;
                    return Ok(());
                }
            };
            let session_key = normalize_session_key(Some(&params.session_key));
            let send_body = SendRequest {
                session_key: Some(session_key.clone()),
                sender_name: Some("ws-user".to_string()),
                message: params.message,
            };
            let resp = match stream::start_stream_run_with_actor(
                state.clone(),
                send_body,
                identity.actor.clone(),
                "/",
            )
            .await
            {
                Ok(resp) => resp,
                Err((_, msg)) => {
                    let _ = send_error_response(sender, &id, "UNAVAILABLE", &msg).await;
                    return Ok(());
                }
            };
            let run_id = resp
                .0
                .get("run_id")
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .unwrap_or_else(|| {
                    params
                        .idempotency_key
                        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
                });
            let ack = ResponseFrame {
                kind: "res",
                id: &id,
                ok: true,
                payload: Some(ChatAckPayload {
                    run_id: run_id.clone(),
                    status: "started",
                }),
                error: None,
            };
            let _ = send_json(sender, &ack).await;
            spawn_chat_event_forwarder(
                state.clone(),
                sender.clone(),
                identity.actor.clone(),
                is_admin,
                run_id,
                session_key,
            );
        }
        "sessions.list" => {
            if !identity.allows(AuthScope::Read) {
                let _ = send_error_response(sender, &id, "FORBIDDEN", "forbidden").await;
                return Ok(());
            }

            let params = match serde_json::from_value::<SessionsListParams>(params) {
                Ok(v) => v,
                Err(err) => {
                    let _ = send_error_response(
                        sender,
                        &id,
                        "INVALID_REQUEST",
                        &format!("invalid sessions.list params: {err}"),
                    )
                    .await;
                    return Ok(());
                }
            };

            let chats = match call_blocking(state.app_state.db.clone(), |db| {
                db.get_recent_chats(400)
            })
            .await
            {
                Ok(chats) => chats,
                Err(err) => {
                    let _ =
                        send_error_response(sender, &id, "INTERNAL_SERVER_ERROR", &err.to_string())
                            .await;
                    return Ok(());
                }
            };

            let sessions = chats
                .into_iter()
                .map(|c| map_chat_to_session(&state.app_state.channel_registry, c))
                .filter(|s| {
                    if let Some(ref agent_id) = params.agent_id {
                        if !s.session_key.starts_with(agent_id) {
                            return false;
                        }
                    }
                    if let Some(ref search_term) = params.search {
                        if !search_term.is_empty() && !s.session_key.contains(search_term) {
                            return false;
                        }
                    }
                    true
                })
                .collect::<Vec<_>>();

            let res = ResponseFrame {
                kind: "res",
                id: &id,
                ok: true,
                payload: Some(json!({
                    "ok": true,
                    "sessions": sessions,
                })),
                error: None,
            };
            let _ = send_json(sender, &res).await;
        }
        "sessions.delete" => {
            if !identity.allows(AuthScope::Write) {
                let _ = send_error_response(sender, &id, "FORBIDDEN", "forbidden").await;
                return Ok(());
            }
            let params = match serde_json::from_value::<SessionDeleteParams>(params) {
                Ok(v) => v,
                Err(err) => {
                    let _ = send_error_response(
                        sender,
                        &id,
                        "INVALID_REQUEST",
                        &format!("invalid sessions.delete params: {err}"),
                    )
                    .await;
                    return Ok(());
                }
            };
            let session_key = normalize_session_key(Some(&params.session_key));
            let chat_id = match resolve_chat_id_for_session_key_read(state, &session_key).await {
                Ok(chat_id) => chat_id,
                Err((_, msg)) => {
                    let _ = send_error_response(sender, &id, "NOT_FOUND", &msg).await;
                    return Ok(());
                }
            };
            let deleted = call_blocking(state.app_state.db.clone(), move |db| {
                db.delete_chat_data(chat_id)
            })
            .await
            .map_err(|err| {
                warn!(target: "web", "sessions.delete db error: {err}");
            })?;
            let res = ResponseFrame {
                kind: "res",
                id: &id,
                ok: true,
                payload: Some(json!({
                    "ok": true,
                    "deleted": deleted,
                    "key": session_key,
                })),
                error: None,
            };
            let _ = send_json(sender, &res).await;
        }
        "sessions.send" => {
            if !identity.allows(AuthScope::Write) {
                let _ = send_error_response(sender, &id, "FORBIDDEN", "forbidden").await;
                return Ok(());
            }
            let params = match serde_json::from_value::<SessionsSendParams>(params) {
                Ok(v) => v,
                Err(err) => {
                    let _ = send_error_response(
                        sender,
                        &id,
                        "INVALID_REQUEST",
                        &format!("invalid sessions.send params: {err}"),
                    )
                    .await;
                    return Ok(());
                }
            };
            let session_key = normalize_session_key(Some(&params.session_key));
            if matches!(
                params.message.get("type").and_then(|v| v.as_str()),
                Some("control")
            ) {
                let action = params
                    .message
                    .get("action")
                    .and_then(|v| v.as_str())
                    .unwrap_or("noop");
                let res = ResponseFrame {
                    kind: "res",
                    id: &id,
                    ok: true,
                    payload: Some(json!({
                        "ok": true,
                        "key": session_key,
                        "action": action,
                        "applied": false,
                        "reason": "control messages are acknowledged but not yet enforced",
                    })),
                    error: None,
                };
                let _ = send_json(sender, &res).await;
                return Ok(());
            }

            let message = match params.message {
                serde_json::Value::String(text) => text,
                other => other.to_string(),
            };
            let send_body = SendRequest {
                session_key: Some(session_key.clone()),
                sender_name: Some("ws-user".to_string()),
                message,
            };
            let resp = match stream::start_stream_run_with_actor(
                state.clone(),
                send_body,
                identity.actor.clone(),
                "/",
            )
            .await
            {
                Ok(resp) => resp,
                Err((_, msg)) => {
                    let _ = send_error_response(sender, &id, "UNAVAILABLE", &msg).await;
                    return Ok(());
                }
            };
            let run_id = resp
                .0
                .get("run_id")
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
            let res = ResponseFrame {
                kind: "res",
                id: &id,
                ok: true,
                payload: Some(json!({
                    "ok": true,
                    "runId": run_id,
                    "key": session_key,
                    "status": "started",
                })),
                error: None,
            };
            let _ = send_json(sender, &res).await;
            spawn_chat_event_forwarder(
                state.clone(),
                sender.clone(),
                identity.actor.clone(),
                is_admin,
                run_id,
                session_key,
            );
        }
        "sessions.kill" => {
            if !identity.allows(AuthScope::Write) {
                let _ = send_error_response(sender, &id, "FORBIDDEN", "forbidden").await;
                return Ok(());
            }
            let params = match serde_json::from_value::<SessionDeleteParams>(params) {
                Ok(v) => v,
                Err(err) => {
                    let _ = send_error_response(
                        sender,
                        &id,
                        "INVALID_REQUEST",
                        &format!("invalid sessions.kill params: {err}"),
                    )
                    .await;
                    return Ok(());
                }
            };
            let session_key = normalize_session_key(Some(&params.session_key));
            let chat_id = match resolve_chat_id_for_session_key_read(state, &session_key).await {
                Ok(chat_id) => chat_id,
                Err((_, msg)) => {
                    let _ = send_error_response(sender, &id, "NOT_FOUND", &msg).await;
                    return Ok(());
                }
            };
            let channel = call_blocking(state.app_state.db.clone(), move |db| {
                db.get_chat_channel(chat_id)
            })
            .await
            .map_err(|err| {
                warn!(target: "web", "sessions.kill db error: {err}");
            })?
            .unwrap_or_else(|| "web".to_string());
            let aborted = crate::run_control::abort_runs(&channel, chat_id).await;
            let res = ResponseFrame {
                kind: "res",
                id: &id,
                ok: true,
                payload: Some(json!({
                    "ok": true,
                    "key": session_key,
                    "terminated": aborted > 0,
                    "activeAborted": aborted,
                    "channel": channel,
                })),
                error: None,
            };
            let _ = send_json(sender, &res).await;
        }
        "sessions.spawn" => {
            if !identity.allows(AuthScope::Write) {
                let _ = send_error_response(sender, &id, "FORBIDDEN", "forbidden").await;
                return Ok(());
            }
            let params = match serde_json::from_value::<SessionsSpawnParams>(params) {
                Ok(v) => v,
                Err(err) => {
                    let _ = send_error_response(
                        sender,
                        &id,
                        "INVALID_REQUEST",
                        &format!("invalid sessions.spawn params: {err}"),
                    )
                    .await;
                    return Ok(());
                }
            };
            if params.task.trim().is_empty() {
                let _ =
                    send_error_response(sender, &id, "INVALID_REQUEST", "task is required").await;
                return Ok(());
            }
            let session_key = format!("spawn:{}", uuid::Uuid::new_v4().simple());
            let spawn_chat_id = match resolve_chat_id_for_session_key(state, &session_key).await {
                Ok(chat_id) => chat_id,
                Err((_, msg)) => {
                    let _ = send_error_response(sender, &id, "UNAVAILABLE", &msg).await;
                    return Ok(());
                }
            };
            if params.label.is_some() {
                let settings = SessionSettings {
                    label: params.label.clone(),
                    ..SessionSettings::default()
                };
                if let Err(err) = call_blocking(state.app_state.db.clone(), move |db| {
                    db.save_session_settings(spawn_chat_id, &settings)
                })
                .await
                {
                    let _ = send_error_response(sender, &id, "UNAVAILABLE", &err.to_string()).await;
                    return Ok(());
                }
            }
            let send_body = SendRequest {
                session_key: Some(session_key.clone()),
                sender_name: Some("ws-user".to_string()),
                message: params.task,
            };
            let resp = match stream::start_stream_run_with_actor(
                state.clone(),
                send_body,
                identity.actor.clone(),
                "/",
            )
            .await
            {
                Ok(resp) => resp,
                Err((_, msg)) => {
                    let _ = send_error_response(sender, &id, "UNAVAILABLE", &msg).await;
                    return Ok(());
                }
            };
            let run_id = resp
                .0
                .get("run_id")
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
            let res = ResponseFrame {
                kind: "res",
                id: &id,
                ok: true,
                payload: Some(json!({
                    "ok": true,
                    "run_id": run_id,

                    "key": session_key,
                    "label": params.label,
                    "model": params.model,
                    "runTimeoutSeconds": params.run_timeout_seconds,
                })),
                error: None,
            };
            let _ = send_json(sender, &res).await;
        }
        "sessions.setThinking"
        | "sessions.setVerbose"
        | "sessions.setReasoning"
        | "sessions.setLabel" => {
            if !identity.allows(AuthScope::Write) {
                let _ = send_error_response(sender, &id, "FORBIDDEN", "forbidden").await;
                return Ok(());
            }
            let params = match serde_json::from_value::<SessionSettingParams>(params) {
                Ok(v) => v,
                Err(err) => {
                    let _ = send_error_response(
                        sender,
                        &id,
                        "INVALID_REQUEST",
                        &format!("invalid session setting params: {err}"),
                    )
                    .await;
                    return Ok(());
                }
            };
            let session_key = normalize_session_key(Some(&params.session_key));
            let chat_id = match resolve_chat_id_for_session_key(state, &session_key).await {
                Ok(chat_id) => chat_id,
                Err((_, msg)) => {
                    let _ = send_error_response(sender, &id, "UNAVAILABLE", &msg).await;
                    return Ok(());
                }
            };
            let settings = build_session_settings_update(&method, &params);
            let settings_to_save = settings.clone();
            if let Err(err) = call_blocking(state.app_state.db.clone(), move |db| {
                db.save_session_settings(chat_id, &settings_to_save)
            })
            .await
            {
                let _ = send_error_response(sender, &id, "UNAVAILABLE", &err.to_string()).await;
                return Ok(());
            }
            let stored = match call_blocking(state.app_state.db.clone(), move |db| {
                db.load_session_settings(chat_id)
            })
            .await
            {
                Ok(v) => v.unwrap_or_default(),
                Err(err) => {
                    let _ = send_error_response(sender, &id, "UNAVAILABLE", &err.to_string()).await;
                    return Ok(());
                }
            };
            let res = ResponseFrame {
                kind: "res",
                id: &id,
                ok: true,
                payload: Some(json!({
                    "ok": true,
                    "key": session_key,
                    "applied": true,
                    "settings": session_settings_payload(&stored),
                })),
                error: None,
            };
            let _ = send_json(sender, &res).await;
        }
        _ => {
            let _ = send_error_response(
                sender,
                &id,
                "METHOD_NOT_FOUND",
                "method not supported by MicroClaw mission-control bridge",
            )
            .await;
        }
    }
    Ok(())
}

fn bridge_agents(config: &crate::config::Config) -> Vec<GatewayAgent> {
    let label = config.bot_username_for_channel("web");
    let display = if label.trim().is_empty() {
        "MicroClaw".to_string()
    } else {
        label
    };

    vec![GatewayAgent {
        id: "microclaw-main".to_string(),
        name: "MicroClaw Orchestrator".to_string(),
        label: display,
        model: bridge_primary_model(config),
        channel: "web",
        status: "online",
    }]
}

fn bridge_primary_model(config: &crate::config::Config) -> String {
    let model = config.model.trim();
    if !model.is_empty() {
        model.to_string()
    } else {
        "unknown".to_string()
    }
}

fn bridge_models(config: &crate::config::Config) -> Vec<GatewayModel> {
    let mut out = Vec::new();
    for profile in config.list_llm_provider_profiles() {
        let provider = profile.provider.clone();
        for model in profile.models {
            out.push(GatewayModel {
                id: if model.contains('/') {
                    model.clone()
                } else {
                    format!("{provider}/{model}")
                },
                name: model,
                provider: provider.clone(),
            });
        }
    }
    out.sort_by(|left, right| left.id.cmp(&right.id));
    out.dedup_by(|left, right| left.id == right.id);
    out
}

fn spawn_chat_event_forwarder(
    state: WebState,
    sender: SharedSender,
    actor: String,
    is_admin: bool,
    run_id: String,
    session_key: String,
) {
    tokio::spawn(async move {
        let (mut rx, replay, done, _, _) = match state
            .run_hub
            .subscribe_with_replay(&run_id, None, &actor, is_admin)
            .await
        {
            Ok(v) => v,
            Err(_) => return,
        };

        let mut seq = 0_u64;
        for evt in replay {
            if forward_run_event(&sender, &run_id, &session_key, &mut seq, evt).await {
                return;
            }
        }
        if done {
            return;
        }

        while let Ok(evt) = rx.recv().await {
            if forward_run_event(&sender, &run_id, &session_key, &mut seq, evt).await {
                break;
            }
        }
    });
}

async fn forward_run_event(
    sender: &SharedSender,
    run_id: &str,
    session_key: &str,
    seq: &mut u64,
    evt: RunEvent,
) -> bool {
    let payload = match evt.event.as_str() {
        "delta" => {
            let delta = serde_json::from_str::<serde_json::Value>(&evt.data)
                .ok()
                .and_then(|v| v.get("delta").and_then(|v| v.as_str()).map(str::to_string))
                .unwrap_or_default();
            if delta.is_empty() {
                return false;
            }
            Some(ChatEventPayload {
                run_id: run_id.to_string(),
                session_key: session_key.to_string(),
                seq: *seq,
                state: "delta",
                message: Some(ChatEventMessage {
                    role: "assistant",
                    content: vec![ChatEventContent {
                        kind: "text",
                        text: delta,
                    }],
                }),
                error_message: None,
            })
        }
        "done" => {
            let text = serde_json::from_str::<serde_json::Value>(&evt.data)
                .ok()
                .and_then(|v| {
                    v.get("response")
                        .and_then(|v| v.as_str())
                        .map(str::to_string)
                })
                .unwrap_or_default();
            Some(ChatEventPayload {
                run_id: run_id.to_string(),
                session_key: session_key.to_string(),
                seq: *seq,
                state: "final",
                message: Some(ChatEventMessage {
                    role: "assistant",
                    content: vec![ChatEventContent { kind: "text", text }],
                }),
                error_message: None,
            })
        }
        "error" => {
            let error_message = serde_json::from_str::<serde_json::Value>(&evt.data)
                .ok()
                .and_then(|v| v.get("error").and_then(|v| v.as_str()).map(str::to_string))
                .unwrap_or_else(|| "stream run failed".to_string());
            Some(ChatEventPayload {
                run_id: run_id.to_string(),
                session_key: session_key.to_string(),
                seq: *seq,
                state: "error",
                message: None,
                error_message: Some(error_message),
            })
        }
        _ => None,
    };

    if let Some(payload) = payload {
        *seq = seq.saturating_add(1);
        let event = EventFrame {
            kind: "event",
            event: "chat".to_string(),
            payload: Some(payload),
        };
        if send_json(sender, &event).await.is_err() {
            return true;
        }
    }

    evt.event == "done" || evt.event == "error"
}

async fn send_error_response(
    sender: &SharedSender,
    id: &str,
    code: &str,
    message: &str,
) -> Result<(), ()> {
    let frame: ResponseFrame<'_, serde_json::Value> = ResponseFrame {
        kind: "res",
        id,
        ok: false,
        payload: None,
        error: Some(ErrorShape {
            code: code.to_string(),
            message: message.to_string(),
        }),
    };
    send_json(sender, &frame).await
}

async fn send_json<T: Serialize>(sender: &SharedSender, value: &T) -> Result<(), ()> {
    let text = serde_json::to_string(value).map_err(|_| ())?;
    if text.len() > MAX_PAYLOAD_BYTES {
        return Err(());
    }
    sender
        .lock()
        .await
        .send(Message::Text(text))
        .await
        .map_err(|err| {
            if is_expected_closed_socket_error(&err.to_string()) {
                debug!(target: "web", "websocket closed before send completed: {err}");
            } else {
                info!(target: "web", "websocket send failed: {err}");
            }
        })
        .map_err(|_| ())
}

fn is_expected_closed_socket_error(err: &str) -> bool {
    let normalized = err.to_ascii_lowercase();
    normalized.contains("sending after closing is not allowed")
        || normalized.contains("already closed")
        || normalized.contains("connection closed normally")
}

#[cfg(test)]
mod tests {
    use super::is_expected_closed_socket_error;

    #[test]
    fn test_expected_closed_socket_errors_are_downgraded() {
        assert!(is_expected_closed_socket_error(
            "WebSocket protocol error: Sending after closing is not allowed"
        ));
        assert!(is_expected_closed_socket_error(
            "connection closed normally"
        ));
        assert!(!is_expected_closed_socket_error("tls handshake failed"));
    }
}
