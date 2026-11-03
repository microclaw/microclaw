//! Remote execution against a paired MicroClaw Server.
//!
//! This module is the Desktop-side half of the v0.10.0 pairing contract. It owns
//! the device credential file, a small HTTP/SSE client for the Server's
//! pairing and run endpoints, the mapping from Server SSE frames onto
//! [`RuntimeEvent`]s, and [`RemoteRuntimeService`], which drives a remote run
//! through the same [`DesktopRunHandle`] the embedded runtime returns.

use crate::{
    DesktopRunCancellation, DesktopRunHandle, DesktopRunRequest, DesktopRunSteering,
    DesktopRuntimeMessage,
};
use futures_util::StreamExt;
use futures_util::stream::BoxStream;
use microclaw_core::runtime_event::{RuntimeEvent, RuntimeEventEnvelope};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::Sender;
use std::time::Duration;
use std::{fs, io};

/// File name of the device credential file inside the Desktop data root.
pub const CREDENTIALS_FILE_NAME: &str = "remote-server.json";

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const ERROR_BODY_LIMIT: usize = 512;

static NEXT_REMOTE_RUN_ID: AtomicU64 = AtomicU64::new(1);

/// Location of the device credential file for a Desktop data root.
pub fn credentials_path(desktop_data_root: &Path) -> PathBuf {
    desktop_data_root.join(CREDENTIALS_FILE_NAME)
}

#[derive(Debug, thiserror::Error)]
pub enum RemoteError {
    #[error("server URL is invalid: {0}")]
    InvalidUrl(String),
    #[error("the server rejected the device credentials; pair again")]
    Unauthorized,
    #[error("not found on the server")]
    NotFound,
    #[error("server responded with HTTP {status}: {message}")]
    Http { status: u16, message: String },
    #[error("could not reach the server: {0}")]
    Transport(String),
    #[error("unexpected server response: {0}")]
    Protocol(String),
}

/// Device credentials issued by `POST /api/pairing/claim`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteServerCredentials {
    pub server_url: String,
    pub device_id: String,
    pub device_token: String,
    pub label: String,
    #[serde(default)]
    pub server_version: Option<String>,
    pub paired_at: String,
}

impl RemoteServerCredentials {
    /// Load credentials from `path`. A missing file yields `Ok(None)`.
    pub fn load(path: &Path) -> io::Result<Option<Self>> {
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }

    /// Persist credentials atomically (`.tmp` + rename) with mode `0600` on
    /// Unix.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let temporary = path.with_extension("json.tmp");
        fs::write(&temporary, bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))?;
        }
        fs::rename(&temporary, path)?;
        Ok(())
    }

    /// Delete the credential file. A missing file is not an error.
    pub fn remove(path: &Path) -> io::Result<()> {
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }
}

/// Identity reported by `GET /api/pairing/whoami`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteIdentity {
    pub actor: String,
    pub scopes: Vec<String>,
    pub device: Option<RemoteDevice>,
    pub server_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteDevice {
    pub device_id: String,
    pub label: String,
    #[serde(default)]
    pub platform: Option<String>,
}

/// One frame of the Server's `text/event-stream`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerSseEvent {
    pub id: Option<u64>,
    pub event: String,
    pub data: String,
}

/// Normalize a user-entered server URL: trim whitespace, require `http` or
/// `https`, and drop trailing slashes so paths can be appended verbatim.
pub fn normalize_server_url(raw: &str) -> Result<String, RemoteError> {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(RemoteError::InvalidUrl("server URL is required".into()));
    }
    let parsed =
        url::Url::parse(trimmed).map_err(|error| RemoteError::InvalidUrl(error.to_string()))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(RemoteError::InvalidUrl(format!(
            "scheme {:?} is not supported; use http or https",
            parsed.scheme()
        )));
    }
    if parsed.host_str().is_none_or(str::is_empty) {
        return Err(RemoteError::InvalidUrl("server URL has no host".into()));
    }
    Ok(trimmed.to_string())
}

/// Run one async client call on a private current-thread Tokio runtime.
///
/// For callers without a runtime of their own (the GPUI desktop app calls
/// these from a plain `std::thread`).
fn block_on_client<T>(
    call: impl AsyncFnOnce(&RemoteServerClient) -> Result<T, RemoteError>,
) -> Result<T, RemoteError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| {
            RemoteError::Transport(format!("could not create a Tokio runtime: {error}"))
        })?;
    let client = RemoteServerClient::new()?;
    runtime.block_on(call(&client))
}

/// Blocking form of [`RemoteServerClient::pair`] for threads without a Tokio
/// runtime.
pub fn pair_blocking(
    server_url: &str,
    code: &str,
    device_name: &str,
) -> Result<RemoteServerCredentials, RemoteError> {
    block_on_client(async |client| client.pair(server_url, code, device_name).await)
}

/// Blocking form of [`RemoteServerClient::whoami`] for threads without a Tokio
/// runtime.
pub fn whoami_blocking(
    credentials: &RemoteServerCredentials,
) -> Result<RemoteIdentity, RemoteError> {
    block_on_client(async |client| client.whoami(credentials).await)
}

/// Async HTTP client for the Server's pairing and run endpoints.
#[derive(Debug, Clone)]
pub struct RemoteServerClient {
    http: reqwest::Client,
}

#[derive(Deserialize)]
struct ClaimResponse {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    error: Option<String>,
    device_id: Option<String>,
    device_token: Option<String>,
    label: Option<String>,
    #[serde(default)]
    server: Option<ServerInfo>,
}

#[derive(Deserialize)]
struct ServerInfo {
    version: Option<String>,
}

#[derive(Deserialize)]
struct WhoamiResponse {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    error: Option<String>,
    actor: Option<String>,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    device: Option<RemoteDevice>,
    #[serde(default)]
    server: Option<ServerInfo>,
}

#[derive(Deserialize)]
struct SubmitResponse {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    error: Option<String>,
    run_id: Option<String>,
}

#[derive(Deserialize)]
struct CancelResponse {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    aborted: bool,
}

impl RemoteServerClient {
    pub fn new() -> Result<Self, RemoteError> {
        let http = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .user_agent(format!("microclaw-desktop/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|error| RemoteError::Transport(error.to_string()))?;
        Ok(Self { http })
    }

    /// Claim a pairing code and receive device credentials.
    pub async fn pair(
        &self,
        server_url: &str,
        code: &str,
        device_name: &str,
    ) -> Result<RemoteServerCredentials, RemoteError> {
        let server_url = normalize_server_url(server_url)?;
        let code = code.trim();
        if code.is_empty() {
            return Err(RemoteError::Protocol("pairing code is required".into()));
        }
        let response = self
            .http
            .post(format!("{server_url}/api/pairing/claim"))
            .timeout(REQUEST_TIMEOUT)
            .json(&serde_json::json!({
                "code": code,
                "device_name": device_name.trim(),
                "platform": std::env::consts::OS,
            }))
            .send()
            .await
            .map_err(transport)?;
        let claim: ClaimResponse = decode_json(response).await?;
        if !claim.ok {
            return Err(RemoteError::Protocol(
                claim
                    .error
                    .unwrap_or_else(|| "pairing claim was not accepted".into()),
            ));
        }
        let device_id = claim
            .device_id
            .filter(|value| !value.is_empty())
            .ok_or_else(|| RemoteError::Protocol("claim response has no device_id".into()))?;
        let device_token = claim
            .device_token
            .filter(|value| !value.is_empty())
            .ok_or_else(|| RemoteError::Protocol("claim response has no device_token".into()))?;
        Ok(RemoteServerCredentials {
            server_url,
            device_id,
            device_token,
            label: claim
                .label
                .unwrap_or_else(|| device_name.trim().to_string()),
            server_version: claim.server.and_then(|server| server.version),
            paired_at: chrono::Utc::now().to_rfc3339(),
        })
    }

    /// Verify the device token and fetch the identity the Server sees.
    pub async fn whoami(
        &self,
        credentials: &RemoteServerCredentials,
    ) -> Result<RemoteIdentity, RemoteError> {
        let response = self
            .authorized(reqwest::Method::GET, credentials, "/api/pairing/whoami")
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(transport)?;
        let identity: WhoamiResponse = decode_json(response).await?;
        if !identity.ok {
            return Err(RemoteError::Protocol(
                identity
                    .error
                    .unwrap_or_else(|| "whoami was not accepted".into()),
            ));
        }
        Ok(RemoteIdentity {
            actor: identity
                .actor
                .ok_or_else(|| RemoteError::Protocol("whoami response has no actor".into()))?,
            scopes: identity.scopes,
            device: identity.device,
            server_version: identity.server.and_then(|server| server.version),
        })
    }

    /// Submit a task through `POST /api/send_stream` and return the Server run id.
    pub async fn submit(
        &self,
        credentials: &RemoteServerCredentials,
        session_key: &str,
        sender_name: &str,
        message: &str,
    ) -> Result<String, RemoteError> {
        let response = self
            .authorized(reqwest::Method::POST, credentials, "/api/send_stream")
            .timeout(REQUEST_TIMEOUT)
            .json(&serde_json::json!({
                "session_key": session_key,
                "sender_name": sender_name,
                "message": message,
            }))
            .send()
            .await
            .map_err(transport)?;
        let submit: SubmitResponse = decode_json(response).await?;
        if !submit.ok {
            return Err(RemoteError::Protocol(
                submit
                    .error
                    .unwrap_or_else(|| "task submission was not accepted".into()),
            ));
        }
        submit
            .run_id
            .filter(|value| !value.is_empty())
            .ok_or_else(|| RemoteError::Protocol("send_stream response has no run_id".into()))
    }

    /// Cancel a run through `POST /api/runs/{run_id}/cancel`. Returns whether
    /// the Server actually aborted a running turn.
    pub async fn cancel(
        &self,
        credentials: &RemoteServerCredentials,
        run_id: &str,
    ) -> Result<bool, RemoteError> {
        let path = format!("/api/runs/{}/cancel", encode_path_segment(run_id));
        let response = self
            .authorized(reqwest::Method::POST, credentials, &path)
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(transport)?;
        let cancel: CancelResponse = decode_json(response).await?;
        if !cancel.ok {
            return Err(RemoteError::Protocol(
                cancel
                    .error
                    .unwrap_or_else(|| "cancel was not accepted".into()),
            ));
        }
        Ok(cancel.aborted)
    }

    /// Open `GET /api/stream` for a run and parse its SSE frames.
    ///
    /// The stream has no overall timeout because runs can take minutes; the
    /// Server sends a keepalive comment every 15 seconds.
    pub async fn stream_events(
        &self,
        credentials: &RemoteServerCredentials,
        run_id: &str,
        last_event_id: Option<u64>,
    ) -> Result<BoxStream<'static, Result<ServerSseEvent, RemoteError>>, RemoteError> {
        let mut query = vec![("run_id", run_id.to_string())];
        if let Some(id) = last_event_id {
            query.push(("last_event_id", id.to_string()));
        }
        let response = self
            .authorized(reqwest::Method::GET, credentials, "/api/stream")
            .header(reqwest::header::ACCEPT, "text/event-stream")
            .query(&query)
            .send()
            .await
            .map_err(transport)?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(error_for_status(status, &body));
        }
        let bytes = response.bytes_stream();
        let stream = futures_util::stream::unfold(
            (bytes, SseParser::default(), VecDeque::new(), false),
            |(mut bytes, mut parser, mut pending, mut finished)| async move {
                loop {
                    if let Some(event) = pending.pop_front() {
                        return Some((Ok(event), (bytes, parser, pending, finished)));
                    }
                    if finished {
                        return None;
                    }
                    match bytes.next().await {
                        Some(Ok(chunk)) => pending.extend(parser.push(&chunk)),
                        Some(Err(error)) => {
                            finished = true;
                            return Some((
                                Err(RemoteError::Transport(error.to_string())),
                                (bytes, parser, pending, finished),
                            ));
                        }
                        None => {
                            finished = true;
                            pending.extend(parser.finish());
                        }
                    }
                }
            },
        );
        Ok(stream.boxed())
    }

    fn authorized(
        &self,
        method: reqwest::Method,
        credentials: &RemoteServerCredentials,
        path: &str,
    ) -> reqwest::RequestBuilder {
        self.http
            .request(method, format!("{}{path}", credentials.server_url))
            .bearer_auth(&credentials.device_token)
    }
}

fn transport(error: reqwest::Error) -> RemoteError {
    RemoteError::Transport(error.without_url().to_string())
}

fn encode_path_segment(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char)
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

fn error_for_status(status: StatusCode, body: &str) -> RemoteError {
    match status {
        StatusCode::UNAUTHORIZED => RemoteError::Unauthorized,
        StatusCode::NOT_FOUND => RemoteError::NotFound,
        _ => RemoteError::Http {
            status: status.as_u16(),
            message: error_message_from_body(body),
        },
    }
}

fn error_message_from_body(body: &str) -> String {
    let message = serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("error")
                .or_else(|| value.get("message"))
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_else(|| body.trim().to_string());
    if message.is_empty() {
        return "no response body".into();
    }
    message.chars().take(ERROR_BODY_LIMIT).collect()
}

async fn decode_json<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
) -> Result<T, RemoteError> {
    let status = response.status();
    let body = response.text().await.map_err(transport)?;
    if !status.is_success() {
        return Err(error_for_status(status, &body));
    }
    serde_json::from_str(&body).map_err(|error| RemoteError::Protocol(error.to_string()))
}

/// Incremental parser for `text/event-stream` bodies.
#[derive(Debug, Default)]
pub struct SseParser {
    buffer: Vec<u8>,
    id: Option<u64>,
    event: Option<String>,
    data: Vec<String>,
}

impl SseParser {
    /// Feed a chunk of bytes and return every frame completed by it.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<ServerSseEvent> {
        self.buffer.extend_from_slice(chunk);
        let mut events = Vec::new();
        while let Some(newline) = self.buffer.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = self.buffer.drain(..=newline).collect();
            let line = String::from_utf8_lossy(&line);
            let line = line.trim_end_matches(['\n', '\r']);
            if let Some(event) = self.handle_line(line) {
                events.push(event);
            }
        }
        events
    }

    /// Flush a trailing frame that was not terminated by a blank line.
    pub fn finish(&mut self) -> Vec<ServerSseEvent> {
        let mut events = Vec::new();
        if !self.buffer.is_empty() {
            let line = String::from_utf8_lossy(&std::mem::take(&mut self.buffer)).to_string();
            if let Some(event) = self.handle_line(line.trim_end_matches(['\n', '\r'])) {
                events.push(event);
            }
        }
        if let Some(event) = self.dispatch() {
            events.push(event);
        }
        events
    }

    fn handle_line(&mut self, line: &str) -> Option<ServerSseEvent> {
        if line.is_empty() {
            return self.dispatch();
        }
        if line.starts_with(':') {
            return None;
        }
        let (field, value) = match line.split_once(':') {
            Some((field, value)) => (field, value.strip_prefix(' ').unwrap_or(value)),
            None => (line, ""),
        };
        match field {
            "id" => self.id = value.trim().parse().ok(),
            "event" => self.event = Some(value.to_string()),
            "data" => self.data.push(value.to_string()),
            _ => {}
        }
        None
    }

    fn dispatch(&mut self) -> Option<ServerSseEvent> {
        let id = self.id.take();
        let event = self.event.take();
        let data = std::mem::take(&mut self.data);
        if event.is_none() && data.is_empty() {
            return None;
        }
        let data = data.join("\n");
        let event = event.unwrap_or_else(|| "message".into());
        if event == "message" && data == "keepalive" {
            return None;
        }
        Some(ServerSseEvent { id, event, data })
    }
}

/// A Server SSE frame projected onto the Desktop runtime vocabulary.
#[derive(Debug, Clone, PartialEq)]
pub enum MappedServerEvent {
    Runtime(RuntimeEvent),
    Done { response: String },
    Aborted { text: Option<String> },
    Error { message: String },
    Ignored,
}

/// Map one Server SSE frame (`event` name + JSON `data`) onto the Desktop runtime
/// vocabulary. Unknown event names are ignored; known names with malformed
/// payloads are protocol errors.
pub fn map_server_event(event: &str, data: &str) -> Result<MappedServerEvent, RemoteError> {
    let known = matches!(
        event,
        "status"
            | "tool_start"
            | "tool_result"
            | "delta"
            | "approval_required"
            | "mid_turn_injection"
            | "file_diff"
            | "subagent_started"
            | "subagent_finished"
            | "checkpoint_created"
            | "plan_updated"
            | "process_output"
            | "done"
            | "aborted"
            | "error"
    );
    if !known {
        return Ok(MappedServerEvent::Ignored);
    }
    let payload: Value = serde_json::from_str(data)
        .map_err(|error| RemoteError::Protocol(format!("{event} payload is not JSON: {error}")))?;
    let Value::Object(mut object) = payload else {
        return Err(RemoteError::Protocol(format!(
            "{event} payload is not a JSON object"
        )));
    };
    match event {
        "status" => {
            let message = object
                .get("message")
                .and_then(Value::as_str)
                .ok_or_else(|| RemoteError::Protocol("status payload has no message".into()))?;
            Ok(
                match message
                    .strip_prefix("iteration ")
                    .and_then(|value| value.trim().parse::<usize>().ok())
                {
                    Some(iteration) => {
                        MappedServerEvent::Runtime(RuntimeEvent::Iteration { iteration })
                    }
                    None => MappedServerEvent::Ignored,
                },
            )
        }
        "done" => Ok(MappedServerEvent::Done {
            response: string_field(&object, "response").unwrap_or_default(),
        }),
        "aborted" => Ok(MappedServerEvent::Aborted {
            text: string_field(&object, "text").filter(|text| !text.is_empty()),
        }),
        "error" => Ok(MappedServerEvent::Error {
            message: string_field(&object, "error")
                .filter(|message| !message.is_empty())
                .unwrap_or_else(|| "the server reported an unknown error".into()),
        }),
        "tool_start" => {
            object.entry("input").or_insert(Value::Null);
            decode_runtime_event("tool_start", object)
        }
        "delta" => decode_runtime_event("text_delta", object),
        other => decode_runtime_event(other, object),
    }
}

fn string_field(object: &Map<String, Value>, key: &str) -> Option<String> {
    object.get(key).and_then(Value::as_str).map(str::to_string)
}

fn decode_runtime_event(
    type_name: &str,
    mut object: Map<String, Value>,
) -> Result<MappedServerEvent, RemoteError> {
    object.insert("type".into(), Value::String(type_name.into()));
    serde_json::from_value::<RuntimeEvent>(Value::Object(object))
        .map(MappedServerEvent::Runtime)
        .map_err(|error| {
            RemoteError::Protocol(format!("{type_name} payload is malformed: {error}"))
        })
}

/// Runs Desktop tasks on a paired MicroClaw Server.
///
/// `DesktopRunRequest::workspace` is ignored here: the Server owns its working
/// directory and checkpoints. The request's `session` becomes the Server
/// session key `work:<session>` so a Desktop thread maps onto one Server chat.
#[derive(Debug, Clone)]
pub struct RemoteRuntimeService {
    credentials: RemoteServerCredentials,
    client: RemoteServerClient,
}

impl RemoteRuntimeService {
    pub fn new(credentials: RemoteServerCredentials) -> Result<Self, RemoteError> {
        Ok(Self {
            credentials,
            client: RemoteServerClient::new()?,
        })
    }

    pub fn with_client(credentials: RemoteServerCredentials, client: RemoteServerClient) -> Self {
        Self {
            credentials,
            client,
        }
    }

    pub fn credentials(&self) -> &RemoteServerCredentials {
        &self.credentials
    }

    pub fn client(&self) -> &RemoteServerClient {
        &self.client
    }

    /// Submit `request` to the Server and follow it on a dedicated OS thread.
    ///
    /// Envelopes carry the Server's run id and a client-side sequence that
    /// starts at 1 and increments by exactly one. Steering is rejected with a
    /// `SteeringResult { accepted: false }`. Cancellation calls the Server's
    /// cancel endpoint and keeps draining until the run reports `aborted`,
    /// `done`, or `error`.
    pub fn start(&self, request: DesktopRunRequest) -> Result<DesktopRunHandle, RemoteError> {
        let (message_tx, message_rx) = std::sync::mpsc::channel();
        let (cancel_tx, cancel_rx) = tokio::sync::mpsc::unbounded_channel();
        let (steer_tx, steer_rx) = tokio::sync::mpsc::unbounded_channel();
        let placeholder_run_id = next_remote_run_id();
        let thread_name = format!("microclaw-desktop-remote-{placeholder_run_id}");
        let worker_message_tx = message_tx.clone();
        let client = self.client.clone();
        let credentials = self.credentials.clone();
        std::thread::Builder::new()
            .name(thread_name)
            .spawn(move || {
                run_remote_worker(
                    client,
                    credentials,
                    request,
                    placeholder_run_id,
                    worker_message_tx,
                    cancel_rx,
                    steer_rx,
                )
            })
            .map_err(|error| {
                RemoteError::Transport(format!(
                    "could not start the remote runtime worker thread: {error}"
                ))
            })?;
        Ok(DesktopRunHandle {
            messages: message_rx,
            cancellation: DesktopRunCancellation { cancel_tx },
            steering: DesktopRunSteering { steer_tx },
        })
    }
}

fn next_remote_run_id() -> String {
    let counter = NEXT_REMOTE_RUN_ID.fetch_add(1, Ordering::Relaxed);
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis());
    format!("server-{millis}-{counter}")
}

fn run_remote_worker(
    client: RemoteServerClient,
    credentials: RemoteServerCredentials,
    request: DesktopRunRequest,
    placeholder_run_id: String,
    message_tx: Sender<DesktopRuntimeMessage>,
    cancel_rx: tokio::sync::mpsc::UnboundedReceiver<()>,
    steer_rx: tokio::sync::mpsc::UnboundedReceiver<String>,
) {
    let tokio_runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = message_tx.send(DesktopRuntimeMessage::Failed {
                run_id: placeholder_run_id,
                message: format!("Could not create the Tokio runtime: {error}"),
            });
            return;
        }
    };
    let mut run_id = placeholder_run_id;
    let mut steer_rx = steer_rx;
    let result = tokio_runtime.block_on(follow_remote_run(
        &client,
        &credentials,
        request,
        &mut run_id,
        &message_tx,
        cancel_rx,
        &mut steer_rx,
    ));
    // Guidance that arrived while the stream was finishing still deserves an
    // answer, so the UI never waits on a steer that nobody will acknowledge.
    while let Ok(_update) = steer_rx.try_recv() {
        let _ = message_tx.send(DesktopRuntimeMessage::SteeringResult {
            run_id: run_id.clone(),
            accepted: false,
            message: STEERING_UNAVAILABLE.into(),
        });
    }
    match result {
        Ok(()) => {
            let _ = message_tx.send(DesktopRuntimeMessage::Completed { run_id });
        }
        Err(message) => {
            let _ = message_tx.send(DesktopRuntimeMessage::Failed { run_id, message });
        }
    }
}

async fn follow_remote_run(
    client: &RemoteServerClient,
    credentials: &RemoteServerCredentials,
    request: DesktopRunRequest,
    run_id: &mut String,
    message_tx: &Sender<DesktopRuntimeMessage>,
    mut cancel_rx: tokio::sync::mpsc::UnboundedReceiver<()>,
    steer_rx: &mut tokio::sync::mpsc::UnboundedReceiver<String>,
) -> Result<(), String> {
    let session_key = format!("work:{}", request.session.trim());
    *run_id = client
        .submit(credentials, &session_key, &credentials.label, &request.task)
        .await
        .map_err(|error| error.to_string())?;

    let mut sequence = 0_u64;
    let mut last_event_id: Option<u64> = None;
    let mut reconnects_left = 1_u8;
    let mut cancel_open = true;
    let mut steer_open = true;
    let mut cancel_requested = false;

    let mut emit = |event: RuntimeEvent| {
        sequence += 1;
        let _ = message_tx.send(DesktopRuntimeMessage::Envelope(RuntimeEventEnvelope::new(
            run_id.clone(),
            sequence,
            event,
        )));
    };

    'connection: loop {
        let mut stream = match client
            .stream_events(credentials, run_id, last_event_id)
            .await
        {
            Ok(stream) => stream,
            Err(RemoteError::Transport(detail)) if reconnects_left > 0 => {
                reconnects_left -= 1;
                tracing_reconnect(&detail);
                continue 'connection;
            }
            Err(error) => return Err(error.to_string()),
        };
        loop {
            tokio::select! {
                next = stream.next() => {
                    match next {
                        Some(Ok(event)) => {
                            if let Some(id) = event.id {
                                if last_event_id.is_some_and(|last| id <= last) {
                                    continue;
                                }
                                last_event_id = Some(id);
                            }
                            match map_server_event(&event.event, &event.data)
                                .map_err(|error| error.to_string())?
                            {
                                MappedServerEvent::Runtime(runtime_event) => emit(runtime_event),
                                MappedServerEvent::Done { response } => {
                                    emit(RuntimeEvent::FinalResponse { text: response });
                                    return Ok(());
                                }
                                MappedServerEvent::Aborted { text } => {
                                    emit(RuntimeEvent::Cancelled {
                                        final_text: text.unwrap_or_default(),
                                    });
                                    return Ok(());
                                }
                                MappedServerEvent::Error { message } => return Err(message),
                                MappedServerEvent::Ignored => {}
                            }
                        }
                        Some(Err(error)) if reconnects_left > 0 => {
                            reconnects_left -= 1;
                            tracing_reconnect(&error.to_string());
                            continue 'connection;
                        }
                        Some(Err(error)) => return Err(error.to_string()),
                        None if reconnects_left > 0 => {
                            reconnects_left -= 1;
                            tracing_reconnect("the event stream closed before the run finished");
                            continue 'connection;
                        }
                        None => {
                            return Err(
                                "The server closed the event stream before the run finished.".into(),
                            );
                        }
                    }
                }
                signal = cancel_rx.recv(), if cancel_open && !cancel_requested => {
                    match signal {
                        Some(()) => {
                            cancel_requested = true;
                            if let Err(error) = client.cancel(credentials, run_id).await {
                                return Err(format!("Could not cancel the server run: {error}"));
                            }
                        }
                        None => cancel_open = false,
                    }
                }
                update = steer_rx.recv(), if steer_open => {
                    match update {
                        Some(_) => {
                            let _ = message_tx.send(DesktopRuntimeMessage::SteeringResult {
                                run_id: run_id.clone(),
                                accepted: false,
                                message: STEERING_UNAVAILABLE.into(),
                            });
                        }
                        None => steer_open = false,
                    }
                }
            }
        }
    }
}

const STEERING_UNAVAILABLE: &str = "Steering is not available for Server runs yet.";

fn tracing_reconnect(detail: &str) {
    // The runtime crate does not depend on `tracing`; keep a stderr breadcrumb
    // so headless smoke runs explain a reconnect.
    eprintln!("microclaw-desktop remote: reconnecting event stream ({detail})");
}

#[cfg(test)]
mod tests {
    use super::*;
    use microclaw_core::runtime_event::{
        RuntimeApprovalDecision, RuntimeApprovalOption, RuntimeApprovalOptionKind, RuntimePlanStep,
        RuntimePlanStepStatus, RuntimeProcessKind,
    };
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc::{self, Receiver};
    use std::sync::{Arc, Condvar, Mutex};

    fn credentials(server_url: &str) -> RemoteServerCredentials {
        RemoteServerCredentials {
            server_url: server_url.to_string(),
            device_id: "dev-1".into(),
            device_token: "mcd_0123456789abcdef0123456789abcdef".into(),
            label: "Everett's laptop".into(),
            server_version: Some("0.10.0".into()),
            paired_at: "2026-10-18T00:00:00Z".into(),
        }
    }

    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(future)
    }

    #[derive(Debug, Clone)]
    struct MockRequest {
        method: String,
        path: String,
        headers: String,
        body: String,
    }

    fn read_request(stream: &mut TcpStream) -> Option<MockRequest> {
        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 4096];
        let mut header_end = None;
        let mut content_length = 0;
        loop {
            if header_end.is_some_and(|end| buffer.len() >= end + content_length) {
                break;
            }
            let count = stream.read(&mut chunk).ok()?;
            if count == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..count]);
            if header_end.is_none()
                && let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n")
            {
                header_end = Some(position + 4);
                let headers = String::from_utf8_lossy(&buffer[..position]).to_string();
                content_length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .unwrap_or(0);
            }
        }
        let end = header_end?;
        let headers = String::from_utf8_lossy(&buffer[..end]).to_string();
        let mut request_line = headers.lines().next().unwrap_or_default().split(' ');
        let method = request_line.next().unwrap_or_default().to_string();
        let path = request_line.next().unwrap_or_default().to_string();
        let body = String::from_utf8_lossy(&buffer[end..end + content_length]).to_string();
        Some(MockRequest {
            method,
            path,
            headers,
            body,
        })
    }

    fn write_json(stream: &mut TcpStream, status: &str, body: &str) {
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).unwrap();
        stream.flush().unwrap();
    }

    fn write_sse_headers(stream: &mut TcpStream) {
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n",
            )
            .unwrap();
        stream.flush().unwrap();
    }

    type Handler = dyn Fn(MockRequest, &mut TcpStream) + Send + Sync + 'static;

    /// Minimal HTTP server: one thread per connection, every request is
    /// recorded, the handler writes the response.
    fn mock_server(
        handler: impl Fn(MockRequest, &mut TcpStream) + Send + Sync + 'static,
    ) -> (String, Receiver<MockRequest>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (request_tx, request_rx) = mpsc::channel();
        let handler: Arc<Handler> = Arc::new(handler);
        std::thread::spawn(move || {
            while let Ok((mut stream, _)) = listener.accept() {
                let handler = handler.clone();
                let request_tx = request_tx.clone();
                std::thread::spawn(move || {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    if let Some(request) = read_request(&mut stream) {
                        let _ = request_tx.send(request.clone());
                        handler(request, &mut stream);
                    }
                });
            }
        });
        (format!("http://{address}"), request_rx)
    }

    fn frame(id: Option<u64>, event: &str, data: &str) -> String {
        let mut frame = String::new();
        if let Some(id) = id {
            frame.push_str(&format!("id: {id}\n"));
        }
        frame.push_str(&format!("event: {event}\ndata: {data}\n\n"));
        frame
    }

    fn drain(handle: &DesktopRunHandle) -> Vec<DesktopRuntimeMessage> {
        let mut messages = Vec::new();
        loop {
            match handle.messages.recv_timeout(Duration::from_secs(10)) {
                Ok(message @ DesktopRuntimeMessage::Completed { .. })
                | Ok(message @ DesktopRuntimeMessage::Failed { .. }) => {
                    messages.push(message);
                    return messages;
                }
                Ok(message) => messages.push(message),
                Err(error) => panic!("runtime stopped without a terminal message: {error}"),
            }
        }
    }

    fn envelopes(messages: &[DesktopRuntimeMessage]) -> Vec<&RuntimeEventEnvelope> {
        messages
            .iter()
            .filter_map(|message| match message {
                DesktopRuntimeMessage::Envelope(envelope) => Some(envelope),
                _ => None,
            })
            .collect()
    }

    fn assert_contiguous(envelopes: &[&RuntimeEventEnvelope], run_id: &str) {
        for (index, envelope) in envelopes.iter().enumerate() {
            assert_eq!(envelope.run_id, run_id);
            assert_eq!(envelope.sequence, index as u64 + 1);
            assert_eq!(
                envelope.schema_version,
                RuntimeEventEnvelope::SCHEMA_VERSION
            );
        }
    }

    // ----- credentials -----

    #[test]
    fn credentials_round_trip_through_a_private_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = credentials_path(&directory.path().join("work"));
        assert_eq!(path.file_name().unwrap(), CREDENTIALS_FILE_NAME);
        assert_eq!(RemoteServerCredentials::load(&path).unwrap(), None);

        let saved = credentials("https://server.example");
        saved.save(&path).unwrap();
        assert!(!path.with_extension("json.tmp").exists());
        assert_eq!(RemoteServerCredentials::load(&path).unwrap(), Some(saved));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        RemoteServerCredentials::remove(&path).unwrap();
        assert!(!path.exists());
        RemoteServerCredentials::remove(&path).unwrap();
    }

    #[test]
    fn corrupt_credentials_are_reported_not_ignored() {
        let directory = tempfile::tempdir().unwrap();
        let path = credentials_path(directory.path());
        fs::write(&path, b"{not json").unwrap();
        let error = RemoteServerCredentials::load(&path).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn server_urls_are_normalized() {
        assert_eq!(
            normalize_server_url("  https://claw.example:8787/ ").unwrap(),
            "https://claw.example:8787"
        );
        assert_eq!(
            normalize_server_url("http://10.0.0.2:8080/prefix//").unwrap(),
            "http://10.0.0.2:8080/prefix"
        );
        assert!(matches!(
            normalize_server_url("ftp://claw.example"),
            Err(RemoteError::InvalidUrl(_))
        ));
        assert!(matches!(
            normalize_server_url("claw.example"),
            Err(RemoteError::InvalidUrl(_))
        ));
        assert!(matches!(
            normalize_server_url("   "),
            Err(RemoteError::InvalidUrl(_))
        ));
    }

    // ----- SSE parser -----

    #[test]
    fn sse_parser_handles_ids_multiline_data_comments_and_split_frames() {
        let mut parser = SseParser::default();
        let mut events = parser.push(b": keepalive\n\nevent: replay_meta\ndata: {\"a\":1}\n\n");
        assert_eq!(
            events,
            vec![ServerSseEvent {
                id: None,
                event: "replay_meta".into(),
                data: "{\"a\":1}".into(),
            }]
        );

        events = parser.push(b"id: 7\r\nevent: delta\r\ndata: line one\r\ndata: line two\r\n");
        assert!(events.is_empty());
        events = parser.push(b"\r\n");
        assert_eq!(
            events,
            vec![ServerSseEvent {
                id: Some(7),
                event: "delta".into(),
                data: "line one\nline two".into(),
            }]
        );

        // A frame split mid-line across chunks.
        events = parser.push(b"id: 8\nevent: to");
        assert!(events.is_empty());
        events =
            parser.push(b"ol_start\ndata: {\"call_id\":\"c\"}\n\nid: 9\nevent: done\ndata: {}");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, Some(8));
        assert_eq!(events[0].event, "tool_start");

        // The pending `done` frame completes on the next blank line; keepalive
        // text frames are dropped.
        events = parser.push(b"\n\ndata: keepalive\n\n");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, Some(9));
        assert_eq!(events[0].event, "done");
        assert!(parser.finish().is_empty());

        // A trailing frame without a terminating blank line flushes on finish.
        let mut parser = SseParser::default();
        assert!(parser.push(b"data: keepalive\n\n").is_empty());
        assert!(
            parser
                .push(b"id: 3\nevent: done\ndata: {\"response\":\"x\"}")
                .is_empty()
        );
        let flushed = parser.finish();
        assert_eq!(flushed.len(), 1);
        assert_eq!(flushed[0].id, Some(3));
        assert_eq!(flushed[0].data, "{\"response\":\"x\"}");
    }

    // ----- event mapping -----

    #[test]
    fn maps_every_server_event_name() {
        assert_eq!(
            map_server_event("status", r#"{"message":"iteration 3"}"#).unwrap(),
            MappedServerEvent::Runtime(RuntimeEvent::Iteration { iteration: 3 })
        );
        assert_eq!(
            map_server_event("status", r#"{"message":"running"}"#).unwrap(),
            MappedServerEvent::Ignored
        );
        assert_eq!(
            map_server_event("tool_start", r#"{"call_id":"c1","name":"read_file"}"#).unwrap(),
            MappedServerEvent::Runtime(RuntimeEvent::ToolStart {
                call_id: "c1".into(),
                name: "read_file".into(),
                input: Value::Null,
            })
        );
        assert_eq!(
            map_server_event(
                "tool_result",
                r#"{"call_id":"c1","name":"read_file","is_error":false,"preview":"ok","duration_ms":12,"status_code":null,"bytes":40,"error_type":null}"#
            )
            .unwrap(),
            MappedServerEvent::Runtime(RuntimeEvent::ToolResult {
                call_id: "c1".into(),
                name: "read_file".into(),
                is_error: false,
                preview: "ok".into(),
                duration_ms: 12,
                status_code: None,
                bytes: 40,
                error_type: None,
            })
        );
        assert_eq!(
            map_server_event("delta", r#"{"delta":"Hel"}"#).unwrap(),
            MappedServerEvent::Runtime(RuntimeEvent::TextDelta {
                delta: "Hel".into()
            })
        );
        assert_eq!(
            map_server_event(
                "approval_required",
                r#"{"approval_id":"a1","tool":"bash","preview":"rm x","options":[{"value":"1","label":"Approve once","kind":"primary","decision":"approve"}],"advisory":null}"#
            )
            .unwrap(),
            MappedServerEvent::Runtime(RuntimeEvent::ApprovalRequired {
                approval_id: "a1".into(),
                tool: "bash".into(),
                preview: Some("rm x".into()),
                options: vec![RuntimeApprovalOption {
                    value: "1".into(),
                    label: "Approve once".into(),
                    kind: RuntimeApprovalOptionKind::Primary,
                    decision: RuntimeApprovalDecision::Approve,
                }],
                advisory: None,
            })
        );
        assert_eq!(
            map_server_event("mid_turn_injection", r#"{"count":2}"#).unwrap(),
            MappedServerEvent::Runtime(RuntimeEvent::MidTurnInjection { count: 2 })
        );
        assert_eq!(
            map_server_event(
                "file_diff",
                r#"{"path":"a.rs","diff":"+x","added":1,"removed":0,"truncated":false}"#
            )
            .unwrap(),
            MappedServerEvent::Runtime(RuntimeEvent::FileDiff {
                path: "a.rs".into(),
                diff: "+x".into(),
                added: 1,
                removed: 0,
                truncated: false,
            })
        );
        assert_eq!(
            map_server_event("subagent_started", r#"{"run_id":"s1","label":"tests"}"#).unwrap(),
            MappedServerEvent::Runtime(RuntimeEvent::SubagentStarted {
                run_id: "s1".into(),
                label: "tests".into(),
            })
        );
        assert_eq!(
            map_server_event(
                "subagent_finished",
                r#"{"run_id":"s1","status":"completed"}"#
            )
            .unwrap(),
            MappedServerEvent::Runtime(RuntimeEvent::SubagentFinished {
                run_id: "s1".into(),
                status: "completed".into(),
            })
        );
        assert_eq!(
            map_server_event("checkpoint_created", r#"{"commit":"abc","label":"before"}"#).unwrap(),
            MappedServerEvent::Runtime(RuntimeEvent::CheckpointCreated {
                commit: "abc".into(),
                label: "before".into(),
            })
        );
        assert_eq!(
            map_server_event(
                "plan_updated",
                r#"{"steps":[{"title":"Inspect","status":"in_progress"}]}"#
            )
            .unwrap(),
            MappedServerEvent::Runtime(RuntimeEvent::PlanUpdated {
                steps: vec![RuntimePlanStep {
                    title: "Inspect".into(),
                    status: RuntimePlanStepStatus::InProgress,
                }],
            })
        );
        assert_eq!(
            map_server_event(
                "process_output",
                r#"{"call_id":"c2","command":"cargo test","output":"ok","exit_code":0,"duration_ms":5,"truncated":false,"kind":"verification"}"#
            )
            .unwrap(),
            MappedServerEvent::Runtime(RuntimeEvent::ProcessOutput {
                call_id: "c2".into(),
                command: "cargo test".into(),
                output: "ok".into(),
                exit_code: Some(0),
                duration_ms: 5,
                truncated: false,
                kind: RuntimeProcessKind::Verification,
            })
        );
        assert_eq!(
            map_server_event("done", r#"{"response":"All set."}"#).unwrap(),
            MappedServerEvent::Done {
                response: "All set.".into()
            }
        );
        assert_eq!(
            map_server_event("aborted", r#"{"text":null}"#).unwrap(),
            MappedServerEvent::Aborted { text: None }
        );
        assert_eq!(
            map_server_event("aborted", r#"{"text":"partial"}"#).unwrap(),
            MappedServerEvent::Aborted {
                text: Some("partial".into())
            }
        );
        assert_eq!(
            map_server_event("error", r#"{"error":"boom"}"#).unwrap(),
            MappedServerEvent::Error {
                message: "boom".into()
            }
        );
        assert_eq!(
            map_server_event("replay_meta", r#"{"replay_truncated":false}"#).unwrap(),
            MappedServerEvent::Ignored
        );
        assert_eq!(
            map_server_event("something_new", "not even json").unwrap(),
            MappedServerEvent::Ignored
        );
    }

    #[test]
    fn malformed_known_payloads_are_protocol_errors() {
        assert!(matches!(
            map_server_event("delta", "{oops"),
            Err(RemoteError::Protocol(_))
        ));
        assert!(matches!(
            map_server_event("tool_result", r#"{"call_id":1}"#),
            Err(RemoteError::Protocol(_))
        ));
        assert!(matches!(
            map_server_event("status", r#"[]"#),
            Err(RemoteError::Protocol(_))
        ));
        assert!(matches!(
            map_server_event("status", r#"{}"#),
            Err(RemoteError::Protocol(_))
        ));
        assert!(matches!(
            map_server_event(
                "plan_updated",
                r#"{"steps":[{"title":"x","status":"bogus"}]}"#
            ),
            Err(RemoteError::Protocol(_))
        ));
    }

    // ----- HTTP client -----

    #[test]
    fn pairs_whoami_and_maps_http_errors() {
        let (url, requests) = mock_server(|request, stream| match request.path.as_str() {
            "/api/pairing/claim" => write_json(
                stream,
                "200 OK",
                r#"{"ok":true,"device_id":"dev-9","device_token":"mcd_ff","label":"Laptop","scopes":["operator.read","operator.write"],"server":{"version":"0.10.0"}}"#,
            ),
            "/api/pairing/whoami" => {
                if request.headers.contains("Bearer mcd_ff") {
                    write_json(
                        stream,
                        "200 OK",
                        r#"{"ok":true,"actor":"device:dev-9","scopes":["operator.read"],"device":{"device_id":"dev-9","label":"Laptop","platform":"macos"},"server":{"version":"0.10.0"}}"#,
                    )
                } else {
                    write_json(stream, "401 Unauthorized", r#"{"error":"unauthorized"}"#)
                }
            }
            _ => write_json(stream, "500 Internal Server Error", r#"{"error":"nope"}"#),
        });
        let client = RemoteServerClient::new().unwrap();

        let paired = block_on(client.pair(&format!("{url}/"), " ABCD2345 ", "Laptop")).unwrap();
        assert_eq!(paired.server_url, url);
        assert_eq!(paired.device_id, "dev-9");
        assert_eq!(paired.device_token, "mcd_ff");
        assert_eq!(paired.label, "Laptop");
        assert_eq!(paired.server_version.as_deref(), Some("0.10.0"));
        let claim = requests.recv().unwrap();
        assert_eq!(claim.method, "POST");
        let body: Value = serde_json::from_str(&claim.body).unwrap();
        assert_eq!(body["code"], "ABCD2345");
        assert_eq!(body["device_name"], "Laptop");
        assert_eq!(body["platform"], std::env::consts::OS);

        let identity = block_on(client.whoami(&paired)).unwrap();
        assert_eq!(identity.actor, "device:dev-9");
        assert_eq!(identity.device.unwrap().platform.as_deref(), Some("macos"));
        assert_eq!(identity.server_version.as_deref(), Some("0.10.0"));

        let mut revoked = paired.clone();
        revoked.device_token = "mcd_revoked".into();
        assert!(matches!(
            block_on(client.whoami(&revoked)),
            Err(RemoteError::Unauthorized)
        ));

        // Blocking helpers work from a thread without a Tokio runtime.
        let (blocking_paired, blocking_identity) = std::thread::spawn({
            let url = url.clone();
            move || {
                let paired = pair_blocking(&url, "ABCD2345", "Laptop").unwrap();
                let identity = whoami_blocking(&paired).unwrap();
                (paired, identity)
            }
        })
        .join()
        .unwrap();
        assert_eq!(blocking_paired.device_id, "dev-9");
        assert_eq!(blocking_identity.actor, "device:dev-9");

        let mut other = paired.clone();
        other.server_url = url.clone();
        assert!(matches!(
            block_on(client.cancel(&other, "r/1")),
            Err(RemoteError::Http { status: 500, ref message }) if message == "nope"
        ));
        let cancel = std::iter::from_fn(|| requests.recv_timeout(Duration::from_secs(5)).ok())
            .find(|request| request.path.starts_with("/api/runs/"))
            .unwrap();
        assert_eq!(cancel.path, "/api/runs/r%2F1/cancel");

        assert!(matches!(
            block_on(client.pair("http://127.0.0.1:1", "ABCD2345", "x")),
            Err(RemoteError::Transport(_))
        ));
    }

    // ----- remote runtime service -----

    fn handshake_requests(requests: &Receiver<MockRequest>) -> (MockRequest, MockRequest) {
        let submit = requests.recv_timeout(Duration::from_secs(5)).unwrap();
        let stream = requests.recv_timeout(Duration::from_secs(5)).unwrap();
        (submit, stream)
    }

    #[test]
    fn remote_run_streams_envelopes_in_order_and_completes() {
        let (url, requests) = mock_server(|request, stream| match request.path.as_str() {
            "/api/send_stream" => write_json(stream, "200 OK", r#"{"ok":true,"run_id":"r1"}"#),
            path if path.starts_with("/api/stream?") => {
                write_sse_headers(stream);
                let mut body = String::new();
                body.push_str("event: replay_meta\ndata: {\"replay_truncated\":false}\n\n");
                body.push_str(&frame(Some(1), "status", r#"{"message":"running"}"#));
                body.push_str(": keepalive\n\n");
                body.push_str(&frame(Some(2), "status", r#"{"message":"iteration 1"}"#));
                body.push_str(&frame(Some(3), "delta", r#"{"delta":"Looking"}"#));
                body.push_str(&frame(
                    Some(4),
                    "tool_start",
                    r#"{"call_id":"c1","name":"read_file"}"#,
                ));
                body.push_str(&frame(
                    Some(5),
                    "tool_result",
                    r#"{"call_id":"c1","name":"read_file","is_error":false,"preview":"42 lines","duration_ms":3,"status_code":null,"bytes":900,"error_type":null}"#,
                ));
                body.push_str(&frame(Some(6), "done", r#"{"response":"Finished."}"#));
                stream.write_all(body.as_bytes()).unwrap();
                stream.flush().unwrap();
            }
            _ => write_json(stream, "404 Not Found", "run not found"),
        });
        let service = RemoteRuntimeService::new(credentials(&url)).unwrap();
        let handle = service
            .start(DesktopRunRequest {
                task: "Summarize the repo".into(),
                workspace: "/ignored/locally".into(),
                session: "thread-7".into(),
            })
            .unwrap();

        let messages = drain(&handle);
        let (submit, stream) = handshake_requests(&requests);
        assert_eq!(submit.method, "POST");
        assert!(
            submit
                .headers
                .contains("Bearer mcd_0123456789abcdef0123456789abcdef")
        );
        let body: Value = serde_json::from_str(&submit.body).unwrap();
        assert_eq!(body["session_key"], "work:thread-7");
        assert_eq!(body["sender_name"], "Everett's laptop");
        assert_eq!(body["message"], "Summarize the repo");
        assert_eq!(stream.method, "GET");
        assert_eq!(stream.path, "/api/stream?run_id=r1");
        assert!(
            stream
                .headers
                .to_ascii_lowercase()
                .contains("accept: text/event-stream")
        );

        let events = envelopes(&messages);
        assert_contiguous(&events, "r1");
        let kinds: Vec<&RuntimeEvent> = events.iter().map(|envelope| &envelope.event).collect();
        assert_eq!(kinds.len(), 5);
        assert_eq!(kinds[0], &RuntimeEvent::Iteration { iteration: 1 });
        assert_eq!(
            kinds[1],
            &RuntimeEvent::TextDelta {
                delta: "Looking".into()
            }
        );
        assert!(matches!(kinds[2], RuntimeEvent::ToolStart { name, .. } if name == "read_file"));
        assert!(matches!(
            kinds[3],
            RuntimeEvent::ToolResult { bytes: 900, .. }
        ));
        assert_eq!(
            kinds[4],
            &RuntimeEvent::FinalResponse {
                text: "Finished.".into()
            }
        );
        assert!(matches!(
            messages.last(),
            Some(DesktopRuntimeMessage::Completed { run_id }) if run_id == "r1"
        ));
    }

    #[test]
    fn remote_run_surfaces_approval_requests() {
        let (url, _requests) = mock_server(|request, stream| match request.path.as_str() {
            "/api/send_stream" => write_json(stream, "200 OK", r#"{"ok":true,"run_id":"r2"}"#),
            path if path.starts_with("/api/stream?") => {
                write_sse_headers(stream);
                let mut body = String::new();
                body.push_str(&frame(Some(1), "status", r#"{"message":"iteration 1"}"#));
                body.push_str(&frame(
                    Some(2),
                    "approval_required",
                    r#"{"approval_id":"ap-1","tool":"bash","preview":"cargo clean","options":[{"value":"1","label":"Approve once","kind":"primary","decision":"approve"},{"value":"3","label":"Deny","kind":"danger","decision":"deny"}],"advisory":"Deletes build output"}"#,
                ));
                body.push_str(&frame(
                    Some(3),
                    "done",
                    r#"{"response":"Reply with 1 to approve."}"#,
                ));
                stream.write_all(body.as_bytes()).unwrap();
                stream.flush().unwrap();
            }
            _ => write_json(stream, "404 Not Found", "run not found"),
        });
        let service = RemoteRuntimeService::new(credentials(&url)).unwrap();
        let handle = service
            .start(DesktopRunRequest {
                task: "Clean the build".into(),
                workspace: String::new(),
                session: "thread-8".into(),
            })
            .unwrap();

        // Steering is rejected without touching the server.
        handle.steering.steer("focus on docs").unwrap();

        let messages = drain(&handle);
        let events = envelopes(&messages);
        assert_contiguous(&events, "r2");
        assert_eq!(events.len(), 3);
        match &events[1].event {
            RuntimeEvent::ApprovalRequired {
                approval_id,
                tool,
                preview,
                options,
                advisory,
            } => {
                assert_eq!(approval_id, "ap-1");
                assert_eq!(tool, "bash");
                assert_eq!(preview.as_deref(), Some("cargo clean"));
                assert_eq!(options.len(), 2);
                assert_eq!(options[1].decision, RuntimeApprovalDecision::Deny);
                assert_eq!(advisory.as_deref(), Some("Deletes build output"));
            }
            other => panic!("expected approval, got {other:?}"),
        }
        assert!(matches!(
            &events[2].event,
            RuntimeEvent::FinalResponse { text } if text == "Reply with 1 to approve."
        ));
        assert!(messages.iter().any(|message| matches!(
            message,
            DesktopRuntimeMessage::SteeringResult { run_id, accepted: false, message }
                if run_id == "r2" && message.contains("not available")
        )));
        assert!(matches!(
            messages.last(),
            Some(DesktopRuntimeMessage::Completed { run_id }) if run_id == "r2"
        ));
    }

    #[test]
    fn remote_run_cancels_through_the_server_and_drains_until_aborted() {
        let cancel_gate = Arc::new((Mutex::new(false), Condvar::new()));
        let gate_for_handler = cancel_gate.clone();
        let (url, requests) = mock_server(move |request, stream| match request.path.as_str() {
            "/api/send_stream" => write_json(stream, "200 OK", r#"{"ok":true,"run_id":"r3"}"#),
            "/api/runs/r3/cancel" => {
                let (flag, signal) = &*gate_for_handler;
                *flag.lock().unwrap() = true;
                signal.notify_all();
                write_json(
                    stream,
                    "200 OK",
                    r#"{"ok":true,"run_id":"r3","aborted":true}"#,
                )
            }
            path if path.starts_with("/api/stream?") => {
                write_sse_headers(stream);
                let mut body = String::new();
                body.push_str(&frame(Some(1), "status", r#"{"message":"iteration 1"}"#));
                body.push_str(&frame(Some(2), "delta", r#"{"delta":"Working"}"#));
                stream.write_all(body.as_bytes()).unwrap();
                stream.flush().unwrap();
                let (flag, signal) = &*gate_for_handler;
                let mut cancelled = flag.lock().unwrap();
                while !*cancelled {
                    let (guard, timeout) = signal
                        .wait_timeout(cancelled, Duration::from_secs(10))
                        .unwrap();
                    cancelled = guard;
                    if timeout.timed_out() {
                        break;
                    }
                }
                drop(cancelled);
                stream
                    .write_all(frame(Some(3), "aborted", r#"{"text":"Working"}"#).as_bytes())
                    .unwrap();
                stream.flush().unwrap();
            }
            _ => write_json(stream, "404 Not Found", "run not found"),
        });
        let service = RemoteRuntimeService::new(credentials(&url)).unwrap();
        let handle = service
            .start(DesktopRunRequest {
                task: "Long task".into(),
                workspace: String::new(),
                session: "thread-9".into(),
            })
            .unwrap();

        let mut messages = Vec::new();
        loop {
            let message = handle
                .messages
                .recv_timeout(Duration::from_secs(10))
                .unwrap();
            let is_delta = matches!(
                &message,
                DesktopRuntimeMessage::Envelope(envelope)
                    if matches!(envelope.event, RuntimeEvent::TextDelta { .. })
            );
            messages.push(message);
            if is_delta {
                break;
            }
        }
        handle.cancellation.cancel().unwrap();
        messages.extend(drain(&handle));

        let events = envelopes(&messages);
        assert_contiguous(&events, "r3");
        assert_eq!(events.len(), 3);
        assert_eq!(
            events[2].event,
            RuntimeEvent::Cancelled {
                final_text: "Working".into()
            }
        );
        assert!(matches!(
            messages.last(),
            Some(DesktopRuntimeMessage::Completed { run_id }) if run_id == "r3"
        ));
        let paths: Vec<String> = std::iter::from_fn(|| requests.try_recv().ok())
            .map(|request| format!("{} {}", request.method, request.path))
            .collect();
        assert!(
            paths.contains(&"POST /api/runs/r3/cancel".to_string()),
            "{paths:?}"
        );
    }

    #[test]
    fn remote_run_reconnects_once_with_last_event_id_and_skips_replayed_events() {
        let connections = Arc::new(Mutex::new(0_u32));
        let connections_for_handler = connections.clone();
        let (url, requests) = mock_server(move |request, stream| match request.path.as_str() {
            "/api/send_stream" => write_json(stream, "200 OK", r#"{"ok":true,"run_id":"r4"}"#),
            path if path.starts_with("/api/stream?") => {
                let attempt = {
                    let mut guard = connections_for_handler.lock().unwrap();
                    *guard += 1;
                    *guard
                };
                write_sse_headers(stream);
                let mut body = String::new();
                if attempt == 1 {
                    body.push_str(&frame(Some(1), "status", r#"{"message":"iteration 1"}"#));
                    body.push_str(&frame(Some(2), "delta", r#"{"delta":"A"}"#));
                    // Connection drops here without a terminal event.
                } else {
                    // The server replays from history, including one already-seen frame.
                    body.push_str(&frame(Some(2), "delta", r#"{"delta":"A"}"#));
                    body.push_str(&frame(Some(3), "delta", r#"{"delta":"B"}"#));
                    body.push_str(&frame(Some(4), "done", r#"{"response":"AB"}"#));
                }
                stream.write_all(body.as_bytes()).unwrap();
                stream.flush().unwrap();
            }
            _ => write_json(stream, "404 Not Found", "run not found"),
        });
        let service = RemoteRuntimeService::new(credentials(&url)).unwrap();
        let handle = service
            .start(DesktopRunRequest {
                task: "Flaky link".into(),
                workspace: String::new(),
                session: "thread-10".into(),
            })
            .unwrap();

        let messages = drain(&handle);
        let events = envelopes(&messages);
        assert_contiguous(&events, "r4");
        let deltas: Vec<String> = events
            .iter()
            .filter_map(|envelope| match &envelope.event {
                RuntimeEvent::TextDelta { delta } => Some(delta.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(deltas, vec!["A".to_string(), "B".to_string()]);
        assert!(matches!(
            messages.last(),
            Some(DesktopRuntimeMessage::Completed { run_id }) if run_id == "r4"
        ));
        let paths: Vec<String> = std::iter::from_fn(|| requests.try_recv().ok())
            .map(|request| request.path)
            .collect();
        assert!(
            paths.contains(&"/api/stream?run_id=r4".to_string()),
            "{paths:?}"
        );
        assert!(
            paths.contains(&"/api/stream?run_id=r4&last_event_id=2".to_string()),
            "{paths:?}"
        );
    }

    #[test]
    fn remote_run_fails_on_server_error_event_and_on_submit_rejection() {
        let (url, _requests) = mock_server(|request, stream| match request.path.as_str() {
            "/api/send_stream" => write_json(stream, "200 OK", r#"{"ok":true,"run_id":"r5"}"#),
            path if path.starts_with("/api/stream?") => {
                write_sse_headers(stream);
                stream
                    .write_all(
                        frame(Some(1), "error", r#"{"error":"provider exploded"}"#).as_bytes(),
                    )
                    .unwrap();
                stream.flush().unwrap();
            }
            _ => write_json(stream, "404 Not Found", "run not found"),
        });
        let service = RemoteRuntimeService::new(credentials(&url)).unwrap();
        let handle = service
            .start(DesktopRunRequest {
                task: "Explode".into(),
                workspace: String::new(),
                session: "thread-11".into(),
            })
            .unwrap();
        let messages = drain(&handle);
        assert!(matches!(
            messages.last(),
            Some(DesktopRuntimeMessage::Failed { run_id, message })
                if run_id == "r5" && message == "provider exploded"
        ));

        let (url, _requests) = mock_server(|_, stream| {
            write_json(stream, "401 Unauthorized", r#"{"error":"unauthorized"}"#)
        });
        let service = RemoteRuntimeService::new(credentials(&url)).unwrap();
        let handle = service
            .start(DesktopRunRequest {
                task: "Rejected".into(),
                workspace: String::new(),
                session: "thread-12".into(),
            })
            .unwrap();
        let messages = drain(&handle);
        assert!(matches!(
            messages.last(),
            Some(DesktopRuntimeMessage::Failed { run_id, message })
                if run_id.starts_with("server-") && message.contains("pair again")
        ));
    }
}
