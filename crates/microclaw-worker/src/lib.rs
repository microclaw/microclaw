//! Authenticated WebSocket transport and host for MicroClaw Workers.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use http::header::AUTHORIZATION;
use microclaw_core::run_protocol::{
    RuntimeError, RuntimeErrorCode, WorkerCommand, WorkerFrame, WORKER_PROTOCOL_VERSION,
};
use microclaw_runtime::{RunController, Worker, WorkerConnection, WorkerTransport};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use tokio_tungstenite::tungstenite::http::StatusCode;
use tokio_tungstenite::tungstenite::{Error as WebSocketError, Message};
use tokio_tungstenite::{accept_hdr_async, connect_async, MaybeTlsStream, WebSocketStream};

/// Creates authenticated WebSocket connections to a MicroClaw Worker host.
#[derive(Debug, Clone)]
pub struct WebSocketWorkerTransport {
    url: String,
    bearer_token: Option<String>,
}

impl WebSocketWorkerTransport {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            bearer_token: None,
        }
    }

    pub fn bearer_token(mut self, token: impl Into<String>) -> Self {
        self.bearer_token = Some(token.into());
        self
    }
}

struct WebSocketConnection {
    socket: WebSocketStream<MaybeTlsStream<TcpStream>>,
}

#[async_trait]
impl WorkerTransport for WebSocketWorkerTransport {
    async fn connect(&self) -> Result<Box<dyn WorkerConnection>, RuntimeError> {
        let mut request = self
            .url
            .as_str()
            .into_client_request()
            .map_err(configuration_error)?;
        if let Some(token) = &self.bearer_token {
            let value = format!("Bearer {token}")
                .parse()
                .map_err(|_| configuration_error("invalid Worker bearer token"))?;
            request.headers_mut().insert(AUTHORIZATION, value);
        }
        let (socket, _) = connect_async(request).await.map_err(connection_error)?;
        Ok(Box::new(WebSocketConnection { socket }))
    }
}

#[async_trait]
impl WorkerConnection for WebSocketConnection {
    async fn send(&mut self, command: WorkerCommand) -> Result<(), RuntimeError> {
        let payload = serde_json::to_string(&command).map_err(protocol_error)?;
        self.socket
            .send(Message::Text(payload))
            .await
            .map_err(connection_error)
    }

    async fn receive(&mut self) -> Result<Option<WorkerFrame>, RuntimeError> {
        while let Some(message) = self.socket.next().await {
            match message.map_err(connection_error)? {
                Message::Text(payload) => {
                    return serde_json::from_str(&payload)
                        .map(Some)
                        .map_err(protocol_error);
                }
                Message::Binary(payload) => {
                    return serde_json::from_slice(&payload)
                        .map(Some)
                        .map_err(protocol_error);
                }
                Message::Ping(payload) => self
                    .socket
                    .send(Message::Pong(payload))
                    .await
                    .map_err(connection_error)?,
                Message::Close(_) => return Ok(None),
                Message::Pong(_) | Message::Frame(_) => {}
            }
        }
        Ok(None)
    }
}

/// Authenticated WebSocket host for a Local or custom Worker implementation.
pub struct WorkerHost {
    worker: Arc<dyn Worker>,
    bearer_token: Option<String>,
    runs: Arc<tokio::sync::Mutex<HashMap<String, Arc<HostedRun>>>>,
}

struct HostedRun {
    request_fingerprint: String,
    controller: RunController,
    state: Mutex<HostedRunState>,
    changed: tokio::sync::Notify,
}

#[derive(Default)]
struct HostedRunState {
    events: Vec<microclaw_core::runtime_event::RuntimeEventEnvelope>,
    result: Option<microclaw_core::run_protocol::RunResult>,
}

impl WorkerHost {
    pub fn new(worker: impl Worker + 'static) -> Self {
        Self {
            worker: Arc::new(worker),
            bearer_token: None,
            runs: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        }
    }

    pub fn shared(worker: Arc<dyn Worker>) -> Self {
        Self {
            worker,
            bearer_token: None,
            runs: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        }
    }

    pub fn bearer_token(mut self, token: impl Into<String>) -> Self {
        self.bearer_token = Some(token.into());
        self
    }

    /// Serve until the listener is closed or the task is cancelled.
    pub async fn serve(self, listener: TcpListener) -> Result<(), RuntimeError> {
        let worker = self.worker;
        let runs = self.runs;
        let bearer_token = self.bearer_token.map(|token| format!("Bearer {token}"));
        loop {
            let (stream, _) = listener.accept().await.map_err(connection_error)?;
            let worker = worker.clone();
            let runs = runs.clone();
            let bearer_token = bearer_token.clone();
            tokio::spawn(async move {
                let _ = serve_connection(stream, worker, runs, bearer_token).await;
            });
        }
    }
}

#[allow(clippy::result_large_err)]
async fn serve_connection(
    stream: TcpStream,
    worker: Arc<dyn Worker>,
    runs: Arc<tokio::sync::Mutex<HashMap<String, Arc<HostedRun>>>>,
    bearer_token: Option<String>,
) -> Result<(), RuntimeError> {
    let socket = accept_hdr_async(stream, move |request: &Request, mut response: Response| {
        let authorized = bearer_token.as_ref().is_none_or(|expected| {
            request
                .headers()
                .get(AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|actual| constant_time_eq(actual.as_bytes(), expected.as_bytes()))
        });
        if authorized {
            Ok(response)
        } else {
            *response.status_mut() = StatusCode::UNAUTHORIZED;
            Err(response.map(|_| Some("unauthorized".into())))
        }
    })
    .await
    .map_err(connection_error)?;
    let (mut sink, mut stream) = socket.split();

    while let Some(message) = stream.next().await {
        let command = decode_command(message.map_err(connection_error)?)?;
        command.validate_protocol()?;
        match command {
            WorkerCommand::Describe { .. } => {
                send_frame(
                    &mut sink,
                    WorkerFrame::Descriptor {
                        protocol_version: WORKER_PROTOCOL_VERSION,
                        descriptor: worker.descriptor(),
                    },
                )
                .await?;
            }
            WorkerCommand::Health { .. } => {
                send_frame(
                    &mut sink,
                    WorkerFrame::Health {
                        protocol_version: WORKER_PROTOCOL_VERSION,
                        health: worker.health(),
                    },
                )
                .await?;
            }
            WorkerCommand::Submit {
                profile, request, ..
            } => {
                let run_id = request
                    .run_id
                    .clone()
                    .ok_or_else(|| protocol_error("remote submission requires run_id"))?;
                let request_fingerprint =
                    serde_json::to_string(&(profile.clone(), &request)).map_err(protocol_error)?;
                let mut registry = runs.lock().await;
                let hosted = if let Some(existing) = registry.get(run_id.as_str()).cloned() {
                    if existing.request_fingerprint != request_fingerprint {
                        send_frame(
                            &mut sink,
                            WorkerFrame::Error {
                                protocol_version: WORKER_PROTOCOL_VERSION,
                                run_id: Some(run_id),
                                error: protocol_error(
                                    "run_id was already submitted with a different request",
                                ),
                            },
                        )
                        .await?;
                        continue;
                    }
                    existing
                } else {
                    let run = worker.submit(profile, *request).await?;
                    let hosted = Arc::new(HostedRun {
                        request_fingerprint,
                        controller: run.controller(),
                        state: Mutex::new(HostedRunState::default()),
                        changed: tokio::sync::Notify::new(),
                    });
                    registry.insert(run_id.to_string(), hosted.clone());
                    tokio::spawn(pump_run(run, hosted.clone()));
                    hosted
                };
                drop(registry);
                send_frame(
                    &mut sink,
                    WorkerFrame::Accepted {
                        protocol_version: WORKER_PROTOCOL_VERSION,
                        run_id: run_id.clone(),
                    },
                )
                .await?;
                stream_hosted_run(&mut sink, &mut stream, hosted, run_id, None).await?;
                return Ok(());
            }
            WorkerCommand::Control { .. } => {
                return Err(protocol_error("control command has no active run"));
            }
            WorkerCommand::ResumeEvents {
                run_id,
                after_sequence,
                ..
            } => {
                let hosted = runs.lock().await.get(run_id.as_str()).cloned();
                let Some(hosted) = hosted else {
                    send_frame(
                        &mut sink,
                        WorkerFrame::Error {
                            protocol_version: WORKER_PROTOCOL_VERSION,
                            run_id: Some(run_id),
                            error: RuntimeError {
                                code: RuntimeErrorCode::Unavailable,
                                message: "run is not known by this Worker host".into(),
                                retryable: true,
                            },
                        },
                    )
                    .await?;
                    continue;
                };
                stream_hosted_run(&mut sink, &mut stream, hosted, run_id, after_sequence).await?;
                return Ok(());
            }
        }
    }
    Ok(())
}

async fn pump_run(mut run: microclaw_runtime::RunHandle, hosted: Arc<HostedRun>) {
    while let Some(envelope) = run.next_event().await {
        hosted
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .events
            .push(envelope);
        hosted.changed.notify_waiters();
    }
    let result =
        run.result()
            .await
            .unwrap_or_else(|error| microclaw_core::run_protocol::RunResult {
                run_id: hosted.controller.id().clone(),
                session_id: microclaw_core::run_protocol::SessionId::new(""),
                status: microclaw_core::run_protocol::RunStatus::Failed,
                final_text: String::new(),
                error: Some(error),
                metadata: Default::default(),
            });
    hosted
        .state
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .result = Some(result);
    hosted.changed.notify_waiters();
}

async fn stream_hosted_run<S, R>(
    sink: &mut S,
    stream: &mut R,
    hosted: Arc<HostedRun>,
    run_id: microclaw_core::run_protocol::RunId,
    after_sequence: Option<u64>,
) -> Result<(), RuntimeError>
where
    S: futures_util::Sink<Message, Error = WebSocketError> + Unpin,
    R: futures_util::Stream<Item = Result<Message, WebSocketError>> + Unpin,
{
    let mut cursor = after_sequence;
    loop {
        let (events, result) = {
            let state = hosted
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            (
                state
                    .events
                    .iter()
                    .filter(|event| cursor.is_none_or(|value| event.sequence > value))
                    .cloned()
                    .collect::<Vec<_>>(),
                state.result.clone(),
            )
        };
        for envelope in events {
            cursor = Some(envelope.sequence);
            send_frame(
                sink,
                WorkerFrame::Event {
                    protocol_version: WORKER_PROTOCOL_VERSION,
                    envelope,
                },
            )
            .await?;
        }
        if let Some(result) = result {
            send_frame(
                sink,
                WorkerFrame::Result {
                    protocol_version: WORKER_PROTOCOL_VERSION,
                    result,
                },
            )
            .await?;
            return Ok(());
        }
        tokio::select! {
            _ = hosted.changed.notified() => {}
            message = stream.next() => {
                let Some(message) = message else { return Err(connection_error("Worker client disconnected")); };
                let command = decode_command(message.map_err(connection_error)?)?;
                command.validate_protocol()?;
                let WorkerCommand::Control { control, .. } = command else {
                    send_frame(sink, WorkerFrame::Error { protocol_version: WORKER_PROTOCOL_VERSION, run_id: Some(run_id.clone()), error: protocol_error("only control commands are accepted during a run") }).await?;
                    continue;
                };
                let outcome = match control {
                    microclaw_core::run_protocol::RuntimeControl::Cancel { run_id: target } if target == run_id => hosted.controller.cancel_confirmed().await,
                    microclaw_core::run_protocol::RuntimeControl::Steer { run_id: target, message } if target == run_id => hosted.controller.steer_confirmed(message).await,
                    microclaw_core::run_protocol::RuntimeControl::ResolveApproval { run_id: target, approval_id, decision } if target == run_id => hosted.controller.resolve_approval_confirmed(approval_id, decision).await,
                    _ => Err(protocol_error("control command targets a different run")),
                };
                match outcome {
                    Ok(()) => send_frame(sink, WorkerFrame::ControlAcknowledged { protocol_version: WORKER_PROTOCOL_VERSION, run_id: run_id.clone() }).await?,
                    Err(error) => send_frame(sink, WorkerFrame::Error { protocol_version: WORKER_PROTOCOL_VERSION, run_id: Some(run_id.clone()), error }).await?,
                }
            }
        }
    }
}

fn decode_command(message: Message) -> Result<WorkerCommand, RuntimeError> {
    match message {
        Message::Text(payload) => serde_json::from_str(&payload).map_err(protocol_error),
        Message::Binary(payload) => serde_json::from_slice(&payload).map_err(protocol_error),
        _ => Err(protocol_error("expected a JSON Worker command")),
    }
}

async fn send_frame<S>(sink: &mut S, frame: WorkerFrame) -> Result<(), RuntimeError>
where
    S: futures_util::Sink<Message, Error = WebSocketError> + Unpin,
{
    let payload = serde_json::to_string(&frame).map_err(protocol_error)?;
    sink.send(Message::Text(payload))
        .await
        .map_err(connection_error)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |diff, (left, right)| diff | (left ^ right))
        == 0
}

fn configuration_error(error: impl std::fmt::Display) -> RuntimeError {
    RuntimeError {
        code: RuntimeErrorCode::Configuration,
        message: error.to_string(),
        retryable: false,
    }
}

fn protocol_error(error: impl std::fmt::Display) -> RuntimeError {
    RuntimeError {
        code: RuntimeErrorCode::InvalidRequest,
        message: error.to_string(),
        retryable: false,
    }
}

fn connection_error(error: impl std::fmt::Display) -> RuntimeError {
    RuntimeError {
        code: RuntimeErrorCode::Unavailable,
        message: error.to_string(),
        retryable: true,
    }
}

#[cfg(test)]
mod tests {
    use microclaw_core::run_protocol::{
        AgentProfile, RunRequest, RuntimeCapabilities, SessionId, WorkerHealthStatus,
    };
    use microclaw_core::runtime_event::RuntimeEvent;
    use microclaw_runtime::{
        ExecutionContext, ExecutionResult, LocalWorker, RemoteWorker, RunExecutor, Runtime,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    struct Echo;

    #[async_trait]
    impl RunExecutor for Echo {
        async fn execute(
            &self,
            _profile: AgentProfile,
            request: RunRequest,
            context: ExecutionContext,
        ) -> Result<ExecutionResult, RuntimeError> {
            context.emit(RuntimeEvent::TextDelta {
                delta: "from worker".into(),
            })?;
            Ok(ExecutionResult::new(
                request
                    .session_id
                    .unwrap_or_else(|| SessionId::new("remote-session")),
                request.prompt,
            ))
        }

        fn capabilities(&self) -> RuntimeCapabilities {
            RuntimeCapabilities {
                streaming: true,
                cancellation: true,
                remote_workers: true,
                ..RuntimeCapabilities::default()
            }
        }
    }

    struct CountingEcho(Arc<AtomicUsize>);

    #[async_trait]
    impl RunExecutor for CountingEcho {
        async fn execute(
            &self,
            _profile: AgentProfile,
            request: RunRequest,
            context: ExecutionContext,
        ) -> Result<ExecutionResult, RuntimeError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
            context.emit(RuntimeEvent::TextDelta {
                delta: "persisted".into(),
            })?;
            Ok(ExecutionResult::new(
                SessionId::new("resumed-session"),
                request.prompt,
            ))
        }
    }

    async fn start_host(token: &str) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let runtime = Runtime::builder().executor(Echo).build().unwrap();
        let worker = LocalWorker::new(runtime, "worker-1", "Test worker");
        let host = WorkerHost::new(worker).bearer_token(token);
        let task = tokio::spawn(async move {
            let _ = host.serve(listener).await;
        });
        (format!("ws://{address}"), task)
    }

    #[tokio::test]
    async fn authenticated_websocket_worker_runs_and_reports_health() {
        let (url, host) = start_host("secret").await;
        let transport = WebSocketWorkerTransport::new(url).bearer_token("secret");
        let worker = RemoteWorker::connect(transport).await.unwrap();
        assert_eq!(worker.descriptor().name, "Test worker");

        let health = worker.refresh_health().await.unwrap();
        assert_eq!(health.status, WorkerHealthStatus::Ready);
        let mut run = worker
            .submit(AgentProfile::default(), RunRequest::new("hello remote"))
            .await
            .unwrap();
        assert!(matches!(
            run.next_event().await.unwrap().event,
            RuntimeEvent::TextDelta { .. }
        ));
        assert!(matches!(
            run.next_event().await.unwrap().event,
            RuntimeEvent::FinalResponse { .. }
        ));
        assert_eq!(run.result().await.unwrap().final_text, "hello remote");
        host.abort();
    }

    #[tokio::test]
    async fn websocket_worker_rejects_invalid_credentials() {
        let (url, host) = start_host("secret").await;
        let transport = WebSocketWorkerTransport::new(url).bearer_token("wrong");
        let error = match RemoteWorker::connect(transport).await {
            Ok(_) => panic!("invalid Worker credentials should fail"),
            Err(error) => error,
        };
        assert_eq!(error.code, RuntimeErrorCode::Unavailable);
        host.abort();
    }

    #[tokio::test]
    async fn websocket_worker_keeps_run_alive_and_resumes_after_disconnect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let executions = Arc::new(AtomicUsize::new(0));
        let runtime = Runtime::builder()
            .executor(CountingEcho(executions.clone()))
            .build()
            .unwrap();
        let host = WorkerHost::new(LocalWorker::new(runtime, "worker-1", "Test worker"));
        let host_task = tokio::spawn(async move {
            let _ = host.serve(listener).await;
        });
        let transport = WebSocketWorkerTransport::new(format!("ws://{address}"));
        let run_id = microclaw_core::run_protocol::RunId::new("durable-run");
        let mut first = transport.connect().await.unwrap();
        let mut request = RunRequest::new("survive disconnect");
        request.run_id = Some(run_id.clone());
        first
            .send(WorkerCommand::Submit {
                protocol_version: WORKER_PROTOCOL_VERSION,
                profile: AgentProfile::default(),
                request: Box::new(request),
            })
            .await
            .unwrap();
        assert!(matches!(
            first.receive().await.unwrap(),
            Some(WorkerFrame::Accepted { .. })
        ));
        drop(first);

        tokio::time::sleep(std::time::Duration::from_millis(60)).await;
        let mut resumed = transport.connect().await.unwrap();
        resumed
            .send(WorkerCommand::ResumeEvents {
                protocol_version: WORKER_PROTOCOL_VERSION,
                run_id: run_id.clone(),
                after_sequence: None,
            })
            .await
            .unwrap();
        let result = loop {
            match resumed.receive().await.unwrap() {
                Some(WorkerFrame::Event { .. }) => {}
                Some(WorkerFrame::Result { result, .. }) => break result,
                frame => panic!("unexpected resumed frame: {frame:?}"),
            }
        };
        assert_eq!(result.run_id, run_id);
        assert_eq!(executions.load(Ordering::SeqCst), 1);
        host_task.abort();
    }
}
