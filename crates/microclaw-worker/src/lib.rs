//! Authenticated WebSocket transport and host for MicroClaw Workers.

use std::sync::Arc;

use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use http::header::AUTHORIZATION;
use microclaw_core::run_protocol::{
    RuntimeError, RuntimeErrorCode, WorkerCommand, WorkerFrame, WORKER_PROTOCOL_VERSION,
};
use microclaw_runtime::{Worker, WorkerConnection, WorkerTransport};
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
}

impl WorkerHost {
    pub fn new(worker: impl Worker + 'static) -> Self {
        Self {
            worker: Arc::new(worker),
            bearer_token: None,
        }
    }

    pub fn shared(worker: Arc<dyn Worker>) -> Self {
        Self {
            worker,
            bearer_token: None,
        }
    }

    pub fn bearer_token(mut self, token: impl Into<String>) -> Self {
        self.bearer_token = Some(token.into());
        self
    }

    /// Serve until the listener is closed or the task is cancelled.
    pub async fn serve(self, listener: TcpListener) -> Result<(), RuntimeError> {
        let worker = self.worker;
        let bearer_token = self.bearer_token.map(|token| format!("Bearer {token}"));
        loop {
            let (stream, _) = listener.accept().await.map_err(connection_error)?;
            let worker = worker.clone();
            let bearer_token = bearer_token.clone();
            tokio::spawn(async move {
                let _ = serve_connection(stream, worker, bearer_token).await;
            });
        }
    }
}

#[allow(clippy::result_large_err)]
async fn serve_connection(
    stream: TcpStream,
    worker: Arc<dyn Worker>,
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
                let mut run = worker.submit(profile, *request).await?;
                let controller = run.controller();
                send_frame(
                    &mut sink,
                    WorkerFrame::Accepted {
                        protocol_version: WORKER_PROTOCOL_VERSION,
                        run_id: run_id.clone(),
                    },
                )
                .await?;
                loop {
                    tokio::select! {
                        event = run.next_event() => match event {
                            Some(envelope) => send_frame(&mut sink, WorkerFrame::Event {
                                protocol_version: WORKER_PROTOCOL_VERSION,
                                envelope,
                            }).await?,
                            None => {
                                let result = run.result().await?;
                                send_frame(&mut sink, WorkerFrame::Result {
                                    protocol_version: WORKER_PROTOCOL_VERSION,
                                    result,
                                }).await?;
                                break;
                            }
                        },
                        message = stream.next() => {
                            let Some(message) = message else {
                                return Err(connection_error("Worker client disconnected"));
                            };
                            let control = decode_command(message.map_err(connection_error)?)?;
                            control.validate_protocol()?;
                            let WorkerCommand::Control { control, .. } = control else {
                                send_frame(&mut sink, WorkerFrame::Error {
                                    protocol_version: WORKER_PROTOCOL_VERSION,
                                    run_id: Some(run_id.clone()),
                                    error: protocol_error("only control commands are accepted during a run"),
                                }).await?;
                                continue;
                            };
                            let outcome = match control {
                                microclaw_core::run_protocol::RuntimeControl::Cancel { .. } => {
                                    controller.cancel_confirmed().await
                                }
                                microclaw_core::run_protocol::RuntimeControl::Steer { message, .. } => {
                                    controller.steer_confirmed(message).await
                                }
                                microclaw_core::run_protocol::RuntimeControl::ResolveApproval {
                                    approval_id, decision, ..
                                } => controller.resolve_approval_confirmed(approval_id, decision).await,
                            };
                            match outcome {
                                Ok(()) => send_frame(&mut sink, WorkerFrame::ControlAcknowledged {
                                    protocol_version: WORKER_PROTOCOL_VERSION,
                                    run_id: run_id.clone(),
                                }).await?,
                                Err(error) => send_frame(&mut sink, WorkerFrame::Error {
                                    protocol_version: WORKER_PROTOCOL_VERSION,
                                    run_id: Some(run_id.clone()),
                                    error,
                                }).await?,
                            }
                        }
                    }
                }
            }
            WorkerCommand::Control { .. } => {
                return Err(protocol_error("control command has no active run"));
            }
            WorkerCommand::ResumeEvents { .. } => {
                return Err(RuntimeError {
                    code: RuntimeErrorCode::Unavailable,
                    message: "event resume is not enabled by this Worker host".into(),
                    retryable: false,
                });
            }
        }
    }
    Ok(())
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
}
