use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use microclaw_core::run_protocol::{
    AgentProfile, RunRequest, RunStatus, RuntimeCapabilities, RuntimeControl, RuntimeError,
    RuntimeErrorCode, WorkerCommand, WorkerDescriptor, WorkerFrame, WorkerHealth,
    WorkerHealthStatus, WORKER_PROTOCOL_VERSION,
};

use crate::internal::runtime::{
    ControlRequest, ExecutionContext, ExecutionResult, RunExecutor, RunHandle, Runtime, Worker,
};

/// One ordered, bidirectional connection to a remote Worker endpoint.
#[async_trait]
pub trait WorkerConnection: Send {
    async fn send(&mut self, command: WorkerCommand) -> Result<(), RuntimeError>;
    async fn receive(&mut self) -> Result<Option<WorkerFrame>, RuntimeError>;
}

/// Creates independent remote Worker connections for discovery, health, and runs.
#[async_trait]
pub trait WorkerTransport: Send + Sync + 'static {
    async fn connect(&self) -> Result<Box<dyn WorkerConnection>, RuntimeError>;
}

struct RemoteExecutor {
    transport: Arc<dyn WorkerTransport>,
    capabilities: RuntimeCapabilities,
    reconnect: RemoteWorkerOptions,
}

/// Reconnection policy for remote Worker runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoteWorkerOptions {
    pub max_reconnect_attempts: u8,
    pub reconnect_backoff: Duration,
}

impl Default for RemoteWorkerOptions {
    fn default() -> Self {
        Self {
            max_reconnect_attempts: 3,
            reconnect_backoff: Duration::from_millis(250),
        }
    }
}

impl RemoteWorkerOptions {
    pub fn max_reconnect_attempts(mut self, attempts: u8) -> Self {
        self.max_reconnect_attempts = attempts;
        self
    }

    pub fn reconnect_backoff(mut self, backoff: Duration) -> Self {
        self.reconnect_backoff = backoff;
        self
    }
}

#[async_trait]
impl RunExecutor for RemoteExecutor {
    async fn execute(
        &self,
        profile: AgentProfile,
        mut request: RunRequest,
        mut context: ExecutionContext,
    ) -> Result<ExecutionResult, RuntimeError> {
        let run_id = context.run_id().clone();
        request.run_id = Some(run_id.clone());
        let mut connection = self.transport.connect().await?;
        connection
            .send(WorkerCommand::Submit {
                protocol_version: WORKER_PROTOCOL_VERSION,
                profile,
                request: Box::new(request),
            })
            .await?;

        let mut controls_open = true;
        let mut pending_control: Option<ControlRequest> = None;
        let mut last_remote_sequence = None;
        let mut reconnect_attempts = 0_u8;
        loop {
            tokio::select! {
                frame = connection.receive() => {
                    let frame = match frame {
                        Ok(Some(frame)) => {
                            reconnect_attempts = 0;
                            frame
                        }
                        Ok(None) | Err(_) if reconnect_attempts < self.reconnect.max_reconnect_attempts => {
                            loop {
                                reconnect_attempts += 1;
                                if !self.reconnect.reconnect_backoff.is_zero() {
                                    tokio::time::sleep(
                                        self.reconnect.reconnect_backoff
                                            * u32::from(reconnect_attempts),
                                    )
                                    .await;
                                }
                                let resumed = async {
                                    let mut next = self.transport.connect().await?;
                                    next.send(WorkerCommand::ResumeEvents {
                                        protocol_version: WORKER_PROTOCOL_VERSION,
                                        run_id: run_id.clone(),
                                        after_sequence: last_remote_sequence,
                                    })
                                    .await?;
                                    if let Some(control) = pending_control.as_ref() {
                                        next.send(WorkerCommand::Control {
                                            protocol_version: WORKER_PROTOCOL_VERSION,
                                            control: control.control().clone(),
                                        })
                                        .await?;
                                    }
                                    Ok::<_, RuntimeError>(next)
                                }
                                .await;
                                match resumed {
                                    Ok(next) => {
                                        connection = next;
                                        break;
                                    }
                                    Err(_) if reconnect_attempts < self.reconnect.max_reconnect_attempts => continue,
                                    Err(error) => return Err(error),
                                }
                            }
                            continue;
                        }
                        Ok(None) => return Err(unavailable("remote Worker disconnected before returning a result")),
                        Err(error) => return Err(error),
                    };
                    frame.validate_protocol()?;
                    match frame {
                        WorkerFrame::Accepted { run_id: accepted, .. } => {
                            ensure_run_id(&run_id, &accepted)?;
                        }
                        WorkerFrame::Event { envelope, .. } => {
                            if envelope.run_id != run_id.as_str() {
                                return Err(protocol_error("remote Worker returned an event for a different run"));
                            }
                            if last_remote_sequence.is_some_and(|sequence| envelope.sequence <= sequence) {
                                continue;
                            }
                            last_remote_sequence = Some(envelope.sequence);
                            if !matches!(
                                envelope.event,
                                microclaw_core::runtime_event::RuntimeEvent::FinalResponse { .. }
                                    | microclaw_core::runtime_event::RuntimeEvent::Cancelled { .. }
                            ) {
                                context.emit(envelope.event)?;
                            }
                        }
                        WorkerFrame::ControlAcknowledged { run_id: acknowledged, .. } => {
                            ensure_run_id(&run_id, &acknowledged)?;
                            if let Some(control) = pending_control.take() {
                                control.accept();
                            }
                        }
                        WorkerFrame::Result { result, .. } => {
                            ensure_run_id(&run_id, &result.run_id)?;
                            if let Some(control) = pending_control.take() {
                                control.reject(unavailable("run completed before control acknowledgement"));
                            }
                            return if result.status == RunStatus::Completed {
                                Ok(ExecutionResult {
                                    session_id: result.session_id,
                                    final_text: result.final_text,
                                    metadata: result.metadata,
                                })
                            } else {
                                Err(result.error.unwrap_or(RuntimeError {
                                    code: RuntimeErrorCode::Internal,
                                    message: format!("remote Worker ended with status {:?}", result.status),
                                    retryable: false,
                                }))
                            };
                        }
                        WorkerFrame::Error { run_id: frame_run_id, error, .. } => {
                            if let Some(frame_run_id) = frame_run_id.as_ref() {
                                ensure_run_id(&run_id, frame_run_id)?;
                            }
                            if let Some(control) = pending_control.take() {
                                control.reject(error);
                            } else {
                                return Err(error);
                            }
                        }
                        WorkerFrame::Descriptor { .. } | WorkerFrame::Health { .. } => {}
                    }
                }
                control = context.next_control_request(), if controls_open && pending_control.is_none() => {
                    match control {
                        Some(control) => {
                            let command = control.control().clone();
                            ensure_control_run_id(&run_id, &command)?;
                            connection.send(WorkerCommand::Control {
                                protocol_version: WORKER_PROTOCOL_VERSION,
                                control: command,
                            }).await?;
                            pending_control = Some(control);
                        }
                        None => controls_open = false,
                    }
                }
            }
        }
    }

    fn capabilities(&self) -> RuntimeCapabilities {
        self.capabilities.clone()
    }
}

/// A Worker backed by a versioned remote transport.
#[derive(Clone)]
pub struct RemoteWorker {
    descriptor: WorkerDescriptor,
    runtime: Runtime,
    transport: Arc<dyn WorkerTransport>,
    health: Arc<Mutex<WorkerHealth>>,
}

impl RemoteWorker {
    pub async fn connect(transport: impl WorkerTransport) -> Result<Self, RuntimeError> {
        Self::connect_with_options(transport, RemoteWorkerOptions::default()).await
    }

    pub async fn connect_with_options(
        transport: impl WorkerTransport,
        reconnect: RemoteWorkerOptions,
    ) -> Result<Self, RuntimeError> {
        let transport: Arc<dyn WorkerTransport> = Arc::new(transport);
        let mut connection = transport.connect().await?;
        connection
            .send(WorkerCommand::Describe {
                protocol_version: WORKER_PROTOCOL_VERSION,
            })
            .await?;
        let frame = connection
            .receive()
            .await?
            .ok_or_else(|| unavailable("remote Worker disconnected during discovery"))?;
        frame.validate_protocol()?;
        let WorkerFrame::Descriptor { descriptor, .. } = frame else {
            return Err(protocol_error(
                "remote Worker did not return a descriptor during discovery",
            ));
        };
        let health = WorkerHealth {
            worker_id: descriptor.id.clone(),
            status: WorkerHealthStatus::Ready,
            active_runs: 0,
            queued_runs: 0,
            observed_at: String::new(),
        };
        let runtime = Runtime::builder()
            .shared_executor(Arc::new(RemoteExecutor {
                transport: transport.clone(),
                capabilities: descriptor.capabilities.clone(),
                reconnect,
            }))
            .max_concurrent_runs(descriptor.max_concurrent_runs.max(1))
            .build()
            .map_err(|error| RuntimeError {
                code: RuntimeErrorCode::Configuration,
                message: error.to_string(),
                retryable: false,
            })?;
        Ok(Self {
            descriptor,
            runtime,
            transport,
            health: Arc::new(Mutex::new(health)),
        })
    }

    pub async fn refresh_health(&self) -> Result<WorkerHealth, RuntimeError> {
        let mut connection = self.transport.connect().await?;
        connection
            .send(WorkerCommand::Health {
                protocol_version: WORKER_PROTOCOL_VERSION,
            })
            .await?;
        let frame = connection
            .receive()
            .await?
            .ok_or_else(|| unavailable("remote Worker disconnected during health check"))?;
        frame.validate_protocol()?;
        let WorkerFrame::Health { health, .. } = frame else {
            return Err(protocol_error(
                "remote Worker did not return health during health check",
            ));
        };
        if health.worker_id != self.descriptor.id {
            return Err(protocol_error("remote Worker health identity changed"));
        }
        *self
            .health
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = health.clone();
        Ok(health)
    }
}

#[async_trait]
impl Worker for RemoteWorker {
    fn descriptor(&self) -> WorkerDescriptor {
        self.descriptor.clone()
    }

    fn health(&self) -> WorkerHealth {
        self.health
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }

    async fn submit(
        &self,
        profile: AgentProfile,
        request: RunRequest,
    ) -> Result<RunHandle, RuntimeError> {
        if matches!(
            self.health().status,
            WorkerHealthStatus::Draining | WorkerHealthStatus::Unavailable
        ) {
            return Err(unavailable("remote Worker is not accepting new runs"));
        }
        Ok(self.runtime.agent(profile).run(request))
    }
}

fn ensure_run_id(
    expected: &microclaw_core::run_protocol::RunId,
    actual: &microclaw_core::run_protocol::RunId,
) -> Result<(), RuntimeError> {
    if expected == actual {
        Ok(())
    } else {
        Err(protocol_error(
            "remote Worker returned a frame for a different run",
        ))
    }
}

fn ensure_control_run_id(
    expected: &microclaw_core::run_protocol::RunId,
    control: &RuntimeControl,
) -> Result<(), RuntimeError> {
    let actual = match control {
        RuntimeControl::Cancel { run_id }
        | RuntimeControl::Steer { run_id, .. }
        | RuntimeControl::ResolveApproval { run_id, .. } => run_id,
    };
    ensure_run_id(expected, actual)
}

fn protocol_error(message: impl Into<String>) -> RuntimeError {
    RuntimeError {
        code: RuntimeErrorCode::InvalidRequest,
        message: message.into(),
        retryable: false,
    }
}

fn unavailable(message: impl Into<String>) -> RuntimeError {
    RuntimeError {
        code: RuntimeErrorCode::Unavailable,
        message: message.into(),
        retryable: true,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, VecDeque};

    use microclaw_core::run_protocol::{RunId, RunResult, SessionId, WorkerId};
    use microclaw_core::runtime_event::{RuntimeEvent, RuntimeEventEnvelope};

    use super::*;

    #[derive(Clone)]
    struct ScriptedTransport {
        connections: Arc<Mutex<VecDeque<VecDeque<WorkerFrame>>>>,
        sent: Arc<Mutex<Vec<WorkerCommand>>>,
    }

    struct ScriptedConnection {
        frames: VecDeque<WorkerFrame>,
        sent: Arc<Mutex<Vec<WorkerCommand>>>,
    }

    #[async_trait]
    impl WorkerTransport for ScriptedTransport {
        async fn connect(&self) -> Result<Box<dyn WorkerConnection>, RuntimeError> {
            let frames = self
                .connections
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| unavailable("missing scripted connection"))?;
            Ok(Box::new(ScriptedConnection {
                frames,
                sent: self.sent.clone(),
            }))
        }
    }

    #[async_trait]
    impl WorkerConnection for ScriptedConnection {
        async fn send(&mut self, command: WorkerCommand) -> Result<(), RuntimeError> {
            self.sent.lock().unwrap().push(command);
            Ok(())
        }

        async fn receive(&mut self) -> Result<Option<WorkerFrame>, RuntimeError> {
            Ok(self.frames.pop_front())
        }
    }

    fn descriptor() -> WorkerDescriptor {
        WorkerDescriptor {
            id: WorkerId::new("remote-1"),
            name: "Remote one".into(),
            capabilities: RuntimeCapabilities {
                streaming: true,
                remote_workers: true,
                ..RuntimeCapabilities::default()
            },
            max_concurrent_runs: 2,
            labels: BTreeMap::new(),
        }
    }

    #[tokio::test]
    async fn remote_worker_discovers_streams_and_returns_result() {
        let run_id = RunId::new("remote-run");
        let transport = ScriptedTransport {
            connections: Arc::new(Mutex::new(VecDeque::from([
                VecDeque::from([WorkerFrame::Descriptor {
                    protocol_version: WORKER_PROTOCOL_VERSION,
                    descriptor: descriptor(),
                }]),
                VecDeque::from([
                    WorkerFrame::Accepted {
                        protocol_version: WORKER_PROTOCOL_VERSION,
                        run_id: run_id.clone(),
                    },
                    WorkerFrame::Event {
                        protocol_version: WORKER_PROTOCOL_VERSION,
                        envelope: RuntimeEventEnvelope::new(
                            run_id.to_string(),
                            0,
                            RuntimeEvent::TextDelta {
                                delta: "remote".into(),
                            },
                        ),
                    },
                    WorkerFrame::Result {
                        protocol_version: WORKER_PROTOCOL_VERSION,
                        result: RunResult {
                            run_id: run_id.clone(),
                            session_id: SessionId::new("remote-session"),
                            status: RunStatus::Completed,
                            final_text: "done".into(),
                            error: None,
                            metadata: BTreeMap::new(),
                        },
                    },
                ]),
            ]))),
            sent: Arc::new(Mutex::new(Vec::new())),
        };
        let worker = RemoteWorker::connect(transport).await.unwrap();
        assert_eq!(worker.descriptor().id, WorkerId::new("remote-1"));
        let mut request = RunRequest::new("work remotely");
        request.run_id = Some(run_id);
        let mut run = worker
            .submit(AgentProfile::default(), request)
            .await
            .unwrap();
        let event = run.next_event().await.unwrap();
        assert!(matches!(event.event, RuntimeEvent::TextDelta { .. }));
        assert!(matches!(
            run.next_event().await.unwrap().event,
            RuntimeEvent::FinalResponse { .. }
        ));
        assert_eq!(run.result().await.unwrap().final_text, "done");
    }

    #[tokio::test]
    async fn remote_worker_resumes_without_replaying_delivered_events() {
        let run_id = RunId::new("resumable-run");
        let sent = Arc::new(Mutex::new(Vec::new()));
        let result = WorkerFrame::Result {
            protocol_version: WORKER_PROTOCOL_VERSION,
            result: RunResult {
                run_id: run_id.clone(),
                session_id: SessionId::new("resumed-session"),
                status: RunStatus::Completed,
                final_text: "resumed".into(),
                error: None,
                metadata: BTreeMap::new(),
            },
        };
        let event = |sequence, delta: &str| WorkerFrame::Event {
            protocol_version: WORKER_PROTOCOL_VERSION,
            envelope: RuntimeEventEnvelope::new(
                run_id.to_string(),
                sequence,
                RuntimeEvent::TextDelta {
                    delta: delta.into(),
                },
            ),
        };
        let transport = ScriptedTransport {
            connections: Arc::new(Mutex::new(VecDeque::from([
                VecDeque::from([WorkerFrame::Descriptor {
                    protocol_version: WORKER_PROTOCOL_VERSION,
                    descriptor: descriptor(),
                }]),
                VecDeque::from([
                    WorkerFrame::Accepted {
                        protocol_version: WORKER_PROTOCOL_VERSION,
                        run_id: run_id.clone(),
                    },
                    event(0, "first"),
                ]),
                VecDeque::from([event(0, "duplicate"), event(1, "second"), result]),
            ]))),
            sent: sent.clone(),
        };
        let worker = RemoteWorker::connect(transport).await.unwrap();
        let mut request = RunRequest::new("resume remotely");
        request.run_id = Some(run_id.clone());
        let mut run = worker
            .submit(AgentProfile::default(), request)
            .await
            .unwrap();

        let mut deltas = Vec::new();
        while let Some(envelope) = run.next_event().await {
            if let RuntimeEvent::TextDelta { delta } = envelope.event {
                deltas.push(delta);
            }
        }
        assert_eq!(deltas, ["first", "second"]);
        assert_eq!(run.result().await.unwrap().final_text, "resumed");
        assert!(sent.lock().unwrap().iter().any(|command| matches!(
            command,
            WorkerCommand::ResumeEvents {
                run_id: resumed,
                after_sequence: Some(0),
                ..
            } if resumed == &run_id
        )));
    }

    #[tokio::test]
    async fn remote_worker_reconnect_policy_can_fail_fast() {
        let run_id = RunId::new("fail-fast-run");
        let transport = ScriptedTransport {
            connections: Arc::new(Mutex::new(VecDeque::from([
                VecDeque::from([WorkerFrame::Descriptor {
                    protocol_version: WORKER_PROTOCOL_VERSION,
                    descriptor: descriptor(),
                }]),
                VecDeque::from([WorkerFrame::Accepted {
                    protocol_version: WORKER_PROTOCOL_VERSION,
                    run_id: run_id.clone(),
                }]),
            ]))),
            sent: Arc::new(Mutex::new(Vec::new())),
        };
        let worker = RemoteWorker::connect_with_options(
            transport,
            RemoteWorkerOptions::default()
                .max_reconnect_attempts(0)
                .reconnect_backoff(Duration::ZERO),
        )
        .await
        .unwrap();
        let mut request = RunRequest::new("do not reconnect");
        request.run_id = Some(run_id);
        let run = worker
            .submit(AgentProfile::default(), request)
            .await
            .unwrap();
        let result = run.result().await.unwrap();
        assert_eq!(result.status, RunStatus::Failed);
        let error = result.error.unwrap();
        assert_eq!(error.code, RuntimeErrorCode::Unavailable);
        assert!(error.retryable);
    }
}
