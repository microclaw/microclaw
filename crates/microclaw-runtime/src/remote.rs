use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use microclaw_core::run_protocol::{
    AgentProfile, RunRequest, RunStatus, RuntimeCapabilities, RuntimeControl, RuntimeError,
    RuntimeErrorCode, WorkerCommand, WorkerDescriptor, WorkerFrame, WorkerHealth,
    WorkerHealthStatus, WORKER_PROTOCOL_VERSION,
};

use crate::{
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
        loop {
            tokio::select! {
                frame = connection.receive() => {
                    let Some(frame) = frame? else {
                        return Err(unavailable("remote Worker disconnected before returning a result"));
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
                            context.emit(envelope.event)?;
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
    }

    struct ScriptedConnection {
        frames: VecDeque<WorkerFrame>,
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
            Ok(Box::new(ScriptedConnection { frames }))
        }
    }

    #[async_trait]
    impl WorkerConnection for ScriptedConnection {
        async fn send(&mut self, _command: WorkerCommand) -> Result<(), RuntimeError> {
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
}
