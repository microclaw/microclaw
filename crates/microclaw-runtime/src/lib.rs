//! Embeddable, UI-independent MicroClaw run lifecycle.
//!
//! Product adapters supply a [`RunExecutor`]. The runtime owns stable Agent and Run handles,
//! concurrency, control routing, terminal results, and the provider-neutral event stream.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use microclaw_core::run_protocol::{
    AgentProfile, RunId, RunRequest, RunResult, RunStatus, RuntimeCapabilities, RuntimeControl,
    RuntimeError, RuntimeErrorCode, SessionId, WorkerDescriptor, WorkerHealth, WorkerHealthStatus,
    WorkerId,
};
use microclaw_core::runtime_event::{RuntimeEvent, RuntimeEventEnvelope};
use tokio::sync::{mpsc, oneshot, Semaphore};

#[derive(Debug, Clone, PartialEq)]
pub struct ExecutionResult {
    pub session_id: SessionId,
    pub final_text: String,
    pub metadata: BTreeMap<String, serde_json::Value>,
}

impl ExecutionResult {
    pub fn new(session_id: impl Into<SessionId>, final_text: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            final_text: final_text.into(),
            metadata: BTreeMap::new(),
        }
    }
}

/// Runtime-owned context passed to an execution engine for one run.
pub struct ExecutionContext {
    run_id: RunId,
    event_tx: mpsc::UnboundedSender<RuntimeEventEnvelope>,
    control_rx: mpsc::UnboundedReceiver<RuntimeControl>,
    next_sequence: Arc<AtomicU64>,
}

impl ExecutionContext {
    pub fn run_id(&self) -> &RunId {
        &self.run_id
    }

    pub fn emit(&self, event: RuntimeEvent) -> Result<(), RuntimeError> {
        let sequence = self.next_sequence.fetch_add(1, Ordering::Relaxed);
        self.event_tx
            .send(RuntimeEventEnvelope::new(
                self.run_id.to_string(),
                sequence,
                event,
            ))
            .map_err(|_| RuntimeError {
                code: RuntimeErrorCode::Unavailable,
                message: "runtime event consumer disconnected".into(),
                retryable: false,
            })
    }

    pub fn try_next_control(&mut self) -> Option<RuntimeControl> {
        self.control_rx.try_recv().ok()
    }

    pub async fn next_control(&mut self) -> Option<RuntimeControl> {
        self.control_rx.recv().await
    }
}

/// Product-independent execution port used by the Runtime.
///
/// MicroClaw's shared Agent Engine implements this port. Tests and embedding applications may
/// provide another implementation without depending on Server or UI code.
#[async_trait]
pub trait RunExecutor: Send + Sync + 'static {
    async fn execute(
        &self,
        profile: AgentProfile,
        request: RunRequest,
        context: ExecutionContext,
    ) -> Result<ExecutionResult, RuntimeError>;

    fn capabilities(&self) -> RuntimeCapabilities {
        RuntimeCapabilities::default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeBuildError {
    MissingExecutor,
    InvalidConcurrency,
}

impl std::fmt::Display for RuntimeBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingExecutor => f.write_str("a run executor is required"),
            Self::InvalidConcurrency => f.write_str("max concurrent runs must be greater than 0"),
        }
    }
}

impl std::error::Error for RuntimeBuildError {}

pub struct RuntimeBuilder {
    executor: Option<Arc<dyn RunExecutor>>,
    max_concurrent_runs: usize,
}

impl Default for RuntimeBuilder {
    fn default() -> Self {
        Self {
            executor: None,
            max_concurrent_runs: 4,
        }
    }
}

impl RuntimeBuilder {
    pub fn executor(mut self, executor: impl RunExecutor) -> Self {
        self.executor = Some(Arc::new(executor));
        self
    }

    pub fn shared_executor(mut self, executor: Arc<dyn RunExecutor>) -> Self {
        self.executor = Some(executor);
        self
    }

    pub fn max_concurrent_runs(mut self, max: usize) -> Self {
        self.max_concurrent_runs = max;
        self
    }

    pub fn build(self) -> Result<Runtime, RuntimeBuildError> {
        if self.max_concurrent_runs == 0 {
            return Err(RuntimeBuildError::InvalidConcurrency);
        }
        let executor = self.executor.ok_or(RuntimeBuildError::MissingExecutor)?;
        Ok(Runtime {
            inner: Arc::new(RuntimeInner {
                executor,
                permits: Arc::new(Semaphore::new(self.max_concurrent_runs)),
            }),
        })
    }
}

struct RuntimeInner {
    executor: Arc<dyn RunExecutor>,
    permits: Arc<Semaphore>,
}

#[derive(Clone)]
pub struct Runtime {
    inner: Arc<RuntimeInner>,
}

impl Runtime {
    pub fn builder() -> RuntimeBuilder {
        RuntimeBuilder::default()
    }

    pub fn agent(&self, profile: AgentProfile) -> AgentHandle {
        AgentHandle {
            runtime: self.clone(),
            profile,
        }
    }

    pub fn capabilities(&self) -> RuntimeCapabilities {
        self.inner.executor.capabilities()
    }
}

#[derive(Clone)]
pub struct AgentHandle {
    runtime: Runtime,
    profile: AgentProfile,
}

impl AgentHandle {
    pub fn profile(&self) -> &AgentProfile {
        &self.profile
    }

    pub fn run(&self, request: RunRequest) -> RunHandle {
        let run_id = request
            .run_id
            .clone()
            .unwrap_or_else(|| RunId::new(uuid::Uuid::new_v4().to_string()));
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (control_tx, control_rx) = mpsc::unbounded_channel();
        let (result_tx, result_rx) = oneshot::channel();
        let next_sequence = Arc::new(AtomicU64::new(0));
        let executor = self.runtime.inner.executor.clone();
        let permits = self.runtime.inner.permits.clone();
        let profile = self.profile.clone();
        let task_run_id = run_id.clone();
        let fallback_session_id = request
            .session_id
            .clone()
            .unwrap_or_else(|| SessionId::new(task_run_id.to_string()));

        tokio::spawn(async move {
            let permit = match permits.acquire_owned().await {
                Ok(permit) => permit,
                Err(_) => {
                    let _ = result_tx.send(RunResult {
                        run_id: task_run_id,
                        session_id: fallback_session_id,
                        status: RunStatus::Failed,
                        final_text: String::new(),
                        error: Some(RuntimeError {
                            code: RuntimeErrorCode::Unavailable,
                            message: "runtime is shutting down".into(),
                            retryable: true,
                        }),
                        metadata: BTreeMap::new(),
                    });
                    return;
                }
            };
            let context = ExecutionContext {
                run_id: task_run_id.clone(),
                event_tx: event_tx.clone(),
                control_rx,
                next_sequence: next_sequence.clone(),
            };
            let result = executor.execute(profile, request, context).await;
            drop(permit);

            let terminal = match result {
                Ok(output) => {
                    emit_terminal_event(
                        &event_tx,
                        &next_sequence,
                        &task_run_id,
                        RuntimeEvent::FinalResponse {
                            text: output.final_text.clone(),
                        },
                    );
                    RunResult {
                        run_id: task_run_id,
                        session_id: output.session_id,
                        status: RunStatus::Completed,
                        final_text: output.final_text,
                        error: None,
                        metadata: output.metadata,
                    }
                }
                Err(error) => {
                    let status = match error.code {
                        RuntimeErrorCode::Cancelled => RunStatus::Cancelled,
                        RuntimeErrorCode::TimedOut => RunStatus::TimedOut,
                        _ => RunStatus::Failed,
                    };
                    if status == RunStatus::Cancelled {
                        emit_terminal_event(
                            &event_tx,
                            &next_sequence,
                            &task_run_id,
                            RuntimeEvent::Cancelled {
                                final_text: error.message.clone(),
                            },
                        );
                    }
                    RunResult {
                        run_id: task_run_id,
                        session_id: fallback_session_id,
                        status,
                        final_text: String::new(),
                        error: Some(error),
                        metadata: BTreeMap::new(),
                    }
                }
            };
            let _ = result_tx.send(terminal);
        });

        RunHandle {
            run_id,
            events: event_rx,
            control_tx,
            result_rx,
        }
    }
}

fn emit_terminal_event(
    event_tx: &mpsc::UnboundedSender<RuntimeEventEnvelope>,
    next_sequence: &AtomicU64,
    run_id: &RunId,
    event: RuntimeEvent,
) {
    let sequence = next_sequence.fetch_add(1, Ordering::Relaxed);
    let _ = event_tx.send(RuntimeEventEnvelope::new(
        run_id.to_string(),
        sequence,
        event,
    ));
}

pub struct RunHandle {
    run_id: RunId,
    events: mpsc::UnboundedReceiver<RuntimeEventEnvelope>,
    control_tx: mpsc::UnboundedSender<RuntimeControl>,
    result_rx: oneshot::Receiver<RunResult>,
}

impl RunHandle {
    pub fn id(&self) -> &RunId {
        &self.run_id
    }

    pub async fn next_event(&mut self) -> Option<RuntimeEventEnvelope> {
        self.events.recv().await
    }

    pub fn try_next_event(&mut self) -> Option<RuntimeEventEnvelope> {
        self.events.try_recv().ok()
    }

    pub fn cancel(&self) -> Result<(), RuntimeError> {
        self.send_control(RuntimeControl::Cancel {
            run_id: self.run_id.clone(),
        })
    }

    pub fn steer(&self, message: impl Into<String>) -> Result<(), RuntimeError> {
        self.send_control(RuntimeControl::Steer {
            run_id: self.run_id.clone(),
            message: message.into(),
        })
    }

    pub fn resolve_approval(
        &self,
        approval_id: impl Into<String>,
        decision: impl Into<String>,
    ) -> Result<(), RuntimeError> {
        self.send_control(RuntimeControl::ResolveApproval {
            run_id: self.run_id.clone(),
            approval_id: approval_id.into(),
            decision: decision.into(),
        })
    }

    fn send_control(&self, control: RuntimeControl) -> Result<(), RuntimeError> {
        self.control_tx.send(control).map_err(|_| RuntimeError {
            code: RuntimeErrorCode::Unavailable,
            message: "run is no longer accepting control messages".into(),
            retryable: false,
        })
    }

    pub async fn result(self) -> Result<RunResult, RuntimeError> {
        self.result_rx.await.map_err(|_| RuntimeError {
            code: RuntimeErrorCode::Internal,
            message: "run ended without a terminal result".into(),
            retryable: false,
        })
    }
}

#[async_trait]
pub trait Worker: Send + Sync {
    fn descriptor(&self) -> WorkerDescriptor;
    fn health(&self) -> WorkerHealth;
    async fn submit(&self, profile: AgentProfile, request: RunRequest) -> RunHandle;
}

#[derive(Clone)]
pub struct LocalWorker {
    descriptor: WorkerDescriptor,
    runtime: Runtime,
}

impl LocalWorker {
    pub fn new(
        runtime: Runtime,
        id: impl Into<WorkerId>,
        name: impl Into<String>,
        max_concurrent_runs: usize,
    ) -> Self {
        Self {
            descriptor: WorkerDescriptor {
                id: id.into(),
                name: name.into(),
                capabilities: runtime.capabilities(),
                max_concurrent_runs,
                labels: BTreeMap::new(),
            },
            runtime,
        }
    }
}

#[async_trait]
impl Worker for LocalWorker {
    fn descriptor(&self) -> WorkerDescriptor {
        self.descriptor.clone()
    }

    fn health(&self) -> WorkerHealth {
        WorkerHealth {
            worker_id: self.descriptor.id.clone(),
            status: WorkerHealthStatus::Ready,
            active_runs: 0,
            observed_at: String::new(),
        }
    }

    async fn submit(&self, profile: AgentProfile, request: RunRequest) -> RunHandle {
        self.runtime.agent(profile).run(request)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use super::*;

    struct EchoExecutor;

    #[async_trait]
    impl RunExecutor for EchoExecutor {
        async fn execute(
            &self,
            profile: AgentProfile,
            request: RunRequest,
            context: ExecutionContext,
        ) -> Result<ExecutionResult, RuntimeError> {
            context.emit(RuntimeEvent::TextDelta {
                delta: format!("{}: ", profile.name),
            })?;
            Ok(ExecutionResult::new(
                request
                    .session_id
                    .clone()
                    .unwrap_or_else(|| SessionId::new("default")),
                request.prompt,
            ))
        }

        fn capabilities(&self) -> RuntimeCapabilities {
            RuntimeCapabilities {
                streaming: true,
                cancellation: true,
                steering: true,
                approvals: true,
                skills: false,
                subagents: false,
                remote_workers: false,
            }
        }
    }

    #[tokio::test]
    async fn runtime_streams_events_and_returns_a_result() {
        let runtime = Runtime::builder().executor(EchoExecutor).build().unwrap();
        let agent = runtime.agent(AgentProfile {
            name: "coder".into(),
            ..AgentProfile::default()
        });
        let mut request = RunRequest::new("hello");
        request.session_id = Some(SessionId::new("session-1"));
        let mut run = agent.run(request);
        let run_id = run.id().clone();

        let delta = run.next_event().await.unwrap();
        assert_eq!(delta.run_id, run_id.as_str());
        assert_eq!(delta.sequence, 0);
        assert!(matches!(delta.event, RuntimeEvent::TextDelta { .. }));
        let final_event = run.next_event().await.unwrap();
        assert_eq!(final_event.sequence, 1);
        assert!(matches!(
            final_event.event,
            RuntimeEvent::FinalResponse { ref text } if text == "hello"
        ));

        let result = run.result().await.unwrap();
        assert_eq!(result.status, RunStatus::Completed);
        assert_eq!(result.session_id, SessionId::new("session-1"));
        assert_eq!(result.final_text, "hello");
    }

    struct ControlledExecutor;

    #[async_trait]
    impl RunExecutor for ControlledExecutor {
        async fn execute(
            &self,
            _profile: AgentProfile,
            _request: RunRequest,
            mut context: ExecutionContext,
        ) -> Result<ExecutionResult, RuntimeError> {
            match context.next_control().await {
                Some(RuntimeControl::Cancel { .. }) => Err(RuntimeError {
                    code: RuntimeErrorCode::Cancelled,
                    message: "cancelled by caller".into(),
                    retryable: false,
                }),
                Some(RuntimeControl::Steer { message, .. }) => {
                    Ok(ExecutionResult::new("steered", message))
                }
                Some(RuntimeControl::ResolveApproval { decision, .. }) => {
                    Ok(ExecutionResult::new("approved", decision))
                }
                None => Err(RuntimeError {
                    code: RuntimeErrorCode::Unavailable,
                    message: "control channel closed".into(),
                    retryable: false,
                }),
            }
        }
    }

    #[tokio::test]
    async fn run_handle_routes_cancellation() {
        let runtime = Runtime::builder()
            .executor(ControlledExecutor)
            .build()
            .unwrap();
        let run = runtime
            .agent(AgentProfile::default())
            .run(RunRequest::new("wait"));
        run.cancel().unwrap();
        let result = run.result().await.unwrap();
        assert_eq!(result.status, RunStatus::Cancelled);
        assert_eq!(result.error.unwrap().code, RuntimeErrorCode::Cancelled);
    }

    #[tokio::test]
    async fn run_handle_routes_steering() {
        let runtime = Runtime::builder()
            .executor(ControlledExecutor)
            .build()
            .unwrap();
        let run = runtime
            .agent(AgentProfile::default())
            .run(RunRequest::new("wait"));
        run.steer("new direction").unwrap();
        let result = run.result().await.unwrap();
        assert_eq!(result.final_text, "new direction");
    }

    struct ConcurrentExecutor {
        active: Arc<AtomicUsize>,
        peak: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl RunExecutor for ConcurrentExecutor {
        async fn execute(
            &self,
            _profile: AgentProfile,
            request: RunRequest,
            _context: ExecutionContext,
        ) -> Result<ExecutionResult, RuntimeError> {
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(active, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(20)).await;
            self.active.fetch_sub(1, Ordering::SeqCst);
            Ok(ExecutionResult::new("session", request.prompt))
        }
    }

    #[tokio::test]
    async fn runtime_enforces_concurrency_limit() {
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let runtime = Runtime::builder()
            .executor(ConcurrentExecutor {
                active: active.clone(),
                peak: peak.clone(),
            })
            .max_concurrent_runs(1)
            .build()
            .unwrap();
        let agent = runtime.agent(AgentProfile::default());
        let first = agent.run(RunRequest::new("one"));
        let second = agent.run(RunRequest::new("two"));
        let (a, b) = tokio::join!(first.result(), second.result());
        assert!(a.is_ok());
        assert!(b.is_ok());
        assert_eq!(peak.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn local_worker_uses_the_same_runtime_contract() {
        let runtime = Runtime::builder().executor(EchoExecutor).build().unwrap();
        let worker = LocalWorker::new(runtime, "local", "Local worker", 4);
        let descriptor = worker.descriptor();
        assert_eq!(descriptor.id, WorkerId::new("local"));
        assert!(descriptor.capabilities.streaming);
        let run = worker
            .submit(AgentProfile::default(), RunRequest::new("worker task"))
            .await;
        assert_eq!(run.result().await.unwrap().final_text, "worker task");
    }
}
