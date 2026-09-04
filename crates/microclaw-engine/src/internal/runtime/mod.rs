//! Embeddable, UI-independent MicroClaw run lifecycle.
//!
//! Product adapters supply a [`RunExecutor`]. The runtime owns stable Agent and Run handles,
//! concurrency, control routing, terminal results, and the provider-neutral event stream.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use microclaw_core::run_protocol::{
    AgentProfile, RunId, RunRequest, RunResult, RunStatus, RuntimeCapabilities, RuntimeControl,
    RuntimeError, RuntimeErrorCode, SessionId, WorkerDescriptor, WorkerHealth, WorkerHealthStatus,
    WorkerId,
};
use microclaw_core::runtime_event::{RuntimeEvent, RuntimeEventEnvelope};
use tokio::sync::{mpsc, oneshot, Notify, Semaphore};

mod remote;

pub use remote::{RemoteWorker, RemoteWorkerOptions, WorkerConnection, WorkerTransport};

struct PendingControl {
    control: RuntimeControl,
    receipt: Option<oneshot::Sender<Result<(), RuntimeError>>>,
}

/// A control message received by an executor that can be explicitly accepted or rejected.
///
/// Executors should acknowledge only after the underlying engine has accepted the operation.
/// Dropping a request without responding reports an unavailable control path to the caller.
pub struct ControlRequest {
    control: RuntimeControl,
    receipt: Option<oneshot::Sender<Result<(), RuntimeError>>>,
}

impl ControlRequest {
    pub fn control(&self) -> &RuntimeControl {
        &self.control
    }

    pub fn into_control(self) -> RuntimeControl {
        let control = self.control.clone();
        self.accept();
        control
    }

    pub fn accept(mut self) {
        if let Some(receipt) = self.receipt.take() {
            let _ = receipt.send(Ok(()));
        }
    }

    pub fn reject(mut self, error: RuntimeError) {
        if let Some(receipt) = self.receipt.take() {
            let _ = receipt.send(Err(error));
        }
    }
}

impl Drop for ControlRequest {
    fn drop(&mut self) {
        if let Some(receipt) = self.receipt.take() {
            let _ = receipt.send(Err(RuntimeError {
                code: RuntimeErrorCode::Unavailable,
                message: "executor did not acknowledge the control request".into(),
                retryable: false,
            }));
        }
    }
}

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
    control_rx: mpsc::UnboundedReceiver<PendingControl>,
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
        self.try_next_control_request()
            .map(ControlRequest::into_control)
    }

    pub async fn next_control(&mut self) -> Option<RuntimeControl> {
        self.next_control_request()
            .await
            .map(ControlRequest::into_control)
    }

    pub fn try_next_control_request(&mut self) -> Option<ControlRequest> {
        self.control_rx
            .try_recv()
            .ok()
            .map(|pending| ControlRequest {
                control: pending.control,
                receipt: pending.receipt,
            })
    }

    pub async fn next_control_request(&mut self) -> Option<ControlRequest> {
        self.control_rx.recv().await.map(|pending| ControlRequest {
            control: pending.control,
            receipt: pending.receipt,
        })
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
                max_concurrent_runs: self.max_concurrent_runs,
                active_runs: Arc::new(AtomicUsize::new(0)),
                queued_runs: AtomicUsize::new(0),
                idle: Notify::new(),
            }),
        })
    }
}

struct RuntimeInner {
    executor: Arc<dyn RunExecutor>,
    permits: Arc<Semaphore>,
    max_concurrent_runs: usize,
    active_runs: Arc<AtomicUsize>,
    queued_runs: AtomicUsize,
    idle: Notify,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeStats {
    pub active_runs: usize,
    pub queued_runs: usize,
    pub max_concurrent_runs: usize,
    pub shutting_down: bool,
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

    pub fn max_concurrent_runs(&self) -> usize {
        self.inner.max_concurrent_runs
    }

    pub fn active_runs(&self) -> usize {
        self.inner.active_runs.load(Ordering::Acquire)
    }

    pub fn queued_runs(&self) -> usize {
        self.inner.queued_runs.load(Ordering::Acquire)
    }

    pub fn stats(&self) -> RuntimeStats {
        RuntimeStats {
            active_runs: self.active_runs(),
            queued_runs: self.queued_runs(),
            max_concurrent_runs: self.max_concurrent_runs(),
            shutting_down: self.is_shutting_down(),
        }
    }

    /// Stop accepting new runs and wait until active and queued work has drained.
    pub async fn shutdown(&self) {
        self.inner.permits.close();
        self.wait_for_idle().await;
    }

    /// Returns true after graceful shutdown has begun.
    pub fn is_shutting_down(&self) -> bool {
        self.inner.permits.is_closed()
    }

    pub async fn wait_for_idle(&self) {
        loop {
            let notified = self.inner.idle.notified();
            if self.active_runs() == 0 && self.queued_runs() == 0 {
                return;
            }
            notified.await;
        }
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
        let active_runs = self.runtime.inner.active_runs.clone();
        let runtime_inner = self.runtime.inner.clone();
        let profile = self.profile.clone();
        let task_run_id = run_id.clone();
        let fallback_session_id = request
            .session_id
            .clone()
            .unwrap_or_else(|| SessionId::new(task_run_id.to_string()));

        runtime_inner.queued_runs.fetch_add(1, Ordering::AcqRel);
        tokio::spawn(async move {
            let permit = match permits.acquire_owned().await {
                Ok(permit) => permit,
                Err(_) => {
                    runtime_inner.queued_runs.fetch_sub(1, Ordering::AcqRel);
                    runtime_inner.idle.notify_waiters();
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
            runtime_inner.queued_runs.fetch_sub(1, Ordering::AcqRel);
            let _active_run = ActiveRunGuard::new(active_runs, runtime_inner.clone());
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

struct ActiveRunGuard {
    active_runs: Arc<AtomicUsize>,
    runtime: Arc<RuntimeInner>,
}

impl ActiveRunGuard {
    fn new(active_runs: Arc<AtomicUsize>, runtime: Arc<RuntimeInner>) -> Self {
        active_runs.fetch_add(1, Ordering::AcqRel);
        Self {
            active_runs,
            runtime,
        }
    }
}

impl Drop for ActiveRunGuard {
    fn drop(&mut self) {
        self.active_runs.fetch_sub(1, Ordering::AcqRel);
        self.runtime.idle.notify_waiters();
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
    control_tx: mpsc::UnboundedSender<PendingControl>,
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
        self.controller().cancel()
    }

    pub fn controller(&self) -> RunController {
        RunController {
            run_id: self.run_id.clone(),
            control_tx: self.control_tx.clone(),
        }
    }

    pub async fn cancel_confirmed(&self) -> Result<(), RuntimeError> {
        self.controller().cancel_confirmed().await
    }

    pub fn steer(&self, message: impl Into<String>) -> Result<(), RuntimeError> {
        self.controller().steer(message)
    }

    pub async fn steer_confirmed(&self, message: impl Into<String>) -> Result<(), RuntimeError> {
        self.controller().steer_confirmed(message).await
    }

    pub fn resolve_approval(
        &self,
        approval_id: impl Into<String>,
        decision: impl Into<String>,
    ) -> Result<(), RuntimeError> {
        self.controller().resolve_approval(approval_id, decision)
    }

    pub async fn resolve_approval_confirmed(
        &self,
        approval_id: impl Into<String>,
        decision: impl Into<String>,
    ) -> Result<(), RuntimeError> {
        self.controller()
            .resolve_approval_confirmed(approval_id, decision)
            .await
    }

    pub async fn result(self) -> Result<RunResult, RuntimeError> {
        self.result_rx.await.map_err(|_| RuntimeError {
            code: RuntimeErrorCode::Internal,
            message: "run ended without a terminal result".into(),
            retryable: false,
        })
    }
}

/// Cloneable control plane for a running task.
///
/// Keeping this separate from [`RunHandle`] lets one task consume events while another task or
/// UI callback controls the run without sharing the event receiver.
#[derive(Clone)]
pub struct RunController {
    run_id: RunId,
    control_tx: mpsc::UnboundedSender<PendingControl>,
}

impl RunController {
    pub fn id(&self) -> &RunId {
        &self.run_id
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
        self.control_tx
            .send(PendingControl {
                control,
                receipt: None,
            })
            .map_err(|_| RuntimeError {
                code: RuntimeErrorCode::Unavailable,
                message: "run is no longer accepting control messages".into(),
                retryable: false,
            })
    }

    pub async fn cancel_confirmed(&self) -> Result<(), RuntimeError> {
        self.send_control_confirmed(RuntimeControl::Cancel {
            run_id: self.run_id.clone(),
        })
        .await
    }

    pub async fn steer_confirmed(&self, message: impl Into<String>) -> Result<(), RuntimeError> {
        self.send_control_confirmed(RuntimeControl::Steer {
            run_id: self.run_id.clone(),
            message: message.into(),
        })
        .await
    }

    pub async fn resolve_approval_confirmed(
        &self,
        approval_id: impl Into<String>,
        decision: impl Into<String>,
    ) -> Result<(), RuntimeError> {
        self.send_control_confirmed(RuntimeControl::ResolveApproval {
            run_id: self.run_id.clone(),
            approval_id: approval_id.into(),
            decision: decision.into(),
        })
        .await
    }

    async fn send_control_confirmed(&self, control: RuntimeControl) -> Result<(), RuntimeError> {
        let (receipt_tx, receipt_rx) = oneshot::channel();
        self.control_tx
            .send(PendingControl {
                control,
                receipt: Some(receipt_tx),
            })
            .map_err(|_| RuntimeError {
                code: RuntimeErrorCode::Unavailable,
                message: "run is no longer accepting control messages".into(),
                retryable: false,
            })?;
        receipt_rx.await.map_err(|_| RuntimeError {
            code: RuntimeErrorCode::Unavailable,
            message: "run ended before acknowledging the control request".into(),
            retryable: false,
        })?
    }
}

#[async_trait]
pub trait Worker: Send + Sync {
    fn descriptor(&self) -> WorkerDescriptor;
    fn health(&self) -> WorkerHealth;
    async fn submit(
        &self,
        profile: AgentProfile,
        request: RunRequest,
    ) -> Result<RunHandle, RuntimeError>;
}

const WORKER_READY: u8 = 0;
const WORKER_DRAINING: u8 = 1;
const WORKER_UNAVAILABLE: u8 = 2;

#[derive(Clone)]
pub struct LocalWorker {
    descriptor: WorkerDescriptor,
    runtime: Runtime,
    state: Arc<AtomicU8>,
}

impl LocalWorker {
    pub fn new(runtime: Runtime, id: impl Into<WorkerId>, name: impl Into<String>) -> Self {
        let max_concurrent_runs = runtime.max_concurrent_runs();
        Self {
            descriptor: WorkerDescriptor {
                id: id.into(),
                name: name.into(),
                capabilities: runtime.capabilities(),
                max_concurrent_runs,
                labels: BTreeMap::new(),
            },
            runtime,
            state: Arc::new(AtomicU8::new(WORKER_READY)),
        }
    }

    pub fn with_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.descriptor.labels.insert(key.into(), value.into());
        self
    }

    pub fn begin_drain(&self) {
        self.state.store(WORKER_DRAINING, Ordering::Release);
    }

    pub fn mark_unavailable(&self) {
        self.state.store(WORKER_UNAVAILABLE, Ordering::Release);
    }

    pub fn resume(&self) {
        self.state.store(WORKER_READY, Ordering::Release);
    }

    pub async fn wait_for_idle(&self) {
        self.runtime.wait_for_idle().await;
    }
}

#[async_trait]
impl Worker for LocalWorker {
    fn descriptor(&self) -> WorkerDescriptor {
        self.descriptor.clone()
    }

    fn health(&self) -> WorkerHealth {
        let active_runs = self.runtime.active_runs();
        let state = self.state.load(Ordering::Acquire);
        WorkerHealth {
            worker_id: self.descriptor.id.clone(),
            status: match state {
                WORKER_DRAINING => WorkerHealthStatus::Draining,
                WORKER_UNAVAILABLE => WorkerHealthStatus::Unavailable,
                _ if active_runs >= self.descriptor.max_concurrent_runs => WorkerHealthStatus::Busy,
                _ => WorkerHealthStatus::Ready,
            },
            active_runs,
            queued_runs: self.runtime.queued_runs(),
            observed_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .to_string(),
        }
    }

    async fn submit(
        &self,
        profile: AgentProfile,
        request: RunRequest,
    ) -> Result<RunHandle, RuntimeError> {
        if self.state.load(Ordering::Acquire) != WORKER_READY {
            return Err(RuntimeError {
                code: RuntimeErrorCode::Unavailable,
                message: "Worker is not accepting new runs".into(),
                retryable: true,
            });
        }
        Ok(self.runtime.agent(profile).run(request))
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

    #[tokio::test]
    async fn confirmed_control_waits_for_executor_acknowledgement() {
        let runtime = Runtime::builder()
            .executor(ControlledExecutor)
            .build()
            .unwrap();
        let run = runtime
            .agent(AgentProfile::default())
            .run(RunRequest::new("wait"));
        let controller = run.controller();

        controller.steer_confirmed("accepted update").await.unwrap();
        let result = run.result().await.unwrap();
        assert_eq!(result.final_text, "accepted update");
    }

    struct RejectingExecutor;

    #[async_trait]
    impl RunExecutor for RejectingExecutor {
        async fn execute(
            &self,
            _profile: AgentProfile,
            _request: RunRequest,
            mut context: ExecutionContext,
        ) -> Result<ExecutionResult, RuntimeError> {
            let request = context.next_control_request().await.unwrap();
            request.reject(RuntimeError {
                code: RuntimeErrorCode::ApprovalDenied,
                message: "control rejected by policy".into(),
                retryable: false,
            });
            Ok(ExecutionResult::new("rejected", "unchanged"))
        }
    }

    #[tokio::test]
    async fn confirmed_control_surfaces_executor_rejection() {
        let runtime = Runtime::builder()
            .executor(RejectingExecutor)
            .build()
            .unwrap();
        let run = runtime
            .agent(AgentProfile::default())
            .run(RunRequest::new("wait"));
        let controller = run.controller();

        let error = controller.cancel_confirmed().await.unwrap_err();
        assert_eq!(error.code, RuntimeErrorCode::ApprovalDenied);
        assert_eq!(run.result().await.unwrap().final_text, "unchanged");
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
    async fn runtime_shutdown_drains_and_rejects_new_runs() {
        let runtime = Runtime::builder().executor(EchoExecutor).build().unwrap();
        runtime.shutdown().await;
        assert!(runtime.is_shutting_down());
        assert!(runtime.stats().shutting_down);

        let result = runtime
            .agent(AgentProfile::default())
            .run(RunRequest::new("after shutdown"))
            .result()
            .await
            .unwrap();
        assert_eq!(result.status, RunStatus::Failed);
        assert_eq!(result.error.unwrap().code, RuntimeErrorCode::Unavailable);
    }

    #[tokio::test]
    async fn local_worker_uses_the_same_runtime_contract() {
        let runtime = Runtime::builder().executor(EchoExecutor).build().unwrap();
        let worker = LocalWorker::new(runtime, "local", "Local worker");
        let descriptor = worker.descriptor();
        assert_eq!(descriptor.id, WorkerId::new("local"));
        assert_eq!(descriptor.max_concurrent_runs, 4);
        assert!(descriptor.capabilities.streaming);
        let run = worker
            .submit(AgentProfile::default(), RunRequest::new("worker task"))
            .await
            .unwrap();
        assert_eq!(run.result().await.unwrap().final_text, "worker task");
    }

    #[tokio::test]
    async fn local_worker_health_reports_runtime_capacity_and_activity() {
        let runtime = Runtime::builder()
            .executor(ConcurrentExecutor {
                active: Arc::new(AtomicUsize::new(0)),
                peak: Arc::new(AtomicUsize::new(0)),
            })
            .max_concurrent_runs(1)
            .build()
            .unwrap();
        let worker = LocalWorker::new(runtime, "local", "Local worker");
        let run = worker
            .submit(AgentProfile::default(), RunRequest::new("worker task"))
            .await
            .unwrap();

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let health = worker.health();
                if health.active_runs == 1 {
                    assert_eq!(health.status, WorkerHealthStatus::Busy);
                    assert!(!health.observed_at.is_empty());
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("worker should report its active run");

        run.result().await.unwrap();
        let health = worker.health();
        assert_eq!(health.active_runs, 0);
        assert_eq!(health.status, WorkerHealthStatus::Ready);
    }

    struct RelationshipExecutor;

    #[async_trait]
    impl RunExecutor for RelationshipExecutor {
        async fn execute(
            &self,
            profile: AgentProfile,
            request: RunRequest,
            _context: ExecutionContext,
        ) -> Result<ExecutionResult, RuntimeError> {
            let mut output = ExecutionResult::new("child-session", request.prompt);
            output.metadata.insert(
                "agent_id".into(),
                serde_json::json!(profile.id.map(|id| id.into_inner())),
            );
            output.metadata.insert(
                "parent_run_id".into(),
                serde_json::json!(request.parent_run_id.map(|id| id.into_inner())),
            );
            Ok(output)
        }
    }

    #[tokio::test]
    async fn parent_child_identity_survives_local_worker_submission() {
        let runtime = Runtime::builder()
            .executor(RelationshipExecutor)
            .build()
            .unwrap();
        let worker = LocalWorker::new(runtime, "local", "Local worker");
        let profile = AgentProfile {
            id: Some(microclaw_core::run_protocol::AgentId::new("reviewer")),
            ..AgentProfile::default()
        };
        let mut request = RunRequest::new("review child task");
        request.parent_run_id = Some(RunId::new("parent-1"));

        let result = worker
            .submit(profile, request)
            .await
            .unwrap()
            .result()
            .await
            .unwrap();
        assert_eq!(result.metadata["agent_id"], "reviewer");
        assert_eq!(result.metadata["parent_run_id"], "parent-1");
    }

    #[tokio::test]
    async fn local_worker_drains_without_accepting_new_runs() {
        let runtime = Runtime::builder()
            .executor(ConcurrentExecutor {
                active: Arc::new(AtomicUsize::new(0)),
                peak: Arc::new(AtomicUsize::new(0)),
            })
            .max_concurrent_runs(1)
            .build()
            .unwrap();
        let worker =
            LocalWorker::new(runtime, "local", "Local worker").with_label("pool", "foreground");
        let run = worker
            .submit(AgentProfile::default(), RunRequest::new("existing"))
            .await
            .unwrap();
        worker.begin_drain();

        assert_eq!(worker.descriptor().labels["pool"], "foreground");
        assert_eq!(worker.health().status, WorkerHealthStatus::Draining);
        let rejected = match worker
            .submit(AgentProfile::default(), RunRequest::new("new"))
            .await
        {
            Ok(_) => panic!("draining Worker should reject new runs"),
            Err(error) => error,
        };
        assert_eq!(rejected.code, RuntimeErrorCode::Unavailable);

        run.result().await.unwrap();
        worker.wait_for_idle().await;
        assert_eq!(worker.health().active_runs, 0);
        worker.mark_unavailable();
        assert_eq!(worker.health().status, WorkerHealthStatus::Unavailable);
        worker.resume();
        assert_eq!(worker.health().status, WorkerHealthStatus::Ready);
    }
}
