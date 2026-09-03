//! Stable facade for embedding MicroClaw in Rust applications.
//!
//! Most applications should import contracts and runtime handles from this crate instead of
//! depending on MicroClaw's internal capability crates individually.

pub use microclaw_core::run_protocol::{
    validate_worker_protocol_version, AgentId, AgentProfile, CallerContext, RunId, RunRequest,
    RunResult, RunStatus, RuntimeCapabilities, RuntimeControl, RuntimeError, RuntimeErrorCode,
    SessionId, ToolPolicy, WorkerCommand, WorkerDescriptor, WorkerFrame, WorkerHealth,
    WorkerHealthStatus, WorkerId, WORKER_PROTOCOL_VERSION,
};
pub use microclaw_core::runtime_event::{
    RuntimeApprovalDecision, RuntimeApprovalOption, RuntimeApprovalOptionKind, RuntimeEvent,
    RuntimeEventEnvelope, RuntimePlanStep, RuntimePlanStepStatus, RuntimeProcessKind,
};
pub use microclaw_runtime::{
    AgentHandle, ControlRequest, ExecutionContext, ExecutionResult, LocalWorker, RunController,
    RunExecutor, RunHandle, Runtime, RuntimeBuildError, RuntimeBuilder, Worker,
};

/// Lower-level contracts for applications that need the complete foundational API.
pub mod core {
    pub use microclaw_core::*;
}

/// Supported default MicroClaw services for applications using the `full` preset.
///
/// The facade exposes the concrete Agent Engine without pulling in the Server, Web console,
/// concrete channel adapters, or native Work UI.
#[cfg(feature = "full")]
pub mod engine {
    pub use microclaw_engine::*;
}
