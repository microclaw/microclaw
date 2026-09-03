//! Stable facade for embedding MicroClaw in Rust applications.
//!
//! Most applications should import contracts and runtime handles from this crate instead of
//! depending on MicroClaw's internal capability crates individually.

pub use microclaw_core::run_protocol::{
    AgentId, AgentProfile, CallerContext, RunId, RunRequest, RunResult, RunStatus,
    RuntimeCapabilities, RuntimeControl, RuntimeError, RuntimeErrorCode, SessionId, ToolPolicy,
    WorkerDescriptor, WorkerHealth, WorkerHealthStatus, WorkerId,
};
pub use microclaw_core::runtime_event::{
    RuntimeApprovalDecision, RuntimeApprovalOption, RuntimeApprovalOptionKind, RuntimeEvent,
    RuntimeEventEnvelope, RuntimePlanStep, RuntimePlanStepStatus, RuntimeProcessKind,
};
pub use microclaw_runtime::{
    AgentHandle, ExecutionContext, ExecutionResult, LocalWorker, RunExecutor, RunHandle, Runtime,
    RuntimeBuildError, RuntimeBuilder, Worker,
};

/// Lower-level contracts for applications that need the complete foundational API.
pub mod core {
    pub use microclaw_core::*;
}
