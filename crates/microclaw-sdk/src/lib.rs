//! Stable facade for embedding MicroClaw in Rust applications.
//!
//! `minimal` exposes protocol contracts only, `standard` adds the embeddable runtime, and
//! `full` adds configuration-driven Agent Engine construction and Skill discovery.

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

#[cfg(feature = "standard")]
mod runtime_api;
#[cfg(feature = "standard")]
pub use runtime_api::*;
