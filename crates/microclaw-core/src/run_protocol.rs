//! Stable, provider-neutral contracts for embedding and remotely hosting MicroClaw runs.
//!
//! These types intentionally contain no Server, UI, database, or model-provider details. The
//! same request and lifecycle model is shared by embedded runtimes, local workers, and remote
//! workers.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::runtime_event::RuntimeEventEnvelope;

pub const WORKER_PROTOCOL_VERSION: u16 = 1;

pub fn validate_worker_protocol_version(protocol_version: u16) -> Result<(), RuntimeError> {
    if protocol_version == WORKER_PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(RuntimeError {
            code: RuntimeErrorCode::InvalidRequest,
            message: format!(
                "unsupported Worker protocol version {protocol_version}; expected {WORKER_PROTOCOL_VERSION}"
            ),
            retryable: false,
        })
    }
}

macro_rules! string_id {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn into_inner(self) -> String {
                self.0
            }
        }

        impl From<String> for $name {
            fn from(value: String) -> Self {
                Self(value)
            }
        }

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self(value.to_owned())
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

string_id!(RunId);
string_id!(SessionId);
string_id!(AgentId);
string_id!(WorkerId);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    #[default]
    Accepted,
    Queued,
    Running,
    WaitingForApproval,
    Completed,
    Failed,
    TimedOut,
    Cancelled,
}

impl RunStatus {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::TimedOut | Self::Cancelled
        )
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolPolicy {
    ReadOnly,
    WorkspaceWrite,
    #[default]
    RuntimeDefault,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AgentProfile {
    pub id: Option<AgentId>,
    pub name: String,
    pub system_prompt: Option<String>,
    #[serde(default)]
    pub skills: Vec<String>,
    #[serde(default)]
    pub tool_policy: ToolPolicy,
    #[serde(default)]
    pub metadata: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallerContext {
    pub channel: String,
    pub principal: Option<String>,
    pub chat_id: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunRequest {
    pub run_id: Option<RunId>,
    pub prompt: String,
    pub session_id: Option<SessionId>,
    pub agent_id: Option<AgentId>,
    pub parent_run_id: Option<RunId>,
    pub workspace: Option<PathBuf>,
    #[serde(default)]
    pub caller: CallerContext,
    #[serde(default)]
    pub metadata: BTreeMap<String, Value>,
}

impl RunRequest {
    pub fn new(prompt: impl Into<String>) -> Self {
        Self {
            run_id: None,
            prompt: prompt.into(),
            session_id: None,
            agent_id: None,
            parent_run_id: None,
            workspace: None,
            caller: CallerContext::default(),
            metadata: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunResult {
    pub run_id: RunId,
    pub session_id: SessionId,
    pub status: RunStatus,
    pub final_text: String,
    pub error: Option<RuntimeError>,
    #[serde(default)]
    pub metadata: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeErrorCode {
    InvalidRequest,
    Configuration,
    Provider,
    Tool,
    Storage,
    ApprovalDenied,
    Cancelled,
    TimedOut,
    Unavailable,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeError {
    pub code: RuntimeErrorCode,
    pub message: String,
    pub retryable: bool,
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for RuntimeError {}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeCapabilities {
    pub streaming: bool,
    pub cancellation: bool,
    pub steering: bool,
    pub approvals: bool,
    pub skills: bool,
    pub subagents: bool,
    pub remote_workers: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RuntimeControl {
    Cancel {
        run_id: RunId,
    },
    Steer {
        run_id: RunId,
        message: String,
    },
    ResolveApproval {
        run_id: RunId,
        approval_id: String,
        decision: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerDescriptor {
    pub id: WorkerId,
    pub name: String,
    pub capabilities: RuntimeCapabilities,
    pub max_concurrent_runs: usize,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerHealthStatus {
    Ready,
    Busy,
    Draining,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerHealth {
    pub worker_id: WorkerId,
    pub status: WorkerHealthStatus,
    pub active_runs: usize,
    #[serde(default)]
    pub queued_runs: usize,
    pub observed_at: String,
}

/// Transport-neutral command vocabulary for a remote Worker endpoint.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WorkerCommand {
    Describe {
        protocol_version: u16,
    },
    Health {
        protocol_version: u16,
    },
    Submit {
        protocol_version: u16,
        profile: AgentProfile,
        request: Box<RunRequest>,
    },
    Control {
        protocol_version: u16,
        control: RuntimeControl,
    },
    ResumeEvents {
        protocol_version: u16,
        run_id: RunId,
        after_sequence: Option<u64>,
    },
}

impl WorkerCommand {
    pub fn protocol_version(&self) -> u16 {
        match self {
            Self::Describe { protocol_version }
            | Self::Health { protocol_version }
            | Self::Submit {
                protocol_version, ..
            }
            | Self::Control {
                protocol_version, ..
            }
            | Self::ResumeEvents {
                protocol_version, ..
            } => *protocol_version,
        }
    }

    pub fn validate_protocol(&self) -> Result<(), RuntimeError> {
        validate_worker_protocol_version(self.protocol_version())
    }
}

/// Frames returned by a Worker transport. Events and the terminal result may be streamed over
/// WebSocket/SSE or represented by repeated polling without changing their JSON shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WorkerFrame {
    Descriptor {
        protocol_version: u16,
        descriptor: WorkerDescriptor,
    },
    Health {
        protocol_version: u16,
        health: WorkerHealth,
    },
    Accepted {
        protocol_version: u16,
        run_id: RunId,
    },
    Event {
        protocol_version: u16,
        envelope: RuntimeEventEnvelope,
    },
    ControlAcknowledged {
        protocol_version: u16,
        run_id: RunId,
    },
    Result {
        protocol_version: u16,
        result: RunResult,
    },
    Error {
        protocol_version: u16,
        run_id: Option<RunId>,
        error: RuntimeError,
    },
}

impl WorkerFrame {
    pub fn protocol_version(&self) -> u16 {
        match self {
            Self::Descriptor {
                protocol_version, ..
            }
            | Self::Health {
                protocol_version, ..
            }
            | Self::Accepted {
                protocol_version, ..
            }
            | Self::Event {
                protocol_version, ..
            }
            | Self::ControlAcknowledged {
                protocol_version, ..
            }
            | Self::Result {
                protocol_version, ..
            }
            | Self::Error {
                protocol_version, ..
            } => *protocol_version,
        }
    }

    pub fn validate_protocol(&self) -> Result<(), RuntimeError> {
        validate_worker_protocol_version(self.protocol_version())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_transport_stable() {
        let id = RunId::new("run-1");
        assert_eq!(serde_json::to_string(&id).unwrap(), "\"run-1\"");
        assert_eq!(serde_json::from_str::<RunId>("\"run-1\"").unwrap(), id);
        assert_eq!(id.to_string(), "run-1");
    }

    #[test]
    fn run_request_round_trips_without_product_details() {
        let mut request = RunRequest::new("inspect this project");
        request.session_id = Some(SessionId::new("project-1"));
        request.agent_id = Some(AgentId::new("coder"));
        request.workspace = Some(PathBuf::from("/workspace"));
        request.caller = CallerContext {
            channel: "work".into(),
            principal: Some("local-user".into()),
            chat_id: Some(42),
        };

        let json = serde_json::to_string(&request).unwrap();
        let decoded: RunRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, request);
        assert!(!json.contains("provider"));
        assert!(!json.contains("database"));
    }

    #[test]
    fn worker_protocol_round_trips_submission_and_result_frames() {
        let mut request = RunRequest::new("implement the parser");
        request.run_id = Some(RunId::new("run-7"));
        request.parent_run_id = Some(RunId::new("parent-2"));
        let command = WorkerCommand::Submit {
            protocol_version: WORKER_PROTOCOL_VERSION,
            profile: AgentProfile {
                id: Some(AgentId::new("coder")),
                skills: vec!["rust-review".into()],
                ..AgentProfile::default()
            },
            request: Box::new(request),
        };
        let encoded = serde_json::to_string(&command).unwrap();
        let decoded: WorkerCommand = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, command);
        assert_eq!(decoded.protocol_version(), WORKER_PROTOCOL_VERSION);

        let frame = WorkerFrame::Result {
            protocol_version: WORKER_PROTOCOL_VERSION,
            result: RunResult {
                run_id: RunId::new("run-7"),
                session_id: SessionId::new("session-3"),
                status: RunStatus::Completed,
                final_text: "done".into(),
                error: None,
                metadata: BTreeMap::new(),
            },
        };
        let encoded = serde_json::to_string(&frame).unwrap();
        assert_eq!(
            serde_json::from_str::<WorkerFrame>(&encoded).unwrap(),
            frame
        );
        assert_eq!(frame.protocol_version(), WORKER_PROTOCOL_VERSION);
    }

    #[test]
    fn terminal_statuses_are_explicit() {
        assert!(!RunStatus::Running.is_terminal());
        assert!(!RunStatus::WaitingForApproval.is_terminal());
        assert!(RunStatus::Completed.is_terminal());
        assert!(RunStatus::Failed.is_terminal());
        assert!(RunStatus::TimedOut.is_terminal());
        assert!(RunStatus::Cancelled.is_terminal());
    }

    #[test]
    fn worker_protocol_rejects_incompatible_versions() {
        let command = WorkerCommand::Describe {
            protocol_version: WORKER_PROTOCOL_VERSION + 1,
        };
        let error = command.validate_protocol().unwrap_err();
        assert_eq!(error.code, RuntimeErrorCode::InvalidRequest);
        assert!(error
            .message
            .contains("unsupported Worker protocol version"));

        let frame = WorkerFrame::Accepted {
            protocol_version: WORKER_PROTOCOL_VERSION,
            run_id: RunId::new("run-1"),
        };
        frame.validate_protocol().unwrap();
    }

    #[test]
    fn worker_contract_round_trips() {
        let descriptor = WorkerDescriptor {
            id: WorkerId::new("local-1"),
            name: "Local worker".into(),
            capabilities: RuntimeCapabilities {
                streaming: true,
                cancellation: true,
                steering: true,
                approvals: true,
                skills: true,
                subagents: true,
                remote_workers: false,
            },
            max_concurrent_runs: 4,
            labels: BTreeMap::from([("arch".into(), "arm64".into())]),
        };

        let json = serde_json::to_string(&descriptor).unwrap();
        assert_eq!(
            serde_json::from_str::<WorkerDescriptor>(&json).unwrap(),
            descriptor
        );
    }
}
