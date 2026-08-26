//! Provider-neutral runtime events shared by Server, Work, and headless clients.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePlanStepStatus {
    #[default]
    Pending,
    InProgress,
    Completed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimePlanStep {
    pub title: String,
    pub status: RuntimePlanStepStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeApprovalOptionKind {
    Primary,
    Secondary,
    Danger,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeApprovalDecision {
    Approve,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeApprovalOption {
    pub value: String,
    pub label: String,
    pub kind: RuntimeApprovalOptionKind,
    pub decision: RuntimeApprovalDecision,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeProcessKind {
    Command,
    Verification,
}

/// An observable event emitted by the shared agent runtime.
///
/// Keep provider-specific payloads behind the runtime boundary. Consumers
/// should be able to project this stream without knowing which LLM produced it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RuntimeEvent {
    Iteration {
        iteration: usize,
    },
    ToolStart {
        call_id: String,
        name: String,
        input: Value,
    },
    ToolResult {
        call_id: String,
        name: String,
        is_error: bool,
        preview: String,
        duration_ms: u64,
        status_code: Option<i32>,
        bytes: usize,
        error_type: Option<String>,
    },
    TextDelta {
        delta: String,
    },
    ToolWaveStart {
        wave: usize,
        tool_count: usize,
    },
    ToolWaveComplete {
        wave: usize,
    },
    Cancelled {
        final_text: String,
    },
    FinalResponse {
        text: String,
    },
    MidTurnInjection {
        count: usize,
    },
    FileDiff {
        path: String,
        diff: String,
        added: usize,
        removed: usize,
        truncated: bool,
    },
    SubagentStarted {
        run_id: String,
        label: String,
    },
    SubagentFinished {
        run_id: String,
        status: String,
    },
    ApprovalRequired {
        approval_id: String,
        tool: String,
        preview: Option<String>,
        options: Vec<RuntimeApprovalOption>,
        advisory: Option<String>,
    },
    CheckpointCreated {
        commit: String,
        label: String,
    },
    PlanUpdated {
        steps: Vec<RuntimePlanStep>,
    },
    ProcessOutput {
        call_id: String,
        command: String,
        output: String,
        exit_code: Option<i32>,
        duration_ms: u64,
        truncated: bool,
        kind: RuntimeProcessKind,
    },
}

/// Versioned transport envelope for replayable runtime event streams.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeEventEnvelope {
    pub schema_version: u32,
    pub run_id: String,
    pub sequence: u64,
    pub event: RuntimeEvent,
}

impl RuntimeEventEnvelope {
    pub const SCHEMA_VERSION: u32 = 6;

    pub fn new(run_id: impl Into<String>, sequence: u64, event: RuntimeEvent) -> Self {
        Self {
            schema_version: Self::SCHEMA_VERSION,
            run_id: run_id.into(),
            sequence,
            event,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_round_trips_as_tagged_json() {
        let expected = RuntimeEventEnvelope::new(
            "run-1",
            7,
            RuntimeEvent::ToolStart {
                call_id: "call-1".into(),
                name: "read_file".into(),
                input: serde_json::json!({"path": "README.md"}),
            },
        );

        let json = serde_json::to_string(&expected).expect("serialize runtime event");
        assert!(json.contains("\"type\":\"tool_start\""));
        let actual: RuntimeEventEnvelope =
            serde_json::from_str(&json).expect("deserialize runtime event");
        assert_eq!(actual, expected);
    }

    #[test]
    fn plan_update_round_trips_with_step_statuses() {
        let expected = RuntimeEventEnvelope::new(
            "run-plan",
            2,
            RuntimeEvent::PlanUpdated {
                steps: vec![
                    RuntimePlanStep {
                        title: "Inspect the workspace".into(),
                        status: RuntimePlanStepStatus::Completed,
                    },
                    RuntimePlanStep {
                        title: "Implement the change".into(),
                        status: RuntimePlanStepStatus::InProgress,
                    },
                ],
            },
        );
        let json = serde_json::to_string(&expected).expect("serialize plan update");
        let actual: RuntimeEventEnvelope =
            serde_json::from_str(&json).expect("deserialize plan update");
        assert_eq!(actual, expected);
    }

    #[test]
    fn approval_options_round_trip_with_stable_values_and_intent() {
        let expected = RuntimeEventEnvelope::new(
            "run-approval",
            3,
            RuntimeEvent::ApprovalRequired {
                approval_id: "approval-1".into(),
                tool: "bash".into(),
                preview: Some("cargo test".into()),
                options: vec![RuntimeApprovalOption {
                    value: "3".into(),
                    label: "Deny".into(),
                    kind: RuntimeApprovalOptionKind::Danger,
                    decision: RuntimeApprovalDecision::Deny,
                }],
                advisory: Some("Review command scope".into()),
            },
        );
        let json = serde_json::to_string(&expected).expect("serialize approval event");
        let actual: RuntimeEventEnvelope =
            serde_json::from_str(&json).expect("deserialize approval event");
        assert_eq!(actual, expected);
    }

    #[test]
    fn process_output_round_trips_as_bounded_execution_evidence() {
        let expected = RuntimeEventEnvelope::new(
            "run-process",
            4,
            RuntimeEvent::ProcessOutput {
                call_id: "bash-1".into(),
                command: "cargo test".into(),
                output: "test result: ok".into(),
                exit_code: Some(0),
                duration_ms: 250,
                truncated: false,
                kind: RuntimeProcessKind::Verification,
            },
        );
        let json = serde_json::to_string(&expected).expect("serialize process output");
        let actual: RuntimeEventEnvelope =
            serde_json::from_str(&json).expect("deserialize process output");
        assert_eq!(actual, expected);
    }

    #[test]
    fn tool_result_duration_is_json_transport_safe() {
        let expected = RuntimeEventEnvelope::new(
            "run-tool",
            5,
            RuntimeEvent::ToolResult {
                call_id: "call-1".into(),
                name: "bash".into(),
                is_error: false,
                preview: "ok".into(),
                duration_ms: u64::MAX,
                status_code: Some(0),
                bytes: 2,
                error_type: None,
            },
        );
        let json = serde_json::to_string(&expected).expect("serialize tool result");
        let actual: RuntimeEventEnvelope =
            serde_json::from_str(&json).expect("deserialize tool result");
        assert_eq!(actual, expected);
    }
}
