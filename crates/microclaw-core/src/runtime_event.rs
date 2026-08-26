//! Provider-neutral runtime events shared by Server, Work, and headless clients.

use serde::{Deserialize, Serialize};
use serde_json::Value;

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
        duration_ms: u128,
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
        options: Vec<String>,
        advisory: Option<String>,
    },
    CheckpointCreated {
        commit: String,
        label: String,
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
    pub const SCHEMA_VERSION: u32 = 3;

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
}
