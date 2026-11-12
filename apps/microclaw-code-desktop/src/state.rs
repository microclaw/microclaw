//! The conversation as the window shows it: a list of items built from
//! driver [`Update`]s by a pure reducer, so it is tested without GPUI.

use microclaw_code_core::driver::{HistoryEntry, PendingApproval, Update};
use microclaw_sdk::{RunStatus, RuntimeEvent};

/// Lines of command output kept per tool call.
const TOOL_OUTPUT_KEEP: usize = 12;

#[derive(Debug, Clone, PartialEq)]
pub enum ToolState {
    Running,
    WaitingForApproval,
    Done { duration_ms: u64 },
    Failed(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct ToolCall {
    pub call_id: String,
    pub name: String,
    pub summary: String,
    pub state: ToolState,
    pub output: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ApprovalState {
    Waiting,
    Answered { label: String, denied: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Item {
    User(String),
    Steer(String),
    /// Agent text (Markdown), growing while it streams.
    Agent(String),
    Tool(ToolCall),
    Diff {
        path: String,
        added: usize,
        removed: usize,
        diff: String,
    },
    Approval {
        approval: PendingApproval,
        state: ApprovalState,
    },
    Check {
        name: String,
        passed: Option<bool>,
        detail: String,
    },
    Notice(String, Tone),
    /// End of a turn: what it did.
    Receipt(String),
}

/// The visible conversation of one session.
#[derive(Debug, Default, Clone)]
pub struct Transcript {
    pub items: Vec<Item>,
    /// Bumped on every change; views use it to skip work.
    pub revision: u64,
    /// The approval the running turn waits for.
    pub pending: Option<PendingApproval>,
    /// Text streamed since the last tool call (merged into one item).
    streaming: bool,
    /// Files changed this turn, for the receipt.
    turn_files: Vec<String>,
}

fn one_line(text: &str, max: usize) -> String {
    let line = text
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .trim();
    if line.chars().count() <= max {
        line.to_string()
    } else {
        format!("{}…", line.chars().take(max).collect::<String>())
    }
}

/// A short description of a tool call from its input.
pub fn tool_summary(name: &str, input: &serde_json::Value) -> String {
    let field = |key: &str| input.get(key).and_then(|v| v.as_str());
    let text = match name {
        "bash" => field("command"),
        "read_file" | "write_file" | "edit_file" => field("path"),
        "glob" | "grep" => field("pattern"),
        "web_fetch" => field("url"),
        "web_search" => field("query"),
        "sub_agent" | "explore" => field("task").or_else(|| field("prompt")),
        _ => None,
    };
    match text {
        Some(text) => one_line(text, 120),
        None => one_line(&input.to_string(), 120),
    }
}

impl Transcript {
    fn push(&mut self, item: Item) {
        self.streaming = false;
        self.items.push(item);
    }

    pub fn notice(&mut self, text: impl Into<String>, tone: Tone) {
        self.push(Item::Notice(text.into(), tone));
        self.revision += 1;
    }

    pub fn clear(&mut self) {
        *self = Self {
            revision: self.revision + 1,
            ..Self::default()
        };
    }

    /// Show an earlier conversation of this session.
    pub fn load_history(&mut self, history: &[HistoryEntry]) {
        self.clear();
        for entry in history {
            self.push(match entry {
                HistoryEntry::User(text) => Item::User(text.clone()),
                HistoryEntry::Agent(text) => Item::Agent(text.clone()),
                HistoryEntry::Verification(text) => {
                    Item::Notice(format!("verification {text}"), Tone::Info)
                }
            });
        }
        self.revision += 1;
    }

    pub fn begin_turn(&mut self, prompt: &str) {
        self.push(Item::User(prompt.to_string()));
        self.turn_files.clear();
        self.pending = None;
        self.revision += 1;
    }

    pub fn steer(&mut self, text: &str) {
        self.push(Item::Steer(text.to_string()));
        self.revision += 1;
    }

    fn find_call(&mut self, call_id: &str) -> Option<&mut ToolCall> {
        self.items.iter_mut().rev().find_map(|item| match item {
            Item::Tool(call) if call.call_id == call_id => Some(call),
            _ => None,
        })
    }

    fn apply_runtime(&mut self, event: &RuntimeEvent) {
        match event {
            RuntimeEvent::TextDelta { delta } if !delta.is_empty() => match self.items.last_mut() {
                Some(Item::Agent(text)) if self.streaming => text.push_str(delta),
                _ => {
                    self.push(Item::Agent(delta.clone()));
                    self.streaming = true;
                }
            },
            RuntimeEvent::ToolStart {
                call_id,
                name,
                input,
            } => self.push(Item::Tool(ToolCall {
                call_id: call_id.clone(),
                name: name.clone(),
                summary: tool_summary(name, input),
                state: ToolState::Running,
                output: Vec::new(),
            })),
            RuntimeEvent::ToolResult {
                call_id,
                is_error,
                preview,
                duration_ms,
                error_type,
                ..
            } => {
                let Some(call) = self.find_call(call_id) else {
                    return;
                };
                if *is_error {
                    call.state = if error_type.as_deref() == Some("approval_required") {
                        ToolState::WaitingForApproval
                    } else {
                        ToolState::Failed(one_line(preview, 160))
                    };
                } else {
                    call.state = ToolState::Done {
                        duration_ms: *duration_ms,
                    };
                    if matches!(call.name.as_str(), "bash" | "bash_output") {
                        let lines: Vec<&str> = preview.lines().collect();
                        let start = lines.len().saturating_sub(TOOL_OUTPUT_KEEP);
                        call.output = lines[start..]
                            .iter()
                            .map(|l| l.chars().take(400).collect())
                            .collect();
                    }
                }
            }
            RuntimeEvent::FileDiff {
                path,
                diff,
                added,
                removed,
                ..
            } => {
                if !self.turn_files.contains(path) {
                    self.turn_files.push(path.clone());
                }
                self.push(Item::Diff {
                    path: path.clone(),
                    added: *added,
                    removed: *removed,
                    diff: diff.clone(),
                });
            }
            RuntimeEvent::ContextCompacted {
                tokens_before,
                tokens_after,
                ..
            } => self.push(Item::Notice(
                format!("context compacted: ~{tokens_before} → ~{tokens_after} tokens"),
                Tone::Info,
            )),
            RuntimeEvent::SubagentStarted { label, .. } => self.push(Item::Notice(
                format!("sub-agent started: {label}"),
                Tone::Info,
            )),
            RuntimeEvent::SubagentFinished { status, .. } => {
                self.push(Item::Notice(format!("sub-agent {status}"), Tone::Info))
            }
            _ => {}
        }
    }

    /// Apply one driver update.
    pub fn apply(&mut self, update: &Update) {
        match update {
            Update::Runtime(envelope) => self.apply_runtime(&envelope.event),
            Update::SteerAccepted(_) => {}
            Update::SteerRejected(text) => self.push(Item::Notice(
                format!("guidance not delivered: {text}"),
                Tone::Warning,
            )),
            Update::ApprovalRequested(approval) => {
                self.pending = Some(approval.clone());
                self.push(Item::Approval {
                    approval: approval.clone(),
                    state: ApprovalState::Waiting,
                });
            }
            Update::ApprovalAnswered { label, denied, .. } => {
                self.pending = None;
                if let Some(Item::Approval { state, .. }) = self.items.iter_mut().rev().find(|i| {
                    matches!(
                        i,
                        Item::Approval {
                            state: ApprovalState::Waiting,
                            ..
                        }
                    )
                }) {
                    *state = ApprovalState::Answered {
                        label: label.clone(),
                        denied: *denied,
                    };
                }
            }
            Update::AutoApproved { tool, rule } => self.push(Item::Notice(
                match rule {
                    Some(rule) => format!("{tool} approved by {rule}"),
                    None => format!("{tool} approved (auto mode)"),
                },
                Tone::Info,
            )),
            Update::RunFinished { status, error, .. } => {
                self.pending = None;
                // Approvals left waiting were not answered in this run.
                for item in &mut self.items {
                    if let Item::Approval { state, .. } = item
                        && *state == ApprovalState::Waiting
                    {
                        *state = ApprovalState::Answered {
                            label: "not answered".into(),
                            denied: true,
                        };
                    }
                }
                match (status, error) {
                    (_, Some(error)) => self.push(Item::Notice(error.clone(), Tone::Error)),
                    (RunStatus::Cancelled, None) => {
                        self.push(Item::Notice("stopped".into(), Tone::Warning))
                    }
                    _ => {}
                }
            }
            Update::CheckStarted(check) => self.push(Item::Check {
                name: check.name.clone(),
                passed: None,
                detail: check.run.clone(),
            }),
            Update::CheckFinished(outcome) => {
                let name = outcome.check.name.clone();
                let passed = outcome.success;
                let mut detail = format!(
                    "{} in {:.1}s",
                    outcome.status_label(),
                    outcome.duration.as_secs_f32()
                );
                if !passed {
                    let lines: Vec<&str> = outcome.output.lines().collect();
                    let start = lines.len().saturating_sub(TOOL_OUTPUT_KEEP);
                    detail.push('\n');
                    detail.push_str(&lines[start..].join("\n"));
                }
                if let Some(Item::Check {
                    passed: p,
                    detail: d,
                    ..
                }) =
                    self.items.iter_mut().rev().find(
                        |i| matches!(i, Item::Check { name: n, passed: None, .. } if *n == name),
                    )
                {
                    *p = Some(passed);
                    *d = detail;
                } else {
                    self.push(Item::Check {
                        name,
                        passed: Some(passed),
                        detail,
                    });
                }
            }
            Update::FixRound { round, max, check } => self.push(Item::Notice(
                format!("fix round {round}/{max}: {check} failed, handing it back"),
                Tone::Warning,
            )),
            Update::ChecksGaveUp(outcome) => self.push(Item::Notice(
                format!(
                    "checks still failing after the fix rounds: {}",
                    outcome.check.name
                ),
                Tone::Error,
            )),
            Update::Notice(text) => self.push(Item::Notice(text.clone(), Tone::Info)),
            Update::ContextPercent(_) | Update::TurnUsage { .. } => {}
        }
        self.revision += 1;
    }

    /// Close the turn with a one-line receipt.
    pub fn finish_turn(&mut self, receipt: Option<String>) {
        self.pending = None;
        if let Some(text) = receipt {
            self.push(Item::Receipt(text));
        }
        self.revision += 1;
    }

    #[cfg(test)]
    pub fn turn_files(&self) -> &[String] {
        &self.turn_files
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use microclaw_sdk::{
        RuntimeApprovalDecision, RuntimeApprovalOption, RuntimeApprovalOptionKind,
        RuntimeEventEnvelope,
    };

    fn runtime(seq: u64, event: RuntimeEvent) -> Update {
        Update::Runtime(RuntimeEventEnvelope::new("r", seq, event))
    }

    #[test]
    fn streamed_text_merges_until_a_tool_call() {
        let mut t = Transcript::default();
        t.begin_turn("fix it");
        t.apply(&runtime(
            1,
            RuntimeEvent::TextDelta {
                delta: "Hel".into(),
            },
        ));
        t.apply(&runtime(2, RuntimeEvent::TextDelta { delta: "lo".into() }));
        t.apply(&runtime(
            3,
            RuntimeEvent::ToolStart {
                call_id: "c1".into(),
                name: "bash".into(),
                input: serde_json::json!({"command": "cargo test\nmore"}),
            },
        ));
        t.apply(&runtime(
            4,
            RuntimeEvent::TextDelta {
                delta: "Done".into(),
            },
        ));
        assert_eq!(t.items[0], Item::User("fix it".into()));
        assert_eq!(t.items[1], Item::Agent("Hello".into()));
        match &t.items[2] {
            Item::Tool(call) => {
                assert_eq!(call.summary, "cargo test");
                assert_eq!(call.state, ToolState::Running);
            }
            other => panic!("expected a tool call, got {other:?}"),
        }
        assert_eq!(t.items[3], Item::Agent("Done".into()));
    }

    #[test]
    fn tool_results_update_their_call() {
        let mut t = Transcript::default();
        t.apply(&runtime(
            1,
            RuntimeEvent::ToolStart {
                call_id: "c1".into(),
                name: "bash".into(),
                input: serde_json::json!({"command": "ls"}),
            },
        ));
        t.apply(&runtime(
            2,
            RuntimeEvent::ToolResult {
                call_id: "c1".into(),
                name: "bash".into(),
                is_error: false,
                preview: "a\nb".into(),
                duration_ms: 12,
                status_code: None,
                bytes: 3,
                error_type: None,
            },
        ));
        match &t.items[0] {
            Item::Tool(call) => {
                assert_eq!(call.state, ToolState::Done { duration_ms: 12 });
                assert_eq!(call.output, vec!["a", "b"]);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn approvals_wait_then_record_the_answer() {
        let mut t = Transcript::default();
        let approval = PendingApproval::from_event(
            "a1",
            "bash",
            Some("rm -rf target"),
            &[RuntimeApprovalOption {
                value: "1".into(),
                label: "Approve once".into(),
                kind: RuntimeApprovalOptionKind::Primary,
                decision: RuntimeApprovalDecision::Approve,
            }],
            None,
        );
        t.apply(&Update::ApprovalRequested(approval.clone()));
        assert_eq!(t.pending.as_ref(), Some(&approval));
        t.apply(&Update::ApprovalAnswered {
            tool: "bash".into(),
            label: "Approve once".into(),
            denied: false,
        });
        assert!(t.pending.is_none());
        assert!(matches!(
            &t.items[0],
            Item::Approval {
                state: ApprovalState::Answered { denied: false, .. },
                ..
            }
        ));
    }

    #[test]
    fn history_replaces_the_transcript() {
        let mut t = Transcript::default();
        t.notice("old", Tone::Info);
        t.load_history(&[
            HistoryEntry::User("hi".into()),
            HistoryEntry::Agent("hello".into()),
        ]);
        assert_eq!(
            t.items,
            vec![Item::User("hi".into()), Item::Agent("hello".into())]
        );
    }

    #[test]
    fn file_diffs_are_counted_for_the_receipt() {
        let mut t = Transcript::default();
        t.begin_turn("edit");
        for _ in 0..2 {
            t.apply(&runtime(
                1,
                RuntimeEvent::FileDiff {
                    path: "src/lib.rs".into(),
                    diff: "@@\n-a\n+b".into(),
                    added: 1,
                    removed: 1,
                    truncated: false,
                },
            ));
        }
        assert_eq!(t.turn_files(), ["src/lib.rs"]);
    }
}
