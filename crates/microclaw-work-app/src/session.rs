use microclaw_core::runtime_event::{RuntimeEvent, RuntimeEventEnvelope, RuntimePlanStepStatus};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkStatus {
    Planning,
    Running,
    AwaitingApproval,
    Verifying,
    Completed,
    Cancelled,
    Failed,
    Interrupted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanStep {
    pub title: String,
    #[serde(default)]
    pub status: RuntimePlanStepStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkApproval {
    pub approval_id: String,
    pub tool: String,
    pub reason: String,
    pub options: Vec<microclaw_core::runtime_event::RuntimeApprovalOption>,
    pub advisory: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkEventKind {
    System,
    Plan,
    Tool,
    Approval,
    Verification,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkEvent {
    pub id: u64,
    pub kind: WorkEventKind,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolActivityStatus {
    Running,
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkReviewStatus {
    #[default]
    None,
    Pending,
    Accepted,
    Reverted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolActivity {
    pub call_id: String,
    pub name: String,
    pub input_preview: String,
    pub status: ToolActivityStatus,
    pub result_preview: Option<String>,
    pub duration_ms: Option<u128>,
    pub status_code: Option<i32>,
    pub bytes: Option<usize>,
    pub error_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileChange {
    pub path: String,
    pub diff: String,
    pub added: usize,
    pub removed: usize,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubagentActivity {
    pub run_id: String,
    pub label: String,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum WorkCommand {
    StartTask {
        task: String,
    },
    SetTaskDraft {
        task: String,
    },
    SetWorkspace {
        path: String,
    },
    RecordProgress {
        kind: WorkEventKind,
        message: String,
        completed_step: Option<usize>,
    },
    RecordSteering {
        message: String,
    },
    RequestApproval {
        reason: String,
    },
    Approve,
    ResolveApproval {
        value: String,
    },
    ApplyRuntimeEvent(RuntimeEventEnvelope),
    FailRun {
        message: String,
    },
    CancelRun,
    MarkInterrupted,
    AcceptChanges,
    MarkReverted,
    PrepareFollowUp,
    ResetDemo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandOutcome {
    pub previous_status: WorkStatus,
    pub current_status: WorkStatus,
    pub latest_event_id: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WorkCommandError {
    #[error("task must not be empty")]
    EmptyTask,
    #[error("steering update must not be empty")]
    EmptySteering,
    #[error("approval option is unavailable: {value}")]
    UnknownApprovalOption { value: String },
    #[error("workspace is not an accessible directory: {path}")]
    InvalidWorkspace { path: String },
    #[error("cannot {command} while Work status is {actual:?}")]
    InvalidStatus {
        command: &'static str,
        actual: WorkStatus,
    },
    #[error("unsupported runtime event schema {actual}, expected {expected}")]
    UnsupportedRuntimeEventSchema { actual: u32, expected: u32 },
    #[error("runtime event sequence for {run_id} must be {expected}, got {actual}")]
    UnexpectedRuntimeEventSequence {
        run_id: String,
        expected: u64,
        actual: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WorkArtifactError {
    #[error("no workspace is selected")]
    WorkspaceNotSelected,
    #[error("artifact is unavailable: {path}")]
    Unavailable { path: String },
    #[error("artifact is outside the selected workspace: {path}")]
    OutsideWorkspace { path: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkSessionSnapshot {
    pub schema_version: u32,
    pub session_id: String,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub workspace: String,
    #[serde(default)]
    pub title: String,
    pub task: String,
    pub status: WorkStatus,
    pub plan: Vec<PlanStep>,
    pub approval_reason: Option<String>,
    #[serde(default)]
    pub pending_approval: Option<WorkApproval>,
    pub diff_summary: String,
    #[serde(default)]
    pub tool_activities: Vec<ToolActivity>,
    #[serde(default)]
    pub file_changes: Vec<FileChange>,
    #[serde(default)]
    pub subagents: Vec<SubagentActivity>,
    #[serde(default)]
    pub final_response: Option<String>,
    #[serde(default)]
    pub baseline_checkpoint: Option<String>,
    #[serde(default)]
    pub review_status: WorkReviewStatus,
    #[serde(default)]
    pub runtime_run_id: Option<String>,
    #[serde(default)]
    pub last_runtime_sequence: u64,
    #[serde(default)]
    pub events: Vec<WorkEvent>,
}

impl WorkSessionSnapshot {
    pub const SCHEMA_VERSION: u32 = 9;
    pub const MAX_EVENTS: usize = 200;
    pub const MAX_TOOL_ACTIVITIES: usize = 100;
    pub const MAX_FILE_CHANGES: usize = 50;
    pub const MAX_SUBAGENTS: usize = 50;

    pub fn new(workspace: impl Into<String>) -> Self {
        let now = current_time_ms();
        Self {
            schema_version: Self::SCHEMA_VERSION,
            session_id: new_session_id(now),
            created_at_ms: now,
            updated_at_ms: now,
            workspace: workspace.into(),
            title: String::new(),
            task: String::new(),
            status: WorkStatus::Planning,
            plan: Vec::new(),
            approval_reason: None,
            pending_approval: None,
            diff_summary: String::new(),
            tool_activities: Vec::new(),
            file_changes: Vec::new(),
            subagents: Vec::new(),
            final_response: None,
            baseline_checkpoint: None,
            review_status: WorkReviewStatus::None,
            runtime_run_id: None,
            last_runtime_sequence: 0,
            events: Vec::new(),
        }
    }

    pub fn spike_demo() -> Self {
        let now = current_time_ms();
        Self {
            schema_version: Self::SCHEMA_VERSION,
            session_id: new_session_id(now),
            created_at_ms: now,
            updated_at_ms: now,
            workspace: String::new(),
            title: "Build a native desktop workflow for MicroClaw Work".into(),
            task: "Build a native desktop workflow for MicroClaw Work".into(),
            status: WorkStatus::AwaitingApproval,
            plan: vec![
                PlanStep {
                    title: "Understand the workspace and task".into(),
                    status: RuntimePlanStepStatus::Completed,
                },
                PlanStep {
                    title: "Build the GPUI work interface".into(),
                    status: RuntimePlanStepStatus::InProgress,
                },
                PlanStep {
                    title: "Approve file changes".into(),
                    status: RuntimePlanStepStatus::Pending,
                },
                PlanStep {
                    title: "Run verification and deliver artifacts".into(),
                    status: RuntimePlanStepStatus::Pending,
                },
            ],
            approval_reason: Some("Allow writes to apps/microclaw-work and run cargo check".into()),
            pending_approval: Some(demo_approval()),
            diff_summary: "+ GPUI app shell\n+ resumable session projection\n+ approval surface"
                .into(),
            tool_activities: vec![ToolActivity {
                call_id: "demo-read".into(),
                name: "read_file".into(),
                input_preview: "{\"path\":\"Cargo.toml\"}".into(),
                status: ToolActivityStatus::Succeeded,
                result_preview: Some("Read Cargo workspace configuration".into()),
                duration_ms: Some(18),
                status_code: None,
                bytes: Some(2048),
                error_type: None,
            }],
            file_changes: Vec::new(),
            subagents: Vec::new(),
            final_response: None,
            baseline_checkpoint: None,
            review_status: WorkReviewStatus::None,
            runtime_run_id: None,
            last_runtime_sequence: 0,
            events: vec![
                WorkEvent {
                    id: 1,
                    kind: WorkEventKind::System,
                    message: "Restored the Work session".into(),
                },
                WorkEvent {
                    id: 2,
                    kind: WorkEventKind::Approval,
                    message: "A tool requested access to write desktop prototype files".into(),
                },
            ],
        }
    }

    fn push_event(&mut self, kind: WorkEventKind, message: impl Into<String>) {
        let id = self.events.last().map_or(1, |event| event.id + 1);
        self.events.push(WorkEvent {
            id,
            kind,
            message: message.into(),
        });
        let overflow = self.events.len().saturating_sub(Self::MAX_EVENTS);
        if overflow > 0 {
            self.events.drain(..overflow);
        }
    }

    pub fn apply(&mut self, command: WorkCommand) -> Result<CommandOutcome, WorkCommandError> {
        let previous_status = self.status;
        match command {
            WorkCommand::StartTask { task } => self.start_task(task)?,
            WorkCommand::SetTaskDraft { task } => self.task = task,
            WorkCommand::SetWorkspace { path } => self.set_workspace(path)?,
            WorkCommand::RecordProgress {
                kind,
                message,
                completed_step,
            } => {
                self.require_status("record progress", WorkStatus::Running)?;
                self.record_progress(kind, message, completed_step);
            }
            WorkCommand::RecordSteering { message } => self.record_steering(message)?,
            WorkCommand::RequestApproval { reason } => {
                self.require_status("request approval", WorkStatus::Running)?;
                self.request_approval(reason);
            }
            WorkCommand::Approve => {
                self.require_status("approve", WorkStatus::AwaitingApproval)?;
                self.resolve_approval("1")?;
            }
            WorkCommand::ResolveApproval { value } => {
                self.require_status("resolve approval", WorkStatus::AwaitingApproval)?;
                self.resolve_approval(&value)?;
            }
            WorkCommand::ApplyRuntimeEvent(envelope) => self.apply_runtime_event(envelope)?,
            WorkCommand::FailRun { message } => self.fail_run(message),
            WorkCommand::CancelRun => self.cancel_run()?,
            WorkCommand::MarkInterrupted => self.mark_interrupted()?,
            WorkCommand::AcceptChanges => self.finish_review(WorkReviewStatus::Accepted)?,
            WorkCommand::MarkReverted => self.finish_review(WorkReviewStatus::Reverted)?,
            WorkCommand::PrepareFollowUp => self.prepare_follow_up()?,
            WorkCommand::ResetDemo => self.reset_demo(),
        }
        self.touch();
        Ok(CommandOutcome {
            previous_status,
            current_status: self.status,
            latest_event_id: self.events.last().map(|event| event.id),
        })
    }

    fn require_status(
        &self,
        command: &'static str,
        expected: WorkStatus,
    ) -> Result<(), WorkCommandError> {
        if self.status == expected {
            Ok(())
        } else {
            Err(WorkCommandError::InvalidStatus {
                command,
                actual: self.status,
            })
        }
    }

    fn start_task(&mut self, task: String) -> Result<(), WorkCommandError> {
        if task.trim().is_empty() {
            return Err(WorkCommandError::EmptyTask);
        }
        self.task = task;
        if self.title.trim().is_empty() {
            self.title = self.task.clone();
        }
        self.status = WorkStatus::Running;
        self.approval_reason = None;
        self.pending_approval = None;
        self.runtime_run_id = None;
        self.last_runtime_sequence = 0;
        self.events.clear();
        self.tool_activities.clear();
        self.file_changes.clear();
        self.subagents.clear();
        self.final_response = None;
        self.baseline_checkpoint = None;
        self.review_status = WorkReviewStatus::None;
        self.diff_summary.clear();
        self.plan.clear();
        self.push_event(WorkEventKind::System, "Created a foreground Work task");
        Ok(())
    }

    fn reset_demo(&mut self) {
        let session_id = self.session_id.clone();
        let workspace = self.workspace.clone();
        let created_at_ms = self.created_at_ms;
        *self = Self::spike_demo();
        self.session_id = session_id;
        self.workspace = workspace;
        self.created_at_ms = created_at_ms;
    }

    fn set_workspace(&mut self, path: String) -> Result<(), WorkCommandError> {
        let candidate = Path::new(&path);
        let canonical = candidate
            .canonicalize()
            .map_err(|_| WorkCommandError::InvalidWorkspace { path: path.clone() })?;
        if !canonical.is_dir() {
            return Err(WorkCommandError::InvalidWorkspace { path });
        }
        self.workspace = canonical.display().to_string();
        self.push_event(
            WorkEventKind::System,
            format!("Workspace changed to {}", self.workspace),
        );
        Ok(())
    }

    fn record_progress(
        &mut self,
        kind: WorkEventKind,
        message: impl Into<String>,
        completed_step: Option<usize>,
    ) {
        if let Some(step) = completed_step.and_then(|index| self.plan.get_mut(index)) {
            step.status = RuntimePlanStepStatus::Completed;
        }
        self.push_event(kind, message);
    }

    fn request_approval(&mut self, reason: impl Into<String>) {
        self.status = WorkStatus::AwaitingApproval;
        let reason = reason.into();
        self.approval_reason = Some(reason.clone());
        self.pending_approval = Some(WorkApproval {
            approval_id: "local-approval".into(),
            tool: "workspace changes".into(),
            reason,
            options: default_approval_options("workspace changes"),
            advisory: None,
        });
        self.push_event(
            WorkEventKind::Approval,
            "Waiting for approval to modify files",
        );
    }

    fn record_steering(&mut self, message: String) -> Result<(), WorkCommandError> {
        if !matches!(self.status, WorkStatus::Running | WorkStatus::Verifying) {
            return Err(WorkCommandError::InvalidStatus {
                command: "steer task",
                actual: self.status,
            });
        }
        let message = message.trim();
        if message.is_empty() {
            return Err(WorkCommandError::EmptySteering);
        }
        let end = microclaw_core::text::floor_char_boundary(message, message.len().min(2_000));
        self.push_event(
            WorkEventKind::System,
            format!("Steering update: {}", &message[..end]),
        );
        Ok(())
    }

    fn resolve_approval(&mut self, value: &str) -> Result<(), WorkCommandError> {
        let (label, decision) = self
            .pending_approval
            .as_ref()
            .and_then(|approval| approval.options.iter().find(|option| option.value == value))
            .map(|option| (option.label.clone(), option.decision))
            .ok_or_else(|| WorkCommandError::UnknownApprovalOption {
                value: value.to_string(),
            })?;
        self.status = if decision == microclaw_core::runtime_event::RuntimeApprovalDecision::Deny {
            WorkStatus::Running
        } else {
            WorkStatus::Verifying
        };
        self.approval_reason = None;
        self.pending_approval = None;
        self.push_event(
            WorkEventKind::Approval,
            format!("Approval response: {label}"),
        );
        if self.status == WorkStatus::Verifying {
            self.push_event(
                WorkEventKind::Verification,
                "Approved the requested action; resuming the Agent",
            );
        }
        Ok(())
    }

    fn fail_run(&mut self, message: impl Into<String>) {
        self.status = WorkStatus::Failed;
        self.approval_reason = None;
        self.pending_approval = None;
        self.push_event(
            WorkEventKind::System,
            format!("Task failed: {}", message.into()),
        );
    }

    fn cancel_run(&mut self) -> Result<(), WorkCommandError> {
        if !matches!(
            self.status,
            WorkStatus::Running | WorkStatus::AwaitingApproval | WorkStatus::Verifying
        ) {
            return Err(WorkCommandError::InvalidStatus {
                command: "cancel run",
                actual: self.status,
            });
        }
        self.status = WorkStatus::Cancelled;
        self.approval_reason = None;
        self.pending_approval = None;
        self.push_event(
            WorkEventKind::System,
            "Requested cancellation of the current task",
        );
        Ok(())
    }

    fn mark_interrupted(&mut self) -> Result<(), WorkCommandError> {
        if !matches!(self.status, WorkStatus::Running | WorkStatus::Verifying) {
            return Err(WorkCommandError::InvalidStatus {
                command: "mark interrupted",
                actual: self.status,
            });
        }
        self.status = WorkStatus::Interrupted;
        self.approval_reason = None;
        self.pending_approval = None;
        self.push_event(
            WorkEventKind::System,
            "The previous desktop process exited before this task finished",
        );
        Ok(())
    }

    fn finish_review(&mut self, status: WorkReviewStatus) -> Result<(), WorkCommandError> {
        if self.status != WorkStatus::Completed || self.review_status != WorkReviewStatus::Pending {
            return Err(WorkCommandError::InvalidStatus {
                command: match status {
                    WorkReviewStatus::Accepted => "accept changes",
                    WorkReviewStatus::Reverted => "mark changes reverted",
                    _ => "finish review",
                },
                actual: self.status,
            });
        }
        self.review_status = status;
        self.push_event(
            WorkEventKind::System,
            match status {
                WorkReviewStatus::Accepted => "Accepted the completed workspace changes",
                WorkReviewStatus::Reverted => "Restored the pre-task workspace checkpoint",
                _ => unreachable!(),
            },
        );
        Ok(())
    }

    fn prepare_follow_up(&mut self) -> Result<(), WorkCommandError> {
        if self.status != WorkStatus::Completed {
            return Err(WorkCommandError::InvalidStatus {
                command: "continue task",
                actual: self.status,
            });
        }
        self.status = WorkStatus::Planning;
        self.task.clear();
        self.review_status = WorkReviewStatus::None;
        self.push_event(
            WorkEventKind::System,
            "Prepared a follow-up in the same Agent Engine session",
        );
        Ok(())
    }

    fn apply_runtime_event(
        &mut self,
        envelope: RuntimeEventEnvelope,
    ) -> Result<(), WorkCommandError> {
        if envelope.schema_version != RuntimeEventEnvelope::SCHEMA_VERSION {
            return Err(WorkCommandError::UnsupportedRuntimeEventSchema {
                actual: envelope.schema_version,
                expected: RuntimeEventEnvelope::SCHEMA_VERSION,
            });
        }

        let expected = if self.runtime_run_id.as_deref() == Some(envelope.run_id.as_str()) {
            self.last_runtime_sequence.saturating_add(1)
        } else {
            1
        };
        if envelope.sequence != expected {
            return Err(WorkCommandError::UnexpectedRuntimeEventSequence {
                run_id: envelope.run_id,
                expected,
                actual: envelope.sequence,
            });
        }

        self.runtime_run_id = Some(envelope.run_id);
        self.last_runtime_sequence = envelope.sequence;
        match envelope.event {
            RuntimeEvent::Iteration { iteration } => {
                self.status = WorkStatus::Running;
                self.push_event(
                    WorkEventKind::System,
                    format!("Agent iteration {iteration}"),
                );
            }
            RuntimeEvent::ToolStart {
                call_id,
                name,
                input,
            } => {
                self.status = WorkStatus::Running;
                self.tool_activities.push(ToolActivity {
                    call_id,
                    name: name.clone(),
                    input_preview: tool_input_preview(&input),
                    status: ToolActivityStatus::Running,
                    result_preview: None,
                    duration_ms: None,
                    status_code: None,
                    bytes: None,
                    error_type: None,
                });
                trim_front(&mut self.tool_activities, Self::MAX_TOOL_ACTIVITIES);
                self.push_event(WorkEventKind::Tool, format!("Started tool: {name}"));
            }
            RuntimeEvent::ToolResult {
                call_id,
                name,
                is_error,
                preview,
                duration_ms,
                status_code,
                bytes,
                error_type,
            } => {
                if let Some(activity) = self
                    .tool_activities
                    .iter_mut()
                    .rev()
                    .find(|activity| activity.call_id == call_id)
                {
                    activity.status = if is_error {
                        ToolActivityStatus::Failed
                    } else {
                        ToolActivityStatus::Succeeded
                    };
                    activity.result_preview =
                        Some(microclaw_core::redact::redact_secrets(&preview));
                    activity.duration_ms = Some(duration_ms);
                    activity.status_code = status_code;
                    activity.bytes = Some(bytes);
                    activity.error_type = error_type;
                } else {
                    self.tool_activities.push(ToolActivity {
                        call_id,
                        name: name.clone(),
                        input_preview: String::new(),
                        status: if is_error {
                            ToolActivityStatus::Failed
                        } else {
                            ToolActivityStatus::Succeeded
                        },
                        result_preview: Some(microclaw_core::redact::redact_secrets(&preview)),
                        duration_ms: Some(duration_ms),
                        status_code,
                        bytes: Some(bytes),
                        error_type,
                    });
                    trim_front(&mut self.tool_activities, Self::MAX_TOOL_ACTIVITIES);
                }
                let outcome = if is_error { "failed" } else { "completed" };
                self.push_event(
                    WorkEventKind::Tool,
                    format!("Tool {name} {outcome}: {preview}"),
                );
            }
            RuntimeEvent::TextDelta { delta } => {
                if !delta.is_empty() {
                    self.push_event(WorkEventKind::System, delta);
                }
            }
            RuntimeEvent::ToolWaveStart { wave, tool_count } => self.push_event(
                WorkEventKind::Tool,
                format!("Started tool wave {wave} ({tool_count} tools)"),
            ),
            RuntimeEvent::ToolWaveComplete { wave } => {
                self.push_event(WorkEventKind::Tool, format!("Tool wave {wave} completed"))
            }
            RuntimeEvent::Cancelled { final_text } => {
                self.status = WorkStatus::Cancelled;
                self.approval_reason = None;
                self.pending_approval = None;
                self.push_event(
                    WorkEventKind::System,
                    format!("Task cancelled: {final_text}"),
                );
            }
            RuntimeEvent::FinalResponse { text } => {
                if self.status == WorkStatus::AwaitingApproval {
                    self.push_event(WorkEventKind::System, text);
                } else {
                    self.status = WorkStatus::Completed;
                    self.final_response = Some(text.clone());
                    self.review_status =
                        if self.baseline_checkpoint.is_some() && !self.file_changes.is_empty() {
                            WorkReviewStatus::Pending
                        } else {
                            WorkReviewStatus::None
                        };
                    self.approval_reason = None;
                    self.pending_approval = None;
                    self.push_event(WorkEventKind::System, format!("Task completed: {text}"));
                }
            }
            RuntimeEvent::MidTurnInjection { count } => self.push_event(
                WorkEventKind::System,
                format!("Received {count} task updates"),
            ),
            RuntimeEvent::FileDiff {
                path,
                diff,
                added,
                removed,
                truncated,
            } => {
                self.diff_summary = format!(
                    "{path}: +{added} -{removed}{}",
                    if truncated { " (truncated)" } else { "" }
                );
                self.file_changes.retain(|change| change.path != path);
                self.file_changes.push(FileChange {
                    path: path.clone(),
                    diff: microclaw_core::redact::redact_secrets(&diff),
                    added,
                    removed,
                    truncated,
                });
                trim_front(&mut self.file_changes, Self::MAX_FILE_CHANGES);
                self.push_event(WorkEventKind::Tool, format!("File changed: {path}"));
            }
            RuntimeEvent::SubagentStarted { run_id, label } => {
                self.subagents.push(SubagentActivity {
                    run_id: run_id.clone(),
                    label: label.clone(),
                    status: "running".into(),
                });
                trim_front(&mut self.subagents, Self::MAX_SUBAGENTS);
                self.push_event(
                    WorkEventKind::System,
                    format!("Subagent {label} started ({run_id})"),
                );
            }
            RuntimeEvent::SubagentFinished { run_id, status } => {
                if let Some(activity) = self
                    .subagents
                    .iter_mut()
                    .rev()
                    .find(|activity| activity.run_id == run_id)
                {
                    activity.status = status.clone();
                }
                self.push_event(
                    WorkEventKind::System,
                    format!("Subagent {run_id} finished: {status}"),
                );
            }
            RuntimeEvent::ApprovalRequired {
                approval_id,
                tool,
                preview,
                options,
                advisory,
            } => {
                self.status = WorkStatus::AwaitingApproval;
                let reason = preview.unwrap_or_else(|| format!("Tool {tool} requested permission"));
                self.approval_reason = Some(reason.clone());
                let options = sanitize_approval_options(options, &tool);
                self.pending_approval = Some(WorkApproval {
                    approval_id: approval_id.clone(),
                    tool,
                    reason: reason.clone(),
                    options,
                    advisory: advisory.map(|text| trim_owned(text, 2_000)),
                });
                self.push_event(
                    WorkEventKind::Approval,
                    format!("Awaiting approval {approval_id}: {reason}"),
                );
            }
            RuntimeEvent::CheckpointCreated { commit, label } => {
                if self.baseline_checkpoint.is_none() {
                    self.baseline_checkpoint = Some(commit.clone());
                    self.push_event(
                        WorkEventKind::System,
                        format!("Created pre-task checkpoint {commit}: {label}"),
                    );
                }
            }
            RuntimeEvent::PlanUpdated { steps } => {
                self.plan = steps
                    .into_iter()
                    .take(100)
                    .map(|step| PlanStep {
                        title: step.title,
                        status: step.status,
                    })
                    .collect();
                self.push_event(
                    WorkEventKind::Plan,
                    format!("Agent updated the plan ({} steps)", self.plan.len()),
                );
            }
        }
        Ok(())
    }

    pub fn save(&self, path: impl AsRef<Path>) -> io::Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec_pretty(self).map_err(io::Error::other)?;
        let temporary = path.with_extension("tmp");
        fs::write(&temporary, bytes)?;
        fs::rename(temporary, path)
    }

    pub(crate) fn touch(&mut self) {
        self.updated_at_ms = current_time_ms().max(self.updated_at_ms.saturating_add(1));
    }

    pub fn resolve_artifact_path(
        &self,
        path: &str,
    ) -> Result<std::path::PathBuf, WorkArtifactError> {
        if self.workspace.is_empty() {
            return Err(WorkArtifactError::WorkspaceNotSelected);
        }
        let workspace = Path::new(&self.workspace).canonicalize().map_err(|_| {
            WorkArtifactError::Unavailable {
                path: self.workspace.clone(),
            }
        })?;
        let candidate = Path::new(path);
        let candidate = if candidate.is_absolute() {
            candidate.to_path_buf()
        } else {
            workspace.join(candidate)
        };
        let canonical = candidate
            .canonicalize()
            .map_err(|_| WorkArtifactError::Unavailable {
                path: path.to_string(),
            })?;
        if !canonical.starts_with(&workspace) {
            return Err(WorkArtifactError::OutsideWorkspace {
                path: path.to_string(),
            });
        }
        Ok(canonical)
    }

    pub fn load(path: impl AsRef<Path>) -> io::Result<Self> {
        let bytes = fs::read(path)?;
        let mut snapshot: Self = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        if (5..Self::SCHEMA_VERSION).contains(&snapshot.schema_version) {
            if snapshot.schema_version < 8 {
                snapshot.plan.clear();
            }
            snapshot.schema_version = Self::SCHEMA_VERSION;
        } else if snapshot.schema_version != Self::SCHEMA_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unsupported work session schema {}, expected {}",
                    snapshot.schema_version,
                    Self::SCHEMA_VERSION
                ),
            ));
        }
        if snapshot.title.trim().is_empty() {
            snapshot.title = snapshot.task.clone();
        }
        if snapshot.status == WorkStatus::AwaitingApproval && snapshot.pending_approval.is_none() {
            let reason = snapshot
                .approval_reason
                .clone()
                .unwrap_or_else(|| "The active task requested permission".into());
            snapshot.pending_approval = Some(WorkApproval {
                approval_id: "migrated-approval".into(),
                tool: "pending action".into(),
                reason,
                options: default_approval_options("pending action"),
                advisory: None,
            });
        }
        Ok(snapshot)
    }
}

fn default_approval_options(
    tool: &str,
) -> Vec<microclaw_core::runtime_event::RuntimeApprovalOption> {
    use microclaw_core::runtime_event::{
        RuntimeApprovalDecision, RuntimeApprovalOption, RuntimeApprovalOptionKind,
    };
    vec![
        RuntimeApprovalOption {
            value: "1".into(),
            label: "Approve once".into(),
            kind: RuntimeApprovalOptionKind::Primary,
            decision: RuntimeApprovalDecision::Approve,
        },
        RuntimeApprovalOption {
            value: "2".into(),
            label: format!("Always allow '{tool}' in this chat"),
            kind: RuntimeApprovalOptionKind::Secondary,
            decision: RuntimeApprovalDecision::Approve,
        },
        RuntimeApprovalOption {
            value: "3".into(),
            label: "Deny".into(),
            kind: RuntimeApprovalOptionKind::Danger,
            decision: RuntimeApprovalDecision::Deny,
        },
    ]
}

fn demo_approval() -> WorkApproval {
    WorkApproval {
        approval_id: "demo-approval".into(),
        tool: "workspace changes".into(),
        reason: "Allow writes to apps/microclaw-work and run cargo check".into(),
        options: default_approval_options("workspace changes"),
        advisory: Some(
            "Demo only: review the requested scope before choosing a durable allowance.".into(),
        ),
    }
}

fn sanitize_approval_options(
    options: Vec<microclaw_core::runtime_event::RuntimeApprovalOption>,
    tool: &str,
) -> Vec<microclaw_core::runtime_event::RuntimeApprovalOption> {
    let mut seen = std::collections::HashSet::new();
    let options = options
        .into_iter()
        .filter_map(|mut option| {
            option.value = trim_owned(option.value, 32);
            option.label = trim_owned(option.label, 160);
            if option.value.is_empty()
                || option.label.is_empty()
                || !seen.insert(option.value.clone())
            {
                None
            } else {
                Some(option)
            }
        })
        .take(5)
        .collect::<Vec<_>>();
    if options.is_empty() {
        default_approval_options(tool)
    } else {
        options
    }
}

fn trim_owned(value: String, max_bytes: usize) -> String {
    let value = value.trim();
    let end = microclaw_core::text::floor_char_boundary(value, value.len().min(max_bytes));
    value[..end].to_string()
}

fn current_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis() as u64)
}

fn new_session_id(now: u64) -> String {
    let counter = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
    format!("session-{now}-{}-{counter}", std::process::id())
}

fn tool_input_preview(input: &serde_json::Value) -> String {
    let serialized = serde_json::to_string(input).unwrap_or_else(|_| "{}".into());
    let redacted = microclaw_core::redact::redact_secrets(&serialized);
    redacted.chars().take(240).collect()
}

fn trim_front<T>(items: &mut Vec<T>, limit: usize) {
    let overflow = items.len().saturating_sub(limit);
    if overflow > 0 {
        items.drain(..overflow);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_round_trips() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        let path = directory.path().join("session.json");
        let expected = WorkSessionSnapshot::spike_demo();

        expected.save(&path).expect("save session");
        let actual = WorkSessionSnapshot::load(&path).expect("load session");

        assert_eq!(actual, expected);
    }

    #[test]
    fn rejects_unknown_schema() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        let path = directory.path().join("session.json");
        let mut snapshot = WorkSessionSnapshot::spike_demo();
        snapshot.schema_version += 1;
        fs::write(&path, serde_json::to_vec(&snapshot).unwrap()).unwrap();

        let error = WorkSessionSnapshot::load(&path).expect_err("schema should be rejected");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn loads_v5_snapshot_with_defaulted_structured_fields() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        let path = directory.path().join("session.json");
        let mut value = serde_json::to_value(WorkSessionSnapshot::spike_demo()).unwrap();
        let object = value.as_object_mut().unwrap();
        object.insert("schema_version".into(), 5.into());
        object.remove("tool_activities");
        object.remove("file_changes");
        object.remove("subagents");
        object.remove("final_response");
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();

        let snapshot = WorkSessionSnapshot::load(&path).expect("v5 should migrate");
        assert_eq!(snapshot.schema_version, WorkSessionSnapshot::SCHEMA_VERSION);
        assert!(snapshot.tool_activities.is_empty());
        assert!(snapshot.file_changes.is_empty());
        assert!(snapshot.subagents.is_empty());
        assert!(snapshot.final_response.is_none());
    }

    #[test]
    fn event_projection_is_bounded_and_monotonic() {
        let mut snapshot = WorkSessionSnapshot::spike_demo();
        snapshot.events.clear();

        for index in 0..(WorkSessionSnapshot::MAX_EVENTS + 25) {
            snapshot.push_event(WorkEventKind::Tool, format!("event {index}"));
        }

        assert_eq!(snapshot.events.len(), WorkSessionSnapshot::MAX_EVENTS);
        assert_eq!(snapshot.events.first().unwrap().id, 26);
        assert_eq!(snapshot.events.last().unwrap().id, 225);
    }

    #[test]
    fn runtime_plan_replaces_placeholder_free_projection_and_is_durable() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        let path = directory.path().join("session.json");
        let mut snapshot = WorkSessionSnapshot::new("");
        assert!(snapshot.plan.is_empty());

        snapshot
            .apply(WorkCommand::ApplyRuntimeEvent(RuntimeEventEnvelope::new(
                "plan-run",
                1,
                RuntimeEvent::PlanUpdated {
                    steps: vec![
                        microclaw_core::runtime_event::RuntimePlanStep {
                            title: "Inspect the workspace".into(),
                            status: RuntimePlanStepStatus::Completed,
                        },
                        microclaw_core::runtime_event::RuntimePlanStep {
                            title: "Implement the feature".into(),
                            status: RuntimePlanStepStatus::InProgress,
                        },
                    ],
                },
            )))
            .unwrap();
        snapshot.save(&path).unwrap();
        let restored = WorkSessionSnapshot::load(&path).unwrap();

        assert_eq!(restored.plan.len(), 2);
        assert_eq!(restored.plan[1].title, "Implement the feature");
        assert_eq!(restored.plan[1].status, RuntimePlanStepStatus::InProgress);
        assert_eq!(restored.events.last().unwrap().kind, WorkEventKind::Plan);
    }

    #[test]
    fn steering_is_accepted_only_for_an_active_task_and_persists() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        let path = directory.path().join("session.json");
        let mut snapshot = WorkSessionSnapshot::new("");
        assert!(matches!(
            snapshot.apply(WorkCommand::RecordSteering {
                message: "Too early".into(),
            }),
            Err(WorkCommandError::InvalidStatus { .. })
        ));

        snapshot
            .apply(WorkCommand::StartTask {
                task: "Refactor the parser".into(),
            })
            .unwrap();
        assert_eq!(
            snapshot.apply(WorkCommand::RecordSteering {
                message: "   ".into(),
            }),
            Err(WorkCommandError::EmptySteering)
        );
        snapshot
            .apply(WorkCommand::RecordSteering {
                message: "Keep the public API small".into(),
            })
            .unwrap();
        snapshot.save(&path).unwrap();
        let restored = WorkSessionSnapshot::load(&path).unwrap();

        assert_eq!(restored.events.last().unwrap().kind, WorkEventKind::System);
        assert_eq!(
            restored.events.last().unwrap().message,
            "Steering update: Keep the public API small"
        );
    }

    #[test]
    fn foreground_lifecycle_pauses_for_approval_and_resumes_verification() {
        let mut snapshot = WorkSessionSnapshot::spike_demo();

        snapshot
            .apply(WorkCommand::StartTask {
                task: "Implement task input".into(),
            })
            .unwrap();
        snapshot
            .apply(WorkCommand::RecordProgress {
                kind: WorkEventKind::Plan,
                message: "Generated a plan".into(),
                completed_step: Some(0),
            })
            .unwrap();
        snapshot
            .apply(WorkCommand::RequestApproval {
                reason: "Allow workspace changes".into(),
            })
            .unwrap();

        assert_eq!(snapshot.status, WorkStatus::AwaitingApproval);
        assert_eq!(
            snapshot.approval_reason.as_deref(),
            Some("Allow workspace changes")
        );

        snapshot.apply(WorkCommand::Approve).unwrap();

        assert_eq!(snapshot.status, WorkStatus::Verifying);
        assert!(snapshot.approval_reason.is_none());
        assert!(snapshot.plan.is_empty());
        assert_eq!(
            snapshot.events.last().unwrap().kind,
            WorkEventKind::Verification
        );
    }

    #[test]
    fn rejects_invalid_approval_transition() {
        let mut snapshot = WorkSessionSnapshot::spike_demo();
        snapshot
            .apply(WorkCommand::StartTask {
                task: "A task that is still running".into(),
            })
            .unwrap();

        let error = snapshot.apply(WorkCommand::Approve).unwrap_err();

        assert_eq!(
            error,
            WorkCommandError::InvalidStatus {
                command: "approve",
                actual: WorkStatus::Running,
            }
        );
    }

    #[test]
    fn structured_approval_rejects_unknown_values_and_denial_resumes_without_permission() {
        let mut snapshot = WorkSessionSnapshot::new("");
        snapshot
            .apply(WorkCommand::StartTask {
                task: "Run a guarded command".into(),
            })
            .unwrap();
        snapshot
            .apply(WorkCommand::ApplyRuntimeEvent(RuntimeEventEnvelope::new(
                "approval-run",
                1,
                RuntimeEvent::ApprovalRequired {
                    approval_id: "approval-42".into(),
                    tool: "bash".into(),
                    preview: Some("rm generated.tmp".into()),
                    options: default_approval_options("bash"),
                    advisory: Some("This command removes a file".into()),
                },
            )))
            .unwrap();

        assert!(matches!(
            snapshot.apply(WorkCommand::ResolveApproval {
                value: "unknown".into(),
            }),
            Err(WorkCommandError::UnknownApprovalOption { .. })
        ));
        assert_eq!(snapshot.status, WorkStatus::AwaitingApproval);
        assert!(snapshot.pending_approval.is_some());

        snapshot
            .apply(WorkCommand::ResolveApproval { value: "3".into() })
            .unwrap();
        assert_eq!(snapshot.status, WorkStatus::Running);
        assert!(snapshot.pending_approval.is_none());
        assert_eq!(
            snapshot.events.last().unwrap().message,
            "Approval response: Deny"
        );
    }

    #[test]
    fn shared_runtime_events_drive_approval_diff_and_completion() {
        let mut snapshot = WorkSessionSnapshot::new("/workspace");
        snapshot
            .apply(WorkCommand::StartTask {
                task: "edit a file".into(),
            })
            .unwrap();
        let events = [
            RuntimeEvent::FileDiff {
                path: "src/main.rs".into(),
                diff: "+fn main() {}".into(),
                added: 1,
                removed: 0,
                truncated: false,
            },
            RuntimeEvent::ApprovalRequired {
                approval_id: "approval-1".into(),
                tool: "bash".into(),
                preview: Some("run cargo test".into()),
                options: default_approval_options("bash"),
                advisory: Some("Review the command scope".into()),
            },
        ];
        for (index, event) in events.into_iter().enumerate() {
            snapshot
                .apply(WorkCommand::ApplyRuntimeEvent(RuntimeEventEnvelope::new(
                    "server-run-1",
                    index as u64 + 1,
                    event,
                )))
                .unwrap();
        }

        assert_eq!(snapshot.status, WorkStatus::AwaitingApproval);
        assert_eq!(
            snapshot.pending_approval.as_ref().unwrap().options[2].value,
            "3"
        );
        assert_eq!(
            snapshot
                .pending_approval
                .as_ref()
                .unwrap()
                .advisory
                .as_deref(),
            Some("Review the command scope")
        );
        snapshot
            .apply(WorkCommand::ResolveApproval { value: "1".into() })
            .unwrap();
        snapshot
            .apply(WorkCommand::ApplyRuntimeEvent(RuntimeEventEnvelope::new(
                "server-run-2",
                1,
                RuntimeEvent::FinalResponse {
                    text: "done".into(),
                },
            )))
            .unwrap();

        assert_eq!(snapshot.status, WorkStatus::Completed);
        assert_eq!(snapshot.diff_summary, "src/main.rs: +1 -0");
        assert_eq!(snapshot.last_runtime_sequence, 1);
        assert!(snapshot.approval_reason.is_none());
    }

    #[test]
    fn rejects_runtime_event_gaps_without_mutating_projection() {
        let mut snapshot = WorkSessionSnapshot::new("/workspace");
        snapshot
            .apply(WorkCommand::StartTask {
                task: "ordered events".into(),
            })
            .unwrap();

        let error = snapshot
            .apply(WorkCommand::ApplyRuntimeEvent(RuntimeEventEnvelope::new(
                "server-run-1",
                2,
                RuntimeEvent::Iteration { iteration: 1 },
            )))
            .unwrap_err();

        assert_eq!(
            error,
            WorkCommandError::UnexpectedRuntimeEventSequence {
                run_id: "server-run-1".into(),
                expected: 1,
                actual: 2,
            }
        );
        assert_eq!(snapshot.last_runtime_sequence, 0);
        assert!(snapshot.runtime_run_id.is_none());
    }

    #[test]
    fn final_explanation_does_not_clear_pending_approval() {
        let mut snapshot = WorkSessionSnapshot::new("/workspace");
        snapshot
            .apply(WorkCommand::StartTask {
                task: "dangerous task".into(),
            })
            .unwrap();
        snapshot
            .apply(WorkCommand::ApplyRuntimeEvent(RuntimeEventEnvelope::new(
                "run-approval",
                1,
                RuntimeEvent::ApprovalRequired {
                    approval_id: "approval-1".into(),
                    tool: "bash".into(),
                    preview: Some("run command".into()),
                    options: default_approval_options("bash"),
                    advisory: None,
                },
            )))
            .unwrap();
        snapshot
            .apply(WorkCommand::ApplyRuntimeEvent(RuntimeEventEnvelope::new(
                "run-approval",
                2,
                RuntimeEvent::FinalResponse {
                    text: "Please approve the command".into(),
                },
            )))
            .unwrap();

        assert_eq!(snapshot.status, WorkStatus::AwaitingApproval);
        assert_eq!(snapshot.approval_reason.as_deref(), Some("run command"));
    }

    #[test]
    fn runtime_failure_is_projected_as_terminal_state() {
        let mut snapshot = WorkSessionSnapshot::new("/workspace");
        snapshot
            .apply(WorkCommand::StartTask {
                task: "unavailable provider".into(),
            })
            .unwrap();

        snapshot
            .apply(WorkCommand::FailRun {
                message: "provider rejected model".into(),
            })
            .unwrap();

        assert_eq!(snapshot.status, WorkStatus::Failed);
        assert!(
            snapshot
                .events
                .last()
                .unwrap()
                .message
                .contains("provider rejected model")
        );
    }

    #[test]
    fn active_run_can_be_cancelled_but_completed_run_cannot() {
        let mut snapshot = WorkSessionSnapshot::new("/workspace");
        snapshot
            .apply(WorkCommand::StartTask {
                task: "long task".into(),
            })
            .unwrap();

        snapshot.apply(WorkCommand::CancelRun).unwrap();
        assert_eq!(snapshot.status, WorkStatus::Cancelled);
        assert!(snapshot.approval_reason.is_none());
        assert!(snapshot.apply(WorkCommand::CancelRun).is_err());
    }

    #[test]
    fn pending_approval_can_be_cancelled_without_resuming_the_runtime() {
        let mut snapshot = WorkSessionSnapshot::new("/workspace");
        snapshot
            .apply(WorkCommand::StartTask {
                task: "dangerous task".into(),
            })
            .unwrap();
        snapshot
            .apply(WorkCommand::RequestApproval {
                reason: "write file".into(),
            })
            .unwrap();

        snapshot.apply(WorkCommand::CancelRun).unwrap();
        assert_eq!(snapshot.status, WorkStatus::Cancelled);
        assert!(snapshot.approval_reason.is_none());
    }

    #[test]
    fn workspace_change_is_canonicalized_and_rejects_files() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("not-a-workspace.txt");
        std::fs::write(&file, "file").unwrap();
        let mut snapshot = WorkSessionSnapshot::new("/workspace");

        snapshot
            .apply(WorkCommand::SetWorkspace {
                path: directory.path().display().to_string(),
            })
            .unwrap();
        assert_eq!(
            Path::new(&snapshot.workspace),
            directory.path().canonicalize().unwrap()
        );
        assert!(
            snapshot
                .apply(WorkCommand::SetWorkspace {
                    path: file.display().to_string(),
                })
                .is_err()
        );
    }

    #[test]
    fn active_status_can_be_recovered_as_interrupted() {
        let mut snapshot = WorkSessionSnapshot::new("/workspace");
        snapshot
            .apply(WorkCommand::StartTask {
                task: "long task".into(),
            })
            .unwrap();

        snapshot.apply(WorkCommand::MarkInterrupted).unwrap();
        assert_eq!(snapshot.status, WorkStatus::Interrupted);
        assert!(
            snapshot
                .events
                .last()
                .unwrap()
                .message
                .contains("previous desktop process")
        );
    }

    #[test]
    fn demo_reset_preserves_session_identity_and_selected_workspace() {
        let directory = tempfile::tempdir().unwrap();
        let mut snapshot = WorkSessionSnapshot::new(directory.path().display().to_string());
        let session_id = snapshot.session_id.clone();
        let created_at_ms = snapshot.created_at_ms;

        snapshot.apply(WorkCommand::ResetDemo).unwrap();

        assert_eq!(snapshot.session_id, session_id);
        assert_eq!(snapshot.created_at_ms, created_at_ms);
        assert_eq!(snapshot.workspace, directory.path().display().to_string());
    }

    #[test]
    fn tool_activity_pairs_by_call_id_and_redacts_secrets() {
        let mut snapshot = WorkSessionSnapshot::new("/workspace");
        snapshot
            .apply(WorkCommand::StartTask {
                task: "run tools".into(),
            })
            .unwrap();
        snapshot
            .apply(WorkCommand::ApplyRuntimeEvent(RuntimeEventEnvelope::new(
                "run-tools",
                1,
                RuntimeEvent::ToolStart {
                    call_id: "call-a".into(),
                    name: "web_fetch".into(),
                    input: serde_json::json!({
                        "authorization": "Bearer abcdefghijklmnopqrstuvwxyz"
                    }),
                },
            )))
            .unwrap();
        snapshot
            .apply(WorkCommand::ApplyRuntimeEvent(RuntimeEventEnvelope::new(
                "run-tools",
                2,
                RuntimeEvent::ToolResult {
                    call_id: "call-a".into(),
                    name: "web_fetch".into(),
                    is_error: false,
                    preview: "used sk-abcdefghijklmnopqrstuvwxyz".into(),
                    duration_ms: 42,
                    status_code: Some(200),
                    bytes: 512,
                    error_type: None,
                },
            )))
            .unwrap();

        let activity = &snapshot.tool_activities[0];
        assert_eq!(activity.call_id, "call-a");
        assert_eq!(activity.status, ToolActivityStatus::Succeeded);
        assert_eq!(activity.duration_ms, Some(42));
        assert!(
            !activity
                .input_preview
                .contains("abcdefghijklmnopqrstuvwxyz")
        );
        assert!(
            !activity
                .result_preview
                .as_deref()
                .unwrap()
                .contains("abcdefghijklmnopqrstuvwxyz")
        );
    }

    #[test]
    fn file_changes_and_final_response_are_structured_artifacts() {
        let mut snapshot = WorkSessionSnapshot::new("/workspace");
        snapshot
            .apply(WorkCommand::StartTask {
                task: "edit file".into(),
            })
            .unwrap();
        snapshot
            .apply(WorkCommand::ApplyRuntimeEvent(RuntimeEventEnvelope::new(
                "run-artifacts",
                1,
                RuntimeEvent::FileDiff {
                    path: "src/main.rs".into(),
                    diff: "+fn main() {}".into(),
                    added: 1,
                    removed: 0,
                    truncated: false,
                },
            )))
            .unwrap();
        snapshot
            .apply(WorkCommand::ApplyRuntimeEvent(RuntimeEventEnvelope::new(
                "run-artifacts",
                2,
                RuntimeEvent::FinalResponse {
                    text: "Implemented and verified".into(),
                },
            )))
            .unwrap();

        assert_eq!(snapshot.file_changes[0].path, "src/main.rs");
        assert_eq!(snapshot.file_changes[0].added, 1);
        assert_eq!(
            snapshot.final_response.as_deref(),
            Some("Implemented and verified")
        );
    }

    #[test]
    fn completed_file_changes_require_explicit_review() {
        let mut snapshot = WorkSessionSnapshot::new("/workspace");
        snapshot
            .apply(WorkCommand::StartTask {
                task: "change a file".into(),
            })
            .unwrap();
        for (sequence, event) in [
            RuntimeEvent::CheckpointCreated {
                commit: "deadbeef".into(),
                label: "before task".into(),
            },
            RuntimeEvent::FileDiff {
                path: "src/main.rs".into(),
                diff: "+change".into(),
                added: 1,
                removed: 0,
                truncated: false,
            },
            RuntimeEvent::FinalResponse {
                text: "done".into(),
            },
        ]
        .into_iter()
        .enumerate()
        {
            snapshot
                .apply(WorkCommand::ApplyRuntimeEvent(RuntimeEventEnvelope::new(
                    "run-review",
                    sequence as u64 + 1,
                    event,
                )))
                .unwrap();
        }

        assert_eq!(snapshot.review_status, WorkReviewStatus::Pending);
        assert_eq!(snapshot.baseline_checkpoint.as_deref(), Some("deadbeef"));
        snapshot.apply(WorkCommand::AcceptChanges).unwrap();
        assert_eq!(snapshot.review_status, WorkReviewStatus::Accepted);
        assert!(snapshot.apply(WorkCommand::MarkReverted).is_err());
    }

    #[test]
    fn reverted_review_is_durable_and_new_task_resets_it() {
        let mut snapshot = WorkSessionSnapshot::new("/workspace");
        snapshot.status = WorkStatus::Completed;
        snapshot.review_status = WorkReviewStatus::Pending;
        snapshot.baseline_checkpoint = Some("deadbeef".into());

        snapshot.apply(WorkCommand::MarkReverted).unwrap();
        assert_eq!(snapshot.review_status, WorkReviewStatus::Reverted);
        snapshot
            .apply(WorkCommand::StartTask {
                task: "follow-up".into(),
            })
            .unwrap();
        assert_eq!(snapshot.title, "follow-up");
        assert_eq!(snapshot.review_status, WorkReviewStatus::None);
        assert!(snapshot.baseline_checkpoint.is_none());

        snapshot.status = WorkStatus::Completed;
        snapshot.apply(WorkCommand::PrepareFollowUp).unwrap();
        assert_eq!(snapshot.status, WorkStatus::Planning);
        assert!(snapshot.task.is_empty());
        assert_eq!(snapshot.title, "follow-up");
    }

    #[test]
    fn artifact_paths_must_resolve_inside_workspace() {
        let workspace = tempfile::tempdir().unwrap();
        let inside = workspace.path().join("artifact.txt");
        std::fs::write(&inside, "artifact").unwrap();
        let outside_dir = tempfile::tempdir().unwrap();
        let outside = outside_dir.path().join("secret.txt");
        std::fs::write(&outside, "secret").unwrap();
        let snapshot = WorkSessionSnapshot::new(workspace.path().display().to_string());

        assert_eq!(
            snapshot.resolve_artifact_path("artifact.txt").unwrap(),
            inside.canonicalize().unwrap()
        );
        assert!(matches!(
            snapshot
                .resolve_artifact_path(outside.to_str().unwrap())
                .unwrap_err(),
            WorkArtifactError::OutsideWorkspace { .. }
        ));
        assert!(matches!(
            snapshot.resolve_artifact_path("missing.txt").unwrap_err(),
            WorkArtifactError::Unavailable { .. }
        ));
    }
}
