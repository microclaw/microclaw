use microclaw_core::runtime_event::{RuntimeEvent, RuntimeEventEnvelope};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::Path;

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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanStep {
    pub title: String,
    pub completed: bool,
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

#[derive(Debug, Clone, PartialEq)]
pub enum WorkCommand {
    StartTask {
        task: String,
    },
    RecordProgress {
        kind: WorkEventKind,
        message: String,
        completed_step: Option<usize>,
    },
    RequestApproval {
        reason: String,
    },
    Approve,
    ApplyRuntimeEvent(RuntimeEventEnvelope),
    FailRun {
        message: String,
    },
    CancelRun,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkSessionSnapshot {
    pub schema_version: u32,
    pub workspace: String,
    pub task: String,
    pub status: WorkStatus,
    pub plan: Vec<PlanStep>,
    pub approval_reason: Option<String>,
    pub diff_summary: String,
    #[serde(default)]
    pub runtime_run_id: Option<String>,
    #[serde(default)]
    pub last_runtime_sequence: u64,
    #[serde(default)]
    pub events: Vec<WorkEvent>,
}

impl WorkSessionSnapshot {
    pub const SCHEMA_VERSION: u32 = 2;
    pub const MAX_EVENTS: usize = 200;

    pub fn new(workspace: impl Into<String>) -> Self {
        Self {
            schema_version: Self::SCHEMA_VERSION,
            workspace: workspace.into(),
            task: String::new(),
            status: WorkStatus::Planning,
            plan: vec![
                PlanStep {
                    title: "理解任务与工作区".into(),
                    completed: false,
                },
                PlanStep {
                    title: "执行任务".into(),
                    completed: false,
                },
                PlanStep {
                    title: "处理审批".into(),
                    completed: false,
                },
                PlanStep {
                    title: "验证并交付结果".into(),
                    completed: false,
                },
            ],
            approval_reason: None,
            diff_summary: String::new(),
            runtime_run_id: None,
            last_runtime_sequence: 0,
            events: Vec::new(),
        }
    }

    pub fn spike_demo() -> Self {
        Self {
            schema_version: Self::SCHEMA_VERSION,
            workspace: "~/github/microclaw".into(),
            task: "为 MicroClaw Work 建立原生桌面工作流".into(),
            status: WorkStatus::AwaitingApproval,
            plan: vec![
                PlanStep {
                    title: "理解 Workspace 和任务目标".into(),
                    completed: true,
                },
                PlanStep {
                    title: "建立 GPUI 工作界面".into(),
                    completed: true,
                },
                PlanStep {
                    title: "审批文件修改".into(),
                    completed: false,
                },
                PlanStep {
                    title: "运行验证并交付 Artifact".into(),
                    completed: false,
                },
            ],
            approval_reason: Some("允许写入 apps/microclaw-work 并运行 cargo check".into()),
            diff_summary: "+ GPUI app shell\n+ resumable session projection\n+ approval surface"
                .into(),
            runtime_run_id: None,
            last_runtime_sequence: 0,
            events: vec![
                WorkEvent {
                    id: 1,
                    kind: WorkEventKind::System,
                    message: "已恢复 Work Session".into(),
                },
                WorkEvent {
                    id: 2,
                    kind: WorkEventKind::Approval,
                    message: "工具请求写入桌面原型文件".into(),
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
            WorkCommand::RecordProgress {
                kind,
                message,
                completed_step,
            } => {
                self.require_status("record progress", WorkStatus::Running)?;
                self.record_progress(kind, message, completed_step);
            }
            WorkCommand::RequestApproval { reason } => {
                self.require_status("request approval", WorkStatus::Running)?;
                self.request_approval(reason);
            }
            WorkCommand::Approve => {
                self.require_status("approve", WorkStatus::AwaitingApproval)?;
                self.approve();
            }
            WorkCommand::ApplyRuntimeEvent(envelope) => self.apply_runtime_event(envelope)?,
            WorkCommand::FailRun { message } => self.fail_run(message),
            WorkCommand::CancelRun => self.cancel_run()?,
            WorkCommand::ResetDemo => *self = Self::spike_demo(),
        }
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
        self.status = WorkStatus::Running;
        self.approval_reason = None;
        self.runtime_run_id = None;
        self.last_runtime_sequence = 0;
        self.events.clear();
        for step in &mut self.plan {
            step.completed = false;
        }
        self.push_event(WorkEventKind::System, "已创建前台 Work Task");
        Ok(())
    }

    fn record_progress(
        &mut self,
        kind: WorkEventKind,
        message: impl Into<String>,
        completed_step: Option<usize>,
    ) {
        if let Some(step) = completed_step.and_then(|index| self.plan.get_mut(index)) {
            step.completed = true;
        }
        self.push_event(kind, message);
    }

    fn request_approval(&mut self, reason: impl Into<String>) {
        self.status = WorkStatus::AwaitingApproval;
        self.approval_reason = Some(reason.into());
        self.push_event(WorkEventKind::Approval, "等待用户批准文件修改");
    }

    fn approve(&mut self) {
        self.status = WorkStatus::Verifying;
        self.approval_reason = None;
        if let Some(step) = self.plan.get_mut(2) {
            step.completed = true;
        }
        self.push_event(WorkEventKind::Approval, "用户允许写入，开始验证");
        self.push_event(
            WorkEventKind::Verification,
            "cargo check -p microclaw-work 已加入验证队列",
        );
    }

    fn fail_run(&mut self, message: impl Into<String>) {
        self.status = WorkStatus::Failed;
        self.approval_reason = None;
        self.push_event(
            WorkEventKind::System,
            format!("任务失败：{}", message.into()),
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
        self.push_event(WorkEventKind::System, "已请求停止当前任务");
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
            RuntimeEvent::ToolStart { name, .. } => {
                self.status = WorkStatus::Running;
                self.push_event(WorkEventKind::Tool, format!("开始执行工具：{name}"));
            }
            RuntimeEvent::ToolResult {
                name,
                is_error,
                preview,
                ..
            } => {
                let outcome = if is_error { "失败" } else { "完成" };
                self.push_event(
                    WorkEventKind::Tool,
                    format!("工具 {name} {outcome}：{preview}"),
                );
            }
            RuntimeEvent::TextDelta { delta } => {
                if !delta.is_empty() {
                    self.push_event(WorkEventKind::System, delta);
                }
            }
            RuntimeEvent::ToolWaveStart { wave, tool_count } => self.push_event(
                WorkEventKind::Tool,
                format!("开始工具批次 {wave}（{tool_count} 个工具）"),
            ),
            RuntimeEvent::ToolWaveComplete { wave } => {
                self.push_event(WorkEventKind::Tool, format!("工具批次 {wave} 已完成"))
            }
            RuntimeEvent::Cancelled { final_text } => {
                self.status = WorkStatus::Cancelled;
                self.approval_reason = None;
                self.push_event(WorkEventKind::System, format!("任务已取消：{final_text}"));
            }
            RuntimeEvent::FinalResponse { text } => {
                if self.status == WorkStatus::AwaitingApproval {
                    self.push_event(WorkEventKind::System, text);
                } else {
                    self.status = WorkStatus::Completed;
                    self.approval_reason = None;
                    for step in &mut self.plan {
                        step.completed = true;
                    }
                    self.push_event(WorkEventKind::System, format!("任务已完成：{text}"));
                }
            }
            RuntimeEvent::MidTurnInjection { count } => self.push_event(
                WorkEventKind::System,
                format!("已接收 {count} 条任务补充信息"),
            ),
            RuntimeEvent::FileDiff {
                path,
                added,
                removed,
                truncated,
                ..
            } => {
                self.diff_summary = format!(
                    "{path}: +{added} -{removed}{}",
                    if truncated { "（已截断）" } else { "" }
                );
                self.push_event(WorkEventKind::Tool, format!("文件已修改：{path}"));
            }
            RuntimeEvent::SubagentStarted { run_id, label } => self.push_event(
                WorkEventKind::System,
                format!("子 Agent {label} 已启动（{run_id}）"),
            ),
            RuntimeEvent::SubagentFinished { run_id, status } => self.push_event(
                WorkEventKind::System,
                format!("子 Agent {run_id} 已结束：{status}"),
            ),
            RuntimeEvent::ApprovalRequired {
                approval_id,
                tool,
                preview,
                ..
            } => {
                self.status = WorkStatus::AwaitingApproval;
                let reason = preview.unwrap_or_else(|| format!("工具 {tool} 请求执行权限"));
                self.approval_reason = Some(reason.clone());
                self.push_event(
                    WorkEventKind::Approval,
                    format!("等待审批 {approval_id}：{reason}"),
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

    pub fn load(path: impl AsRef<Path>) -> io::Result<Self> {
        let bytes = fs::read(path)?;
        let snapshot: Self = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        if snapshot.schema_version != Self::SCHEMA_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unsupported work session schema {}, expected {}",
                    snapshot.schema_version,
                    Self::SCHEMA_VERSION
                ),
            ));
        }
        Ok(snapshot)
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
    fn foreground_lifecycle_pauses_for_approval_and_resumes_verification() {
        let mut snapshot = WorkSessionSnapshot::spike_demo();

        snapshot
            .apply(WorkCommand::StartTask {
                task: "实现中文任务输入".into(),
            })
            .unwrap();
        snapshot
            .apply(WorkCommand::RecordProgress {
                kind: WorkEventKind::Plan,
                message: "已生成计划".into(),
                completed_step: Some(0),
            })
            .unwrap();
        snapshot
            .apply(WorkCommand::RequestApproval {
                reason: "允许修改 Workspace".into(),
            })
            .unwrap();

        assert_eq!(snapshot.status, WorkStatus::AwaitingApproval);
        assert_eq!(
            snapshot.approval_reason.as_deref(),
            Some("允许修改 Workspace")
        );

        snapshot.apply(WorkCommand::Approve).unwrap();

        assert_eq!(snapshot.status, WorkStatus::Verifying);
        assert!(snapshot.approval_reason.is_none());
        assert!(snapshot.plan[2].completed);
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
                task: "仍在运行的任务".into(),
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
                options: vec!["approve once".into(), "deny".into()],
                advisory: None,
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
        snapshot.apply(WorkCommand::Approve).unwrap();
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
                    options: vec!["approve".into(), "deny".into()],
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
}
