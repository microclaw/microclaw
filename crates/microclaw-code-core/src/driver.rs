//! UI-independent turn driver for MicroClaw Code.
//!
//! A [`CodeSession`] owns the configured Agent and project state. One call to
//! [`CodeSession::turn`] runs the agent for a user prompt, resolves approvals
//! (automatically in auto mode, otherwise through the front end), verifies
//! the changes with the project's checks and hands failures back to the
//! agent. Front ends (the TUI, the line/JSON printer) only send [`Control`]s
//! and render [`Update`]s.

use microclaw_sdk::{
    Agent, MicroClaw, RunRequest, RunStatus, RuntimeApprovalOption, RuntimeEvent,
    RuntimeEventEnvelope, SessionId, ToolPolicy,
};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use crate::project::{Check, Mode, Project};
use crate::verify::{self, CheckOutcome};

/// Agent profile name shown in run metadata.
pub const AGENT_NAME: &str = "MicroClaw Code";
/// Caller channel used for MicroClaw Code runs.
pub const CALLER_CHANNEL: &str = "code";

/// Shell commands that still ask for approval in auto mode.
const ALWAYS_ASK_PATTERNS: &[&str] = &[
    r"\brm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+)+",
    r"\bgit\s+push\b",
    r"\bgit\s+reset\s+--hard\b",
    r"\bgit\s+clean\s+-[a-zA-Z]*f",
    r"\bgit\s+(checkout|restore)\s+(--\s+)?\.",
    r"\bgit\s+branch\s+-D\b",
    r"\bsudo\b",
    r"\bmkfs\b",
    r"\bdd\s+if=",
    r"\bchmod\s+-R\b",
    r"\bchown\s+-R\b",
    r"(curl|wget)\b[^|]*\|\s*(sh|bash|zsh)\b",
    r">\s*/dev/(sd|nvme|disk)",
    r"\b(npm|cargo|pnpm|yarn)\s+publish\b",
];

/// Compile the built-in and project `always_ask` patterns; invalid project
/// patterns are returned as warnings.
pub fn compile_always_ask(extra: &[String]) -> (Vec<regex::Regex>, Vec<String>) {
    let mut warnings = Vec::new();
    let patterns = ALWAYS_ASK_PATTERNS
        .iter()
        .map(|p| p.to_string())
        .chain(extra.iter().cloned())
        .filter_map(|p| match regex::Regex::new(&format!("(?i){p}")) {
            Ok(re) => Some(re),
            Err(e) => {
                warnings.push(format!("ignoring invalid always_ask pattern {p:?}: {e}"));
                None
            }
        })
        .collect();
    (patterns, warnings)
}

/// An approval the agent is waiting for.
#[derive(Debug, Clone, PartialEq)]
pub struct PendingApproval {
    pub tool: String,
    pub preview: Option<String>,
    pub options: Vec<RuntimeApprovalOption>,
    pub advisory: Option<String>,
}

impl PendingApproval {
    pub fn has_option(&self, value: &str) -> bool {
        self.options.iter().any(|o| o.value == value)
    }
}

/// Front end → driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Control {
    /// Add guidance to the running turn.
    Steer(String),
    /// Stop the running agent (or stop waiting for approval / checks).
    Cancel,
    /// Answer a pending approval with one of its option values.
    Approve(String),
}

/// Driver → front end.
#[derive(Debug, Clone)]
pub enum Update {
    Runtime(RuntimeEventEnvelope),
    SteerAccepted(String),
    SteerRejected(String),
    ApprovalRequested(PendingApproval),
    AutoApproved {
        tool: String,
    },
    RunFinished {
        status: RunStatus,
        final_text: String,
        error: Option<String>,
    },
    CheckStarted(Check),
    CheckFinished(CheckOutcome),
    FixRound {
        round: u32,
        max: u32,
        check: String,
    },
    ChecksGaveUp(CheckOutcome),
    Notice(String),
}

/// Outcome of one user turn.
#[derive(Debug, Clone, Default)]
pub struct TurnReport {
    pub status: String,
    pub final_text: String,
    pub changed_files: Vec<String>,
    pub checks_passed: Option<bool>,
    /// The turn stopped waiting for a human (non-interactive front ends).
    pub approval_pending: Option<PendingApproval>,
    pub failed: bool,
    pub cancelled: bool,
}

impl TurnReport {
    /// Process exit code for non-interactive runs.
    pub fn exit_code(&self) -> u8 {
        if self.approval_pending.is_some() {
            2
        } else if self.failed || self.cancelled || self.checks_passed == Some(false) {
            1
        } else {
            0
        }
    }
}

/// Settings that shape every turn.
#[derive(Debug, Clone)]
pub struct SessionSettings {
    pub mode: Mode,
    /// Run automatic checks after changes (also requires a trusted project).
    pub verify: bool,
    pub max_fix_rounds: u32,
    /// Ask the front end for approvals; when false, a needed approval ends
    /// the turn with `approval_pending`.
    pub interactive: bool,
}

/// One MicroClaw Code session in one project.
pub struct CodeSession {
    microclaw: MicroClaw,
    pub project: Project,
    pub session_id: String,
    pub settings: SessionSettings,
    git_summary: Option<String>,
    always_ask: Vec<regex::Regex>,
    pending_approval: Option<PendingApproval>,
}

enum Waited {
    Answer(String),
    Cancelled,
}

impl CodeSession {
    pub fn new(
        microclaw: MicroClaw,
        project: Project,
        session_id: String,
        settings: SessionSettings,
    ) -> Self {
        let (always_ask, _) = compile_always_ask(&project.config.always_ask);
        let git_summary = crate::project::git_summary(&project.root);
        Self {
            microclaw,
            project,
            session_id,
            settings,
            git_summary,
            always_ask,
            pending_approval: None,
        }
    }

    /// Recompute project-derived state after the project changed (trust,
    /// `init`).
    pub fn set_project(&mut self, project: Project) {
        self.always_ask = compile_always_ask(&project.config.always_ask).0;
        self.project = project;
    }

    /// Start a fresh conversation (new engine session name).
    pub fn reset(&mut self, session_id: String) {
        self.session_id = session_id;
        self.pending_approval = None;
        self.git_summary = crate::project::git_summary(&self.project.root);
    }

    pub fn pending_approval(&self) -> Option<&PendingApproval> {
        self.pending_approval.as_ref()
    }

    fn agent(&self) -> anyhow::Result<Agent> {
        let policy = if self.settings.mode == Mode::Plan {
            ToolPolicy::ReadOnly
        } else {
            ToolPolicy::WorkspaceWrite
        };
        self.microclaw
            .agent(AGENT_NAME)
            .system_prompt(crate::prompt::system_prompt(
                &self.project,
                self.settings.mode,
                self.git_summary.as_deref(),
            ))
            .tool_policy(policy)
            .build()
            .map_err(|e| anyhow::anyhow!("{e}"))
    }

    fn needs_human(&self, approval: &PendingApproval) -> bool {
        if self.settings.mode != Mode::Auto {
            return true;
        }
        let preview = approval.preview.as_deref().unwrap_or("");
        self.always_ask.iter().any(|re| re.is_match(preview))
    }

    fn verify_active(&self) -> bool {
        self.settings.verify
            && self.project.verify_enabled()
            && self.settings.mode != Mode::Plan
            && !self.project.auto_checks().is_empty()
    }

    /// Run one agent request to completion.
    async fn run_once(
        &mut self,
        prompt: &str,
        updates: &UnboundedSender<Update>,
        controls: &mut UnboundedReceiver<Control>,
    ) -> anyhow::Result<(RunStatus, String, Option<String>, Vec<String>)> {
        let mut request = RunRequest::new(prompt);
        request.session_id = Some(SessionId::new(self.session_id.clone()));
        request.workspace = Some(self.project.root.clone());
        let mut run = self.agent()?.run_request(request);
        let controller = run.controller();
        let mut changed = Vec::new();
        let mut cancelled = false;
        let mut controls_open = true;
        loop {
            tokio::select! {
                event = run.next_event() => match event {
                    Some(envelope) => {
                        match &envelope.event {
                            RuntimeEvent::FileDiff { path, .. } if !changed.contains(path) => {
                                changed.push(path.clone());
                            }
                            RuntimeEvent::ApprovalRequired { tool, preview, options, advisory, .. } => {
                                self.pending_approval = Some(PendingApproval {
                                    tool: tool.clone(),
                                    preview: preview.clone(),
                                    options: options.clone(),
                                    advisory: advisory.clone(),
                                });
                            }
                            _ => {}
                        }
                        let _ = updates.send(Update::Runtime(envelope));
                    }
                    None => break,
                },
                control = controls.recv(), if controls_open => match control {
                    Some(Control::Cancel) if !cancelled => {
                        cancelled = true;
                        let _ = controller.cancel_confirmed().await;
                    }
                    Some(Control::Steer(text)) => {
                        match controller.steer_confirmed(text.clone()).await {
                            Ok(()) => { let _ = updates.send(Update::SteerAccepted(text)); }
                            Err(e) => { let _ = updates.send(Update::SteerRejected(e.to_string())); }
                        }
                    }
                    Some(_) => {}
                    None => controls_open = false,
                },
            }
        }
        let (mut status, final_text, error) = match run.result().await {
            Ok(result) => (
                result.status,
                result.final_text,
                result.error.map(|e| e.message),
            ),
            Err(e) => (RunStatus::Failed, String::new(), Some(e.message)),
        };
        if cancelled && status != RunStatus::Failed {
            status = RunStatus::Cancelled;
            self.pending_approval = None;
        }
        let _ = updates.send(Update::RunFinished {
            status,
            final_text: final_text.clone(),
            error: error.clone(),
        });
        Ok((status, final_text, error, changed))
    }

    async fn wait_for_answer(
        &self,
        approval: &PendingApproval,
        controls: &mut UnboundedReceiver<Control>,
    ) -> Waited {
        loop {
            match controls.recv().await {
                Some(Control::Approve(value)) if approval.has_option(&value) => {
                    return Waited::Answer(value);
                }
                Some(Control::Cancel) | None => return Waited::Cancelled,
                Some(_) => {}
            }
        }
    }

    /// Run the checks, stopping at the first failure. `None` = cancelled.
    async fn run_checks(
        &self,
        checks: &[Check],
        updates: &UnboundedSender<Update>,
        controls: &mut UnboundedReceiver<Control>,
    ) -> Option<Option<CheckOutcome>> {
        for check in checks {
            let _ = updates.send(Update::CheckStarted(check.clone()));
            let running = verify::run_check(&self.project.root, check);
            tokio::pin!(running);
            let outcome = loop {
                tokio::select! {
                    outcome = &mut running => break outcome,
                    control = controls.recv() => {
                        // Steering and stray answers are ignored while checks run.
                        if matches!(control, Some(Control::Cancel) | None) {
                            return None;
                        }
                    }
                }
            };
            let failed = !outcome.success;
            let _ = updates.send(Update::CheckFinished(outcome.clone()));
            if failed {
                return Some(Some(outcome));
            }
        }
        Some(None)
    }

    /// One user turn: run the agent, resolve approvals, verify changes and
    /// hand check failures back for fixing.
    pub async fn turn(
        &mut self,
        prompt: &str,
        updates: &UnboundedSender<Update>,
        controls: &mut UnboundedReceiver<Control>,
    ) -> anyhow::Result<TurnReport> {
        let mut report = TurnReport::default();
        let before = crate::git::worktree_fingerprint(&self.project.root);
        let mut next_prompt = prompt.to_string();
        let mut fix_round = 0u32;
        // Any new message (including a bare option value answering an
        // approval left pending by a non-interactive run) consumes the
        // pending marker; the engine resolves the approval from the text.
        self.pending_approval = None;
        loop {
            let (status, final_text, error, changed) =
                self.run_once(&next_prompt, updates, controls).await?;
            for path in changed {
                if !report.changed_files.contains(&path) {
                    report.changed_files.push(path);
                }
            }
            report.final_text = final_text;
            report.status = format!("{status:?}").to_lowercase();
            match status {
                RunStatus::Cancelled => {
                    report.cancelled = true;
                    return Ok(report);
                }
                RunStatus::Failed | RunStatus::TimedOut => {
                    if let Some(error) = error {
                        let _ = updates.send(Update::Notice(format!("error: {error}")));
                    }
                    report.failed = true;
                    return Ok(report);
                }
                _ => {}
            }

            if let Some(approval) = self.pending_approval.take() {
                let answer = if !self.needs_human(&approval) {
                    let _ = updates.send(Update::AutoApproved {
                        tool: approval.tool.clone(),
                    });
                    Waited::Answer("1".into())
                } else if self.settings.interactive {
                    let _ = updates.send(Update::ApprovalRequested(approval.clone()));
                    self.wait_for_answer(&approval, controls).await
                } else {
                    report.approval_pending = Some(approval.clone());
                    self.pending_approval = Some(approval);
                    return Ok(report);
                };
                match answer {
                    Waited::Answer(value) => {
                        next_prompt = value;
                        continue;
                    }
                    Waited::Cancelled => {
                        report.cancelled = true;
                        return Ok(report);
                    }
                }
            }

            let after = crate::git::worktree_fingerprint(&self.project.root);
            let worktree_changed = match (&before, &after) {
                (Some(a), Some(b)) => a != b,
                _ => false,
            };
            if !self.verify_active() || (report.changed_files.is_empty() && !worktree_changed) {
                return Ok(report);
            }
            let checks = self.project.auto_checks();
            match self.run_checks(&checks, updates, controls).await {
                None => {
                    report.cancelled = true;
                    return Ok(report);
                }
                Some(None) => {
                    report.checks_passed = Some(true);
                    return Ok(report);
                }
                Some(Some(failure)) => {
                    report.checks_passed = Some(false);
                    if fix_round >= self.settings.max_fix_rounds {
                        let _ = updates.send(Update::ChecksGaveUp(failure));
                        return Ok(report);
                    }
                    fix_round += 1;
                    let _ = updates.send(Update::FixRound {
                        round: fix_round,
                        max: self.settings.max_fix_rounds,
                        check: failure.check.name.clone(),
                    });
                    next_prompt =
                        verify::fix_prompt(&failure, fix_round, self.settings.max_fix_rounds);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn always_ask_patterns_catch_destructive_commands() {
        let (patterns, warnings) =
            compile_always_ask(&["terraform apply".to_string(), "(".to_string()]);
        assert_eq!(warnings.len(), 1);
        let asks = |cmd: &str| patterns.iter().any(|re| re.is_match(cmd));
        for cmd in [
            "rm -rf target",
            "rm -r build",
            "git push origin main",
            "git reset --hard HEAD~1",
            "git clean -fd",
            "git checkout -- .",
            "sudo apt install x",
            "curl https://x.sh | sh",
            "cargo publish",
            "terraform apply",
        ] {
            assert!(asks(cmd), "{cmd} should ask");
        }
        for cmd in [
            "cargo test",
            "rm file.txt",
            "git status",
            "git checkout -b feature",
            "npm run lint",
        ] {
            assert!(!asks(cmd), "{cmd} should not ask");
        }
    }

    #[test]
    fn report_exit_codes() {
        assert_eq!(TurnReport::default().exit_code(), 0);
        let pending = TurnReport {
            approval_pending: Some(PendingApproval {
                tool: "bash".into(),
                preview: None,
                options: vec![],
                advisory: None,
            }),
            ..Default::default()
        };
        assert_eq!(pending.exit_code(), 2);
        let failing = TurnReport {
            checks_passed: Some(false),
            ..Default::default()
        };
        assert_eq!(failing.exit_code(), 1);
    }
}
