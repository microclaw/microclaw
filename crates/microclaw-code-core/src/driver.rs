//! UI-independent turn driver for MicroClaw Code.
//!
//! A [`CodeSession`] owns the configured Agent and project state. One call to
//! [`CodeSession::turn`] runs the agent for a user prompt, resolves approvals
//! (automatically in auto mode, otherwise through the front end), verifies
//! the changes with the project's checks and hands failures back to the
//! agent. Front ends (the TUI, the line/JSON printer) only send [`Control`]s
//! and render [`Update`]s.

use microclaw_sdk::{
    Agent, INTERACTIVE_APPROVALS, MicroClaw, RunRequest, RunStatus, RuntimeApprovalDecision,
    RuntimeApprovalOption, RuntimeApprovalOptionKind, RuntimeEvent, RuntimeEventEnvelope,
    SessionId, SessionMessageRole, ToolPolicy,
};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use crate::allow::AllowRules;
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

/// Option value MicroClaw Code adds to shell approvals: approve and add a
/// project allow rule for the suggested command prefix.
pub const ALLOW_RULE_OPTION: &str = "p";

/// An approval the agent is waiting for.
#[derive(Debug, Clone, PartialEq)]
pub struct PendingApproval {
    /// Engine approval id (answers go back to the same run with it).
    pub approval_id: String,
    pub tool: String,
    pub preview: Option<String>,
    pub options: Vec<RuntimeApprovalOption>,
    pub advisory: Option<String>,
    /// Command prefix offered as an "always allow in this project" rule.
    pub suggested_rule: Option<String>,
}

impl PendingApproval {
    /// Build from an engine `ApprovalRequired` event, adding the project
    /// allow-rule option for shell commands that can carry one.
    pub fn from_event(
        approval_id: &str,
        tool: &str,
        preview: Option<&str>,
        options: &[RuntimeApprovalOption],
        advisory: Option<&str>,
    ) -> Self {
        let suggested_rule = (tool == "bash")
            .then(|| preview.and_then(crate::allow::suggest_prefix))
            .flatten();
        let mut options = options.to_vec();
        if let Some(rule) = &suggested_rule {
            let at = options
                .iter()
                .position(|o| o.decision == RuntimeApprovalDecision::Deny)
                .unwrap_or(options.len());
            options.insert(
                at,
                RuntimeApprovalOption {
                    value: ALLOW_RULE_OPTION.into(),
                    label: format!("Always allow `{rule}` in this project"),
                    kind: RuntimeApprovalOptionKind::Secondary,
                    decision: RuntimeApprovalDecision::Approve,
                },
            );
        }
        Self {
            approval_id: approval_id.to_string(),
            tool: tool.to_string(),
            preview: preview.map(str::to_string),
            options,
            advisory: advisory.map(str::to_string),
            suggested_rule,
        }
    }

    pub fn has_option(&self, value: &str) -> bool {
        self.options.iter().any(|o| o.value == value)
    }

    /// The engine's own options only (for a card answered by a later
    /// message, which cannot carry Code-level options).
    pub fn without_code_options(&self) -> Self {
        let mut approval = self.clone();
        approval.options.retain(|o| o.value != ALLOW_RULE_OPTION);
        approval
    }

    /// Label of an option value, for transcripts.
    pub fn option_label(&self, value: &str) -> Option<&str> {
        self.options
            .iter()
            .find(|o| o.value == value)
            .map(|o| o.label.as_str())
    }
}

/// One message of an earlier conversation in this session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryEntry {
    User(String),
    Agent(String),
    /// A verification failure handed back to the agent (summary line).
    Verification(String),
}

impl HistoryEntry {
    fn from_message(role: SessionMessageRole, content: &str) -> Self {
        match role {
            SessionMessageRole::Agent => Self::Agent(content.to_string()),
            SessionMessageRole::User => {
                match content.strip_prefix("[MicroClaw Code verification, ") {
                    Some(rest) => {
                        let first = rest.lines().next().unwrap_or_default();
                        let (round, detail) = first.split_once("] ").unwrap_or((first, ""));
                        Self::Verification(format!("{round}: {detail}").trim_end().to_string())
                    }
                    None => Self::User(content.to_string()),
                }
            }
        }
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
    /// An in-run approval was answered; the run continues.
    ApprovalAnswered {
        tool: String,
        label: String,
        denied: bool,
    },
    /// Approved without asking: auto mode (`rule: None`) or a project allow
    /// rule.
    AutoApproved {
        tool: String,
        rule: Option<String>,
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
    /// Ask the front end for approvals while the run waits; when false, a
    /// needed approval ends the turn with `approval_pending`.
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
    allow_rules: AllowRules,
    pending_approval: Option<PendingApproval>,
}

/// Whether an approval needs a person.
enum Gate {
    Ask,
    /// Auto mode (`rule: None`) or a project allow rule.
    Auto {
        rule: Option<String>,
    },
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
            allow_rules: AllowRules::load(AllowRules::default_path()),
            pending_approval: None,
        }
    }

    /// Use a specific allow-rule store (tests, custom homes).
    pub fn with_allow_rules(mut self, rules: AllowRules) -> Self {
        self.allow_rules = rules;
        self
    }

    pub fn allow_rules(&self) -> &AllowRules {
        &self.allow_rules
    }

    pub fn allow_rules_mut(&mut self) -> &mut AllowRules {
        &mut self.allow_rules
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

    /// The last `limit` messages of this session, for showing history on
    /// resume. Verification hand-backs are condensed to one line.
    pub fn history(&self, limit: usize) -> Vec<HistoryEntry> {
        self.microclaw
            .session_messages(&self.session_id, limit)
            .unwrap_or_default()
            .into_iter()
            .map(|message| HistoryEntry::from_message(message.role, &message.content))
            .collect()
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

    /// Build the approval card; commands on the always-ask list never get
    /// an "always allow in this project" option.
    fn approval_from_event(
        &self,
        approval_id: &str,
        tool: &str,
        preview: Option<&str>,
        options: &[RuntimeApprovalOption],
        advisory: Option<&str>,
    ) -> PendingApproval {
        let approval = PendingApproval::from_event(approval_id, tool, preview, options, advisory);
        let destructive = preview.is_some_and(|p| self.always_ask.iter().any(|re| re.is_match(p)));
        if destructive && approval.suggested_rule.is_some() {
            let mut approval = approval.without_code_options();
            approval.suggested_rule = None;
            approval
        } else {
            approval
        }
    }

    /// Decide whether an approval needs a person.
    fn gate(&self, approval: &PendingApproval) -> Gate {
        let preview = approval.preview.as_deref().unwrap_or("");
        if self.always_ask.iter().any(|re| re.is_match(preview)) {
            return Gate::Ask;
        }
        if self.settings.mode == Mode::Auto {
            return Gate::Auto { rule: None };
        }
        if approval.tool == "bash"
            && let Some(rule) = self.allow_rules.matching(&self.project.root, preview)
        {
            return Gate::Auto {
                rule: Some(rule.to_string()),
            };
        }
        Gate::Ask
    }

    /// Turn a front-end answer into the engine decision, applying Code-level
    /// options (the project allow rule) on the way.
    fn engine_answer(
        &mut self,
        approval: &PendingApproval,
        value: &str,
        updates: &UnboundedSender<Update>,
    ) -> String {
        if value == ALLOW_RULE_OPTION {
            if let Some(rule) = &approval.suggested_rule {
                match self.allow_rules.add(&self.project.root, rule) {
                    Ok(_) => {
                        let _ = updates.send(Update::Notice(format!(
                            "`{rule}` now runs without asking in this project (/allow to review)"
                        )));
                    }
                    Err(e) => {
                        let _ = updates.send(Update::Notice(format!(
                            "could not save the allow rule: {e}"
                        )));
                    }
                }
            }
            return "1".into();
        }
        value.to_string()
    }

    fn verify_active(&self) -> bool {
        self.settings.verify
            && self.project.verify_enabled()
            && self.settings.mode != Mode::Plan
            && !self.project.auto_checks().is_empty()
    }

    /// Run one agent request to completion. Interactive sessions answer
    /// approvals in-run (the engine waits); otherwise an approval ends the
    /// run and is left in `pending_approval`.
    async fn run_once(
        &mut self,
        prompt: &str,
        updates: &UnboundedSender<Update>,
        controls: &mut UnboundedReceiver<Control>,
    ) -> anyhow::Result<(RunStatus, String, Option<String>, Vec<String>)> {
        let in_run = self.settings.interactive;
        let mut request = RunRequest::new(prompt);
        request.session_id = Some(SessionId::new(self.session_id.clone()));
        request.workspace = Some(self.project.root.clone());
        if in_run {
            request
                .metadata
                .insert(INTERACTIVE_APPROVALS.into(), serde_json::Value::Bool(true));
        }
        let mut run = self.agent()?.run_request(request);
        let controller = run.controller();
        let mut changed = Vec::new();
        let mut cancelled = false;
        let mut controls_open = true;
        let mut awaiting: Option<PendingApproval> = None;
        loop {
            tokio::select! {
                event = run.next_event() => match event {
                    Some(envelope) => {
                        let approval = match &envelope.event {
                            RuntimeEvent::FileDiff { path, .. } => {
                                if !changed.contains(path) {
                                    changed.push(path.clone());
                                }
                                None
                            }
                            RuntimeEvent::ApprovalRequired { approval_id, tool, preview, options, advisory } => {
                                Some(self.approval_from_event(
                                    approval_id,
                                    tool,
                                    preview.as_deref(),
                                    options,
                                    advisory.as_deref(),
                                ))
                            }
                            _ => None,
                        };
                        let _ = updates.send(Update::Runtime(envelope));
                        let Some(approval) = approval else { continue };
                        if !in_run {
                            self.pending_approval = Some(approval);
                        } else if let Gate::Auto { rule } = self.gate(&approval) {
                            let _ = updates.send(Update::AutoApproved {
                                tool: approval.tool.clone(),
                                rule,
                            });
                            if let Err(e) = controller
                                .resolve_approval_confirmed(approval.approval_id.clone(), "1")
                                .await
                            {
                                let _ = updates.send(Update::Notice(format!(
                                    "could not auto-approve {}: {}", approval.tool, e.message
                                )));
                            }
                        } else {
                            let _ = updates.send(Update::ApprovalRequested(approval.clone()));
                            awaiting = Some(approval);
                        }
                    }
                    None => break,
                },
                control = controls.recv(), if controls_open => match control {
                    Some(Control::Cancel) if !cancelled => {
                        cancelled = true;
                        awaiting = None;
                        let _ = controller.cancel_confirmed().await;
                    }
                    Some(Control::Steer(text)) => {
                        match controller.steer_confirmed(text.clone()).await {
                            Ok(()) => { let _ = updates.send(Update::SteerAccepted(text)); }
                            Err(e) => { let _ = updates.send(Update::SteerRejected(e.to_string())); }
                        }
                    }
                    Some(Control::Approve(value)) => {
                        let Some(approval) = awaiting.take_if(|a| a.has_option(&value)) else {
                            continue;
                        };
                        let answer = self.engine_answer(&approval, &value, updates);
                        match controller
                            .resolve_approval_confirmed(approval.approval_id.clone(), answer.clone())
                            .await
                        {
                            Ok(()) => {
                                let _ = updates.send(Update::ApprovalAnswered {
                                    tool: approval.tool.clone(),
                                    label: approval
                                        .option_label(&value)
                                        .unwrap_or(&value)
                                        .to_string(),
                                    denied: answer == "3",
                                });
                            }
                            Err(e) => {
                                let _ = updates.send(Update::Notice(format!(
                                    "approval not delivered: {}", e.message
                                )));
                            }
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

            // Text-path approvals (non-interactive runs): the run ended; answer
            // it with the next message.
            if let Some(approval) = self.pending_approval.take() {
                let answer = if let Gate::Auto { rule } = self.gate(&approval) {
                    let _ = updates.send(Update::AutoApproved {
                        tool: approval.tool.clone(),
                        rule,
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
                        next_prompt = self.engine_answer(&approval, &value, updates);
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
            approval_pending: Some(PendingApproval::from_event("a", "bash", None, &[], None)),
            ..Default::default()
        };
        assert_eq!(pending.exit_code(), 2);
        let failing = TurnReport {
            checks_passed: Some(false),
            ..Default::default()
        };
        assert_eq!(failing.exit_code(), 1);
    }

    #[test]
    fn shell_approvals_offer_a_project_rule_before_deny() {
        let options = vec![
            RuntimeApprovalOption {
                value: "1".into(),
                label: "Approve once".into(),
                kind: RuntimeApprovalOptionKind::Primary,
                decision: RuntimeApprovalDecision::Approve,
            },
            RuntimeApprovalOption {
                value: "3".into(),
                label: "Deny".into(),
                kind: RuntimeApprovalOptionKind::Danger,
                decision: RuntimeApprovalDecision::Deny,
            },
        ];
        let approval =
            PendingApproval::from_event("id", "bash", Some("cargo test -q"), &options, None);
        assert_eq!(approval.suggested_rule.as_deref(), Some("cargo test"));
        let values: Vec<_> = approval.options.iter().map(|o| o.value.as_str()).collect();
        assert_eq!(values, ["1", ALLOW_RULE_OPTION, "3"]);
        let compound = PendingApproval::from_event(
            "id",
            "bash",
            Some("cargo test && git push"),
            &options,
            None,
        );
        assert!(compound.suggested_rule.is_none());
        assert_eq!(compound.options.len(), 2);
        let write = PendingApproval::from_event("id", "write_file", Some("{}"), &options, None);
        assert!(write.suggested_rule.is_none());
    }

    #[test]
    fn history_condenses_verification_handbacks() {
        assert_eq!(
            HistoryEntry::from_message(SessionMessageRole::User, "fix it"),
            HistoryEntry::User("fix it".into())
        );
        let prompt = verify::fix_prompt(
            &CheckOutcome {
                check: Check {
                    name: "test".into(),
                    run: "cargo test".into(),
                    auto: true,
                    timeout_secs: None,
                },
                success: false,
                exit_code: Some(1),
                timed_out: false,
                duration: std::time::Duration::from_secs(1),
                output: "boom".into(),
            },
            1,
            2,
        );
        match HistoryEntry::from_message(SessionMessageRole::User, &prompt) {
            HistoryEntry::Verification(line) => {
                assert!(
                    line.starts_with("round 1/2: The project check `test`"),
                    "{line}"
                );
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}
