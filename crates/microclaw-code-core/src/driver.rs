//! UI-independent turn driver for MicroClaw Code.
//!
//! A [`CodeSession`] owns the configured Agent and project state. One call to
//! [`CodeSession::turn`] runs the agent for a user prompt, resolves approvals
//! (automatically in auto mode, otherwise through the front end), verifies
//! the changes with the project's checks and hands failures back to the
//! agent. Front ends (the TUI, the line/JSON printer) only send [`Control`]s
//! and render [`Update`]s.

use microclaw_sdk::{
    Agent, IMAGE_METADATA, INTERACTIVE_APPROVALS, MicroClaw, RunRequest, RunStatus,
    RuntimeApprovalDecision, RuntimeApprovalOption, RuntimeApprovalOptionKind, RuntimeEvent,
    RuntimeEventEnvelope, SessionId, SessionMessageRole, ToolPolicy,
};
pub use microclaw_sdk::{Checkpoint, SessionUsage};
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

/// Messages `/compact` keeps verbatim.
const COMPACT_KEEP_RECENT: usize = 8;
/// Cap on the diff embedded in a review request.
const REVIEW_DIFF_LIMIT: usize = 60_000;

/// The request `/review` sends.
/// Markdown transcript of a session.
pub fn export_markdown(
    root: &std::path::Path,
    session_id: &str,
    messages: &[microclaw_sdk::SessionMessage],
) -> String {
    let mut out = format!(
        "# MicroClaw Code session {session_id}\n\nProject: `{}`  \nMessages: {}\n",
        root.display(),
        messages.len()
    );
    for message in messages {
        let who = match message.role {
            microclaw_sdk::SessionMessageRole::User => "You",
            microclaw_sdk::SessionMessageRole::Agent => "MicroClaw Code",
        };
        out.push_str(&format!(
            "\n## {who} · {}\n\n{}\n",
            message.timestamp,
            message.content.trim()
        ));
    }
    out
}

pub fn review_prompt(diff: &str, focus: Option<&str>) -> String {
    let focus = focus
        .map(str::trim)
        .filter(|f| !f.is_empty())
        .map(|f| format!(" Focus on: {f}."))
        .unwrap_or_default();
    format!(
        "[MicroClaw Code review] Review the uncommitted changes below as a careful senior reviewer.{focus} \
         Read the surrounding code where you need context. Look for bugs, unhandled edge cases and errors, \
         security problems, missing or weakened tests, and code that does not match the project's conventions. \
         Do not modify any files. Report findings ordered by severity, each with `file:line`, what is wrong and a \
         concrete fix; skip praise and trivia, and say plainly if you found nothing significant.\n\n```diff\n{diff}\n```"
    )
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
    /// Share of the usable context window in use after a turn.
    ContextPercent(u8),
}

/// Outcome of one user turn.
#[derive(Debug, Clone, Default)]
pub struct TurnReport {
    pub status: String,
    pub final_text: String,
    pub changed_files: Vec<String>,
    /// The session's token budget was used up; nothing more was sent.
    pub budget_exhausted: bool,
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
    /// The OS sandbox shell commands run in, when active.
    pub sandbox: Option<SandboxInfo>,
    /// Stop before a request once the session used this many tokens
    /// (input + output, all models).
    pub max_session_tokens: Option<u64>,
}

/// An active shell sandbox (shown to the user and the agent).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxInfo {
    /// `bubblewrap`, `seatbelt` or `landlock`.
    pub mechanism: String,
    pub network: bool,
    /// Credential directories are hidden (not with `landlock`).
    pub confines_reads: bool,
}

/// `AutoApproved.rule` for commands auto-approved because they run in the
/// sandbox without network access.
pub const SANDBOX_RULE: &str = "sandbox";

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
    /// Workspace checkpoints taken at the start of each turn, oldest first,
    /// with the turn's prompt.
    turn_checkpoints: Vec<(Checkpoint, String)>,
    /// Language servers, started on first use.
    lsp: Option<crate::lsp::LspPool>,
    /// Tool policy for the next run instead of the mode's (reviews).
    policy_override: Option<ToolPolicy>,
}

fn one_line(text: &str, max: usize) -> String {
    let line = text.lines().next().unwrap_or_default().trim();
    if line.chars().count() <= max {
        line.to_string()
    } else {
        format!("{}…", line.chars().take(max).collect::<String>())
    }
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
            turn_checkpoints: Vec::new(),
            lsp: None,
            policy_override: None,
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
        self.turn_checkpoints.clear();
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

    /// Undo the most recent turn that changed the workspace: restore the
    /// files to the checkpoint taken when it started. The current state is
    /// checkpointed first (`/rewind` can return to it). Returns the restored
    /// checkpoint and that turn's prompt, or `None` when there is nothing to
    /// undo in this session.
    pub async fn undo(&mut self) -> anyhow::Result<Option<(Checkpoint, String)>> {
        let now = self
            .microclaw
            .checkpoint(&self.session_id, "before undo")
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        while let Some((checkpoint, prompt)) = self.turn_checkpoints.pop() {
            if now.as_ref().is_some_and(|n| n.commit == checkpoint.commit) {
                continue;
            }
            self.microclaw
                .restore_checkpoint(&self.session_id, &checkpoint.commit)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            return Ok(Some((checkpoint, prompt)));
        }
        Ok(None)
    }

    /// Recent workspace checkpoints, newest first.
    pub async fn checkpoints(&self, limit: usize) -> anyhow::Result<Vec<Checkpoint>> {
        self.microclaw
            .checkpoints(&self.session_id, limit)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))
    }

    /// Restore the workspace to any checkpoint (the current state is
    /// checkpointed first).
    pub async fn rewind(&mut self, commit: &str) -> anyhow::Result<()> {
        self.microclaw
            .restore_checkpoint(&self.session_id, commit)
            .await
            .map(|_| ())
            .map_err(|e| anyhow::anyhow!("{e}"))
    }

    /// Token usage of this session.
    pub async fn usage(&self) -> anyhow::Result<SessionUsage> {
        self.microclaw
            .session_usage(&self.session_id)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))
    }

    /// The model the next turn uses.
    pub async fn model(&self) -> anyhow::Result<String> {
        self.microclaw
            .session_model(&self.session_id)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))
    }

    /// Switch this session's model (`None` = back to the configured one).
    pub async fn set_model(&self, model: Option<&str>) -> anyhow::Result<String> {
        self.microclaw
            .set_session_model(&self.session_id, model)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))
    }

    /// Summarize older messages now; `focus` says what the summary must keep.
    pub async fn compact(
        &self,
        focus: Option<&str>,
    ) -> anyhow::Result<microclaw_sdk::SessionCompaction> {
        self.microclaw
            .compact_session_with(&self.session_id, COMPACT_KEEP_RECENT, focus)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))
    }

    /// Measure the context in the background and report it as
    /// [`Update::ContextPercent`].
    pub fn report_context_percent(&self, updates: tokio::sync::mpsc::UnboundedSender<Update>) {
        let microclaw = self.microclaw.clone();
        let session = self.session_id.clone();
        tokio::spawn(async move {
            if let Ok(usage) = microclaw.context_usage(&session).await {
                let _ = updates.send(Update::ContextPercent(usage.percent_used()));
            }
        });
    }

    /// How full this session's context is.
    pub async fn context_usage(&self) -> anyhow::Result<microclaw_sdk::ContextUsage> {
        self.microclaw
            .context_usage(&self.session_id)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))
    }

    /// Continue in a copy of this conversation under `new_id`; the original
    /// session stays as it was.
    pub async fn fork(&mut self, new_id: String) -> anyhow::Result<()> {
        let model = self.model().await.ok();
        self.microclaw
            .fork_session(&self.session_id, &new_id)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        self.session_id = new_id;
        self.pending_approval = None;
        // A `/model` override is per session; carry it into the fork.
        if let Some(model) = model
            && self.model().await.ok().as_deref() != Some(model.as_str())
        {
            self.set_model(Some(&model)).await?;
        }
        Ok(())
    }

    /// This session as Markdown: every stored user message and reply, oldest
    /// first.
    pub fn export_markdown(&self) -> anyhow::Result<String> {
        let messages = self
            .microclaw
            .session_messages(&self.session_id, 100_000)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(export_markdown(
            &self.project.root,
            &self.session_id,
            &messages,
        ))
    }

    /// Continue in a new session `new_id` that starts from a summary of
    /// this one focused on `goal`; this session stays as it was.
    pub async fn handoff(&mut self, new_id: String, goal: &str) -> anyhow::Result<usize> {
        let model = self.model().await.ok();
        let tokens = self
            .microclaw
            .handoff_session(&self.session_id, &new_id, goal)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        self.session_id = new_id;
        self.pending_approval = None;
        self.turn_checkpoints.clear();
        if let Some(model) = model
            && self.model().await.ok().as_deref() != Some(model.as_str())
        {
            self.set_model(Some(&model)).await?;
        }
        Ok(tokens)
    }

    /// Review the uncommitted changes with read-only tools. `focus` narrows
    /// the review ("error handling", a path, …).
    pub async fn review(
        &mut self,
        focus: Option<&str>,
        updates: &UnboundedSender<Update>,
        controls: &mut UnboundedReceiver<Control>,
    ) -> anyhow::Result<TurnReport> {
        let Some(diff) = crate::git::review_diff(&self.project.root, REVIEW_DIFF_LIMIT) else {
            let _ = updates.send(Update::Notice(
                "nothing to review: the working tree has no uncommitted changes".into(),
            ));
            return Ok(TurnReport {
                status: "completed".into(),
                ..Default::default()
            });
        };
        self.review_diff(&diff, focus, updates, controls).await
    }

    /// Review a given diff (for example a pull request) with read-only tools.
    pub async fn review_diff(
        &mut self,
        diff: &str,
        focus: Option<&str>,
        updates: &UnboundedSender<Update>,
        controls: &mut UnboundedReceiver<Control>,
    ) -> anyhow::Result<TurnReport> {
        let mut report = TurnReport::default();
        let diff = if diff.len() > REVIEW_DIFF_LIMIT {
            let mut end = REVIEW_DIFF_LIMIT;
            while !diff.is_char_boundary(end) {
                end -= 1;
            }
            format!("{}\n… (diff truncated)", &diff[..end])
        } else {
            diff.to_string()
        };
        let prompt = review_prompt(&diff, focus);
        self.policy_override = Some(ToolPolicy::ReadOnly);
        let outcome = self.run_once(&prompt, updates, controls).await;
        self.policy_override = None;
        let (status, final_text, error, _) = outcome?;
        report.final_text = final_text;
        report.status = format!("{status:?}").to_lowercase();
        match status {
            RunStatus::Cancelled => report.cancelled = true,
            RunStatus::Failed | RunStatus::TimedOut => {
                if let Some(error) = error {
                    let _ = updates.send(Update::Notice(format!("error: {error}")));
                }
                report.failed = true;
            }
            _ => {}
        }
        Ok(report)
    }

    pub fn pending_approval(&self) -> Option<&PendingApproval> {
        self.pending_approval.as_ref()
    }

    fn agent(&self) -> anyhow::Result<Agent> {
        let policy = match self.policy_override.clone() {
            Some(policy) => policy,
            None if self.settings.mode == Mode::Plan => ToolPolicy::ReadOnly,
            None => ToolPolicy::WorkspaceWrite,
        };
        self.microclaw
            .agent(AGENT_NAME)
            .system_prompt(crate::prompt::system_prompt_with_sandbox(
                &self.project,
                self.settings.mode,
                self.git_summary.as_deref(),
                self.settings.sandbox.as_ref(),
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
        // A command reviewer that calls the command dangerous always gets a
        // person, even in auto mode.
        if approval
            .advisory
            .as_deref()
            .is_some_and(|a| a.trim_start().to_ascii_uppercase().starts_with("DANGEROUS"))
        {
            return Gate::Ask;
        }
        if self.settings.mode == Mode::Auto {
            return Gate::Auto { rule: None };
        }
        // Ask mode: a shell command that runs in the OS sandbox without
        // network access cannot change anything outside the repository, so
        // it runs without asking (like Codex's on-request policy).
        if approval.tool == "bash"
            && self
                .settings
                .sandbox
                .as_ref()
                .is_some_and(|s| !s.network && s.confines_reads)
        {
            return Gate::Auto {
                rule: Some(SANDBOX_RULE.into()),
            };
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
        // Approvals are always answered in-run: automatically (auto mode,
        // allow rules, the sandbox), by the front end, or — when no person
        // can answer (`-p`) — deferred, which ends the run with the text
        // approval prompt so `--session <id> -p 1|3` resumes it.
        let mut request = RunRequest::new(prompt);
        request.session_id = Some(SessionId::new(self.session_id.clone()));
        request.workspace = Some(self.project.root.clone());
        request
            .metadata
            .insert(INTERACTIVE_APPROVALS.into(), serde_json::Value::Bool(true));
        match crate::images::first_image(&self.project.root, prompt) {
            Ok(Some(image)) => {
                let _ = updates.send(Update::Notice(format!(
                    "attached image {}",
                    image.path.display()
                )));
                request.metadata.insert(
                    IMAGE_METADATA.into(),
                    serde_json::json!({"media_type": image.media_type, "data": image.base64}),
                );
            }
            Ok(None) => {}
            Err(e) => {
                let _ = updates.send(Update::Notice(e));
            }
        }
        let mut deferred = false;
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
                        if deferred {
                            // The text-path prompt that follows a deferral.
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
                        } else if self.settings.interactive {
                            let _ = updates.send(Update::ApprovalRequested(approval.clone()));
                            awaiting = Some(approval);
                        } else {
                            deferred = true;
                            self.pending_approval = Some(approval.clone());
                            if let Err(e) = controller
                                .resolve_approval_confirmed(approval.approval_id.clone(), "defer")
                                .await
                            {
                                let _ = updates.send(Update::Notice(format!(
                                    "could not pause for approval: {}", e.message
                                )));
                            }
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

    /// Run project hooks; a failing hook is reported but does not stop the turn.
    async fn run_hooks(&self, kind: &str, commands: &[String], updates: &UnboundedSender<Update>) {
        for command in commands {
            let check = Check {
                name: format!("{kind} hook"),
                run: command.clone(),
                auto: false,
                timeout_secs: Some(120),
            };
            let outcome = verify::run_check(&self.project.root, &check).await;
            if !outcome.success {
                let _ = updates.send(Update::Notice(format!(
                    "{kind} hook `{command}` failed: {}",
                    verify::tail(outcome.output.trim_end(), 300)
                )));
            }
        }
    }

    /// Language-server diagnostics for `files`, as a check outcome (`None`:
    /// no running server covers them).
    async fn lsp_check(
        &mut self,
        files: &[String],
        updates: &UnboundedSender<Update>,
    ) -> Option<CheckOutcome> {
        if !self.project.lsp_enabled() || self.settings.mode == Mode::Plan || files.is_empty() {
            return None;
        }
        let root = self.project.root.clone();
        let pool = self
            .lsp
            .get_or_insert_with(|| crate::lsp::LspPool::new(&root));
        if !pool.covers(files) {
            return None;
        }
        // Start the servers before announcing a check: a server that is on
        // PATH but cannot run must not show up as a passing check.
        for message in pool.start_servers(files).await {
            let _ = updates.send(Update::Notice(message));
        }
        if !pool.ready_for(files) {
            return None;
        }
        let check = Check {
            name: "lsp".into(),
            run: "language server diagnostics".into(),
            auto: true,
            timeout_secs: None,
        };
        let _ = updates.send(Update::CheckStarted(check.clone()));
        let started = std::time::Instant::now();
        let report = pool.diagnose(files).await;
        if !report.silent.is_empty() {
            let _ = updates.send(Update::Notice(format!(
                "{} sent no diagnostics in time (still indexing?); those files were not checked",
                report.silent.join(", ")
            )));
        }
        let output = report
            .errors
            .iter()
            .take(40)
            .map(|d| d.render())
            .collect::<Vec<_>>()
            .join("\n");
        let outcome = CheckOutcome {
            check,
            success: report.errors.is_empty(),
            exit_code: Some(if report.errors.is_empty() { 0 } else { 1 }),
            timed_out: false,
            duration: started.elapsed(),
            output: if output.is_empty() {
                format!("no errors ({})", report.languages.join(", "))
            } else {
                output
            },
        };
        let _ = updates.send(Update::CheckFinished(outcome.clone()));
        Some(outcome)
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

    /// End of a turn: `after_turn` hooks when files changed.
    async fn finish_turn(&self, report: &TurnReport, updates: &UnboundedSender<Update>) {
        if !report.changed_files.is_empty()
            && self.project.trusted
            && self.settings.mode != Mode::Plan
        {
            let hooks = self.project.config.hooks.after_turn.clone();
            self.run_hooks("after_turn", &hooks, updates).await;
        }
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
        // Checkpoint the workspace so `/undo` can return to this point.
        match self
            .microclaw
            .checkpoint(
                &self.session_id,
                &format!("before: {}", one_line(prompt, 60)),
            )
            .await
        {
            Ok(Some(checkpoint)) => self.turn_checkpoints.push((checkpoint, prompt.to_string())),
            Ok(None) => {}
            Err(e) => {
                let _ = updates.send(Update::Notice(format!("checkpoint skipped: {e}")));
            }
        }
        let before = crate::git::worktree_fingerprint(&self.project.root);
        let mut next_prompt = prompt.to_string();
        let mut fix_round = 0u32;
        // Any new message (including a bare option value answering an
        // approval left pending by a non-interactive run) consumes the
        // pending marker; the engine resolves the approval from the text.
        self.pending_approval = None;
        loop {
            if let Some(limit) = self.settings.max_session_tokens
                && let Ok(usage) = self.usage().await
            {
                let used = (usage.input_tokens + usage.output_tokens).max(0) as u64;
                if used >= limit {
                    let _ = updates.send(Update::Notice(format!(
                        "token budget reached: this session used {used} of {limit} tokens; raise it with --max-session-tokens or start a new session"
                    )));
                    report.budget_exhausted = true;
                    report.failed = true;
                    report.status = "budget_exhausted".into();
                    return Ok(report);
                }
            }
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
            let changed_now = !report.changed_files.is_empty() || worktree_changed;
            if changed_now && self.settings.mode != Mode::Plan && self.project.trusted {
                let hooks = self.project.config.hooks.after_edit.clone();
                self.run_hooks("after_edit", &hooks, updates).await;
            }
            let lsp = if changed_now {
                let files = report.changed_files.clone();
                self.lsp_check(&files, updates).await
            } else {
                None
            };
            let lsp_passed = lsp.as_ref().is_some_and(|outcome| outcome.success);
            let lsp_failure = lsp.filter(|outcome| !outcome.success);
            if lsp_failure.is_none() && (!self.verify_active() || !changed_now) {
                // Language-server diagnostics were the only check: their
                // result is the turn's (it may follow a failed round).
                if lsp_passed {
                    report.checks_passed = Some(true);
                }
                self.finish_turn(&report, updates).await;
                return Ok(report);
            }
            let result = match lsp_failure {
                Some(failure) => Some(Some(failure)),
                None => {
                    let checks = self.project.auto_checks();
                    self.run_checks(&checks, updates, controls).await
                }
            };
            match result {
                None => {
                    report.cancelled = true;
                    return Ok(report);
                }
                Some(None) => {
                    report.checks_passed = Some(true);
                    self.finish_turn(&report, updates).await;
                    return Ok(report);
                }
                Some(Some(failure)) => {
                    report.checks_passed = Some(false);
                    if fix_round >= self.settings.max_fix_rounds {
                        let _ = updates.send(Update::ChecksGaveUp(failure));
                        self.finish_turn(&report, updates).await;
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

    struct Idle;

    #[async_trait::async_trait]
    impl microclaw_sdk::RunExecutor for Idle {
        async fn execute(
            &self,
            _profile: microclaw_sdk::AgentProfile,
            request: RunRequest,
            _context: microclaw_sdk::ExecutionContext,
        ) -> Result<microclaw_sdk::ExecutionResult, microclaw_sdk::RuntimeError> {
            Ok(microclaw_sdk::ExecutionResult::new("t", request.prompt))
        }
    }

    fn session(mode: Mode, sandbox: Option<SandboxInfo>) -> (CodeSession, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let project = Project::discover(dir.path(), |_, _| false).unwrap();
        let microclaw = MicroClaw::from_runtime(
            microclaw_sdk::Runtime::builder()
                .executor(Idle)
                .build()
                .unwrap(),
        );
        let settings = SessionSettings {
            max_session_tokens: None,
            mode,
            verify: false,
            max_fix_rounds: 0,
            interactive: true,
            sandbox,
        };
        let session = CodeSession::new(microclaw, project, "s".into(), settings)
            .with_allow_rules(AllowRules::load(dir.path().join("allow.json")));
        (session, dir)
    }

    fn bash(command: &str, advisory: Option<&str>) -> PendingApproval {
        PendingApproval::from_event("id", "bash", Some(command), &[], advisory)
    }

    #[test]
    fn gate_follows_mode_sandbox_rules_and_reviews() {
        let no_net = SandboxInfo {
            mechanism: "bubblewrap".into(),
            network: false,
            confines_reads: true,
        };
        let (ask, _d1) = session(Mode::Ask, None);
        assert!(matches!(ask.gate(&bash("cargo test", None)), Gate::Ask));

        let (sandboxed, _d2) = session(Mode::Ask, Some(no_net.clone()));
        assert!(matches!(
            sandboxed.gate(&bash("cargo test", None)),
            Gate::Auto { rule: Some(ref r) } if r == SANDBOX_RULE
        ));
        // Destructive commands still ask inside the sandbox.
        assert!(matches!(sandboxed.gate(&bash("git push", None)), Gate::Ask));

        let with_net = SandboxInfo {
            network: true,
            ..no_net.clone()
        };
        let (networked, _d3) = session(Mode::Ask, Some(with_net));
        assert!(matches!(
            networked.gate(&bash("cargo test", None)),
            Gate::Ask
        ));

        let landlock = SandboxInfo {
            mechanism: "landlock".into(),
            confines_reads: false,
            ..no_net
        };
        let (weak, _d4) = session(Mode::Ask, Some(landlock));
        assert!(matches!(weak.gate(&bash("cargo test", None)), Gate::Ask));

        let (auto, _d5) = session(Mode::Auto, None);
        assert!(matches!(
            auto.gate(&bash("make", None)),
            Gate::Auto { rule: None }
        ));
        assert!(matches!(
            auto.gate(&bash("make clean-db", Some("DANGEROUS drops the database"))),
            Gate::Ask
        ));
        assert!(matches!(
            auto.gate(&bash("make", Some("CAUTION writes files"))),
            Gate::Auto { .. }
        ));
    }
}
