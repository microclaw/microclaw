//! Full-screen terminal UI for MicroClaw Code.
//!
//! The UI owns presentation and input only. A user turn runs on a Tokio task
//! that owns the [`CodeSession`]; the UI talks to it through
//! [`Control`]s and folds the returned [`Update`]s into the transcript.

mod input;
mod transcript;
mod view;

use std::io::Stdout;
use std::time::{Duration, Instant};

use crossterm::event::{Event, EventStream, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use futures_util::StreamExt;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::task::JoinHandle;

use crate::format;
use microclaw_code_core::allow;
use microclaw_code_core::driver::{
    CodeSession, Control, HistoryEntry, PendingApproval, TurnReport, Update,
};
use microclaw_code_core::project::{self, Mode, Project};
use microclaw_code_core::sessions::SessionIndex;
use microclaw_code_core::trust::{TrustDecision, TrustStore};
use microclaw_code_core::verify;

use input::InputBox;
use transcript::{Item, Tone, Transcript};

const SLASH_COMMANDS: &[(&str, &str)] = &[
    ("/help", "show commands and keys"),
    ("/mode", "show or set the mode: plan, ask, auto"),
    ("/plan", "switch to plan mode, optionally with a task"),
    ("/check", "run project checks (all or named)"),
    ("/verify", "turn automatic checks after edits on/off"),
    (
        "/trust",
        "trust this project (honour .microclaw/project.yaml)",
    ),
    (
        "/allow",
        "list, add or remove commands that run without asking",
    ),
    ("/diff", "show git diff --stat (or `full`)"),
    (
        "/undo",
        "restore files to before the last turn that changed them",
    ),
    ("/rewind", "list checkpoints, or restore one: /rewind <id>"),
    (
        "/review",
        "review uncommitted changes (read-only), optionally /review <focus>",
    ),
    (
        "/model",
        "show or switch this session's model: /model <name> | reset",
    ),
    ("/cost", "token usage of this session"),
    (
        "/compact",
        "summarize older messages to free context (/compact <focus>)",
    ),
    ("/context", "show how full the context window is"),
    ("/fork", "continue in a copy of this conversation"),
    (
        "/handoff",
        "start a new session from a summary focused on the next task",
    ),
    ("/new", "start a new session"),
    ("/sessions", "list this project's sessions"),
    ("/status", "show project, mode and session details"),
    ("/init", "write .microclaw/project.yaml"),
    ("/clear", "clear the screen (the session continues)"),
    ("/exit", "quit"),
];

pub enum Dialog {
    Approval(PendingApproval),
    Trust {
        root: String,
        has_config: bool,
        changed: bool,
    },
    ExecutePlan,
}

/// Session commands that need the engine (run like a short turn).
enum SessionOp {
    Undo,
    Rewind(Option<String>),
    Cost,
    Model(Option<String>),
    Compact(Option<String>),
    Context,
    Fork(String),
    Handoff(String, String),
}

/// `/context`: window, threshold and where the tokens go.
fn context_report(u: &microclaw_sdk::ContextUsage) -> String {
    let t = |n: usize| format::tokens(n as i64);
    let mut text = format!(
        "context: ~{} of {} tokens ({}%) · model {}\n",
        t(u.used_tokens),
        t(u.window),
        u.percent_used(),
        u.model
    );
    if u.auto_compact_threshold > 0 {
        text.push_str(&format!(
            "automatic compaction at ~{} tokens ({} left)\n",
            t(u.auto_compact_threshold),
            t(u.auto_compact_threshold.saturating_sub(u.used_tokens))
        ));
    } else {
        text.push_str("automatic compaction is off\n");
    }
    if let Some(last) = u.last_request_tokens {
        text.push_str(&format!("last request: {} input tokens\n", t(last)));
    }
    text.push_str(&format!(
        "conversation ({} messages): summary {} · your messages {} · replies {} · tool calls {} · tool output {}",
        u.messages,
        t(u.summary_tokens),
        t(u.user_tokens),
        t(u.assistant_tokens),
        t(u.tool_call_tokens),
        t(u.tool_result_tokens),
    ));
    if u.image_tokens > 0 {
        text.push_str(&format!(" · images {}", t(u.image_tokens)));
    }
    text.push_str("\n/compact <focus> summarizes now");
    text
}

async fn run_session_op(
    session: &mut CodeSession,
    op: SessionOp,
    updates: &UnboundedSender<Update>,
) {
    let notice = |text: String| {
        let _ = updates.send(Update::Notice(text));
    };
    match op {
        SessionOp::Undo => match session.undo().await {
            Ok(Some((checkpoint, prompt))) => notice(format!(
                "restored files to checkpoint {} (before “{}”); /rewind lists checkpoints, including the state you just left",
                checkpoint.commit,
                format::truncate(&prompt, 60)
            )),
            Ok(None) => notice("nothing to undo in this session".into()),
            Err(e) => notice(format!("undo failed: {e}")),
        },
        SessionOp::Rewind(None) => match session.checkpoints(15).await {
            Ok(list) if list.is_empty() => notice("no checkpoints yet".into()),
            Ok(list) => {
                let mut text = String::from("checkpoints (newest first; /rewind <id> restores):");
                for c in list {
                    text.push_str(&format!("\n  {}  {}  {}", c.commit, c.timestamp, c.label));
                }
                notice(text)
            }
            Err(e) => notice(format!("could not list checkpoints: {e}")),
        },
        SessionOp::Rewind(Some(commit)) => match session.rewind(&commit).await {
            Ok(()) => notice(format!("restored files to checkpoint {commit}")),
            Err(e) => notice(format!("rewind failed: {e}")),
        },
        SessionOp::Cost => match session.usage().await {
            Ok(usage) if usage.requests == 0 => {
                notice("no model requests in this session yet".into())
            }
            Ok(usage) => {
                let mut text = format!(
                    "this session: {} requests · {} input + {} output tokens",
                    usage.requests,
                    format::tokens(usage.input_tokens),
                    format::tokens(usage.output_tokens)
                );
                if usage.by_model.len() > 1 {
                    for m in &usage.by_model {
                        text.push_str(&format!(
                            "\n  {}: {} requests · {} in · {} out",
                            m.model,
                            m.requests,
                            format::tokens(m.input_tokens),
                            format::tokens(m.output_tokens)
                        ));
                    }
                }
                notice(text)
            }
            Err(e) => notice(format!("could not read usage: {e}")),
        },
        SessionOp::Model(None) => match session.model().await {
            Ok(model) => notice(format!(
                "model: {model} (switch with /model <name>, /model reset)"
            )),
            Err(e) => notice(format!("could not read the model: {e}")),
        },
        SessionOp::Model(Some(name)) => {
            let target = (name != "reset" && name != "default").then_some(name.as_str());
            match session.set_model(target).await {
                Ok(model) => notice(format!("model for this session: {model}")),
                Err(e) => notice(format!("could not switch the model: {e}")),
            }
        }
        SessionOp::Compact(focus) => match session.compact(focus.as_deref()).await {
            Ok(c) if c.method != "none" => notice(format!(
                "compacted the conversation ({}): {} → {} messages, ~{} → ~{} tokens",
                c.method,
                c.messages_before,
                c.messages_after,
                format::tokens(c.tokens_before as i64),
                format::tokens(c.tokens_after as i64),
            )),
            Ok(_) => notice("the conversation is already short; nothing to compact".into()),
            Err(e) => notice(format!("compact failed: {e}")),
        },
        SessionOp::Context => match session.context_usage().await {
            Ok(u) => notice(context_report(&u)),
            Err(e) => notice(format!("could not read the context: {e}")),
        },
        SessionOp::Handoff(new_id, goal) => {
            let from = session.session_id.clone();
            match session.handoff(new_id, &goal).await {
                Ok(tokens) => notice(format!(
                    "handed off {from} → {} (~{} tokens of context); {from} is unchanged",
                    session.session_id,
                    format::tokens(tokens as i64)
                )),
                Err(e) => notice(format!("handoff failed: {e}")),
            }
        }
        SessionOp::Fork(new_id) => {
            let from = session.session_id.clone();
            match session.fork(new_id).await {
                Ok(()) => notice(format!(
                    "forked {from} → {}; you are now in the copy (the original is unchanged)",
                    session.session_id
                )),
                Err(e) => notice(format!("fork failed: {e}")),
            }
        }
    }
}

pub struct RunningTurn {
    pub started: Instant,
    controls: UnboundedSender<Control>,
    handle: JoinHandle<(CodeSession, anyhow::Result<TurnReport>)>,
    /// The turn ran in plan mode (offer to execute the plan afterwards).
    plan: bool,
}

pub struct App {
    session: Option<CodeSession>,
    pub running: Option<RunningTurn>,
    updates_tx: UnboundedSender<Update>,
    updates_rx: UnboundedReceiver<Update>,
    pub transcript: Transcript,
    pub input: InputBox,
    pub dialog: Option<Dialog>,
    pub mode: Mode,
    pub trusted: bool,
    pub project_name: String,
    pub branch: Option<String>,
    pub session_label: String,
    pub scroll: usize,
    pub hint: Option<String>,
    /// Context window in use after the last turn (status bar).
    pub context_pct: Option<u8>,
    quit_armed: Option<Instant>,
    should_quit: bool,
    files: Option<Vec<String>>,
    index: SessionIndex,
    trust_store: TrustStore,
    checks_task: Option<JoinHandle<()>>,
}

/// Restore the terminal even when the app panics.
fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(std::io::stdout(), LeaveAlternateScreen);
        previous(info);
    }));
}

fn setup_terminal() -> anyhow::Result<Terminal<CrosstermBackend<Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    Ok(Terminal::new(CrosstermBackend::new(stdout))?)
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<Stdout>>) {
    let _ = disable_raw_mode();
    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
    let _ = terminal.show_cursor();
}

/// Run the TUI until the user quits. Returns the session id.
fn sandbox_label(sandbox: &microclaw_code_core::driver::SandboxInfo) -> String {
    format!(
        "shell sandbox: {} — commands write only the repository, temp and tool caches{}; network {}",
        sandbox.mechanism,
        if sandbox.confines_reads {
            ""
        } else {
            " (credential directories stay readable)"
        },
        if sandbox.network {
            "on"
        } else {
            "off, so commands run without asking in ask mode"
        }
    )
}

/// Messages of a resumed session shown before the prompt.
const HISTORY_LIMIT: usize = 60;

fn replay_history(transcript: &mut Transcript, session: &CodeSession) {
    let history = session.history(HISTORY_LIMIT);
    if history.is_empty() {
        transcript.notice(
            format!("session {} has no earlier messages", session.session_id),
            Tone::Info,
        );
        return;
    }
    transcript.notice(
        format!(
            "resumed session {} · last {} messages",
            session.session_id,
            history.len()
        ),
        Tone::Info,
    );
    for entry in history {
        match entry {
            HistoryEntry::User(text) => transcript.push(Item::User(text)),
            HistoryEntry::Agent(text) => transcript.push(Item::Assistant(text)),
            HistoryEntry::Verification(line) => {
                transcript.notice(format!("verification {line}"), Tone::Warning)
            }
        }
    }
    transcript.notice("— end of history —", Tone::Info);
}

pub async fn run(
    session: CodeSession,
    index: SessionIndex,
    trust_store: TrustStore,
    initial_prompt: Option<String>,
    notices: Vec<String>,
    resumed: bool,
) -> anyhow::Result<String> {
    let (updates_tx, updates_rx) = mpsc::unbounded_channel();
    let project = &session.project;
    let mut app = App {
        mode: session.settings.mode,
        trusted: project.trusted,
        project_name: project
            .root
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| project.root.display().to_string()),
        branch: microclaw_code_core::git::branch(&project.root),
        session_label: session.session_id.clone(),
        session: None,
        running: None,
        updates_tx,
        updates_rx,
        transcript: Transcript::default(),
        input: InputBox::default(),
        dialog: None,
        scroll: 0,
        hint: None,
        context_pct: None,
        quit_armed: None,
        should_quit: false,
        files: None,
        index,
        trust_store,
        checks_task: None,
    };
    app.transcript.notice(
        format!(
            "MicroClaw Code in {} · {} mode · {}",
            session.project.root.display(),
            session.settings.mode.as_str(),
            if session.project.trusted {
                "trusted"
            } else {
                "untrusted: checks will not run automatically"
            }
        ),
        Tone::Info,
    );
    if resumed {
        replay_history(&mut app.transcript, &session);
    }
    if let Some(sandbox) = &session.settings.sandbox {
        app.transcript.notice(sandbox_label(sandbox), Tone::Info);
    }
    for notice in notices {
        app.transcript.notice(notice, Tone::Warning);
    }
    let decision = app.trust_store.decision(
        &session.project.root,
        session.project.config_sha256.as_deref(),
    );
    let trust_matters = session.project.has_config_file || !session.project.checks.is_empty();
    if trust_matters
        && matches!(
            decision,
            TrustDecision::Undecided | TrustDecision::ConfigChanged
        )
    {
        app.dialog = Some(Dialog::Trust {
            root: session.project.root.display().to_string(),
            has_config: session.project.has_config_file,
            changed: decision == TrustDecision::ConfigChanged,
        });
    }
    app.session = Some(session);

    install_panic_hook();
    let mut terminal = setup_terminal()?;
    let result = app.event_loop(&mut terminal, initial_prompt).await;
    restore_terminal(&mut terminal);
    result?;
    Ok(app.session_label.clone())
}

impl App {
    async fn event_loop(
        &mut self,
        terminal: &mut Terminal<CrosstermBackend<Stdout>>,
        initial_prompt: Option<String>,
    ) -> anyhow::Result<()> {
        let mut events = EventStream::new();
        let mut tick = tokio::time::interval(Duration::from_millis(120));
        if let Some(prompt) = initial_prompt.filter(|p| !p.trim().is_empty()) {
            if self.dialog.is_none() {
                self.submit(prompt);
            } else {
                self.input.set_text(&prompt);
            }
        }
        loop {
            terminal.draw(|frame| view::draw(frame, self))?;
            if self.should_quit {
                return Ok(());
            }
            tokio::select! {
                event = events.next() => match event {
                    Some(Ok(Event::Key(key))) if key.kind != KeyEventKind::Release => self.on_key(key),
                    Some(Ok(Event::Paste(text))) => self.input.insert_str(&text.replace('\r', "\n")),
                    Some(Ok(_)) => {}
                    Some(Err(e)) => return Err(e.into()),
                    None => return Ok(()),
                },
                Some(update) = self.updates_rx.recv() => self.on_update(update),
                result = async { (&mut self.running.as_mut().unwrap().handle).await }, if self.running.is_some() => {
                    self.on_turn_finished(result);
                }
                _ = tick.tick() => {
                    if self.checks_task.as_ref().is_some_and(|t| t.is_finished()) {
                        self.checks_task = None;
                    }
                }
            }
        }
    }

    fn on_update(&mut self, update: Update) {
        if let Update::ContextPercent(pct) = &update {
            self.context_pct = Some(*pct);
            return;
        }
        if let Update::ApprovalRequested(approval) = &update {
            self.dialog = Some(Dialog::Approval(approval.clone()));
        }
        self.transcript.apply(&update);
    }

    fn on_turn_finished(
        &mut self,
        result: Result<(CodeSession, anyhow::Result<TurnReport>), tokio::task::JoinError>,
    ) {
        let running = self.running.take().expect("running turn");
        // Drain updates the task sent before finishing.
        while let Ok(update) = self.updates_rx.try_recv() {
            self.on_update(update);
        }
        if matches!(self.dialog, Some(Dialog::Approval(_))) {
            self.dialog = None;
        }
        match result {
            Ok((mut session, report)) => {
                session.settings.mode = self.mode;
                match report {
                    Ok(report) => {
                        if report.cancelled {
                            self.transcript.notice("stopped", Tone::Warning);
                        } else if report.checks_passed == Some(true) {
                            self.transcript.notice("all checks passed", Tone::Success);
                        }
                        let ok = !report.cancelled && !report.failed;
                        if running.plan && ok && self.mode == Mode::Plan {
                            self.dialog = Some(Dialog::ExecutePlan);
                        }
                    }
                    Err(e) => self.transcript.notice(format!("error: {e:#}"), Tone::Error),
                }
                self.session_label = session.session_id.clone();
                session.report_context_percent(self.updates_tx.clone());
                self.session = Some(session);
            }
            Err(e) => {
                self.transcript
                    .notice(format!("the turn crashed: {e}"), Tone::Error);
                self.should_quit = true;
            }
        }
        self.branch = self
            .session
            .as_ref()
            .and_then(|s| microclaw_code_core::git::branch(&s.project.root));
    }

    fn start_turn(&mut self, prompt: String, label: Option<String>) {
        let Some(mut session) = self.session.take() else {
            return;
        };
        session.settings.mode = self.mode;
        if let Err(e) = self.index.touch(&session.session_id, &prompt) {
            self.transcript.notice(
                format!("could not update the session index: {e}"),
                Tone::Warning,
            );
        }
        self.transcript
            .push(Item::User(label.unwrap_or_else(|| prompt.clone())));
        let (controls_tx, mut controls_rx) = mpsc::unbounded_channel();
        let updates = self.updates_tx.clone();
        let plan = self.mode == Mode::Plan;
        let handle = tokio::spawn(async move {
            let report = session.turn(&prompt, &updates, &mut controls_rx).await;
            (session, report)
        });
        self.running = Some(RunningTurn {
            started: Instant::now(),
            controls: controls_tx,
            handle,
            plan,
        });
        self.scroll = 0;
    }

    /// Run a session command in the background (the session is busy until
    /// it finishes, like a turn).
    fn start_session_op(&mut self, op: SessionOp) {
        let Some(mut session) = self.session.take() else {
            self.hint = Some("wait for the current turn to finish".into());
            return;
        };
        let (controls_tx, _controls_rx) = mpsc::unbounded_channel();
        let updates = self.updates_tx.clone();
        let handle = tokio::spawn(async move {
            run_session_op(&mut session, op, &updates).await;
            (session, Ok(TurnReport::default()))
        });
        self.running = Some(RunningTurn {
            started: Instant::now(),
            controls: controls_tx,
            handle,
            plan: false,
        });
    }

    fn start_review(&mut self, focus: Option<String>) {
        let Some(mut session) = self.session.take() else {
            self.hint = Some("wait for the current turn to finish".into());
            return;
        };
        self.transcript.push(Item::User(match &focus {
            Some(f) => format!("/review {f}"),
            None => "/review".into(),
        }));
        let (controls_tx, mut controls_rx) = mpsc::unbounded_channel();
        let updates = self.updates_tx.clone();
        let handle = tokio::spawn(async move {
            let report = session
                .review(focus.as_deref(), &updates, &mut controls_rx)
                .await;
            (session, report)
        });
        self.running = Some(RunningTurn {
            started: Instant::now(),
            controls: controls_tx,
            handle,
            plan: false,
        });
        self.scroll = 0;
    }

    fn send(&self, control: Control) {
        if let Some(running) = &self.running {
            let _ = running.controls.send(control);
        }
    }

    fn submit(&mut self, text: String) {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return;
        }
        if trimmed.starts_with('/') && !trimmed.starts_with("//") {
            self.command(trimmed);
            return;
        }
        if self.running.is_some() {
            self.transcript.push(Item::Steer(trimmed.to_string()));
            self.send(Control::Steer(trimmed.to_string()));
            return;
        }
        if self.checks_task.is_some() {
            self.hint = Some("checks are still running".into());
            self.input.set_text(trimmed);
            return;
        }
        self.start_turn(trimmed.to_string(), None);
    }

    fn cycle_mode(&mut self) {
        self.mode = match self.mode {
            Mode::Plan => Mode::Ask,
            Mode::Ask => Mode::Auto,
            Mode::Auto => Mode::Plan,
        };
        self.hint = Some(format!(
            "{} mode: {}",
            self.mode.as_str(),
            self.mode.describe()
        ));
        if let Some(session) = &mut self.session {
            session.settings.mode = self.mode;
        }
    }

    fn on_key(&mut self, key: KeyEvent) {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let alt = key.modifiers.contains(KeyModifiers::ALT);
        let shift = key.modifiers.contains(KeyModifiers::SHIFT);
        if !matches!(key.code, KeyCode::Char('c') if ctrl) {
            self.quit_armed = None;
        }
        if self.dialog.is_some() {
            self.on_dialog_key(key);
            return;
        }
        self.hint = None;
        match key.code {
            KeyCode::Char('c') if ctrl => {
                if self.running.is_some() {
                    self.send(Control::Cancel);
                    self.hint = Some("stopping…".into());
                } else if !self.input.is_empty() {
                    self.input.clear();
                } else if self
                    .quit_armed
                    .is_some_and(|at| at.elapsed() < Duration::from_secs(2))
                {
                    self.should_quit = true;
                } else {
                    self.quit_armed = Some(Instant::now());
                    self.hint = Some("press Ctrl+C again to quit".into());
                }
            }
            KeyCode::Char('d') if ctrl && self.input.is_empty() && self.running.is_none() => {
                self.should_quit = true;
            }
            KeyCode::Esc => {
                if self.running.is_some() {
                    self.send(Control::Cancel);
                    self.hint = Some("stopping…".into());
                }
            }
            KeyCode::BackTab => self.cycle_mode(),
            KeyCode::Enter if alt || shift => self.input.insert('\n'),
            KeyCode::Char('j') if ctrl => self.input.insert('\n'),
            KeyCode::Enter => {
                let text = self.input.text();
                if let Some(stripped) = text.strip_suffix('\\') {
                    self.input.set_text(&format!("{stripped}\n"));
                } else {
                    let text = self.input.submit();
                    self.submit(text);
                }
            }
            KeyCode::Tab => self.complete(),
            KeyCode::Backspace if alt || ctrl => self.input.delete_word(),
            KeyCode::Char('w') if ctrl => self.input.delete_word(),
            KeyCode::Backspace => self.input.backspace(),
            KeyCode::Delete => self.input.delete(),
            KeyCode::Left => self.input.left(),
            KeyCode::Right => self.input.right(),
            KeyCode::Home => self.input.home(),
            KeyCode::Char('a') if ctrl => self.input.home(),
            KeyCode::End if self.input.is_empty() => self.scroll = 0,
            KeyCode::End => self.input.end(),
            KeyCode::Char('e') if ctrl => self.input.end(),
            KeyCode::Char('u') if ctrl => self.input.clear(),
            KeyCode::Char('l') if ctrl => self.transcript.clear(),
            KeyCode::Up if !self.input.is_multiline() => self.input.history_prev(),
            KeyCode::Down if !self.input.is_multiline() => self.input.history_next(),
            KeyCode::PageUp => self.scroll += 10,
            KeyCode::PageDown => self.scroll = self.scroll.saturating_sub(10),
            KeyCode::Char(ch) if !ctrl => self.input.insert(ch),
            _ => {}
        }
    }

    fn on_dialog_key(&mut self, key: KeyEvent) {
        let Some(dialog) = self.dialog.take() else {
            return;
        };
        let answer = match key.code {
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => Some('\u{1b}'),
            KeyCode::Char(ch) => Some(ch.to_ascii_lowercase()),
            KeyCode::Esc => Some('\u{1b}'),
            _ => None,
        };
        match dialog {
            Dialog::Approval(approval) => {
                let value = match answer {
                    Some(ch @ '1'..='9') => Some(ch.to_string()),
                    Some('y') => Some("1".to_string()),
                    Some('p') => Some(microclaw_code_core::driver::ALLOW_RULE_OPTION.to_string()),
                    Some('n') | Some('\u{1b}') => Some(
                        approval
                            .options
                            .iter()
                            .find(|o| o.decision == microclaw_sdk::RuntimeApprovalDecision::Deny)
                            .map(|o| o.value.clone())
                            .unwrap_or_else(|| "3".into()),
                    ),
                    _ => None,
                };
                match value {
                    Some(v) if approval.has_option(&v) => {
                        let label = approval
                            .options
                            .iter()
                            .find(|o| o.value == v)
                            .map(|o| o.label.clone())
                            .unwrap_or_default();
                        self.transcript.notice(label, Tone::Info);
                        self.send(Control::Approve(v));
                    }
                    _ => self.dialog = Some(Dialog::Approval(approval)),
                }
            }
            Dialog::Trust {
                root,
                has_config,
                changed,
            } => match answer {
                Some('y') => self.set_trust(true),
                Some('n') | Some('\u{1b}') => self.set_trust(false),
                _ => {
                    self.dialog = Some(Dialog::Trust {
                        root,
                        has_config,
                        changed,
                    })
                }
            },
            Dialog::ExecutePlan => match answer {
                Some('y') => {
                    self.mode = Mode::Ask;
                    self.start_turn(
                        "The plan above is approved. Execute it now, then verify the result."
                            .into(),
                        Some("execute the plan".into()),
                    );
                }
                Some('n') | Some('\u{1b}') => {
                    self.hint = Some("still in plan mode; Shift+Tab switches mode".into())
                }
                _ => self.dialog = Some(Dialog::ExecutePlan),
            },
        }
    }

    fn set_trust(&mut self, trusted: bool) {
        let Some(session) = &mut self.session else {
            self.hint = Some("wait for the current turn to finish".into());
            return;
        };
        let root = session.project.root.clone();
        let hash = session.project.config_sha256.clone();
        if let Err(e) = self.trust_store.set(&root, trusted, hash.as_deref()) {
            self.transcript.notice(
                format!("could not save the trust decision: {e}"),
                Tone::Error,
            );
        }
        let mut project = session.project.clone();
        project.set_trusted(trusted);
        if trusted {
            if let Some(mode) = project.config.mode {
                self.mode = mode;
                session.settings.mode = mode;
            }
            if let Some(rounds) = project.config.max_fix_rounds {
                session.settings.max_fix_rounds = rounds;
            }
        }
        session.set_project(project);
        self.trusted = trusted;
        self.transcript.notice(
            if trusted {
                "project trusted: its settings apply and checks run after edits"
            } else {
                "project not trusted: its settings are ignored and checks do not run automatically"
            },
            Tone::Info,
        );
    }

    fn project(&self) -> Option<&Project> {
        self.session.as_ref().map(|s| &s.project)
    }

    fn command(&mut self, line: &str) {
        let mut parts = line.split_whitespace();
        let name = parts.next().unwrap_or("");
        let args: Vec<String> = parts.map(str::to_string).collect();
        let busy = self.running.is_some();
        match name {
            "/exit" | "/quit" | "/q" => self.should_quit = true,
            "/help" | "/?" => {
                let mut text = String::from("Commands:");
                for (cmd, desc) in SLASH_COMMANDS {
                    text.push_str(&format!("\n  {cmd:<10} {desc}"));
                }
                let custom = self.custom_commands();
                if !custom.is_empty() {
                    text.push_str("\nCustom commands:");
                    for c in &custom {
                        text.push_str(&format!(
                            "\n  /{:<9} {} ({})",
                            c.name, c.description, c.scope
                        ));
                    }
                }
                text.push_str(
                    "\nKeys: Enter send · Alt+Enter/Ctrl+J new line · Shift+Tab mode · Tab complete /commands and @files\n      Esc stop the agent · type while it works to guide it · PgUp/PgDn scroll · Ctrl+C twice quit",
                );
                self.transcript.notice(text, Tone::Info);
            }
            "/mode" => match args.first().map(|a| Mode::parse(a)) {
                Some(Some(mode)) => {
                    self.mode = mode;
                    if let Some(s) = &mut self.session {
                        s.settings.mode = mode;
                    }
                    self.transcript.notice(
                        format!("mode: {} — {}", mode.as_str(), mode.describe()),
                        Tone::Info,
                    );
                }
                Some(None) => self
                    .transcript
                    .notice("expected plan, ask or auto", Tone::Error),
                None => {
                    let mut text = String::new();
                    for mode in [Mode::Plan, Mode::Ask, Mode::Auto] {
                        let mark = if mode == self.mode { "●" } else { " " };
                        text.push_str(&format!(
                            "{mark} {:<5} {}\n",
                            mode.as_str(),
                            mode.describe()
                        ));
                    }
                    self.transcript.notice(text.trim_end(), Tone::Info);
                }
            },
            "/plan" => {
                self.mode = Mode::Plan;
                if let Some(s) = &mut self.session {
                    s.settings.mode = Mode::Plan;
                }
                self.transcript.notice(
                    format!("mode: plan — {}", Mode::Plan.describe()),
                    Tone::Info,
                );
                if !args.is_empty() && !busy {
                    self.start_turn(args.join(" "), None);
                }
            }
            "/check" => self.run_checks(&args),
            "/verify" => match (args.first().map(String::as_str), &mut self.session) {
                (Some("on"), Some(s)) if !s.project.trusted => self
                    .transcript
                    .notice("this project is not trusted; run /trust first", Tone::Error),
                (Some(v @ ("on" | "off")), Some(s)) => {
                    s.settings.verify = v == "on";
                    self.transcript
                        .notice(format!("auto-verify {v}"), Tone::Info);
                }
                (_, Some(s)) => {
                    let names: Vec<_> = s
                        .project
                        .auto_checks()
                        .into_iter()
                        .map(|c| c.name)
                        .collect();
                    self.transcript.notice(
                        format!(
                            "auto-verify is {} (auto checks: {})",
                            if s.settings.verify && s.project.verify_enabled() {
                                "on"
                            } else {
                                "off"
                            },
                            if names.is_empty() {
                                "none".into()
                            } else {
                                names.join(", ")
                            }
                        ),
                        Tone::Info,
                    );
                }
                (_, None) => self.hint = Some("wait for the current turn to finish".into()),
            },
            "/trust" => self.set_trust(args.first().map(String::as_str) != Some("off")),
            "/allow" => {
                let Some(session) = self.session.as_mut() else {
                    self.hint = Some("wait for the current turn to finish".into());
                    return;
                };
                let root = session.project.root.clone();
                let rest = args.get(1..).unwrap_or_default().join(" ");
                let (text, tone) = match args.first().map(String::as_str) {
                    Some("add") if !rest.is_empty() => {
                        match session.allow_rules_mut().add(&root, &rest) {
                            Ok(true) => (
                                format!("`{}` now runs without asking", allow::normalize(&rest)),
                                Tone::Success,
                            ),
                            Ok(false) => ("already allowed".into(), Tone::Info),
                            Err(e) => (e.to_string(), Tone::Error),
                        }
                    }
                    Some("rm" | "remove") if !rest.is_empty() => {
                        match session.allow_rules_mut().remove(&root, &rest) {
                            Ok(true) => {
                                (format!("removed `{}`", allow::normalize(&rest)), Tone::Info)
                            }
                            Ok(false) => ("no such rule".into(), Tone::Warning),
                            Err(e) => (e.to_string(), Tone::Error),
                        }
                    }
                    None | Some("list") => {
                        let rules = session.allow_rules().for_project(&root);
                        if rules.is_empty() {
                            (
                                "no allow rules; choose \"always allow … in this project\" on a shell approval, or /allow add <command prefix>".into(),
                                Tone::Info,
                            )
                        } else {
                            (
                                format!(
                                    "commands that run without asking (destructive ones still ask):\n  {}",
                                    rules.join("\n  ")
                                ),
                                Tone::Info,
                            )
                        }
                    }
                    _ => (
                        "usage: /allow [list | add <prefix> | rm <prefix>]".into(),
                        Tone::Warning,
                    ),
                };
                self.transcript.notice(text, tone);
            }
            "/diff" => {
                let Some(root) = self.project().map(|p| p.root.clone()) else {
                    return;
                };
                let mut cmd = std::process::Command::new("git");
                cmd.current_dir(&root)
                    .args(["--no-pager", "diff", "--no-color"]);
                if args.first().map(String::as_str) != Some("full") {
                    cmd.arg("--stat");
                }
                match cmd.output() {
                    Ok(out) => {
                        let text = String::from_utf8_lossy(&out.stdout).trim_end().to_string();
                        self.transcript.notice(
                            if text.is_empty() {
                                "no changes".into()
                            } else {
                                text
                            },
                            Tone::Info,
                        );
                    }
                    Err(e) => self
                        .transcript
                        .notice(format!("git diff failed: {e}"), Tone::Error),
                }
            }
            "/undo" | "/rewind" | "/cost" | "/usage" | "/model" | "/compact" | "/fork"
            | "/review" | "/context" | "/handoff"
                if busy =>
            {
                self.hint = Some("wait for the current turn to finish".into());
            }
            "/undo" => self.start_session_op(SessionOp::Undo),
            "/rewind" => self.start_session_op(SessionOp::Rewind(args.first().cloned())),
            "/cost" | "/usage" => self.start_session_op(SessionOp::Cost),
            "/model" => {
                self.start_session_op(SessionOp::Model((!args.is_empty()).then(|| args.join(" "))))
            }
            "/compact" => self.start_session_op(SessionOp::Compact(
                (!args.is_empty()).then(|| args.join(" ")),
            )),
            "/context" => self.start_session_op(SessionOp::Context),
            "/review" => self.start_review((!args.is_empty()).then(|| args.join(" "))),
            "/export" => {
                let Some(session) = &self.session else {
                    self.hint = Some("wait for the current turn to finish".into());
                    return;
                };
                let path = match args.first() {
                    Some(path) => std::path::PathBuf::from(path),
                    None => session
                        .project
                        .root
                        .join(format!("mccode-{}.md", session.session_id)),
                };
                match session
                    .export_markdown()
                    .and_then(|text| std::fs::write(&path, text).map_err(Into::into))
                {
                    Ok(()) => self
                        .transcript
                        .notice(format!("wrote {}", path.display()), Tone::Success),
                    Err(e) => self
                        .transcript
                        .notice(format!("export failed: {e}"), Tone::Error),
                }
            }
            "/handoff" if args.is_empty() => {
                self.hint = Some("usage: /handoff <the next task>".into());
            }
            "/handoff" => {
                let Some(root) = self.project().map(|p| p.root.clone()) else {
                    return;
                };
                match self.index.create(&root) {
                    Ok(record) => {
                        let _ = self.index.touch(&record.id, &args.join(" "));
                        self.start_session_op(SessionOp::Handoff(record.id, args.join(" ")))
                    }
                    Err(e) => self.transcript.notice(e.to_string(), Tone::Error),
                }
            }
            "/fork" => {
                let Some(root) = self.project().map(|p| p.root.clone()) else {
                    return;
                };
                match self.index.create(&root) {
                    Ok(record) => self.start_session_op(SessionOp::Fork(record.id)),
                    Err(e) => self.transcript.notice(e.to_string(), Tone::Error),
                }
            }
            "/new" => {
                if busy {
                    self.hint = Some("wait for the current turn to finish".into());
                    return;
                }
                let Some(session) = &mut self.session else {
                    return;
                };
                match self.index.create(&session.project.root) {
                    Ok(record) => {
                        session.reset(record.id.clone());
                        self.session_label = record.id.clone();
                        self.transcript.clear();
                        self.transcript
                            .notice(format!("new session {}", record.id), Tone::Info);
                    }
                    Err(e) => self.transcript.notice(e.to_string(), Tone::Error),
                }
            }
            "/sessions" => {
                let Some(root) = self.project().map(|p| p.root.clone()) else {
                    return;
                };
                let records = self.index.for_project(&root);
                let mut text = String::from("Sessions (resume with `mccode --session <id>`):");
                for r in records.iter().take(15) {
                    let mark = if r.id == self.session_label {
                        "●"
                    } else {
                        " "
                    };
                    text.push_str(&format!(
                        "\n{mark} {}  {} turn(s)  {}",
                        r.id,
                        r.turns,
                        if r.title.is_empty() {
                            "(empty)"
                        } else {
                            &r.title
                        }
                    ));
                }
                self.transcript.notice(text, Tone::Info);
            }
            "/status" => {
                let text = match &self.session {
                    Some(s) => format!(
                        "project: {}\nmode: {}  ·  trusted: {}  ·  auto-verify: {}  ·  fix rounds: {}\nsession: {}\nchecks: {}\n{}",
                        s.project.root.display(),
                        self.mode.as_str(),
                        if s.project.trusted { "yes" } else { "no" },
                        if s.settings.verify && s.project.verify_enabled() {
                            "on"
                        } else {
                            "off"
                        },
                        s.settings.max_fix_rounds,
                        s.session_id,
                        s.project
                            .checks
                            .iter()
                            .map(|c| format!("{}{}", c.name, if c.auto { "*" } else { "" }))
                            .collect::<Vec<_>>()
                            .join(", "),
                        match &s.settings.sandbox {
                            Some(sandbox) => sandbox_label(sandbox),
                            None => "shell sandbox: off".into(),
                        }
                    ),
                    None => "a turn is running".into(),
                };
                self.transcript.notice(text, Tone::Info);
            }
            "/init" => {
                let Some(project) = self.project() else {
                    return;
                };
                let path = project.config_path();
                if path.exists() {
                    self.transcript
                        .notice(format!("{} already exists", path.display()), Tone::Warning);
                    return;
                }
                let template = project::config_template(project);
                let result = std::fs::create_dir_all(path.parent().unwrap_or(&project.root))
                    .and_then(|_| std::fs::write(&path, template));
                match result {
                    Ok(()) => self.transcript.notice(
                        format!("wrote {}; /trust to apply it", path.display()),
                        Tone::Success,
                    ),
                    Err(e) => self.transcript.notice(e.to_string(), Tone::Error),
                }
            }
            "/clear" => self.transcript.clear(),
            _ => match microclaw_code_core::commands::expand(&self.custom_commands(), line) {
                Some(_) if busy => {
                    self.hint = Some("wait for the current turn to finish".into());
                }
                Some(prompt) => self.start_turn(prompt, Some(line.trim().to_string())),
                None => self.transcript.notice(
                    format!("unknown command {name}; /help lists commands"),
                    Tone::Error,
                ),
            },
        }
    }

    /// Custom commands (`.microclaw/commands`, `~/.microclaw/code/commands`).
    fn custom_commands(&self) -> Vec<microclaw_code_core::commands::CustomCommand> {
        match self.project() {
            Some(project) => microclaw_code_core::commands::load(
                project,
                &microclaw_code_core::commands::personal_dir(),
            ),
            None => Vec::new(),
        }
    }

    fn run_checks(&mut self, names: &[String]) {
        if self.running.is_some() || self.checks_task.is_some() {
            self.hint = Some("busy; try again when the current work finishes".into());
            return;
        }
        let Some(project) = self.project().cloned() else {
            return;
        };
        let checks: Vec<_> = if names.is_empty() || names.iter().any(|n| n == "all") {
            project.checks.clone()
        } else {
            project
                .checks
                .iter()
                .filter(|c| names.contains(&c.name))
                .cloned()
                .collect()
        };
        if checks.is_empty() {
            self.transcript
                .notice("no matching checks; /init to configure them", Tone::Warning);
            return;
        }
        let updates = self.updates_tx.clone();
        self.checks_task = Some(tokio::spawn(async move {
            for check in checks {
                let _ = updates.send(Update::CheckStarted(check.clone()));
                let outcome = verify::run_check(&project.root, &check).await;
                let failed = !outcome.success;
                let tail = verify::tail(outcome.output.trim_end(), 1_500).to_string();
                let _ = updates.send(Update::CheckFinished(outcome));
                if failed {
                    let _ = updates.send(Update::Notice(tail));
                    break;
                }
            }
        }));
    }

    /// Tab completion for slash commands and `@file` mentions.
    fn complete(&mut self) {
        let word = self.input.current_word();
        let candidates: Vec<String> = if word.starts_with('/') && self.input.text().trim() == word {
            SLASH_COMMANDS
                .iter()
                .map(|(c, _)| c.to_string())
                .chain(
                    self.custom_commands()
                        .iter()
                        .map(|c| format!("/{}", c.name)),
                )
                .filter(|c| c.starts_with(&word))
                .collect()
        } else if let Some(prefix) = word.strip_prefix('@') {
            let files = self.files();
            files
                .iter()
                .filter(|f| f.starts_with(prefix))
                .take(200)
                .map(|f| format!("@{f}"))
                .collect()
        } else {
            return;
        };
        match candidates.len() {
            0 => self.hint = Some("no matches".into()),
            1 => {
                let mut c = candidates[0].clone();
                c.push(' ');
                self.input.replace_current_word(&c);
            }
            _ => {
                let common = common_prefix(&candidates);
                if common.chars().count() > word.chars().count() {
                    self.input.replace_current_word(&common);
                }
                let shown: Vec<_> = candidates.iter().take(8).cloned().collect();
                let more = candidates.len().saturating_sub(shown.len());
                self.hint = Some(format!(
                    "{}{}",
                    shown.join("  "),
                    if more > 0 {
                        format!("  (+{more})")
                    } else {
                        String::new()
                    }
                ));
            }
        }
    }

    fn files(&mut self) -> &[String] {
        if self.files.is_none() {
            let root = self.project().map(|p| p.root.clone());
            let files = root
                .and_then(|root| {
                    std::process::Command::new("git")
                        .args(["ls-files", "--cached", "--others", "--exclude-standard"])
                        .current_dir(root)
                        .output()
                        .ok()
                })
                .map(|out| {
                    String::from_utf8_lossy(&out.stdout)
                        .lines()
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            self.files = Some(files);
        }
        self.files.as_deref().unwrap_or_default()
    }
}

fn common_prefix(items: &[String]) -> String {
    let Some(first) = items.first() else {
        return String::new();
    };
    let mut prefix: Vec<char> = first.chars().collect();
    for item in &items[1..] {
        let common = prefix
            .iter()
            .zip(item.chars())
            .take_while(|(a, b)| **a == *b)
            .count();
        prefix.truncate(common);
    }
    prefix.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_prefix_of_candidates() {
        let items = vec!["@src/main.rs".to_string(), "@src/mod.rs".to_string()];
        assert_eq!(common_prefix(&items), "@src/m");
        assert_eq!(common_prefix(&["/help".to_string()]), "/help");
    }
}
