//! Terminal UI for MicroClaw Code.
//!
//! The UI owns presentation and input only. A user turn runs on a Tokio task
//! that owns the [`CodeSession`]; the UI talks to it through
//! [`Control`]s and folds the returned [`Update`]s into the transcript.
//!
//! Two screen modes: fullscreen (alternate screen, the default) and inline
//! (finished transcript items are written into the terminal's own
//! scrollback; only the live tail, status and input are redrawn).

mod commands;
mod configure;
mod dialogs;
mod input;
mod keymap;
mod keys;
mod notify;
mod pager;
mod popup;
#[cfg(test)]
mod preview;
mod review;
mod transcript;
mod view;

use std::io::Stdout;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crossterm::event::{
    DisableBracketedPaste, DisableFocusChange, DisableMouseCapture, EnableBracketedPaste,
    EnableFocusChange, EnableMouseCapture, Event, EventStream, KeyEventKind, MouseButton,
    MouseEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use futures_util::StreamExt;
use ratatui::backend::CrosstermBackend;
use ratatui::{Terminal, TerminalOptions, Viewport};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::task::JoinHandle;

use microclaw_code_core::driver::{CodeSession, Control, HistoryEntry, TurnReport, Update};
use microclaw_code_core::project::Mode;
use microclaw_code_core::sessions::SessionIndex;
use microclaw_code_core::settings::{CodeSettings, ScreenMode, SidebarMode};
use microclaw_code_core::trust::{TrustDecision, TrustStore};

use crate::ui::theme::Theme;
use dialogs::{ApprovalDialog, Dialog};
use input::InputBox;
use transcript::{Item, RenderOptions, Tone, Transcript};

/// Settings and environment the TUI needs besides the session.
pub struct TuiOptions {
    pub settings: CodeSettings,
    /// Warnings from loading settings, keymap and theme (shown at start).
    pub warnings: Vec<String>,
    /// Where `/theme` and `/config set` write user settings.
    pub user_settings_path: PathBuf,
    pub themes_dir: PathBuf,
    /// Where prompt history is kept.
    pub history_file: PathBuf,
    /// The model the session starts with.
    pub model: String,
    /// Push notifications / approvals to a chat (paired Server).
    pub remote: Option<microclaw_code_core::remote_notify::RemoteNotifier>,
    /// Permission-rule and hook events from the tool gate.
    pub gate_events: Option<UnboundedReceiver<microclaw_code_core::gate::GateEvent>>,
    /// Called after settings change (`/config set`, `/permissions add`) so
    /// the tool gate picks up new rules and hooks.
    pub on_settings_reload: Option<SettingsReload>,
    /// The lock on the session the TUI starts with; it follows `/new`,
    /// `/resume` and `/fork` at the next turn.
    pub session_lock: Option<microclaw_code_core::session_lock::SessionLock>,
}

pub type SettingsReload =
    Box<dyn Fn(&std::path::Path, &microclaw_code_core::settings::LoadedSettings) + Send>;

/// Results of background work started by the UI itself.
pub enum UiEvent {
    ShellLine(String),
    ShellDone(Option<i32>),
    SideAnswer(Result<String, String>),
    ConfigureReply(Result<String, String>),
    RemoteSent {
        approval_id: String,
        result: Result<String, String>,
    },
    RemoteAnswer {
        approval_id: String,
        value: String,
    },
    Info(String, Tone),
}

pub struct RunningTurn {
    pub started: Instant,
    controls: UnboundedSender<Control>,
    handle: JoinHandle<(CodeSession, anyhow::Result<TurnReport>)>,
    /// The turn ran in plan mode (offer to execute the plan afterwards).
    plan: bool,
    /// A real agent turn (receipt, notifications), not a session command.
    agent_turn: bool,
}

/// Where a goal turn leaves its `--until` outcome for `on_turn_finished`.
type UntilSlot =
    std::sync::Arc<std::sync::Mutex<Option<microclaw_code_core::verify::CheckOutcome>>>;

pub struct App {
    session: Option<CodeSession>,
    /// This front end drives the session (see `session_lock`).
    session_lock: Option<microclaw_code_core::session_lock::SessionLock>,
    /// Background work of the current session; usable while a turn runs.
    jobs: Option<microclaw_code_core::driver::JobHandle>,
    pub running: Option<RunningTurn>,
    updates_tx: UnboundedSender<Update>,
    updates_rx: UnboundedReceiver<Update>,
    ui_tx: UnboundedSender<UiEvent>,
    ui_rx: UnboundedReceiver<UiEvent>,
    gate_rx: Option<UnboundedReceiver<microclaw_code_core::gate::GateEvent>>,
    pub transcript: Transcript,
    pub input: InputBox,
    pub dialog: Option<Dialog>,
    pub popup: Option<popup::Popup>,
    pub mode: Mode,
    pub trusted: bool,
    pub project_name: String,
    pub branch: Option<String>,
    pub session_label: String,
    pub model: String,
    pub scroll: usize,
    pub hint: Option<String>,
    /// Files a command asked to open in `$EDITOR` (`/memory`).
    pub(crate) pending_editor: Option<keys::EditorRequest>,
    /// When the last agent turn ended (`None` after a compaction).
    last_request_end: Option<Instant>,
    /// Idle compaction schedule measured after the last turn.
    idle_plan: Option<microclaw_code_core::driver::IdleCompactPlan>,
    /// Context window in use after the last turn (status bar).
    pub context_pct: Option<u8>,
    /// Tokens and estimated cost of this session (status bar).
    pub session_tokens: (i64, i64),
    pub session_cost: Option<f64>,
    /// Messages typed while a turn runs; sent as the next turns.
    pub queue: Vec<String>,
    /// `!` shell mode.
    pub shell_mode: bool,
    pub shell_running: bool,
    /// Context from `!commands` added to the next prompt.
    shell_context: Vec<String>,
    /// `/goal` in progress (shared loop in `microclaw_code_core::goal`).
    pub goal: Option<microclaw_code_core::goal::Goal>,
    goal_until: UntilSlot,
    pub settings: CodeSettings,
    pub theme: Theme,
    pub keymap: keymap::Keymap,
    pub render: RenderOptions,
    pub show_sidebar: bool,
    pub inline: bool,
    /// Items already written to the scrollback (inline mode).
    flushed: usize,
    pub focused: bool,
    last_input: Instant,
    last_esc: Option<Instant>,
    notifier: notify::Notifier,
    remote: Option<microclaw_code_core::remote_notify::RemoteNotifier>,
    pending_usage: Option<(i64, i64, String)>,
    /// Transcript line → item index, from the last frame (mouse clicks).
    pub line_owners: Vec<usize>,
    pub transcript_area: ratatui::layout::Rect,
    quit_armed: Option<Instant>,
    should_quit: bool,
    files: Option<Vec<String>>,
    index: SessionIndex,
    trust_store: TrustStore,
    checks_task: Option<JoinHandle<()>>,
    user_settings_path: PathBuf,
    themes_dir: PathBuf,
    last_title: String,
    /// Side-question handle kept while the session is busy with a turn.
    side_asker: Option<microclaw_code_core::driver::SideAsker>,
    on_settings_reload: Option<SettingsReload>,
}

type Term = Terminal<CrosstermBackend<Stdout>>;

/// Restore the terminal even when the app panics.
fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(
            std::io::stdout(),
            DisableMouseCapture,
            DisableBracketedPaste,
            DisableFocusChange,
            LeaveAlternateScreen
        );
        previous(info);
    }));
}

/// Inline viewport height (live tail, status and input).
const INLINE_HEIGHT: u16 = 16;

fn setup_terminal(inline: bool, mouse: bool) -> anyhow::Result<Term> {
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnableBracketedPaste, EnableFocusChange)?;
    if inline {
        let backend = CrosstermBackend::new(stdout);
        Ok(Terminal::with_options(
            backend,
            TerminalOptions {
                viewport: Viewport::Inline(INLINE_HEIGHT),
            },
        )?)
    } else {
        execute!(stdout, EnterAlternateScreen)?;
        if mouse {
            execute!(stdout, EnableMouseCapture)?;
        }
        Ok(Terminal::new(CrosstermBackend::new(stdout))?)
    }
}

fn restore_terminal(terminal: &mut Term, inline: bool) {
    let _ = disable_raw_mode();
    let _ = execute!(
        terminal.backend_mut(),
        DisableMouseCapture,
        DisableBracketedPaste,
        DisableFocusChange
    );
    if inline {
        let _ = terminal.clear();
    } else {
        let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
    }
    let _ = terminal.show_cursor();
}

/// Inline under Zellij (its alternate screen has no scrollback), otherwise
/// fullscreen.
pub fn resolve_screen(mode: Option<ScreenMode>) -> bool {
    match mode.unwrap_or(ScreenMode::Auto) {
        ScreenMode::Inline => true,
        ScreenMode::Fullscreen => false,
        ScreenMode::Auto => std::env::var_os("ZELLIJ").is_some(),
    }
}

pub(crate) fn sandbox_label(sandbox: &microclaw_code_core::driver::SandboxInfo) -> String {
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

/// Load the theme named in settings (falls back to `dark` with a warning).
pub fn load_theme(name: Option<&str>, themes_dir: &std::path::Path) -> (Theme, Vec<String>) {
    let name = name.unwrap_or("auto");
    let dark = crate::ui::theme::detect_dark_background();
    crate::ui::theme::resolve(name, Some(themes_dir), dark)
}

pub async fn run(
    session: CodeSession,
    index: SessionIndex,
    trust_store: TrustStore,
    initial_prompt: Option<String>,
    notices: Vec<String>,
    resumed: bool,
    options: TuiOptions,
) -> anyhow::Result<String> {
    let (updates_tx, updates_rx) = mpsc::unbounded_channel();
    let (ui_tx, ui_rx) = mpsc::unbounded_channel();
    let project = &session.project;
    let tui = options.settings.tui.clone();
    let (theme, theme_warnings) = load_theme(tui.theme.as_deref(), &options.themes_dir);
    let (keymap, keymap_warnings) = keymap::Keymap::from_config(&tui.keymap);
    let inline = resolve_screen(tui.screen);
    let mouse = tui.mouse.unwrap_or(true);
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
        model: options.model.clone(),
        jobs: Some(session.job_handle()),
        session: None,
        session_lock: options.session_lock,
        running: None,
        updates_tx,
        updates_rx,
        ui_tx,
        ui_rx,
        gate_rx: options.gate_events,
        transcript: Transcript::default(),
        input: InputBox::with_history_file(options.history_file.clone(), &project.root),
        dialog: None,
        popup: None,
        scroll: 0,
        hint: None,
        pending_editor: None,
        last_request_end: None,
        idle_plan: None,
        context_pct: None,
        session_tokens: (0, 0),
        session_cost: None,
        queue: Vec::new(),
        shell_mode: false,
        shell_running: false,
        shell_context: Vec::new(),
        goal: None,
        goal_until: UntilSlot::default(),
        render: RenderOptions {
            diff_style: tui
                .diff
                .unwrap_or(microclaw_code_core::settings::DiffStyle::Auto),
            expand_all: false,
        },
        show_sidebar: tui.sidebar != Some(SidebarMode::Hide),
        notifier: notify::Notifier::from_settings(tui.notifications.as_ref()),
        settings: options.settings.clone(),
        theme,
        keymap,
        inline,
        flushed: 0,
        focused: true,
        last_input: Instant::now(),
        last_esc: None,
        remote: options.remote,
        pending_usage: None,
        line_owners: Vec::new(),
        transcript_area: ratatui::layout::Rect::default(),
        quit_armed: None,
        should_quit: false,
        files: None,
        index,
        trust_store,
        checks_task: None,
        user_settings_path: options.user_settings_path,
        themes_dir: options.themes_dir,
        last_title: String::new(),
        side_asker: None,
        on_settings_reload: options.on_settings_reload,
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
    for notice in notices
        .into_iter()
        .chain(options.warnings)
        .chain(theme_warnings)
        .chain(keymap_warnings)
    {
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
    let mut terminal = match setup_terminal(inline, mouse && !inline) {
        Ok(t) => t,
        Err(e) if inline => {
            // Inline needs the terminal to report the cursor position.
            let _ = disable_raw_mode();
            app.inline = false;
            app.transcript.notice(
                format!("inline mode is not available in this terminal ({e}); using fullscreen"),
                Tone::Warning,
            );
            setup_terminal(false, mouse)?
        }
        Err(e) => return Err(e),
    };
    let inline = app.inline;
    let result = app.event_loop(&mut terminal, initial_prompt).await;
    if inline {
        // Leave the rest of the transcript in the scrollback.
        app.flush_inline(&mut terminal, true);
    }
    restore_terminal(&mut terminal, inline);
    notify::set_title("");
    result?;
    Ok(app.session_label.clone())
}

impl App {
    async fn event_loop(
        &mut self,
        terminal: &mut Term,
        initial_prompt: Option<String>,
    ) -> anyhow::Result<()> {
        let mut events = EventStream::new();
        let mut tick = tokio::time::interval(Duration::from_millis(90));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        if let Some(prompt) = initial_prompt.filter(|p| !p.trim().is_empty()) {
            if self.dialog.is_none() {
                self.submit(prompt);
            } else {
                self.input.set_text(&prompt);
            }
        }
        let mut dirty = true;
        loop {
            if dirty || self.animating() {
                if self.inline {
                    self.flush_inline(terminal, false);
                }
                terminal.draw(|frame| view::draw(frame, self))?;
                self.update_title();
                dirty = false;
            }
            if self.should_quit {
                return Ok(());
            }
            tokio::select! {
                event = events.next() => {
                    dirty = true;
                    match event {
                        Some(Ok(Event::Key(key))) if key.kind != KeyEventKind::Release => {
                            self.last_input = Instant::now();
                            let editor = self.on_key(key).or_else(|| self.pending_editor.take());
                            if let Some(editor) = editor {
                                self.run_editor(terminal, editor)?;
                            }
                        }
                        Some(Ok(Event::Paste(text))) => {
                            self.last_input = Instant::now();
                            self.on_paste(&text);
                        }
                        Some(Ok(Event::Mouse(mouse))) => self.on_mouse(mouse),
                        Some(Ok(Event::FocusGained)) => self.focused = true,
                        Some(Ok(Event::FocusLost)) => self.focused = false,
                        Some(Ok(Event::Resize(_, _))) => {
                            if self.inline {
                                let _ = terminal.autoresize();
                            }
                        }
                        Some(Ok(_)) => {}
                        Some(Err(e)) => return Err(e.into()),
                        None => return Ok(()),
                    }
                }
                Some(update) = self.updates_rx.recv() => {
                    dirty = true;
                    self.on_update(update);
                }
                Some(event) = self.ui_rx.recv() => {
                    dirty = true;
                    self.on_ui_event(event);
                }
                Some(event) = async {
                    match &mut self.gate_rx {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    dirty = true;
                    self.on_gate_event(event);
                }
                result = async { (&mut self.running.as_mut().unwrap().handle).await }, if self.running.is_some() => {
                    dirty = true;
                    self.on_turn_finished(result);
                }
                _ = tick.tick() => {
                    if self.checks_task.as_ref().is_some_and(|t| t.is_finished()) {
                        self.checks_task = None;
                        dirty = true;
                    }
                    self.maybe_send_remote_approval();
                    if self.maybe_idle_compact() {
                        dirty = true;
                    }
                }
            }
        }
    }

    /// Compact the session in the background when it has been idle for
    /// most of its prompt cache lifetime (`tui.idle_compact`). Returns true
    /// when it started.
    fn maybe_idle_compact(&mut self) -> bool {
        if self.running.is_some()
            || self.session.is_none()
            || self.dialog.is_some()
            || self.settings.tui.idle_compact == Some(false)
        {
            return false;
        }
        let (Some(end), Some(plan)) = (self.last_request_end, self.idle_plan) else {
            return false;
        };
        if !plan.due(end.elapsed()) {
            return false;
        }
        self.idle_plan = None;
        self.transcript.notice(
            format!(
                "idle for {}s with ~{} tokens of context: compacting before the prompt cache expires (tui.idle_compact)",
                end.elapsed().as_secs(),
                crate::format::tokens(plan.used_tokens as i64)
            ),
            Tone::Info,
        );
        self.start_session_op(commands::SessionOp::IdleCompact);
        true
    }

    /// Something on screen animates (spinners).
    fn animating(&self) -> bool {
        self.running.is_some()
            || self.checks_task.is_some()
            || self.shell_running
            || self
                .transcript
                .items
                .last()
                .is_some_and(|i| matches!(i, Item::Side { answer: None, .. }))
    }

    fn update_title(&mut self) {
        let state = if matches!(self.dialog, Some(Dialog::Approval(_))) {
            "◐ needs approval"
        } else if self.running.is_some() {
            "● working"
        } else {
            "○ ready"
        };
        let title = format!("{state} · mccode · {}", self.project_name);
        if title != self.last_title {
            notify::set_title(&title);
            self.last_title = title;
        }
    }

    /// Inline mode: write settled items to the scrollback.
    fn flush_inline(&mut self, terminal: &mut Term, all: bool) {
        let settled = if all || self.running.is_none() {
            self.transcript.items.len()
        } else {
            let first_live = self
                .transcript
                .items
                .iter()
                .position(|i| {
                    matches!(
                        i,
                        Item::Tool(_)
                            | Item::Explore(_)
                            | Item::Check { .. }
                            | Item::Shell { .. }
                            | Item::Side { .. }
                    ) && self.item_live(i)
                })
                .unwrap_or(usize::MAX);
            first_live.min(self.transcript.items.len().saturating_sub(1))
        };
        if settled <= self.flushed {
            return;
        }
        let width = terminal.size().map(|s| s.width).unwrap_or(80);
        let lines =
            self.transcript
                .lines_of(self.flushed, settled, width, &self.theme, &self.render);
        self.flushed = settled;
        if lines.is_empty() {
            return;
        }
        let height = lines.len() as u16;
        let _ = terminal.insert_before(height, |buf| {
            use ratatui::widgets::Widget;
            ratatui::widgets::Paragraph::new(lines).render(buf.area, buf);
        });
    }

    fn item_live(&self, item: &Item) -> bool {
        match item {
            Item::Tool(t) => t.state == transcript::ToolState::Running,
            Item::Explore(c) => c.iter().any(|t| t.state == transcript::ToolState::Running),
            Item::Check { state, .. } => *state == transcript::CheckState::Running,
            Item::Shell { running, .. } => *running,
            Item::Side { answer, .. } => answer.is_none(),
            _ => false,
        }
    }

    /// First transcript item shown in the viewport (inline mode).
    pub fn first_visible_item(&self) -> usize {
        if self.inline { self.flushed } else { 0 }
    }

    fn on_update(&mut self, update: Update) {
        match &update {
            Update::ContextPercent(pct) => {
                self.context_pct = Some(*pct);
                return;
            }
            Update::IdleCompact(plan) => {
                self.idle_plan = *plan;
                return;
            }
            Update::TurnUsage {
                input_tokens,
                output_tokens,
                model,
            } => {
                self.pending_usage = Some((*input_tokens, *output_tokens, model.clone()));
                if !model.is_empty() {
                    self.model = model.clone();
                }
                self.session_tokens.0 += input_tokens;
                self.session_tokens.1 += output_tokens;
                if let Some(cost) = estimate_cost(model, *input_tokens, *output_tokens) {
                    *self.session_cost.get_or_insert(0.0) += cost;
                }
                return;
            }
            Update::ApprovalRequested(approval) => {
                self.dialog = Some(Dialog::Approval(ApprovalDialog::new(approval.clone())));
                self.notifier.notify(
                    self.focused,
                    "MicroClaw Code needs approval",
                    &format!(
                        "{}: {}",
                        approval.tool,
                        approval.preview.as_deref().unwrap_or("")
                    ),
                );
            }
            Update::ApprovalAnswered { .. } => {
                if let Some(Dialog::Approval(d)) = &self.dialog
                    && let Some(id) = d.remote.clone()
                {
                    self.cancel_remote(id);
                }
            }
            Update::ChecksGaveUp(outcome) => {
                self.notifier.notify(
                    self.focused,
                    "Checks still fail",
                    &format!("{} — over to you", outcome.check.name),
                );
                self.remote_notify("check_failed", "Checks still fail", &outcome.check.name);
            }
            _ => {}
        }
        self.transcript.apply(&update);
    }

    fn on_gate_event(&mut self, event: microclaw_code_core::gate::GateEvent) {
        use microclaw_code_core::gate::GateEvent;
        let (text, tone) = match event {
            GateEvent::Denied { tool, reason } => {
                (format!("blocked {tool}: {reason}"), Tone::Warning)
            }
            GateEvent::AskedByRule { tool, rule } => (
                format!("{tool} needs approval by rule `{rule}`"),
                Tone::Info,
            ),
            GateEvent::HookMessage { event, text } => (format!("{event} hook: {text}"), Tone::Info),
            GateEvent::HookFailed { event, error } => {
                (format!("{event} hook failed: {error}"), Tone::Warning)
            }
        };
        self.transcript.notice(text, tone);
    }

    fn on_ui_event(&mut self, event: UiEvent) {
        match event {
            UiEvent::ShellLine(line) => {
                if let Some(Item::Shell { output, .. }) = self
                    .transcript
                    .items
                    .iter_mut()
                    .rev()
                    .find(|i| matches!(i, Item::Shell { running: true, .. }))
                {
                    output.push(line);
                    if output.len() > 2_000 {
                        output.remove(0);
                    }
                }
                self.transcript.invalidate_last_shell();
            }
            UiEvent::ShellDone(code) => {
                self.shell_running = false;
                let mut context = None;
                if let Some(Item::Shell {
                    command,
                    output,
                    exit,
                    running,
                }) = self
                    .transcript
                    .items
                    .iter_mut()
                    .rev()
                    .find(|i| matches!(i, Item::Shell { running: true, .. }))
                {
                    *running = false;
                    *exit = code;
                    let tail: Vec<&String> = output.iter().rev().take(200).collect();
                    let body: String = tail
                        .into_iter()
                        .rev()
                        .map(String::as_str)
                        .collect::<Vec<_>>()
                        .join("\n");
                    context = Some(format!(
                        "[The user ran `{command}` (exit {}):\n{body}]",
                        code.map(|c| c.to_string()).unwrap_or_else(|| "?".into())
                    ));
                }
                self.transcript.invalidate_last_shell();
                if let Some(c) = context {
                    self.shell_context.push(c);
                    self.hint =
                        Some("the command output goes to the agent with your next message".into());
                }
            }
            UiEvent::SideAnswer(result) => {
                let text = match result {
                    Ok(t) if !t.trim().is_empty() => t,
                    Ok(_) => "(no answer)".into(),
                    Err(e) => format!("could not answer: {e}"),
                };
                if let Some(index) = self
                    .transcript
                    .items
                    .iter()
                    .rposition(|i| matches!(i, Item::Side { answer: None, .. }))
                {
                    self.transcript.set_side_answer(index, text);
                }
            }
            UiEvent::RemoteSent {
                approval_id,
                result,
            } => match result {
                Ok(remote_id) => {
                    if let Some(Dialog::Approval(d)) = &mut self.dialog
                        && d.approval.approval_id == approval_id
                    {
                        d.remote = Some(remote_id.clone());
                        self.transcript
                            .notice("approval also sent to your chat", Tone::Info);
                        self.poll_remote(approval_id, remote_id);
                    } else {
                        self.cancel_remote(remote_id);
                    }
                }
                Err(e) => self.transcript.notice(
                    format!("could not send the approval to your chat: {e}"),
                    Tone::Warning,
                ),
            },
            UiEvent::RemoteAnswer { approval_id, value } => {
                let matches = matches!(&self.dialog, Some(Dialog::Approval(d)) if d.approval.approval_id == approval_id);
                if matches && let Some(Dialog::Approval(d)) = self.dialog.take() {
                    let label = d
                        .approval
                        .option_label(&value)
                        .unwrap_or(&value)
                        .to_string();
                    self.transcript
                        .notice(format!("{label} (answered from chat)"), Tone::Info);
                    self.send(Control::Approve(value));
                }
            }
            UiEvent::ConfigureReply(result) => {
                self.shell_running = false;
                match result {
                    Ok(reply) => {
                        let changes = configure::parse(&reply);
                        let explanation = configure::explanation(&reply);
                        if changes.is_empty() {
                            self.transcript.notice(
                                if explanation.is_empty() {
                                    "no settings changes proposed".to_string()
                                } else {
                                    explanation
                                },
                                Tone::Info,
                            );
                        } else {
                            self.dialog = Some(Dialog::Configure {
                                explanation,
                                changes,
                            });
                        }
                    }
                    Err(e) => self
                        .transcript
                        .notice(format!("/configure failed: {e}"), Tone::Error),
                }
            }
            UiEvent::Info(text, tone) => self.transcript.notice(text, tone),
        }
    }

    /// Send the open approval to the chat when the user seems away.
    fn maybe_send_remote_approval(&mut self) {
        let Some(remote) = self.remote.clone() else {
            return;
        };
        if !self.settings.notify.events.iter().any(|e| e == "approval") {
            return;
        }
        let idle = self.settings.notify.after_idle_secs.unwrap_or(60);
        let Some(Dialog::Approval(d)) = &mut self.dialog else {
            return;
        };
        if d.remote.is_some() || d.remote.as_deref() == Some("") {
            return;
        }
        if self.focused && self.last_input.elapsed() < Duration::from_secs(idle) {
            return;
        }
        // Mark as in flight.
        d.remote = Some(String::new());
        let approval = d.approval.clone();
        let tx = self.ui_tx.clone();
        let project = self.project_name.clone();
        tokio::spawn(async move {
            let options: Vec<(String, String)> = approval
                .options
                .iter()
                .map(|o| (o.value.clone(), o.label.clone()))
                .collect();
            let text = format!(
                "{}{}{}",
                approval.preview.as_deref().unwrap_or(""),
                approval
                    .advisory
                    .as_deref()
                    .map(|a| format!("\n\n{a}"))
                    .unwrap_or_default(),
                ""
            );
            let result = remote
                .request_approval(
                    &format!("mccode · {project}: approve {}?", approval.tool),
                    &text,
                    &options,
                )
                .await
                .map(|r| r.id)
                .map_err(|e| e.to_string());
            let _ = tx.send(UiEvent::RemoteSent {
                approval_id: approval.approval_id.clone(),
                result,
            });
        });
    }

    fn poll_remote(&self, approval_id: String, remote_id: String) {
        let Some(remote) = self.remote.clone() else {
            return;
        };
        let tx = self.ui_tx.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                match remote.poll(&remote_id).await {
                    Ok(microclaw_code_core::remote_notify::RemoteStatus::Answered {
                        value,
                        ..
                    }) => {
                        let _ = tx.send(UiEvent::RemoteAnswer { approval_id, value });
                        return;
                    }
                    Ok(microclaw_code_core::remote_notify::RemoteStatus::Pending) => continue,
                    Ok(_) => return,
                    Err(_) => continue,
                }
            }
        });
    }

    fn cancel_remote(&self, remote_id: String) {
        if remote_id.is_empty() {
            return;
        }
        if let Some(remote) = self.remote.clone() {
            tokio::spawn(async move {
                let _ = remote.cancel(&remote_id).await;
            });
        }
    }

    fn remote_notify(&self, event: &str, title: &str, body: &str) {
        let Some(remote) = self.remote.clone() else {
            return;
        };
        if !self.settings.notify.events.iter().any(|e| e == event) {
            return;
        }
        if self.focused && self.last_input.elapsed() < Duration::from_secs(60) {
            return;
        }
        let title = format!("mccode · {}: {title}", self.project_name);
        let body = body.to_string();
        let tx = self.ui_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = remote.notify(&title, &body).await {
                let _ = tx.send(UiEvent::Info(
                    format!("chat notification failed: {e}"),
                    Tone::Warning,
                ));
            }
        });
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
        if matches!(self.dialog, Some(Dialog::Approval(_)))
            && let Some(Dialog::Approval(d)) = self.dialog.take()
            && let Some(id) = d.remote
        {
            self.cancel_remote(id);
        }
        let mut next_goal_round = false;
        match result {
            Ok((mut session, report)) => {
                session.settings.mode = self.mode;
                match report {
                    Ok(report) => {
                        if running.agent_turn {
                            self.last_request_end = Some(Instant::now());
                            self.finish_receipt(&session, &report);
                        }
                        if report.cancelled {
                            self.transcript.notice("stopped", Tone::Warning);
                            self.goal = None;
                        }
                        let ok = !report.cancelled && !report.failed;
                        if running.plan && ok && self.mode == Mode::Plan {
                            self.dialog = Some(Dialog::ExecutePlan);
                        }
                        if running.agent_turn {
                            let body = crate::format::truncate(&report.final_text, 160);
                            self.notifier.notify(
                                self.focused,
                                if ok {
                                    "MicroClaw Code finished"
                                } else {
                                    "MicroClaw Code stopped"
                                },
                                &body,
                            );
                            if report.failed {
                                self.remote_notify("error", "failed", &body);
                            } else {
                                self.remote_notify(
                                    "done",
                                    if ok { "finished" } else { "stopped" },
                                    &body,
                                );
                            }
                        }
                        if let Some(goal) = &mut self.goal {
                            let until = self.goal_until.lock().ok().and_then(|mut s| s.take());
                            let verdict = goal.judge(&report, until);
                            if verdict.is_final() {
                                let tone = if verdict.is_reached() {
                                    Tone::Success
                                } else {
                                    Tone::Warning
                                };
                                self.transcript.notice(goal.summary(&verdict), tone);
                                self.goal = None;
                            } else {
                                next_goal_round = true;
                            }
                        }
                    }
                    Err(e) => self.transcript.notice(format!("error: {e:#}"), Tone::Error),
                }
                self.session_label = session.session_id.clone();
                session.report_context_percent(self.updates_tx.clone());
                self.jobs = Some(session.job_handle());
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
        self.files = None;
        if next_goal_round {
            self.continue_goal();
        } else if self.dialog.is_none() && !self.queue.is_empty() {
            let next = self.queue.remove(0);
            self.submit(next);
        }
    }

    fn finish_receipt(&mut self, session: &CodeSession, report: &TurnReport) {
        let Some(mut receipt) = self.transcript.take_receipt() else {
            return;
        };
        if let Some((input, output, model)) = self.pending_usage.take() {
            receipt.tokens_in = input;
            receipt.tokens_out = output;
            receipt.cost = estimate_cost(&model, input, output);
        }
        receipt.sandbox = session
            .settings
            .sandbox
            .as_ref()
            .map(|s| s.mechanism.clone());
        receipt.network = session
            .settings
            .sandbox
            .as_ref()
            .map(|s| s.network)
            .unwrap_or(true);
        if receipt.checkpoint.is_none() {
            receipt.checkpoint = session
                .turn_checkpoints()
                .last()
                .map(|(c, _)| c.commit.clone());
        }
        receipt.status = if report.cancelled {
            "stopped".into()
        } else if report.failed {
            "failed".into()
        } else if report.checks_passed == Some(false) {
            "checks failing".into()
        } else {
            "done".into()
        };
        // Skip receipts for turns that only talked.
        if receipt.files.is_empty()
            && receipt.checks.is_empty()
            && receipt.domains.is_empty()
            && receipt.reviewed.is_empty()
        {
            return;
        }
        self.transcript.push(Item::Receipt(receipt));
    }

    fn continue_goal(&mut self) {
        let Some(goal) = &self.goal else {
            return;
        };
        let prompt = goal.prompt();
        let label = format!("goal {}", goal.progress());
        self.start_turn(prompt, Some(label));
    }

    /// Hold the lock of session `id`; `Err` names the front end that drives
    /// it instead.
    fn hold_session_lock(&mut self, id: &str) -> Result<(), String> {
        use microclaw_code_core::session_lock::{LockError, SessionLock};
        let home = microclaw_code_core::home::code_home();
        if let Some(lock) = &self.session_lock
            && lock.session_id() == id
        {
            return lock.check().map_err(|holder| {
                format!(
                    "{} took this session over; start another with /new or /resume, or restart mccode with --take-over",
                    holder.describe()
                )
            });
        }
        match SessionLock::acquire(&home, id, "tui", false) {
            Ok(lock) => {
                self.session_lock = Some(lock);
                Ok(())
            }
            Err(LockError::Held(holder)) => Err(format!(
                "this session is open in {}; continue it there, or restart mccode with --session {id} --take-over",
                holder.describe()
            )),
            // An unwritable lock never blocks work.
            Err(LockError::Io(_)) => Ok(()),
        }
    }

    fn start_turn(&mut self, prompt: String, label: Option<String>) {
        let Some(id) = self.session.as_ref().map(|s| s.session_id.clone()) else {
            return;
        };
        if let Err(message) = self.hold_session_lock(&id) {
            self.transcript.notice(message, Tone::Error);
            return;
        }
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
        let prompt = if self.shell_context.is_empty() {
            prompt
        } else {
            let context = std::mem::take(&mut self.shell_context).join("\n\n");
            format!("{context}\n\n{prompt}")
        };
        self.transcript.begin_turn();
        self.side_asker = Some(session.side_asker());
        let (controls_tx, mut controls_rx) = mpsc::unbounded_channel();
        let updates = self.updates_tx.clone();
        let plan = self.mode == Mode::Plan;
        // A goal with `--until` runs its command after each completed round.
        let until = self
            .goal
            .as_ref()
            .and_then(|g| g.spec.until.clone())
            .map(|command| (command, self.goal_until.clone()));
        let handle = tokio::spawn(async move {
            let report = session.turn(&prompt, &updates, &mut controls_rx).await;
            if let (Some((command, slot)), Ok(r)) = (until, &report)
                && !r.cancelled
                && !r.failed
            {
                let _ = updates.send(Update::Notice(format!("goal: running `{command}`")));
                let outcome =
                    microclaw_code_core::goal::run_until(&session.project.root, &command).await;
                if let Ok(mut slot) = slot.lock() {
                    *slot = Some(outcome);
                }
            }
            (session, report)
        });
        self.running = Some(RunningTurn {
            started: Instant::now(),
            controls: controls_tx,
            handle,
            plan,
            agent_turn: true,
        });
        self.scroll = 0;
    }

    fn send(&self, control: Control) {
        if let Some(running) = &self.running {
            let _ = running.controls.send(control);
        }
    }

    /// Submit typed text: a command, a `!` shell command, guidance or a new
    /// turn (queued while one runs).
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
            self.queue.push(trimmed.to_string());
            self.hint = Some(format!(
                "queued; it runs after this turn ({} to send it now as guidance)",
                self.keymap
                    .label(keymap::Action::Steer)
                    .unwrap_or_else(|| "Ctrl+S".into())
            ));
            return;
        }
        if self.checks_task.is_some() {
            self.hint = Some("checks are still running".into());
            self.input.set_text(trimmed);
            return;
        }
        self.start_turn(trimmed.to_string(), None);
    }

    /// Send typed text to the running turn right away.
    fn steer(&mut self, text: String) {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return;
        }
        if self.running.is_none() {
            self.submit(text);
            return;
        }
        self.transcript.push(Item::Steer(trimmed.to_string()));
        self.send(Control::Steer(trimmed.to_string()));
    }

    fn cycle_mode(&mut self) {
        let disabled = &self.settings.permissions.disabled_modes;
        let mut next = self.mode;
        for _ in 0..3 {
            next = match next {
                Mode::Plan => Mode::Ask,
                Mode::Ask => Mode::Auto,
                Mode::Auto => Mode::Plan,
            };
            if !disabled.iter().any(|d| d == next.as_str()) {
                break;
            }
        }
        self.set_mode(next);
        self.hint = Some(format!(
            "{} mode: {}",
            self.mode.as_str(),
            self.mode.describe()
        ));
    }

    /// Change mode unless the managed settings disable it.
    fn set_mode(&mut self, mode: Mode) -> bool {
        if self
            .settings
            .permissions
            .disabled_modes
            .iter()
            .any(|d| d == mode.as_str())
        {
            self.transcript.notice(
                format!(
                    "{} mode is disabled by your organization's settings",
                    mode.as_str()
                ),
                Tone::Warning,
            );
            return false;
        }
        self.mode = mode;
        if let Some(session) = &mut self.session {
            session.settings.mode = mode;
        }
        true
    }

    fn on_paste(&mut self, text: &str) {
        if self.dialog.is_some() {
            return;
        }
        self.input.paste(text);
        self.refresh_popup();
    }

    fn on_mouse(&mut self, mouse: crossterm::event::MouseEvent) {
        if self.dialog.is_some() {
            if let Some(Dialog::Pager(p)) = &mut self.dialog {
                let h = self.transcript_area.height as usize;
                match mouse.kind {
                    MouseEventKind::ScrollUp => {
                        p.key(pager::PagerKey::Up(3), h);
                    }
                    MouseEventKind::ScrollDown => {
                        p.key(pager::PagerKey::Down(3), h);
                    }
                    _ => {}
                }
            }
            return;
        }
        match mouse.kind {
            MouseEventKind::ScrollUp => self.scroll += 3,
            MouseEventKind::ScrollDown => self.scroll = self.scroll.saturating_sub(3),
            MouseEventKind::Down(MouseButton::Left) => {
                let area = self.transcript_area;
                if mouse.row >= area.y
                    && mouse.row < area.y + area.height
                    && mouse.column >= area.x
                    && mouse.column < area.x + area.width
                {
                    let row = (mouse.row - area.y) as usize;
                    if let Some(&item) = self.line_owners.get(row) {
                        self.transcript.toggle(item);
                    }
                }
            }
            _ => {}
        }
    }

    /// Run a `!command` in the project directory (outside the agent).
    fn run_shell(&mut self, command: String) {
        let Some(root) = self
            .session
            .as_ref()
            .map(|s| s.project.root.clone())
            .or_else(|| {
                self.files
                    .as_ref()
                    .map(|_| std::env::current_dir().unwrap_or_default())
            })
        else {
            self.hint = Some("wait for the current turn to finish".into());
            return;
        };
        if self.shell_running {
            self.hint = Some("a shell command is still running".into());
            return;
        }
        self.shell_running = true;
        self.transcript.push(Item::Shell {
            command: command.clone(),
            output: Vec::new(),
            exit: None,
            running: true,
        });
        let tx = self.ui_tx.clone();
        tokio::spawn(async move {
            use tokio::io::{AsyncBufReadExt, BufReader};
            #[cfg(unix)]
            let mut cmd = {
                let mut c = tokio::process::Command::new("sh");
                c.arg("-c").arg(&command);
                c
            };
            #[cfg(windows)]
            let mut cmd = {
                let mut c = tokio::process::Command::new("cmd");
                c.arg("/C").arg(&command);
                c
            };
            cmd.current_dir(&root)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .kill_on_drop(true);
            let mut child = match cmd.spawn() {
                Ok(c) => c,
                Err(e) => {
                    let _ = tx.send(UiEvent::ShellLine(format!("could not start: {e}")));
                    let _ = tx.send(UiEvent::ShellDone(None));
                    return;
                }
            };
            let stdout = child.stdout.take();
            let stderr = child.stderr.take();
            let tx_out = tx.clone();
            let out_task = tokio::spawn(async move {
                if let Some(s) = stdout {
                    let mut lines = BufReader::new(s).lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        let _ = tx_out.send(UiEvent::ShellLine(line));
                    }
                }
            });
            let tx_err = tx.clone();
            let err_task = tokio::spawn(async move {
                if let Some(s) = stderr {
                    let mut lines = BufReader::new(s).lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        let _ = tx_err.send(UiEvent::ShellLine(line));
                    }
                }
            });
            let status = tokio::time::timeout(Duration::from_secs(600), child.wait()).await;
            let _ = out_task.await;
            let _ = err_task.await;
            let code = match status {
                Ok(Ok(s)) => s.code(),
                _ => {
                    let _ = tx.send(UiEvent::ShellLine("timed out after 10 minutes".into()));
                    None
                }
            };
            let _ = tx.send(UiEvent::ShellDone(code));
        });
    }

    /// `/configure`: ask the model for settings changes (applied on yes).
    fn configure(&mut self, request: String) {
        let asker = match (&self.session, &self.side_asker) {
            (Some(s), _) => s.side_asker(),
            (None, Some(a)) => a.clone(),
            _ => return,
        };
        let prompt = configure::prompt(&request, &self.settings);
        self.transcript
            .notice(format!("working out settings for: {request}"), Tone::Info);
        self.shell_running = true;
        let tx = self.ui_tx.clone();
        tokio::spawn(async move {
            let result = asker.ask_raw(&prompt).await.map_err(|e| e.to_string());
            let _ = tx.send(UiEvent::ConfigureReply(result));
        });
    }

    /// `/btw`: answer in a throwaway fork while the main turn continues.
    fn side_question(&mut self, question: String) {
        let asker = match (&self.session, &self.running) {
            (Some(s), _) => s.side_asker(),
            (None, Some(_)) => match &self.side_asker {
                Some(a) => a.clone(),
                None => {
                    self.hint = Some("ask again after this turn".into());
                    return;
                }
            },
            _ => return,
        };
        self.transcript.push(Item::Side {
            question: question.clone(),
            answer: None,
        });
        let tx = self.ui_tx.clone();
        tokio::spawn(async move {
            let result = asker.ask(&question).await.map_err(|e| e.to_string());
            let _ = tx.send(UiEvent::SideAnswer(result));
        });
    }
}

/// Estimated cost from the model presets (`None` when prices are unknown).
pub fn estimate_cost(model: &str, input: i64, output: i64) -> Option<f64> {
    let preset = microclaw_code_core::presets::lookup(model)?;
    let input_price = preset.input_price_per_mtok?;
    let output_price = preset.output_price_per_mtok?;
    Some(input as f64 / 1e6 * input_price + output as f64 / 1e6 * output_price)
}
