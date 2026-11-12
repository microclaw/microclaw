//! One project's engine and session, run on the app's Tokio runtime.
//!
//! The window sends [`Command`]s and receives [`Event`]s over unbounded
//! channels; nothing here touches GPUI. The engine is built with
//! `code-core::launch` (the same assembly `mccode acp` / MCP use), and turns go
//! through `CodeSession::turn`, so approvals, checks and fix rounds behave as
//! in the TUI and sessions are the same ones `mccode` lists and resumes.

use std::path::{Path, PathBuf};

use microclaw_code_core::driver::{
    CodeSession, Control, HistoryEntry, SessionSettings, TurnReport, Update,
};
use microclaw_code_core::home;
use microclaw_code_core::launch::{self, EngineOptions};
use microclaw_code_core::project::{Mode, Project};
use microclaw_code_core::session_lock::{LockError, SessionLock};
use microclaw_code_core::sessions::{SessionIndex, SessionRecord};
use microclaw_code_core::trust::TrustStore;
use microclaw_code_core::user_hooks::HookEvent;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

/// Messages kept when a session is shown again.
const HISTORY_LIMIT: usize = 200;

/// Window → service.
#[derive(Debug, Clone, PartialEq)]
pub enum Command {
    /// Build (or rebuild, after setup or trust) the engine.
    Start,
    Send(String),
    Steer(String),
    Cancel,
    Approve(String),
    SetMode(Mode),
    /// `None`: back to the configured model.
    SetModel(Option<String>),
    NewSession,
    OpenSession(String),
    /// Drive the current session although another front end holds it.
    TakeOver,
    Trust,
}

/// What the project looks like before the engine starts.
#[derive(Debug, Clone)]
pub struct ProjectInfo {
    pub root: PathBuf,
    pub name: String,
    pub branch: Option<String>,
    pub trusted: bool,
    /// The project has `.microclaw/project.yaml` or detected checks that
    /// only run once trusted.
    pub trust_matters: bool,
}

/// Service → window.
#[derive(Debug, Clone)]
pub enum Event {
    Project(ProjectInfo),
    /// No model is configured; the window shows onboarding.
    NeedsSetup(String),
    Starting,
    Ready {
        model: String,
        mode: Mode,
        sandbox: Option<String>,
        warnings: Vec<String>,
        models: Vec<String>,
        disabled_modes: Vec<String>,
    },
    Failed(String),
    Sessions(Vec<SessionRecord>),
    SessionOpened {
        id: String,
        history: Vec<HistoryEntry>,
    },
    /// Another front end drives this session.
    SessionLocked {
        holder: String,
    },
    TurnStarted(String),
    Update(Update),
    TurnFinished {
        receipt: Option<String>,
        /// Not failed, stopped or left with failing checks.
        ok: bool,
    },
    ModeChanged(Mode),
    ModelChanged(String),
    Notice(String),
    Error(String),
}

/// The window's end of a running service.
pub struct ProjectHandle {
    pub commands: UnboundedSender<Command>,
    pub events: UnboundedReceiver<Event>,
    /// Resolves once the service has stopped and released its session.
    pub stopped: tokio::sync::oneshot::Receiver<()>,
}

/// Start the service for `root` on `runtime`; it stops when the handle's
/// command sender is dropped (closing the window), which drops the engine
/// and with it the background processes it started.
pub fn spawn(
    runtime: &tokio::runtime::Handle,
    root: PathBuf,
    session: Option<String>,
) -> ProjectHandle {
    let (commands_tx, commands_rx) = mpsc::unbounded_channel();
    let (events_tx, events_rx) = mpsc::unbounded_channel();
    let (stopped_tx, stopped_rx) = tokio::sync::oneshot::channel();
    runtime.spawn(async move {
        let mut service = Service::new(root, session, events_tx);
        service.run(commands_rx).await;
        drop(service);
        let _ = stopped_tx.send(());
    });
    let _ = commands_tx.send(Command::Start);
    ProjectHandle {
        commands: commands_tx,
        events: events_rx,
        stopped: stopped_rx,
    }
}

struct Engine {
    session: Option<CodeSession>,
    gate: microclaw_code_core::gate::CodeToolGate,
    roles: microclaw_code_core::driver::RoleModels,
    settings: SessionSettings,
    microclaw: microclaw_sdk::MicroClaw,
    project: Project,
    disabled_modes: Vec<String>,
}

struct Service {
    root: PathBuf,
    requested_session: Option<String>,
    events: UnboundedSender<Event>,
    index: SessionIndex,
    engine: Option<Engine>,
    session_id: String,
    lock: Option<SessionLock>,
    /// The running turn's control channel.
    running: Option<UnboundedSender<Control>>,
    mode: Mode,
}

/// A finished turn hands the session back.
type TurnDone = (CodeSession, anyhow::Result<TurnReport>);

impl Service {
    fn new(root: PathBuf, session: Option<String>, events: UnboundedSender<Event>) -> Self {
        Self {
            root,
            requested_session: session,
            events,
            index: SessionIndex::load(SessionIndex::default_path()),
            engine: None,
            session_id: String::new(),
            lock: None,
            running: None,
            mode: Mode::default(),
        }
    }

    fn emit(&self, event: Event) {
        let _ = self.events.send(event);
    }

    async fn run(&mut self, mut commands: UnboundedReceiver<Command>) {
        let (done_tx, mut done_rx) = mpsc::unbounded_channel::<TurnDone>();
        loop {
            tokio::select! {
                command = commands.recv() => match command {
                    Some(command) => self.handle(command, &done_tx).await,
                    None => break,
                },
                Some((session, report)) = done_rx.recv() => self.turn_done(session, report),
            }
        }
        // The window closed: stop a running turn and let it hand the session
        // back so its hooks and processes end cleanly.
        if let Some(controls) = self.running.take() {
            let _ = controls.send(Control::Cancel);
            if let Some((session, _)) = done_rx.recv().await {
                self.session_end(&session).await;
            }
        } else if let Some(session) = self.engine.as_mut().and_then(|e| e.session.take()) {
            self.session_end(&session).await;
        }
    }

    async fn session_end(&self, session: &CodeSession) {
        if let Some(hooks) = session.tool_gate().map(|g| g.hooks())
            && hooks.has(HookEvent::SessionEnd)
        {
            let _ = hooks
                .run(
                    HookEvent::SessionEnd,
                    microclaw_code_core::user_hooks::HookPayload::default().with("reason", "exit"),
                )
                .await;
        }
    }

    fn session_mut(&mut self) -> Option<&mut CodeSession> {
        self.engine.as_mut()?.session.as_mut()
    }

    async fn handle(&mut self, command: Command, done: &UnboundedSender<TurnDone>) {
        match command {
            Command::Start => self.start().await,
            Command::Trust => {
                let project = match launch::trusted_project(&self.root) {
                    Ok(p) => p,
                    Err(e) => return self.emit(Event::Error(e.to_string())),
                };
                let mut store = TrustStore::load(TrustStore::default_path());
                if let Err(e) = store.set(&project.root, true, project.config_sha256.as_deref()) {
                    return self.emit(Event::Error(format!("could not save trust: {e}")));
                }
                if self.running.is_some() {
                    return self.emit(Event::Notice(
                        "trusted; project settings apply after this turn".into(),
                    ));
                }
                // Project settings, checks and instructions now apply.
                self.requested_session = Some(self.session_id.clone());
                self.start().await;
            }
            Command::Send(prompt) => self.send(prompt, done),
            Command::Steer(text) => match &self.running {
                Some(controls) => {
                    let _ = controls.send(Control::Steer(text));
                }
                None => self.send(text, done),
            },
            Command::Cancel => {
                if let Some(controls) = &self.running {
                    let _ = controls.send(Control::Cancel);
                }
            }
            Command::Approve(value) => {
                if let Some(controls) = &self.running {
                    let _ = controls.send(Control::Approve(value));
                }
            }
            Command::SetMode(mode) => self.set_mode(mode),
            Command::SetModel(model) => {
                let Some(session) = self.session_mut() else {
                    return self.emit(Event::Notice(
                        "the model can be changed between turns".into(),
                    ));
                };
                match session.set_model(model.as_deref()).await {
                    Ok(model) => self.emit(Event::ModelChanged(model)),
                    Err(e) => self.emit(Event::Error(format!("could not switch the model: {e}"))),
                }
            }
            Command::NewSession => {
                if self.busy() {
                    return;
                }
                match self.index.create(&self.root) {
                    Ok(record) => self.open_session(record.id, false).await,
                    Err(e) => self.emit(Event::Error(e.to_string())),
                }
            }
            Command::OpenSession(id) => {
                if self.busy() {
                    return;
                }
                self.open_session(id, false).await;
            }
            Command::TakeOver => {
                if self.busy() {
                    return;
                }
                let id = self.session_id.clone();
                self.open_session(id, true).await;
            }
        }
    }

    fn busy(&self) -> bool {
        if self.running.is_some() {
            self.emit(Event::Notice(
                "a turn is running; stop it first (⌘.)".into(),
            ));
            true
        } else {
            false
        }
    }

    fn set_mode(&mut self, mode: Mode) {
        if let Some(engine) = &self.engine
            && engine.disabled_modes.iter().any(|d| d == mode.as_str())
        {
            return self.emit(Event::Error(format!(
                "{} mode is disabled by your organization's settings",
                mode.as_str()
            )));
        }
        self.mode = mode;
        if let Some(engine) = &mut self.engine {
            engine.settings.mode = mode;
            if let Some(session) = engine.session.as_mut() {
                session.settings.mode = mode;
            }
        }
        if self.running.is_some() {
            self.emit(Event::Notice(format!(
                "{} mode applies from the next turn",
                mode.as_str()
            )));
        }
        self.emit(Event::ModeChanged(mode));
    }

    /// Discover the project, build the engine and open a session.
    async fn start(&mut self) {
        if self.running.is_some() {
            return;
        }
        let trust = TrustStore::load(TrustStore::default_path());
        let project = match Project::discover(&self.root, |r, h| trust.is_trusted(r, h)) {
            Ok(project) => project,
            Err(e) => return self.emit(Event::Failed(format!("not a project: {e}"))),
        };
        self.root = project.root.clone();
        self.emit(Event::Project(ProjectInfo {
            name: project
                .root
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| project.root.display().to_string()),
            branch: microclaw_code_core::git::branch(&project.root),
            trusted: project.trusted,
            trust_matters: project.has_config_file || !project.checks.is_empty(),
            root: project.root.clone(),
        }));

        let loaded = launch::project_settings(&project.root);
        let settings = loaded.settings;
        if let Err(e) = launch::model_source(&settings, None) {
            return self.emit(Event::NeedsSetup(e.to_string()));
        }
        self.emit(Event::Starting);
        // Drop the old engine (and its processes) before building a new one.
        if let Some(old) = self.engine.take()
            && let Some(session) = old.session
        {
            self.session_end(&session).await;
        }

        let sandbox = match launch::sandbox_choice(None, false) {
            Ok(choice) => launch::settings_sandbox(choice, false, &settings),
            Err(e) => return self.emit(Event::Failed(e.to_string())),
        };
        let sandbox_info = launch::sandbox_info(&sandbox);
        let session_id = match self.requested_session.take() {
            Some(id) if !id.is_empty() => id,
            _ => match self.index.create(&project.root) {
                Ok(record) => record.id,
                Err(e) => return self.emit(Event::Failed(e.to_string())),
            },
        };
        let options = EngineOptions {
            explicit_config: None,
            sandbox: sandbox.clone(),
            review_commands: false,
            max_concurrent_runs: 1,
        };
        let built = match launch::project_engine(&project.root, &options, &session_id).await {
            Ok(built) => built,
            Err(e) => return self.emit(Event::Failed(format!("{e:#}"))),
        };
        let mut warnings = loaded.warnings;
        warnings.extend(built.warnings.iter().cloned());
        let mut mode = project
            .config
            .mode
            .or_else(|| {
                settings
                    .permissions
                    .default_mode
                    .as_deref()
                    .and_then(Mode::parse)
            })
            .unwrap_or_default();
        let disabled_modes = settings.permissions.disabled_modes.clone();
        if disabled_modes.iter().any(|m| m == mode.as_str()) {
            warnings.push(format!(
                "{} mode is disabled by managed settings; using ask mode",
                mode.as_str()
            ));
            mode = Mode::Ask;
        }
        if sandbox_info.is_none() && !matches!(sandbox, microclaw_sdk::ShellSandbox::Off) {
            warnings.push("no OS sandbox is available here; shell commands run unconfined".into());
        }
        self.mode = mode;
        let session_settings = SessionSettings {
            mode,
            verify: true,
            max_fix_rounds: project.max_fix_rounds(),
            interactive: true,
            sandbox: sandbox_info.clone(),
            max_session_tokens: project.config.max_session_tokens,
            reviewer: built.reviewer,
        };
        let models = model_choices(&built.settings, &built.model);
        self.engine = Some(Engine {
            session: None,
            gate: built.gate,
            roles: built.roles,
            settings: session_settings,
            microclaw: built.engine,
            project,
            disabled_modes: disabled_modes.clone(),
        });
        let model = {
            let engine = self.engine.as_ref().unwrap();
            engine
                .microclaw
                .session_model(&session_id)
                .await
                .unwrap_or_default()
        };
        self.emit(Event::Ready {
            model,
            mode,
            sandbox: sandbox_info.map(|s| {
                format!(
                    "{} sandbox{}",
                    s.mechanism,
                    if s.network { "" } else { ", no network" }
                )
            }),
            warnings,
            models,
            disabled_modes,
        });
        self.open_session(session_id, false).await;
    }

    fn sessions(&self) -> Vec<SessionRecord> {
        self.index.for_project(&self.root)
    }

    /// Make `id` the current session (taking its lock).
    async fn open_session(&mut self, id: String, take_over: bool) {
        let Some(engine) = self.engine.as_mut() else {
            return;
        };
        let previous = engine.session.take();
        let reopening = previous.as_ref().is_some_and(|s| s.session_id == id);
        if !reopening && let Some(session) = &previous {
            self.session_end(session).await;
        }
        let engine = self.engine.as_mut().unwrap();
        let mut session = match previous {
            Some(mut session) => {
                session.reset(id.clone());
                session
            }
            None => {
                let mut session = CodeSession::new(
                    engine.microclaw.clone(),
                    engine.project.clone(),
                    id.clone(),
                    engine.settings.clone(),
                );
                session.set_tool_gate(engine.gate.clone());
                session.set_role_models(engine.roles.clone());
                session
            }
        };
        session.settings.mode = self.mode;
        self.session_id = id.clone();
        // Release the old lock before taking the new one.
        if self.lock.as_ref().is_some_and(|l| l.session_id() != id) {
            self.lock = None;
        }
        let locked = match SessionLock::acquire(&home::code_home(), &id, "desktop", take_over) {
            Ok(lock) => {
                self.lock = Some(lock);
                None
            }
            Err(LockError::Held(holder)) => Some(holder.describe()),
            Err(LockError::Io(e)) => {
                self.emit(Event::Notice(format!("could not lock the session: {e}")));
                None
            }
        };
        let history = session.history(HISTORY_LIMIT);
        let resumed = !history.is_empty();
        let hook_messages = if reopening {
            Vec::new()
        } else {
            session
                .session_hook(
                    HookEvent::SessionStart,
                    if resumed { "resume" } else { "startup" },
                )
                .await
        };
        self.engine.as_mut().unwrap().session = Some(session);
        self.emit(Event::Sessions(self.sessions()));
        self.emit(Event::SessionOpened {
            id: id.clone(),
            history,
        });
        for message in hook_messages {
            self.emit(Event::Notice(message));
        }
        if let Some(holder) = locked {
            self.emit(Event::SessionLocked { holder });
        }
    }

    fn send(&mut self, prompt: String, done: &UnboundedSender<TurnDone>) {
        let prompt = prompt.trim().to_string();
        if prompt.is_empty() {
            return;
        }
        if self.running.is_some() {
            return self.emit(Event::Notice(
                "a turn is running; send this as guidance (⌘⏎) or wait".into(),
            ));
        }
        match &self.lock {
            Some(lock) => {
                if let Err(holder) = lock.check() {
                    return self.emit(Event::SessionLocked {
                        holder: holder.describe(),
                    });
                }
            }
            None => {
                // Not ours: someone else drives it (or it could not be locked).
                if let microclaw_code_core::session_lock::LockState::Held(holder) =
                    microclaw_code_core::session_lock::inspect(&home::code_home(), &self.session_id)
                {
                    return self.emit(Event::SessionLocked {
                        holder: holder.describe(),
                    });
                }
            }
        }
        let Some(mut session) = self.engine.as_mut().and_then(|e| e.session.take()) else {
            return self.emit(Event::Notice("the engine is not ready yet".into()));
        };
        session.settings.mode = self.mode;
        if let Err(e) = self.index.touch(&session.session_id, &prompt) {
            self.emit(Event::Notice(format!(
                "could not update the session index: {e}"
            )));
        }
        self.emit(Event::TurnStarted(prompt.clone()));
        self.emit(Event::Sessions(self.sessions()));
        let (controls_tx, mut controls_rx) = mpsc::unbounded_channel();
        self.running = Some(controls_tx);
        let events = self.events.clone();
        let done = done.clone();
        tokio::spawn(async move {
            let (updates_tx, mut updates_rx) = mpsc::unbounded_channel::<Update>();
            let forward = tokio::spawn(async move {
                while let Some(update) = updates_rx.recv().await {
                    let _ = events.send(Event::Update(update));
                }
            });
            let report = session.turn(&prompt, &updates_tx, &mut controls_rx).await;
            drop(updates_tx);
            // Every update reaches the window before the turn ends.
            let _ = forward.await;
            let _ = done.send((session, report));
        });
    }

    fn turn_done(&mut self, session: CodeSession, report: anyhow::Result<TurnReport>) {
        self.running = None;
        let (receipt, ok) = match &report {
            Ok(report) => (receipt(report), report.exit_code() == 0),
            Err(e) => {
                self.emit(Event::Error(format!("{e:#}")));
                (None, false)
            }
        };
        if let Some(engine) = &mut self.engine {
            engine.session = Some(session);
        }
        self.emit(Event::TurnFinished { receipt, ok });
    }
}

/// One line on what a turn did.
pub fn receipt(report: &TurnReport) -> Option<String> {
    let mut parts = Vec::new();
    match report.changed_files.len() {
        0 => {}
        1 => parts.push(format!("changed {}", report.changed_files[0])),
        n => parts.push(format!("changed {n} files")),
    }
    match report.checks_passed {
        Some(true) => parts.push("checks passed".into()),
        Some(false) => parts.push("checks failing".into()),
        None => {}
    }
    if report.cancelled {
        parts.push("stopped".into());
    } else if report.failed {
        parts.push("failed".into());
    }
    if report.budget_exhausted {
        parts.push("session token budget used up".into());
    }
    (!parts.is_empty()).then(|| parts.join(" · "))
}

/// Models offered in the model menu: profile models, then known model
/// names of the active provider.
pub fn model_choices(
    settings: &microclaw_code_core::settings::CodeSettings,
    source: &launch::ModelSource,
) -> Vec<String> {
    let mut models: Vec<String> = Vec::new();
    for profile in settings.model.profiles.values() {
        if let Some(model) = &profile.model
            && !models.contains(model)
        {
            models.push(model.clone());
        }
    }
    let provider = match source {
        launch::ModelSource::Profile(m) => Some(m.provider.clone()),
        launch::ModelSource::ConfigFile(path) => config_provider(path),
    };
    for preset in microclaw_code_core::presets::all()
        .iter()
        .filter(|p| p.model_name)
        .filter(|p| provider.as_deref().is_none_or(|prov| p.provider == prov))
    {
        let id = preset.id.to_string();
        if !models.contains(&id) {
            models.push(id);
        }
    }
    models
}

/// `llm_provider` of a MicroClaw configuration file.
fn config_provider(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let doc: serde_yaml::Value = serde_yaml::from_str(&text).ok()?;
    doc.get("llm_provider")?.as_str().map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipts_summarize_the_turn() {
        let report = TurnReport {
            changed_files: vec!["a.rs".into(), "b.rs".into()],
            checks_passed: Some(true),
            ..Default::default()
        };
        assert_eq!(
            receipt(&report).as_deref(),
            Some("changed 2 files · checks passed")
        );
        assert_eq!(receipt(&TurnReport::default()), None);
    }
}
