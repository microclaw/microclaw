//! `mccode acp`: MicroClaw Code as an Agent Client Protocol (v1) agent over
//! stdio, for editors such as Zed.
//!
//! Each ACP session is a [`CodeSession`] in the project that contains the
//! session's `cwd`: the same turn driver as the TUI (verification, fix
//! rounds, allow rules, the sandbox) on an engine built by
//! [`launch::project_engine`] from the project's settings. Approvals become
//! `session/request_permission` requests. Modes (`plan` / `ask` / `auto`)
//! and the model are offered as session config options (and as legacy
//! modes), slash commands through `available_commands_update`, and context
//! use through `usage_update`. Without a model configuration a session fails
//! with `auth_required` and the client can run `mccode setup` in a terminal
//! (terminal auth). Project trust is not asked for here: a project is
//! trusted only after `mccode trust` (or the TUI).

mod commands;
mod mapper;
mod rpc;

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use agent_client_protocol_schema::ProtocolVersion;
use agent_client_protocol_schema::v1::{
    AGENT_METHOD_NAMES, AgentCapabilities, AuthMethod, AuthMethodTerminal, CLIENT_METHOD_NAMES,
    CancelNotification, CloseSessionRequest, CloseSessionResponse, ConfigOptionUpdate,
    ContentBlock, ContentChunk, CurrentModeUpdate, EmbeddedResourceResource, Error, Implementation,
    InitializeRequest, InitializeResponse, ListSessionsRequest, ListSessionsResponse,
    LoadSessionRequest, LoadSessionResponse, NewSessionRequest, NewSessionResponse,
    PermissionOption, PermissionOptionKind, PromptCapabilities, PromptRequest, PromptResponse,
    RequestPermissionOutcome, RequestPermissionRequest, RequestPermissionResponse,
    ResumeSessionRequest, ResumeSessionResponse, SessionCapabilities, SessionCloseCapabilities,
    SessionConfigOption, SessionConfigOptionCategory, SessionConfigSelectOption, SessionId,
    SessionInfo, SessionInfoUpdate, SessionListCapabilities, SessionMode, SessionModeState,
    SessionNotification, SessionResumeCapabilities, SessionUpdate, SetSessionConfigOptionRequest,
    SetSessionConfigOptionResponse, SetSessionModeRequest, SetSessionModeResponse, StopReason,
    ToolCallContent, ToolCallUpdate, ToolCallUpdateFields, UsageUpdate,
};
use microclaw_code_core::commands::CustomCommand;
use microclaw_code_core::driver::{
    CodeSession, Control, HistoryEntry, PendingApproval, SandboxInfo, SessionSettings, Update,
};
use microclaw_code_core::launch::{self, ModelSource, ProjectEngine};
use microclaw_code_core::project::Mode;
use microclaw_code_core::sessions::SessionIndex;
use microclaw_sdk::{MicroClaw, RuntimeApprovalDecision, ShellSandbox};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;

use self::commands::{Builtin, Parsed};
use self::mapper::{ClientSupport, UpdateMapper};
use self::rpc::{Connection, Incoming};

/// How sessions are run (from the command line).
pub struct AcpOptions {
    /// Kept for `eval`, which needs a configuration file.
    pub config_path: PathBuf,
    pub engine: launch::EngineOptions,
    pub sandbox: ShellSandbox,
    pub sandbox_info: Option<SandboxInfo>,
    pub verify: bool,
    pub max_fix_rounds: Option<u32>,
    pub default_mode: Option<Mode>,
}

const SETUP_AUTH_ID: &str = "mccode-setup";

struct AcpSession {
    /// Taken while a prompt runs.
    code: Option<CodeSession>,
    controls: Option<mpsc::UnboundedSender<Control>>,
    engine: MicroClaw,
    project: Rc<ProjectEngine>,
    root: PathBuf,
    mode: Mode,
    custom: Vec<CustomCommand>,
    titled: bool,
}

struct Agent {
    conn: Rc<Connection>,
    support: std::cell::Cell<ClientSupport>,
    options: AcpOptions,
    projects: RefCell<HashMap<PathBuf, Rc<ProjectEngine>>>,
    sessions: RefCell<HashMap<String, AcpSession>>,
}

fn invalid(error: impl std::fmt::Display) -> Error {
    Error::invalid_params().data(Value::String(error.to_string()))
}

fn internal(error: impl std::fmt::Display) -> Error {
    Error::new(-32603, error.to_string())
}

fn params<T: DeserializeOwned>(value: Value) -> Result<T, Error> {
    serde_json::from_value(value).map_err(invalid)
}

fn to_value(value: impl Serialize) -> Result<Value, Error> {
    serde_json::to_value(value).map_err(internal)
}

fn not_found(id: &str) -> Error {
    Error::session_not_found(SessionId::new(id.to_string()))
}

/// Serve ACP on stdin/stdout until the client disconnects.
pub async fn serve(options: AcpOptions) -> anyhow::Result<()> {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async move {
            let (conn, out) = Connection::new();
            let conn = Rc::new(conn);
            let writer = tokio::task::spawn_local(rpc::write_loop(out, tokio::io::stdout()));
            let agent = Rc::new(Agent {
                conn: conn.clone(),
                support: std::cell::Cell::new(ClientSupport::default()),
                options,
                projects: RefCell::new(HashMap::new()),
                sessions: RefCell::new(HashMap::new()),
            });
            let mut lines = BufReader::new(tokio::io::stdin()).lines();
            while let Some(line) = lines.next_line().await? {
                if line.trim().is_empty() {
                    continue;
                }
                match rpc::parse(&line) {
                    Ok(Incoming::Request { id, method, params }) => {
                        let agent = agent.clone();
                        tokio::task::spawn_local(async move {
                            let result = agent.handle(&method, params).await;
                            let (result, announce) = match result {
                                Ok((value, announce)) => (Ok(value), announce),
                                Err(e) => (Err(e), None),
                            };
                            agent.conn.respond(id, result);
                            if let Some(session_id) = announce {
                                agent.announce(&session_id);
                            }
                        });
                    }
                    Ok(Incoming::Notification { method, params }) => {
                        agent.notification(&method, params);
                    }
                    Ok(Incoming::Response { id, result }) => conn.resolve(&id, result),
                    Err(error) => conn.respond(Value::Null, Err(error)),
                }
            }
            // The client went away: stop running turns and pending requests.
            conn.close();
            agent.cancel_all();
            writer.abort();
            Ok(())
        })
        .await
}

fn flatten_prompt(blocks: &[ContentBlock]) -> String {
    let mut parts = Vec::new();
    for block in blocks {
        match block {
            ContentBlock::Text(text) => parts.push(text.text.clone()),
            ContentBlock::ResourceLink(link) => {
                let target = link.uri.strip_prefix("file://").unwrap_or(&link.uri);
                parts.push(format!("@{target}"));
            }
            ContentBlock::Resource(resource) => {
                if let EmbeddedResourceResource::TextResourceContents(text) = &resource.resource {
                    let path = text.uri.strip_prefix("file://").unwrap_or(&text.uri);
                    parts.push(format!("File {path}:\n```\n{}\n```", text.text));
                }
            }
            ContentBlock::Image(image) => {
                let dir = microclaw_code_core::home::code_home().join("acp-images");
                match microclaw_code_core::images::save_base64(&dir, &image.mime_type, &image.data)
                {
                    Ok(path) => parts.push(format!("(image attached: @{})", path.display())),
                    Err(e) => parts.push(format!("(an image could not be attached: {e})")),
                }
            }
            _ => {}
        }
    }
    parts.join("\n\n")
}

fn permission_options(approval: &PendingApproval) -> Vec<PermissionOption> {
    approval
        .options
        .iter()
        .map(|option| {
            let kind = match (option.decision, option.value.as_str()) {
                (RuntimeApprovalDecision::Deny, _) => PermissionOptionKind::RejectOnce,
                (_, "1") => PermissionOptionKind::AllowOnce,
                _ => PermissionOptionKind::AllowAlways,
            };
            PermissionOption::new(option.value.clone(), option.label.clone(), kind)
        })
        .collect()
}

fn mode_info(mode: Mode) -> (&'static str, &'static str) {
    match mode {
        Mode::Plan => (
            "Plan",
            "Read-only research; proposes a plan before changing anything.",
        ),
        Mode::Ask => ("Ask", "Edits apply directly; shell commands ask first."),
        Mode::Auto => (
            "Auto",
            "Commands run without asking, except destructive ones.",
        ),
    }
}

fn modes_for(project: &ProjectEngine) -> Vec<Mode> {
    [Mode::Plan, Mode::Ask, Mode::Auto]
        .into_iter()
        .filter(|m| {
            !project
                .settings
                .permissions
                .disabled_modes
                .iter()
                .any(|d| d == m.as_str())
        })
        .collect()
}

fn mode_state(project: &ProjectEngine, current: Mode) -> SessionModeState {
    SessionModeState::new(
        current.as_str(),
        modes_for(project)
            .into_iter()
            .map(|m| {
                let (name, description) = mode_info(m);
                SessionMode::new(m.as_str(), name).description(description)
            })
            .collect(),
    )
}

/// Models offered for a session now on `current`: the current one, the
/// active profile's models and the presets of the same provider.
fn model_choices(project: &ProjectEngine, current: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let push = |id: String, out: &mut Vec<(String, String)>| {
        let id = id.trim().to_string();
        if id.is_empty() || out.iter().any(|(v, _)| *v == id) {
            return;
        }
        let detail = microclaw_code_core::presets::lookup(&id)
            .map(|p| format!("{}k context", p.context_window / 1000))
            .unwrap_or_default();
        out.push((id, detail));
    };
    push(current.to_string(), &mut out);
    if let ModelSource::Profile(model) = &project.model {
        if let Some(profile) = project.settings.model.profiles.get(&model.profile)
            && let Some(m) = &profile.model
        {
            push(m.clone(), &mut out);
        }
        let prefix = format!("{}/", model.profile);
        for spec in project
            .settings
            .model
            .default
            .iter()
            .chain(project.roles.plan.iter())
            .chain(project.roles.review.iter())
        {
            push(
                spec.strip_prefix(&prefix).unwrap_or(spec).to_string(),
                &mut out,
            );
        }
    }
    if let Some(provider) = microclaw_code_core::presets::lookup(current).map(|p| p.provider) {
        for preset in microclaw_code_core::presets::all() {
            // Family ids such as `deepseek` or `claude` are not model names.
            if preset.provider == provider && preset.id.contains('-') {
                push(preset.id.to_string(), &mut out);
            }
        }
    }
    out
}

fn config_options(project: &ProjectEngine, mode: Mode, model: &str) -> Vec<SessionConfigOption> {
    let modes: Vec<SessionConfigSelectOption> = modes_for(project)
        .into_iter()
        .map(|m| {
            let (name, description) = mode_info(m);
            SessionConfigSelectOption::new(m.as_str(), name).description(description)
        })
        .collect();
    let models: Vec<SessionConfigSelectOption> = model_choices(project, model)
        .into_iter()
        .map(|(id, detail)| {
            let option = SessionConfigSelectOption::new(id.clone(), id);
            if detail.is_empty() {
                option
            } else {
                option.description(detail)
            }
        })
        .collect();
    vec![
        SessionConfigOption::select("mode", "Mode", mode.as_str(), modes)
            .category(SessionConfigOptionCategory::Mode),
        SessionConfigOption::select("model", "Model", model.to_string(), models)
            .category(SessionConfigOptionCategory::Model),
    ]
}

/// A short thread title from the first prompt.
fn title_of(prompt: &str) -> String {
    let line = prompt
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .trim();
    let mut title: String = line.chars().take(60).collect();
    if line.chars().count() > 60 {
        title.push('…');
    }
    title
}

enum TurnKind {
    Prompt(String),
    Review(Option<String>),
}

impl Agent {
    fn notify(&self, session_id: &str, update: SessionUpdate) {
        self.conn.notify(
            CLIENT_METHOD_NAMES.session_update,
            SessionNotification::new(SessionId::new(session_id.to_string()), update),
        );
    }

    fn say(&self, session_id: &str, text: impl Into<String>) {
        self.notify(
            session_id,
            SessionUpdate::AgentMessageChunk(ContentChunk::new(text.into().into())),
        );
    }

    async fn handle(&self, method: &str, p: Value) -> Result<(Value, Option<String>), Error> {
        let m = &AGENT_METHOD_NAMES;
        if method == m.initialize {
            Ok((self.initialize(params(p)?)?, None))
        } else if method == m.authenticate {
            Ok((self.authenticate()?, None))
        } else if method == m.session_new {
            let request: NewSessionRequest = params(p)?;
            let id = self.open(&request.cwd, None).await?;
            let response = NewSessionResponse::new(SessionId::new(id.clone()));
            let (modes, options) = self.session_state(&id).await?;
            Ok((
                to_value(response.modes(modes).config_options(options))?,
                Some(id),
            ))
        } else if method == m.session_load {
            let request: LoadSessionRequest = params(p)?;
            let id = request.session_id.0.to_string();
            self.open(&request.cwd, Some(id.clone())).await?;
            self.replay(&id);
            let (modes, options) = self.session_state(&id).await?;
            Ok((
                to_value(
                    LoadSessionResponse::new()
                        .modes(modes)
                        .config_options(options),
                )?,
                Some(id),
            ))
        } else if method == m.session_resume {
            let request: ResumeSessionRequest = params(p)?;
            let id = request.session_id.0.to_string();
            self.open(&request.cwd, Some(id.clone())).await?;
            let (modes, options) = self.session_state(&id).await?;
            Ok((
                to_value(
                    ResumeSessionResponse::new()
                        .modes(modes)
                        .config_options(options),
                )?,
                Some(id),
            ))
        } else if method == m.session_list {
            Ok((self.list(params(p)?)?, None))
        } else if method == m.session_close {
            let request: CloseSessionRequest = params(p)?;
            self.close(request.session_id.0.as_ref());
            Ok((to_value(CloseSessionResponse::new())?, None))
        } else if method == m.session_set_mode {
            let request: SetSessionModeRequest = params(p)?;
            let mode = Mode::parse(&request.mode_id.0).ok_or_else(|| invalid("unknown mode"))?;
            self.set_mode(request.session_id.0.as_ref(), mode).await?;
            Ok((to_value(SetSessionModeResponse::new())?, None))
        } else if method == m.session_set_config_option {
            let request: SetSessionConfigOptionRequest = params(p)?;
            let options = self.set_option(request).await?;
            Ok((
                to_value(SetSessionConfigOptionResponse::new(options))?,
                None,
            ))
        } else if method == m.session_prompt {
            Ok((self.prompt(params(p)?).await?, None))
        } else {
            Err(Error::method_not_found())
        }
    }

    fn notification(&self, method: &str, p: Value) {
        if method == AGENT_METHOD_NAMES.session_cancel
            && let Ok(request) = params::<CancelNotification>(p)
            && let Some(controls) = self
                .sessions
                .borrow()
                .get(request.session_id.0.as_ref())
                .and_then(|s| s.controls.clone())
        {
            let _ = controls.send(Control::Cancel);
        }
    }

    fn cancel_all(&self) {
        for session in self.sessions.borrow().values() {
            if let Some(controls) = &session.controls {
                let _ = controls.send(Control::Cancel);
            }
        }
    }

    fn initialize(&self, request: InitializeRequest) -> Result<Value, Error> {
        if let Some(session) = &request.client_capabilities.session {
            self.support.set(ClientSupport {
                notices: session.notices.is_some(),
                compaction: session.compaction.is_some(),
            });
        }
        let version = if request.protocol_version < ProtocolVersion::V1 {
            request.protocol_version
        } else {
            ProtocolVersion::V1
        };
        let response = InitializeResponse::new(version)
            .agent_info(
                Implementation::new("mccode", env!("CARGO_PKG_VERSION")).title("MicroClaw Code"),
            )
            .agent_capabilities(
                AgentCapabilities::new()
                    .load_session(true)
                    .prompt_capabilities(
                        PromptCapabilities::new().embedded_context(true).image(true),
                    )
                    .session_capabilities(
                        SessionCapabilities::new()
                            .list(SessionListCapabilities::new())
                            .resume(SessionResumeCapabilities::new())
                            .close(SessionCloseCapabilities::new()),
                    ),
            )
            .auth_methods(vec![AuthMethod::Terminal(
                AuthMethodTerminal::new(SETUP_AUTH_ID, "Set up MicroClaw Code")
                    .description("Choose a model provider and enter its API key (`mccode setup`).")
                    .args(vec!["setup".to_string()]),
            )]);
        to_value(response)
    }

    /// Terminal auth already ran `mccode setup`; succeed when a model is
    /// configured now.
    fn authenticate(&self) -> Result<Value, Error> {
        let settings = microclaw_code_core::settings::load(Path::new("."), false).settings;
        launch::model_source(&settings, self.options.engine.explicit_config.as_deref())
            .map_err(|e| Error::auth_required().data(Value::String(e.to_string())))?;
        Ok(serde_json::json!({}))
    }

    async fn project_engine(&self, root: &Path) -> Result<Rc<ProjectEngine>, Error> {
        if let Some(engine) = self.projects.borrow().get(root) {
            return Ok(engine.clone());
        }
        let settings = launch::project_settings(root).settings;
        launch::model_source(&settings, self.options.engine.explicit_config.as_deref())
            .map_err(|e| Error::auth_required().data(Value::String(e.to_string())))?;
        let built = launch::project_engine(root, &self.options.engine, "editor")
            .await
            .map_err(internal)?;
        for warning in &built.warnings {
            eprintln!("mccode: {warning}");
        }
        let built = Rc::new(built);
        self.projects
            .borrow_mut()
            .insert(root.to_path_buf(), built.clone());
        Ok(built)
    }

    async fn open(&self, cwd: &Path, session_id: Option<String>) -> Result<String, Error> {
        let project = launch::trusted_project(cwd).map_err(internal)?;
        let engine = self.project_engine(&project.root).await?;
        let mut index = SessionIndex::load(SessionIndex::default_path());
        let id = match session_id {
            Some(id) => id,
            None => index.create(&project.root).map_err(internal)?.id,
        };
        let titled = index.get(&id).is_some_and(|r| !r.title.is_empty());
        let allowed = modes_for(&engine);
        let mode = self
            .options
            .default_mode
            .or(project.config.mode)
            .or_else(|| {
                engine
                    .settings
                    .permissions
                    .default_mode
                    .as_deref()
                    .and_then(Mode::parse)
            })
            .filter(|m| allowed.contains(m))
            .unwrap_or(Mode::Ask);
        let settings = SessionSettings {
            max_session_tokens: project.config.max_session_tokens,
            mode,
            verify: self.options.verify,
            max_fix_rounds: self
                .options
                .max_fix_rounds
                .unwrap_or_else(|| project.max_fix_rounds()),
            interactive: true,
            sandbox: self.options.sandbox_info.clone(),
        };
        let custom = microclaw_code_core::commands::load(
            &project,
            &microclaw_code_core::commands::personal_dir(),
        );
        let root = project.root.clone();
        let mut code = CodeSession::new(engine.engine.clone(), project, id.clone(), settings);
        code.set_tool_gate(engine.gate.clone());
        code.set_role_models(engine.roles.clone());
        let previous = self.sessions.borrow_mut().insert(
            id.clone(),
            AcpSession {
                code: Some(code),
                controls: None,
                engine: engine.engine.clone(),
                project: engine,
                root,
                mode,
                custom,
                titled,
            },
        );
        if let Some(controls) = previous.and_then(|p| p.controls) {
            let _ = controls.send(Control::Cancel);
        }
        Ok(id)
    }

    async fn session_state(
        &self,
        id: &str,
    ) -> Result<(SessionModeState, Vec<SessionConfigOption>), Error> {
        let (engine, project, mode) = {
            let sessions = self.sessions.borrow();
            let s = sessions.get(id).ok_or_else(|| not_found(id))?;
            (s.engine.clone(), s.project.clone(), s.mode)
        };
        let model = engine.session_model(id).await.unwrap_or_default();
        Ok((
            mode_state(&project, mode),
            config_options(&project, mode, &model),
        ))
    }

    /// Sent right after a session is created or loaded.
    fn announce(&self, id: &str) {
        let custom = match self.sessions.borrow().get(id) {
            Some(s) => s.custom.clone(),
            None => return,
        };
        self.notify(
            id,
            SessionUpdate::AvailableCommandsUpdate(
                agent_client_protocol_schema::v1::AvailableCommandsUpdate::new(
                    commands::available(&custom),
                ),
            ),
        );
    }

    fn replay(&self, id: &str) {
        let history = match self.sessions.borrow().get(id) {
            Some(s) => s.code.as_ref().map(|c| c.history(200)).unwrap_or_default(),
            None => return,
        };
        for entry in history {
            let update = match entry {
                HistoryEntry::User(text) => {
                    SessionUpdate::UserMessageChunk(ContentChunk::new(text.into()))
                }
                HistoryEntry::Agent(text) => {
                    SessionUpdate::AgentMessageChunk(ContentChunk::new(text.into()))
                }
                HistoryEntry::Verification(line) => SessionUpdate::AgentThoughtChunk(
                    ContentChunk::new(format!("verification {line}").into()),
                ),
            };
            self.notify(id, update);
        }
    }

    fn list(&self, request: ListSessionsRequest) -> Result<Value, Error> {
        let index = SessionIndex::load(SessionIndex::default_path());
        // `cwd` is an optional filter: without it (Zed's "Import Threads")
        // every project's sessions are listed, each with its own directory.
        let records = match request.cwd {
            Some(cwd) => {
                let root = launch::trusted_project(&cwd).map(|p| p.root).unwrap_or(cwd);
                index.for_project(&root)
            }
            None => index.all(),
        };
        let sessions = records
            .into_iter()
            .filter(|r| r.turns > 0 || !r.title.is_empty())
            .take(100)
            .map(|r| {
                let cwd = std::path::PathBuf::from(&r.project);
                let mut info = SessionInfo::new(SessionId::new(r.id.clone()), cwd)
                    .updated_at(r.updated_at.clone());
                if !r.title.is_empty() {
                    info = info.title(r.title.clone());
                }
                info
            })
            .collect();
        to_value(ListSessionsResponse::new(sessions))
    }

    fn close(&self, id: &str) {
        if let Some(session) = self.sessions.borrow_mut().remove(id)
            && let Some(controls) = session.controls
        {
            let _ = controls.send(Control::Cancel);
        }
    }

    async fn set_mode(&self, id: &str, mode: Mode) -> Result<(), Error> {
        let project = {
            let mut sessions = self.sessions.borrow_mut();
            let s = sessions.get_mut(id).ok_or_else(|| not_found(id))?;
            if !modes_for(&s.project).contains(&mode) {
                return Err(invalid(format!("{} mode is disabled", mode.as_str())));
            }
            s.mode = mode;
            if let Some(code) = s.code.as_mut() {
                code.settings.mode = mode;
            }
            s.project.clone()
        };
        self.notify(
            id,
            SessionUpdate::CurrentModeUpdate(CurrentModeUpdate::new(mode.as_str())),
        );
        let engine = self.sessions.borrow().get(id).map(|s| s.engine.clone());
        if let Some(engine) = engine {
            let model = engine.session_model(id).await.unwrap_or_default();
            self.notify(
                id,
                SessionUpdate::ConfigOptionUpdate(ConfigOptionUpdate::new(config_options(
                    &project, mode, &model,
                ))),
            );
        }
        Ok(())
    }

    async fn set_option(
        &self,
        request: SetSessionConfigOptionRequest,
    ) -> Result<Vec<SessionConfigOption>, Error> {
        let id = request.session_id.0.to_string();
        let value = request
            .value
            .as_value_id()
            .map(|v| v.0.to_string())
            .ok_or_else(|| invalid("expected a value id"))?;
        match request.config_id.0.as_ref() {
            "mode" => {
                let mode = Mode::parse(&value).ok_or_else(|| invalid("unknown mode"))?;
                self.set_mode(&id, mode).await?;
            }
            "model" => {
                let engine = self
                    .sessions
                    .borrow()
                    .get(&id)
                    .map(|s| s.engine.clone())
                    .ok_or_else(|| not_found(&id))?;
                engine
                    .set_session_model(&id, Some(&value))
                    .await
                    .map_err(internal)?;
            }
            other => return Err(invalid(format!("unknown option {other}"))),
        }
        let (_, options) = self.session_state(&id).await?;
        Ok(options)
    }

    async fn send_usage(&self, id: &str, code: &CodeSession) {
        let Ok(context) = code.context_usage().await else {
            return;
        };
        let mut update = UsageUpdate::new(context.used_tokens as u64, context.window as u64);
        if let Ok(usage) = code.usage().await {
            let cost: Option<f64> = usage
                .by_model
                .iter()
                .map(|m| crate::tui::estimate_cost(&m.model, m.input_tokens, m.output_tokens))
                .sum();
            if let Some(cost) = cost {
                update = update.cost(agent_client_protocol_schema::v1::Cost::new(cost, "USD"));
            }
        }
        self.notify(id, SessionUpdate::UsageUpdate(update));
    }

    async fn prompt(&self, request: PromptRequest) -> Result<Value, Error> {
        let id = request.session_id.0.to_string();
        let text = flatten_prompt(&request.prompt);
        if text.trim().is_empty() {
            return Err(invalid("the prompt is empty"));
        }
        let custom = self
            .sessions
            .borrow()
            .get(&id)
            .map(|s| s.custom.clone())
            .ok_or_else(|| not_found(&id))?;
        let parsed = commands::parse(&text, &custom);
        // Built-in commands neither name the thread nor count as a turn.
        let command = matches!(parsed, Parsed::Builtin(..));
        let (mut code, mode, root, titled) = {
            let mut sessions = self.sessions.borrow_mut();
            let s = sessions.get_mut(&id).ok_or_else(|| not_found(&id))?;
            let code = s
                .code
                .take()
                .ok_or_else(|| internal("a prompt is already running in this session"))?;
            let titled = s.titled || command;
            s.titled |= !command;
            (code, s.mode, s.root.clone(), titled)
        };
        code.settings.mode = mode;
        if !command {
            let _ = SessionIndex::load(SessionIndex::default_path()).touch(&id, &text);
        }
        if !titled {
            self.notify(
                &id,
                SessionUpdate::SessionInfoUpdate(SessionInfoUpdate::new().title(title_of(&text))),
            );
        }
        let result = match parsed {
            Parsed::Builtin(Builtin::Review, focus) => {
                let focus = (!focus.is_empty()).then_some(focus);
                self.run_turn(&id, &root, code, TurnKind::Review(focus))
                    .await
            }
            Parsed::Builtin(builtin, args) => {
                self.builtin(&id, &mut code, builtin, &args, &custom).await;
                Ok((code, StopReason::EndTurn))
            }
            Parsed::Prompt(prompt) => {
                self.run_turn(&id, &root, code, TurnKind::Prompt(prompt))
                    .await
            }
            Parsed::Plain => {
                self.run_turn(&id, &root, code, TurnKind::Prompt(text))
                    .await
            }
        };
        let (code, stop) = result?;
        self.send_usage(&id, &code).await;
        if let Some(s) = self.sessions.borrow_mut().get_mut(&id) {
            s.code = Some(code);
            s.controls = None;
        }
        to_value(PromptResponse::new(stop))
    }

    async fn builtin(
        &self,
        id: &str,
        code: &mut CodeSession,
        builtin: Builtin,
        args: &str,
        custom: &[CustomCommand],
    ) {
        let text = match builtin {
            Builtin::Compact => {
                let focus = (!args.is_empty()).then_some(args);
                match code.compact(focus).await {
                    Ok(c) if c.method == "none" => "Nothing to compact yet.".to_string(),
                    Ok(c) => format!(
                        "Compacted the conversation: {} → {} messages, about {} → {} tokens.",
                        c.messages_before, c.messages_after, c.tokens_before, c.tokens_after
                    ),
                    Err(e) => format!("Could not compact: {e}"),
                }
            }
            Builtin::Undo => match code.undo().await {
                Ok(Some((_, prompt))) => {
                    format!("Undid the file changes of “{}”.", title_of(&prompt))
                }
                Ok(None) => "Nothing to undo in this session.".to_string(),
                Err(e) => format!("Could not undo: {e}"),
            },
            Builtin::Cost => match code.usage().await {
                Ok(usage) => {
                    let cost: Option<f64> = usage
                        .by_model
                        .iter()
                        .map(|m| {
                            crate::tui::estimate_cost(&m.model, m.input_tokens, m.output_tokens)
                        })
                        .sum();
                    let mut text = format!(
                        "{} requests, {} input and {} output tokens",
                        usage.requests, usage.input_tokens, usage.output_tokens
                    );
                    if let Some(cost) = cost {
                        text.push_str(&format!(", about ${cost:.4}"));
                    }
                    text.push('.');
                    text
                }
                Err(e) => format!("Usage is not available: {e}"),
            },
            Builtin::Context => match code.context_usage().await {
                Ok(c) => format!(
                    "Context: {} of {} tokens ({}%) on {}.",
                    c.used_tokens,
                    c.window,
                    (c.used_tokens * 100).checked_div(c.window).unwrap_or(0),
                    c.model
                ),
                Err(e) => format!("Context usage is not available: {e}"),
            },
            Builtin::Help => commands::help(custom),
            Builtin::Review => unreachable!("review runs as a turn"),
        };
        self.say(id, text);
    }

    async fn run_turn(
        &self,
        id: &str,
        root: &Path,
        mut code: CodeSession,
        kind: TurnKind,
    ) -> Result<(CodeSession, StopReason), Error> {
        let (updates_tx, mut updates_rx) = mpsc::unbounded_channel();
        let (controls_tx, mut controls_rx) = mpsc::unbounded_channel();
        if let Some(s) = self.sessions.borrow_mut().get_mut(id) {
            s.controls = Some(controls_tx.clone());
        }
        let turn = tokio::spawn(async move {
            let report = match kind {
                TurnKind::Prompt(prompt) => code.turn(&prompt, &updates_tx, &mut controls_rx).await,
                TurnKind::Review(focus) => {
                    code.review(focus.as_deref(), &updates_tx, &mut controls_rx)
                        .await
                }
            };
            (code, report)
        });
        tokio::pin!(turn);
        let mut mapper = UpdateMapper::new(root, self.support.get());
        let (code, report) = loop {
            tokio::select! {
                update = updates_rx.recv() => {
                    let Some(update) = update else { continue };
                    if let Update::ApprovalRequested(approval) = &update {
                        self.ask_permission(id, &mapper, approval, controls_tx.clone());
                        continue;
                    }
                    for mapped in mapper.map(&update) {
                        self.notify(id, mapped);
                    }
                }
                result = &mut turn => break result.map_err(internal)?,
            }
        };
        while let Ok(update) = updates_rx.try_recv() {
            for mapped in mapper.map(&update) {
                self.notify(id, mapped);
            }
        }
        let stop = match report {
            Ok(report) if report.cancelled => StopReason::Cancelled,
            Ok(report) => {
                if report.budget_exhausted {
                    self.say(id, "\n\nThe session's token budget is used up.");
                }
                StopReason::EndTurn
            }
            Err(e) => {
                self.say(id, format!("\n\nError: {e}"));
                StopReason::EndTurn
            }
        };
        Ok((code, stop))
    }

    fn ask_permission(
        &self,
        id: &str,
        mapper: &UpdateMapper,
        approval: &PendingApproval,
        controls: mpsc::UnboundedSender<Control>,
    ) {
        let call_id = mapper
            .running_call(&approval.tool)
            .unwrap_or_else(|| approval.approval_id.clone());
        let mut fields = ToolCallUpdateFields::new().title(format!("Allow {}?", approval.tool));
        if let Some(preview) = &approval.preview {
            let mut text = format!("```\n{preview}\n```");
            if let Some(advisory) = &approval.advisory {
                text.push_str(&format!("\n{advisory}"));
            }
            fields = fields.content(vec![ToolCallContent::from(text)]);
        }
        let request = RequestPermissionRequest::new(
            SessionId::new(id.to_string()),
            ToolCallUpdate::new(call_id, fields),
            permission_options(approval),
        );
        let conn = self.conn.clone();
        tokio::task::spawn_local(async move {
            let answer = conn
                .request(CLIENT_METHOD_NAMES.session_request_permission, request)
                .await
                .ok()
                .and_then(|v| serde_json::from_value::<RequestPermissionResponse>(v).ok());
            let control = match answer.map(|r| r.outcome) {
                Some(RequestPermissionOutcome::Selected(selected)) => {
                    Control::Approve(selected.option_id.0.to_string())
                }
                _ => Control::Cancel,
            };
            let _ = controls.send(control);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use microclaw_sdk::{RuntimeApprovalOption, RuntimeApprovalOptionKind};

    #[test]
    fn approval_options_become_permission_options() {
        let option = |value: &str, decision| RuntimeApprovalOption {
            value: value.into(),
            label: value.into(),
            kind: RuntimeApprovalOptionKind::Primary,
            decision,
        };
        let approval = PendingApproval::from_event(
            "a",
            "bash",
            Some("cargo test"),
            &[
                option("1", RuntimeApprovalDecision::Approve),
                option("2", RuntimeApprovalDecision::Approve),
                option("3", RuntimeApprovalDecision::Deny),
            ],
            None,
        );
        let kinds: Vec<_> = permission_options(&approval)
            .into_iter()
            .map(|o| (o.option_id.0.to_string(), o.kind))
            .collect();
        assert_eq!(
            kinds,
            vec![
                ("1".to_string(), PermissionOptionKind::AllowOnce),
                ("2".to_string(), PermissionOptionKind::AllowAlways),
                ("p".to_string(), PermissionOptionKind::AllowAlways),
                ("3".to_string(), PermissionOptionKind::RejectOnce),
            ]
        );
    }

    #[test]
    fn prompts_flatten_and_titles_are_short() {
        assert_eq!(flatten_prompt(&[ContentBlock::from("fix it")]), "fix it");
        assert_eq!(title_of("\n  Fix the parser\nmore"), "Fix the parser");
        assert!(title_of(&"x".repeat(80)).ends_with('…'));
    }
}
