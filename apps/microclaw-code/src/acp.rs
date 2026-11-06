//! `mccode acp`: MicroClaw Code as an Agent Client Protocol agent over
//! stdio, for editors such as Zed.
//!
//! Each ACP session is a [`CodeSession`] in the project that contains the
//! session's `cwd`: the same turn driver as the TUI (verification, fix
//! rounds, allow rules, the sandbox). Approvals become
//! `session/request_permission` requests; modes are `plan` / `ask` / `auto`.
//! Project trust is not asked for here: a project is trusted only after
//! `mccode trust` (or the TUI).

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use agent_client_protocol::{
    Agent, AgentCapabilities, AgentSideConnection, AuthenticateRequest, AuthenticateResponse,
    CancelNotification, Client, ContentBlock, ContentChunk, CurrentModeUpdate, Error,
    Implementation, InitializeRequest, InitializeResponse, LoadSessionRequest, LoadSessionResponse,
    NewSessionRequest, NewSessionResponse, PermissionOption, PermissionOptionKind, Plan, PlanEntry,
    PlanEntryPriority, PlanEntryStatus, PromptCapabilities, PromptRequest, PromptResponse,
    RequestPermissionOutcome, RequestPermissionRequest, Result as AcpResult, SessionId,
    SessionMode, SessionModeState, SessionNotification, SessionUpdate, SetSessionModeRequest,
    SetSessionModeResponse, StopReason, ToolCall, ToolCallContent, ToolCallLocation,
    ToolCallStatus, ToolCallUpdate, ToolCallUpdateFields, ToolKind,
};
use microclaw_code_core::driver::{
    CodeSession, Control, PendingApproval, SandboxInfo, SessionSettings, Update,
};
use microclaw_code_core::project::{Mode, Project};
use microclaw_code_core::sessions::SessionIndex;
use microclaw_code_core::trust::TrustStore;
use microclaw_sdk::{
    MicroClaw, RuntimeApprovalDecision, RuntimeEvent, RuntimePlanStepStatus, ShellSandbox,
};
use tokio::sync::{mpsc, oneshot};
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

/// How the engine for each project is built.
pub struct AcpOptions {
    pub config_path: PathBuf,
    pub sandbox: ShellSandbox,
    pub sandbox_info: Option<SandboxInfo>,
    pub review_commands: bool,
    pub verify: bool,
    pub max_fix_rounds: Option<u32>,
    pub default_mode: Option<Mode>,
}

enum Outbound {
    Notify(SessionNotification),
    Permission(RequestPermissionRequest, oneshot::Sender<Option<String>>),
    /// Answered once every earlier notification was written.
    Flush(oneshot::Sender<()>),
}

struct AcpSession {
    /// Taken while a prompt runs.
    session: Option<CodeSession>,
    controls: Option<mpsc::UnboundedSender<Control>>,
    mode: Mode,
}

struct CodeAcpAgent {
    options: AcpOptions,
    outbound: mpsc::UnboundedSender<Outbound>,
    engines: RefCell<HashMap<PathBuf, MicroClaw>>,
    gates: RefCell<
        HashMap<
            PathBuf,
            (
                microclaw_code_core::settings::CodeSettings,
                microclaw_code_core::gate::CodeToolGate,
            ),
        >,
    >,
    sessions: Rc<RefCell<HashMap<String, AcpSession>>>,
}

fn to_acp_error(error: impl std::fmt::Display) -> Error {
    Error::internal_error().data(serde_json::Value::String(error.to_string()))
}

/// Serve ACP on stdin/stdout until the client disconnects.
pub async fn serve(options: AcpOptions) -> anyhow::Result<()> {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async move {
            let (outbound_tx, mut outbound_rx) = mpsc::unbounded_channel::<Outbound>();
            let agent = CodeAcpAgent {
                options,
                outbound: outbound_tx,
                engines: RefCell::new(HashMap::new()),
                gates: RefCell::new(HashMap::new()),
                sessions: Rc::new(RefCell::new(HashMap::new())),
            };
            let (client, io) = AgentSideConnection::new(
                agent,
                tokio::io::stdout().compat_write(),
                tokio::io::stdin().compat(),
                |fut| {
                    tokio::task::spawn_local(fut);
                },
            );
            let client = Rc::new(client);
            let pump = tokio::task::spawn_local(async move {
                while let Some(message) = outbound_rx.recv().await {
                    match message {
                        Outbound::Notify(notification) => {
                            if client.session_notification(notification).await.is_err() {
                                break;
                            }
                        }
                        Outbound::Flush(done) => {
                            let _ = done.send(());
                        }
                        Outbound::Permission(request, reply) => {
                            let client = client.clone();
                            tokio::task::spawn_local(async move {
                                let answer = match client.request_permission(request).await {
                                    Ok(response) => match response.outcome {
                                        RequestPermissionOutcome::Selected(selected) => {
                                            Some(selected.option_id.0.to_string())
                                        }
                                        _ => None,
                                    },
                                    Err(_) => None,
                                };
                                let _ = reply.send(answer);
                            });
                        }
                    }
                }
            });
            let result = io.await;
            pump.abort();
            result.map_err(|e| anyhow::anyhow!("ACP transport failed: {e}"))
        })
        .await
}

fn mode_state(current: Mode) -> SessionModeState {
    SessionModeState::new(
        current.as_str(),
        vec![
            SessionMode::new("plan", "Plan")
                .description("Read-only research; proposes a plan before changing anything."),
            SessionMode::new("ask", "Ask")
                .description("Edits apply directly; shell commands ask first."),
            SessionMode::new("auto", "Auto")
                .description("Commands run without asking, except destructive ones."),
        ],
    )
}

fn flatten_prompt(blocks: &[ContentBlock]) -> String {
    let mut parts = Vec::new();
    for block in blocks {
        match block {
            ContentBlock::Text(text) => parts.push(text.text.clone()),
            ContentBlock::ResourceLink(link) => {
                parts.push(format!("@{} ({})", link.name, link.uri));
            }
            ContentBlock::Resource(resource) => {
                if let agent_client_protocol::EmbeddedResourceResource::TextResourceContents(text) =
                    &resource.resource
                {
                    parts.push(format!(
                        "Embedded file {}:\n```\n{}\n```",
                        text.uri, text.text
                    ));
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

fn tool_kind(name: &str) -> ToolKind {
    match name {
        "read_file" | "bash_output" => ToolKind::Read,
        "edit_file" | "write_file" | "apply_patch" => ToolKind::Edit,
        "grep" | "glob" => ToolKind::Search,
        "bash" | "bash_kill" | "bash_input" => ToolKind::Execute,
        "web_fetch" | "web_search" => ToolKind::Fetch,
        "todo_write" => ToolKind::Think,
        _ => ToolKind::Other,
    }
}

/// Maps driver updates to ACP session updates.
#[derive(Default)]
struct UpdateMapper {
    streamed: bool,
    /// Last running call id per tool name (for permission requests).
    running: HashMap<String, String>,
    /// Call id by `path` argument (for diffs).
    by_path: HashMap<String, String>,
}

impl UpdateMapper {
    fn map(&mut self, update: &Update) -> Vec<SessionUpdate> {
        let thought = |text: String| {
            vec![SessionUpdate::AgentThoughtChunk(ContentChunk::new(
                text.into(),
            ))]
        };
        match update {
            Update::Runtime(envelope) => match &envelope.event {
                RuntimeEvent::TextDelta { delta } if !delta.is_empty() => {
                    self.streamed = true;
                    vec![SessionUpdate::AgentMessageChunk(ContentChunk::new(
                        delta.clone().into(),
                    ))]
                }
                RuntimeEvent::ToolStart {
                    call_id,
                    name,
                    input,
                } => {
                    self.running.insert(name.clone(), call_id.clone());
                    let path = input.get("path").and_then(|v| v.as_str());
                    if let Some(path) = path {
                        self.by_path.insert(path.to_string(), call_id.clone());
                    }
                    let title = crate::format::tool_summary(name, input);
                    let mut call = ToolCall::new(
                        call_id.clone(),
                        if title.is_empty() {
                            name.clone()
                        } else {
                            format!("{name}: {title}")
                        },
                    )
                    .kind(tool_kind(name))
                    .status(ToolCallStatus::InProgress)
                    .raw_input(input.clone());
                    if let Some(path) = path {
                        call = call.locations(vec![ToolCallLocation::new(path)]);
                    }
                    vec![SessionUpdate::ToolCall(call)]
                }
                RuntimeEvent::ToolResult {
                    call_id,
                    is_error,
                    preview,
                    error_type,
                    ..
                } => {
                    if error_type.as_deref() == Some("approval_required") {
                        return Vec::new();
                    }
                    let status = if *is_error {
                        ToolCallStatus::Failed
                    } else {
                        ToolCallStatus::Completed
                    };
                    let mut fields = ToolCallUpdateFields::new().status(status);
                    if !preview.trim().is_empty() {
                        fields = fields.content(vec![ToolCallContent::from(preview.clone())]);
                    }
                    vec![SessionUpdate::ToolCallUpdate(ToolCallUpdate::new(
                        call_id.clone(),
                        fields,
                    ))]
                }
                RuntimeEvent::FileDiff {
                    path,
                    diff,
                    added,
                    removed,
                    ..
                } => {
                    let Some(call_id) = self
                        .by_path
                        .get(path)
                        .or_else(|| self.running.get("apply_patch"))
                        .cloned()
                    else {
                        return Vec::new();
                    };
                    let text = format!("{path} (+{added} -{removed})\n```diff\n{diff}\n```");
                    vec![SessionUpdate::ToolCallUpdate(ToolCallUpdate::new(
                        call_id,
                        ToolCallUpdateFields::new()
                            .content(vec![ToolCallContent::from(text)])
                            .locations(vec![ToolCallLocation::new(path.clone())]),
                    ))]
                }
                RuntimeEvent::PlanUpdated { steps } => {
                    let entries = steps
                        .iter()
                        .map(|step| {
                            let status = match step.status {
                                RuntimePlanStepStatus::Completed => PlanEntryStatus::Completed,
                                RuntimePlanStepStatus::InProgress => PlanEntryStatus::InProgress,
                                RuntimePlanStepStatus::Pending => PlanEntryStatus::Pending,
                            };
                            PlanEntry::new(step.title.clone(), PlanEntryPriority::Medium, status)
                        })
                        .collect();
                    vec![SessionUpdate::Plan(Plan::new(entries))]
                }
                _ => Vec::new(),
            },
            Update::RunFinished { final_text, .. } => {
                let mut out = Vec::new();
                if !self.streamed && !final_text.trim().is_empty() {
                    out.push(SessionUpdate::AgentMessageChunk(ContentChunk::new(
                        final_text.clone().into(),
                    )));
                }
                self.streamed = false;
                out
            }
            Update::CheckStarted(check) => thought(format!("Running check `{}`…", check.name)),
            Update::CheckFinished(outcome) => thought(format!(
                "Check `{}`: {}",
                outcome.check.name,
                outcome.status_label()
            )),
            Update::FixRound { round, max, check } => {
                thought(format!("`{check}` failed; fixing (round {round}/{max})"))
            }
            Update::ChecksGaveUp(outcome) => thought(format!(
                "Check `{}` still fails after the fix rounds.",
                outcome.check.name
            )),
            Update::AutoApproved { tool, .. } => thought(format!("Auto-approved {tool}.")),
            Update::Notice(text) => thought(text.clone()),
            _ => Vec::new(),
        }
    }
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

impl CodeAcpAgent {
    fn notify(&self, session_id: &SessionId, update: SessionUpdate) {
        let _ = self
            .outbound
            .send(Outbound::Notify(SessionNotification::new(
                session_id.clone(),
                update,
            )));
    }

    /// Wait until every queued notification was sent, so a response never
    /// overtakes the updates it belongs to.
    async fn flush(&self) {
        let (done_tx, done_rx) = oneshot::channel();
        if self.outbound.send(Outbound::Flush(done_tx)).is_ok() {
            let _ = done_rx.await;
        }
    }

    async fn engine_for(&self, root: &Path) -> anyhow::Result<MicroClaw> {
        if let Some(engine) = self.engines.borrow().get(root) {
            return Ok(engine.clone());
        }
        let (code_settings, gate) = crate::project_gate(root);
        self.gates
            .borrow_mut()
            .insert(root.to_path_buf(), (code_settings.clone(), gate.clone()));
        let mut builder = MicroClaw::builder(&self.options.config_path)
            .tool_gate(std::sync::Arc::new(gate))
            .summary_model(microclaw_code_core::settings::role_model(
                &code_settings,
                "summary",
            ))
            .caller_channel(microclaw_code_core::driver::CALLER_CHANNEL)
            .workspace(root)
            .data_dir(microclaw_code_core::home::data_dir())
            .max_concurrent_runs(4)
            .shell_sandbox(self.options.sandbox.clone());
        if self.options.review_commands {
            builder = builder.command_reviewer(None);
        }
        let engine = builder.build().await.map_err(|e| anyhow::anyhow!("{e}"))?;
        self.engines
            .borrow_mut()
            .insert(root.to_path_buf(), engine.clone());
        Ok(engine)
    }

    async fn open_session(&self, cwd: &Path, session_id: Option<String>) -> anyhow::Result<String> {
        let trust = TrustStore::load(TrustStore::default_path());
        let project = Project::discover(cwd, |root, hash| trust.is_trusted(root, hash))?;
        let mut index = SessionIndex::load(SessionIndex::default_path());
        let id = match session_id {
            Some(id) => id,
            None => index.create(&project.root)?.id,
        };
        let engine = self.engine_for(&project.root).await?;
        let mode = self
            .options
            .default_mode
            .or(project.config.mode)
            .unwrap_or_default();
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
        let root = project.root.clone();
        let mut session = CodeSession::new(engine, project, id.clone(), settings);
        if let Some((code_settings, gate)) = self.gates.borrow().get(&root) {
            session.set_tool_gate(gate.clone());
            session.set_role_models(crate::role_models(code_settings));
        }
        self.sessions.borrow_mut().insert(
            id.clone(),
            AcpSession {
                session: Some(session),
                controls: None,
                mode,
            },
        );
        Ok(id)
    }
}

#[async_trait::async_trait(?Send)]
impl Agent for CodeAcpAgent {
    async fn initialize(&self, args: InitializeRequest) -> AcpResult<InitializeResponse> {
        Ok(InitializeResponse::new(args.protocol_version)
            .agent_info(
                Implementation::new("mccode", env!("CARGO_PKG_VERSION")).title("MicroClaw Code"),
            )
            .agent_capabilities(
                AgentCapabilities::new()
                    .load_session(true)
                    .prompt_capabilities(
                        PromptCapabilities::new().embedded_context(true).image(true),
                    ),
            ))
    }

    async fn authenticate(&self, _args: AuthenticateRequest) -> AcpResult<AuthenticateResponse> {
        Ok(AuthenticateResponse::new())
    }

    async fn new_session(&self, args: NewSessionRequest) -> AcpResult<NewSessionResponse> {
        let id = self
            .open_session(&args.cwd, None)
            .await
            .map_err(to_acp_error)?;
        let mode = self.sessions.borrow()[&id].mode;
        Ok(NewSessionResponse::new(SessionId::new(id)).modes(mode_state(mode)))
    }

    async fn load_session(&self, args: LoadSessionRequest) -> AcpResult<LoadSessionResponse> {
        let id = args.session_id.0.to_string();
        self.open_session(&args.cwd, Some(id.clone()))
            .await
            .map_err(to_acp_error)?;
        let (history, mode) = {
            let sessions = self.sessions.borrow();
            let entry = &sessions[&id];
            (
                entry
                    .session
                    .as_ref()
                    .map(|s| s.history(200))
                    .unwrap_or_default(),
                entry.mode,
            )
        };
        for entry in history {
            let update = match entry {
                microclaw_code_core::driver::HistoryEntry::User(text) => {
                    SessionUpdate::UserMessageChunk(ContentChunk::new(text.into()))
                }
                microclaw_code_core::driver::HistoryEntry::Agent(text) => {
                    SessionUpdate::AgentMessageChunk(ContentChunk::new(text.into()))
                }
                microclaw_code_core::driver::HistoryEntry::Verification(line) => {
                    SessionUpdate::AgentThoughtChunk(ContentChunk::new(
                        format!("verification {line}").into(),
                    ))
                }
            };
            self.notify(&args.session_id, update);
        }
        self.flush().await;
        Ok(LoadSessionResponse::new().modes(mode_state(mode)))
    }

    async fn set_session_mode(
        &self,
        args: SetSessionModeRequest,
    ) -> AcpResult<SetSessionModeResponse> {
        let mode = Mode::parse(&args.mode_id.0).ok_or_else(Error::invalid_params)?;
        {
            let mut sessions = self.sessions.borrow_mut();
            let entry = sessions
                .get_mut(args.session_id.0.as_ref())
                .ok_or_else(Error::invalid_params)?;
            entry.mode = mode;
            if let Some(session) = entry.session.as_mut() {
                session.settings.mode = mode;
            }
        }
        self.notify(
            &args.session_id,
            SessionUpdate::CurrentModeUpdate(CurrentModeUpdate::new(args.mode_id)),
        );
        self.flush().await;
        Ok(SetSessionModeResponse::new())
    }

    async fn prompt(&self, args: PromptRequest) -> AcpResult<PromptResponse> {
        let id = args.session_id.0.to_string();
        let prompt = flatten_prompt(&args.prompt);
        if prompt.trim().is_empty() {
            return Err(Error::invalid_params());
        }
        let (mut session, mode) = {
            let mut sessions = self.sessions.borrow_mut();
            let entry = sessions.get_mut(&id).ok_or_else(Error::invalid_params)?;
            let session = entry
                .session
                .take()
                .ok_or_else(|| to_acp_error("a prompt is already running in this session"))?;
            (session, entry.mode)
        };
        session.settings.mode = mode;
        let _ = SessionIndex::load(SessionIndex::default_path()).touch(&id, &prompt);
        let (updates_tx, mut updates_rx) = mpsc::unbounded_channel();
        let (controls_tx, mut controls_rx) = mpsc::unbounded_channel();
        if let Some(entry) = self.sessions.borrow_mut().get_mut(&id) {
            entry.controls = Some(controls_tx.clone());
        }
        let turn = tokio::spawn(async move {
            let report = session.turn(&prompt, &updates_tx, &mut controls_rx).await;
            (session, report)
        });
        tokio::pin!(turn);
        let mut mapper = UpdateMapper::default();
        let (session, report) = loop {
            tokio::select! {
                update = updates_rx.recv() => {
                    let Some(update) = update else { continue };
                    if let Update::ApprovalRequested(approval) = &update {
                        let call_id = mapper
                            .running
                            .get(&approval.tool)
                            .cloned()
                            .unwrap_or_else(|| approval.approval_id.clone());
                        let mut fields = ToolCallUpdateFields::new()
                            .title(format!("Allow {}?", approval.tool));
                        if let Some(preview) = &approval.preview {
                            let mut text = format!("```\n{preview}\n```");
                            if let Some(advisory) = &approval.advisory {
                                text.push_str(&format!("\n{advisory}"));
                            }
                            fields = fields.content(vec![ToolCallContent::from(text)]);
                        }
                        let request = RequestPermissionRequest::new(
                            args.session_id.clone(),
                            ToolCallUpdate::new(call_id, fields),
                            permission_options(approval),
                        );
                        let (reply_tx, reply_rx) = oneshot::channel();
                        let _ = self.outbound.send(Outbound::Permission(request, reply_tx));
                        let controls = controls_tx.clone();
                        tokio::task::spawn_local(async move {
                            let control = match reply_rx.await {
                                Ok(Some(value)) => Control::Approve(value),
                                _ => Control::Cancel,
                            };
                            let _ = controls.send(control);
                        });
                        continue;
                    }
                    for mapped in mapper.map(&update) {
                        self.notify(&args.session_id, mapped);
                    }
                }
                result = &mut turn => break result.map_err(to_acp_error)?,
            }
        };
        while let Ok(update) = updates_rx.try_recv() {
            for mapped in mapper.map(&update) {
                self.notify(&args.session_id, mapped);
            }
        }
        if let Some(entry) = self.sessions.borrow_mut().get_mut(&id) {
            entry.session = Some(session);
            entry.controls = None;
        }
        self.flush().await;
        let report = report.map_err(to_acp_error)?;
        Ok(PromptResponse::new(if report.cancelled {
            StopReason::Cancelled
        } else {
            StopReason::EndTurn
        }))
    }

    async fn cancel(&self, args: CancelNotification) -> AcpResult<()> {
        if let Some(controls) = self
            .sessions
            .borrow()
            .get(args.session_id.0.as_ref())
            .and_then(|entry| entry.controls.clone())
        {
            let _ = controls.send(Control::Cancel);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use microclaw_sdk::{RuntimeApprovalOption, RuntimeApprovalOptionKind, RuntimeEventEnvelope};

    #[test]
    fn maps_runtime_events_to_session_updates() {
        let mut mapper = UpdateMapper::default();
        let start = Update::Runtime(RuntimeEventEnvelope::new(
            "r",
            1,
            RuntimeEvent::ToolStart {
                call_id: "c1".into(),
                name: "edit_file".into(),
                input: serde_json::json!({"path": "src/lib.rs"}),
            },
        ));
        assert!(matches!(
            mapper.map(&start)[..],
            [SessionUpdate::ToolCall(_)]
        ));
        let diff = Update::Runtime(RuntimeEventEnvelope::new(
            "r",
            2,
            RuntimeEvent::FileDiff {
                path: "src/lib.rs".into(),
                diff: "+a".into(),
                added: 1,
                removed: 0,
                truncated: false,
            },
        ));
        assert!(matches!(
            mapper.map(&diff)[..],
            [SessionUpdate::ToolCallUpdate(_)]
        ));
        let text = Update::Runtime(RuntimeEventEnvelope::new(
            "r",
            3,
            RuntimeEvent::TextDelta { delta: "hi".into() },
        ));
        assert!(matches!(
            mapper.map(&text)[..],
            [SessionUpdate::AgentMessageChunk(_)]
        ));
        // Streamed text is not repeated at the end of the run.
        let finished = Update::RunFinished {
            status: microclaw_sdk::RunStatus::Completed,
            final_text: "hi".into(),
            error: None,
        };
        assert!(mapper.map(&finished).is_empty());
        assert!(matches!(
            mapper.map(&Update::Notice("n".into()))[..],
            [SessionUpdate::AgentThoughtChunk(_)]
        ));
    }

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
        assert_eq!(flatten_prompt(&[ContentBlock::from("fix it")]), "fix it");
    }
}
