use gpui::*;
use gpui_component::{
    ActiveTheme, Disableable, Root, StyledExt,
    button::{Button, ButtonVariants},
    h_flex,
    input::{Input, InputContentType, InputEvent, InputState},
    scroll::ScrollableElement,
    v_flex,
};
use microclaw_core::runtime_event::{RuntimeEvent, RuntimeEventEnvelope};
use microclaw_work_app::session::{
    ConversationRole, WorkCommand, WorkEventKind, WorkReviewStatus, WorkSessionSnapshot, WorkStatus,
};
use microclaw_work_app::store::{WorkSessionStore, WorkSessionSummary};
use microclaw_work_runtime::{
    ModelSettingsDraft, RuntimeConfigSummary, WorkRunCancellation, WorkRunRequest, WorkRunSteering,
    WorkRuntimeMessage, WorkRuntimeService,
};
use smol::Timer;
use std::path::PathBuf;
use std::sync::mpsc::TryRecvError;
use std::time::Duration;

struct WorkApp {
    session: WorkSessionSnapshot,
    session_store: WorkSessionStore,
    recent_sessions: Vec<WorkSessionSummary>,
    persistence_message: String,
    task_input: Entity<InputState>,
    steer_input: Entity<InputState>,
    active_run_id: u64,
    runtime_active: bool,
    runtime_cancellation: Option<WorkRunCancellation>,
    runtime_steering: Option<WorkRunSteering>,
    runtime_service: WorkRuntimeService,
    runtime_config: RuntimeConfigSummary,
    settings_open: bool,
    settings_has_api_key: bool,
    provider_input: Entity<InputState>,
    model_input: Entity<InputState>,
    base_url_input: Entity<InputState>,
    api_key_input: Entity<InputState>,
    last_run_was_demo: bool,
    connection_test_active: bool,
    connection_test_message: String,
    inspector_open: bool,
    draft_revision: u64,
    _subscriptions: Vec<Subscription>,
}

impl WorkApp {
    fn runtime_busy(&self) -> bool {
        self.runtime_active
    }

    fn reject_if_runtime_busy(&mut self, cx: &mut Context<Self>) -> bool {
        if self.runtime_busy() {
            self.persistence_message = "A runtime task is already active.".into();
            cx.notify();
            true
        } else {
            false
        }
    }

    fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let work_data_root = dirs::data_local_dir()
            .unwrap_or_else(std::env::temp_dir)
            .join("microclaw-work");
        let session_root = work_data_root.join("work-sessions");
        let runtime_service =
            WorkRuntimeService::discover(work_data_root.join("microclaw.config.yaml"));
        let runtime_config = runtime_service.config_summary();
        let model_settings = runtime_service.model_settings().ok();
        let settings_provider = model_settings
            .as_ref()
            .map_or_else(|| "openai".to_string(), |value| value.provider.clone());
        let settings_model = model_settings
            .as_ref()
            .map_or_else(|| "gpt-5".to_string(), |value| value.model.clone());
        let settings_base_url = model_settings
            .as_ref()
            .map_or_else(String::new, |value| value.base_url.clone());
        let settings_has_api_key = model_settings
            .as_ref()
            .is_some_and(|value| value.has_api_key);
        let session_store = WorkSessionStore::new(session_root);
        let (mut session, persistence_message) = match session_store.load_active_or_create() {
            Ok(session) if session.status == WorkStatus::Interrupted => (
                session,
                "Recovered an interrupted task. Review it before retrying.".into(),
            ),
            Ok(session) => (session, "Restored the previous session.".into()),
            Err(error) => (
                WorkSessionSnapshot::new(""),
                format!("Could not open the session store: {error}"),
            ),
        };
        let workspace_is_valid =
            !session.workspace.is_empty() && PathBuf::from(&session.workspace).is_dir();
        let persistence_message = if workspace_is_valid {
            persistence_message
        } else {
            let unavailable = std::mem::take(&mut session.workspace);
            if unavailable.is_empty() {
                persistence_message
            } else {
                format!("The previous workspace is unavailable ({unavailable}). Select another.")
            }
        };
        if !workspace_is_valid {
            let _ = session_store.save(&session);
        }
        let recent_sessions = session_store.list().unwrap_or_default();

        let task_input = cx.new(|cx| {
            InputState::new(window, cx)
                .default_value(session.composer_draft.clone())
                .placeholder("Describe what you want MicroClaw Work to do…")
        });
        let steer_input = cx.new(|cx| {
            InputState::new(window, cx).placeholder("Add guidance while the Agent is working…")
        });
        let provider_input = cx.new(|cx| {
            InputState::new(window, cx)
                .default_value(settings_provider)
                .placeholder("openai, anthropic, ollama, openrouter, or custom")
        });
        let model_input = cx.new(|cx| {
            InputState::new(window, cx)
                .default_value(settings_model)
                .placeholder("Model ID")
        });
        let base_url_input = cx.new(|cx| {
            InputState::new(window, cx)
                .default_value(settings_base_url)
                .placeholder("Optional HTTPS provider endpoint")
        });
        let api_key_input = cx.new(|cx| {
            InputState::new(window, cx)
                .masked(true)
                .placeholder(if settings_has_api_key {
                    "Saved key — leave blank to keep it"
                } else {
                    "API key"
                })
        });
        let _subscriptions = vec![
            cx.subscribe_in(&task_input, window, {
                let task_input = task_input.clone();
                move |this, _, event: &InputEvent, _, cx| {
                    if matches!(event, InputEvent::Change) {
                        let _ = this.session.apply(WorkCommand::SetComposerDraft {
                            draft: task_input.read(cx).value().to_string(),
                        });
                        this.draft_revision = this.draft_revision.saturating_add(1);
                        let revision = this.draft_revision;
                        cx.spawn(async move |this, cx| {
                            Timer::after(Duration::from_millis(350)).await;
                            let _ = this.update(cx, |this, cx| {
                                if this.draft_revision != revision || this.runtime_active {
                                    return;
                                }
                                if let Err(error) = this.save_session() {
                                    this.persistence_message =
                                        format!("Draft save failed: {error}");
                                }
                                cx.notify();
                            });
                        })
                        .detach();
                        cx.notify();
                    }
                }
            }),
            cx.subscribe_in(
                &steer_input,
                window,
                move |_, _, event: &InputEvent, _, cx| {
                    if matches!(event, InputEvent::Change) {
                        cx.notify();
                    }
                },
            ),
        ];
        let inspector_open = !session.plan.is_empty()
            || !session.process_activities.is_empty()
            || !session.file_changes.is_empty()
            || !session.subagents.is_empty();

        Self {
            session,
            session_store,
            recent_sessions,
            persistence_message,
            task_input,
            steer_input,
            active_run_id: 0,
            runtime_active: false,
            runtime_cancellation: None,
            runtime_steering: None,
            runtime_service,
            runtime_config,
            settings_open: false,
            settings_has_api_key,
            provider_input,
            model_input,
            base_url_input,
            api_key_input,
            last_run_was_demo: false,
            connection_test_active: false,
            connection_test_message: "Save settings, then test the provider connection.".into(),
            inspector_open,
            draft_revision: 0,
            _subscriptions,
        }
    }

    fn toggle_inspector(&mut self, _: &ClickEvent, _: &mut Window, cx: &mut Context<Self>) {
        self.inspector_open = !self.inspector_open;
        cx.notify();
    }

    fn persist(&mut self) {
        self.persistence_message = match self.save_session() {
            Ok(()) => "Session saved.".into(),
            Err(error) => format!("Save failed: {error}"),
        };
    }

    fn save_session(&mut self) -> std::io::Result<()> {
        self.session_store.save(&self.session)?;
        self.recent_sessions = self.session_store.list()?;
        Ok(())
    }

    fn replace_session(
        &mut self,
        session: WorkSessionSnapshot,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.inspector_open = !session.plan.is_empty()
            || !session.process_activities.is_empty()
            || !session.file_changes.is_empty()
            || !session.subagents.is_empty();
        self.session = session;
        let task = self.session.composer_draft.clone();
        self.task_input.update(cx, |input, cx| {
            input.set_value(task, window, cx);
        });
        self.last_run_was_demo = false;
        self.draft_revision = self.draft_revision.saturating_add(1);
        self.runtime_active = false;
        self.runtime_cancellation = None;
    }

    fn new_session(&mut self, _: &ClickEvent, window: &mut Window, cx: &mut Context<Self>) {
        if self.reject_if_runtime_busy(cx) {
            return;
        }
        if let Err(error) = self.save_session() {
            self.persistence_message = format!("Could not save the current session: {error}");
            cx.notify();
            return;
        }
        let workspace = self.session.workspace.clone();
        match self.session_store.create(workspace) {
            Ok(session) => {
                self.replace_session(session, window, cx);
                self.recent_sessions = self.session_store.list().unwrap_or_default();
                self.persistence_message = "Created a new Work session.".into();
            }
            Err(error) => self.persistence_message = format!("Could not create session: {error}"),
        }
        cx.notify();
    }

    fn open_session(&mut self, session_id: &str, window: &mut Window, cx: &mut Context<Self>) {
        if self.reject_if_runtime_busy(cx) || self.session.session_id == session_id {
            return;
        }
        if let Err(error) = self.save_session() {
            self.persistence_message = format!("Could not save the current session: {error}");
            cx.notify();
            return;
        }
        match self.session_store.open(session_id) {
            Ok(session) => {
                let interrupted = session.status == WorkStatus::Interrupted;
                self.replace_session(session, window, cx);
                self.recent_sessions = self.session_store.list().unwrap_or_default();
                self.persistence_message = if interrupted {
                    "Opened an interrupted session. Review it before retrying.".into()
                } else {
                    "Opened Work session.".into()
                };
            }
            Err(error) => self.persistence_message = format!("Could not open session: {error}"),
        }
        cx.notify();
    }

    fn choose_workspace(&mut self, _: &ClickEvent, window: &mut Window, cx: &mut Context<Self>) {
        if self.reject_if_runtime_busy(cx) {
            return;
        }
        let selection = cx.prompt_for_paths(PathPromptOptions {
            files: false,
            directories: true,
            multiple: false,
            prompt: Some("Select a MicroClaw Work workspace".into()),
        });
        let view = cx.entity();
        cx.spawn_in(window, async move |_, window| {
            let selected = match selection.await {
                Ok(Ok(Some(paths))) => Ok(paths.into_iter().next()),
                Ok(Ok(None)) => Ok(None),
                Ok(Err(error)) => Err(error.to_string()),
                Err(error) => Err(error.to_string()),
            };
            window
                .update(|_, cx| {
                    view.update(cx, |this, cx| {
                        match selected {
                            Ok(Some(path)) => {
                                match this.session.apply(WorkCommand::SetWorkspace {
                                    path: path.display().to_string(),
                                }) {
                                    Ok(_) => this.persist(),
                                    Err(error) => this.persistence_message = error.to_string(),
                                }
                            }
                            Ok(None) => {
                                this.persistence_message = "Workspace unchanged.".into();
                            }
                            Err(error) => {
                                this.persistence_message =
                                    format!("Could not open the workspace picker: {error}");
                            }
                        }
                        cx.notify();
                    });
                })
                .ok()
        })
        .detach();
    }

    fn refresh_runtime_config(&mut self, _: &ClickEvent, _: &mut Window, cx: &mut Context<Self>) {
        self.runtime_config = self.runtime_service.config_summary();
        self.persistence_message = if self.runtime_config.ready {
            "Runtime configuration refreshed.".into()
        } else {
            "Runtime configuration is incomplete.".into()
        };
        cx.notify();
    }

    fn open_model_settings(&mut self, _: &ClickEvent, window: &mut Window, cx: &mut Context<Self>) {
        if self.reject_if_runtime_busy(cx) {
            return;
        }
        if let Ok(settings) = self.runtime_service.model_settings() {
            self.provider_input.update(cx, |input, cx| {
                input.set_value(settings.provider, window, cx)
            });
            self.model_input
                .update(cx, |input, cx| input.set_value(settings.model, window, cx));
            self.base_url_input.update(cx, |input, cx| {
                input.set_value(settings.base_url, window, cx)
            });
            self.settings_has_api_key = settings.has_api_key;
        }
        self.api_key_input
            .update(cx, |input, cx| input.set_value("", window, cx));
        self.settings_open = true;
        cx.notify();
    }

    fn close_model_settings(&mut self, _: &ClickEvent, _: &mut Window, cx: &mut Context<Self>) {
        self.settings_open = false;
        cx.notify();
    }

    fn save_model_settings(&mut self, _: &ClickEvent, _: &mut Window, cx: &mut Context<Self>) {
        let api_key = self.api_key_input.read(cx).value().trim().to_string();
        let draft = ModelSettingsDraft {
            provider: self.provider_input.read(cx).value().to_string(),
            model: self.model_input.read(cx).value().to_string(),
            base_url: self.base_url_input.read(cx).value().to_string(),
            api_key: if api_key.is_empty() && self.settings_has_api_key {
                None
            } else {
                Some(api_key)
            },
        };
        match self.runtime_service.save_model_settings(draft) {
            Ok(settings) => {
                self.settings_has_api_key = settings.has_api_key;
                self.runtime_config = self.runtime_service.config_summary();
                self.persistence_message = "Model configuration saved for MicroClaw Work.".into();
                self.connection_test_message =
                    "Settings saved. Test the connection before starting work.".into();
            }
            Err(error) => {
                self.persistence_message = format!("Could not save model settings: {error}");
            }
        }
        cx.notify();
    }

    fn test_provider_connection(&mut self, _: &ClickEvent, _: &mut Window, cx: &mut Context<Self>) {
        if self.connection_test_active {
            return;
        }
        self.runtime_config = self.runtime_service.config_summary();
        if !self.runtime_config.ready {
            self.connection_test_message =
                "Save a complete model configuration before testing.".into();
            cx.notify();
            return;
        }
        self.connection_test_active = true;
        self.connection_test_message = format!(
            "Testing {} / {}…",
            self.runtime_config.provider, self.runtime_config.model
        );
        let receiver = self.runtime_service.test_provider_connection();
        cx.spawn(async move |this, cx| {
            loop {
                match receiver.try_recv() {
                    Ok(Ok(report)) => {
                        let _ = this.update(cx, |this, cx| {
                            this.connection_test_active = false;
                            this.connection_test_message = format!(
                                "Connected to {} / {} in {} ms. Response: {}",
                                report.provider,
                                report.model,
                                report.latency_ms,
                                report.response_preview
                            );
                            cx.notify();
                        });
                        break;
                    }
                    Ok(Err(error)) => {
                        let _ = this.update(cx, |this, cx| {
                            this.connection_test_active = false;
                            this.connection_test_message =
                                format!("Connection test failed: {error}");
                            cx.notify();
                        });
                        break;
                    }
                    Err(TryRecvError::Empty) => {
                        Timer::after(Duration::from_millis(50)).await;
                    }
                    Err(TryRecvError::Disconnected) => {
                        let _ = this.update(cx, |this, cx| {
                            this.connection_test_active = false;
                            this.connection_test_message =
                                "Connection test worker exited unexpectedly.".into();
                            cx.notify();
                        });
                        break;
                    }
                }
            }
        })
        .detach();
        cx.notify();
    }

    fn open_artifact(&mut self, path: &str, cx: &mut Context<Self>) {
        match self.session.resolve_artifact_path(path) {
            Ok(path) => match url::Url::from_file_path(&path) {
                Ok(url) => {
                    cx.open_url(url.as_str());
                    self.persistence_message = format!("Opened artifact: {}", path.display());
                }
                Err(()) => {
                    self.persistence_message =
                        format!("Could not create an artifact URL for {}", path.display());
                }
            },
            Err(error) => self.persistence_message = error.to_string(),
        }
        cx.notify();
    }

    fn select_file_change(&mut self, path: String, cx: &mut Context<Self>) {
        match self.session.apply(WorkCommand::SelectFileChange { path }) {
            Ok(_) => self.persist(),
            Err(error) => self.persistence_message = error.to_string(),
        }
        cx.notify();
    }

    fn accept_changes(&mut self, _: &ClickEvent, _: &mut Window, cx: &mut Context<Self>) {
        match self.session.apply(WorkCommand::AcceptChanges) {
            Ok(_) => {
                self.persistence_message = "Accepted the completed workspace changes.".into();
                self.persist();
            }
            Err(error) => self.persistence_message = error.to_string(),
        }
        cx.notify();
    }

    fn request_revert_changes(
        &mut self,
        _: &ClickEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.runtime_active || self.session.review_status != WorkReviewStatus::Pending {
            self.persistence_message = "No completed change set is awaiting review.".into();
            cx.notify();
            return;
        }
        let Some(commit) = self.session.baseline_checkpoint.clone() else {
            self.persistence_message = "No pre-task checkpoint is available.".into();
            cx.notify();
            return;
        };
        let confirmation = window.prompt(
            PromptLevel::Critical,
            "Revert this task's workspace changes?",
            Some("Tracked files return to the pre-task checkpoint. New non-ignored files created after it are removed. Ignored files and nested repositories are preserved."),
            &["Revert Changes", "Cancel"],
            cx,
        );
        let view = cx.entity();
        cx.spawn_in(window, async move |_, window| {
            let confirmed = matches!(confirmation.await, Ok(0));
            if !confirmed {
                return;
            }
            window
                .update(|_, cx| {
                    view.update(cx, |this, cx| {
                        if this.last_run_was_demo {
                            let _ = this.session.apply(WorkCommand::MarkReverted);
                            this.persistence_message = "Demo changes marked as reverted.".into();
                            this.persist();
                            cx.notify();
                            return;
                        }
                        let workspace = PathBuf::from(&this.session.workspace);
                        let receiver = this.runtime_service.restore_workspace(workspace, commit);
                        this.runtime_active = true;
                        this.persistence_message = "Restoring the pre-task checkpoint…".into();
                        cx.notify();
                        cx.spawn(async move |this, cx| {
                            loop {
                                match receiver.try_recv() {
                                    Ok(result) => {
                                        let _ = this.update(cx, |this, cx| {
                                            this.runtime_active = false;
                                            match result {
                                                Ok(()) => {
                                                    let _ = this
                                                        .session
                                                        .apply(WorkCommand::MarkReverted);
                                                    this.persistence_message =
                                                    "Restored the pre-task workspace checkpoint."
                                                        .into();
                                                    this.persist();
                                                }
                                                Err(error) => {
                                                    this.persistence_message = format!(
                                                        "Could not revert changes: {error}"
                                                    );
                                                }
                                            }
                                            cx.notify();
                                        });
                                        return;
                                    }
                                    Err(TryRecvError::Empty) => {
                                        Timer::after(Duration::from_millis(40)).await;
                                    }
                                    Err(TryRecvError::Disconnected) => {
                                        let _ = this.update(cx, |this, cx| {
                                            this.runtime_active = false;
                                            this.persistence_message =
                                                "The restore worker disconnected.".into();
                                            cx.notify();
                                        });
                                        return;
                                    }
                                }
                            }
                        })
                        .detach();
                    });
                })
                .ok();
        })
        .detach();
    }

    fn resolve_approval(&mut self, value: String, cx: &mut Context<Self>) {
        if !self.last_run_was_demo
            && (self.session.workspace.is_empty()
                || !PathBuf::from(&self.session.workspace).is_dir())
        {
            self.persistence_message = "Select an available workspace first.".into();
            cx.notify();
            return;
        }
        if let Err(error) = self.session.apply(WorkCommand::ResolveApproval {
            value: value.clone(),
        }) {
            self.persistence_message = error.to_string();
            cx.notify();
            return;
        }
        if self.last_run_was_demo {
            let run_id = self
                .session
                .runtime_run_id
                .clone()
                .unwrap_or_else(|| format!("demo-{}", self.active_run_id));
            let sequence = self.session.last_runtime_sequence.saturating_add(1);
            let completed_steps = self
                .session
                .plan
                .iter()
                .map(|step| microclaw_core::runtime_event::RuntimePlanStep {
                    title: step.title.clone(),
                    status: microclaw_core::runtime_event::RuntimePlanStepStatus::Completed,
                })
                .collect();
            let _ = self
                .session
                .apply(WorkCommand::ApplyRuntimeEvent(RuntimeEventEnvelope::new(
                    &run_id,
                    sequence,
                    RuntimeEvent::PlanUpdated {
                        steps: completed_steps,
                    },
                )));
            let _ = self
                .session
                .apply(WorkCommand::ApplyRuntimeEvent(RuntimeEventEnvelope::new(
                    run_id,
                    sequence.saturating_add(1),
                    RuntimeEvent::FinalResponse {
                        text: "Demo task completed with structured activity and artifacts.".into(),
                    },
                )));
        }
        self.persist();
        cx.notify();
        if !self.last_run_was_demo {
            self.launch_runtime_prompt(value, cx);
        }
    }

    fn start_runtime(&mut self, _: &ClickEvent, window: &mut Window, cx: &mut Context<Self>) {
        if self.reject_if_runtime_busy(cx) {
            return;
        }
        self.runtime_config = self.runtime_service.config_summary();
        if !self.runtime_config.ready {
            self.persistence_message = "Open Model Settings to configure the runtime.".into();
            cx.notify();
            return;
        }
        let retrying = matches!(
            self.session.status,
            WorkStatus::Interrupted | WorkStatus::Failed | WorkStatus::Cancelled
        ) && self.task_input.read(cx).value().trim().is_empty();
        let task = if retrying {
            self.session.task.clone()
        } else {
            self.task_input.read(cx).value().to_string()
        };
        let command = if retrying {
            WorkCommand::RetryTask
        } else {
            WorkCommand::StartTask { task: task.clone() }
        };
        if let Err(error) = self.session.apply(command) {
            self.persistence_message = error.to_string();
            cx.notify();
            return;
        }
        self.last_run_was_demo = false;
        self.task_input.update(cx, |input, cx| {
            input.set_value("", window, cx);
        });
        self.persist();
        self.launch_runtime_prompt(task, cx);
    }

    fn primary_action(&mut self, event: &ClickEvent, window: &mut Window, cx: &mut Context<Self>) {
        if self.runtime_active {
            self.send_steering(event, window, cx);
        } else {
            self.start_runtime(event, window, cx);
        }
    }

    fn send_steering(&mut self, _: &ClickEvent, window: &mut Window, cx: &mut Context<Self>) {
        let update = self.steer_input.read(cx).value().to_string();
        if self.last_run_was_demo {
            match self.session.apply(WorkCommand::RecordSteering {
                message: update.clone(),
            }) {
                Ok(_) => {
                    self.steer_input.update(cx, |input, cx| {
                        input.set_value("", window, cx);
                    });
                    self.persistence_message = "Demo Agent accepted the guidance.".into();
                    self.persist();
                }
                Err(error) => self.persistence_message = error.to_string(),
            }
            cx.notify();
            return;
        }
        let Some(steering) = &self.runtime_steering else {
            self.persistence_message = "The active runtime cannot receive updates.".into();
            cx.notify();
            return;
        };
        match steering.steer(&update) {
            Ok(()) => {
                self.steer_input.update(cx, |input, cx| {
                    input.set_value("", window, cx);
                });
                self.persistence_message = "Sending guidance to the active Agent…".into();
            }
            Err(message) => self.persistence_message = message.into(),
        }
        cx.notify();
    }

    fn launch_runtime_prompt(&mut self, prompt: String, cx: &mut Context<Self>) {
        self.active_run_id = self.active_run_id.saturating_add(1);
        self.runtime_active = true;
        let generation = self.active_run_id;
        let handle = self.runtime_service.start(WorkRunRequest {
            task: prompt,
            workspace: self.session.workspace.clone(),
            session: self.session.session_id.clone(),
        });
        let receiver = handle.messages;
        self.runtime_cancellation = Some(handle.cancellation);
        self.runtime_steering = Some(handle.steering);
        self.persistence_message = "Connecting to the MicroClaw runtime…".into();
        cx.notify();

        cx.spawn(async move |this, cx| {
            loop {
                match receiver.try_recv() {
                    Ok(message) => {
                        let terminal = matches!(
                            &message,
                            WorkRuntimeMessage::Completed { .. }
                                | WorkRuntimeMessage::Failed { .. }
                        );
                        if this
                            .update(cx, |this, cx| {
                                if this.active_run_id != generation {
                                    return;
                                }
                                match message {
                                    WorkRuntimeMessage::Envelope(envelope) => {
                                        if let Err(error) = this
                                            .session
                                            .apply(WorkCommand::ApplyRuntimeEvent(envelope))
                                        {
                                            this.persistence_message = error.to_string();
                                        }
                                    }
                                    WorkRuntimeMessage::SteeringResult {
                                        run_id,
                                        accepted,
                                        message,
                                    } => {
                                        if accepted {
                                            if let Err(error) =
                                                this.session.apply(WorkCommand::RecordSteering {
                                                    message: message.clone(),
                                                })
                                            {
                                                this.persistence_message = error.to_string();
                                            } else {
                                                this.persistence_message = format!(
                                                    "Runtime {run_id} accepted the guidance."
                                                );
                                            }
                                        } else {
                                            this.persistence_message = format!(
                                                "Runtime {run_id} rejected the guidance: {message}"
                                            );
                                        }
                                    }
                                    WorkRuntimeMessage::Completed { run_id } => {
                                        this.runtime_active = false;
                                        this.runtime_cancellation = None;
                                        this.runtime_steering = None;
                                        this.persistence_message = match this.session.status {
                                            WorkStatus::AwaitingApproval => {
                                                format!("Runtime {run_id} paused for approval.")
                                            }
                                            WorkStatus::Cancelled => {
                                                format!("Runtime {run_id} stopped.")
                                            }
                                            _ => format!("Runtime {run_id} completed."),
                                        };
                                    }
                                    WorkRuntimeMessage::Failed { run_id, message } => {
                                        this.runtime_active = false;
                                        this.runtime_cancellation = None;
                                        this.runtime_steering = None;
                                        let display = format!("Runtime {run_id} failed: {message}");
                                        let _ = this.session.apply(WorkCommand::FailRun {
                                            message: message.clone(),
                                        });
                                        this.persistence_message = display;
                                    }
                                }
                                if let Err(error) = this.save_session() {
                                    this.persistence_message = format!("Save failed: {error}");
                                }
                                cx.notify();
                            })
                            .is_err()
                        {
                            return;
                        }
                        if terminal {
                            return;
                        }
                    }
                    Err(TryRecvError::Empty) => {
                        Timer::after(Duration::from_millis(40)).await;
                    }
                    Err(TryRecvError::Disconnected) => {
                        let _ = this.update(cx, |this, cx| {
                            if this.active_run_id != generation || !this.runtime_active {
                                return;
                            }
                            this.runtime_active = false;
                            this.runtime_cancellation = None;
                            this.runtime_steering = None;
                            let message = "The runtime message channel disconnected.".to_string();
                            let _ = this.session.apply(WorkCommand::FailRun {
                                message: message.clone(),
                            });
                            this.persistence_message = message;
                            if let Err(error) = this.save_session() {
                                this.persistence_message = format!("Save failed: {error}");
                            }
                            cx.notify();
                        });
                        return;
                    }
                }
            }
        })
        .detach();
    }

    fn stop_runtime(&mut self, _: &ClickEvent, _: &mut Window, cx: &mut Context<Self>) {
        if !self.runtime_active {
            if self.session.status == WorkStatus::AwaitingApproval {
                if let Err(error) = self.session.apply(WorkCommand::CancelRun) {
                    self.persistence_message = error.to_string();
                } else {
                    self.persistence_message = "Cancelled the task awaiting approval.".into();
                    self.persist();
                }
            } else {
                self.persistence_message = "No task is running or awaiting approval.".into();
            }
            cx.notify();
            return;
        }

        if self.last_run_was_demo {
            self.active_run_id = self.active_run_id.saturating_add(1);
            self.runtime_active = false;
            self.runtime_cancellation = None;
            self.runtime_steering = None;
        } else if let Some(cancellation) = &self.runtime_cancellation
            && let Err(message) = cancellation.cancel()
        {
            self.persistence_message = message.into();
            cx.notify();
            return;
        }

        if let Err(error) = self.session.apply(WorkCommand::CancelRun) {
            self.persistence_message = error.to_string();
        } else {
            self.persistence_message = "Stop requested. Waiting for the runtime to exit…".into();
        }
        self.persist();
        cx.notify();
    }

    fn start_demo(&mut self, _: &ClickEvent, window: &mut Window, cx: &mut Context<Self>) {
        if self.reject_if_runtime_busy(cx) {
            return;
        }
        if self.task_input.read(cx).value().trim().is_empty() {
            let task = "Build a native desktop workflow for MicroClaw Work".to_string();
            self.task_input.update(cx, |input, cx| {
                input.set_value(task, window, cx);
            });
        }
        let task = self.task_input.read(cx).value().to_string();
        if let Err(error) = self.session.apply(WorkCommand::StartTask { task }) {
            self.persistence_message = error.to_string();
            cx.notify();
            return;
        }

        self.active_run_id += 1;
        self.runtime_active = true;
        self.last_run_was_demo = true;
        self.task_input.update(cx, |input, cx| {
            input.set_value("", window, cx);
        });
        let run_id = self.active_run_id;
        self.persist();
        cx.notify();

        cx.spawn(async move |this, cx| {
            let events = [
                (WorkEventKind::Plan, "Analyzing the workspace and task"),
                (
                    WorkEventKind::Tool,
                    "Reading the Cargo workspace and desktop code",
                ),
                (WorkEventKind::Tool, "Preparing the Work projection update"),
            ];

            for (kind, message) in events {
                Timer::after(Duration::from_millis(1_500)).await;
                let result = this.update(cx, |this, cx| {
                    if this.active_run_id != run_id {
                        return;
                    }
                    let _ = this.session.apply(WorkCommand::RecordProgress {
                        kind,
                        message: message.into(),
                        completed_step: None,
                    });
                    this.persist();
                    cx.notify();
                });
                if result.is_err() {
                    return;
                }
            }

            Timer::after(Duration::from_millis(1_500)).await;
            let _ = this.update(cx, |this, cx| {
                if this.active_run_id != run_id {
                    return;
                }
                let demo_runtime_id = format!("demo-{run_id}");
                let structured_events = [
                    RuntimeEvent::PlanUpdated {
                        steps: vec![
                            microclaw_core::runtime_event::RuntimePlanStep {
                                title: "Inspect the workspace and task".into(),
                                status: microclaw_core::runtime_event::RuntimePlanStepStatus::Completed,
                            },
                            microclaw_core::runtime_event::RuntimePlanStep {
                                title: "Build the GPUI workflow".into(),
                                status: microclaw_core::runtime_event::RuntimePlanStepStatus::InProgress,
                            },
                            microclaw_core::runtime_event::RuntimePlanStep {
                                title: "Review workspace changes".into(),
                                status: microclaw_core::runtime_event::RuntimePlanStepStatus::Pending,
                            },
                            microclaw_core::runtime_event::RuntimePlanStep {
                                title: "Verify and deliver results".into(),
                                status: microclaw_core::runtime_event::RuntimePlanStepStatus::Pending,
                            },
                        ],
                    },
                    RuntimeEvent::CheckpointCreated {
                        commit: "deadbeef".into(),
                        label: "demo pre-task checkpoint".into(),
                    },
                    RuntimeEvent::ToolStart {
                        call_id: "demo-read".into(),
                        name: "read_file".into(),
                        input: serde_json::json!({"path": "Cargo.toml"}),
                    },
                    RuntimeEvent::ToolResult {
                        call_id: "demo-read".into(),
                        name: "read_file".into(),
                        is_error: false,
                        preview: "Read the Cargo workspace configuration".into(),
                        duration_ms: 18,
                        status_code: None,
                        bytes: 2048,
                        error_type: None,
                    },
                    RuntimeEvent::ProcessOutput {
                        call_id: "demo-check".into(),
                        command: "cargo check -p microclaw-work".into(),
                        output: "Checking microclaw-work\nFinished dev profile".into(),
                        exit_code: Some(0),
                        duration_ms: 842,
                        truncated: false,
                        kind: microclaw_core::runtime_event::RuntimeProcessKind::Verification,
                    },
                    RuntimeEvent::FileDiff {
                        path: "demo-output.md".into(),
                        diff: "+# MicroClaw Work demo artifact\n+Structured runtime projection verified."
                            .into(),
                        added: 2,
                        removed: 0,
                        truncated: false,
                    },
                    RuntimeEvent::FileDiff {
                        path: "src/work.rs".into(),
                        diff: "@@ -1,3 +1,4 @@\n pub struct WorkTask {\n-    pub prompt: String,\n+    pub conversation: Vec<Message>,\n+    pub composer_draft: String,\n }"
                            .into(),
                        added: 2,
                        removed: 1,
                        truncated: false,
                    },
                ];
                for (index, event) in structured_events.into_iter().enumerate() {
                    let _ = this.session.apply(WorkCommand::ApplyRuntimeEvent(
                        RuntimeEventEnvelope::new(
                            &demo_runtime_id,
                            index as u64 + 1,
                            event,
                        ),
                    ));
                }
                let _ = this.session.apply(WorkCommand::RequestApproval {
                    reason: "Allow the demo to write to the workspace and run checks".into(),
                });
                this.runtime_active = false;
                this.persist();
                cx.notify();
            });
        })
        .detach();
    }

    fn render_model_settings(&self, cx: &mut Context<Self>) -> impl IntoElement {
        v_flex()
            .size_full()
            .bg(cx.theme().background)
            .text_color(cx.theme().foreground)
            .p_8()
            .gap_5()
            .child(
                h_flex()
                    .justify_between()
                    .items_center()
                    .child(
                        v_flex()
                            .gap_1()
                            .child(div().text_2xl().font_bold().child("Model Settings"))
                            .child(
                                div()
                                    .text_sm()
                                    .text_color(cx.theme().muted_foreground)
                                    .child("Configure the model used by this Work installation."),
                            ),
                    )
                    .child(
                        Button::new("close-model-settings")
                            .outline()
                            .disabled(self.connection_test_active)
                            .label("Back to Work")
                            .on_click(cx.listener(Self::close_model_settings)),
                    ),
            )
            .child(
                v_flex()
                    .w(px(680.))
                    .gap_4()
                    .p_5()
                    .rounded(cx.theme().radius)
                    .border_1()
                    .border_color(cx.theme().border)
                    .child(div().text_sm().font_bold().child("Provider"))
                    .child(Input::new(&self.provider_input))
                    .child(div().text_sm().font_bold().child("Model ID"))
                    .child(Input::new(&self.model_input))
                    .child(div().text_sm().font_bold().child("Base URL (optional)"))
                    .child(Input::new(&self.base_url_input).content_type(InputContentType::Url))
                    .child(div().text_sm().font_bold().child("API key"))
                    .child(
                        Input::new(&self.api_key_input)
                            .content_type(InputContentType::Password)
                            .mask_toggle(),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(cx.theme().muted_foreground)
                            .child(if self.settings_has_api_key {
                                "A key is already saved. Leave this field blank to keep it."
                            } else {
                                "Ollama and account-authenticated providers may not require a key."
                            }),
                    )
                    .child(
                        h_flex()
                            .gap_3()
                            .child(
                                Button::new("save-model-settings")
                                    .primary()
                                    .disabled(self.connection_test_active)
                                    .label("Save Model Settings")
                                    .on_click(cx.listener(Self::save_model_settings)),
                            )
                            .child(
                                Button::new("test-provider-connection")
                                    .outline()
                                    .disabled(
                                        self.connection_test_active || !self.runtime_config.ready,
                                    )
                                    .label(if self.connection_test_active {
                                        "Testing…"
                                    } else {
                                        "Test Connection"
                                    })
                                    .on_click(cx.listener(Self::test_provider_connection)),
                            ),
                    ),
            )
            .child(
                div()
                    .text_sm()
                    .text_color(if self.connection_test_message.starts_with("Connected") {
                        cx.theme().success
                    } else if self.connection_test_message.contains("failed") {
                        cx.theme().danger
                    } else {
                        cx.theme().muted_foreground
                    })
                    .child(self.connection_test_message.clone()),
            )
            .child(div().text_sm().child(self.persistence_message.clone()))
            .child(
                div()
                    .text_xs()
                    .text_color(cx.theme().muted_foreground)
                    .child(format!(
                        "Configuration file: {}",
                        self.runtime_service.config_path().display()
                    )),
            )
    }
}

impl Render for WorkApp {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        if self.settings_open {
            return self.render_model_settings(cx).into_any_element();
        }
        let conversation_is_empty = self.session.messages.is_empty()
            && self.session.task.trim().is_empty()
            && self.session.assistant_draft.is_empty();
        let status = if conversation_is_empty {
            "Ready"
        } else {
            match self.session.status {
                WorkStatus::Planning => "Planning",
                WorkStatus::Running => "Running",
                WorkStatus::AwaitingApproval => "Awaiting approval",
                WorkStatus::Verifying => "Verifying",
                WorkStatus::Completed => "Completed",
                WorkStatus::Cancelled => "Cancelled",
                WorkStatus::Failed => "Failed",
                WorkStatus::Interrupted => "Interrupted",
            }
        };
        let recent_sessions = self.recent_sessions.clone();
        let process_activities = self.session.process_activities.clone();
        let file_changes = self.session.file_changes.clone();
        let subagents = self.session.subagents.clone();
        let has_inspector_content = !self.session.plan.is_empty()
            || !process_activities.is_empty()
            || !file_changes.is_empty()
            || !subagents.is_empty();
        let selected_file_change = self.session.selected_file_change().cloned();
        let review_status = self.session.review_status;
        let inline_approval = self.session.pending_approval.clone();
        let messages = self.session.messages.clone();
        let assistant_draft = self.session.assistant_draft.clone();
        let retryable = matches!(
            self.session.status,
            WorkStatus::Interrupted | WorkStatus::Failed | WorkStatus::Cancelled
        );
        let composer_input = if self.runtime_active {
            &self.steer_input
        } else {
            &self.task_input
        };

        h_flex()
            .size_full()
            .bg(cx.theme().background)
            .text_color(cx.theme().foreground)
            .child(
                v_flex()
                    .w(px(260.))
                    .h_full()
                    .p_4()
                    .gap_3()
                    .border_r_1()
                    .border_color(cx.theme().border)
                    .child(div().text_xl().font_bold().child("MicroClaw Work"))
                    .child(
                        Button::new("new-session")
                            .primary()
                            .disabled(self.runtime_active)
                            .label("New Chat")
                            .on_click(cx.listener(Self::new_session)),
                    )
                    .child(
                        div()
                            .mt_3()
                            .text_sm()
                            .text_color(cx.theme().muted_foreground)
                            .child("Chats"),
                    )
                    .children(recent_sessions.into_iter().take(6).map(|summary| {
                        let session_id = summary.session_id.clone();
                        let is_active = session_id == self.session.session_id;
                        let title = if summary.task.trim().is_empty() {
                            "New conversation".to_string()
                        } else {
                            summary.task.chars().take(42).collect()
                        };
                        let summary_status = if summary.task.trim().is_empty() {
                            "Ready"
                        } else {
                            work_status_label(summary.status)
                        };
                        let label = format!("{title} · {summary_status}");
                        Button::new(format!("session-{session_id}"))
                            .outline()
                            .disabled(self.runtime_active || is_active)
                            .label(label)
                            .on_click(cx.listener(move |this, _, window, cx| {
                                this.open_session(&session_id, window, cx);
                            }))
                    }))
                    .child(
                        v_flex()
                            .mt_auto()
                            .gap_2()
                            .pt_3()
                            .border_t_1()
                            .border_color(cx.theme().border)
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(cx.theme().muted_foreground)
                                    .child("Workspace"),
                            )
                            .child(div().text_sm().child(if self.session.workspace.is_empty() {
                                "No folder selected".to_string()
                            } else {
                                self.session.workspace.clone()
                            }))
                            .child(
                                Button::new("choose-workspace")
                                    .outline()
                                    .disabled(self.runtime_active)
                                    .label(if self.session.workspace.is_empty() {
                                        "Choose Folder"
                                    } else {
                                        "Change Folder"
                                    })
                                    .on_click(cx.listener(Self::choose_workspace)),
                            )
                            .child(
                                h_flex()
                                    .gap_2()
                                    .child(
                                        Button::new("model-settings")
                                            .outline()
                                            .disabled(self.runtime_active)
                                            .label("Model")
                                            .on_click(cx.listener(Self::open_model_settings)),
                                    )
                                    .child(
                                        Button::new("refresh-config")
                                            .outline()
                                            .label("Refresh")
                                            .on_click(cx.listener(Self::refresh_runtime_config)),
                                    ),
                            )
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(cx.theme().muted_foreground)
                                    .child(format!(
                                        "{} · {}",
                                        self.runtime_config.provider, self.runtime_config.model
                                    )),
                            )
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(cx.theme().muted_foreground)
                                    .child(self.persistence_message.clone()),
                            ),
                    ),
            )
            .child(
                v_flex()
                    .flex_1()
                    .min_w_0()
                    .h_full()
                    .p_5()
                    .gap_3()
                    .child(
                        h_flex()
                            .items_center()
                            .justify_between()
                            .child(
                                v_flex()
                                    .gap_1()
                                    .child(div().text_xl().font_bold().child(
                                        if self.session.title.trim().is_empty() {
                                            "New conversation".to_string()
                                        } else {
                                            trim_text(&self.session.title, 72)
                                        },
                                    ))
                                    .child(div().text_sm().text_color(cx.theme().muted_foreground).child(
                                        if self.session.workspace.is_empty() {
                                            "Choose a folder when this conversation needs local files".to_string()
                                        } else {
                                            format!("Working in {}", self.session.workspace)
                                        },
                                    )),
                            )
                            .child(
                                h_flex()
                                    .gap_2()
                                    .child(
                                        div()
                                            .px_3()
                                            .py_1()
                                            .rounded_full()
                                            .bg(cx.theme().warning.opacity(0.18))
                                            .child(status),
                                    )
                                    .children(has_inspector_content.then(|| {
                                        Button::new("toggle-inspector")
                                            .outline()
                                            .label(if self.inspector_open {
                                                "Hide Details"
                                            } else {
                                                "Show Details"
                                            })
                                            .on_click(cx.listener(Self::toggle_inspector))
                                    })),
                            ),
                    )
                    .child(
                        h_flex()
                            .flex_1()
                            .min_h_0()
                            .gap_4()
                            .child(
                                v_flex()
                                    .flex_1()
                                    .min_h_0()
                                    .overflow_y_scrollbar()
                                    .gap_4()
                                    .px_5()
                                    .py_4()
                                    .children(messages.is_empty().then(|| {
                                        v_flex()
                                            .flex_1()
                                            .items_center()
                                            .justify_center()
                                            .gap_3()
                                            .p_8()
                                            .child(
                                                div()
                                                    .text_2xl()
                                                    .font_bold()
                                                    .child("What would you like to get done?"),
                                            )
                                            .child(
                                                div()
                                                    .max_w(px(560.))
                                                    .text_center()
                                                    .text_color(cx.theme().muted_foreground)
                                                    .child("Ask MicroClaw to research, create, organize, or automate work across your files and tools."),
                                            )
                                            .children(self.session.workspace.is_empty().then(|| {
                                                Button::new("empty-choose-workspace")
                                                    .outline()
                                                    .disabled(self.runtime_active)
                                                    .label("Connect a Folder")
                                                    .on_click(cx.listener(Self::choose_workspace))
                                            }))
                                    }))
                                    .children(messages.into_iter().map(|message| {
                                        let is_user = message.role == ConversationRole::User;
                                        let row = h_flex().w_full();
                                        let row = if is_user { row.justify_end() } else { row };
                                        row.child(
                                                v_flex()
                                                    .max_w(px(if is_user { 620. } else { 760. }))
                                                    .gap_1()
                                                    .p_3()
                                                    .rounded(cx.theme().radius)
                                                    .bg(if is_user { cx.theme().accent } else { cx.theme().background })
                                                    .child(div().text_xs().font_bold().child(if is_user {
                                                        "You"
                                                    } else {
                                                        "MicroClaw"
                                                    }))
                                                    .child(message.content),
                                            )
                                    }))
                                    .children((!assistant_draft.is_empty()).then(|| {
                                        v_flex()
                                            .max_w(px(720.))
                                            .gap_1()
                                            .p_3()
                                            .rounded(cx.theme().radius)
                                            .bg(cx.theme().secondary)
                                            .child(div().text_xs().font_bold().child(match self.session.status {
                                                WorkStatus::Interrupted => "MicroClaw · interrupted",
                                                WorkStatus::Failed => "MicroClaw · failed",
                                                WorkStatus::Cancelled => "MicroClaw · cancelled",
                                                _ => "MicroClaw · working",
                                            }))
                                            .child(assistant_draft)
                                    }))
                                    .children(inline_approval.map(|approval| {
                                        v_flex()
                                            .gap_3()
                                            .p_4()
                                            .rounded(cx.theme().radius)
                                            .border_1()
                                            .border_color(cx.theme().warning)
                                            .bg(cx.theme().warning.opacity(0.08))
                                            .child(div().text_sm().font_bold().child(format!(
                                                "Approval required · {}",
                                                approval.tool
                                            )))
                                            .child(approval.reason)
                                            .children(approval.advisory.map(|advisory| {
                                                div()
                                                    .text_sm()
                                                    .text_color(cx.theme().muted_foreground)
                                                    .child(advisory)
                                            }))
                                            .child(h_flex().gap_2().children(
                                                approval.options.into_iter().map(|option| {
                                                    let value = option.value.clone();
                                                    let button = Button::new(format!(
                                                        "inline-approval-{}-{value}",
                                                        self.session.session_id
                                                    ))
                                                    .disabled(
                                                        self.session.status
                                                            != WorkStatus::AwaitingApproval,
                                                    )
                                                    .label(option.label);
                                                    let button = match option.kind {
                                                        microclaw_core::runtime_event::RuntimeApprovalOptionKind::Primary => button.primary(),
                                                        microclaw_core::runtime_event::RuntimeApprovalOptionKind::Secondary => button.secondary(),
                                                        microclaw_core::runtime_event::RuntimeApprovalOptionKind::Danger => button.danger(),
                                                    };
                                                    button.on_click(cx.listener(
                                                        move |this, _, _, cx| {
                                                            this.resolve_approval(
                                                                value.clone(),
                                                                cx,
                                                            );
                                                        },
                                                    ))
                                                }),
                                            ))
                                    })),
                            )
                            .children((self.inspector_open && has_inspector_content).then(|| {
                                v_flex()
                                    .w(px(360.))
                                    .h_full()
                                    .min_h_0()
                                    .overflow_y_scrollbar()
                                    .gap_3()
                                    .child(
                                        v_flex()
                                            .gap_3()
                                            .p_4()
                                            .rounded(cx.theme().radius)
                                            .border_1()
                                            .border_color(cx.theme().border)
                                            .child(div().text_lg().font_bold().child("Plan"))
                                            .children((self.session.plan.is_empty()).then(|| {
                                                div()
                                                    .text_sm()
                                                    .text_color(cx.theme().muted_foreground)
                                                    .child("No plan published yet.")
                                            }))
                                            .children(self.session.plan.iter().enumerate().map(
                                                |(index, step)| {
                                                    let marker = match step.status {
                                                        microclaw_core::runtime_event::RuntimePlanStepStatus::Completed => "✓",
                                                        microclaw_core::runtime_event::RuntimePlanStepStatus::InProgress => "●",
                                                        microclaw_core::runtime_event::RuntimePlanStepStatus::Pending => "○",
                                                    };
                                                    h_flex().gap_2().text_sm().child(marker).child(
                                                        format!("{}. {}", index + 1, step.title),
                                                    )
                                                },
                                            )),
                                    )
                                    .children((!subagents.is_empty()).then(|| {
                                        v_flex()
                                            .gap_3()
                                            .p_4()
                                            .rounded(cx.theme().radius)
                                            .border_1()
                                            .border_color(cx.theme().border)
                                            .child(div().text_lg().font_bold().child("Agents"))
                                            .children(subagents.into_iter().map(|agent| {
                                                h_flex()
                                                    .items_center()
                                                    .justify_between()
                                                    .gap_3()
                                                    .child(
                                                        v_flex()
                                                            .gap_1()
                                                            .child(
                                                                div()
                                                                    .text_sm()
                                                                    .font_bold()
                                                                    .child(agent.label),
                                                            )
                                                            .child(
                                                                div()
                                                                    .text_xs()
                                                                    .text_color(
                                                                        cx.theme()
                                                                            .muted_foreground,
                                                                    )
                                                                    .child(trim_text(
                                                                        &agent.run_id,
                                                                        28,
                                                                    )),
                                                            ),
                                                    )
                                                    .child(
                                                        div()
                                                            .px_2()
                                                            .py_1()
                                                            .rounded_full()
                                                            .bg(cx.theme().accent)
                                                            .text_xs()
                                                            .child(agent.status),
                                                    )
                                            }))
                                    }))
                                    .child(
                                        v_flex()
                                            .gap_3()
                                            .p_4()
                                            .rounded(cx.theme().radius)
                                            .border_1()
                                            .border_color(cx.theme().border)
                                            .child(
                                                div()
                                                    .text_lg()
                                                    .font_bold()
                                                    .child("Verification / Process Output"),
                                            )
                                            .children((process_activities.is_empty()).then(|| {
                                                div()
                                                    .text_sm()
                                                    .text_color(cx.theme().muted_foreground)
                                                    .child("No command output yet.")
                                            }))
                                            .children(process_activities.into_iter().rev().take(3).map(
                                                |activity| {
                                                    let category = match activity.kind {
                                                        microclaw_core::runtime_event::RuntimeProcessKind::Command => "Command",
                                                        microclaw_core::runtime_event::RuntimeProcessKind::Verification => "Verification",
                                                    };
                                                    let exit = activity
                                                        .exit_code
                                                        .map_or_else(|| "—".into(), |code| code.to_string());
                                                    v_flex()
                                                        .gap_1()
                                                        .pt_2()
                                                        .border_t_1()
                                                        .border_color(cx.theme().border)
                                                        .child(div().text_sm().font_bold().child(format!(
                                                            "{category} · exit {exit} · {} ms{}",
                                                            activity.duration_ms,
                                                            if activity.truncated { " · truncated" } else { "" }
                                                        )))
                                                        .child(div().font_family("monospace").text_xs().child(
                                                            format!(
                                                                "$ {}\n{}",
                                                                trim_text(&activity.command, 220),
                                                                trim_text(&activity.output, 1_200)
                                                            ),
                                                        ))
                                                },
                                            )),
                                    )
                                    .child(
                                        v_flex()
                                            .gap_3()
                                            .p_4()
                                            .rounded(cx.theme().radius)
                                            .border_1()
                                            .border_color(cx.theme().border)
                                            .child(
                                                div()
                                                    .text_lg()
                                                    .font_bold()
                                                    .child("Changes / Artifacts"),
                                            )
                                            .children(file_changes.iter().map(|change| {
                                                let path = change.path.clone();
                                                let selected = selected_file_change
                                                    .as_ref()
                                                    .is_some_and(|selected| selected.path == path);
                                                let button = Button::new(format!("change-{path}"))
                                                    .w_full()
                                                    .label(format!(
                                                        "{}  +{} -{}{}",
                                                        change.path,
                                                        change.added,
                                                        change.removed,
                                                        if change.truncated { " · truncated" } else { "" }
                                                    ));
                                                let button = if selected {
                                                    button.primary()
                                                } else {
                                                    button.outline()
                                                };
                                                button.on_click(cx.listener(move |this, _, _, cx| {
                                                    this.select_file_change(path.clone(), cx);
                                                }))
                                            }))
                                            .children(selected_file_change.clone().map(|change| {
                                                v_flex()
                                                    .gap_2()
                                                    .pt_2()
                                                    .border_t_1()
                                                    .border_color(cx.theme().border)
                                                    .child(
                                                        h_flex()
                                                            .items_center()
                                                            .justify_between()
                                                            .child(div().text_sm().font_bold().child(change.path.clone()))
                                                            .child(
                                                                Button::new("open-selected-artifact")
                                                                    .outline()
                                                                    .label("Open File")
                                                                    .on_click(cx.listener({
                                                                        let path = change.path.clone();
                                                                        move |this, _, _, cx| {
                                                                            this.open_artifact(&path, cx);
                                                                        }
                                                                    })),
                                                            ),
                                                    )
                                                    .child(
                                                        v_flex()
                                                            .max_h(px(320.))
                                                            .overflow_y_scrollbar()
                                                            .rounded(cx.theme().radius)
                                                            .border_1()
                                                            .border_color(cx.theme().border)
                                                            .font_family("monospace")
                                                            .text_xs()
                                                            .children(change.diff.lines().map(str::to_owned).map(|line| {
                                                                let background = if line.starts_with('+')
                                                                    && !line.starts_with("+++")
                                                                {
                                                                    cx.theme().success.opacity(0.12)
                                                                } else if line.starts_with('-')
                                                                    && !line.starts_with("---")
                                                                {
                                                                    cx.theme().danger.opacity(0.12)
                                                                } else {
                                                                    cx.theme().background
                                                                };
                                                                div()
                                                                    .px_2()
                                                                    .py_1()
                                                                    .bg(background)
                                                                    .child(if line.is_empty() { " ".into() } else { line })
                                                            })),
                                                    )
                                            }))
                                            .children(file_changes.is_empty().then(|| {
                                                div()
                                                    .text_sm()
                                                    .text_color(cx.theme().muted_foreground)
                                                    .child("No workspace changes yet.")
                                            }))
                                            .child(
                                                v_flex()
                                                    .gap_2()
                                                    .child(
                                                        div()
                                                            .text_sm()
                                                            .font_bold()
                                                            .child("Review"),
                                                    )
                                                    .child(match review_status {
                                                        WorkReviewStatus::None => {
                                                            "No change review is pending."
                                                        }
                                                        WorkReviewStatus::Pending => {
                                                            "Accept these changes or restore the pre-task checkpoint."
                                                        }
                                                        WorkReviewStatus::Accepted => {
                                                            "Changes accepted."
                                                        }
                                                        WorkReviewStatus::Reverted => {
                                                            "Changes reverted."
                                                        }
                                                    })
                                                    .child(
                                                        v_flex()
                                                            .gap_2()
                                                            .child(
                                                                Button::new("accept-changes")
                                                                    .primary()
                                                                    .disabled(
                                                                        review_status
                                                                            != WorkReviewStatus::Pending
                                                                            || self.runtime_active,
                                                                    )
                                                                    .label("Accept Changes")
                                                                    .on_click(cx.listener(
                                                                        Self::accept_changes,
                                                                    )),
                                                            )
                                                            .child(
                                                                Button::new("revert-changes")
                                                                    .outline()
                                                                    .disabled(
                                                                        review_status
                                                                            != WorkReviewStatus::Pending
                                                                            || self.runtime_active,
                                                                    )
                                                                    .label("Revert Changes")
                                                                    .on_click(cx.listener(
                                                                        Self::request_revert_changes,
                                                                    )),
                                                            ),
                                                    ),
                                            ),
                                    )
                            })),
                    )
                    .child(
                        v_flex()
                            .gap_2()
                            .p_3()
                            .rounded(cx.theme().radius)
                            .border_1()
                            .border_color(cx.theme().border)
                            .child(
                                div()
                                    .min_h(px(44.))
                                    .child(Input::new(composer_input)),
                            )
                            .child(
                                h_flex()
                                    .items_center()
                                    .justify_between()
                                    .child(
                                        h_flex()
                                            .gap_2()
                                            .child(
                                                div()
                                                    .px_2()
                                                    .py_1()
                                                    .rounded_full()
                                                    .bg(cx.theme().accent)
                                                    .text_xs()
                                                    .child(if self.session.workspace.is_empty() {
                                                        "No folder"
                                                    } else {
                                                        "Folder connected"
                                                    }),
                                            )
                                            .child(
                                                div()
                                                    .px_2()
                                                    .py_1()
                                                    .rounded_full()
                                                    .bg(cx.theme().accent)
                                                    .text_xs()
                                                    .child(format!(
                                                        "{} / {}",
                                                        self.runtime_config.provider,
                                                        self.runtime_config.model
                                                    )),
                                            ),
                                    )
                                    .child(
                                        h_flex()
                                            .gap_2()
                                            .child(
                                                Button::new("run-demo")
                                                    .outline()
                                                    .disabled(self.runtime_active)
                                                    .label("Try Demo")
                                                    .on_click(cx.listener(Self::start_demo)),
                                            )
                                            .child(
                                                Button::new("stop-runtime")
                                                    .outline()
                                                    .disabled(
                                                        !self.runtime_active
                                                            && self.session.status
                                                                != WorkStatus::AwaitingApproval,
                                                    )
                                                    .label("Stop")
                                                    .on_click(cx.listener(Self::stop_runtime)),
                                            )
                                            .child(
                                                Button::new("run-runtime")
                                                    .primary()
                                                    .disabled(if self.runtime_active {
                                                        self.steer_input
                                                            .read(cx)
                                                            .value()
                                                            .trim()
                                                            .is_empty()
                                                    } else {
                                                        (!retryable
                                                            && self
                                                                .task_input
                                                                .read(cx)
                                                                .value()
                                                                .trim()
                                                                .is_empty())
                                                            || !self.runtime_config.ready
                                                            || self.session.workspace.is_empty()
                                                    })
                                                    .label(if self.runtime_active {
                                                        "Send Update"
                                                    } else if self.session.status
                                                        == WorkStatus::Completed
                                                    {
                                                        "Continue"
                                                    } else if retryable
                                                        && self
                                                            .task_input
                                                            .read(cx)
                                                            .value()
                                                            .trim()
                                                            .is_empty()
                                                    {
                                                        "Retry"
                                                    } else {
                                                        "Send"
                                                    })
                                                    .on_click(cx.listener(Self::primary_action)),
                                            ),
                                    )
                            ),
                    ),
            )
            .into_any_element()
    }
}

fn work_status_label(status: WorkStatus) -> &'static str {
    match status {
        WorkStatus::Planning => "Planning",
        WorkStatus::Running => "Running",
        WorkStatus::AwaitingApproval => "Awaiting approval",
        WorkStatus::Verifying => "Verifying",
        WorkStatus::Completed => "Completed",
        WorkStatus::Cancelled => "Cancelled",
        WorkStatus::Failed => "Failed",
        WorkStatus::Interrupted => "Interrupted",
    }
}

fn trim_text(text: &str, limit: usize) -> String {
    let mut chars = text.chars();
    let trimmed: String = chars.by_ref().take(limit).collect();
    if chars.next().is_some() {
        format!("{trimmed}…")
    } else {
        trimmed
    }
}

fn main() {
    gpui_platform::application().run(move |cx| {
        gpui_component::init(cx);

        let options = WindowOptions {
            window_bounds: Some(WindowBounds::centered(size(px(1180.), px(760.)), cx)),
            ..Default::default()
        };

        cx.spawn(async move |cx| {
            cx.open_window(options, |window, cx| {
                let view = cx.new(|cx| WorkApp::new(window, cx));
                cx.new(|cx| Root::new(view, window, cx))
            })
            .expect("failed to open MicroClaw Work window");
        })
        .detach();
    });
}
