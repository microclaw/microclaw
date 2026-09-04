use gpui::prelude::FluentBuilder as _;
use gpui::*;
use gpui_base::Button as BaseButton;
use gpui_component::{
    ActiveTheme, Disableable, Root, Sizable, StyledExt, Theme, ThemeMode, WindowExt,
    button::{Button, ButtonVariants},
    h_flex,
    input::{Input, InputContentType, InputEvent, InputState, Textarea, TextareaState},
    menu::{ContextMenuExt, PopupMenuItem},
    notification::Notification,
    scroll::ScrollableElement,
    v_flex,
};
use microclaw_core::runtime_event::{RuntimeEvent, RuntimeEventEnvelope};
use microclaw_work_app::session::{
    ConversationRole, WorkCommand, WorkEventKind, WorkReviewStatus, WorkSessionSnapshot, WorkStatus,
};
use microclaw_work_app::store::{WorkSessionStore, WorkSessionSummary, startup_workspace};
use microclaw_work_runtime::{
    AgentSettingsDraft, DiagnosticStatus, ModelProviderPreset, ModelSettingsDraft,
    RuntimeConfigSummary, WorkDiagnosticsReport, WorkRunCancellation, WorkRunRequest,
    WorkRunSteering, WorkRuntimeMessage, WorkRuntimeService, WorkSkill, WorkSubagent,
    popular_model_provider_presets,
};
use smol::Timer;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock, mpsc::TryRecvError};
use std::time::Duration;

actions!(
    microclaw_work,
    [
        Quit,
        NewChat,
        FocusComposer,
        OpenModelSettings,
        OpenDiagnostics
    ]
);

const WORK_KEY_CONTEXT: &str = "MicroClawWork";
const INITIAL_VISIBLE_MESSAGES: usize = 60;
const MESSAGE_LOAD_BATCH: usize = 60;
const MAX_VISIBLE_DIFF_LINES: usize = 400;

const SIDEBAR_WIDTH: Pixels = px(242.);
const CONTENT_MAX_WIDTH: Pixels = px(800.);
const SETTINGS_NAV_WIDTH: Pixels = px(172.);
const SETTINGS_CONTENT_WIDTH: Pixels = px(640.);
const UI_TEXT_SIZE: Pixels = px(12.);
const UI_CAPTION_SIZE: Pixels = px(11.);
const UI_PAGE_TITLE_SIZE: Pixels = px(17.);

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct WorkspaceContext {
    name: String,
    branch: Option<String>,
    is_repository: bool,
}

impl WorkspaceContext {
    fn subtitle(&self) -> String {
        match self.branch.as_deref() {
            Some(branch) => format!("Git · {branch}"),
            None if self.is_repository => "Git repository · detached HEAD".into(),
            None => "Local folder".into(),
        }
    }
}

fn work_logo() -> Arc<Image> {
    static LOGO: OnceLock<Arc<Image>> = OnceLock::new();
    LOGO.get_or_init(|| {
        Arc::new(Image::from_bytes(
            ImageFormat::Png,
            include_bytes!("../../../site/static/img/logo.png").to_vec(),
        ))
    })
    .clone()
}

fn sidebar_width_for(viewport_width: Pixels) -> Pixels {
    if viewport_width < px(1_000.) {
        px(224.)
    } else {
        SIDEBAR_WIDTH
    }
}

fn inspector_fits(viewport_width: Pixels) -> bool {
    viewport_width >= px(1_100.)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum SettingsSection {
    General,
    Appearance,
    #[default]
    Models,
    Agent,
    Skills,
    Workspace,
    Diagnostics,
}

impl SettingsSection {
    const ALL: [(Self, &'static str, &'static str); 7] = [
        (Self::General, "General", "⌘"),
        (Self::Appearance, "Appearance", "◐"),
        (Self::Models, "Models", "◇"),
        (Self::Agent, "Agent", "✦"),
        (Self::Skills, "Skills", "◇"),
        (Self::Workspace, "Workspace", "▱"),
        (Self::Diagnostics, "Diagnostics", "✓"),
    ];

    fn title(self) -> &'static str {
        Self::ALL
            .iter()
            .find_map(|(section, title, _)| (*section == self).then_some(*title))
            .unwrap_or("Settings")
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum AppearancePreference {
    #[default]
    System,
    Light,
    Dark,
}

impl AppearancePreference {
    fn load(path: &Path) -> Self {
        match fs::read_to_string(path).as_deref().map(str::trim) {
            Ok("light") => Self::Light,
            Ok("dark") => Self::Dark,
            _ => Self::System,
        }
    }

    fn save(self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, self.name())
    }

    fn name(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Light => "light",
            Self::Dark => "dark",
        }
    }

    fn apply(self, window: &mut Window, cx: &mut App) {
        match self {
            Self::System => Theme::sync_system_appearance(Some(window), cx),
            Self::Light => Theme::change(ThemeMode::Light, Some(window), cx),
            Self::Dark => Theme::change(ThemeMode::Dark, Some(window), cx),
        }
    }
}

impl Global for AppearancePreference {}

fn configure_native_application(cx: &mut App) {
    cx.activate(true);
    cx.on_action(|_: &Quit, cx| cx.quit());
    #[cfg(target_os = "macos")]
    cx.bind_keys([
        KeyBinding::new("cmd-q", Quit, None),
        KeyBinding::new("cmd-n", NewChat, Some(WORK_KEY_CONTEXT)),
        KeyBinding::new("cmd-l", FocusComposer, Some(WORK_KEY_CONTEXT)),
        KeyBinding::new("cmd-,", OpenModelSettings, Some(WORK_KEY_CONTEXT)),
        KeyBinding::new("cmd-shift-d", OpenDiagnostics, Some(WORK_KEY_CONTEXT)),
    ]);
    #[cfg(not(target_os = "macos"))]
    cx.bind_keys([KeyBinding::new("ctrl-q", Quit, None)]);

    cx.set_menus(vec![
        Menu {
            name: "MicroClaw Work".into(),
            items: vec![
                MenuItem::action("Settings…", OpenModelSettings),
                MenuItem::separator(),
                MenuItem::action("Quit MicroClaw Work", Quit),
            ],
            disabled: false,
        },
        Menu {
            name: "File".into(),
            items: vec![MenuItem::action("New Chat", NewChat)],
            disabled: false,
        },
        Menu {
            name: "Edit".into(),
            items: vec![
                MenuItem::action("Undo", gpui_component::input::Undo),
                MenuItem::action("Redo", gpui_component::input::Redo),
                MenuItem::separator(),
                MenuItem::action("Cut", gpui_component::input::Cut),
                MenuItem::action("Copy", gpui_component::input::Copy),
                MenuItem::action("Paste", gpui_component::input::Paste),
                MenuItem::separator(),
                MenuItem::action("Select All", gpui_component::input::SelectAll),
            ],
            disabled: false,
        },
        Menu {
            name: "View".into(),
            items: vec![
                MenuItem::action("Focus Composer", FocusComposer),
                MenuItem::action("Diagnostics", OpenDiagnostics),
            ],
            disabled: false,
        },
    ]);
}

struct WorkApp {
    session: WorkSessionSnapshot,
    session_store: WorkSessionStore,
    work_home: PathBuf,
    workspace_context: WorkspaceContext,
    recent_sessions: Vec<WorkSessionSummary>,
    persistence_message: String,
    session_search_input: Entity<InputState>,
    task_input: Entity<TextareaState>,
    steer_input: Entity<TextareaState>,
    active_run_id: u64,
    runtime_active: bool,
    runtime_cancellation: Option<WorkRunCancellation>,
    runtime_steering: Option<WorkRunSteering>,
    runtime_service: WorkRuntimeService,
    runtime_config: RuntimeConfigSummary,
    diagnostics_open: bool,
    diagnostics_report: WorkDiagnosticsReport,
    settings_open: bool,
    settings_section: SettingsSection,
    appearance_preference: AppearancePreference,
    appearance_preferences_path: PathBuf,
    settings_has_api_key: bool,
    codex_account_available: bool,
    provider_input: Entity<InputState>,
    model_input: Entity<InputState>,
    base_url_input: Entity<InputState>,
    api_key_input: Entity<InputState>,
    soul_path_input: Entity<InputState>,
    soul_content_input: Entity<TextareaState>,
    context_dir_input: Entity<InputState>,
    agent_settings_message: String,
    skills: Vec<WorkSkill>,
    skills_message: String,
    skill_import_input: Entity<InputState>,
    skill_import_active: bool,
    durable_subagents: Vec<WorkSubagent>,
    last_run_was_demo: bool,
    connection_test_active: bool,
    connection_test_message: String,
    first_response_active: bool,
    first_response_message: String,
    inspector_open: bool,
    visible_message_limit: usize,
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
        let work_data_root = work_data_root();
        let work_home = work_data_root.join("workspace");
        let appearance_preferences_path = work_data_root.join("appearance");
        let appearance_preference = AppearancePreference::load(&appearance_preferences_path);
        appearance_preference.apply(window, cx);
        cx.set_global(appearance_preference);
        let session_root = work_data_root.join("work-sessions");
        let runtime_service =
            WorkRuntimeService::discover(work_data_root.join("microclaw.config.yaml"));
        let runtime_config = runtime_service.config_summary();
        let model_settings = runtime_service.model_settings().ok();
        let settings_provider = model_settings
            .as_ref()
            .map_or_else(|| "openai".to_string(), |value| value.provider.clone());
        let settings_model = model_settings.as_ref().map_or_else(
            || {
                popular_model_provider_presets()
                    .into_iter()
                    .find(|preset| preset.id == "openai")
                    .and_then(|preset| preset.models.first().copied())
                    .unwrap_or("gpt-5.6-sol")
                    .to_string()
            },
            |value| value.model.clone(),
        );
        let settings_base_url = model_settings
            .as_ref()
            .map_or_else(String::new, |value| value.base_url.clone());
        let settings_has_api_key = model_settings
            .as_ref()
            .is_some_and(|value| value.has_api_key);
        let agent_settings = runtime_service.agent_settings().ok();
        let (skills, skills_message) = match runtime_service.skills() {
            Ok(skills) => {
                let message = format!("{} skills installed.", skills.len());
                (skills, message)
            }
            Err(error) => (Vec::new(), format!("Could not load skills: {error}")),
        };
        let settings_soul_path = agent_settings.as_ref().map_or_else(
            || work_data_root.join("SOUL.md").display().to_string(),
            |value| value.soul_path.clone(),
        );
        let settings_soul_content = agent_settings
            .as_ref()
            .map_or_else(String::new, |value| value.soul_content.clone());
        let settings_context_dir = agent_settings.as_ref().map_or_else(
            || work_data_root.join("context").display().to_string(),
            |value| value.context_dir.clone(),
        );
        let codex_account_available = runtime_service.codex_account_available();
        let session_store = WorkSessionStore::new(session_root);
        let (mut session, persistence_message) = match session_store.load_active_or_recover() {
            Ok(loaded) if loaded.snapshot.status == WorkStatus::Interrupted => {
                let message = loaded.recovery_message.map_or_else(
                    || "Recovered an interrupted task. Review it before retrying.".into(),
                    |recovery| {
                        format!(
                            "{recovery} The restored task was interrupted; review it before retrying."
                        )
                    },
                );
                (loaded.snapshot, message)
            }
            Ok(loaded) => {
                let message = loaded
                    .recovery_message
                    .unwrap_or_else(|| "Restored the previous session.".into());
                (loaded.snapshot, message)
            }
            Err(error) => (
                WorkSessionSnapshot::new(""),
                format!("Could not open the session store: {error}"),
            ),
        };
        let unavailable = session.workspace.clone();
        let persistence_message = match startup_workspace(&unavailable, &work_home) {
            Ok((_, false)) => persistence_message,
            Ok((workspace, true)) => {
                session.workspace = workspace.display().to_string();
                let _ = session_store.save(&session);
                if unavailable.is_empty() {
                    "Ready in your private Work Home. Connect a project folder when needed.".into()
                } else {
                    format!(
                        "The previous workspace is unavailable ({unavailable}). Using Work Home instead."
                    )
                }
            }
            Err(work_home_error) => {
                session.workspace.clear();
                let _ = session_store.save(&session);
                format!(
                    "Could not create Work Home: {work_home_error}. Select a folder before chatting{}.",
                    if unavailable.is_empty() {
                        String::new()
                    } else {
                        format!("; previous workspace unavailable ({unavailable})")
                    }
                )
            }
        };
        let durable_subagents = runtime_service
            .subagents(&session.session_id)
            .unwrap_or_default();
        let recent_sessions = session_store.list().unwrap_or_default();
        let workspace_context = inspect_workspace(Path::new(&session.workspace));
        let diagnostics_report =
            runtime_service.local_diagnostics(Path::new(&session.workspace), session_store.root());

        let session_search_input =
            cx.new(|cx| InputState::new(window, cx).placeholder("Search conversations"));
        let task_input = cx.new(|cx| {
            TextareaState::new(window, cx)
                .auto_grow(1, 5)
                .submit_on_enter(true)
                .default_value(session.composer_draft.clone())
                .placeholder("Describe a task… Return to send, Shift-Return for a new line")
        });
        let steer_input = cx.new(|cx| {
            TextareaState::new(window, cx)
                .auto_grow(1, 4)
                .submit_on_enter(true)
                .placeholder("Add guidance… Return to send, Shift-Return for a new line")
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
        let soul_path_input = cx.new(|cx| {
            InputState::new(window, cx)
                .default_value(settings_soul_path)
                .placeholder("Path to SOUL.md")
        });
        let soul_content_input = cx.new(|cx| {
            TextareaState::new(window, cx)
                .auto_grow(8, 18)
                .default_value(settings_soul_content)
                .placeholder("Describe the agent's identity, voice, values, and working style…")
        });
        let context_dir_input = cx.new(|cx| {
            InputState::new(window, cx)
                .default_value(settings_context_dir)
                .placeholder("Directory containing project context Markdown files")
        });
        let skill_import_input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Local folder, GitHub URL, owner/repo/skill, or ClawHub slug")
        });
        let _subscriptions = vec![
            cx.subscribe_in(
                &provider_input,
                window,
                move |_, _, event: &InputEvent, _, cx| {
                    if matches!(event, InputEvent::Change) {
                        cx.notify();
                    }
                },
            ),
            cx.subscribe_in(
                &session_search_input,
                window,
                move |_, _, event: &InputEvent, _, cx| {
                    if matches!(event, InputEvent::Change) {
                        cx.notify();
                    }
                },
            ),
            cx.subscribe_in(&task_input, window, {
                let task_input = task_input.clone();
                move |this, _, event: &InputEvent, window, cx| match event {
                    InputEvent::Change => {
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
                    InputEvent::PressEnter { shift: false, .. } => {
                        this.submit_composer(window, cx);
                    }
                    _ => {}
                }
            }),
            cx.subscribe_in(
                &steer_input,
                window,
                move |this, _, event: &InputEvent, window, cx| match event {
                    InputEvent::Change => cx.notify(),
                    InputEvent::PressEnter { shift: false, .. } => {
                        this.submit_composer(window, cx);
                    }
                    _ => {}
                },
            ),
        ];
        let inspector_open = !session.plan.is_empty()
            || !session.process_activities.is_empty()
            || !session.file_changes.is_empty()
            || !session.subagents.is_empty();
        let initial_input = task_input.clone();
        window.defer(cx, move |window, cx| {
            initial_input.update(cx, |input, cx| input.focus(window, cx));
        });

        Self {
            session,
            session_store,
            work_home,
            workspace_context,
            recent_sessions,
            persistence_message,
            session_search_input,
            task_input,
            steer_input,
            active_run_id: 0,
            runtime_active: false,
            runtime_cancellation: None,
            runtime_steering: None,
            runtime_service,
            runtime_config,
            diagnostics_open: false,
            diagnostics_report,
            settings_open: false,
            settings_section: SettingsSection::default(),
            appearance_preference,
            appearance_preferences_path,
            settings_has_api_key,
            codex_account_available,
            provider_input,
            model_input,
            base_url_input,
            api_key_input,
            soul_path_input,
            soul_content_input,
            context_dir_input,
            agent_settings_message:
                "Edit the personality and shared project context used by new turns.".into(),
            skills,
            skills_message,
            skill_import_input,
            skill_import_active: false,
            durable_subagents,
            last_run_was_demo: false,
            connection_test_active: false,
            connection_test_message: "Save settings, then test the provider connection.".into(),
            first_response_active: false,
            first_response_message: "Run First Response to verify the complete Agent Engine path."
                .into(),
            inspector_open,
            visible_message_limit: INITIAL_VISIBLE_MESSAGES,
            draft_revision: 0,
            _subscriptions,
        }
    }

    fn toggle_inspector(&mut self, _: &ClickEvent, _: &mut Window, cx: &mut Context<Self>) {
        self.inspector_open = !self.inspector_open;
        cx.notify();
    }

    fn show_earlier_messages(&mut self, _: &ClickEvent, _: &mut Window, cx: &mut Context<Self>) {
        self.visible_message_limit = self
            .visible_message_limit
            .saturating_add(MESSAGE_LOAD_BATCH)
            .min(WorkSessionSnapshot::MAX_MESSAGES);
        cx.notify();
    }

    fn use_starter_prompt(&mut self, prompt: &str, window: &mut Window, cx: &mut Context<Self>) {
        self.task_input.update(cx, |input, cx| {
            input.set_value(prompt, window, cx);
        });
        let _ = self.session.apply(WorkCommand::SetComposerDraft {
            draft: prompt.to_string(),
        });
        self.persist();
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
        mut session: WorkSessionSnapshot,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if let Ok((workspace, true)) = startup_workspace(&session.workspace, &self.work_home) {
            session.workspace = workspace.display().to_string();
            let _ = self.session_store.save(&session);
        }
        self.inspector_open = !session.plan.is_empty()
            || !session.process_activities.is_empty()
            || !session.file_changes.is_empty()
            || !session.subagents.is_empty();
        self.session = session;
        self.workspace_context = inspect_workspace(Path::new(&self.session.workspace));
        self.visible_message_limit = INITIAL_VISIBLE_MESSAGES;
        let task = self.session.composer_draft.clone();
        self.task_input.update(cx, |input, cx| {
            input.set_value(task, window, cx);
        });
        self.last_run_was_demo = false;
        self.draft_revision = self.draft_revision.saturating_add(1);
        self.runtime_active = false;
        self.runtime_cancellation = None;
        self.runtime_steering = None;
    }

    fn new_session(&mut self, _: &ClickEvent, window: &mut Window, cx: &mut Context<Self>) {
        self.create_new_session(window, cx);
    }

    fn create_new_session(&mut self, window: &mut Window, cx: &mut Context<Self>) {
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
                self.durable_subagents = self
                    .runtime_service
                    .subagents(&self.session.session_id)
                    .unwrap_or_default();
                self.recent_sessions = self.session_store.list().unwrap_or_default();
                self.persistence_message = "Created a new Work session.".into();
            }
            Err(error) => self.persistence_message = format!("Could not create session: {error}"),
        }
        cx.notify();
    }

    fn new_chat_action(&mut self, _: &NewChat, window: &mut Window, cx: &mut Context<Self>) {
        self.create_new_session(window, cx);
    }

    fn focus_composer_action(
        &mut self,
        _: &FocusComposer,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.settings_open = false;
        self.diagnostics_open = false;
        let input = if self.runtime_active {
            self.steer_input.clone()
        } else {
            self.task_input.clone()
        };
        input.update(cx, |input, cx| input.focus(window, cx));
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

    fn set_session_pinned(&mut self, session_id: &str, pinned: bool, cx: &mut Context<Self>) {
        match self.session_store.set_pinned(session_id, pinned) {
            Ok(()) => {
                self.recent_sessions = self.session_store.list().unwrap_or_default();
                self.persistence_message = if pinned {
                    "Conversation pinned.".into()
                } else {
                    "Conversation unpinned.".into()
                };
            }
            Err(error) => {
                self.persistence_message = format!("Could not update conversation pin: {error}");
            }
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
                                this.workspace_context =
                                    inspect_workspace(Path::new(&this.session.workspace));
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

    fn choose_attachments(&mut self, _: &ClickEvent, window: &mut Window, cx: &mut Context<Self>) {
        if self.runtime_active || self.session.workspace.is_empty() {
            return;
        }
        let selection = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: true,
            prompt: Some("Attach files from the current workspace".into()),
        });
        let view = cx.entity();
        cx.spawn_in(window, async move |_, window| {
            let selected = match selection.await {
                Ok(Ok(Some(paths))) => Ok(paths),
                Ok(Ok(None)) => Ok(Vec::new()),
                Ok(Err(error)) => Err(error.to_string()),
                Err(error) => Err(error.to_string()),
            };
            window
                .update(|_, cx| {
                    view.update(cx, |this, cx| {
                        match selected {
                            Ok(paths) if !paths.is_empty() => {
                                this.attach_workspace_paths(paths, cx);
                            }
                            Ok(_) => this.persistence_message = "Attachments unchanged.".into(),
                            Err(error) => {
                                this.persistence_message =
                                    format!("Could not open the file picker: {error}");
                            }
                        }
                        cx.notify();
                    });
                })
                .ok()
        })
        .detach();
    }

    fn attach_workspace_paths(&mut self, paths: Vec<PathBuf>, cx: &mut Context<Self>) {
        let count_before = self.session.composer_attachments.len();
        let result = self.session.apply(WorkCommand::AttachWorkspaceFiles {
            paths: paths
                .into_iter()
                .map(|path| path.display().to_string())
                .collect(),
        });
        match result {
            Ok(_) => {
                let added = self
                    .session
                    .composer_attachments
                    .len()
                    .saturating_sub(count_before);
                self.persistence_message = if added == 0 {
                    "No new workspace files were attached.".into()
                } else {
                    format!(
                        "Attached {added} workspace file{}.",
                        if added == 1 { "" } else { "s" }
                    )
                };
                self.persist();
            }
            Err(error) => self.persistence_message = error.to_string(),
        }
        cx.notify();
    }

    fn handle_attachment_drop(
        &mut self,
        paths: &ExternalPaths,
        _: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if !self.runtime_active {
            self.attach_workspace_paths(paths.paths().to_vec(), cx);
        }
    }

    fn remove_attachment(&mut self, path: &str, cx: &mut Context<Self>) {
        let _ = self.session.apply(WorkCommand::RemoveComposerAttachment {
            path: path.to_string(),
        });
        self.persistence_message = format!("Removed attachment: {path}");
        self.persist();
        cx.notify();
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

    fn refresh_diagnostics(&mut self, _: &ClickEvent, _: &mut Window, cx: &mut Context<Self>) {
        self.refresh_diagnostics_state(cx);
    }

    fn refresh_diagnostics_state(&mut self, cx: &mut Context<Self>) {
        self.runtime_config = self.runtime_service.config_summary();
        self.diagnostics_report = self.runtime_service.local_diagnostics(
            Path::new(&self.session.workspace),
            self.session_store.root(),
        );
        self.persistence_message = if self.diagnostics_report.ready {
            "Local diagnostics passed.".into()
        } else {
            "Diagnostics found an item that blocks Work.".into()
        };
        cx.notify();
    }

    fn open_diagnostics(
        &mut self,
        event: &ClickEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.reject_if_runtime_busy(cx) {
            return;
        }
        self.settings_section = SettingsSection::Diagnostics;
        self.settings_open = true;
        self.diagnostics_open = false;
        self.refresh_diagnostics(event, window, cx);
    }

    fn open_diagnostics_action(
        &mut self,
        _: &OpenDiagnostics,
        _: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.reject_if_runtime_busy(cx) {
            return;
        }
        self.settings_section = SettingsSection::Diagnostics;
        self.settings_open = true;
        self.diagnostics_open = false;
        self.refresh_diagnostics_state(cx);
    }

    fn close_diagnostics(&mut self, _: &ClickEvent, window: &mut Window, cx: &mut Context<Self>) {
        self.diagnostics_open = false;
        self.task_input
            .update(cx, |input, cx| input.focus(window, cx));
        cx.notify();
    }

    fn open_model_settings(&mut self, _: &ClickEvent, window: &mut Window, cx: &mut Context<Self>) {
        self.open_model_settings_view(window, cx);
    }

    fn open_model_settings_action(
        &mut self,
        _: &OpenModelSettings,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.open_model_settings_view(window, cx);
    }

    fn open_model_settings_view(&mut self, window: &mut Window, cx: &mut Context<Self>) {
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
        if let Ok(settings) = self.runtime_service.agent_settings() {
            self.soul_path_input.update(cx, |input, cx| {
                input.set_value(settings.soul_path, window, cx)
            });
            self.soul_content_input.update(cx, |input, cx| {
                input.set_value(settings.soul_content, window, cx)
            });
            self.context_dir_input.update(cx, |input, cx| {
                input.set_value(settings.context_dir, window, cx)
            });
        }
        self.settings_open = true;
        self.diagnostics_open = false;
        cx.notify();
    }

    fn close_model_settings(
        &mut self,
        _: &ClickEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.settings_open = false;
        self.task_input
            .update(cx, |input, cx| input.focus(window, cx));
        cx.notify();
    }

    fn set_appearance_preference(
        &mut self,
        preference: AppearancePreference,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.appearance_preference = preference;
        *cx.global_mut::<AppearancePreference>() = preference;
        preference.apply(window, cx);
        self.persistence_message = match preference.save(&self.appearance_preferences_path) {
            Ok(()) => format!("Appearance set to {}.", preference.name()),
            Err(error) => format!("Appearance changed, but the preference was not saved: {error}"),
        };
        cx.notify();
    }

    fn apply_model_provider_preset(
        &mut self,
        preset: ModelProviderPreset,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.provider_input
            .update(cx, |input, cx| input.set_value(preset.id, window, cx));
        if let Some(model) = preset.models.first() {
            self.model_input
                .update(cx, |input, cx| input.set_value(*model, window, cx));
        }
        self.base_url_input.update(cx, |input, cx| {
            input.set_value(preset.default_base_url, window, cx)
        });
        self.connection_test_message = format!(
            "Selected {}. Review the model and credentials, then Save & Test.",
            preset.label
        );
        cx.notify();
    }

    fn apply_model_suggestion(
        &mut self,
        model: &'static str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.model_input
            .update(cx, |input, cx| input.set_value(model, window, cx));
        cx.notify();
    }

    fn save_model_settings(&mut self, cx: &mut Context<Self>) -> bool {
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
                self.persistence_message = settings.recovery_backup.map_or_else(
                    || "Model configuration saved for MicroClaw Work.".into(),
                    |backup| {
                        format!(
                            "Recovered the Work configuration and saved the damaged file at {backup}."
                        )
                    },
                );
                self.connection_test_message =
                    "Settings saved. Test the connection before starting work.".into();
                self.diagnostics_report = self.runtime_service.local_diagnostics(
                    Path::new(&self.session.workspace),
                    self.session_store.root(),
                );
                cx.notify();
                true
            }
            Err(error) => {
                self.persistence_message = format!("Could not save model settings: {error}");
                cx.notify();
                false
            }
        }
    }

    fn save_agent_settings(&mut self, _: &ClickEvent, _: &mut Window, cx: &mut Context<Self>) {
        let draft = AgentSettingsDraft {
            soul_path: self.soul_path_input.read(cx).value().to_string(),
            soul_content: self.soul_content_input.read(cx).value().to_string(),
            context_dir: self.context_dir_input.read(cx).value().to_string(),
        };
        match self.runtime_service.save_agent_settings(draft) {
            Ok(settings) => {
                self.agent_settings_message =
                    format!("Agent settings saved. SOUL.md: {}", settings.soul_path);
                self.persistence_message =
                    "Agent identity and project context configuration saved.".into();
                self.runtime_config = self.runtime_service.config_summary();
            }
            Err(error) => {
                self.agent_settings_message = format!("Could not save agent settings: {error}");
            }
        }
        cx.notify();
    }

    fn refresh_skills(&mut self, cx: &mut Context<Self>) {
        match self.runtime_service.skills() {
            Ok(skills) => {
                self.skills_message = format!("{} skills installed.", skills.len());
                self.skills = skills;
            }
            Err(error) => self.skills_message = format!("Could not load skills: {error}"),
        }
        cx.notify();
    }

    fn refresh_subagents(&mut self, cx: &mut Context<Self>) {
        if let Ok(subagents) = self.runtime_service.subagents(&self.session.session_id) {
            self.durable_subagents = subagents;
        }
        cx.notify();
    }

    fn cancel_subagent(&mut self, run_id: String, cx: &mut Context<Self>) {
        match self
            .runtime_service
            .cancel_subagent(&self.session.session_id, &run_id)
        {
            Ok(true) => self.persistence_message = format!("Cancellation requested for {run_id}."),
            Ok(false) => self.persistence_message = format!("Subagent {run_id} already finished."),
            Err(error) => self.persistence_message = format!("Could not cancel {run_id}: {error}"),
        }
        self.refresh_subagents(cx);
    }

    fn set_skill_enabled(&mut self, name: String, enabled: bool, cx: &mut Context<Self>) {
        match self.runtime_service.set_skill_enabled(&name, enabled) {
            Ok(skills) => {
                self.skills = skills;
                self.skills_message = format!(
                    "Skill {name} {}.",
                    if enabled { "enabled" } else { "disabled" }
                );
            }
            Err(error) => {
                self.skills_message = format!("Could not update skill {name}: {error}");
            }
        }
        cx.notify();
    }

    fn remove_skill(&mut self, name: String, cx: &mut Context<Self>) {
        match self.runtime_service.remove_skill(&name) {
            Ok(result) => {
                self.skills = result.skills;
                self.skills_message =
                    format!("Skill {} archived to {}.", result.name, result.archived_to);
            }
            Err(error) => {
                self.skills_message = format!("Could not archive skill {name}: {error}");
            }
        }
        cx.notify();
    }

    fn import_skill(&mut self, cx: &mut Context<Self>) {
        if self.skill_import_active {
            return;
        }
        let reference = self.skill_import_input.read(cx).value().trim().to_string();
        if reference.is_empty() {
            self.skills_message = "Enter a local folder, GitHub reference, or ClawHub slug.".into();
            cx.notify();
            return;
        }
        self.skill_import_active = true;
        self.skills_message = format!("Importing {reference}…");
        let receiver = self.runtime_service.install_skill_background(reference);
        cx.spawn(async move |this, cx| {
            loop {
                match receiver.try_recv() {
                    Ok(Ok(result)) => {
                        let _ = this.update(cx, |this, cx| {
                            this.skill_import_active = false;
                            this.skills = result.skills;
                            this.skills_message = if result.warnings.is_empty() {
                                result.message
                            } else {
                                format!(
                                    "{} Warnings: {}",
                                    result.message,
                                    result.warnings.join("; ")
                                )
                            };
                            cx.notify();
                        });
                        break;
                    }
                    Ok(Err(error)) => {
                        let _ = this.update(cx, |this, cx| {
                            this.skill_import_active = false;
                            this.skills_message = format!("Could not import skill: {error}");
                            cx.notify();
                        });
                        break;
                    }
                    Err(TryRecvError::Empty) => {
                        Timer::after(Duration::from_millis(50)).await;
                    }
                    Err(TryRecvError::Disconnected) => {
                        let _ = this.update(cx, |this, cx| {
                            this.skill_import_active = false;
                            this.skills_message =
                                "Skill import worker stopped unexpectedly.".into();
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

    fn save_and_test_model_settings(
        &mut self,
        _: &ClickEvent,
        _: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.save_model_settings(cx) {
            self.start_provider_connection_test(cx);
        }
    }

    fn use_codex_account(&mut self, _: &ClickEvent, window: &mut Window, cx: &mut Context<Self>) {
        let model = self.runtime_service.codex_default_model();
        self.provider_input
            .update(cx, |input, cx| input.set_value("openai-codex", window, cx));
        self.model_input
            .update(cx, |input, cx| input.set_value(model, window, cx));
        self.base_url_input
            .update(cx, |input, cx| input.set_value("", window, cx));
        self.api_key_input
            .update(cx, |input, cx| input.set_value("", window, cx));
        self.settings_has_api_key = false;
        if self.save_model_settings(cx) {
            self.start_provider_connection_test(cx);
        }
    }

    fn test_provider_connection(&mut self, _: &ClickEvent, _: &mut Window, cx: &mut Context<Self>) {
        self.start_provider_connection_test(cx);
    }

    fn start_provider_connection_test(&mut self, cx: &mut Context<Self>) {
        if self.connection_test_active || self.first_response_active {
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

    fn test_first_response(&mut self, _: &ClickEvent, _: &mut Window, cx: &mut Context<Self>) {
        if self.connection_test_active || self.first_response_active {
            return;
        }
        self.runtime_config = self.runtime_service.config_summary();
        self.diagnostics_report = self.runtime_service.local_diagnostics(
            Path::new(&self.session.workspace),
            self.session_store.root(),
        );
        if !self.diagnostics_report.ready {
            self.first_response_message =
                "Resolve the failing local diagnostics before running First Response.".into();
            cx.notify();
            return;
        }
        self.first_response_active = true;
        self.first_response_message =
            "Running the shared Agent Engine first-response proof…".into();
        let receiver = self
            .runtime_service
            .test_first_response(PathBuf::from(&self.session.workspace));
        cx.spawn(async move |this, cx| {
            loop {
                match receiver.try_recv() {
                    Ok(Ok(report)) => {
                        let _ = this.update(cx, |this, cx| {
                            this.first_response_active = false;
                            this.first_response_message = format!(
                                "First response passed in {} ms · {} events · {} / {} · {}",
                                report.latency_ms,
                                report.event_count,
                                report.provider,
                                report.model,
                                report.response_preview
                            );
                            cx.notify();
                        });
                        break;
                    }
                    Ok(Err(error)) => {
                        let _ = this.update(cx, |this, cx| {
                            this.first_response_active = false;
                            this.first_response_message = format!("First response failed: {error}");
                            cx.notify();
                        });
                        break;
                    }
                    Err(TryRecvError::Empty) => {
                        Timer::after(Duration::from_millis(50)).await;
                    }
                    Err(TryRecvError::Disconnected) => {
                        let _ = this.update(cx, |this, cx| {
                            this.first_response_active = false;
                            this.first_response_message =
                                "First-response worker exited unexpectedly.".into();
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

    fn open_release_page(&mut self, _: &ClickEvent, _: &mut Window, cx: &mut Context<Self>) {
        cx.open_url("https://github.com/microclaw/microclaw/releases/latest");
        self.persistence_message = "Opened the latest MicroClaw release.".into();
        cx.notify();
    }

    fn reveal_workspace(&mut self, _: &ClickEvent, _: &mut Window, cx: &mut Context<Self>) {
        let workspace = Path::new(&self.session.workspace);
        if !workspace.is_dir() {
            self.persistence_message = "Select an available workspace first.".into();
            cx.notify();
            return;
        }

        match url::Url::from_directory_path(workspace) {
            Ok(url) => {
                cx.open_url(url.as_str());
                self.persistence_message = format!("Opened workspace: {}", workspace.display());
            }
            Err(()) => {
                self.persistence_message = format!(
                    "Could not create a workspace URL for {}",
                    workspace.display()
                );
            }
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

    fn resolve_approval(&mut self, value: String, window: &mut Window, cx: &mut Context<Self>) {
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
            self.launch_runtime_prompt(value, window, cx);
        }
    }

    fn start_runtime(&mut self, window: &mut Window, cx: &mut Context<Self>) {
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
        let runtime_prompt = self.session.runtime_task_prompt();
        self.persist();
        self.launch_runtime_prompt(runtime_prompt, window, cx);
    }

    fn primary_action(&mut self, _: &ClickEvent, window: &mut Window, cx: &mut Context<Self>) {
        self.submit_composer(window, cx);
    }

    fn submit_composer(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.runtime_active {
            self.send_steering(window, cx);
        } else {
            self.start_runtime(window, cx);
        }
    }

    fn send_steering(&mut self, window: &mut Window, cx: &mut Context<Self>) {
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

    fn launch_runtime_prompt(
        &mut self,
        prompt: String,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
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
        let window_handle = window.window_handle();
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
                        let update_result = this.update(cx, |this, cx| {
                                if this.active_run_id != generation {
                                    return None;
                                }
                                let notification = match message {
                                    WorkRuntimeMessage::Envelope(envelope) => {
                                        if let Err(error) = this
                                            .session
                                            .apply(WorkCommand::ApplyRuntimeEvent(envelope))
                                        {
                                            this.persistence_message = error.to_string();
                                        }
                                        this.durable_subagents = this
                                            .runtime_service
                                            .subagents(&this.session.session_id)
                                            .unwrap_or_default();
                                        None
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
                                        None
                                    }
                                    WorkRuntimeMessage::Completed { run_id } => {
                                        this.runtime_active = false;
                                        this.runtime_cancellation = None;
                                        this.runtime_steering = None;
                                        this.durable_subagents = this
                                            .runtime_service
                                            .subagents(&this.session.session_id)
                                            .unwrap_or_default();
                                        let (message, notification) = match this.session.status {
                                            WorkStatus::AwaitingApproval => {
                                                (format!("Runtime {run_id} paused for approval."), None)
                                            }
                                            WorkStatus::Cancelled => {
                                                (format!("Runtime {run_id} stopped."), None)
                                            }
                                            _ => (
                                                format!("Runtime {run_id} completed."),
                                                Some((
                                                    "MicroClaw Work finished",
                                                    "Your task is ready to review.",
                                                    true,
                                                )),
                                            ),
                                        };
                                        this.persistence_message = message;
                                        notification
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
                                        Some((
                                            "MicroClaw Work needs attention",
                                            "The task stopped before completion. Open Work for details.",
                                            false,
                                        ))
                                    }
                                };
                                if let Err(error) = this.save_session() {
                                    this.persistence_message = format!("Save failed: {error}");
                                }
                                cx.notify();
                                notification
                            });
                        let Ok(notification) = update_result else {
                            return;
                        };
                        if let Some((title, message, success)) = notification {
                            let _ = window_handle.update(cx, move |_, window, cx| {
                                let notification = if success {
                                    Notification::success(message)
                                } else {
                                    Notification::error(message)
                                };
                                window.push_notification(
                                    notification.title(title).in_app_and_system(),
                                    cx,
                                );
                            });
                        }
                        if terminal {
                            loop {
                                Timer::after(Duration::from_millis(500)).await;
                                let active = this.update(cx, |this, cx| {
                                    let Ok(subagents) = this
                                        .runtime_service
                                        .subagents(&this.session.session_id)
                                    else {
                                        return false;
                                    };
                                    let active = subagents.iter().any(|agent| {
                                        matches!(
                                            agent.status.as_str(),
                                            "accepted" | "queued" | "running"
                                        )
                                    });
                                    this.durable_subagents = subagents;
                                    cx.notify();
                                    active
                                });
                                match active {
                                    Ok(true) => continue,
                                    Ok(false) | Err(_) => return,
                                }
                            }
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

    fn render_settings_navigation(&self, cx: &mut Context<Self>) -> impl IntoElement {
        v_flex()
            .w(SETTINGS_NAV_WIDTH)
            .h_full()
            .flex_shrink_0()
            .p_3()
            .gap_1()
            .bg(cx.theme().secondary.opacity(0.32))
            .border_r_1()
            .border_color(cx.theme().border.opacity(0.72))
            .child(
                h_flex()
                    .h(px(42.))
                    .items_center()
                    .gap_2()
                    .px_2()
                    .child(img(work_logo()).size(px(24.)))
                    .child(
                        v_flex()
                            .gap_0p5()
                            .child(
                                div()
                                    .text_size(UI_TEXT_SIZE)
                                    .font_semibold()
                                    .child("MicroClaw Work"),
                            )
                            .child(
                                div()
                                    .text_size(px(10.))
                                    .text_color(cx.theme().muted_foreground)
                                    .child("SETTINGS"),
                            ),
                    ),
            )
            .child(div().h(px(8.)))
            .children(
                SettingsSection::ALL
                    .into_iter()
                    .map(|(section, title, icon)| {
                        BaseButton::new(format!("settings-nav-{title}"))
                            .w_full()
                            .h(px(32.))
                            .px_2()
                            .gap_2()
                            .items_center()
                            .justify_start()
                            .rounded(px(7.))
                            .when(self.settings_section == section, |button| {
                                button.bg(cx.theme().accent.opacity(0.16))
                            })
                            .hover(|style| style.bg(cx.theme().accent.opacity(0.10)))
                            .child(
                                div()
                                    .w(px(18.))
                                    .text_center()
                                    .text_size(UI_CAPTION_SIZE)
                                    .text_color(if self.settings_section == section {
                                        cx.theme().foreground
                                    } else {
                                        cx.theme().muted_foreground
                                    })
                                    .child(icon),
                            )
                            .child(
                                div()
                                    .text_size(UI_TEXT_SIZE)
                                    .font_weight(if self.settings_section == section {
                                        FontWeight::SEMIBOLD
                                    } else {
                                        FontWeight::NORMAL
                                    })
                                    .child(title),
                            )
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.settings_section = section;
                                if section == SettingsSection::Diagnostics {
                                    this.refresh_diagnostics_state(cx);
                                } else if section == SettingsSection::Skills {
                                    this.refresh_skills(cx);
                                } else {
                                    cx.notify();
                                }
                            }))
                    }),
            )
            .child(div().flex_1())
            .child(
                div()
                    .px_2()
                    .pb_1()
                    .text_size(px(10.))
                    .line_height(relative(1.35))
                    .text_color(cx.theme().muted_foreground)
                    .child("Settings are stored locally on this Mac."),
            )
    }

    fn settings_page_header(
        &self,
        subtitle: &'static str,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        v_flex()
            .w_full()
            .gap_1()
            .pb_4()
            .child(
                div()
                    .text_size(UI_PAGE_TITLE_SIZE)
                    .font_semibold()
                    .child(self.settings_section.title()),
            )
            .child(
                div()
                    .text_size(UI_CAPTION_SIZE)
                    .text_color(cx.theme().muted_foreground)
                    .child(subtitle),
            )
    }

    fn settings_group(&self, children: Vec<AnyElement>, cx: &mut Context<Self>) -> AnyElement {
        v_flex()
            .w_full()
            .rounded(px(10.))
            .border_1()
            .border_color(cx.theme().border.opacity(0.78))
            .bg(cx.theme().secondary.opacity(0.18))
            .p_4()
            .gap_3()
            .children(children)
            .into_any_element()
    }

    fn settings_label(&self, label: &'static str) -> AnyElement {
        div()
            .text_size(UI_CAPTION_SIZE)
            .font_medium()
            .child(label)
            .into_any_element()
    }

    fn render_general_settings(&self, cx: &mut Context<Self>) -> AnyElement {
        v_flex()
            .w_full()
            .gap_4()
            .child(self.settings_page_header(
                "Core desktop behavior and local configuration.",
                cx,
            ))
            .child(self.settings_group(
                vec![
                    h_flex()
                        .items_center()
                        .justify_between()
                        .child(
                            v_flex()
                                .gap_0p5()
                                .child(div().text_size(UI_TEXT_SIZE).font_medium().child("Local-first runtime"))
                                .child(
                                    div()
                                        .text_size(UI_CAPTION_SIZE)
                                        .text_color(cx.theme().muted_foreground)
                                        .child("Work runs against the shared MicroClaw core on this Mac."),
                                ),
                        )
                        .child(
                            div()
                                .px_2()
                                .py_1()
                                .rounded_full()
                                .bg(cx.theme().success.opacity(0.14))
                                .text_color(cx.theme().success)
                                .text_size(px(10.))
                                .font_semibold()
                                .child("ACTIVE"),
                        )
                        .into_any_element(),
                    h_flex()
                        .items_center()
                        .justify_between()
                        .pt_3()
                        .border_t_1()
                        .border_color(cx.theme().border.opacity(0.68))
                        .child(
                            v_flex()
                                .gap_0p5()
                                .child(div().text_size(UI_TEXT_SIZE).font_medium().child("Configuration"))
                                .child(
                                    div()
                                        .max_w(px(430.))
                                        .overflow_hidden()
                                        .text_ellipsis()
                                        .whitespace_nowrap()
                                        .text_size(UI_CAPTION_SIZE)
                                        .text_color(cx.theme().muted_foreground)
                                        .child(self.runtime_service.config_path().display().to_string()),
                                ),
                        )
                        .child(
                            Button::new("settings-general-reload")
                                .ghost()
                                .small()
                                .label("Reload")
                                .on_click(cx.listener(Self::refresh_runtime_config)),
                        )
                        .into_any_element(),
                    h_flex()
                        .items_center()
                        .justify_between()
                        .pt_3()
                        .border_t_1()
                        .border_color(cx.theme().border.opacity(0.68))
                        .child(
                            v_flex()
                                .gap_0p5()
                                .child(
                                    div()
                                        .text_size(UI_TEXT_SIZE)
                                        .font_medium()
                                        .child(format!("MicroClaw Work {}", env!("CARGO_PKG_VERSION"))),
                                )
                                .child(
                                    div()
                                        .text_size(UI_CAPTION_SIZE)
                                        .text_color(cx.theme().muted_foreground)
                                        .child("Updates are delivered through signed GitHub releases and Homebrew."),
                                ),
                        )
                        .child(
                            Button::new("settings-view-latest-release")
                                .outline()
                                .small()
                                .label("View Latest")
                                .on_click(cx.listener(Self::open_release_page)),
                        )
                        .into_any_element(),
                ],
                cx,
            ))
            .child(
                div()
                    .text_size(UI_CAPTION_SIZE)
                    .text_color(cx.theme().muted_foreground)
                    .child("Server configuration and channel adapters are unchanged by Work preferences."),
            )
            .into_any_element()
    }

    fn render_appearance_settings(&self, cx: &mut Context<Self>) -> AnyElement {
        v_flex()
            .w_full()
            .gap_4()
            .child(self.settings_page_header("Choose how MicroClaw Work looks on this Mac.", cx))
            .child(self.settings_group(
                vec![
                        self.settings_label("Color scheme"),
                        h_flex()
                            .w_full()
                            .gap_2()
                            .children(
                                [
                                    (
                                        "appearance-system",
                                        "System",
                                        "Follow macOS",
                                        AppearancePreference::System,
                                    ),
                                    (
                                        "appearance-light",
                                        "Light",
                                        "Always light",
                                        AppearancePreference::Light,
                                    ),
                                    (
                                        "appearance-dark",
                                        "Dark",
                                        "Always dark",
                                        AppearancePreference::Dark,
                                    ),
                                ]
                                .into_iter()
                                .map(
                                    |(id, label, detail, preference)| {
                                        BaseButton::new(id)
                                            .flex_1()
                                            .h(px(76.))
                                            .p_3()
                                            .items_start()
                                            .justify_start()
                                            .rounded(px(9.))
                                            .border_1()
                                            .border_color(
                                                if self.appearance_preference == preference {
                                                    cx.theme().primary.opacity(0.72)
                                                } else {
                                                    cx.theme().border
                                                },
                                            )
                                            .bg(if self.appearance_preference == preference {
                                                cx.theme().accent.opacity(0.14)
                                            } else {
                                                cx.theme().background.opacity(0.48)
                                            })
                                            .hover(|style| {
                                                style.bg(cx.theme().accent.opacity(0.10))
                                            })
                                            .child(
                                                v_flex()
                                                    .gap_1()
                                                    .child(
                                                        h_flex()
                                                            .w_full()
                                                            .justify_between()
                                                            .child(
                                                                div()
                                                                    .text_size(UI_TEXT_SIZE)
                                                                    .font_semibold()
                                                                    .child(label),
                                                            )
                                                            .child(
                                                                div()
                                                                    .size(px(10.))
                                                                    .rounded_full()
                                                                    .border_1()
                                                                    .border_color(
                                                                        cx.theme().primary,
                                                                    )
                                                                    .when(
                                                                        self.appearance_preference
                                                                            == preference,
                                                                        |dot| {
                                                                            dot.bg(cx
                                                                                .theme()
                                                                                .primary)
                                                                        },
                                                                    ),
                                                            ),
                                                    )
                                                    .child(
                                                        div()
                                                            .text_size(UI_CAPTION_SIZE)
                                                            .text_color(cx.theme().muted_foreground)
                                                            .child(detail),
                                                    ),
                                            )
                                            .on_click(cx.listener(move |this, _, window, cx| {
                                                this.set_appearance_preference(
                                                    preference, window, cx,
                                                );
                                            }))
                                    },
                                ),
                            )
                            .into_any_element(),
                    ],
                cx,
            ))
            .child(
                div()
                    .text_size(UI_CAPTION_SIZE)
                    .text_color(cx.theme().muted_foreground)
                    .child(
                        "System is recommended and follows macOS appearance changes automatically.",
                    ),
            )
            .into_any_element()
    }

    fn render_model_settings_content(&self, cx: &mut Context<Self>) -> AnyElement {
        let provider_presets = popular_model_provider_presets();
        let selected_provider = self.provider_input.read(cx).value().trim().to_lowercase();
        let selected_preset = provider_presets
            .iter()
            .copied()
            .find(|preset| preset.id == selected_provider);

        v_flex()
            .w_full()
            .gap_4()
            .child(self.settings_page_header(
                "Select the provider and model used for conversations and tools.",
                cx,
            ))
            .when(self.codex_account_available, |this| {
                this.child(
                    h_flex()
                        .items_center()
                        .justify_between()
                        .gap_4()
                        .p_3()
                        .rounded(px(9.))
                        .bg(cx.theme().success.opacity(0.10))
                        .border_1()
                        .border_color(cx.theme().success.opacity(0.24))
                        .child(
                            v_flex()
                                .gap_0p5()
                                .child(div().text_size(UI_TEXT_SIZE).font_semibold().child("Codex account available"))
                                .child(
                                    div()
                                        .text_size(UI_CAPTION_SIZE)
                                        .text_color(cx.theme().muted_foreground)
                                        .child("Use the signed-in account on this Mac without copying an API key."),
                                ),
                        )
                        .child(
                            Button::new("use-codex-account")
                                .primary()
                                .small()
                                .disabled(self.connection_test_active)
                                .label("Use Account")
                                .on_click(cx.listener(Self::use_codex_account)),
                        ),
                )
            })
            .child(self.settings_group(
                vec![
                    self.settings_label("Provider"),
                    h_flex()
                        .w_full()
                        .gap_1()
                        .children(provider_presets.iter().take(6).copied().map(|preset| {
                            let selected = preset.id == selected_provider;
                            Button::new(format!("provider-preset-{}", preset.id))
                                .ghost()
                                .xsmall()
                                .flex_1()
                                .when(selected, |button| {
                                    button.bg(cx.theme().accent.opacity(0.18)).font_semibold()
                                })
                                .label(preset.id)
                                .on_click(cx.listener(move |this, _, window, cx| {
                                    this.apply_model_provider_preset(preset, window, cx);
                                }))
                        }))
                        .into_any_element(),
                    Input::new(&self.provider_input)
                        .aria_label("Model provider")
                        .into_any_element(),
                    self.settings_label("Model"),
                    Input::new(&self.model_input)
                        .aria_label("Model ID")
                        .into_any_element(),
                    v_flex()
                        .gap_1()
                        .children(selected_preset.into_iter().flat_map(|preset| {
                            preset.models.iter().take(4).copied().map(|model| {
                                Button::new(format!("model-suggestion-{model}"))
                                    .ghost()
                                    .xsmall()
                                    .w_full()
                                    .justify_start()
                                    .label(model)
                                    .on_click(cx.listener(move |this, _, window, cx| {
                                        this.apply_model_suggestion(model, window, cx);
                                    }))
                            })
                        }))
                        .into_any_element(),
                ],
                cx,
            ))
            .child(
                v_flex()
                    .w_full()
                    .gap_3()
                    .child(
                        div()
                            .text_size(UI_CAPTION_SIZE)
                            .font_semibold()
                            .text_color(cx.theme().muted_foreground)
                            .child("ADVANCED"),
                    )
                    .child(self.settings_group(
                        vec![
                            self.settings_label("Base URL"),
                            Input::new(&self.base_url_input)
                                .aria_label("Provider base URL")
                                .content_type(InputContentType::Url)
                                .into_any_element(),
                            self.settings_label("API key"),
                            Input::new(&self.api_key_input)
                                .aria_label("Provider API key")
                                .content_type(InputContentType::Password)
                                .mask_toggle()
                                .into_any_element(),
                            div()
                                .text_size(UI_CAPTION_SIZE)
                                .text_color(cx.theme().muted_foreground)
                                .child(if self.settings_has_api_key {
                                    "A key is already saved. Leave this field blank to keep it."
                                } else {
                                    "Local and account-authenticated providers may not require a key."
                                })
                                .into_any_element(),
                        ],
                        cx,
                    )),
            )
            .child(
                h_flex()
                    .w_full()
                    .items_center()
                    .justify_between()
                    .gap_4()
                    .child(
                        div()
                            .flex_1()
                            .text_size(UI_CAPTION_SIZE)
                            .text_color(if self.connection_test_message.starts_with("Connected") {
                                cx.theme().success
                            } else if self.connection_test_message.contains("failed") {
                                cx.theme().danger
                            } else {
                                cx.theme().muted_foreground
                            })
                            .child(self.connection_test_message.clone()),
                    )
                    .child(
                        Button::new("save-and-test-model-settings")
                            .primary()
                            .small()
                            .disabled(self.connection_test_active)
                            .label(if self.connection_test_active {
                                "Saving & Testing…"
                            } else {
                                "Save & Test"
                            })
                            .on_click(cx.listener(Self::save_and_test_model_settings)),
                    ),
            )
            .into_any_element()
    }

    fn render_agent_settings(&self, cx: &mut Context<Self>) -> AnyElement {
        v_flex()
            .w_full()
            .gap_4()
            .child(self.settings_page_header(
                "Shape the stable identity, voice, and working style used for new turns.",
                cx,
            ))
            .child(self.settings_group(
                vec![
                    self.settings_label("SOUL.md file"),
                    Input::new(&self.soul_path_input)
                        .aria_label("SOUL.md file path")
                        .into_any_element(),
                    self.settings_label("Soul"),
                    div()
                        .min_h(px(220.))
                        .p_2()
                        .rounded(px(8.))
                        .border_1()
                        .border_color(cx.theme().border)
                        .bg(cx.theme().background.opacity(0.62))
                        .child(
                            Textarea::new(&self.soul_content_input)
                                .aria_label("Agent soul and personality"),
                        )
                        .into_any_element(),
                    div()
                        .text_size(UI_CAPTION_SIZE)
                        .text_color(cx.theme().muted_foreground)
                        .child("Changes apply to new turns. Server and channel-specific SOUL overrides remain supported.")
                        .into_any_element(),
                ],
                cx,
            ))
            .child(
                h_flex()
                    .w_full()
                    .items_center()
                    .justify_between()
                    .gap_4()
                    .child(
                        div()
                            .flex_1()
                            .text_size(UI_CAPTION_SIZE)
                            .text_color(if self.agent_settings_message.starts_with("Could not") {
                                cx.theme().danger
                            } else {
                                cx.theme().muted_foreground
                            })
                            .child(self.agent_settings_message.clone()),
                    )
                    .child(
                        Button::new("save-agent-settings")
                            .primary()
                            .small()
                            .label("Save Agent")
                            .on_click(cx.listener(Self::save_agent_settings)),
                    ),
            )
            .into_any_element()
    }

    fn render_workspace_settings(&self, cx: &mut Context<Self>) -> AnyElement {
        let using_work_home = Path::new(&self.session.workspace) == self.work_home;
        let workspace = if self.session.workspace.is_empty() {
            "No folder selected".to_string()
        } else {
            self.session.workspace.clone()
        };
        let workspace_kind = if using_work_home {
            "Private Work Home".to_string()
        } else {
            self.workspace_context.subtitle()
        };

        v_flex()
            .w_full()
            .gap_4()
            .child(self.settings_page_header(
                "Control the project folder and durable context available to Work.",
                cx,
            ))
            .child(self.settings_group(
                vec![
                    self.settings_label("Current workspace"),
                    h_flex()
                        .items_center()
                        .justify_between()
                        .gap_3()
                        .child(
                            v_flex()
                                .flex_1()
                                .min_w_0()
                                .gap_0p5()
                                .child(
                                    div()
                                        .overflow_hidden()
                                        .text_ellipsis()
                                        .whitespace_nowrap()
                                        .text_size(UI_TEXT_SIZE)
                                        .font_medium()
                                        .child(workspace),
                                )
                                .child(
                                    div()
                                        .text_size(UI_CAPTION_SIZE)
                                        .text_color(cx.theme().muted_foreground)
                                        .child(workspace_kind),
                                ),
                        )
                        .child(
                            h_flex()
                                .gap_2()
                                .child(
                                    Button::new("settings-reveal-workspace")
                                        .ghost()
                                        .small()
                                        .disabled(self.session.workspace.is_empty())
                                        .label("Open")
                                        .on_click(cx.listener(Self::reveal_workspace)),
                                )
                                .child(
                                    Button::new("settings-choose-workspace")
                                        .outline()
                                        .small()
                                        .disabled(self.runtime_active)
                                        .label(if using_work_home { "Connect Folder" } else { "Change Folder" })
                                        .on_click(cx.listener(Self::choose_workspace)),
                                ),
                        )
                        .into_any_element(),
                    div()
                        .pt_3()
                        .border_t_1()
                        .border_color(cx.theme().border.opacity(0.68))
                        .into_any_element(),
                    self.settings_label("Local access boundary"),
                    div()
                        .p_3()
                        .rounded(px(8.))
                        .bg(cx.theme().accent.opacity(0.08))
                        .border_1()
                        .border_color(cx.theme().accent.opacity(0.24))
                        .text_size(UI_CAPTION_SIZE)
                        .text_color(cx.theme().muted_foreground)
                        .child("Work can inspect attached files and create changes only through the shared runtime's workspace guards. Attachments outside this folder are rejected.")
                        .into_any_element(),
                    div()
                        .pt_3()
                        .border_t_1()
                        .border_color(cx.theme().border.opacity(0.68))
                        .into_any_element(),
                    self.settings_label("Project context directory"),
                    Input::new(&self.context_dir_input)
                        .aria_label("Project context directory")
                        .into_any_element(),
                    div()
                        .text_size(UI_CAPTION_SIZE)
                        .text_color(cx.theme().muted_foreground)
                        .child("Markdown files in this directory provide durable project knowledge.")
                        .into_any_element(),
                ],
                cx,
            ))
            .child(
                h_flex()
                    .w_full()
                    .justify_end()
                    .child(
                        Button::new("save-workspace-agent-settings")
                            .primary()
                            .small()
                            .label("Save Context")
                            .on_click(cx.listener(Self::save_agent_settings)),
                    ),
            )
            .into_any_element()
    }

    fn render_skills_settings(&self, cx: &mut Context<Self>) -> AnyElement {
        let rows = self
            .skills
            .iter()
            .cloned()
            .map(|skill| {
                let name = skill.name.clone();
                let remove_name = name.clone();
                let next_enabled = !skill.enabled;
                h_flex()
                    .w_full()
                    .items_center()
                    .justify_between()
                    .gap_3()
                    .py_2()
                    .border_b_1()
                    .border_color(cx.theme().border.opacity(0.48))
                    .child(
                        v_flex()
                            .flex_1()
                            .min_w_0()
                            .gap_0p5()
                            .child(
                                h_flex()
                                    .gap_2()
                                    .child(
                                        div()
                                            .text_size(UI_TEXT_SIZE)
                                            .font_medium()
                                            .child(skill.name),
                                    )
                                    .child(
                                        div()
                                            .px_2()
                                            .rounded_full()
                                            .text_size(px(10.))
                                            .bg(if skill.available {
                                                cx.theme().success.opacity(0.12)
                                            } else {
                                                cx.theme().warning.opacity(0.12)
                                            })
                                            .text_color(if skill.available {
                                                cx.theme().success
                                            } else {
                                                cx.theme().warning
                                            })
                                            .child(if skill.available {
                                                "READY"
                                            } else {
                                                "UNAVAILABLE"
                                            }),
                                    ),
                            )
                            .child(
                                div()
                                    .text_size(UI_CAPTION_SIZE)
                                    .text_color(cx.theme().muted_foreground)
                                    .child(skill.description),
                            )
                            .child(
                                h_flex()
                                    .gap_2()
                                    .text_size(px(10.))
                                    .text_color(cx.theme().muted_foreground)
                                    .child(format!("Source: {}", skill.source))
                                    .children(
                                        skill
                                            .version
                                            .filter(|version| !version.trim().is_empty())
                                            .map(|version| format!("Version: {version}")),
                                    ),
                            )
                            .children(skill.reason.map(|reason| {
                                div()
                                    .text_size(px(10.))
                                    .text_color(cx.theme().warning)
                                    .child(reason)
                            })),
                    )
                    .child(
                        h_flex()
                            .gap_2()
                            .child(
                                Button::new(format!("toggle-skill-{name}"))
                                    .outline()
                                    .small()
                                    .label(if skill.enabled { "Disable" } else { "Enable" })
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.set_skill_enabled(name.clone(), next_enabled, cx);
                                    })),
                            )
                            .child(
                                Button::new(format!("archive-skill-{remove_name}"))
                                    .ghost()
                                    .small()
                                    .label("Archive")
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.remove_skill(remove_name.clone(), cx);
                                    })),
                            ),
                    )
                    .into_any_element()
            })
            .collect::<Vec<_>>();

        v_flex()
            .w_full()
            .gap_4()
            .child(
                self.settings_page_header(
                    "Choose the Agent Skills available to new Work turns.",
                    cx,
                ),
            )
            .child(self.settings_group(
                vec![
                    v_flex()
                        .gap_2()
                        .child(div().text_size(UI_TEXT_SIZE).font_medium().child("Import or update"))
                        .child(Input::new(&self.skill_import_input).small())
                        .child(
                            div()
                                .text_size(UI_CAPTION_SIZE)
                                .text_color(cx.theme().muted_foreground)
                                .child("Local folders must contain SKILL.md. GitHub and ClawHub imports run existing security and compatibility checks."),
                        )
                        .child(
                            Button::new("import-skill")
                                .primary()
                                .small()
                                .disabled(self.skill_import_active)
                                .label(if self.skill_import_active { "Importing…" } else { "Import Skill" })
                                .on_click(cx.listener(|this, _, _, cx| this.import_skill(cx))),
                        )
                        .into_any_element(),
                ],
                cx,
            ))
            .child(self.settings_group(
                if rows.is_empty() {
                    vec![
                        div()
                            .text_size(UI_CAPTION_SIZE)
                            .text_color(cx.theme().muted_foreground)
                            .child("No skills are installed for this runtime.")
                            .into_any_element(),
                    ]
                } else {
                    rows
                },
                cx,
            ))
            .child(
                h_flex()
                    .w_full()
                    .items_center()
                    .justify_between()
                    .child(
                        div()
                            .text_size(UI_CAPTION_SIZE)
                            .text_color(if self.skills_message.starts_with("Could not") {
                                cx.theme().danger
                            } else {
                                cx.theme().muted_foreground
                            })
                            .child(self.skills_message.clone()),
                    )
                    .child(
                        Button::new("refresh-skills")
                            .ghost()
                            .small()
                            .label("Refresh")
                            .on_click(cx.listener(|this, _, _, cx| this.refresh_skills(cx))),
                    ),
            )
            .into_any_element()
    }

    fn render_settings_diagnostics(&self, cx: &mut Context<Self>) -> AnyElement {
        v_flex()
            .w_full()
            .gap_4()
            .child(self.settings_page_header(
                "Review local readiness without contacting external services.",
                cx,
            ))
            .child(
                self.settings_group(
                    self.diagnostics_report
                        .checks
                        .iter()
                        .map(|check| {
                            let (symbol, color) = match check.status {
                                DiagnosticStatus::Pass => ("✓", cx.theme().success),
                                DiagnosticStatus::Warning => ("!", cx.theme().warning),
                                DiagnosticStatus::Fail => ("×", cx.theme().danger),
                            };
                            h_flex()
                                .items_start()
                                .gap_3()
                                .py_1()
                                .child(
                                    div()
                                        .size(px(20.))
                                        .rounded_full()
                                        .bg(color.opacity(0.12))
                                        .text_color(color)
                                        .flex()
                                        .items_center()
                                        .justify_center()
                                        .text_size(UI_CAPTION_SIZE)
                                        .font_semibold()
                                        .child(symbol),
                                )
                                .child(
                                    v_flex()
                                        .flex_1()
                                        .gap_0p5()
                                        .child(
                                            div()
                                                .text_size(UI_TEXT_SIZE)
                                                .font_medium()
                                                .child(check.label),
                                        )
                                        .child(
                                            div()
                                                .text_size(UI_CAPTION_SIZE)
                                                .text_color(cx.theme().muted_foreground)
                                                .child(check.detail.clone()),
                                        ),
                                )
                                .into_any_element()
                        })
                        .collect(),
                    cx,
                ),
            )
            .child(
                h_flex()
                    .w_full()
                    .items_center()
                    .justify_between()
                    .child(
                        div()
                            .text_size(UI_CAPTION_SIZE)
                            .text_color(cx.theme().muted_foreground)
                            .child("Provider testing remains an explicit action under Models."),
                    )
                    .child(
                        h_flex()
                            .gap_2()
                            .child(
                                Button::new("settings-run-demo")
                                    .ghost()
                                    .small()
                                    .disabled(self.runtime_active)
                                    .label("Run UI Demo")
                                    .on_click(cx.listener(Self::start_demo)),
                            )
                            .child(
                                Button::new("settings-refresh-diagnostics")
                                    .outline()
                                    .small()
                                    .label("Run Checks")
                                    .on_click(cx.listener(Self::refresh_diagnostics)),
                            ),
                    ),
            )
            .into_any_element()
    }

    fn render_model_settings(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let content = match self.settings_section {
            SettingsSection::General => self.render_general_settings(cx),
            SettingsSection::Appearance => self.render_appearance_settings(cx),
            SettingsSection::Models => self.render_model_settings_content(cx),
            SettingsSection::Agent => self.render_agent_settings(cx),
            SettingsSection::Skills => self.render_skills_settings(cx),
            SettingsSection::Workspace => self.render_workspace_settings(cx),
            SettingsSection::Diagnostics => self.render_settings_diagnostics(cx),
        };

        h_flex()
            .size_full()
            .bg(cx.theme().background)
            .text_color(cx.theme().foreground)
            .text_size(UI_TEXT_SIZE)
            .child(self.render_settings_navigation(cx))
            .child(
                v_flex()
                    .flex_1()
                    .min_w_0()
                    .h_full()
                    .child(
                        h_flex()
                            .h(px(52.))
                            .flex_shrink_0()
                            .items_center()
                            .justify_end()
                            .px_5()
                            .border_b_1()
                            .border_color(cx.theme().border.opacity(0.68))
                            .child(
                                Button::new("close-model-settings")
                                    .ghost()
                                    .small()
                                    .disabled(self.connection_test_active)
                                    .label("Done")
                                    .on_click(cx.listener(Self::close_model_settings)),
                            ),
                    )
                    .child(
                        v_flex()
                            .flex_1()
                            .min_h_0()
                            .items_center()
                            .overflow_y_scrollbar()
                            .px_6()
                            .py_5()
                            .child(
                                div()
                                    .w_full()
                                    .max_w(SETTINGS_CONTENT_WIDTH)
                                    .pb_6()
                                    .child(content),
                            ),
                    ),
            )
    }

    fn render_diagnostics(&self, cx: &mut Context<Self>) -> impl IntoElement {
        v_flex()
            .size_full()
            .items_center()
            .bg(cx.theme().background)
            .text_color(cx.theme().foreground)
            .p_8()
            .gap_5()
            .child(
                h_flex()
                    .w(px(860.))
                    .justify_between()
                    .items_center()
                    .child(
                        v_flex()
                            .gap_1()
                            .child(div().text_2xl().font_bold().child("Diagnostics"))
                            .child(
                                div()
                                    .text_sm()
                                    .text_color(cx.theme().muted_foreground)
                                    .child("Check whether this desktop can safely start and persist a Work conversation."),
                            ),
                    )
                    .child(
                        Button::new("close-diagnostics")
                            .outline()
                            .disabled(self.connection_test_active || self.first_response_active)
                            .label("Back to Work")
                            .on_click(cx.listener(Self::close_diagnostics)),
                    ),
            )
            .child(
                h_flex()
                    .w(px(860.))
                    .gap_3()
                    .child(
                        div()
                            .px_3()
                            .py_1()
                            .rounded_full()
                            .bg(if self.diagnostics_report.ready {
                                cx.theme().success.opacity(0.16)
                            } else {
                                cx.theme().danger.opacity(0.16)
                            })
                            .child(if self.diagnostics_report.ready {
                                "Local runtime ready"
                            } else {
                                "Action required"
                            }),
                    )
                    .child(
                        Button::new("refresh-diagnostics")
                            .outline()
                            .disabled(self.connection_test_active || self.first_response_active)
                            .label("Run Again")
                            .on_click(cx.listener(Self::refresh_diagnostics)),
                    )
                    .child(
                        Button::new("diagnostics-model-settings")
                            .outline()
                            .disabled(self.connection_test_active || self.first_response_active)
                            .label("Model Settings")
                            .on_click(cx.listener(Self::open_model_settings)),
                    )
                    .child(
                        Button::new("diagnostics-provider-test")
                            .primary()
                            .disabled(
                                self.connection_test_active
                                    || self.first_response_active
                                    || !self.runtime_config.ready,
                            )
                            .label(if self.connection_test_active {
                                "Testing Provider…"
                            } else {
                                "Test Provider"
                            })
                            .on_click(cx.listener(Self::test_provider_connection)),
                    )
                    .child(
                        Button::new("diagnostics-first-response")
                            .primary()
                            .disabled(
                                self.connection_test_active
                                    || self.first_response_active
                                    || !self.diagnostics_report.ready,
                            )
                            .label(if self.first_response_active {
                                "Running First Response…"
                            } else {
                                "Run First Response"
                            })
                            .on_click(cx.listener(Self::test_first_response)),
                    ),
            )
            .child(
                v_flex()
                    .w(px(860.))
                    .gap_3()
                    .children(self.diagnostics_report.checks.iter().map(|check| {
                        let (status, color) = match check.status {
                            DiagnosticStatus::Pass => ("Pass", cx.theme().success),
                            DiagnosticStatus::Warning => ("Warning", cx.theme().warning),
                            DiagnosticStatus::Fail => ("Fail", cx.theme().danger),
                        };
                        h_flex()
                            .items_start()
                            .gap_3()
                            .p_4()
                            .rounded(cx.theme().radius)
                            .bg(cx.theme().secondary.opacity(0.25))
                            .border_1()
                            .border_color(cx.theme().border)
                            .child(
                                div()
                                    .w(px(94.))
                                    .px_2()
                                    .py_1()
                                    .rounded_full()
                                    .bg(color.opacity(0.14))
                                    .text_xs()
                                    .font_bold()
                                    .text_color(color)
                                    .child(status),
                            )
                            .child(
                                v_flex()
                                    .flex_1()
                                    .gap_1()
                                    .child(div().text_sm().font_bold().child(check.label))
                                    .child(
                                        div()
                                            .text_sm()
                                            .text_color(cx.theme().muted_foreground)
                                            .child(check.detail.clone()),
                                    ),
                            )
                    })),
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
            .child(
                div()
                    .text_sm()
                    .text_color(if self.first_response_message.starts_with("First response passed") {
                        cx.theme().success
                    } else if self.first_response_message.contains("failed") {
                        cx.theme().danger
                    } else {
                        cx.theme().muted_foreground
                    })
                    .child(self.first_response_message.clone()),
            )
            .child(
                div()
                    .text_xs()
                    .text_color(cx.theme().muted_foreground)
                    .child("Local checks are offline. Test Provider is the explicit network and authentication probe."),
            )
    }
}

impl Render for WorkApp {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        if self.settings_open {
            return div()
                .size_full()
                .key_context(WORK_KEY_CONTEXT)
                .on_action(cx.listener(Self::new_chat_action))
                .on_action(cx.listener(Self::focus_composer_action))
                .on_action(cx.listener(Self::open_model_settings_action))
                .on_action(cx.listener(Self::open_diagnostics_action))
                .child(self.render_model_settings(cx))
                .into_any_element();
        }
        if self.diagnostics_open {
            return div()
                .size_full()
                .key_context(WORK_KEY_CONTEXT)
                .on_action(cx.listener(Self::new_chat_action))
                .on_action(cx.listener(Self::focus_composer_action))
                .on_action(cx.listener(Self::open_model_settings_action))
                .on_action(cx.listener(Self::open_diagnostics_action))
                .child(self.render_diagnostics(cx))
                .into_any_element();
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
        let status_color = if conversation_is_empty {
            cx.theme().success
        } else {
            match self.session.status {
                WorkStatus::Completed => cx.theme().success,
                WorkStatus::Failed | WorkStatus::Cancelled | WorkStatus::Interrupted => {
                    cx.theme().danger
                }
                WorkStatus::Planning
                | WorkStatus::Running
                | WorkStatus::AwaitingApproval
                | WorkStatus::Verifying => cx.theme().warning,
            }
        };
        let session_query = self
            .session_search_input
            .read(cx)
            .value()
            .trim()
            .to_lowercase();
        let recent_sessions = self
            .recent_sessions
            .iter()
            .filter(|summary| summary.matches_query(&session_query))
            .take(50)
            .cloned()
            .collect::<Vec<_>>();
        let has_session_results = !recent_sessions.is_empty();
        let process_activities = self.session.process_activities.clone();
        let file_changes = self.session.file_changes.clone();
        let subagents = self.durable_subagents.clone();
        let has_inspector_content = !self.session.plan.is_empty()
            || !process_activities.is_empty()
            || !file_changes.is_empty()
            || !subagents.is_empty();
        let selected_file_change = self.session.selected_file_change().cloned();
        let review_status = self.session.review_status;
        let inline_approval = self.session.pending_approval.clone();
        let message_count = self.session.messages.len();
        let visible_message_start = message_count.saturating_sub(self.visible_message_limit);
        let messages = self
            .session
            .messages
            .iter()
            .skip(visible_message_start)
            .cloned()
            .collect::<Vec<_>>();
        let assistant_draft = self.session.assistant_draft.clone();
        let composer_attachments = self.session.composer_attachments.clone();
        let retryable = matches!(
            self.session.status,
            WorkStatus::Interrupted | WorkStatus::Failed | WorkStatus::Cancelled
        );
        let composer_input = if self.runtime_active {
            &self.steer_input
        } else {
            &self.task_input
        };
        let using_work_home = Path::new(&self.session.workspace) == self.work_home;
        let workspace_label = if using_work_home {
            "Work Home".to_string()
        } else if self.session.workspace.is_empty() {
            "No folder selected".to_string()
        } else {
            self.session.workspace.clone()
        };
        let work_view = cx.entity();
        let viewport_width = window.viewport_size().width;
        let sidebar_width = sidebar_width_for(viewport_width);
        let show_inspector =
            self.inspector_open && has_inspector_content && inspector_fits(viewport_width);

        h_flex()
            .size_full()
            .key_context(WORK_KEY_CONTEXT)
            .on_action(cx.listener(Self::new_chat_action))
            .on_action(cx.listener(Self::focus_composer_action))
            .on_action(cx.listener(Self::open_model_settings_action))
            .on_action(cx.listener(Self::open_diagnostics_action))
            .bg(cx.theme().background)
            .text_color(cx.theme().foreground)
            .child(
                v_flex()
                    .w(sidebar_width)
                    .h_full()
                    .p_3()
                    .gap_2()
                    .text_size(UI_TEXT_SIZE)
                    .bg(cx.theme().secondary.opacity(0.26))
                    .border_r_1()
                    .border_color(cx.theme().border)
                    .child(
                        h_flex()
                            .items_center()
                            .gap_2()
                            .px_1()
                            .py_1()
                            .child(img(work_logo()).size(px(28.)))
                            .child(
                                v_flex()
                                    .gap_0p5()
                                    .child(div().text_sm().font_semibold().child("MicroClaw"))
                                    .child(
                                        div()
                                            .text_size(px(10.))
                                            .text_color(cx.theme().muted_foreground)
                                            .child("WORK"),
                                    ),
                            ),
                    )
                    .child(
                        Button::new("new-session")
                            .primary()
                            .small()
                            .w_full()
                            .disabled(self.runtime_active)
                            .label("+  New chat")
                            .on_click(cx.listener(Self::new_session)),
                    )
                    .child(
                        div()
                            .mt_2()
                            .px_1()
                            .text_size(px(11.))
                            .font_semibold()
                            .text_color(cx.theme().muted_foreground)
                            .child("RECENT"),
                    )
                    .child(
                        Input::new(&self.session_search_input)
                            .small()
                            .cleanable(true)
                            .aria_label("Search conversations"),
                    )
                    .child(
                        v_flex()
                            .flex_1()
                            .min_h_0()
                            .overflow_y_scrollbar()
                            .gap_1()
                            .children((!has_session_results).then(|| {
                                div()
                                    .px_2()
                                    .py_3()
                                    .text_size(px(11.))
                                    .text_color(cx.theme().muted_foreground)
                                    .child(if session_query.is_empty() {
                                        "No conversations yet"
                                    } else {
                                        "No matching conversations"
                                    })
                            }))
                            .children(recent_sessions.into_iter().map(|summary| {
                                let session_id = summary.session_id.clone();
                                let pinned = summary.pinned;
                                let is_active = session_id == self.session.session_id;
                                let title = if summary.task.trim().is_empty() {
                                    "New conversation".to_string()
                                } else {
                                    summary.task.chars().take(54).collect()
                                };
                                let summary_status = if summary.task.trim().is_empty() {
                                    "Ready"
                                } else {
                                    work_status_label(summary.status)
                                };
                                let summary_status_color = match summary.status {
                                    WorkStatus::Completed => cx.theme().success,
                                    WorkStatus::Failed
                                    | WorkStatus::Cancelled
                                    | WorkStatus::Interrupted => cx.theme().danger,
                                    WorkStatus::Planning
                                    | WorkStatus::Running
                                    | WorkStatus::AwaitingApproval
                                    | WorkStatus::Verifying => cx.theme().warning,
                                };
                                BaseButton::new(format!("session-{session_id}"))
                                    .w_full()
                                    .min_w_0()
                                    .h(px(28.))
                                    .px_1()
                                    .gap_2()
                                    .items_center()
                                    .justify_start()
                                    .rounded(cx.theme().radius)
                                    .disabled(self.runtime_active)
                                    .accessibility_label(format!(
                                        "{title}, {summary_status}"
                                    ))
                                    .when(is_active, |button| {
                                        button.bg(cx.theme().accent.opacity(0.12))
                                    })
                                    .hover(|style| style.bg(cx.theme().accent.opacity(0.08)))
                                    .child(
                                        div()
                                            .size(px(6.))
                                            .flex_shrink_0()
                                            .rounded_full()
                                            .bg(summary_status_color.opacity(if is_active {
                                                1.0
                                            } else {
                                                0.62
                                            })),
                                    )
                                    .child(
                                        div()
                                            .flex_1()
                                            .min_w_0()
                                            .overflow_hidden()
                                            .text_ellipsis()
                                            .whitespace_nowrap()
                                            .text_size(px(12.))
                                            .font_weight(if is_active {
                                                FontWeight::SEMIBOLD
                                            } else {
                                                FontWeight::NORMAL
                                            })
                                            .child(title),
                                    )
                                    .children(pinned.then(|| {
                                        div()
                                            .flex_shrink_0()
                                            .text_size(px(10.))
                                            .font_semibold()
                                            .text_color(cx.theme().muted_foreground)
                                            .child("◆")
                                    }))
                                    .on_click(cx.listener(move |this, _, window, cx| {
                                        this.open_session(&session_id, window, cx);
                                    }))
                                    .context_menu({
                                        let work_view = work_view.clone();
                                        let pin_session_id = summary.session_id.clone();
                                        move |menu, window, _| {
                                            let pin_session_id = pin_session_id.clone();
                                            menu.item(
                                                PopupMenuItem::new(if pinned {
                                                    "Unpin conversation"
                                                } else {
                                                    "Pin conversation"
                                                })
                                                .on_click(window.listener_for(
                                                    &work_view,
                                                    move |this, _, _, cx| {
                                                        this.set_session_pinned(
                                                            &pin_session_id,
                                                            !pinned,
                                                            cx,
                                                        );
                                                    },
                                                )),
                                            )
                                        }
                                    })
                            })),
                    )
                    .child(
                        v_flex()
                            .gap_2()
                            .px_1()
                            .pt_3()
                            .border_t_1()
                            .border_color(cx.theme().border.opacity(0.72))
                            .child(
                                h_flex()
                                    .items_center()
                                    .justify_between()
                                    .child(
                                        div()
                                            .text_size(px(10.))
                                            .font_semibold()
                                            .text_color(cx.theme().muted_foreground)
                                            .child("WORKSPACE"),
                                    )
                                    .child(
                                        div()
                                            .size(px(6.))
                                            .rounded_full()
                                            .bg(if self.runtime_config.ready {
                                                cx.theme().success
                                            } else {
                                                cx.theme().warning
                                            }),
                                    ),
                            )
                            .child(
                                div()
                                    .w_full()
                                    .overflow_hidden()
                                    .text_ellipsis()
                                    .whitespace_nowrap()
                                    .text_size(px(12.))
                                    .font_medium()
                                    .child(if using_work_home {
                                        workspace_label.clone()
                                    } else {
                                        self.workspace_context.name.clone()
                                    }),
                            )
                            .children((!using_work_home && !self.session.workspace.is_empty()).then(|| {
                                div()
                                    .w_full()
                                    .overflow_hidden()
                                    .text_ellipsis()
                                    .whitespace_nowrap()
                                    .text_size(px(10.))
                                    .text_color(cx.theme().muted_foreground)
                                    .child(self.workspace_context.subtitle())
                            }))
                            .child(
                                div()
                                    .w_full()
                                    .overflow_hidden()
                                    .text_ellipsis()
                                    .whitespace_nowrap()
                                    .text_size(px(10.))
                                    .text_color(cx.theme().muted_foreground)
                                    .child("Access: current folder only"),
                            )
                            .child(
                                Button::new("choose-workspace")
                                    .ghost()
                                    .small()
                                    .w_full()
                                    .disabled(self.runtime_active)
                                    .label(if using_work_home {
                                        "▱  Connect Project Folder"
                                    } else {
                                        "▱  Change Folder"
                                    })
                                    .on_click(cx.listener(Self::choose_workspace)),
                            )
                            .child(
                                h_flex()
                                    .gap_1()
                                    .child(
                                        Button::new("diagnostics")
                                            .ghost()
                                            .xsmall()
                                            .compact()
                                            .flex_1()
                                            .disabled(self.runtime_active)
                                            .label("✓  Diagnostics")
                                            .on_click(cx.listener(Self::open_diagnostics)),
                                    )
                                    .child(
                                        Button::new("model-settings")
                                            .ghost()
                                            .xsmall()
                                            .compact()
                                            .flex_1()
                                            .disabled(self.runtime_active)
                                            .label("⚙  Settings")
                                            .on_click(cx.listener(Self::open_model_settings)),
                                    ),
                            )
                            .child(
                                div()
                                    .w_full()
                                    .overflow_hidden()
                                    .text_ellipsis()
                                    .whitespace_nowrap()
                                    .text_size(px(10.))
                                    .text_color(cx.theme().muted_foreground)
                                    .child(format!(
                                        "{} · {}",
                                        self.runtime_config.provider, self.runtime_config.model
                                    )),
                            )
                            .children((!self.runtime_config.ready).then(|| {
                                div()
                                    .text_size(px(10.))
                                    .text_color(cx.theme().warning)
                                    .child("Model setup required")
                            })),
                    ),
            )
            .child(
                v_flex()
                    .flex_1()
                    .min_w_0()
                    .h_full()
                    .items_center()
                    .p_4()
                    .text_size(UI_TEXT_SIZE)
                    .gap_3()
                    .child(
                        h_flex()
                            .w_full()
                            .items_center()
                            .gap_3()
                            .child(
                                v_flex()
                                    .flex_1()
                                    .min_w_0()
                                    .overflow_hidden()
                                    .gap_1()
                                    .child(
                                        div()
                                            .w_full()
                                            .overflow_hidden()
                                            .text_ellipsis()
                                            .text_base()
                                            .font_semibold()
                                            .child(if self.session.title.trim().is_empty() {
                                                "New conversation".to_string()
                                            } else {
                                                trim_text(&self.session.title, 72)
                                            }),
                                    )
                                    .child(
                                        div()
                                            .w_full()
                                            .overflow_hidden()
                                            .text_ellipsis()
                                            .text_size(px(11.))
                                            .text_color(cx.theme().muted_foreground)
                                            .child(if using_work_home {
                                                "Chat in Work Home, or connect a project folder when local context is needed".to_string()
                                            } else if self.session.workspace.is_empty() {
                                                "Select a folder before starting this conversation".to_string()
                                            } else {
                                                format!("Working in {}", self.session.workspace)
                                            }),
                                    ),
                            )
                            .child(
                                h_flex()
                                    .flex_shrink_0()
                                    .gap_2()
                                    .child(
                                        div()
                                            .px_2()
                                            .py_1()
                                            .rounded_full()
                                            .bg(status_color.opacity(0.14))
                                            .text_color(status_color)
                                            .text_size(px(11.))
                                            .child(status),
                                    )
                                    .children(has_inspector_content.then(|| {
                                        Button::new("toggle-inspector")
                                            .outline()
                                        .label(if show_inspector {
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
                            .w_full()
                            .flex_1()
                            .min_h_0()
                            .gap_3()
                            .child(
                                v_flex()
                                    .flex_1()
                                    .min_w_0()
                                    .min_h_0()
                                    .items_center()
                                    .overflow_y_scrollbar()
                                    .gap_3()
                                    .px_4()
                                    .py_3()
                                    .children(messages.is_empty().then(|| {
                                        v_flex()
                                            .flex_1()
                                            .items_center()
                                            .justify_center()
                                            .gap_3()
                                            .p_6()
                                            .child(img(work_logo()).size(px(46.)))
                                            .child(
                                                div()
                                            .text_size(UI_PAGE_TITLE_SIZE)
                                                    .font_semibold()
                                                    .child("What would you like to get done?"),
                                            )
                                            .child(
                                                div()
                                                    .max_w(px(560.))
                                                    .text_center()
                                                    .text_size(px(12.))
                                                    .text_color(cx.theme().muted_foreground)
                                                    .child(if self.runtime_config.ready {
                                                        "Ask MicroClaw to research, create, organize, or automate work. Work Home is ready; connect a project folder only when you need its files."
                                                    } else {
                                                        "Connect a model once, then start chatting. A private Work Home is already available for files and artifacts."
                                                    }),
                                            )
                                            .children(self.runtime_config.ready.then(|| {
                                                h_flex()
                                                    .gap_2()
                                                    .child(
                                                        Button::new("starter-plan")
                                                            .outline()
                                                            .label("Plan a feature")
                                                            .on_click(cx.listener(
                                                                |this, _, window, cx| {
                                                                    this.use_starter_prompt(
                                                                        "Help me plan and implement a feature in this workspace.",
                                                                        window,
                                                                        cx,
                                                                    );
                                                                },
                                                            )),
                                                    )
                                                    .child(
                                                        Button::new("starter-review")
                                                            .outline()
                                                            .label("Review this workspace")
                                                            .on_click(cx.listener(
                                                                |this, _, window, cx| {
                                                                    this.use_starter_prompt(
                                                                        "Review this workspace and identify the highest-impact improvements.",
                                                                        window,
                                                                        cx,
                                                                    );
                                                                },
                                                            )),
                                                    )
                                                    .child(
                                                        Button::new("starter-research")
                                                            .outline()
                                                            .label("Research a topic")
                                                            .on_click(cx.listener(
                                                                |this, _, window, cx| {
                                                                    this.use_starter_prompt(
                                                                        "Research a topic with me and produce a concise, evidence-backed brief.",
                                                                        window,
                                                                        cx,
                                                                    );
                                                                },
                                                            )),
                                                    )
                                            }))
                                            .child(
                                                h_flex()
                                                    .gap_2()
                                                    .children((!self.runtime_config.ready).then(|| {
                                                        Button::new("empty-model-settings")
                                                            .primary()
                                                            .disabled(self.runtime_active)
                                                            .label("Configure Model")
                                                            .on_click(cx.listener(Self::open_model_settings))
                                                    }))
                                                    .child(
                                                        Button::new("empty-choose-workspace")
                                                            .outline()
                                                            .disabled(self.runtime_active)
                                                            .label("Connect Project Folder")
                                                            .on_click(cx.listener(Self::choose_workspace)),
                                                    ),
                                            )
                                    }))
                                    .children((visible_message_start > 0).then(|| {
                                        Button::new("show-earlier-messages")
                                            .outline()
                                            .small()
                                            .label(format!(
                                                "Show {} earlier messages",
                                                visible_message_start.min(MESSAGE_LOAD_BATCH)
                                            ))
                                            .on_click(cx.listener(Self::show_earlier_messages))
                                    }))
                                    .children(messages.into_iter().enumerate().map(
                                        |(message_index, message)| {
                                        let message_index = message_index + visible_message_start;
                                        let is_user = message.role == ConversationRole::User;
                                        let speaker = if is_user { "You" } else { "MicroClaw" };
                                        let accessibility_label =
                                            format!("{speaker}: {}", message.content);
                                        let row = h_flex().w_full().max_w(CONTENT_MAX_WIDTH);
                                        let row = if is_user { row.justify_end() } else { row };
                                        row.child(
                                                v_flex()
                                                    .id(("conversation-message", message_index))
                                                    .role(Role::Paragraph)
                                                    .aria_label(accessibility_label)
                                                    .max_w(px(if is_user { 560. } else { 720. }))
                                                    .gap_1()
                                                    .px_3()
                                                    .py_2()
                                                    .rounded(px(9.))
                                                    .bg(if is_user {
                                                        cx.theme().accent
                                                    } else {
                                                        cx.theme().background
                                                    })
                                                    .border_1()
                                                    .border_color(if is_user {
                                                        cx.theme().accent
                                                    } else {
                                                        cx.theme().background
                                                    })
                                                    .child(
                                                        div()
                                                            .text_size(UI_CAPTION_SIZE)
                                                            .font_semibold()
                                                            .child(speaker),
                                                    )
                                                    .child(message.content)
                                                    .children(message.attachments.into_iter().enumerate().map(|(attachment_index, attachment)| {
                                                        let path = attachment.path.clone();
                                                        Button::new((
                                                            "message-attachment",
                                                            message_index
                                                                .saturating_mul(8)
                                                                .saturating_add(attachment_index),
                                                        ))
                                                            .ghost()
                                                            .xsmall()
                                                            .compact()
                                                            .label(format!("▱  {}", attachment.path))
                                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                                this.open_artifact(&path, cx);
                                                            }))
                                                    })),
                                            )
                                        },
                                    ))
                                    .children((!assistant_draft.is_empty()).then(|| {
                                        let accessibility_label =
                                            format!("MicroClaw working: {assistant_draft}");
                                        v_flex()
                                            .id("assistant-draft")
                                            .role(Role::Status)
                                            .aria_label(accessibility_label)
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
                                            .id("inline-approval")
                                            .role(Role::Alert)
                                            .aria_label(format!(
                                                "Approval required for {}: {}",
                                                approval.tool, approval.reason
                                            ))
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
                                                        move |this, _, window, cx| {
                                                            this.resolve_approval(
                                                                value.clone(),
                                                                window,
                                                                cx,
                                                            );
                                                        },
                                                    ))
                                                }),
                                            ))
                                    })),
                            )
                            .children(show_inspector.then(|| {
                                v_flex()
                                    .w(px(360.))
                                    .flex_shrink_0()
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
                                                let run_id = agent.run_id.clone();
                                                let active = matches!(agent.status.as_str(), "accepted" | "queued" | "running") && !agent.cancel_requested;
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
                                                                    .child(format!(
                                                                        "{} · {}",
                                                                        trim_text(&agent.run_id, 28),
                                                                        format_elapsed(agent.elapsed_seconds)
                                                                    )),
                                                            )
                                                            .child(div().text_xs().child(trim_text(&agent.task, 180)))
                                                            .children(agent.progress.map(|progress| div().text_xs().text_color(cx.theme().muted_foreground).child(progress)))
                                                            .children(agent.result.map(|result| div().text_xs().child(trim_text(&result, 180))))
                                                            .children(agent.error.map(|error| div().text_xs().text_color(cx.theme().danger).child(trim_text(&error, 180)))),
                                                    )
                                                    .child(
                                                        v_flex()
                                                            .items_end()
                                                            .gap_1()
                                                            .child(div().px_2().py_1().rounded_full().bg(cx.theme().accent).text_xs().child(agent.status))
                                                            .children(active.then(|| Button::new(format!("cancel-subagent-{run_id}")).danger().xsmall().label("Cancel").on_click(cx.listener(move |this, _, _, cx| this.cancel_subagent(run_id.clone(), cx))))),
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
                                            .child(
                                                v_flex()
                                                    .gap_2()
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
                                                        h_flex()
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
                                                let diff_line_count = change.diff.lines().count();
                                                let diff_preview_truncated =
                                                    diff_line_count > MAX_VISIBLE_DIFF_LINES;
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
                                                            .children(change.diff.lines().take(MAX_VISIBLE_DIFF_LINES).map(str::to_owned).map(|line| {
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
                                                            }))
                                                            .children(diff_preview_truncated.then(|| {
                                                                div()
                                                                    .px_2()
                                                                    .py_2()
                                                                    .border_t_1()
                                                                    .border_color(cx.theme().border)
                                                                    .text_color(cx.theme().muted_foreground)
                                                                    .child(format!(
                                                                        "Previewing the first {MAX_VISIBLE_DIFF_LINES} of {diff_line_count} lines. Open the file for the complete result."
                                                                    ))
                                                            })),
                                                    )
                                            }))
                                            .children(file_changes.is_empty().then(|| {
                                                div()
                                                    .text_sm()
                                                    .text_color(cx.theme().muted_foreground)
                                                    .child("No workspace changes yet.")
                                            }))
                                    )
                            })),
                    )
                    .child(
                        v_flex()
                            .w_full()
                            .max_w(CONTENT_MAX_WIDTH)
                            .gap_3()
                            .p_3()
                            .rounded(px(10.))
                            .bg(cx.theme().secondary.opacity(0.28))
                            .border_1()
                            .border_color(cx.theme().border)
                            .group("composer-drop")
                            .group_drag_over::<ExternalPaths>("composer-drop", |style| {
                                style.border_color(cx.theme().accent).bg(cx.theme().accent.opacity(0.08))
                            })
                            .on_drop(cx.listener(Self::handle_attachment_drop))
                            .children((!composer_attachments.is_empty()).then(|| {
                                h_flex()
                                    .w_full()
                                    .gap_1()
                                    .flex_wrap()
                                    .children(composer_attachments.into_iter().enumerate().map(|(attachment_index, attachment)| {
                                        let path = attachment.path.clone();
                                        Button::new(("composer-attachment", attachment_index))
                                            .ghost()
                                            .xsmall()
                                            .compact()
                                            .label(format!("▱  {}  ×", attachment.path))
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                this.remove_attachment(&path, cx);
                                            }))
                                    }))
                            }))
                            .child(
                                div()
                                    .min_h(px(44.))
                                    .child(
                                        Textarea::new(composer_input)
                                            .aria_label(if self.runtime_active {
                                                "Guidance for the active Work task"
                                            } else {
                                                "Message MicroClaw Work"
                                            }),
                                    ),
                            )
                            .child(
                                h_flex()
                                    .items_center()
                                    .justify_between()
                                    .child(
                                        h_flex()
                                            .gap_2()
                                            .child(
                                                Button::new("attach-workspace-files")
                                                    .ghost()
                                                    .xsmall()
                                                    .compact()
                                                    .disabled(
                                                        self.runtime_active
                                                            || self.session.workspace.is_empty(),
                                                    )
                                                    .label("＋ Attach")
                                                    .on_click(cx.listener(Self::choose_attachments)),
                                            )
                                            .child(
                                                div()
                                                    .px_2()
                                                    .py_1()
                                                    .rounded_full()
                                                    .bg(cx.theme().accent)
                                                    .text_xs()
                                                    .child(if using_work_home {
                                                        "Work Home"
                                                    } else if self.session.workspace.is_empty() {
                                                        "No workspace"
                                                    } else {
                                                        "Project connected"
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
                                                Button::new("stop-runtime")
                                                    .ghost()
                                                    .small()
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
                                                    .small()
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

fn format_elapsed(seconds: u64) -> String {
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 3600 {
        format!("{}m {}s", seconds / 60, seconds % 60)
    } else {
        format!("{}h {}m", seconds / 3600, (seconds % 3600) / 60)
    }
}

fn inspect_workspace(workspace: &Path) -> WorkspaceContext {
    let name = workspace
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("Workspace")
        .to_string();
    let dot_git = workspace.join(".git");
    let git_dir = if dot_git.is_dir() {
        Some(dot_git)
    } else if dot_git.is_file() {
        fs::read_to_string(&dot_git).ok().and_then(|contents| {
            contents
                .trim()
                .strip_prefix("gitdir:")
                .map(str::trim)
                .map(PathBuf::from)
                .map(|path| {
                    if path.is_absolute() {
                        path
                    } else {
                        workspace.join(path)
                    }
                })
        })
    } else {
        None
    };
    let branch = git_dir.as_ref().and_then(|git_dir| {
        fs::read_to_string(git_dir.join("HEAD"))
            .ok()
            .and_then(|head| {
                head.trim()
                    .strip_prefix("ref: refs/heads/")
                    .map(str::to_string)
            })
    });
    WorkspaceContext {
        name,
        branch,
        is_repository: git_dir.is_some(),
    }
}

fn work_data_root() -> PathBuf {
    resolve_work_data_root(
        std::env::var_os("MICROCLAW_WORK_DATA_DIR"),
        dirs::data_local_dir(),
        std::env::temp_dir(),
    )
}

fn resolve_work_data_root(
    override_path: Option<std::ffi::OsString>,
    platform_data_dir: Option<PathBuf>,
    temporary_dir: PathBuf,
) -> PathBuf {
    override_path
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            platform_data_dir
                .unwrap_or(temporary_dir)
                .join("microclaw-work")
        })
}

fn open_work_window(cx: &mut App) {
    if !cx.windows().is_empty() {
        cx.activate(true);
        return;
    }
    let options = WindowOptions {
        window_bounds: Some(WindowBounds::centered(size(px(1180.), px(760.)), cx)),
        ..Default::default()
    };
    cx.spawn(async move |cx| {
        cx.open_window(options, |window, cx| {
            let view = cx.new(|cx| WorkApp::new(window, cx));
            let appearance_subscription = window.observe_window_appearance(|window, cx| {
                if *cx.global::<AppearancePreference>() == AppearancePreference::System {
                    Theme::sync_system_appearance(Some(window), cx);
                }
            });
            view.update(cx, |view, _| {
                view._subscriptions.push(appearance_subscription);
            });
            cx.new(|cx| Root::new(view, window, cx))
        })
        .expect("failed to open MicroClaw Work window");
    })
    .detach();
}

fn main() {
    let application = gpui_platform::application();
    application.on_reopen(open_work_window);
    application.run(move |cx| {
        gpui_component::init(cx);
        configure_native_application(cx);
        open_work_window(cx);
    });
}

#[cfg(test)]
mod tests {
    use super::{
        SettingsSection, format_elapsed, inspect_workspace, inspector_fits, resolve_work_data_root,
        sidebar_width_for,
    };
    use gpui::px;
    use std::ffi::OsString;
    use std::path::PathBuf;

    #[test]
    fn work_data_root_prefers_a_nonempty_explicit_directory() {
        assert_eq!(
            resolve_work_data_root(
                Some(OsString::from("/private/tmp/isolated-work")),
                Some(PathBuf::from("/platform-data")),
                PathBuf::from("/temporary"),
            ),
            PathBuf::from("/private/tmp/isolated-work")
        );
    }

    #[test]
    fn work_data_root_uses_platform_or_temporary_fallback() {
        assert_eq!(
            resolve_work_data_root(
                Some(OsString::new()),
                Some(PathBuf::from("/platform-data")),
                PathBuf::from("/temporary"),
            ),
            PathBuf::from("/platform-data/microclaw-work")
        );
        assert_eq!(
            resolve_work_data_root(None, None, PathBuf::from("/temporary")),
            PathBuf::from("/temporary/microclaw-work")
        );
    }

    #[test]
    fn settings_navigation_is_complete_and_defaults_to_models() {
        let titles = SettingsSection::ALL
            .into_iter()
            .map(|(_, title, _)| title)
            .collect::<Vec<_>>();

        assert_eq!(SettingsSection::default(), SettingsSection::Models);
        assert_eq!(titles.len(), 7);
        assert_eq!(
            titles,
            [
                "General",
                "Appearance",
                "Models",
                "Agent",
                "Skills",
                "Workspace",
                "Diagnostics",
            ]
        );
    }

    #[test]
    fn desktop_layout_adapts_to_supported_window_widths() {
        assert_eq!(sidebar_width_for(px(900.)), px(224.));
        assert_eq!(sidebar_width_for(px(1_280.)), px(242.));
        assert!(!inspector_fits(px(900.)));
        assert!(inspector_fits(px(1_280.)));
    }

    #[test]
    fn subagent_elapsed_time_is_compact() {
        assert_eq!(format_elapsed(9), "9s");
        assert_eq!(format_elapsed(125), "2m 5s");
        assert_eq!(format_elapsed(7_320), "2h 2m");
    }

    #[test]
    fn workspace_context_identifies_git_branch_without_running_git() {
        let workspace = tempfile::tempdir().unwrap();
        std::fs::create_dir(workspace.path().join(".git")).unwrap();
        std::fs::write(
            workspace.path().join(".git/HEAD"),
            "ref: refs/heads/feature/work\n",
        )
        .unwrap();

        let context = inspect_workspace(workspace.path());
        assert!(context.is_repository);
        assert_eq!(context.branch.as_deref(), Some("feature/work"));
        assert_eq!(context.subtitle(), "Git · feature/work");
    }
}
