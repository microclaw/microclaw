//! One open project: header (mode, model, sandbox), banners (trust, lock),
//! the conversation and the composer.

use std::rc::Rc;
use std::time::Instant;

use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::input::{InputEvent, Textarea, TextareaState};
use gpui_kit::component::message_scroller::{MessageScroller, MessageScrollerState};
use gpui_kit::component::select::{Select, SelectEvent, SelectState};
use gpui_kit::component::{ActiveTheme as _, Disableable as _, Sizable as _, h_flex, v_flex};
use gpui_kit::prelude::*;
use gpui_kit::*;
use microclaw_code_core::project::Mode;
use microclaw_code_core::sessions::SessionRecord;
use tokio::sync::mpsc::UnboundedSender;

use super::onboarding::{Onboarding, OnboardingDone};
use super::{AppContext, CycleMode, NewSession, Stop};
use crate::service::{self, Command, Event, ProjectInfo};
use crate::state::{Item, Tone, Transcript};

/// Where the project is in starting up.
#[derive(Debug, Clone, PartialEq)]
enum Phase {
    Loading,
    NeedsSetup,
    Starting,
    Ready,
    Failed(String),
}

pub struct ProjectView {
    commands: UnboundedSender<Command>,
    stopped: Option<tokio::sync::oneshot::Receiver<()>>,
    phase: Phase,
    pub info: Option<ProjectInfo>,
    transcript: Transcript,
    /// What the list renders (rebuilt when the transcript changes).
    items: Rc<Vec<Item>>,
    scroller: Entity<MessageScrollerState>,
    composer: Entity<TextareaState>,
    models: Entity<SelectState<Vec<String>>>,
    onboarding: Option<Entity<Onboarding>>,
    pub sessions: Vec<SessionRecord>,
    pub session_id: String,
    model: String,
    mode: Mode,
    disabled_modes: Vec<String>,
    sandbox: Option<String>,
    /// Start-up warnings (settings, roles, sandbox).
    warnings: Vec<String>,
    running: Option<Instant>,
    /// Who drives this session instead of us.
    locked_by: Option<String>,
    trust_dismissed: bool,
    _tasks: Vec<Task<()>>,
    _subscriptions: Vec<Subscription>,
}

impl ProjectView {
    pub fn new(
        root: std::path::PathBuf,
        session: Option<String>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let runtime = cx.global::<AppContext>().runtime.clone();
        let handle = service::spawn(&runtime, root, session);
        let commands = handle.commands;
        let stopped = Some(handle.stopped);
        let mut events = handle.events;

        let composer = cx.new(|cx| {
            TextareaState::new(window, cx)
                .auto_grow(2, 10)
                .submit_on_enter(true)
                .placeholder("Ask MicroClaw Code to do something…")
        });
        let models =
            cx.new(|cx| SelectState::new(Vec::<String>::new(), None, window, cx).searchable(true));
        let scroller = cx.new(|cx| MessageScrollerState::new(0, cx));

        let mut subscriptions = Vec::new();
        subscriptions.push(cx.subscribe_in(
            &composer,
            window,
            |this, _, event: &InputEvent, window, cx| {
                if let InputEvent::PressEnter { secondary, .. } = event {
                    this.submit(*secondary, window, cx);
                }
            },
        ));
        subscriptions.push(cx.subscribe_in(
            &models,
            window,
            |this, _, event: &SelectEvent<Vec<String>>, _, _| {
                let SelectEvent::Confirm(choice) = event;
                let _ = this.commands.send(Command::SetModel(choice.clone()));
            },
        ));

        let task = cx.spawn_in(window, async move |this, cx| {
            while let Some(event) = events.recv().await {
                if this
                    .update_in(cx, |this, window, cx| this.on_event(event, window, cx))
                    .is_err()
                {
                    break;
                }
            }
        });

        Self {
            commands,
            stopped,
            phase: Phase::Loading,
            info: None,
            transcript: Transcript::default(),
            items: Rc::new(Vec::new()),
            scroller,
            composer,
            models,
            onboarding: None,
            sessions: Vec::new(),
            session_id: String::new(),
            model: String::new(),
            mode: Mode::default(),
            disabled_modes: Vec::new(),
            sandbox: None,
            warnings: Vec::new(),
            running: None,
            locked_by: None,
            trust_dismissed: false,
            _tasks: vec![task],
            _subscriptions: subscriptions,
        }
    }

    /// Stop the service (a running turn is cancelled); resolves once the
    /// session lock is released and session-end hooks ran.
    pub fn shutdown(&mut self) -> impl std::future::Future<Output = ()> + use<> {
        // Dropping the only sender ends the service loop.
        self.commands = tokio::sync::mpsc::unbounded_channel().0;
        let stopped = self.stopped.take();
        async move {
            if let Some(stopped) = stopped {
                let _ = stopped.await;
            }
        }
    }

    pub fn send(&self, command: Command) {
        let _ = self.commands.send(command);
    }

    pub fn is_running(&self) -> bool {
        self.running.is_some()
    }

    /// Re-render the list after the transcript changed.
    fn sync_items(&mut self, cx: &mut Context<Self>) {
        let before = self.items.len();
        self.items = Rc::new(self.transcript.items.clone());
        let after = self.items.len();
        self.scroller.update(cx, |scroller, cx| {
            if after < before || before == 0 {
                scroller.reset(after, cx);
            } else {
                if after > before {
                    scroller.append(after - before, cx);
                }
                // Earlier rows change too (tool results, answered approvals).
                scroller.remeasure(cx);
            }
        });
        cx.notify();
    }

    fn on_event(&mut self, event: Event, window: &mut Window, cx: &mut Context<Self>) {
        match event {
            Event::Project(info) => self.info = Some(info),
            Event::NeedsSetup(message) => {
                self.phase = Phase::NeedsSetup;
                let onboarding = cx.new(|cx| Onboarding::new(message, window, cx));
                self._subscriptions.push(cx.subscribe_in(
                    &onboarding,
                    window,
                    |this, _, _: &OnboardingDone, _, cx| {
                        this.onboarding = None;
                        this.phase = Phase::Loading;
                        this.send(Command::Start);
                        cx.notify();
                    },
                ));
                self.onboarding = Some(onboarding);
            }
            Event::Starting => self.phase = Phase::Starting,
            Event::Ready {
                model,
                mode,
                sandbox,
                warnings,
                models,
                disabled_modes,
            } => {
                self.phase = Phase::Ready;
                self.mode = mode;
                self.sandbox = sandbox;
                self.disabled_modes = disabled_modes;
                self.set_model(model, Some(models), window, cx);
                self.warnings = warnings;
            }
            Event::Failed(message) => self.phase = Phase::Failed(message),
            Event::Sessions(sessions) => self.sessions = sessions,
            Event::SessionOpened { id, history } => {
                self.session_id = id;
                self.locked_by = None;
                self.transcript.load_history(&history);
                // Settings and sandbox warnings head every session shown.
                for warning in &self.warnings {
                    self.transcript.notice(warning.clone(), Tone::Warning);
                }
                self.scroller.update(cx, |s, cx| s.reset(0, cx));
                self.items = Rc::new(Vec::new());
            }
            Event::SessionLocked { holder, .. } => self.locked_by = Some(holder),
            Event::TurnStarted(prompt) => {
                self.running = Some(Instant::now());
                self.transcript.begin_turn(&prompt);
            }
            Event::Update(update) => {
                if let microclaw_code_core::driver::Update::TurnUsage { model, .. } = &update
                    && !model.is_empty()
                {
                    self.model = model.clone();
                }
                self.transcript.apply(&update);
                if self.transcript.pending.is_some() {
                    window.activate_window();
                }
            }
            Event::TurnFinished { receipt } => {
                self.running = None;
                self.transcript.finish_turn(receipt);
            }
            Event::ModeChanged(mode) => self.mode = mode,
            Event::ModelChanged(model) => {
                self.transcript
                    .notice(format!("model for this session: {model}"), Tone::Info);
                self.set_model(model, None, window, cx);
            }
            Event::Notice(text) => self.transcript.notice(text, Tone::Info),
            Event::Error(text) => self.transcript.notice(text, Tone::Error),
        }
        self.sync_items(cx);
    }

    fn set_model(
        &mut self,
        model: String,
        choices: Option<Vec<String>>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.model = model.clone();
        self.models.update(cx, |select, cx| {
            if let Some(mut choices) = choices {
                if !model.is_empty() && !choices.contains(&model) {
                    choices.insert(0, model.clone());
                }
                select.set_items(choices, window, cx);
            }
            select.set_selected_value(&model, window, cx);
        });
    }

    fn submit(&mut self, steer: bool, window: &mut Window, cx: &mut Context<Self>) {
        let text = self.composer.read(cx).value().to_string();
        if text.trim().is_empty() {
            return;
        }
        if self.phase != Phase::Ready {
            return;
        }
        if self.running.is_some() {
            if !steer {
                self.transcript.notice(
                    "a turn is running: ⌘⏎ sends this as guidance, ⌘. stops it",
                    Tone::Info,
                );
                self.sync_items(cx);
                return;
            }
            self.transcript.steer(text.trim());
            self.send(Command::Steer(text.trim().to_string()));
        } else {
            self.send(Command::Send(text));
        }
        self.composer
            .update(cx, |composer, cx| composer.set_value("", window, cx));
        self.sync_items(cx);
    }

    pub fn stop(&mut self, _: &Stop, _: &mut Window, _: &mut Context<Self>) {
        self.send(Command::Cancel);
    }

    pub fn new_session(&mut self, _: &NewSession, _: &mut Window, _: &mut Context<Self>) {
        self.send(Command::NewSession);
    }

    pub fn cycle_mode(&mut self, _: &CycleMode, _: &mut Window, _: &mut Context<Self>) {
        let mut next = self.mode;
        for _ in 0..3 {
            next = match next {
                Mode::Plan => Mode::Ask,
                Mode::Ask => Mode::Auto,
                Mode::Auto => Mode::Plan,
            };
            if !self.disabled_modes.iter().any(|d| d == next.as_str()) {
                break;
            }
        }
        self.send(Command::SetMode(next));
    }

    fn render_header(&self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let theme = cx.theme();
        let (name, branch) = match &self.info {
            Some(info) => (info.name.clone(), info.branch.clone()),
            None => (String::new(), None),
        };
        let mode_button = |mode: Mode| {
            let commands = self.commands.clone();
            Button::new(SharedString::from(format!("mode-{}", mode.as_str())))
                .small()
                .label(mode.as_str())
                .tooltip(mode.describe())
                .when(self.mode == mode, |b| b.primary())
                .when(self.mode != mode, |b| b.ghost())
                .disabled(self.disabled_modes.iter().any(|d| d == mode.as_str()))
                .on_click(move |_, _, _| {
                    let _ = commands.send(Command::SetMode(mode));
                })
        };
        h_flex()
            .px_4()
            .py_2()
            .gap_3()
            .border_b_1()
            .border_color(theme.border)
            .child(
                v_flex()
                    .flex_1()
                    .overflow_hidden()
                    .child(div().font_weight(FontWeight::SEMIBOLD).child(name))
                    .child(
                        div()
                            .text_xs()
                            .text_color(theme.muted_foreground)
                            .overflow_hidden()
                            .text_ellipsis()
                            .child(format!(
                                "{}{}",
                                branch.map(|b| format!("{b} · ")).unwrap_or_default(),
                                self.session_id
                            )),
                    ),
            )
            .child(
                h_flex()
                    .gap_1()
                    .child(mode_button(Mode::Plan))
                    .child(mode_button(Mode::Ask))
                    .child(mode_button(Mode::Auto)),
            )
            .child(
                div().w(px(240.)).child(
                    Select::new(&self.models)
                        .small()
                        .placeholder("Model")
                        .disabled(self.phase != Phase::Ready || self.running.is_some()),
                ),
            )
            .when_some(self.sandbox.clone(), |row, sandbox| {
                row.child(
                    div()
                        .text_xs()
                        .text_color(theme.muted_foreground)
                        .child(sandbox),
                )
            })
    }

    fn render_banners(&self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let theme = cx.theme();
        let mut banners = v_flex();
        if let Some(info) = &self.info
            && !info.trusted
            && !self.trust_dismissed
        {
            let commands = self.commands.clone();
            banners = banners.child(
                h_flex()
                    .gap_3()
                    .px_4()
                    .py_2()
                    .bg(theme.secondary)
                    .border_b_1()
                    .border_color(theme.border)
                    .child(div().flex_1().text_sm().child(if info.trust_matters {
                        "Trust this project? Its .microclaw/project.yaml, checks and instructions apply only to trusted projects."
                    } else {
                        "Trust this project? Trusted projects load their instructions (AGENTS.md / CLAUDE.md) and run checks after changes."
                    }))
                    .child(
                        Button::new("trust")
                            .small()
                            .primary()
                            .label("Trust")
                            .on_click(move |_, _, _| {
                                let _ = commands.send(Command::Trust);
                            }),
                    )
                    .child(
                        Button::new("trust-later")
                            .small()
                            .ghost()
                            .label("Not now")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.trust_dismissed = true;
                                cx.notify();
                            })),
                    ),
            );
        }
        if let Some(holder) = &self.locked_by {
            let commands = self.commands.clone();
            banners = banners.child(
                h_flex()
                    .gap_3()
                    .px_4()
                    .py_2()
                    .bg(theme.secondary)
                    .border_b_1()
                    .border_color(theme.warning)
                    .child(div().flex_1().text_sm().child(format!(
                        "This session is open in {holder}. You can read it here; take it over to continue here."
                    )))
                    .child(
                        Button::new("take-over")
                            .small()
                            .warning()
                            .label("Take over")
                            .on_click(move |_, _, _| {
                                let _ = commands.send(Command::TakeOver);
                            }),
                    ),
            );
        }
        banners
    }

    fn render_composer(&self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let theme = cx.theme();
        let running = self.running.is_some();
        let ready = self.phase == Phase::Ready && self.locked_by.is_none();
        let status = match self.running {
            Some(started) => format!("Working… {}s", started.elapsed().as_secs()),
            None => format!("{} mode · {}", self.mode.as_str(), self.model),
        };
        v_flex()
            .gap_2()
            .px_4()
            .py_3()
            .border_t_1()
            .border_color(theme.border)
            .child(Textarea::new(&self.composer).disabled(!ready))
            .child(
                h_flex()
                    .gap_2()
                    .child(
                        div()
                            .flex_1()
                            .text_xs()
                            .text_color(theme.muted_foreground)
                            .child(format!(
                                "{status}  ·  ⏎ send · ⇧⏎ newline · ⌘⏎ guide the running turn · ⌘. stop · ⇧⇥ mode"
                            )),
                    )
                    .when(running, |row| {
                        row.child(
                            Button::new("steer")
                                .small()
                                .outline()
                                .label("Guide")
                                .on_click(cx.listener(|this, _, window, cx| {
                                    this.submit(true, window, cx)
                                })),
                        )
                        .child(
                            Button::new("stop")
                                .small()
                                .danger()
                                .label("Stop")
                                .on_click(cx.listener(|this, _, _, _| this.send(Command::Cancel))),
                        )
                    })
                    .when(!running, |row| {
                        row.child(
                            Button::new("send")
                                .small()
                                .primary()
                                .label("Send")
                                .disabled(!ready)
                                .on_click(cx.listener(|this, _, window, cx| {
                                    this.submit(false, window, cx)
                                })),
                        )
                    }),
            )
    }
}

impl Render for ProjectView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        // Keep the elapsed time ticking while a turn runs.
        if self.running.is_some() {
            window.request_animation_frame();
        }
        let theme = cx.theme();
        let body: AnyElement = match &self.phase {
            Phase::NeedsSetup => match &self.onboarding {
                Some(onboarding) => onboarding.clone().into_any_element(),
                None => div().into_any_element(),
            },
            Phase::Failed(message) => {
                let commands = self.commands.clone();
                v_flex()
                    .p_6()
                    .gap_3()
                    .child(
                        div()
                            .font_weight(FontWeight::SEMIBOLD)
                            .child("The Agent Engine could not start"),
                    )
                    .child(
                        div()
                            .text_sm()
                            .text_color(theme.danger)
                            .child(message.clone()),
                    )
                    .child(Button::new("retry").small().label("Try again").on_click(
                        move |_, _, _| {
                            let _ = commands.send(Command::Start);
                        },
                    ))
                    .into_any_element()
            }
            Phase::Loading | Phase::Starting if self.items.is_empty() => div()
                .p_6()
                .text_color(theme.muted_foreground)
                .child("Starting the Agent Engine…")
                .into_any_element(),
            _ => {
                let items = self.items.clone();
                let commands = self.commands.clone();
                MessageScroller::new("transcript", self.scroller.clone(), move |ix, _, cx| {
                    match items.get(ix) {
                        Some(item) => super::transcript::render_item(ix, item, &commands, cx),
                        None => div().into_any_element(),
                    }
                })
                .size_full()
                .into_any_element()
            }
        };
        v_flex()
            .key_context("Project")
            .on_action(cx.listener(Self::stop))
            .on_action(cx.listener(Self::new_session))
            .on_action(cx.listener(Self::cycle_mode))
            .size_full()
            .child(self.render_header(cx))
            .child(self.render_banners(cx))
            .child(div().flex_1().min_h_0().child(body))
            .when(self.phase != Phase::NeedsSetup, |this| {
                this.child(self.render_composer(cx))
            })
    }
}
