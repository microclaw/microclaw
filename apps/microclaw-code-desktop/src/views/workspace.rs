//! The window: projects and sessions on the left, the open project on the
//! right. One project runs at a time; switching projects stops the other's
//! engine (and its background processes).

use std::path::PathBuf;

use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::{ActiveTheme as _, Sizable as _, h_flex, v_flex};
use gpui_kit::prelude::*;
use gpui_kit::*;

use super::project::ProjectView;
use super::{AppContext, CycleMode, NewSession, OpenProject, Stop};
use crate::store::DesktopState;

pub struct Workspace {
    store: DesktopState,
    project: Option<Entity<ProjectView>>,
    focus: FocusHandle,
    _quit: Subscription,
}

impl Workspace {
    pub fn new(open: Option<PathBuf>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let store = DesktopState::load(&DesktopState::default_path());
        // On quit, let the engine release the session before the process ends.
        let quit = cx.on_app_quit(|this: &mut Self, cx| {
            let stopping = this
                .project
                .take()
                .map(|project| project.update(cx, |project, _| project.shutdown()));
            async move {
                if let Some(stopping) = stopping {
                    stopping.await;
                }
            }
        });
        let mut this = Self {
            store,
            project: None,
            focus: cx.focus_handle(),
            _quit: quit,
        };
        let first = open
            .and_then(|p| std::fs::canonicalize(p).ok())
            .or_else(|| this.store.recent_projects.first().cloned())
            .filter(|p| p.is_dir());
        if let Some(root) = first {
            this.open_project(root, None, window, cx);
        }
        window.focus(&this.focus, cx);
        this
    }

    fn open_project(
        &mut self,
        root: PathBuf,
        session: Option<String>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if session.is_none()
            && let Some(current) = &self.project
            && current
                .read(cx)
                .info
                .as_ref()
                .is_some_and(|info| info.root == root)
        {
            return;
        }
        self.store.opened(&root);
        let _ = self.store.save(&DesktopState::default_path());
        let project = cx.new(|cx| ProjectView::new(root, session, window, cx));
        cx.observe(&project, |_, _, cx| cx.notify()).detach();
        self.project = Some(project);
        cx.notify();
    }

    fn prompt_open(&mut self, _: &OpenProject, window: &mut Window, cx: &mut Context<Self>) {
        let paths = cx.prompt_for_paths(PathPromptOptions {
            files: false,
            directories: true,
            multiple: false,
            prompt: Some("Open Project".into()),
        });
        cx.spawn_in(window, async move |this, cx| {
            if let Ok(Ok(Some(paths))) = paths.await
                && let Some(root) = paths.into_iter().next()
            {
                let _ = this.update_in(cx, |this, window, cx| {
                    this.open_project(root, None, window, cx)
                });
            }
        })
        .detach();
    }

    fn render_sidebar(&self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let theme = cx.theme();
        let current = self.project.as_ref().map(|p| p.read(cx));
        let current_root = current.and_then(|p| p.info.as_ref().map(|i| i.root.clone()));
        let current_session = current.map(|p| p.session_id.clone()).unwrap_or_default();
        let sessions = current.map(|p| p.sessions.clone()).unwrap_or_default();
        let running = current.is_some_and(|p| p.is_running());

        let mut list = v_flex().gap_0p5();
        for (i, root) in self.store.recent_projects.iter().enumerate() {
            let active = current_root.as_deref() == Some(root.as_path());
            let name = root
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| root.display().to_string());
            let target = root.clone();
            list = list.child(
                div()
                    .id(("project", i))
                    .px_2()
                    .py_1()
                    .rounded_md()
                    .text_sm()
                    .when(active, |d| {
                        d.bg(theme.sidebar_accent)
                            .text_color(theme.sidebar_accent_foreground)
                            .font_weight(FontWeight::SEMIBOLD)
                    })
                    .hover(|d| d.bg(theme.sidebar_accent))
                    .cursor_pointer()
                    .on_click(cx.listener(move |this, _, window, cx| {
                        if this
                            .project
                            .as_ref()
                            .is_some_and(|p| p.read(cx).is_running())
                        {
                            return;
                        }
                        this.open_project(target.clone(), None, window, cx)
                    }))
                    .child(name),
            );
            if active {
                for (j, record) in sessions
                    .iter()
                    .filter(|r| r.turns > 0 || r.id == current_session)
                    .take(30)
                    .enumerate()
                {
                    let selected = record.id == current_session;
                    let id = record.id.clone();
                    let title = if record.title.is_empty() {
                        "New session".to_string()
                    } else {
                        record.title.clone()
                    };
                    let when = record
                        .updated_at
                        .get(..16)
                        .unwrap_or(&record.updated_at)
                        .replace('T', " ");
                    list = list.child(
                        div()
                            .id(("session", j))
                            .ml_3()
                            .px_2()
                            .py_1()
                            .rounded_md()
                            .when(selected, |d| d.bg(theme.sidebar_accent))
                            .hover(|d| d.bg(theme.sidebar_accent))
                            .cursor_pointer()
                            .on_click(cx.listener(move |this, _, _, cx| {
                                if running {
                                    return;
                                }
                                if let Some(project) = &this.project {
                                    project
                                        .read(cx)
                                        .send(crate::service::Command::OpenSession(id.clone()));
                                }
                            }))
                            .child(
                                div()
                                    .text_sm()
                                    .overflow_hidden()
                                    .text_ellipsis()
                                    .whitespace_nowrap()
                                    .child(title),
                            )
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(theme.muted_foreground)
                                    .child(format!("{when} · {} turns", record.turns)),
                            ),
                    );
                }
            }
        }
        let login = cx.global::<AppContext>().login_env.clone();
        v_flex()
            .w(px(250.))
            .h_full()
            .flex_shrink_0()
            .bg(theme.sidebar)
            .text_color(theme.sidebar_foreground)
            .border_r_1()
            .border_color(theme.sidebar_border)
            .child(
                h_flex()
                    .px_3()
                    .pt_3()
                    .pb_2()
                    .justify_between()
                    .child(
                        div()
                            .text_sm()
                            .font_weight(FontWeight::SEMIBOLD)
                            .child("Projects"),
                    )
                    .child(
                        Button::new("new-session")
                            .xsmall()
                            .ghost()
                            .label("New session")
                            .tooltip("⌘N")
                            .on_click(cx.listener(|this, _, _, cx| {
                                if let Some(project) = &this.project {
                                    project.read(cx).send(crate::service::Command::NewSession);
                                }
                            })),
                    ),
            )
            .child(
                div()
                    .id("sidebar-list")
                    .flex_1()
                    .overflow_y_scroll()
                    .px_2()
                    .child(list),
            )
            .child(
                v_flex()
                    .p_3()
                    .gap_1()
                    .child(
                        Button::new("open-project")
                            .small()
                            .outline()
                            .label("Open Project…")
                            .tooltip("⌘O")
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.prompt_open(&OpenProject, window, cx)
                            })),
                    )
                    .when_some(login.error.clone(), |this, error| {
                        this.child(
                            div()
                                .text_xs()
                                .text_color(theme.warning)
                                .child(format!("login shell environment: {error}")),
                        )
                    }),
            )
    }

    fn render_welcome(&self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let theme = cx.theme();
        v_flex()
            .size_full()
            .items_center()
            .justify_center()
            .gap_3()
            .child(
                div()
                    .text_xl()
                    .font_weight(FontWeight::SEMIBOLD)
                    .child("MicroClaw Code"),
            )
            .child(div().text_sm().text_color(theme.muted_foreground).child(
                "Open a project folder to start. Sessions are shared with the mccode command.",
            ))
            .child(
                Button::new("welcome-open")
                    .primary()
                    .label("Open Project…")
                    .on_click(cx.listener(|this, _, window, cx| {
                        this.prompt_open(&OpenProject, window, cx)
                    })),
            )
    }
}

impl Render for Workspace {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let main: AnyElement = match &self.project {
            Some(project) => project.clone().into_any_element(),
            None => self.render_welcome(cx).into_any_element(),
        };
        let sidebar = self.render_sidebar(cx);
        let theme = cx.theme();
        h_flex()
            .key_context("Workspace")
            .track_focus(&self.focus)
            .on_action(cx.listener(Self::prompt_open))
            .on_action(cx.listener(|this, _: &NewSession, _, cx| {
                if let Some(project) = &this.project {
                    project.read(cx).send(crate::service::Command::NewSession);
                }
            }))
            .on_action(cx.listener(|this, _: &Stop, _, cx| {
                if let Some(project) = &this.project {
                    project.read(cx).send(crate::service::Command::Cancel);
                }
            }))
            .on_action(cx.listener(|this, action: &CycleMode, window, cx| {
                if let Some(project) = this.project.clone() {
                    project.update(cx, |p, cx| p.cycle_mode(action, window, cx));
                }
            }))
            .size_full()
            .bg(theme.background)
            .text_color(theme.foreground)
            .child(sidebar)
            .child(div().flex_1().h_full().min_w_0().child(main))
    }
}
