//! GPUI views. They read state and send [`crate::service::Command`]s; the
//! engine never runs on the UI thread.

mod onboarding;
mod project;
mod transcript;
mod workspace;

use std::path::PathBuf;

use gpui_kit::prelude::*;
use gpui_kit::*;

use microclaw_code_core::env::LoginEnvReport;

actions!(
    mccode,
    [
        Quit,
        OpenProject,
        NewSession,
        Stop,
        CycleMode,
        Hide,
        HideOthers,
        ShowAll,
        Minimize,
        Zoom
    ]
);

/// Values every view may need.
#[derive(Clone)]
pub struct AppContext {
    pub runtime: tokio::runtime::Handle,
    pub login_env: std::sync::Arc<LoginEnvReport>,
}

impl Global for AppContext {}

pub fn run(runtime: tokio::runtime::Runtime, login_env: LoginEnvReport, open: Option<PathBuf>) {
    let context = AppContext {
        runtime: runtime.handle().clone(),
        login_env: std::sync::Arc::new(login_env),
    };
    gpui_kit::application()
        .with_assets(gpui_kit::assets::Assets)
        .run(move |cx| {
            gpui_kit::init(cx);
            gpui_kit::component::Theme::sync_system_appearance(None, cx);
            cx.set_global(context);
            cx.bind_keys([
                KeyBinding::new("cmd-q", Quit, None),
                KeyBinding::new("cmd-o", OpenProject, None),
                KeyBinding::new("cmd-n", NewSession, None),
                KeyBinding::new("cmd-.", Stop, None),
                // Later than the input's own bindings, so it wins in the composer.
                KeyBinding::new("shift-tab", CycleMode, Some("Input")),
                KeyBinding::new("cmd-h", Hide, None),
                KeyBinding::new("alt-cmd-h", HideOthers, None),
                KeyBinding::new("cmd-m", Minimize, None),
            ]);
            cx.on_action(|_: &Quit, cx| cx.quit());
            cx.on_action(|_: &Hide, cx| cx.hide());
            cx.on_action(|_: &HideOthers, cx| cx.hide_other_apps());
            cx.on_action(|_: &ShowAll, cx| cx.unhide_other_apps());
            cx.set_menus([
                Menu::new("MicroClaw Code").items([
                    MenuItem::action("Hide MicroClaw Code", Hide),
                    MenuItem::action("Hide Others", HideOthers),
                    MenuItem::action("Show All", ShowAll),
                    MenuItem::separator(),
                    MenuItem::action("Quit MicroClaw Code", Quit),
                ]),
                Menu::new("File").items([
                    MenuItem::action("Open Project…", OpenProject),
                    MenuItem::action("New Session", NewSession),
                ]),
                Menu::new("Session").items([
                    MenuItem::action("Stop", Stop),
                    MenuItem::action("Next Mode", CycleMode),
                ]),
                Menu::new("Window").items([
                    MenuItem::action("Minimize", Minimize),
                    MenuItem::action("Zoom", Zoom),
                ]),
            ]);
            let bounds = Bounds::centered(None, size(px(1180.), px(800.)), cx);
            let options = WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                titlebar: Some(TitlebarOptions {
                    title: Some("MicroClaw Code".into()),
                    ..Default::default()
                }),
                window_min_size: Some(size(px(720.), px(480.))),
                ..Default::default()
            };
            gpui_kit::open_window(options, cx, move |window, cx| {
                cx.new(|cx| workspace::Workspace::new(open, window, cx))
            })
            .expect("failed to open the window");
            cx.on_window_closed(|cx, _| {
                if cx.windows().is_empty() {
                    cx.quit();
                }
            })
            .detach();
            cx.activate(true);
        });
    // Keep the engine runtime alive until the app has quit.
    drop(runtime);
}
