//! MicroClaw Code desktop app: a GPUI front end of MicroClaw Code next to the
//! `mccode` TUI. Same `~/.mccode`, same sessions, settings, trust and rules.
//!
//! - [`state`]: the conversation as shown, built from driver updates (pure);
//! - [`service`]: one project's engine and session on the Tokio runtime;
//! - [`views`]: GPUI windows and components;
//! - [`store`]: the app's own window state in `~/.mccode/desktop/`.

// GPUI's unwind tables exceed what the macOS linker's compact unwind
// encoding holds in debug builds; ld says so on every link.
#![allow(linker_messages)]

mod headless;
mod service;
mod state;
mod store;
mod views;

use std::time::Duration;

/// How long the login shell may take to print its environment.
const LOGIN_ENV_TIMEOUT: Duration = Duration::from_secs(5);

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("MicroClaw Code (desktop) {}", env!("CARGO_PKG_VERSION"));
        return std::process::ExitCode::SUCCESS;
    }
    // Both steps change the process environment, so they run before any
    // thread (Tokio, GPUI) exists.
    // SAFETY: single-threaded so far.
    let login_env = unsafe { microclaw_code_core::env::import_login_shell_env(LOGIN_ENV_TIMEOUT) };
    // SAFETY: as above.
    unsafe {
        microclaw_code_core::env::isolate_engine_env(&microclaw_code_core::home::code_home())
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .thread_name("mccode-engine")
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("microclaw-code-desktop: {e}");
            return std::process::ExitCode::from(1);
        }
    };

    // `--smoke <dir> <prompt>`: one turn through the service layer without a
    // window (packaging smoke test and scripted checks).
    if let Some(at) = args.iter().position(|a| a == "--smoke") {
        let dir = args.get(at + 1).cloned().unwrap_or_else(|| ".".into());
        let prompt = args
            .get(at + 2)
            .cloned()
            .unwrap_or_else(|| "Say hello.".into());
        let session = args
            .iter()
            .position(|a| a == "--session")
            .and_then(|i| args.get(i + 1).cloned());
        return headless::run(&runtime, dir.into(), prompt, session);
    }

    let open = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .map(std::path::PathBuf::from);
    views::run(runtime, login_env, open);
    std::process::ExitCode::SUCCESS
}
