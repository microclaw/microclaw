//! `mcdesk`: the terminal entry point of MicroClaw Desktop.
//!
//! MicroClaw Desktop is the local product: the desktop app and this CLI share
//! one Agent Engine (through `microclaw-sdk`), one session store and state
//! machine (`microclaw-desktop-app`), and the project, trust and verification
//! services in `microclaw-desktop-runtime`. A session started here appears in the
//! desktop app and `/desktop` hands it over.
//!
//! The CLI opens the repository that contains the current directory as a
//! direct workspace, renders tool calls and diffs, resolves approvals
//! according to the permission mode, and verifies edits with the project's
//! own checks, handing failures back to the agent.

mod prompt;
mod render;

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use microclaw_desktop_app::session::{DesktopCommand, DesktopSessionSnapshot, DesktopStatus};
use microclaw_desktop_app::store::{DesktopSessionStore, DesktopSessionSummary};
use microclaw_desktop_runtime::project::{self, Check, Mode, Project};
use microclaw_desktop_runtime::trust::TrustStore;
use microclaw_desktop_runtime::{desktop_data_root, verify};
use microclaw_sdk::{Agent, MicroClaw, RunHandle, RunRequest, RunStatus, SessionId, ToolPolicy};
use tokio::sync::mpsc;

use render::{PendingApproval, Renderer, Style};

const AGENT_NAME: &str = "MicroClaw Desktop";
/// Same caller channel as the desktop app, so sessions, run control and
/// sub-agent listings are shared.
const CALLER_CHANNEL: &str = "desktop";
const DESKTOP_BUNDLE_ID: &str = "org.microclaw.desktop";

/// Shell commands that still ask for approval in auto mode.
const ALWAYS_ASK_PATTERNS: &[&str] = &[
    r"\brm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+)+",
    r"\bgit\s+push\b",
    r"\bgit\s+reset\s+--hard\b",
    r"\bgit\s+clean\s+-[a-zA-Z]*f",
    r"\bgit\s+(checkout|restore)\s+(--\s+)?\.",
    r"\bgit\s+branch\s+-D\b",
    r"\bsudo\b",
    r"\bmkfs\b",
    r"\bdd\s+if=",
    r"\bchmod\s+-R\b",
    r"\bchown\s+-R\b",
    r"(curl|wget)\b[^|]*\|\s*(sh|bash|zsh)\b",
    r">\s*/dev/(sd|nvme|disk)",
    r"\b(npm|cargo|pnpm|yarn)\s+publish\b",
];

#[derive(Debug, Parser)]
#[command(
    name = "mcdesk",
    version,
    about = "MicroClaw Desktop in your terminal: a local agent for your repository",
    long_about = "mcdesk opens the repository that contains the current directory and runs the MicroClaw Agent Engine in it. Sessions are shared with the MicroClaw Desktop app.\n\nRun without arguments for an interactive session, or pass -p for a single non-interactive task. Model credentials come from --config, MICROCLAW_DESKTOP_CONFIG, MICROCLAW_CONFIG, the Desktop app's settings, or ~/.microclaw/microclaw.config.yaml."
)]
struct Cli {
    /// Initial task for an interactive session.
    #[arg(value_name = "PROMPT", trailing_var_arg = true)]
    prompt: Vec<String>,

    /// Run one task non-interactively and print the result (`-` reads stdin).
    #[arg(short = 'p', long = "print", value_name = "PROMPT")]
    print: Option<String>,

    /// Project directory (default: current directory).
    #[arg(short = 'C', long = "cwd", value_name = "DIR")]
    cwd: Option<PathBuf>,

    /// Permission mode: plan, ask, or auto.
    #[arg(long, value_name = "MODE")]
    mode: Option<String>,

    /// Resume the most recent session for this project.
    #[arg(short = 'c', long = "continue")]
    continue_last: bool,

    /// Resume a session by id (see `mcdesk sessions`).
    #[arg(long, value_name = "ID", conflicts_with = "continue_last")]
    session: Option<String>,

    /// Trust this project (honour .microclaw/project.yaml, run checks automatically).
    #[arg(long)]
    trust: bool,

    /// MicroClaw configuration file with model credentials.
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,

    /// Emit JSON Lines runtime events (with -p).
    #[arg(long)]
    json: bool,

    /// Do not run project checks after edits.
    #[arg(long)]
    no_verify: bool,

    /// Maximum verification fix-up rounds.
    #[arg(long, value_name = "N")]
    max_fix_rounds: Option<u32>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the project's checks (all, or the named ones) and exit.
    Check {
        /// Check names; default: all checks.
        names: Vec<String>,
    },
    /// Write a .microclaw/project.yaml template for this project.
    Init {
        /// Overwrite an existing file.
        #[arg(long)]
        force: bool,
    },
    /// Show what MicroClaw Desktop detected for this project.
    Info,
    /// List this project's sessions (shared with the desktop app).
    Sessions,
    /// Trust this project, or revoke trust with --revoke.
    Trust {
        #[arg(long)]
        revoke: bool,
    },
    /// Open the desktop app on this project's most recent session.
    Desktop,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(code) => code,
        Err(error) => {
            eprintln!("mcdesk: {error:#}");
            ExitCode::from(1)
        }
    }
}

fn session_store() -> DesktopSessionStore {
    DesktopSessionStore::new(desktop_data_root().join("work-sessions"))
}

/// Sessions whose workspace is this project, most recent first.
fn project_sessions(
    store: &DesktopSessionStore,
    root: &Path,
) -> anyhow::Result<Vec<DesktopSessionSummary>> {
    let root = root.to_string_lossy();
    let mut sessions: Vec<_> = store
        .list()?
        .into_iter()
        .filter(|s| s.workspace == root)
        .collect();
    sessions.sort_by_key(|s| std::cmp::Reverse(s.updated_at_ms));
    Ok(sessions)
}

async fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    let start = match &cli.cwd {
        Some(dir) => dir.clone(),
        None => std::env::current_dir()?,
    };
    let mut trust_store = TrustStore::load(TrustStore::default_path());
    let mut project = Project::discover(&start, |root| trust_store.is_trusted(root))?;
    let style = Style::detect();

    if cli.trust && !project.trusted {
        trust_store.set(&project.root, true)?;
        project.set_trusted(true);
    }

    match &cli.command {
        Some(Command::Info) => {
            print_info(&project, style);
            return Ok(ExitCode::SUCCESS);
        }
        Some(Command::Init { force }) => return init_project(&project, *force),
        Some(Command::Check { names }) => return check_command(&project, names, style).await,
        Some(Command::Sessions) => {
            print_sessions(&project, style)?;
            return Ok(ExitCode::SUCCESS);
        }
        Some(Command::Trust { revoke }) => {
            trust_store.set(&project.root, !revoke)?;
            println!(
                "{} {}",
                if *revoke {
                    "Revoked trust for"
                } else {
                    "Trusted"
                },
                project.root.display()
            );
            return Ok(ExitCode::SUCCESS);
        }
        Some(Command::Desktop) => {
            let store = session_store();
            if let Some(latest) = project_sessions(&store, &project.root)?.first() {
                // Saving makes it the active session the desktop app opens.
                let snapshot = store.load(&latest.session_id)?;
                store.save(&snapshot)?;
            }
            open_desktop_app()?;
            return Ok(ExitCode::SUCCESS);
        }
        None => {}
    }

    let print_prompt = match cli.print.as_deref() {
        Some("-") => {
            let mut text = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut text)?;
            Some(text)
        }
        Some(text) => Some(text.to_string()),
        None => None,
    };
    let interactive = print_prompt.is_none();
    if interactive && !std::io::stdin().is_terminal() && cli.prompt.is_empty() {
        anyhow::bail!(
            "stdin is not a terminal; pass a task with -p \"...\" (or -p - to read it from stdin)"
        );
    }

    let mut input = interactive.then(spawn_stdin_reader);
    if !project.trusted && trust_store.decision(&project.root).is_none() {
        if interactive {
            if ask_trust(&project, style, &mut input).await {
                trust_store.set(&project.root, true)?;
                project.set_trusted(true);
            } else {
                trust_store.set(&project.root, false)?;
            }
        } else if !cli.json {
            eprintln!(
                "{}",
                style.dim("Project not trusted: .microclaw/project.yaml is ignored and checks do not run automatically. Pass --trust to trust it.")
            );
        }
    }

    let mode = match cli.mode.as_deref() {
        Some(raw) => Mode::parse(raw)
            .ok_or_else(|| anyhow::anyhow!("unknown mode '{raw}' (expected plan, ask or auto)"))?,
        None => project.config.mode.unwrap_or_default(),
    };
    let config_path = resolve_config(cli.config.as_deref())?;

    let store = session_store();
    let snapshot = if let Some(id) = &cli.session {
        store.open(id)?
    } else if cli.continue_last {
        let latest = project_sessions(&store, &project.root)?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("no previous session for this project"))?;
        store.open(&latest.session_id)?
    } else {
        store.create(project.root.to_string_lossy())?
    };

    if interactive || !cli.json {
        eprintln!(
            "{} {} {}",
            style.bold("MicroClaw Desktop"),
            style.dim(&format!(
                "· {} · mode {}{}",
                project.root.display(),
                mode.as_str(),
                if project.trusted { "" } else { " · untrusted" }
            )),
            style.dim(&format!("· session {}", snapshot.session_id))
        );
        eprintln!("{}", style.dim("Loading the Agent Engine…"));
    }
    let microclaw = MicroClaw::builder(&config_path)
        .caller_channel(CALLER_CHANNEL)
        .workspace(&project.root)
        .max_concurrent_runs(1)
        .build()
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let mut app = App {
        git: project::git_summary(&project.root),
        verify: project.verify_enabled() && !cli.no_verify,
        max_fix_rounds: cli
            .max_fix_rounds
            .unwrap_or_else(|| project.max_fix_rounds()),
        always_ask: compile_always_ask(&project.config.always_ask),
        project,
        microclaw,
        mode,
        store,
        snapshot,
        style,
        json: cli.json && !interactive,
        interactive,
        input,
        last_interrupt: None,
    };

    if let Some(prompt) = print_prompt {
        let report = app.turn(prompt.trim()).await?;
        if app.json {
            let line = serde_json::json!({
                "type": "result",
                "status": report.status,
                "session": app.snapshot.session_id,
                "final_text": report.final_text,
                "changed_files": report.changed_files,
                "checks_passed": report.checks_passed,
                "approval_pending": report.approval_pending,
            });
            println!("{line}");
        }
        return Ok(report.exit_code());
    }

    app.repl(cli.prompt.join(" ")).await
}

/// Locate the MicroClaw configuration with model credentials. A config file
/// inside the repository is deliberately not picked up implicitly: a cloned
/// project must not be able to choose the model endpoint or tool policy.
fn resolve_config(explicit: Option<&Path>) -> anyhow::Result<PathBuf> {
    if let Some(path) = explicit {
        anyhow::ensure!(
            path.is_file(),
            "config file {} does not exist",
            path.display()
        );
        return Ok(path.to_path_buf());
    }
    for var in ["MICROCLAW_DESKTOP_CONFIG", "MICROCLAW_CONFIG"] {
        if let Some(value) = std::env::var_os(var) {
            let path = PathBuf::from(value);
            anyhow::ensure!(
                path.is_file(),
                "{var} points to missing file {}",
                path.display()
            );
            return Ok(path);
        }
    }
    let desktop_owned = desktop_data_root().join("microclaw.config.yaml");
    if desktop_owned.is_file() {
        return Ok(desktop_owned);
    }
    if let Some(home) = dirs::home_dir() {
        for name in [
            ".microclaw/microclaw.config.yaml",
            ".microclaw/microclaw.config.yml",
        ] {
            let path = home.join(name);
            if path.is_file() {
                return Ok(path);
            }
        }
    }
    anyhow::bail!(
        "no MicroClaw configuration found. Configure a model in the MicroClaw Desktop app, run `microclaw setup`, create ~/.microclaw/microclaw.config.yaml with llm_provider/model/api_key, or pass --config <PATH>."
    )
}

fn open_desktop_app() -> anyhow::Result<()> {
    let status = if cfg!(target_os = "macos") {
        std::process::Command::new("open")
            .args(["-b", DESKTOP_BUNDLE_ID])
            .status()
    } else {
        let name = if cfg!(windows) {
            "microclaw-desktop.exe"
        } else {
            "microclaw-desktop"
        };
        let sibling = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join(name)))
            .filter(|p| p.is_file());
        let program = sibling.unwrap_or_else(|| PathBuf::from(name));
        std::process::Command::new(program)
            .spawn()
            .map(|_| std::process::ExitStatus::default())
    };
    match status {
        Ok(status) if status.success() => Ok(()),
        _ => anyhow::bail!(
            "could not start the MicroClaw Desktop app; install it (macOS: `brew install --cask microclaw-desktop`) and try again"
        ),
    }
}

async fn ask_trust(
    project: &Project,
    style: Style,
    input: &mut Option<mpsc::UnboundedReceiver<Input>>,
) -> bool {
    eprintln!(
        "{} {}",
        style.yellow("?"),
        style.bold(&format!("Trust {}?", project.root.display()))
    );
    if project.has_config_file {
        eprintln!(
            "  It has {}, which can set the permission mode, add instructions and define check commands.",
            project.config_path().display()
        );
    }
    eprintln!(
        "  Trusted projects run their checks (build scripts included) automatically after edits. Untrusted projects ignore the project file."
    );
    eprint!("{} ", style.yellow("trust this project? [y/N]"));
    let _ = std::io::stderr().flush();
    matches!(
        recv_input(input).await,
        Some(Input::Line(line)) if matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
    )
}

fn compile_always_ask(extra: &[String]) -> Vec<regex::Regex> {
    ALWAYS_ASK_PATTERNS
        .iter()
        .map(|p| p.to_string())
        .chain(extra.iter().cloned())
        .filter_map(|p| match regex::Regex::new(&format!("(?i){p}")) {
            Ok(re) => Some(re),
            Err(e) => {
                eprintln!("ignoring invalid always_ask pattern {p:?}: {e}");
                None
            }
        })
        .collect()
}

fn print_info(project: &Project, style: Style) {
    println!("{} {}", style.bold("root:"), project.root.display());
    println!(
        "{} {}",
        style.bold("project types:"),
        if project.kinds.is_empty() {
            "unknown".to_string()
        } else {
            project.kinds.join(", ")
        }
    );
    println!(
        "{} {}",
        style.bold("trusted:"),
        if project.trusted {
            "yes"
        } else {
            "no (run `mcdesk trust`)"
        }
    );
    let config_state = match (project.has_config_file, project.trusted) {
        (true, true) => "present",
        (true, false) => "present, ignored until trusted",
        (false, _) => "absent (run `mcdesk init`)",
    };
    println!(
        "{} {} ({config_state})",
        style.bold("project config:"),
        project.config_path().display()
    );
    println!(
        "{} {}",
        style.bold("default mode:"),
        project.config.mode.unwrap_or_default().as_str()
    );
    println!(
        "{} {}{}",
        style.bold("checks:"),
        if project.checks_configured {
            "configured"
        } else {
            "detected"
        },
        if project.checks.is_empty() {
            " (none)"
        } else {
            ""
        }
    );
    for check in &project.checks {
        let auto = if check.auto { " [auto]" } else { "" };
        println!("  {}: {}{auto}", check.name, check.run);
    }
    match resolve_config(None) {
        Ok(path) => println!("{} {}", style.bold("model config:"), path.display()),
        Err(e) => println!("{} {e}", style.bold("model config:")),
    }
    println!(
        "{} {}",
        style.bold("desktop data:"),
        desktop_data_root().display()
    );
    if let Some(git) = project::git_summary(&project.root) {
        println!("{}\n{git}", style.bold("git:"));
    }
}

fn print_sessions(project: &Project, style: Style) -> anyhow::Result<()> {
    let sessions = project_sessions(&session_store(), &project.root)?;
    if sessions.is_empty() {
        println!("No sessions for {} yet.", project.root.display());
        return Ok(());
    }
    for s in sessions {
        let task: String = s.task.split_whitespace().collect::<Vec<_>>().join(" ");
        let task: String = task.chars().take(70).collect();
        println!(
            "{}  {:<17} {}",
            style.bold(&s.session_id),
            format!("{:?}", s.status).to_lowercase(),
            task
        );
    }
    println!(
        "{}",
        style.dim("Resume with `mcdesk --session <id>`, or `mcdesk -c` for the most recent.")
    );
    Ok(())
}

fn init_project(project: &Project, force: bool) -> anyhow::Result<ExitCode> {
    let path = project.config_path();
    if path.exists() && !force {
        anyhow::bail!(
            "{} already exists (use --force to overwrite)",
            path.display()
        );
    }
    std::fs::create_dir_all(path.parent().unwrap_or(&project.root))?;
    std::fs::write(&path, project::config_template(project))?;
    println!("Wrote {}", path.display());
    if !project.trusted {
        println!("Run `mcdesk trust` so these settings take effect for you.");
    }
    Ok(ExitCode::SUCCESS)
}

async fn check_command(
    project: &Project,
    names: &[String],
    style: Style,
) -> anyhow::Result<ExitCode> {
    let checks = select_checks(project, names)?;
    let ok = run_checks(&project.root, &checks, style, true)
        .await
        .is_none();
    Ok(if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

fn select_checks(project: &Project, names: &[String]) -> anyhow::Result<Vec<Check>> {
    if project.checks.is_empty() {
        anyhow::bail!(
            "no checks detected for this project; add them to {} (see `mcdesk init`)",
            project.config_path().display()
        );
    }
    if names.is_empty() || names.iter().any(|n| n == "all") {
        return Ok(project.checks.clone());
    }
    names
        .iter()
        .map(|name| {
            project
                .checks
                .iter()
                .find(|c| &c.name == name)
                .cloned()
                .ok_or_else(|| {
                    let known: Vec<_> = project.checks.iter().map(|c| c.name.as_str()).collect();
                    anyhow::anyhow!("unknown check '{name}' (known: {})", known.join(", "))
                })
        })
        .collect()
}

/// Run checks in order, stopping at the first failure, which is returned.
async fn run_checks(
    root: &Path,
    checks: &[Check],
    style: Style,
    show_output_on_failure: bool,
) -> Option<verify::CheckOutcome> {
    for check in checks {
        eprint!(
            "{} {} {}",
            style.cyan("▸"),
            style.bold(&check.name),
            style.dim(&check.run)
        );
        let _ = std::io::stderr().flush();
        let outcome = verify::run_check(root, check).await;
        let secs = outcome.duration.as_secs_f32();
        if outcome.success {
            eprintln!(
                "  {} {}",
                style.green("passed"),
                style.dim(&format!("{secs:.1}s"))
            );
        } else {
            eprintln!(
                "  {} {}",
                style.red(&outcome.status_label()),
                style.dim(&format!("{secs:.1}s"))
            );
            if show_output_on_failure {
                for line in verify::tail(outcome.output.trim_end(), 4_000).lines() {
                    eprintln!("    {}", style.dim(line));
                }
            }
            return Some(outcome);
        }
    }
    None
}

enum Input {
    Line(String),
    Eof,
}

/// Background stdin reader so the agent can be steered while it runs.
fn spawn_stdin_reader() -> mpsc::UnboundedReceiver<Input> {
    let (tx, rx) = mpsc::unbounded_channel();
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        loop {
            let mut line = String::new();
            match stdin.read_line(&mut line) {
                Ok(0) | Err(_) => {
                    let _ = tx.send(Input::Eof);
                    break;
                }
                Ok(_) => {
                    if tx
                        .send(Input::Line(line.trim_end_matches(['\n', '\r']).to_string()))
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    });
    rx
}

struct RunOutcome {
    status: RunStatus,
    final_text: String,
    error: Option<String>,
    changed_files: Vec<String>,
    approval: Option<PendingApproval>,
}

#[derive(Default)]
struct TurnReport {
    status: String,
    final_text: String,
    changed_files: Vec<String>,
    checks_passed: Option<bool>,
    approval_pending: bool,
    failed: bool,
}

impl TurnReport {
    fn exit_code(&self) -> ExitCode {
        if self.approval_pending {
            ExitCode::from(2)
        } else if self.failed || self.checks_passed == Some(false) {
            ExitCode::from(1)
        } else {
            ExitCode::SUCCESS
        }
    }
}

struct App {
    project: Project,
    microclaw: MicroClaw,
    mode: Mode,
    store: DesktopSessionStore,
    snapshot: DesktopSessionSnapshot,
    style: Style,
    json: bool,
    interactive: bool,
    git: Option<String>,
    verify: bool,
    max_fix_rounds: u32,
    always_ask: Vec<regex::Regex>,
    input: Option<mpsc::UnboundedReceiver<Input>>,
    last_interrupt: Option<Instant>,
}

impl App {
    fn agent(&self) -> anyhow::Result<Agent> {
        let policy = if self.mode == Mode::Plan {
            ToolPolicy::ReadOnly
        } else {
            ToolPolicy::WorkspaceWrite
        };
        self.microclaw
            .agent(AGENT_NAME)
            .system_prompt(prompt::system_prompt(
                &self.project,
                self.mode,
                self.git.as_deref(),
            ))
            .tool_policy(policy)
            .build()
            .map_err(|e| anyhow::anyhow!("{e}"))
    }

    fn start_run(&self, prompt: &str) -> anyhow::Result<RunHandle> {
        let mut request = RunRequest::new(prompt);
        request.session_id = Some(SessionId::new(self.snapshot.session_id.clone()));
        request.workspace = Some(self.project.root.clone());
        Ok(self.agent()?.run_request(request))
    }

    /// Apply a state-machine command; a rejected transition is reported but
    /// never stops the run (the engine stays the source of truth).
    fn apply(&mut self, command: DesktopCommand) {
        if let Err(error) = self.snapshot.apply(command)
            && !self.json
        {
            eprintln!("{}", self.style.dim(&format!("  (session: {error})")));
        }
    }

    fn persist(&self) {
        if let Err(error) = self.store.save(&self.snapshot) {
            eprintln!(
                "{}",
                self.style
                    .red(&format!("could not save the session: {error}"))
            );
        }
    }

    /// Drive one agent run to completion, rendering its events and
    /// projecting them into the shared session snapshot.
    async fn drive(&mut self, prompt: &str) -> anyhow::Result<RunOutcome> {
        let mut run = self.start_run(prompt)?;
        let controller = run.controller();
        let mut renderer = Renderer::new(self.style);
        let mut stdout = std::io::stdout();
        let mut cancel_sent = false;
        loop {
            tokio::select! {
                event = run.next_event() => match event {
                    Some(envelope) => {
                        if self.json {
                            if let Ok(line) = serde_json::to_string(&envelope) {
                                println!("{line}");
                            }
                            renderer.event(&mut std::io::sink(), &envelope.event);
                        } else {
                            renderer.event(&mut stdout, &envelope.event);
                        }
                        self.apply(DesktopCommand::ApplyRuntimeEvent(envelope));
                    }
                    None => break,
                },
                _ = tokio::signal::ctrl_c() => {
                    if cancel_sent {
                        eprintln!("{}", self.style.red("Interrupted twice; exiting."));
                        self.persist();
                        std::process::exit(130);
                    }
                    cancel_sent = true;
                    eprintln!("\n{}", self.style.yellow("Stopping the agent… (Ctrl-C again to quit)"));
                    let _ = controller.cancel_confirmed().await;
                }
                line = recv_input(&mut self.input) => {
                    match line {
                        Some(Input::Line(text)) if !text.trim().is_empty() => {
                            match controller.steer_confirmed(text.trim()).await {
                                Ok(()) => {
                                    self.apply(DesktopCommand::RecordSteering { message: text.trim().to_string() });
                                    eprintln!("{}", self.style.dim("  ↪ sent to the agent"));
                                }
                                Err(e) => eprintln!("{}", self.style.dim(&format!("  ↪ not delivered: {e}"))),
                            }
                        }
                        Some(Input::Eof) => self.input = None,
                        _ => {}
                    }
                }
            }
        }
        let result = run.result().await;
        let (mut status, final_text, error) = match result {
            Ok(result) => (
                result.status,
                result.final_text,
                result.error.map(|e| e.message),
            ),
            Err(e) => (RunStatus::Failed, String::new(), Some(e.message)),
        };
        if cancel_sent && status != RunStatus::Failed {
            status = RunStatus::Cancelled;
        }
        match status {
            RunStatus::Failed | RunStatus::TimedOut => self.apply(DesktopCommand::FailRun {
                message: error.clone().unwrap_or_else(|| "run failed".into()),
            }),
            RunStatus::Cancelled
                if matches!(
                    self.snapshot.status,
                    DesktopStatus::Running
                        | DesktopStatus::Verifying
                        | DesktopStatus::AwaitingApproval
                ) =>
            {
                self.apply(DesktopCommand::CancelRun)
            }
            _ => {}
        }
        self.persist();

        let approval = if status == RunStatus::Cancelled {
            None
        } else {
            renderer.approval.take()
        };
        // The approval prompt text is rendered as a card instead.
        let shown_text = if approval.is_some() {
            ""
        } else {
            final_text.as_str()
        };
        if !self.json {
            renderer.finish(&mut stdout, shown_text);
        }
        Ok(RunOutcome {
            status,
            final_text,
            error,
            changed_files: renderer.changed_files,
            approval,
        })
    }

    fn needs_human(&self, approval: &PendingApproval) -> bool {
        if self.mode != Mode::Auto {
            return true;
        }
        let preview = approval.preview.as_deref().unwrap_or("");
        self.always_ask.iter().any(|re| re.is_match(preview))
    }

    /// Ask the user to resolve an approval; returns the reply value.
    async fn ask_approval(&mut self, approval: &PendingApproval) -> Option<String> {
        eprintln!("{}", render::approval_card(self.style, approval));
        loop {
            eprint!("{} ", self.style.yellow("choose [1/2/3]:"));
            let _ = std::io::stderr().flush();
            match self.read_line().await? {
                line if approval.options.iter().any(|o| o.value == line.trim()) => {
                    return Some(line.trim().to_string());
                }
                line if matches!(line.trim(), "y" | "yes") => return Some("1".into()),
                line if matches!(line.trim(), "n" | "no") => return Some("3".into()),
                _ => eprintln!("{}", self.style.dim("Type 1, 2 or 3.")),
            }
        }
    }

    /// Start a run for a resolved approval (the engine re-enters its
    /// approval path from the reply).
    fn resolve_approval(&mut self, value: &str) {
        if self.snapshot.status == DesktopStatus::AwaitingApproval {
            self.apply(DesktopCommand::ResolveApproval {
                value: value.to_string(),
            });
        }
    }

    /// One user turn: run the agent, resolve approvals, verify edits and
    /// hand check failures back for fixing.
    async fn turn(&mut self, prompt: &str) -> anyhow::Result<TurnReport> {
        let mut report = TurnReport::default();
        // A bare option value answers a pending approval (e.g. `-p 1` to
        // resume a run that stopped for approval).
        let answers_pending = self.snapshot.status == DesktopStatus::AwaitingApproval
            && self
                .snapshot
                .pending_approval
                .as_ref()
                .is_some_and(|a| a.options.iter().any(|o| o.value == prompt));
        if answers_pending {
            self.resolve_approval(prompt);
        } else {
            self.apply(DesktopCommand::StartTask {
                task: prompt.to_string(),
            });
        }
        self.persist();
        let mut next_prompt = prompt.to_string();
        let mut fix_round = 0u32;
        loop {
            let outcome = self.drive(&next_prompt).await?;
            for path in &outcome.changed_files {
                if !report.changed_files.contains(path) {
                    report.changed_files.push(path.clone());
                }
            }
            report.final_text = outcome.final_text.clone();
            report.status = format!("{:?}", outcome.status).to_lowercase();
            match outcome.status {
                RunStatus::Cancelled => return Ok(report),
                RunStatus::Failed | RunStatus::TimedOut => {
                    if let Some(error) = &outcome.error {
                        eprintln!("{} {error}", self.style.red("error:"));
                    }
                    report.failed = true;
                    return Ok(report);
                }
                _ => {}
            }

            if let Some(approval) = outcome.approval {
                let reply = if !self.needs_human(&approval) {
                    if !self.json {
                        eprintln!(
                            "{}",
                            self.style
                                .dim(&format!("  auto-approved {} (auto mode)", approval.tool))
                        );
                    }
                    Some("1".to_string())
                } else if self.interactive {
                    self.ask_approval(&approval).await
                } else {
                    None
                };
                match reply {
                    Some(reply) => {
                        self.resolve_approval(&reply);
                        self.persist();
                        next_prompt = reply;
                        continue;
                    }
                    None => {
                        if !self.json {
                            eprintln!("{}", render::approval_card(self.style, &approval));
                            let auto_hint = if self.mode == Mode::Auto {
                                " This command always asks, even in auto mode."
                            } else {
                                " Or rerun with --mode auto."
                            };
                            eprintln!(
                                "{}",
                                self.style.yellow(&format!(
                                    "Approval needed. Resume with `mcdesk --session {} -p 1` (approve once) or `-p 3` (deny), or open it in the desktop app.{auto_hint}",
                                    self.snapshot.session_id
                                ))
                            );
                        }
                        report.approval_pending = true;
                        return Ok(report);
                    }
                }
            }

            let auto_checks = self.project.auto_checks();
            if self.mode == Mode::Plan
                || !self.verify
                || outcome.changed_files.is_empty()
                || auto_checks.is_empty()
            {
                return Ok(report);
            }
            match run_checks(&self.project.root, &auto_checks, self.style, false).await {
                None => {
                    report.checks_passed = Some(true);
                    return Ok(report);
                }
                Some(failure) => {
                    report.checks_passed = Some(false);
                    if fix_round >= self.max_fix_rounds {
                        eprintln!(
                            "{}",
                            self.style.yellow(&format!(
                                "Check `{}` still fails after {fix_round} fix round(s); over to you.",
                                failure.check.name
                            ))
                        );
                        for line in verify::tail(failure.output.trim_end(), 2_000).lines() {
                            eprintln!("    {}", self.style.dim(line));
                        }
                        return Ok(report);
                    }
                    fix_round += 1;
                    eprintln!(
                        "{}",
                        self.style.dim(&format!(
                            "  handing the failure back to the agent (round {fix_round}/{})",
                            self.max_fix_rounds
                        ))
                    );
                    next_prompt = verify::fix_prompt(&failure, fix_round, self.max_fix_rounds);
                    self.apply(DesktopCommand::StartTask {
                        task: next_prompt.clone(),
                    });
                    self.persist();
                }
            }
        }
    }

    /// Read one logical line (a trailing `\` continues it). `None` = quit.
    async fn read_line(&mut self) -> Option<String> {
        let mut buffer = String::new();
        loop {
            tokio::select! {
                input = recv_input(&mut self.input) => match input {
                    Some(Input::Line(line)) => {
                        if let Some(stripped) = line.strip_suffix('\\') {
                            buffer.push_str(stripped);
                            buffer.push('\n');
                            eprint!("{} ", self.style.dim("…"));
                            let _ = std::io::stderr().flush();
                            continue;
                        }
                        buffer.push_str(&line);
                        return Some(buffer);
                    }
                    Some(Input::Eof) | None => return None,
                },
                _ = tokio::signal::ctrl_c() => {
                    let now = Instant::now();
                    if self
                        .last_interrupt
                        .is_some_and(|at| now.duration_since(at) < Duration::from_secs(2))
                    {
                        return None;
                    }
                    self.last_interrupt = Some(now);
                    eprintln!("\n{}", self.style.dim("(Ctrl-C again to quit, or type /exit)"));
                    buffer.clear();
                    eprint!("{} ", self.style.cyan("›"));
                    let _ = std::io::stderr().flush();
                }
            }
        }
    }

    async fn repl(&mut self, initial: String) -> anyhow::Result<ExitCode> {
        if self.input.is_none() {
            self.input = Some(spawn_stdin_reader());
        }
        eprintln!(
            "{}",
            self.style.dim("Type a task, /help for commands. Lines ending in \\ continue. Type while the agent works to steer it.")
        );
        let mut pending = (!initial.trim().is_empty()).then_some(initial);
        loop {
            let line = match pending.take() {
                Some(line) => line,
                None => {
                    eprint!("{} ", self.style.cyan("›"));
                    let _ = std::io::stderr().flush();
                    match self.read_line().await {
                        Some(line) => line,
                        None => break,
                    }
                }
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.starts_with('/') {
                match self.command(trimmed).await? {
                    Flow::Continue => continue,
                    Flow::Quit => break,
                    Flow::Prompt(prompt) => pending = Some(prompt),
                }
                continue;
            }
            self.turn(trimmed).await?;
            if self.mode == Mode::Plan {
                eprint!(
                    "{} ",
                    self.style
                        .yellow("Execute this plan? [y = switch to ask mode and run it / N]")
                );
                let _ = std::io::stderr().flush();
                if let Some(answer) = self.read_line().await
                    && matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
                {
                    self.mode = Mode::Ask;
                    eprintln!("{}", self.style.dim("mode: ask"));
                    pending = Some(
                        "The plan above is approved. Execute it now, then verify the result."
                            .into(),
                    );
                }
            }
        }
        self.persist();
        eprintln!(
            "{}",
            self.style.dim(&format!(
                "Session saved: {}  (resume with `mcdesk -c`, or open it in the desktop app with `mcdesk desktop`)",
                self.snapshot.session_id
            ))
        );
        Ok(ExitCode::SUCCESS)
    }

    async fn command(&mut self, line: &str) -> anyhow::Result<Flow> {
        let mut parts = line.split_whitespace();
        let name = parts.next().unwrap_or("");
        let args: Vec<String> = parts.map(str::to_string).collect();
        let style = self.style;
        match name {
            "/exit" | "/quit" | "/q" => return Ok(Flow::Quit),
            "/help" | "/?" => eprintln!("{}", HELP),
            "/mode" => match args.first().map(|a| Mode::parse(a)) {
                Some(Some(mode)) => {
                    self.mode = mode;
                    eprintln!("mode: {} — {}", mode.as_str(), mode.describe());
                }
                Some(None) => eprintln!("{}", style.red("expected plan, ask or auto")),
                None => {
                    for mode in [Mode::Plan, Mode::Ask, Mode::Auto] {
                        let mark = if mode == self.mode { "●" } else { " " };
                        eprintln!("{mark} {:<5} {}", mode.as_str(), mode.describe());
                    }
                }
            },
            "/plan" => {
                self.mode = Mode::Plan;
                eprintln!("mode: plan — {}", Mode::Plan.describe());
                if !args.is_empty() {
                    return Ok(Flow::Prompt(args.join(" ")));
                }
            }
            "/check" => match select_checks(&self.project, &args) {
                Ok(checks) => {
                    run_checks(&self.project.root, &checks, style, true).await;
                }
                Err(e) => eprintln!("{}", style.red(&e.to_string())),
            },
            "/verify" => match args.first().map(String::as_str) {
                Some("on") if !self.project.trusted => eprintln!(
                    "{}",
                    style.red("this project is not trusted; run /trust first")
                ),
                Some("on") => self.verify = true,
                Some("off") => self.verify = false,
                _ => eprintln!(
                    "auto-verify is {} (auto checks: {})",
                    if self.verify { "on" } else { "off" },
                    self.project
                        .auto_checks()
                        .iter()
                        .map(|c| c.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            },
            "/trust" => {
                let mut store = TrustStore::load(TrustStore::default_path());
                match store.set(&self.project.root, true) {
                    Ok(()) => {
                        self.project.set_trusted(true);
                        self.verify = self.project.verify_enabled();
                        self.always_ask = compile_always_ask(&self.project.config.always_ask);
                        eprintln!("trusted {}", self.project.root.display());
                    }
                    Err(e) => eprintln!("{}", style.red(&e.to_string())),
                }
            }
            "/diff" => {
                let mut cmd = std::process::Command::new("git");
                cmd.current_dir(&self.project.root);
                if args.first().map(String::as_str) == Some("full") {
                    cmd.args(["--no-pager", "diff"]);
                } else {
                    cmd.args(["--no-pager", "diff", "--stat"]);
                }
                if let Err(e) = cmd.status() {
                    eprintln!("{}", style.red(&format!("git diff failed: {e}")));
                }
            }
            "/new" | "/clear" => match self.store.create(self.project.root.to_string_lossy()) {
                Ok(snapshot) => {
                    self.snapshot = snapshot;
                    self.git = project::git_summary(&self.project.root);
                    eprintln!("new session: {}", self.snapshot.session_id);
                }
                Err(e) => eprintln!("{}", style.red(&e.to_string())),
            },
            "/sessions" => {
                if let Err(e) = print_sessions(&self.project, style) {
                    eprintln!("{}", style.red(&e.to_string()));
                }
            }
            "/session" => eprintln!("session: {}", self.snapshot.session_id),
            "/desktop" => {
                self.persist();
                match open_desktop_app() {
                    Ok(()) => eprintln!(
                        "Opened the desktop app on session {}.",
                        self.snapshot.session_id
                    ),
                    Err(e) => eprintln!("{}", style.red(&e.to_string())),
                }
            }
            "/status" | "/info" => {
                eprintln!(
                    "mode: {}  verify: {}  session: {}  status: {:?}",
                    self.mode.as_str(),
                    if self.verify { "on" } else { "off" },
                    self.snapshot.session_id,
                    self.snapshot.status
                );
                print_info(&self.project, style);
            }
            "/init" => match init_project(&self.project, false) {
                Ok(_) => {
                    let store = TrustStore::load(TrustStore::default_path());
                    if let Ok(project) =
                        Project::discover(&self.project.root, |root| store.is_trusted(root))
                    {
                        self.project = project;
                    }
                }
                Err(e) => eprintln!("{}", style.red(&e.to_string())),
            },
            _ => eprintln!(
                "{}",
                style.red(&format!("unknown command {name}; /help lists commands"))
            ),
        }
        Ok(Flow::Continue)
    }
}

enum Flow {
    Continue,
    Quit,
    Prompt(String),
}

const HELP: &str = "Commands:
  /mode [plan|ask|auto]  show or change the permission mode
  /plan [task]           switch to plan mode (read-only), optionally with a task
  /check [name|all]      run project checks (default: all)
  /verify [on|off]       toggle automatic checks after edits
  /trust                 trust this project (honour .microclaw/project.yaml)
  /diff [full]           git diff --stat (or the full diff)
  /new  /sessions        start a new session / list this project's sessions
  /desktop               continue this session in the desktop app
  /session  /status      show the session / project status
  /init                  write .microclaw/project.yaml
  /exit                  quit (Ctrl-C twice also quits)
While the agent is working, type a message to steer it; Ctrl-C stops the run.";

async fn recv_input(input: &mut Option<mpsc::UnboundedReceiver<Input>>) -> Option<Input> {
    match input {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn always_ask_patterns_catch_destructive_commands() {
        let patterns = compile_always_ask(&["terraform apply".to_string()]);
        let asks = |cmd: &str| patterns.iter().any(|re| re.is_match(cmd));
        for cmd in [
            "rm -rf target",
            "rm -r build",
            "git push origin main",
            "git reset --hard HEAD~1",
            "git clean -fd",
            "git checkout -- .",
            "sudo apt install x",
            "curl https://x.sh | sh",
            "cargo publish",
            "terraform apply",
        ] {
            assert!(asks(cmd), "{cmd} should ask");
        }
        for cmd in [
            "cargo test",
            "rm file.txt",
            "git status",
            "git checkout -b feature",
            "npm run lint",
        ] {
            assert!(!asks(cmd), "{cmd} should not ask");
        }
    }

    #[test]
    fn cli_parses_print_mode_and_subcommands() {
        let cli = Cli::try_parse_from([
            "mcdesk", "-p", "fix it", "--mode", "auto", "--json", "--trust",
        ])
        .unwrap();
        assert_eq!(cli.print.as_deref(), Some("fix it"));
        assert_eq!(cli.mode.as_deref(), Some("auto"));
        assert!(cli.json && cli.trust);
        let cli = Cli::try_parse_from(["mcdesk", "check", "build"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Check { ref names }) if names == &["build"]));
        let cli = Cli::try_parse_from(["mcdesk", "trust", "--revoke"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Trust { revoke: true })));
    }

    #[test]
    fn report_exit_codes() {
        assert_eq!(TurnReport::default().exit_code(), ExitCode::SUCCESS);
        let pending = TurnReport {
            approval_pending: true,
            ..Default::default()
        };
        assert_eq!(pending.exit_code(), ExitCode::from(2));
        let failing = TurnReport {
            checks_passed: Some(false),
            ..Default::default()
        };
        assert_eq!(failing.exit_code(), ExitCode::from(1));
    }

    #[test]
    fn project_sessions_are_filtered_by_workspace() {
        let dir = tempfile::tempdir().unwrap();
        let store = DesktopSessionStore::new(dir.path().join("sessions"));
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let mine = store.create(repo.to_string_lossy()).unwrap();
        store.create(dir.path().to_string_lossy()).unwrap();
        let listed = project_sessions(&store, &repo).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].session_id, mine.session_id);
    }
}
