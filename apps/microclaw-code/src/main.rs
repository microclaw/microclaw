//! `mccode` — MicroClaw Code, a terminal coding agent.
//!
//! Opens the repository that contains the current directory and runs the
//! MicroClaw Agent Engine (through `microclaw-sdk`) in it: a full-screen TUI
//! for interactive work, or `-p` for one non-interactive task. Turn logic
//! (approvals, verification, fix loop) lives in `microclaw-code-core`; this
//! binary only handles the command line and presentation.

mod format;
mod print;
mod setup;
mod tui;

use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use microclaw_code_core::driver::{
    CALLER_CHANNEL, CodeSession, Control, SessionSettings, compile_always_ask,
};
use microclaw_code_core::home;
use microclaw_code_core::project::{self, Mode, Project};
use microclaw_code_core::sessions::SessionIndex;
use microclaw_code_core::trust::{TrustDecision, TrustStore};
use microclaw_code_core::verify;
use microclaw_sdk::MicroClaw;
use tokio::sync::mpsc;

use print::{Printer, Style, approval_card};

#[derive(Debug, Parser)]
#[command(
    name = "mccode",
    version,
    about = "MicroClaw Code: a coding agent for your repository",
    long_about = "MicroClaw Code opens the repository that contains the current directory and runs the MicroClaw Agent Engine in it.\n\nRun without arguments for the full-screen interface, or pass -p for one non-interactive task. Configure a model with `mccode setup`."
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

    /// Resume a session by id (see `mccode sessions`).
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
    /// Configure the model MicroClaw Code uses.
    Setup {
        #[arg(long)]
        provider: Option<String>,
        #[arg(long)]
        model: Option<String>,
        #[arg(long)]
        api_key: Option<String>,
        #[arg(long)]
        base_url: Option<String>,
    },
    /// Check the configuration and start the Agent Engine once.
    Doctor,
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
    /// Show what MicroClaw Code detected for this project.
    Info,
    /// List this project's sessions.
    Sessions,
    /// Trust this project, or revoke trust with --revoke.
    Trust {
        #[arg(long)]
        revoke: bool,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(code) => code,
        Err(error) => {
            eprintln!("mccode: {error:#}");
            ExitCode::from(1)
        }
    }
}

async fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    let style = Style::detect();
    if let Some(Command::Setup {
        provider,
        model,
        api_key,
        base_url,
    }) = &cli.command
    {
        let path = setup::run(setup::SetupArgs {
            provider: provider.clone(),
            model: model.clone(),
            api_key: api_key.clone(),
            base_url: base_url.clone(),
        })?;
        eprintln!(
            "Wrote {}. Run `mccode` in a repository to start.",
            path.display()
        );
        return Ok(ExitCode::SUCCESS);
    }

    let start = match &cli.cwd {
        Some(dir) => dir.clone(),
        None => std::env::current_dir()?,
    };
    let mut trust_store = TrustStore::load(TrustStore::default_path());
    let mut project = Project::discover(&start, |root, hash| trust_store.is_trusted(root, hash))?;
    if cli.trust && !project.trusted {
        trust_store.set(&project.root, true, project.config_sha256.as_deref())?;
        project.set_trusted(true);
    }

    match &cli.command {
        Some(Command::Setup { .. }) => unreachable!("handled above"),
        Some(Command::Info) => {
            print_info(&project, &trust_store, style);
            return Ok(ExitCode::SUCCESS);
        }
        Some(Command::Init { force }) => return init_project(&project, *force),
        Some(Command::Check { names }) => return check_command(&project, names, style).await,
        Some(Command::Sessions) => {
            print_sessions(&project, style);
            return Ok(ExitCode::SUCCESS);
        }
        Some(Command::Trust { revoke }) => {
            trust_store.set(&project.root, !revoke, project.config_sha256.as_deref())?;
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
        Some(Command::Doctor) => return doctor(&cli, &project, style).await,
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
    if interactive && !(std::io::stdin().is_terminal() && std::io::stdout().is_terminal()) {
        anyhow::bail!(
            "the interactive interface needs a terminal; pass a task with -p \"...\" (or -p - to read it from stdin)"
        );
    }

    let mut notices = Vec::new();
    let (_, warnings) = compile_always_ask(&project.config.always_ask);
    notices.extend(warnings);
    if !interactive && !project.trusted && !cli.json {
        let decision = trust_store.decision(&project.root, project.config_sha256.as_deref());
        if decision == TrustDecision::ConfigChanged {
            eprintln!("{}", style.yellow(".microclaw/project.yaml changed since you trusted this project; it is ignored until you trust it again (--trust)."));
        } else if project.has_config_file || !project.checks.is_empty() {
            eprintln!("{}", style.dim("Project not trusted: .microclaw/project.yaml is ignored and checks do not run automatically. Pass --trust to trust it."));
        }
    }

    let mode = match cli.mode.as_deref() {
        Some(raw) => Mode::parse(raw)
            .ok_or_else(|| anyhow::anyhow!("unknown mode '{raw}' (expected plan, ask or auto)"))?,
        None => project.config.mode.unwrap_or_default(),
    };
    let (config_path, source) = home::resolve_config(cli.config.as_deref())?;
    if source == home::ConfigSource::Server && !cli.json {
        eprintln!(
            "{}",
            style.dim(&format!(
                "Using model credentials from {} (run `mccode setup` for a Code-only configuration).",
                config_path.display()
            ))
        );
    }

    let mut index = SessionIndex::load(SessionIndex::default_path());
    let session_id = if let Some(id) = &cli.session {
        id.clone()
    } else if cli.continue_last {
        index
            .for_project(&project.root)
            .first()
            .map(|r| r.id.clone())
            .ok_or_else(|| anyhow::anyhow!("no previous session for this project"))?
    } else {
        index.create(&project.root)?.id
    };

    if !cli.json {
        eprintln!("{}", style.dim("Starting the Agent Engine…"));
    }
    let microclaw = MicroClaw::builder(&config_path)
        .caller_channel(CALLER_CHANNEL)
        .workspace(&project.root)
        .data_dir(home::data_dir())
        .max_concurrent_runs(1)
        .build()
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let settings = SessionSettings {
        mode,
        verify: !cli.no_verify,
        max_fix_rounds: cli
            .max_fix_rounds
            .unwrap_or_else(|| project.max_fix_rounds()),
        interactive,
    };
    let session = CodeSession::new(microclaw, project, session_id.clone(), settings);

    match print_prompt {
        Some(prompt) => print_mode(session, &mut index, prompt.trim(), cli.json, style).await,
        None => {
            let initial = (!cli.prompt.is_empty()).then(|| cli.prompt.join(" "));
            let id = tui::run(session, index, trust_store, initial, notices).await?;
            eprintln!("Session {id} saved. Resume with `mccode -c`.");
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// `-p`: one turn, printed as lines (or JSON Lines).
async fn print_mode(
    mut session: CodeSession,
    index: &mut SessionIndex,
    prompt: &str,
    json: bool,
    style: Style,
) -> anyhow::Result<ExitCode> {
    let _ = index.touch(&session.session_id, prompt);
    let (updates_tx, mut updates_rx) = mpsc::unbounded_channel();
    let (controls_tx, mut controls_rx) = mpsc::unbounded_channel();
    let prompt = prompt.to_string();
    let task = tokio::spawn(async move {
        let report = session.turn(&prompt, &updates_tx, &mut controls_rx).await;
        (session, report)
    });
    tokio::pin!(task);
    let mut printer = Printer::new(style, json);
    let (mut out, mut err) = (std::io::stdout(), std::io::stderr());
    let mut interrupted = false;
    let (session, report) = loop {
        tokio::select! {
            Some(update) = updates_rx.recv() => printer.update(&update, &mut out, &mut err),
            _ = tokio::signal::ctrl_c() => {
                if interrupted {
                    std::process::exit(130);
                }
                interrupted = true;
                eprintln!("\n{}", style.yellow("Stopping the agent… (Ctrl-C again to quit)"));
                let _ = controls_tx.send(Control::Cancel);
            }
            result = &mut task => break result?,
        }
    };
    while let Ok(update) = updates_rx.try_recv() {
        printer.update(&update, &mut out, &mut err);
    }
    let report = report?;
    if let Some(approval) = &report.approval_pending {
        if !json {
            eprintln!("{}", approval_card(style, approval));
            let hint = if session.settings.mode == Mode::Auto {
                " This command always asks, even in auto mode."
            } else {
                " Or rerun with --mode auto."
            };
            eprintln!(
                "{}",
                style.yellow(&format!(
                    "Approval needed. Resume with `mccode --session {} -p 1` (approve once) or `-p 3` (deny).{hint}",
                    session.session_id
                ))
            );
        }
    } else if report.checks_passed == Some(true) && !json {
        eprintln!("{}", style.green("all checks passed"));
    }
    if json {
        println!(
            "{}",
            serde_json::json!({
                "type": "result",
                "status": report.status,
                "session": session.session_id,
                "final_text": report.final_text,
                "changed_files": report.changed_files,
                "checks_passed": report.checks_passed,
                "approval_pending": report.approval_pending.is_some(),
            })
        );
    }
    Ok(ExitCode::from(report.exit_code()))
}

fn print_info(project: &Project, trust: &TrustStore, style: Style) {
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
    let trust_label = match trust.decision(&project.root, project.config_sha256.as_deref()) {
        TrustDecision::Trusted => "yes",
        TrustDecision::Distrusted => "no",
        TrustDecision::Undecided => "not decided (run `mccode trust`)",
        TrustDecision::ConfigChanged => "project file changed since trusted (run `mccode trust`)",
    };
    println!("{} {trust_label}", style.bold("trusted:"));
    let config_state = match (project.has_config_file, project.trusted) {
        (true, true) => "present",
        (true, false) => "present, ignored until trusted",
        (false, _) => "absent (run `mccode init`)",
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
    match home::resolve_config(None) {
        Ok((path, source)) => println!(
            "{} {} ({})",
            style.bold("model config:"),
            path.display(),
            source.describe()
        ),
        Err(e) => println!("{} {e}", style.bold("model config:")),
    }
    println!(
        "{} {}",
        style.bold("code home:"),
        home::code_home().display()
    );
    if let Some(git) = project::git_summary(&project.root) {
        println!("{}\n{git}", style.bold("git:"));
    }
}

fn print_sessions(project: &Project, style: Style) {
    let index = SessionIndex::load(SessionIndex::default_path());
    let records = index.for_project(&project.root);
    if records.is_empty() {
        println!("No sessions for {} yet.", project.root.display());
        return;
    }
    for r in records {
        println!(
            "{}  {:>3} turn(s)  {}",
            style.bold(&r.id),
            r.turns,
            if r.title.is_empty() {
                "(empty)"
            } else {
                &r.title
            }
        );
    }
    println!(
        "{}",
        style.dim("Resume with `mccode --session <id>`, or `mccode -c` for the most recent.")
    );
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
    println!("Run `mccode trust` so these settings take effect for you.");
    Ok(ExitCode::SUCCESS)
}

async fn check_command(
    project: &Project,
    names: &[String],
    style: Style,
) -> anyhow::Result<ExitCode> {
    anyhow::ensure!(
        !project.checks.is_empty(),
        "no checks detected for this project; add them to {} (see `mccode init`)",
        project.config_path().display()
    );
    let checks: Vec<_> = if names.is_empty() || names.iter().any(|n| n == "all") {
        project.checks.clone()
    } else {
        names
            .iter()
            .map(|name| {
                project
                    .checks
                    .iter()
                    .find(|c| &c.name == name)
                    .cloned()
                    .ok_or_else(|| {
                        let known: Vec<_> =
                            project.checks.iter().map(|c| c.name.as_str()).collect();
                        anyhow::anyhow!("unknown check '{name}' (known: {})", known.join(", "))
                    })
            })
            .collect::<anyhow::Result<_>>()?
    };
    for check in &checks {
        eprintln!(
            "{} {} {}",
            style.cyan("▸"),
            style.bold(&check.name),
            style.dim(&check.run)
        );
        let outcome = verify::run_check(&project.root, check).await;
        let elapsed = format::elapsed(outcome.duration);
        if outcome.success {
            eprintln!("  {} {}", style.green("passed"), style.dim(&elapsed));
        } else {
            eprintln!(
                "  {} {}",
                style.red(&outcome.status_label()),
                style.dim(&elapsed)
            );
            for line in verify::tail(outcome.output.trim_end(), 4_000).lines() {
                eprintln!("    {}", style.dim(line));
            }
            return Ok(ExitCode::from(1));
        }
    }
    Ok(ExitCode::SUCCESS)
}

async fn doctor(cli: &Cli, project: &Project, style: Style) -> anyhow::Result<ExitCode> {
    let ok = |label: &str, detail: String| println!("{} {label}: {detail}", style.green("✓"));
    let bad = |label: &str, detail: String| println!("{} {label}: {detail}", style.red("✗"));
    let (path, source) = match home::resolve_config(cli.config.as_deref()) {
        Ok(found) => found,
        Err(e) => {
            bad("model configuration", e.to_string());
            return Ok(ExitCode::from(1));
        }
    };
    ok(
        "model configuration",
        format!("{} ({})", path.display(), source.describe()),
    );
    if let Err(e) = microclaw_sdk::validate_config_file(&path) {
        bad("configuration is valid", e.to_string());
        return Ok(ExitCode::from(1));
    }
    ok("configuration is valid", "yes".into());
    ok("code home", home::code_home().display().to_string());
    ok(
        "project",
        format!(
            "{} ({}, {})",
            project.root.display(),
            if project.kinds.is_empty() {
                "unknown type".to_string()
            } else {
                project.kinds.join(", ")
            },
            if project.trusted {
                "trusted"
            } else {
                "untrusted"
            }
        ),
    );
    match MicroClaw::builder(&path)
        .caller_channel(CALLER_CHANNEL)
        .workspace(&project.root)
        .data_dir(home::data_dir())
        .max_concurrent_runs(1)
        .build()
        .await
    {
        Ok(engine) => ok(
            "agent engine",
            format!(
                "started ({} skills available)",
                engine.skills().available().count()
            ),
        ),
        Err(e) => {
            bad("agent engine", e.to_string());
            return Ok(ExitCode::from(1));
        }
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parses_print_mode_and_subcommands() {
        let cli = Cli::try_parse_from([
            "mccode", "-p", "fix it", "--mode", "auto", "--json", "--trust",
        ])
        .unwrap();
        assert_eq!(cli.print.as_deref(), Some("fix it"));
        assert_eq!(cli.mode.as_deref(), Some("auto"));
        assert!(cli.json && cli.trust);
        let cli = Cli::try_parse_from(["mccode", "check", "build"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Check { ref names }) if names == &["build"]));
        let cli = Cli::try_parse_from(["mccode", "trust", "--revoke"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Trust { revoke: true })));
        let cli = Cli::try_parse_from(["mccode", "setup", "--provider", "ollama", "--model", "q"])
            .unwrap();
        assert!(matches!(cli.command, Some(Command::Setup { .. })));
        let cli = Cli::try_parse_from(["mccode", "fix", "the", "bug"]).unwrap();
        assert_eq!(cli.prompt, vec!["fix", "the", "bug"]);
    }
}
