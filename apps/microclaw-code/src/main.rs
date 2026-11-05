//! `mccode` — MicroClaw Code, a terminal coding agent.
//!
//! Opens the repository that contains the current directory and runs the
//! MicroClaw Agent Engine (through `microclaw-sdk`) in it: a full-screen TUI
//! for interactive work, or `-p` for one non-interactive task. Turn logic
//! (approvals, verification, fix loop) lives in `microclaw-code-core`; this
//! binary only handles the command line and presentation.

mod acp;
mod eval;
mod format;
mod mcp_server;
mod print;
mod setup;
mod tui;
mod update;

use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use microclaw_code_core::allow::{self, AllowRules};
use microclaw_code_core::driver::{
    CALLER_CHANNEL, CodeSession, Control, SandboxInfo, SessionSettings, compile_always_ask,
};
use microclaw_code_core::home;
use microclaw_code_core::project::{self, Mode, Project};
use microclaw_code_core::sessions::SessionIndex;
use microclaw_code_core::trust::{TrustDecision, TrustStore};
use microclaw_code_core::verify;
use microclaw_sdk::{MicroClaw, ShellSandbox};
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

    /// Shell sandbox: `workspace-write` (default: commands write only the
    /// repository, temp and tool caches) or `off`. Also MICROCLAW_CODE_SANDBOX.
    #[arg(long, value_name = "MODE")]
    sandbox: Option<String>,

    /// Deny network access to sandboxed shell commands. In ask mode such
    /// commands then run without asking (they cannot change anything outside
    /// the repository).
    #[arg(long)]
    no_network: bool,

    /// Have the model review each command that needs approval; a command it
    /// calls DANGEROUS asks you even in auto mode.
    #[arg(long)]
    review_commands: bool,

    /// Let the agent save checkpoints and rewind its own context
    /// (`context_note` / `rewind_context`; experimental).
    #[arg(long)]
    context_tools: bool,

    /// Run in a new git worktree on branch `mccode/<NAME>` (default: a
    /// generated name), leaving the main checkout untouched.
    #[arg(long, value_name = "NAME", num_args = 0..=1, default_missing_value = "")]
    worktree: Option<String>,

    /// Stop once this session used this many tokens (input + output).
    #[arg(long, value_name = "TOKENS")]
    max_session_tokens: Option<u64>,

    /// With -p: run the task on the paired MicroClaw Server (see
    /// `mccode remote pair`) instead of this machine.
    #[arg(long, requires = "print")]
    remote: bool,

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
    /// Run evaluation cases (directories with case.yaml + repo/), or create
    /// cases from a repository's bug-fix commits with `eval replay`.
    Eval {
        #[command(subcommand)]
        action: Option<EvalAction>,
        /// Directory of cases (or one case).
        #[arg(default_value = "eval")]
        dir: PathBuf,
        /// Only cases whose path contains this text.
        #[arg(long)]
        filter: Option<String>,
        /// Keep each case's workspace for inspection.
        #[arg(long)]
        keep: bool,
    },
    /// Install the latest release of mccode (checksum-verified).
    Update {
        /// Only report whether a newer release exists.
        #[arg(long)]
        check: bool,
    },
    /// Pair with a MicroClaw Server, show or forget the pairing.
    Remote {
        #[command(subcommand)]
        action: RemoteAction,
    },
    /// Serve the Agent Client Protocol on stdin/stdout (for editors such as
    /// Zed: configure `mccode acp` as a custom agent).
    Acp,
    /// Serve the Model Context Protocol on stdin/stdout: tools `run` and
    /// `review` let other agents delegate coding tasks to MicroClaw Code.
    McpServer,
    /// Review the uncommitted changes (read-only) and print the findings.
    Review {
        /// What to focus on, e.g. "error handling" or a path.
        focus: Vec<String>,
        /// Review pull request N (via `gh pr diff`, or fetched from origin)
        /// instead of the uncommitted changes.
        #[arg(long, value_name = "N")]
        pr: Option<u64>,
        /// With --pr: post the review as a PR comment (`gh pr comment`).
        #[arg(long, requires = "pr")]
        post: bool,
    },
    /// Write a session's transcript as Markdown.
    Export {
        /// Output file (default: mccode-<session>.md in the current directory).
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// List or remove worktrees created with --worktree.
    Worktree {
        #[command(subcommand)]
        action: WorktreeAction,
    },
    /// List, add or remove shell commands that run without asking here.
    Allow {
        #[command(subcommand)]
        action: Option<AllowAction>,
    },
}

#[derive(Debug, Subcommand)]
enum EvalAction {
    /// Write one case per bug-fix commit (parent = snapshot, message = prompt).
    Replay {
        /// Commit range, e.g. v0.10.0..HEAD
        range: String,
        /// Check command that must pass after the fix, e.g. "cargo test".
        #[arg(long)]
        check: String,
        /// Output directory.
        #[arg(long, default_value = "eval/replay")]
        out: PathBuf,
        /// Include every commit, not only those that mention a fix.
        #[arg(long)]
        all: bool,
    },
}

#[derive(Debug, Subcommand)]
enum WorktreeAction {
    /// List this repository's MicroClaw Code worktrees.
    List,
    /// Remove a worktree (it must have no uncommitted changes) and its merged branch.
    Remove { name: String },
}

#[derive(Debug, Subcommand)]
enum RemoteAction {
    /// Claim a pairing code from the Server's web console (Access tab).
    Pair {
        /// Server URL, e.g. http://my-server:10961
        url: String,
        /// The 8-character pairing code.
        code: String,
        /// Name shown in the Server's device list (default: host name).
        #[arg(long)]
        name: Option<String>,
    },
    /// Show the pairing and check that the Server accepts it.
    Status,
    /// Remove the stored pairing (revoke the device in the Server too).
    Forget,
}

#[derive(Debug, Subcommand)]
enum AllowAction {
    /// List this project's rules (default).
    List,
    /// Allow commands starting with PREFIX (e.g. `mccode allow add cargo test`).
    Add {
        #[arg(required = true, num_args = 1.., value_name = "PREFIX")]
        prefix: Vec<String>,
    },
    /// Remove a rule.
    Remove {
        #[arg(required = true, num_args = 1.., value_name = "PREFIX")]
        prefix: Vec<String>,
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

    if let Some(Command::Update { check }) = &cli.command {
        update::run(*check).await?;
        return Ok(ExitCode::SUCCESS);
    }
    if let Some(Command::Remote { action }) = &cli.command {
        return remote_command(action, style).await;
    }
    if cli.remote {
        return remote_print(&cli, style).await;
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

    if let Some(Command::Worktree { action }) = &cli.command {
        match action {
            WorktreeAction::List => {
                let trees = microclaw_code_core::worktree::list(&project.root)?;
                if trees.is_empty() {
                    println!(
                        "No MicroClaw Code worktrees for {}.",
                        project.root.display()
                    );
                }
                for tree in trees {
                    println!(
                        "{:<20} {:<28} {}",
                        tree.name,
                        tree.branch,
                        tree.path.display()
                    );
                }
            }
            WorktreeAction::Remove { name } => {
                microclaw_code_core::worktree::remove(&project.root, name)?;
                println!("Removed worktree {name}.");
            }
        }
        return Ok(ExitCode::SUCCESS);
    }
    let main_root = project.root.clone();
    let worktree = match &cli.worktree {
        Some(name) => {
            let name = if name.trim().is_empty() {
                microclaw_code_core::worktree::default_name()
            } else {
                name.trim().to_string()
            };
            let tree = microclaw_code_core::worktree::create(&project.root, &name)?;
            let was_trusted = project.trusted;
            project =
                Project::discover(&tree.path, |root, hash| trust_store.is_trusted(root, hash))?;
            if was_trusted && !project.trusted {
                trust_store.set(&project.root, true, project.config_sha256.as_deref())?;
                project.set_trusted(true);
            }
            eprintln!(
                "{}",
                style.dim(&format!(
                    "Working in worktree {} (branch {}).",
                    tree.path.display(),
                    tree.branch
                ))
            );
            Some(tree)
        }
        None => None,
    };

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
        Some(Command::Allow { action }) => {
            let mut rules = AllowRules::load(AllowRules::default_path());
            match action.as_ref().unwrap_or(&AllowAction::List) {
                AllowAction::List => {
                    let list = rules.for_project(&project.root);
                    if list.is_empty() {
                        println!("No allow rules for {}.", project.root.display());
                    } else {
                        for rule in list {
                            println!("{rule}");
                        }
                    }
                }
                AllowAction::Add { prefix } => {
                    let prefix = prefix.join(" ");
                    if rules.add(&project.root, &prefix)? {
                        println!(
                            "`{}` now runs without asking in this project.",
                            allow::normalize(&prefix)
                        );
                    } else {
                        println!("`{}` was already allowed.", allow::normalize(&prefix));
                    }
                }
                AllowAction::Remove { prefix } => {
                    let prefix = prefix.join(" ");
                    if rules.remove(&project.root, &prefix)? {
                        println!("Removed `{}`.", allow::normalize(&prefix));
                    } else {
                        anyhow::bail!("no rule `{}` for this project", allow::normalize(&prefix));
                    }
                }
            }
            return Ok(ExitCode::SUCCESS);
        }
        Some(Command::Doctor) => return doctor(&cli, &project, style).await,
        Some(Command::Worktree { .. }) => unreachable!("handled above"),
        Some(Command::Export { .. })
        | Some(Command::Review { .. })
        | Some(Command::Remote { .. })
        | Some(Command::Update { .. })
        | Some(Command::Eval { .. })
        | Some(Command::Acp)
        | Some(Command::McpServer)
        | None => {}
    }

    let review_focus = match &cli.command {
        Some(Command::Review { focus, .. }) => Some(focus.join(" ")),
        _ => None,
    };
    let print_prompt = match cli.print.as_deref() {
        Some("-") => {
            let mut text = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut text)?;
            Some(text)
        }
        Some(text) => Some(text.to_string()),
        None => None,
    };
    let print_prompt = match &review_focus {
        Some(_) if print_prompt.is_some() => {
            anyhow::bail!("`mccode review` takes its focus as arguments, not -p")
        }
        Some(focus) => Some(format!("/review {focus}").trim().to_string()),
        None => print_prompt,
    };
    if let Some(Command::Eval {
        action:
            Some(EvalAction::Replay {
                range,
                check,
                out,
                all,
            }),
        ..
    }) = &cli.command
    {
        let written = eval::replay(&project.root, range, out, check, *all)?;
        println!("Wrote {written} case(s) to {}.", out.display());
        return Ok(ExitCode::SUCCESS);
    }
    let acp = matches!(
        cli.command,
        Some(Command::Acp | Command::McpServer | Command::Eval { .. })
    );
    let interactive = print_prompt.is_none();
    if interactive && !acp && !(std::io::stdin().is_terminal() && std::io::stdout().is_terminal()) {
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
    let export = matches!(cli.command, Some(Command::Export { .. }));
    let session_id = if let Some(id) = &cli.session {
        id.clone()
    } else if cli.continue_last || export {
        index
            .for_project(&project.root)
            .first()
            .map(|r| r.id.clone())
            .ok_or_else(|| anyhow::anyhow!("no previous session for this project"))?
    } else if acp {
        // ACP clients create their own sessions.
        String::new()
    } else {
        index.create(&project.root)?.id
    };

    let sandbox_choice = sandbox_choice(&cli)?;
    let sandbox = match (&sandbox_choice, microclaw_sdk::local_sandbox()) {
        (ShellSandbox::Off, _) => None,
        (ShellSandbox::WorkspaceWrite { network, .. }, Some(mechanism)) => Some(SandboxInfo {
            mechanism: mechanism.to_string(),
            network: *network,
            confines_reads: mechanism != "landlock",
        }),
        (ShellSandbox::WorkspaceWrite { .. }, None) => {
            notices.push(NO_SANDBOX_NOTICE.into());
            if !interactive && !cli.json {
                eprintln!("{}", style.yellow(NO_SANDBOX_NOTICE));
            }
            None
        }
    };
    if sandbox.is_none() && mode == Mode::Auto {
        notices.push(AUTO_WITHOUT_SANDBOX.into());
        if !interactive && !cli.json {
            eprintln!("{}", style.yellow(AUTO_WITHOUT_SANDBOX));
        }
    }

    if acp {
        let mode = cli
            .mode
            .as_deref()
            .map(|raw| {
                Mode::parse(raw).ok_or_else(|| {
                    anyhow::anyhow!("unknown mode '{raw}' (expected plan, ask or auto)")
                })
            })
            .transpose()?;
        let options = acp::AcpOptions {
            config_path,
            sandbox: sandbox_choice,
            sandbox_info: sandbox,
            review_commands: cli.review_commands,
            verify: !cli.no_verify,
            max_fix_rounds: cli.max_fix_rounds,
            default_mode: mode,
        };
        if let Some(Command::Eval {
            dir, filter, keep, ..
        }) = &cli.command
        {
            let results = eval::run(
                &eval::EvalOptions {
                    config_path: options.config_path.clone(),
                    sandbox: options.sandbox.clone(),
                    sandbox_info: options.sandbox_info.clone(),
                    max_fix_rounds: options.max_fix_rounds,
                    keep: *keep,
                    filter: filter.clone(),
                },
                dir,
                cli.json,
            )
            .await?;
            return Ok(if results.iter().all(|r| r.passed) {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            });
        }
        if matches!(cli.command, Some(Command::McpServer)) {
            mcp_server::serve(options).await?;
        } else {
            acp::serve(options).await?;
        }
        return Ok(ExitCode::SUCCESS);
    }
    if !cli.json {
        eprintln!("{}", style.dim("Starting the Agent Engine…"));
    }
    let mut builder = MicroClaw::builder(&config_path)
        .caller_channel(CALLER_CHANNEL)
        .workspace(&project.root)
        .data_dir(home::data_dir())
        .max_concurrent_runs(1)
        .shell_sandbox(sandbox_choice)
        .compact_instructions(project.config.compact_instructions.clone())
        .context_tools(cli.context_tools || project.config.context_tools == Some(true))
        .project_agents_dir(project.agents_dir());
    if cli.review_commands {
        builder = builder.command_reviewer(None);
    }
    let microclaw = builder.build().await.map_err(|e| anyhow::anyhow!("{e}"))?;

    let settings = SessionSettings {
        max_session_tokens: cli.max_session_tokens.or(project.config.max_session_tokens),
        mode,
        verify: !cli.no_verify,
        max_fix_rounds: cli
            .max_fix_rounds
            .unwrap_or_else(|| project.max_fix_rounds()),
        interactive,
        sandbox,
    };
    let session = CodeSession::new(microclaw, project, session_id.clone(), settings);

    if let Some(Command::Export { out }) = &cli.command {
        let markdown = session.export_markdown()?;
        let path = out
            .clone()
            .unwrap_or_else(|| PathBuf::from(format!("mccode-{session_id}.md")));
        std::fs::write(&path, markdown)?;
        println!("Wrote {}.", path.display());
        return Ok(ExitCode::SUCCESS);
    }

    let code = match print_prompt {
        Some(prompt) => {
            let task = match (review_focus, &cli.command) {
                (
                    Some(focus),
                    Some(Command::Review {
                        pr: Some(number),
                        post,
                        ..
                    }),
                ) => PrintTask::ReviewPr {
                    number: *number,
                    focus: Some(focus).filter(|f| !f.trim().is_empty()),
                    post: *post,
                },
                (Some(focus), _) => PrintTask::Review(Some(focus).filter(|f| !f.trim().is_empty())),
                (None, _) => {
                    let commands = microclaw_code_core::commands::load(
                        &session.project,
                        &microclaw_code_core::commands::personal_dir(),
                    );
                    let prompt =
                        microclaw_code_core::commands::expand(&commands, &prompt).unwrap_or(prompt);
                    PrintTask::Prompt(prompt.trim().to_string())
                }
            };
            print_mode(session, &mut index, task, cli.json, style).await
        }
        None => {
            let initial = (!cli.prompt.is_empty()).then(|| cli.prompt.join(" "));
            let resumed = cli.session.is_some() || cli.continue_last;
            let id = tui::run(session, index, trust_store, initial, notices, resumed).await?;
            eprintln!("Session {id} saved. Resume with `mccode -c`.");
            Ok(ExitCode::SUCCESS)
        }
    };
    if let Some(tree) = &worktree {
        eprintln!(
            "{}",
            style.bold(&microclaw_code_core::worktree::summary(tree, &main_root))
        );
    }
    code
}

/// `-p`: one turn, printed as lines (or JSON Lines).
/// What a non-interactive run does.
enum PrintTask {
    Prompt(String),
    Review(Option<String>),
    ReviewPr {
        number: u64,
        focus: Option<String>,
        post: bool,
    },
}

async fn print_mode(
    mut session: CodeSession,
    index: &mut SessionIndex,
    task: PrintTask,
    json: bool,
    style: Style,
) -> anyhow::Result<ExitCode> {
    let label = match &task {
        PrintTask::Prompt(prompt) => prompt.clone(),
        PrintTask::Review(focus) => format!("/review {}", focus.as_deref().unwrap_or("")),
        PrintTask::ReviewPr { number, .. } => format!("/review --pr {number}"),
    };
    let post_pr = match &task {
        PrintTask::ReviewPr {
            number, post: true, ..
        } => Some(*number),
        _ => None,
    };
    let _ = index.touch(&session.session_id, label.trim());
    let (updates_tx, mut updates_rx) = mpsc::unbounded_channel();
    let (controls_tx, mut controls_rx) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        let report = match task {
            PrintTask::Prompt(prompt) => session.turn(&prompt, &updates_tx, &mut controls_rx).await,
            PrintTask::Review(focus) => {
                session
                    .review(focus.as_deref(), &updates_tx, &mut controls_rx)
                    .await
            }
            PrintTask::ReviewPr { number, focus, .. } => {
                match microclaw_code_core::worktree::pull_request_diff(
                    &session.project.root,
                    number,
                ) {
                    Ok(diff) if !diff.trim().is_empty() => {
                        session
                            .review_diff(&diff, focus.as_deref(), &updates_tx, &mut controls_rx)
                            .await
                    }
                    Ok(_) => Err(anyhow::anyhow!("pull request #{number} has no changes")),
                    Err(e) => Err(anyhow::anyhow!("could not get pull request #{number}: {e}")),
                }
            }
        };
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
            eprintln!("{}", approval_card(style, &approval.without_code_options()));
            let hint = if session.settings.mode == Mode::Auto {
                " This command always asks, even in auto mode.".to_string()
            } else if let Some(rule) = &approval.suggested_rule {
                format!(" Or allow it from now on with `mccode allow add {rule}`.")
            } else {
                " Or rerun with --mode auto.".to_string()
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
    if let Some(number) = post_pr
        && !report.failed
        && !report.final_text.trim().is_empty()
    {
        let body = format!(
            "{}\n\n---\n_Review by MicroClaw Code_",
            report.final_text.trim()
        );
        let posted = std::process::Command::new("gh")
            .args(["pr", "comment", &number.to_string(), "--body-file", "-"])
            .current_dir(&session.project.root)
            .stdin(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write as _;
                if let Some(stdin) = child.stdin.as_mut() {
                    stdin.write_all(body.as_bytes())?;
                }
                child.wait()
            });
        match posted {
            Ok(status) if status.success() => {
                eprintln!(
                    "{}",
                    style.green(&format!("posted the review on #{number}"))
                )
            }
            _ => eprintln!(
                "{}",
                style.yellow(
                    "could not post the review (is the GitHub CLI `gh` installed and logged in?)"
                )
            ),
        }
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

async fn remote_command(action: &RemoteAction, style: Style) -> anyhow::Result<ExitCode> {
    use microclaw_code_core::remote::{self, RemoteConfig};
    match action {
        RemoteAction::Pair { url, code, name } => {
            let name = name.clone().unwrap_or_else(|| {
                std::env::var("HOSTNAME")
                    .ok()
                    .filter(|h| !h.trim().is_empty())
                    .map(|h| format!("mccode on {h}"))
                    .unwrap_or_else(|| "mccode".into())
            });
            let config = remote::pair(url, code, &name).await?;
            config.save()?;
            println!(
                "{} Paired with {} as \"{}\". Run a task there with `mccode -p \"…\" --remote`.",
                style.green("✓"),
                config.url,
                config.label
            );
        }
        RemoteAction::Status => match RemoteConfig::load() {
            None => println!("Not paired. Use `mccode remote pair <url> <code>`."),
            Some(config) => match remote::whoami(&config).await {
                Ok(info) => println!(
                    "{} Paired with {} as \"{}\" ({})",
                    style.green("✓"),
                    config.url,
                    config.label,
                    info.get("actor")
                        .and_then(|v| v.as_str())
                        .unwrap_or("device")
                ),
                Err(e) => {
                    println!(
                        "{} {} rejected the pairing: {e}",
                        style.red("✗"),
                        config.url
                    );
                    return Ok(ExitCode::from(1));
                }
            },
        },
        RemoteAction::Forget => {
            if RemoteConfig::forget()? {
                println!("Forgot the pairing. Revoke the device in the Server's Access tab too.");
            } else {
                println!("Not paired.");
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// `mccode -p "…" --remote`: run the task on the paired Server.
async fn remote_print(cli: &Cli, style: Style) -> anyhow::Result<ExitCode> {
    use microclaw_code_core::remote::{self, RemoteConfig};
    let config = RemoteConfig::load().ok_or_else(|| {
        anyhow::anyhow!("not paired with a Server; run `mccode remote pair <url> <code>` first")
    })?;
    let prompt = match cli.print.as_deref() {
        Some("-") => {
            let mut text = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut text)?;
            text
        }
        Some(text) => text.to_string(),
        None => anyhow::bail!("--remote needs -p"),
    };
    let start = match &cli.cwd {
        Some(dir) => dir.clone(),
        None => std::env::current_dir()?,
    };
    let session_key = cli.session.clone().unwrap_or_else(|| {
        let name = start
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "default".into());
        format!("mccode-{name}")
    });
    if !cli.json {
        eprintln!(
            "{}",
            style.dim(&format!(
                "Running on {} (session {session_key})…",
                config.url
            ))
        );
    }
    let (updates_tx, mut updates_rx) = mpsc::unbounded_channel();
    let (controls_tx, mut controls_rx) = mpsc::unbounded_channel();
    let prompt = prompt.trim().to_string();
    let key = session_key.clone();
    let task = tokio::spawn(async move {
        remote::run(&config, &key, &prompt, &updates_tx, &mut controls_rx).await
    });
    tokio::pin!(task);
    let mut printer = Printer::new(style, cli.json);
    let (mut out, mut err) = (std::io::stdout(), std::io::stderr());
    let report = loop {
        tokio::select! {
            Some(update) = updates_rx.recv() => printer.update(&update, &mut out, &mut err),
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\n{}", style.yellow("Stopping the remote run…"));
                let _ = controls_tx.send(Control::Cancel);
            }
            result = &mut task => break result??,
        }
    };
    while let Ok(update) = updates_rx.try_recv() {
        printer.update(&update, &mut out, &mut err);
    }
    if let Some(approval) = &report.approval_pending
        && !cli.json
    {
        eprintln!("{}", approval_card(style, approval));
        eprintln!(
            "{}",
            style.yellow(&format!(
                "Approval needed on the Server. Answer with `mccode --remote --session {session_key} -p 1` (approve once) or `-p 3` (deny)."
            ))
        );
    }
    if cli.json {
        println!(
            "{}",
            serde_json::json!({
                "type": "result",
                "remote": true,
                "session": session_key,
                "status": report.status,
                "final_text": report.final_text,
                "changed_files": report.changed_files,
                "approval_pending": report.approval_pending.as_ref().map(|a| a.tool.clone()),
            })
        );
    }
    Ok(ExitCode::from(report.exit_code()))
}

const NO_SANDBOX_NOTICE: &str = if cfg!(windows) {
    "Windows has no OS sandbox for shell commands yet: they run with your permissions. In ask mode every command asks first; avoid auto mode in repositories you do not trust (--sandbox off hides this notice)."
} else if cfg!(target_os = "macos") {
    "No OS sandbox: sandbox-exec is unavailable, so shell commands run unsandboxed (--sandbox off hides this notice)."
} else {
    "No OS sandbox on this machine: shell commands run unsandboxed (install bubblewrap; pass --sandbox off to hide this notice)."
};

/// Auto mode without a sandbox runs commands with the user's full permissions.
const AUTO_WITHOUT_SANDBOX: &str = "auto mode without an OS sandbox: non-destructive commands run without asking and with your full permissions.";

/// The shell sandbox chosen by `--sandbox` / `MICROCLAW_CODE_SANDBOX`.
fn sandbox_choice(cli: &Cli) -> anyhow::Result<ShellSandbox> {
    let raw = cli
        .sandbox
        .clone()
        .or_else(|| std::env::var("MICROCLAW_CODE_SANDBOX").ok())
        .unwrap_or_else(|| "workspace-write".into());
    match raw.trim().to_ascii_lowercase().as_str() {
        "off" | "none" | "danger-full-access" => Ok(ShellSandbox::Off),
        "workspace-write" | "workspace" | "on" => Ok(ShellSandbox::WorkspaceWrite {
            network: !cli.no_network,
            writable_roots: Vec::new(),
        }),
        other => anyhow::bail!("unknown sandbox mode '{other}' (expected workspace-write or off)"),
    }
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
    match (sandbox_choice(cli)?, microclaw_sdk::local_sandbox()) {
        (ShellSandbox::Off, _) => ok("shell sandbox", "off (--sandbox off)".into()),
        (ShellSandbox::WorkspaceWrite { network, .. }, Some(mechanism)) => ok(
            "shell sandbox",
            format!(
                "{mechanism}: writes limited to the repository, temp and tool caches; {}network {}",
                if mechanism == "landlock" {
                    "credential directories stay readable (install bubblewrap to hide them); "
                } else {
                    ""
                },
                if network { "on" } else { "off" }
            ),
        ),
        (ShellSandbox::WorkspaceWrite { .. }, None) => bad(
            "shell sandbox",
            if cfg!(windows) {
                "unavailable on Windows: commands run with your permissions and ask first in ask mode".into()
            } else {
                "unavailable: install bubblewrap (`bwrap`) and allow unprivileged user namespaces; commands run unsandboxed".into()
            },
        ),
    }
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
    fn sandbox_choice_defaults_to_workspace_write() {
        let cli = Cli::try_parse_from(["mccode", "--no-network"]).unwrap();
        if std::env::var_os("MICROCLAW_CODE_SANDBOX").is_none() {
            assert_eq!(
                sandbox_choice(&cli).unwrap(),
                ShellSandbox::WorkspaceWrite {
                    network: false,
                    writable_roots: Vec::new()
                }
            );
        }
        let cli = Cli::try_parse_from(["mccode", "--sandbox", "off"]).unwrap();
        assert_eq!(sandbox_choice(&cli).unwrap(), ShellSandbox::Off);
        let cli = Cli::try_parse_from(["mccode", "--sandbox", "nope"]).unwrap();
        assert!(sandbox_choice(&cli).is_err());
    }

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
