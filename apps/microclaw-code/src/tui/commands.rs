//! Slash commands, session operations and picker actions.

use std::time::Instant;

use tokio::sync::mpsc::{self, UnboundedSender};

use microclaw_code_core::allow;
use microclaw_code_core::driver::{CodeSession, TurnReport, Update};
use microclaw_code_core::project::{self, Mode, Project};
use microclaw_code_core::settings;
use microclaw_code_core::verify;

use super::dialogs::{Dialog, Picker, PickerKind};
use super::popup::Entry;
use super::transcript::{Item, Tone};
use super::{App, Goal, RunningTurn, sandbox_label};
use crate::format;

pub const SLASH_COMMANDS: &[(&str, &str)] = &[
    ("/help", "commands and keys"),
    ("/mode", "show or set the mode: plan, ask, auto"),
    ("/plan", "switch to plan mode, optionally with a task"),
    (
        "/goal",
        "keep working until the goal is met and checks pass: /goal <objective>",
    ),
    (
        "/btw",
        "side question answered in a throwaway copy: /btw <question>",
    ),
    (
        "/changes",
        "review uncommitted changes hunk by hunk (revert, comment)",
    ),
    (
        "/review",
        "agent review of uncommitted changes (read-only), /review <focus>",
    ),
    ("/diff", "git diff --stat (or `full`)"),
    ("/check", "run project checks (all or named)"),
    ("/verify", "turn automatic checks after edits on/off"),
    (
        "/undo",
        "restore files to before the last turn that changed them",
    ),
    (
        "/rewind",
        "pick an earlier turn and restore its files (also Esc Esc)",
    ),
    (
        "/model",
        "pick or switch this session's model: /model <name> | reset",
    ),
    ("/theme", "pick a theme (live preview), /theme <name>"),
    (
        "/config",
        "show settings and their sources; /config set|unset <key> <value>",
    ),
    (
        "/permissions",
        "show allow / ask / deny rules; /permissions add allow|ask|deny <rule>",
    ),
    ("/hooks", "show configured hooks"),
    ("/keys", "show key bindings"),
    (
        "/allow",
        "list, add or remove commands that run without asking",
    ),
    (
        "/trust",
        "trust this project (honour its settings and checks)",
    ),
    ("/cost", "token usage of this session"),
    ("/context", "show how full the context window is"),
    (
        "/compact",
        "summarize older messages to free context (/compact <focus>)",
    ),
    ("/fork", "continue in a copy of this conversation"),
    (
        "/handoff",
        "new session from a summary focused on the next task",
    ),
    ("/new", "start a new session"),
    ("/sessions", "pick a session of this project to resume"),
    ("/queue", "show or clear queued messages (/queue clear)"),
    ("/export", "write the transcript as Markdown"),
    ("/import", "import settings from claude, codex or opencode"),
    (
        "/status",
        "project, mode, session, sandbox and settings files",
    ),
    ("/init", "write .microclaw/project.yaml"),
    ("/clear", "clear the screen (the session continues)"),
    ("/exit", "quit"),
];

/// Session commands that need the engine (run like a short turn).
pub(super) enum SessionOp {
    Undo,
    Rewind(String),
    Cost,
    Model(Option<String>),
    Compact(Option<String>),
    Context,
    Fork(String),
    Handoff(String, String),
}

/// `/context`: window, threshold and where the tokens go.
fn context_report(u: &microclaw_sdk::ContextUsage) -> String {
    let t = |n: usize| format::tokens(n as i64);
    let mut text = format!(
        "context: ~{} of {} tokens ({}%) · model {}\n",
        t(u.used_tokens),
        t(u.window),
        u.percent_used(),
        u.model
    );
    if u.auto_compact_threshold > 0 {
        text.push_str(&format!(
            "automatic compaction at ~{} tokens ({} left)\n",
            t(u.auto_compact_threshold),
            t(u.auto_compact_threshold.saturating_sub(u.used_tokens))
        ));
    } else {
        text.push_str("automatic compaction is off\n");
    }
    if let Some(last) = u.last_request_tokens {
        text.push_str(&format!("last request: {} input tokens\n", t(last)));
    }
    let total = u.used_tokens.max(1) as f64;
    let bar = |n: usize| {
        let cells = ((n as f64 / total) * 20.0).round() as usize;
        format!("{:<20}", "█".repeat(cells.min(20)))
    };
    for (label, n) in [
        ("summary", u.summary_tokens),
        ("your messages", u.user_tokens),
        ("replies", u.assistant_tokens),
        ("tool calls", u.tool_call_tokens),
        ("tool output", u.tool_result_tokens),
        ("images", u.image_tokens),
    ] {
        if n > 0 {
            text.push_str(&format!("  {label:<14} {} {}\n", bar(n), t(n)));
        }
    }
    text.push_str(&format!(
        "{} messages · /compact <focus> summarizes now",
        u.messages
    ));
    text
}

async fn run_session_op(
    session: &mut CodeSession,
    op: SessionOp,
    updates: &UnboundedSender<Update>,
) {
    let notice = |text: String| {
        let _ = updates.send(Update::Notice(text));
    };
    match op {
        SessionOp::Undo => match session.undo().await {
            Ok(Some((checkpoint, prompt))) => notice(format!(
                "restored files to checkpoint {} (before “{}”); /rewind lists checkpoints, including the state you just left",
                checkpoint.commit,
                format::truncate(&prompt, 60)
            )),
            Ok(None) => notice("nothing to undo in this session".into()),
            Err(e) => notice(format!("undo failed: {e}")),
        },
        SessionOp::Rewind(commit) => match session.rewind(&commit).await {
            Ok(()) => notice(format!("restored files to checkpoint {commit}")),
            Err(e) => notice(format!("rewind failed: {e}")),
        },
        SessionOp::Cost => match session.usage().await {
            Ok(usage) if usage.requests == 0 => {
                notice("no model requests in this session yet".into())
            }
            Ok(usage) => {
                let mut text = format!(
                    "this session: {} requests · {} input + {} output tokens",
                    usage.requests,
                    format::tokens(usage.input_tokens),
                    format::tokens(usage.output_tokens)
                );
                for m in &usage.by_model {
                    text.push_str(&format!(
                        "\n  {}: {} requests · {} in · {} out{}",
                        m.model,
                        m.requests,
                        format::tokens(m.input_tokens),
                        format::tokens(m.output_tokens),
                        super::estimate_cost(&m.model, m.input_tokens, m.output_tokens)
                            .map(|c| format!(" · ~${c:.3}"))
                            .unwrap_or_default()
                    ));
                }
                notice(text)
            }
            Err(e) => notice(format!("could not read usage: {e}")),
        },
        SessionOp::Model(None) => match session.model().await {
            Ok(model) => notice(format!(
                "model: {model} (switch with /model <name>, /model reset)"
            )),
            Err(e) => notice(format!("could not read the model: {e}")),
        },
        SessionOp::Model(Some(name)) => {
            let target = (name != "reset" && name != "default").then_some(name.as_str());
            match session.set_model(target).await {
                Ok(model) => {
                    notice(format!("model for this session: {model}"));
                    let _ = updates.send(Update::TurnUsage {
                        input_tokens: 0,
                        output_tokens: 0,
                        model,
                    });
                }
                Err(e) => notice(format!("could not switch the model: {e}")),
            }
        }
        SessionOp::Compact(focus) => match session.compact(focus.as_deref()).await {
            Ok(c) if c.method != "none" => notice(format!(
                "compacted the conversation ({}): {} → {} messages, ~{} → ~{} tokens",
                c.method,
                c.messages_before,
                c.messages_after,
                format::tokens(c.tokens_before as i64),
                format::tokens(c.tokens_after as i64),
            )),
            Ok(_) => notice("the conversation is already short; nothing to compact".into()),
            Err(e) => notice(format!("compact failed: {e}")),
        },
        SessionOp::Context => match session.context_usage().await {
            Ok(u) => notice(context_report(&u)),
            Err(e) => notice(format!("could not read the context: {e}")),
        },
        SessionOp::Handoff(new_id, goal) => {
            let from = session.session_id.clone();
            match session.handoff(new_id, &goal).await {
                Ok(tokens) => notice(format!(
                    "handed off {from} → {} (~{} tokens of context); {from} is unchanged",
                    session.session_id,
                    format::tokens(tokens as i64)
                )),
                Err(e) => notice(format!("handoff failed: {e}")),
            }
        }
        SessionOp::Fork(new_id) => {
            let from = session.session_id.clone();
            match session.fork(new_id).await {
                Ok(()) => notice(format!(
                    "forked {from} → {}; you are now in the copy (the original is unchanged)",
                    session.session_id
                )),
                Err(e) => notice(format!("fork failed: {e}")),
            }
        }
    }
}

impl App {
    /// Run a session command in the background (the session is busy until
    /// it finishes, like a turn).
    pub(super) fn start_session_op(&mut self, op: SessionOp) {
        let Some(mut session) = self.session.take() else {
            self.hint = Some("wait for the current turn to finish".into());
            return;
        };
        let (controls_tx, _controls_rx) = mpsc::unbounded_channel();
        let updates = self.updates_tx.clone();
        let handle = tokio::spawn(async move {
            run_session_op(&mut session, op, &updates).await;
            (session, Ok(TurnReport::default()))
        });
        self.running = Some(RunningTurn {
            started: Instant::now(),
            controls: controls_tx,
            handle,
            plan: false,
            agent_turn: false,
        });
    }

    fn start_review(&mut self, focus: Option<String>) {
        let Some(mut session) = self.session.take() else {
            self.hint = Some("wait for the current turn to finish".into());
            return;
        };
        self.transcript.push(Item::User(match &focus {
            Some(f) => format!("/review {f}"),
            None => "/review".into(),
        }));
        let (controls_tx, mut controls_rx) = mpsc::unbounded_channel();
        let updates = self.updates_tx.clone();
        let handle = tokio::spawn(async move {
            let report = session
                .review(focus.as_deref(), &updates, &mut controls_rx)
                .await;
            (session, report)
        });
        self.running = Some(RunningTurn {
            started: Instant::now(),
            controls: controls_tx,
            handle,
            plan: false,
            agent_turn: false,
        });
        self.scroll = 0;
    }

    pub(super) fn set_trust(&mut self, trusted: bool) {
        let Some(session) = &mut self.session else {
            self.hint = Some("wait for the current turn to finish".into());
            return;
        };
        let root = session.project.root.clone();
        let hash = session.project.config_sha256.clone();
        if let Err(e) = self.trust_store.set(&root, trusted, hash.as_deref()) {
            self.transcript.notice(
                format!("could not save the trust decision: {e}"),
                Tone::Error,
            );
        }
        let mut project = session.project.clone();
        project.set_trusted(trusted);
        if trusted {
            if let Some(mode) = project.config.mode {
                self.mode = mode;
                session.settings.mode = mode;
            }
            if let Some(rounds) = project.config.max_fix_rounds {
                session.settings.max_fix_rounds = rounds;
            }
        }
        session.set_project(project);
        self.trusted = trusted;
        self.transcript.notice(
            if trusted {
                "project trusted: its settings apply and checks run after edits (project settings.yaml applies after a restart)"
            } else {
                "project not trusted: its settings are ignored and checks do not run automatically"
            },
            Tone::Info,
        );
    }

    pub(super) fn project(&self) -> Option<&Project> {
        self.session.as_ref().map(|s| &s.project)
    }

    fn busy_hint(&mut self) {
        self.hint = Some("wait for the current turn to finish".into());
    }

    pub(super) fn command(&mut self, line: &str) {
        let mut parts = line.split_whitespace();
        let name = parts.next().unwrap_or("");
        let args: Vec<String> = parts.map(str::to_string).collect();
        let rest = args.join(" ");
        let busy = self.running.is_some();
        match name {
            "/exit" | "/quit" | "/q" => self.should_quit = true,
            "/help" | "/?" => {
                let mut text = String::from("Commands:");
                for (cmd, desc) in SLASH_COMMANDS {
                    text.push_str(&format!("\n  {cmd:<13} {desc}"));
                }
                let custom = self.custom_commands();
                if !custom.is_empty() {
                    text.push_str("\nCustom commands:");
                    for c in &custom {
                        text.push_str(&format!(
                            "\n  /{:<12} {} ({})",
                            c.name, c.description, c.scope
                        ));
                    }
                }
                text.push_str(
                    "\nKeys: Enter send (queued while a turn runs) · ! shell mode · @ file · / command · Esc stop · Esc Esc rewind · PgUp/PgDn or wheel scroll · click a tool to expand",
                );
                text.push_str(&self.keymap.help());
                self.transcript.notice(text, Tone::Info);
            }
            "/keys" | "/keybindings" => {
                let text = format!(
                    "Key bindings (change them under tui.keymap in settings):{}",
                    self.keymap.help()
                );
                self.transcript.notice(text, Tone::Info);
            }
            "/mode" => match args.first().map(|a| Mode::parse(a)) {
                Some(Some(mode)) => {
                    if self.set_mode(mode) {
                        self.transcript.notice(
                            format!("mode: {} — {}", mode.as_str(), mode.describe()),
                            Tone::Info,
                        );
                    }
                }
                Some(None) => self
                    .transcript
                    .notice("expected plan, ask or auto", Tone::Error),
                None => {
                    let mut text = String::new();
                    for mode in [Mode::Plan, Mode::Ask, Mode::Auto] {
                        let mark = if mode == self.mode { "●" } else { " " };
                        text.push_str(&format!(
                            "{mark} {:<5} {}\n",
                            mode.as_str(),
                            mode.describe()
                        ));
                    }
                    self.transcript.notice(text.trim_end(), Tone::Info);
                }
            },
            "/plan" => {
                if self.set_mode(Mode::Plan) {
                    self.transcript.notice(
                        format!("mode: plan — {}", Mode::Plan.describe()),
                        Tone::Info,
                    );
                    if !args.is_empty() && !busy {
                        self.start_turn(rest, None);
                    }
                }
            }
            "/goal" if rest.is_empty() => match &self.goal {
                Some(g) => self.transcript.notice(
                    format!(
                        "goal: {} (round {}/{}) · /goal stop ends it",
                        g.objective, g.round, g.max_rounds
                    ),
                    Tone::Info,
                ),
                None => self.hint = Some("usage: /goal <objective>".into()),
            },
            "/goal" if rest == "stop" || rest == "clear" => {
                self.goal = None;
                self.transcript.notice("goal cleared", Tone::Info);
            }
            "/goal" if busy => self.busy_hint(),
            "/goal" => {
                self.goal = Some(Goal {
                    objective: rest.clone(),
                    round: 1,
                    max_rounds: 8,
                });
                let prompt = format!(
                    "Goal: {rest}\n\nWork toward this goal. When it is fully achieved and the project's checks pass, \
                     end your reply with the line `{}`. If you are blocked, explain why instead.",
                    super::GOAL_DONE_MARKER
                );
                self.start_turn(prompt, Some(format!("goal: {rest}")));
            }
            "/configure" if rest.is_empty() => {
                self.hint = Some("usage: /configure <what to change>".into())
            }
            "/configure" => self.configure(rest),
            "/btw" if rest.is_empty() => self.hint = Some("usage: /btw <question>".into()),
            "/btw" => self.side_question(rest),
            "/changes" => self.open_review_now(),
            "/check" => self.run_checks(&args),
            "/verify" => match (args.first().map(String::as_str), &mut self.session) {
                (Some("on"), Some(s)) if !s.project.trusted => self
                    .transcript
                    .notice("this project is not trusted; run /trust first", Tone::Error),
                (Some(v @ ("on" | "off")), Some(s)) => {
                    s.settings.verify = v == "on";
                    self.transcript
                        .notice(format!("auto-verify {v}"), Tone::Info);
                }
                (_, Some(s)) => {
                    let names: Vec<_> = s
                        .project
                        .auto_checks()
                        .into_iter()
                        .map(|c| c.name)
                        .collect();
                    self.transcript.notice(
                        format!(
                            "auto-verify is {} (auto checks: {})",
                            if s.settings.verify && s.project.verify_enabled() {
                                "on"
                            } else {
                                "off"
                            },
                            if names.is_empty() {
                                "none".into()
                            } else {
                                names.join(", ")
                            }
                        ),
                        Tone::Info,
                    );
                }
                (_, None) => self.busy_hint(),
            },
            "/trust" => self.set_trust(args.first().map(String::as_str) != Some("off")),
            "/allow" => self.allow_command(&args),
            "/diff" => {
                let Some(root) = self.project().map(|p| p.root.clone()) else {
                    return;
                };
                let mut cmd = std::process::Command::new("git");
                cmd.current_dir(&root)
                    .args(["--no-pager", "diff", "--no-color"]);
                if args.first().map(String::as_str) != Some("full") {
                    cmd.arg("--stat");
                }
                match cmd.output() {
                    Ok(out) => {
                        let text = String::from_utf8_lossy(&out.stdout).trim_end().to_string();
                        self.transcript.notice(
                            if text.is_empty() {
                                "no changes".into()
                            } else {
                                text
                            },
                            Tone::Info,
                        );
                    }
                    Err(e) => self
                        .transcript
                        .notice(format!("git diff failed: {e}"), Tone::Error),
                }
            }
            "/undo" | "/rewind" | "/cost" | "/usage" | "/model" | "/compact" | "/fork"
            | "/review" | "/context" | "/handoff" | "/new" | "/sessions"
                if busy =>
            {
                self.busy_hint()
            }
            "/undo" => self.start_session_op(SessionOp::Undo),
            "/rewind" => match args.first() {
                Some(commit) => self.start_session_op(SessionOp::Rewind(commit.clone())),
                None => self.open_timeline(),
            },
            "/cost" | "/usage" => self.start_session_op(SessionOp::Cost),
            "/model" if args.is_empty() => self.open_model_picker(),
            "/model" => self.start_session_op(SessionOp::Model(Some(rest))),
            "/compact" => {
                self.start_session_op(SessionOp::Compact((!args.is_empty()).then_some(rest)))
            }
            "/context" => self.start_session_op(SessionOp::Context),
            "/review" => self.start_review((!args.is_empty()).then_some(rest)),
            "/theme" if args.is_empty() => self.open_theme_picker(),
            "/theme" => {
                let name = rest.clone();
                self.preview_theme(&name);
                self.save_user_setting("tui.theme", &name);
            }
            "/config" => self.config_command(&args),
            "/permissions" => self.permissions_command(&args),
            "/hooks" => {
                let hooks = &self.settings.hooks;
                let text = if hooks.is_empty() {
                    "no hooks configured (settings.yaml → hooks; Claude Code hook scripts work as-is)".to_string()
                } else {
                    format!(
                        "hooks:\n{}",
                        serde_yaml::to_string(hooks).unwrap_or_default().trim_end()
                    )
                };
                self.transcript.notice(text, Tone::Info);
            }
            "/queue" => {
                if args.first().map(String::as_str) == Some("clear") {
                    self.queue.clear();
                    self.transcript.notice("queue cleared", Tone::Info);
                } else if self.queue.is_empty() {
                    self.transcript.notice("nothing queued", Tone::Info);
                } else {
                    let text = self
                        .queue
                        .iter()
                        .enumerate()
                        .map(|(i, q)| format!("{}. {}", i + 1, format::truncate(q, 100)))
                        .collect::<Vec<_>>()
                        .join("\n");
                    self.transcript
                        .notice(format!("queued:\n{text}"), Tone::Info);
                }
            }
            "/export" => {
                let Some(session) = &self.session else {
                    return self.busy_hint();
                };
                let path = match args.first() {
                    Some(path) => std::path::PathBuf::from(path),
                    None => session
                        .project
                        .root
                        .join(format!("mccode-{}.md", session.session_id)),
                };
                match session
                    .export_markdown()
                    .and_then(|text| std::fs::write(&path, text).map_err(Into::into))
                {
                    Ok(()) => self
                        .transcript
                        .notice(format!("wrote {}", path.display()), Tone::Success),
                    Err(e) => self
                        .transcript
                        .notice(format!("export failed: {e}"), Tone::Error),
                }
            }
            "/import" => self.import_command(&args),
            "/handoff" if args.is_empty() => {
                self.hint = Some("usage: /handoff <the next task>".into())
            }
            "/handoff" => {
                let Some(root) = self.project().map(|p| p.root.clone()) else {
                    return;
                };
                match self.index.create(&root) {
                    Ok(record) => {
                        let _ = self.index.touch(&record.id, &rest);
                        self.start_session_op(SessionOp::Handoff(record.id, rest))
                    }
                    Err(e) => self.transcript.notice(e.to_string(), Tone::Error),
                }
            }
            "/fork" => {
                let Some(root) = self.project().map(|p| p.root.clone()) else {
                    return;
                };
                match self.index.create(&root) {
                    Ok(record) => self.start_session_op(SessionOp::Fork(record.id)),
                    Err(e) => self.transcript.notice(e.to_string(), Tone::Error),
                }
            }
            "/new" => {
                let Some(session) = &mut self.session else {
                    return;
                };
                match self.index.create(&session.project.root) {
                    Ok(record) => {
                        session.reset(record.id.clone());
                        self.session_label = record.id.clone();
                        self.transcript.clear();
                        self.flushed = 0;
                        self.transcript
                            .notice(format!("new session {}", record.id), Tone::Info);
                    }
                    Err(e) => self.transcript.notice(e.to_string(), Tone::Error),
                }
            }
            "/sessions" | "/resume" => self.open_session_picker(),
            "/status" => self.status_command(),
            "/init" => {
                let Some(project) = self.project() else {
                    return;
                };
                let path = project.config_path();
                if path.exists() {
                    self.transcript
                        .notice(format!("{} already exists", path.display()), Tone::Warning);
                    return;
                }
                let template = project::config_template(project);
                let result = std::fs::create_dir_all(path.parent().unwrap_or(&project.root))
                    .and_then(|_| std::fs::write(&path, template));
                match result {
                    Ok(()) => self.transcript.notice(
                        format!("wrote {}; /trust to apply it", path.display()),
                        Tone::Success,
                    ),
                    Err(e) => self.transcript.notice(e.to_string(), Tone::Error),
                }
            }
            "/clear" => {
                self.transcript.clear();
                self.flushed = 0;
            }
            _ => match microclaw_code_core::commands::expand(&self.custom_commands(), line) {
                Some(_) if busy => self.busy_hint(),
                Some(prompt) => self.start_turn(prompt, Some(line.trim().to_string())),
                None => self.transcript.notice(
                    format!("unknown command {name}; /help lists commands"),
                    Tone::Error,
                ),
            },
        }
    }

    pub(super) fn open_review_now(&mut self) {
        let Some(root) = self.project().map(|p| p.root.clone()) else {
            return self.busy_hint();
        };
        match super::review::load_changes(&root) {
            Ok(files) => {
                self.dialog = Some(Dialog::Review(super::review::ReviewState::new(root, files)))
            }
            Err(e) => self
                .transcript
                .notice(format!("could not read changes: {e}"), Tone::Error),
        }
    }

    fn allow_command(&mut self, args: &[String]) {
        let Some(session) = self.session.as_mut() else {
            return self.busy_hint();
        };
        let root = session.project.root.clone();
        let rest = args.get(1..).unwrap_or_default().join(" ");
        let (text, tone) = match args.first().map(String::as_str) {
            Some("add") if !rest.is_empty() => match session.allow_rules_mut().add(&root, &rest) {
                Ok(true) => (
                    format!("`{}` now runs without asking", allow::normalize(&rest)),
                    Tone::Success,
                ),
                Ok(false) => ("already allowed".into(), Tone::Info),
                Err(e) => (e.to_string(), Tone::Error),
            },
            Some("rm" | "remove") if !rest.is_empty() => {
                match session.allow_rules_mut().remove(&root, &rest) {
                    Ok(true) => (format!("removed `{}`", allow::normalize(&rest)), Tone::Info),
                    Ok(false) => ("no such rule".into(), Tone::Warning),
                    Err(e) => (e.to_string(), Tone::Error),
                }
            }
            None | Some("list") => {
                let rules = session.allow_rules().for_project(&root);
                if rules.is_empty() {
                    (
                        "no allow rules; choose \"always allow … in this project\" on a shell approval, or /allow add <command prefix>".into(),
                        Tone::Info,
                    )
                } else {
                    (
                        format!(
                            "commands that run without asking (destructive ones still ask):\n  {}",
                            rules.join("\n  ")
                        ),
                        Tone::Info,
                    )
                }
            }
            _ => (
                "usage: /allow [list | add <prefix> | rm <prefix>]".into(),
                Tone::Warning,
            ),
        };
        self.transcript.notice(text, tone);
    }

    fn status_command(&mut self) {
        let text = match &self.session {
            Some(s) => {
                let mut text = format!(
                    "project: {}\nmode: {}  ·  trusted: {}  ·  auto-verify: {}  ·  fix rounds: {}\nsession: {}  ·  model: {}\nchecks: {}\n{}",
                    s.project.root.display(),
                    self.mode.as_str(),
                    if s.project.trusted { "yes" } else { "no" },
                    if s.settings.verify && s.project.verify_enabled() {
                        "on"
                    } else {
                        "off"
                    },
                    s.settings.max_fix_rounds,
                    s.session_id,
                    self.model,
                    s.project
                        .checks
                        .iter()
                        .map(|c| format!("{}{}", c.name, if c.auto { "*" } else { "" }))
                        .collect::<Vec<_>>()
                        .join(", "),
                    match &s.settings.sandbox {
                        Some(sandbox) => sandbox_label(sandbox),
                        None => "shell sandbox: off".into(),
                    }
                );
                let loaded = settings::load(&s.project.root, s.project.trusted);
                text.push_str("\nsettings files:");
                for (layer, path, ok) in &loaded.layers {
                    text.push_str(&format!(
                        "\n  {:<14} {} {}",
                        layer.name(),
                        if *ok { "✓" } else { "·" },
                        path.display()
                    ));
                }
                text
            }
            None => "a turn is running".into(),
        };
        self.transcript.notice(text, Tone::Info);
    }

    fn config_command(&mut self, args: &[String]) {
        let Some(project) = self.project().cloned() else {
            return self.busy_hint();
        };
        let loaded = settings::load(&project.root, project.trusted);
        match args.first().map(String::as_str) {
            None | Some("show") => {
                let yaml = serde_yaml::to_string(&loaded.settings).unwrap_or_default();
                let mut text = String::from("effective settings (sources: /config get <key>):\n");
                text.push_str(yaml.trim_end());
                for w in &loaded.warnings {
                    text.push_str(&format!("\n! {w}"));
                }
                self.transcript.notice(text, Tone::Info);
            }
            Some("get") if args.len() >= 2 => {
                let key = &args[1];
                let value = settings::get(&loaded, key)
                    .map(|v| serde_yaml::to_string(&v).unwrap_or_default())
                    .unwrap_or_else(|| "(unset)".into());
                let source = loaded
                    .source_of(key)
                    .map(|l| l.name().to_string())
                    .unwrap_or_else(|| "default".into());
                self.transcript
                    .notice(format!("{key} = {} (from {source})", value.trim_end()), Tone::Info);
            }
            Some("set") if args.len() >= 3 => {
                let (layer, key, value) = match settings::SettingsLayer::parse(&args[1]) {
                    Some(layer) if args.len() >= 4 => (layer, args[2].clone(), args[3..].join(" ")),
                    _ => (settings::SettingsLayer::User, args[1].clone(), args[2..].join(" ")),
                };
                let path = layer.path(&project.root);
                match settings::set_in_file(&path, &key, &value) {
                    Ok(()) => {
                        self.transcript.notice(
                            format!("{key} = {value} in {} ({}); some settings apply after a restart", path.display(), layer.name()),
                            Tone::Success,
                        );
                        self.reload_settings();
                    }
                    Err(e) => self.transcript.notice(format!("not saved: {e}"), Tone::Error),
                }
            }
            Some("unset") if args.len() >= 2 => {
                let (layer, key) = match settings::SettingsLayer::parse(&args[1]) {
                    Some(layer) if args.len() >= 3 => (layer, args[2].clone()),
                    _ => (settings::SettingsLayer::User, args[1].clone()),
                };
                let path = layer.path(&project.root);
                match settings::unset_in_file(&path, &key) {
                    Ok(true) => {
                        self.transcript.notice(format!("removed {key} from {}", path.display()), Tone::Success);
                        self.reload_settings();
                    }
                    Ok(false) => self.transcript.notice(format!("{key} was not set there"), Tone::Info),
                    Err(e) => self.transcript.notice(e.to_string(), Tone::Error),
                }
            }
            Some("doctor") => {
                let diags = settings::doctor(&project.root, project.trusted);
                let text = if diags.is_empty() {
                    "settings look fine".to_string()
                } else {
                    diags
                        .iter()
                        .map(|d| format!("{:?} {} {}: {}", d.severity, d.layer.name(), d.path.display(), d.message))
                        .collect::<Vec<_>>()
                        .join("\n")
                };
                self.transcript.notice(text, Tone::Info);
            }
            Some("path") | Some("paths") => {
                let mut text = String::from("settings files (merge order):");
                for (layer, path, ok) in &loaded.layers {
                    text.push_str(&format!("\n  {:<14} {} {}", layer.name(), if *ok { "✓" } else { "·" }, path.display()));
                }
                self.transcript.notice(text, Tone::Info);
            }
            _ => self.transcript.notice(
                "usage: /config [show | get <key> | set [user|project|local] <key> <value> | unset [layer] <key> | doctor | paths]",
                Tone::Warning,
            ),
        }
    }

    fn permissions_command(&mut self, args: &[String]) {
        match (
            args.first().map(String::as_str),
            args.get(1).map(String::as_str),
        ) {
            (Some("add"), Some(effect @ ("allow" | "ask" | "deny"))) if args.len() >= 3 => {
                let rule = args[2..].join(" ");
                let Some(root) = self.project().map(|p| p.root.clone()) else {
                    return self.busy_hint();
                };
                if let Err(e) = settings::check_rule_syntax(&rule) {
                    self.transcript
                        .notice(format!("not a rule: {e}"), Tone::Error);
                    return;
                }
                let path = settings::SettingsLayer::ProjectLocal.path(&root);
                match settings::append_in_file(&path, &format!("permissions.{effect}"), &rule) {
                    Ok(_) => {
                        self.transcript.notice(
                            format!("{effect} {rule} (saved in {})", path.display()),
                            Tone::Success,
                        );
                        self.reload_settings();
                    }
                    Err(e) => self.transcript.notice(e.to_string(), Tone::Error),
                }
            }
            _ => {
                let p = &self.settings.permissions;
                let list = |name: &str, rules: &[String]| {
                    if rules.is_empty() {
                        format!("{name}: (none)")
                    } else {
                        format!("{name}:\n  {}", rules.join("\n  "))
                    }
                };
                let mut text = format!(
                    "permission rules (deny > ask > allow):\n{}\n{}\n{}",
                    list("deny", &p.deny),
                    list("ask", &p.ask),
                    list("allow", &p.allow)
                );
                if !p.disabled_modes.is_empty() {
                    text.push_str(&format!(
                        "\ndisabled modes: {}",
                        p.disabled_modes.join(", ")
                    ));
                }
                text.push_str("\nadd one: /permissions add allow|ask|deny <rule>, e.g. bash(cargo test *), edit(src/**), read(**/.env), net(*.github.com)");
                self.transcript.notice(text, Tone::Info);
            }
        }
    }

    fn import_command(&mut self, args: &[String]) {
        use microclaw_code_core::import::{ImportSource, ImportTarget};
        let Some(root) = self.project().map(|p| p.root.clone()) else {
            return self.busy_hint();
        };
        let source = match args.first().map(String::as_str) {
            Some("claude") => ImportSource::Claude,
            Some("codex") => ImportSource::Codex,
            Some("opencode") => ImportSource::OpenCode,
            _ => {
                self.hint =
                    Some("usage: /import claude|codex|opencode [apply] [user|project]".into());
                return;
            }
        };
        let home = dirs_home();
        let plan = microclaw_code_core::import::plan_import(source, &root, &home);
        if args.get(1).map(String::as_str) != Some("apply") {
            self.transcript.notice(
                format!(
                    "{}\n/import {} apply [user|project] writes it",
                    plan.summary().join("\n"),
                    args[0]
                ),
                Tone::Info,
            );
            return;
        }
        let target = match args.get(2).map(String::as_str) {
            Some("user") => ImportTarget::User,
            _ => ImportTarget::Project,
        };
        match microclaw_code_core::import::apply_import(&plan, target) {
            Ok(report) => {
                let mut text = format!(
                    "imported {} rule(s), {} hook(s), {} file(s), {} MCP server(s)",
                    report.rules_added,
                    report.hooks_added,
                    report.files_written.len(),
                    report.mcp_added.len()
                );
                if let Some(path) = &report.settings_path {
                    text.push_str(&format!("\nsettings: {}", path.display()));
                }
                for skipped in &report.skipped {
                    text.push_str(&format!("\nskipped: {skipped}"));
                }
                self.transcript.notice(text, Tone::Success);
                self.reload_settings();
            }
            Err(e) => self
                .transcript
                .notice(format!("import failed: {e}"), Tone::Error),
        }
    }

    /// Re-read settings after a change (theme, keymap, rules, hooks).
    pub(super) fn reload_settings(&mut self) {
        let Some(project) = self.project().cloned() else {
            return;
        };
        let loaded = settings::load(&project.root, project.trusted);
        self.settings = loaded.settings.clone();
        let (keymap, warnings) = super::keymap::Keymap::from_config(&self.settings.tui.keymap);
        self.keymap = keymap;
        for w in warnings {
            self.transcript.notice(w, Tone::Warning);
        }
        self.render.diff_style = self
            .settings
            .tui
            .diff
            .unwrap_or(microclaw_code_core::settings::DiffStyle::Auto);
        self.notifier =
            super::notify::Notifier::from_settings(self.settings.tui.notifications.as_ref());
        let (theme, _) = super::load_theme(self.settings.tui.theme.as_deref(), &self.themes_dir);
        self.theme = theme;
        self.transcript.invalidate();
        if let Some(reload) = &self.on_settings_reload {
            reload(&project.root, &loaded);
        }
    }

    fn save_user_setting(&mut self, key: &str, value: &str) {
        match settings::set_in_file(&self.user_settings_path, key, value) {
            Ok(()) => self.hint = Some(format!("saved {key} = {value}")),
            Err(e) => self
                .transcript
                .notice(format!("not saved: {e}"), Tone::Error),
        }
    }

    pub(super) fn open_palette(&mut self) {
        let mut entries: Vec<Entry> = self.slash_entries();
        for action in super::keymap::Action::ALL {
            entries.push(Entry {
                label: action.describe().to_string(),
                detail: self.keymap.label(*action).unwrap_or_default(),
                insert: format!("action:{}", action.name()),
            });
        }
        self.dialog = Some(Dialog::Picker(Picker::new(
            PickerKind::Palette,
            "Commands",
            entries,
        )));
    }

    fn open_model_picker(&mut self) {
        let mut entries = Vec::new();
        entries.push(Entry {
            label: "reset".into(),
            detail: "back to the configured model".into(),
            insert: "reset".into(),
        });
        for (name, profile) in &self.settings.model.profiles {
            if let Some(model) = &profile.model {
                entries.push(Entry {
                    label: format!("{name}/{model}"),
                    detail: format!("profile {name} ({})", profile.kind),
                    insert: model.clone(),
                });
            }
        }
        for preset in microclaw_code_core::presets::all() {
            entries.push(Entry {
                label: preset.id.to_string(),
                detail: format!(
                    "{} · {}k context{}",
                    preset.provider,
                    preset.context_window / 1000,
                    if preset.image_input { " · images" } else { "" }
                ),
                insert: preset.id.to_string(),
            });
        }
        let mut picker = Picker::new(
            PickerKind::Model,
            format!("Model (now {})", self.model),
            entries,
        );
        picker.select_value(&self.model);
        self.dialog = Some(Dialog::Picker(picker));
    }

    fn open_theme_picker(&mut self) {
        let mut names: Vec<String> = crate::ui::theme::builtin_names()
            .iter()
            .map(|s| s.to_string())
            .collect();
        if let Ok(dir) = std::fs::read_dir(&self.themes_dir) {
            for entry in dir.flatten() {
                let path = entry.path();
                if matches!(
                    path.extension().and_then(|e| e.to_str()),
                    Some("yaml" | "yml" | "json")
                ) && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
                    && !names.iter().any(|n| n == stem)
                {
                    names.push(stem.to_string());
                }
            }
        }
        let current = self
            .settings
            .tui
            .theme
            .clone()
            .unwrap_or_else(|| "auto".into());
        let entries = names
            .into_iter()
            .map(|n| Entry {
                detail: if n == current {
                    "current".into()
                } else {
                    String::new()
                },
                label: n.clone(),
                insert: n,
            })
            .collect();
        let mut picker = Picker::new(
            PickerKind::Theme,
            "Theme (live preview · Enter saves)",
            entries,
        );
        picker.select_value(&current);
        picker.original = Some(current);
        self.dialog = Some(Dialog::Picker(picker));
    }

    fn open_session_picker(&mut self) {
        let Some(root) = self.project().map(|p| p.root.clone()) else {
            return self.busy_hint();
        };
        let entries: Vec<Entry> = self
            .index
            .for_project(&root)
            .into_iter()
            .take(50)
            .map(|r| Entry {
                label: if r.title.is_empty() {
                    "(empty)".into()
                } else {
                    format::truncate(&r.title, 60)
                },
                detail: format!(
                    "{} · {} turn(s){}",
                    r.id,
                    r.turns,
                    if r.id == self.session_label {
                        " · current"
                    } else {
                        ""
                    }
                ),
                insert: r.id.clone(),
            })
            .collect();
        if entries.is_empty() {
            self.hint = Some("no sessions yet".into());
            return;
        }
        self.dialog = Some(Dialog::Picker(Picker::new(
            PickerKind::Session,
            "Resume a session",
            entries,
        )));
    }

    /// A picker entry was chosen (`alt`: secondary action, e.g. timeline
    /// "edit prompt only").
    pub(super) fn picker_chosen(&mut self, kind: PickerKind, entry: &Entry, alt: bool) {
        match kind {
            PickerKind::Palette => {
                if let Some(action) = entry.insert.strip_prefix("action:") {
                    if let Some(a) = super::keymap::Action::ALL
                        .iter()
                        .find(|a| a.name() == action)
                        && let Some(editor) = self.on_action(*a)
                    {
                        // Editor needs the terminal; leave the text in the box instead.
                        self.input.set_text(&editor.text);
                    }
                } else {
                    let cmd = entry.insert.trim().to_string();
                    let needs_arg = matches!(
                        cmd.as_str(),
                        "/handoff" | "/btw" | "/goal" | "/import" | "/config" | "/permissions"
                    );
                    if needs_arg {
                        self.input.set_text(&entry.insert);
                    } else {
                        self.command(&cmd);
                    }
                }
            }
            PickerKind::Model => {
                if self.running.is_some() {
                    return self.busy_hint();
                }
                self.start_session_op(SessionOp::Model(Some(entry.insert.clone())));
            }
            PickerKind::Theme => {
                let name = entry.insert.clone();
                self.preview_theme(&name);
                self.settings.tui.theme = Some(name.clone());
                self.save_user_setting("tui.theme", &name);
            }
            PickerKind::Session => {
                let Some(session) = &mut self.session else {
                    return self.busy_hint();
                };
                let id = entry.insert.clone();
                session.reset(id.clone());
                self.session_label = id;
                self.transcript.clear();
                self.flushed = 0;
                let session = self.session.as_ref().unwrap();
                super::replay_history(&mut self.transcript, session);
            }
            PickerKind::Timeline => {
                let commit = entry.insert.clone();
                let prompt = self.session.as_ref().and_then(|s| {
                    s.turn_checkpoints()
                        .iter()
                        .find(|(c, _)| c.commit == commit)
                        .map(|(_, p)| p.clone())
                });
                if let Some(prompt) = prompt {
                    self.input.set_text(&prompt);
                }
                if !alt {
                    self.start_session_op(SessionOp::Rewind(commit));
                }
            }
        }
    }

    /// Custom commands (`.microclaw/commands`, `~/.microclaw/code/commands`).
    pub(super) fn custom_commands(&self) -> Vec<microclaw_code_core::commands::CustomCommand> {
        match self.project() {
            Some(project) => microclaw_code_core::commands::load(
                project,
                &microclaw_code_core::commands::personal_dir(),
            ),
            None => Vec::new(),
        }
    }

    fn run_checks(&mut self, names: &[String]) {
        if self.running.is_some() || self.checks_task.is_some() {
            self.hint = Some("busy; try again when the current work finishes".into());
            return;
        }
        let Some(project) = self.project().cloned() else {
            return;
        };
        let checks: Vec<_> = if names.is_empty() || names.iter().any(|n| n == "all") {
            project.checks.clone()
        } else {
            project
                .checks
                .iter()
                .filter(|c| names.contains(&c.name))
                .cloned()
                .collect()
        };
        if checks.is_empty() {
            self.transcript
                .notice("no matching checks; /init to configure them", Tone::Warning);
            return;
        }
        let updates = self.updates_tx.clone();
        self.checks_task = Some(tokio::spawn(async move {
            for check in checks {
                let _ = updates.send(Update::CheckStarted(check.clone()));
                let outcome = verify::run_check(&project.root, &check).await;
                let failed = !outcome.success;
                let tail = verify::tail(outcome.output.trim_end(), 1_500).to_string();
                let _ = updates.send(Update::CheckFinished(outcome));
                if failed {
                    let _ = updates.send(Update::Notice(tail));
                    break;
                }
            }
        }));
    }

    /// Tab without a popup: complete a unique `/command` or `@file`.
    pub(super) fn complete(&mut self) {
        self.refresh_popup();
        if self.popup.as_ref().is_some_and(|p| p.entries.len() == 1)
            && let Some(popup) = self.popup.take()
            && let Some(entry) = popup.current()
        {
            self.input.replace_current_word(&entry.insert);
        }
    }

    pub(super) fn files(&mut self) -> &[String] {
        if self.files.is_none() {
            let root = self.project().map(|p| p.root.clone());
            let files = root
                .and_then(|root| {
                    std::process::Command::new("git")
                        .args(["ls-files", "--cached", "--others", "--exclude-standard"])
                        .current_dir(root)
                        .output()
                        .ok()
                })
                .map(|out| {
                    String::from_utf8_lossy(&out.stdout)
                        .lines()
                        .take(50_000)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            self.files = Some(files);
        }
        self.files.as_deref().unwrap_or_default()
    }
}

fn dirs_home() -> std::path::PathBuf {
    std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_default()
}
