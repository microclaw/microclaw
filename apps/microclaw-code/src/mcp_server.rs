//! `mccode mcp-server`: MicroClaw Code as a Model Context Protocol server on
//! stdio, so other agents and editors can delegate coding tasks to it.
//!
//! Tools:
//! - `run` — run a task in a repository (verification and fix rounds
//!   included) and return the answer, the changed files and the check
//!   result. Approvals cannot be asked here: a command that needs one ends
//!   the run, and the result says how to answer it (`run` again with the same
//!   `session` and prompt `1`, `2` or `3`).
//! - `review` — review the uncommitted changes of a repository (read-only).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use microclaw_code_core::driver::{CodeSession, SessionSettings, TurnReport};
use microclaw_code_core::project::{Mode, Project};
use microclaw_code_core::sessions::SessionIndex;
use microclaw_code_core::trust::TrustStore;
use microclaw_sdk::MicroClaw;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

use crate::acp::AcpOptions as ServeOptions;

const PROTOCOL_VERSION: &str = "2025-06-18";

struct Server {
    options: ServeOptions,
    engines: HashMap<PathBuf, MicroClaw>,
}

fn tools() -> Value {
    json!([
        {
            "name": "run",
            "description": "Run a coding task with MicroClaw Code in a local git repository: it explores, edits files, runs commands and the project's checks, and fixes failures. Returns the answer, changed files and check result. Shell commands that need approval end the run; answer by calling run again with the same session and prompt \"1\" (approve once), \"2\" (always allow the tool) or \"3\" (deny).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "prompt": {"type": "string", "description": "The task, or an approval answer (1/2/3) for a pending session"},
                    "cwd": {"type": "string", "description": "Directory inside the repository (default: the server's working directory)"},
                    "mode": {"type": "string", "enum": ["plan", "ask", "auto"], "description": "plan: read-only plan; ask: shell commands need approval; auto: commands run except destructive ones (default: the project's mode, else ask)"},
                    "session": {"type": "string", "description": "Continue this session (returned by a previous call)"}
                },
                "required": ["prompt"]
            }
        },
        {
            "name": "review",
            "description": "Review the uncommitted changes (git diff HEAD and untracked files) of a repository with read-only tools and return findings ordered by severity, each with file:line and a fix.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "focus": {"type": "string", "description": "What to focus on (optional)"},
                    "cwd": {"type": "string", "description": "Directory inside the repository (default: the server's working directory)"}
                }
            }
        }
    ])
}

/// Text returned for a finished `run`.
pub fn run_summary(session_id: &str, report: &TurnReport) -> String {
    let mut text = report.final_text.trim().to_string();
    let mut facts = vec![format!("session: {session_id}")];
    if !report.changed_files.is_empty() {
        facts.push(format!("changed: {}", report.changed_files.join(", ")));
    }
    match report.checks_passed {
        Some(true) => facts.push("checks: passed".into()),
        Some(false) => facts.push("checks: still failing".into()),
        None => {}
    }
    if report.cancelled {
        facts.push("stopped".into());
    }
    if let Some(approval) = &report.approval_pending {
        let options: Vec<String> = approval
            .without_code_options()
            .options
            .iter()
            .map(|o| format!("{} = {}", o.value, o.label))
            .collect();
        facts.push(format!(
            "approval needed for {}{}: call run with session \"{session_id}\" and prompt {}",
            approval.tool,
            approval
                .preview
                .as_deref()
                .map(|p| format!(" (`{}`)", p.lines().next().unwrap_or("")))
                .unwrap_or_default(),
            options.join(", ")
        ));
    }
    if !text.is_empty() {
        text.push_str("\n\n---\n");
    }
    text.push_str(&facts.join("\n"));
    text
}

impl Server {
    async fn engine(&mut self, root: &Path) -> anyhow::Result<MicroClaw> {
        if let Some(engine) = self.engines.get(root) {
            return Ok(engine.clone());
        }
        let mut builder = MicroClaw::builder(&self.options.config_path)
            .caller_channel(microclaw_code_core::driver::CALLER_CHANNEL)
            .workspace(root)
            .data_dir(microclaw_code_core::home::data_dir())
            .max_concurrent_runs(2)
            .shell_sandbox(self.options.sandbox.clone());
        if self.options.review_commands {
            builder = builder.command_reviewer(None);
        }
        let engine = builder.build().await.map_err(|e| anyhow::anyhow!("{e}"))?;
        self.engines.insert(root.to_path_buf(), engine.clone());
        Ok(engine)
    }

    async fn session(
        &mut self,
        cwd: Option<&str>,
        session: Option<&str>,
        mode: Option<&str>,
    ) -> anyhow::Result<CodeSession> {
        let cwd = match cwd {
            Some(dir) => PathBuf::from(dir),
            None => std::env::current_dir()?,
        };
        let trust = TrustStore::load(TrustStore::default_path());
        let project = Project::discover(&cwd, |root, hash| trust.is_trusted(root, hash))?;
        let mut index = SessionIndex::load(SessionIndex::default_path());
        let id = match session {
            Some(id) => id.to_string(),
            None => index.create(&project.root)?.id,
        };
        let mode = match mode {
            Some(raw) => Mode::parse(raw)
                .ok_or_else(|| anyhow::anyhow!("unknown mode '{raw}' (plan, ask or auto)"))?,
            None => self
                .options
                .default_mode
                .or(project.config.mode)
                .unwrap_or_default(),
        };
        let settings = SessionSettings {
            mode,
            verify: self.options.verify,
            max_fix_rounds: self
                .options
                .max_fix_rounds
                .unwrap_or_else(|| project.max_fix_rounds()),
            interactive: false,
            sandbox: self.options.sandbox_info.clone(),
        };
        let engine = self.engine(&project.root).await?;
        Ok(CodeSession::new(engine, project, id, settings))
    }

    async fn call(&mut self, name: &str, args: &Value) -> anyhow::Result<(String, bool)> {
        let field = |key: &str| args.get(key).and_then(Value::as_str);
        let (updates_tx, mut updates_rx) = mpsc::unbounded_channel();
        // Updates are not streamed over MCP; drain them.
        tokio::spawn(async move { while updates_rx.recv().await.is_some() {} });
        let (_controls_tx, mut controls_rx) = mpsc::unbounded_channel();
        match name {
            "run" => {
                let prompt = field("prompt")
                    .filter(|p| !p.trim().is_empty())
                    .ok_or_else(|| anyhow::anyhow!("`prompt` is required"))?;
                let mut session = self
                    .session(field("cwd"), field("session"), field("mode"))
                    .await?;
                let _ = SessionIndex::load(SessionIndex::default_path())
                    .touch(&session.session_id, prompt);
                let report = session.turn(prompt, &updates_tx, &mut controls_rx).await?;
                Ok((
                    run_summary(&session.session_id, &report),
                    report.failed || report.checks_passed == Some(false),
                ))
            }
            "review" => {
                let mut session = self.session(field("cwd"), None, Some("plan")).await?;
                let report = session
                    .review(field("focus"), &updates_tx, &mut controls_rx)
                    .await?;
                let text = if report.final_text.trim().is_empty() {
                    "Nothing to review: the working tree has no uncommitted changes.".to_string()
                } else {
                    report.final_text
                };
                Ok((text, report.failed))
            }
            other => anyhow::bail!("unknown tool `{other}`"),
        }
    }

    async fn handle(&mut self, request: &Value) -> Option<Value> {
        let id = request.get("id").cloned();
        let method = request.get("method").and_then(Value::as_str).unwrap_or("");
        let params = request.get("params").cloned().unwrap_or(Value::Null);
        // Notifications get no response.
        let id = id?;
        let result = match method {
            "initialize" => Ok(json!({
                "protocolVersion": params
                    .get("protocolVersion")
                    .and_then(Value::as_str)
                    .unwrap_or(PROTOCOL_VERSION),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "mccode", "title": "MicroClaw Code", "version": env!("CARGO_PKG_VERSION")},
                "instructions": "Delegate coding tasks in a local repository with `run`; review uncommitted changes with `review`."
            })),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({"tools": tools()})),
            "tools/call" => {
                let name = params.get("name").and_then(Value::as_str).unwrap_or("");
                let args = params.get("arguments").cloned().unwrap_or(json!({}));
                Ok(match self.call(name, &args).await {
                    Ok((text, is_error)) => json!({
                        "content": [{"type": "text", "text": text}],
                        "isError": is_error
                    }),
                    Err(e) => json!({
                        "content": [{"type": "text", "text": format!("mccode: {e:#}")}],
                        "isError": true
                    }),
                })
            }
            _ => Err(json!({"code": -32601, "message": format!("method not found: {method}")})),
        };
        Some(match result {
            Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
            Err(error) => json!({"jsonrpc": "2.0", "id": id, "error": error}),
        })
    }
}

/// Serve MCP on stdin/stdout until stdin closes.
pub async fn serve(options: ServeOptions) -> anyhow::Result<()> {
    let mut server = Server {
        options,
        engines: HashMap::new(),
    };
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut stdout = tokio::io::stdout();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Value>(&line) {
            Ok(request) => server.handle(&request).await,
            Err(e) => Some(json!({
                "jsonrpc": "2.0",
                "id": Value::Null,
                "error": {"code": -32700, "message": format!("parse error: {e}")}
            })),
        };
        if let Some(response) = response {
            stdout.write_all(response.to_string().as_bytes()).await?;
            stdout.write_all(b"\n").await?;
            stdout.flush().await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use microclaw_code_core::driver::PendingApproval;

    #[test]
    fn tools_are_listed_with_schemas() {
        let tools = tools();
        let names: Vec<_> = tools
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["run", "review"]);
        assert_eq!(tools[0]["inputSchema"]["required"][0], "prompt");
    }

    #[test]
    fn summaries_explain_pending_approvals() {
        let report = TurnReport {
            final_text: "Need to run the migration.".into(),
            changed_files: vec!["src/db.rs".into()],
            checks_passed: Some(true),
            approval_pending: Some(PendingApproval::from_event(
                "a",
                "bash",
                Some("make migrate"),
                &[],
                None,
            )),
            ..Default::default()
        };
        let text = run_summary("code-1", &report);
        assert!(text.starts_with("Need to run the migration."));
        assert!(text.contains("changed: src/db.rs"));
        assert!(text.contains("checks: passed"));
        assert!(text.contains("approval needed for bash (`make migrate`)"));
        assert!(text.contains("session \"code-1\""));
    }
}
