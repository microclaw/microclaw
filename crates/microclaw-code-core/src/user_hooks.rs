//! User hooks with a Claude Code compatible JSON protocol.
//!
//! Hooks are configured per event in the `hooks` settings section. A handler
//! is a shell command (`sh -c`, `cmd /C` on Windows, run in the project root)
//! or an HTTP endpoint (JSON POST). Both receive the same JSON document:
//!
//! ```json
//! {"session_id": "…", "cwd": "/repo", "hook_event_name": "PreToolUse",
//!  "tool_name": "Bash", "microclaw_tool_name": "bash",
//!  "tool_input": {"command": "…"}, "tool_response": {…}, "prompt": "…"}
//! ```
//!
//! `tool_input` gets a `file_path` alias when the tool takes `path`, so
//! Claude Code hook scripts work unchanged. Commands also see
//! `MICROCLAW_PROJECT_DIR` and `CLAUDE_PROJECT_DIR`.
//!
//! Results: exit 2 blocks (stderr is the reason); exit 0 may print JSON with
//! `decision: "block"` + `reason`, `continue: false` + `stopReason`,
//! `systemMessage` and `hookSpecificOutput` (`permissionDecision`
//! allow/deny/ask + `permissionDecisionReason`, `updatedInput`,
//! `additionalContext`); any other exit code is a non-blocking error. HTTP
//! handlers answer with the same JSON. Several hooks for one event run in
//! parallel and are aggregated: deny > ask > allow, contexts concatenated.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use regex::Regex;
use serde_json::{Map, Value, json};
use tokio::io::AsyncWriteExt;

use crate::settings::{HookSpec, HooksConfig};

/// Default handler timeout.
pub const DEFAULT_TIMEOUT_SECS: u64 = 60;

/// Hook events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HookEvent {
    SessionStart,
    UserPromptSubmit,
    PreToolUse,
    PostToolUse,
    /// After a successful file edit; runs once per edited file (`{file}`).
    PostEdit,
    PermissionRequest,
    PreCompact,
    Stop,
    Notification,
    SessionEnd,
}

impl HookEvent {
    pub const ALL: [HookEvent; 10] = [
        Self::SessionStart,
        Self::UserPromptSubmit,
        Self::PreToolUse,
        Self::PostToolUse,
        Self::PostEdit,
        Self::PermissionRequest,
        Self::PreCompact,
        Self::Stop,
        Self::Notification,
        Self::SessionEnd,
    ];

    /// Settings key (`pre_tool_use`).
    pub fn key(self) -> &'static str {
        match self {
            Self::SessionStart => "session_start",
            Self::UserPromptSubmit => "user_prompt_submit",
            Self::PreToolUse => "pre_tool_use",
            Self::PostToolUse => "post_tool_use",
            Self::PostEdit => "post_edit",
            Self::PermissionRequest => "permission_request",
            Self::PreCompact => "pre_compact",
            Self::Stop => "stop",
            Self::Notification => "notification",
            Self::SessionEnd => "session_end",
        }
    }

    /// Claude Code event name (`hook_event_name`).
    pub fn claude_name(self) -> &'static str {
        match self {
            Self::SessionStart => "SessionStart",
            Self::UserPromptSubmit => "UserPromptSubmit",
            Self::PreToolUse => "PreToolUse",
            Self::PostToolUse | Self::PostEdit => "PostToolUse",
            Self::PermissionRequest => "PermissionRequest",
            Self::PreCompact => "PreCompact",
            Self::Stop => "Stop",
            Self::Notification => "Notification",
            Self::SessionEnd => "SessionEnd",
        }
    }

    /// Event for a Claude Code event name.
    pub fn from_claude_name(name: &str) -> Option<Self> {
        Some(match name {
            "SessionStart" => Self::SessionStart,
            "UserPromptSubmit" => Self::UserPromptSubmit,
            "PreToolUse" => Self::PreToolUse,
            "PostToolUse" => Self::PostToolUse,
            "PermissionRequest" => Self::PermissionRequest,
            "PreCompact" => Self::PreCompact,
            "Stop" => Self::Stop,
            "Notification" => Self::Notification,
            "SessionEnd" => Self::SessionEnd,
            _ => return None,
        })
    }

    /// Events whose matcher applies to a tool name.
    pub fn is_tool_event(self) -> bool {
        matches!(
            self,
            Self::PreToolUse | Self::PostToolUse | Self::PostEdit | Self::PermissionRequest
        )
    }

    fn specs(self, config: &HooksConfig) -> &[HookSpec] {
        match self {
            Self::SessionStart => &config.session_start,
            Self::UserPromptSubmit => &config.user_prompt_submit,
            Self::PreToolUse => &config.pre_tool_use,
            Self::PostToolUse => &config.post_tool_use,
            Self::PostEdit => &config.post_edit,
            Self::PermissionRequest => &config.permission_request,
            Self::PreCompact => &config.pre_compact,
            Self::Stop => &config.stop,
            Self::Notification => &config.notification,
            Self::SessionEnd => &config.session_end,
        }
    }
}

impl std::fmt::Display for HookEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.key())
    }
}

/// The Claude Code name of one of our tools (`bash` → `Bash`,
/// `mcp_github_list` → `mcp__github__list`); unknown tools keep their name.
pub fn claude_tool_name(ours: &str) -> String {
    match ours {
        "bash" => "Bash".into(),
        "read_file" => "Read".into(),
        "write_file" => "Write".into(),
        "edit_file" | "apply_patch" => "Edit".into(),
        "glob" => "Glob".into(),
        "grep" => "Grep".into(),
        "web_fetch" => "WebFetch".into(),
        "web_search" => "WebSearch".into(),
        "sessions_spawn" | "sub_agent" | "explore" => "Task".into(),
        "todo_write" => "TodoWrite".into(),
        other => match other.strip_prefix("mcp_").and_then(|r| r.split_once('_')) {
            // The server name is everything up to the first `_` (ambiguous
            // when a server name itself contains `_`).
            Some((server, tool)) if !server.is_empty() => format!("mcp__{server}__{tool}"),
            _ => other.into(),
        },
    }
}

/// What a hook is told about the event.
#[derive(Debug, Clone, Default)]
pub struct HookPayload {
    /// Our tool name (tool events).
    pub tool_name: Option<String>,
    pub tool_input: Option<Value>,
    pub tool_response: Option<Value>,
    /// The user's prompt (`user_prompt_submit`).
    pub prompt: Option<String>,
    /// Notification text.
    pub message: Option<String>,
    /// The edited file (`post_edit`); replaces `{file}` in commands.
    pub file: Option<PathBuf>,
    /// Extra fields (`source`, `trigger`, `reason`, `permission_mode`, …).
    /// `source` / `trigger` are also what non-tool matchers test.
    pub extra: Map<String, Value>,
}

impl HookPayload {
    pub fn tool(name: &str, input: Value) -> Self {
        Self {
            tool_name: Some(name.to_string()),
            tool_input: Some(input),
            ..Default::default()
        }
    }

    pub fn prompt(prompt: impl Into<String>) -> Self {
        Self {
            prompt: Some(prompt.into()),
            ..Default::default()
        }
    }

    pub fn message(message: impl Into<String>) -> Self {
        Self {
            message: Some(message.into()),
            ..Default::default()
        }
    }

    pub fn with(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.extra.insert(key.to_string(), value.into());
        self
    }
}

/// A permission decision from a hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum HookDecision {
    Allow,
    Ask,
    Deny,
}

/// Aggregated result of the hooks of one event.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct HookOutcome {
    /// Handlers that ran.
    pub ran: usize,
    /// `permissionDecision` (or exit 2 / `decision: block` → deny);
    /// strongest wins.
    pub decision: Option<HookDecision>,
    /// Reason for the decision (deny/ask), or the block reason.
    pub reason: Option<String>,
    /// A handler blocked (exit 2 or `decision: "block"`). For tool events
    /// before the call this denies it; after the call and for `stop` /
    /// `user_prompt_submit` the reason is feedback for the model.
    pub blocked: bool,
    /// Replacement tool input (last handler that supplied one wins).
    pub updated_input: Option<Value>,
    /// `additionalContext` (and plain stdout of `session_start` /
    /// `user_prompt_submit` hooks), concatenated.
    pub additional_context: Option<String>,
    /// `continue: false`: stop the turn, with `stopReason`.
    pub stop_reason: Option<String>,
    /// `systemMessage`s to show the user.
    pub system_messages: Vec<String>,
    /// Non-blocking failures (bad exit code, timeout, HTTP error).
    pub errors: Vec<String>,
}

impl HookOutcome {
    fn merge(&mut self, other: HookOutcome) {
        self.ran += other.ran;
        if let Some(d) = other.decision
            && self.decision.is_none_or(|cur| d > cur)
        {
            self.decision = Some(d);
            self.reason = other.reason.clone().or(self.reason.take());
        } else if self.reason.is_none() {
            self.reason = other.reason.clone();
        }
        self.blocked |= other.blocked;
        if other.updated_input.is_some() {
            self.updated_input = other.updated_input;
        }
        if let Some(ctx) = other.additional_context {
            self.additional_context = Some(match self.additional_context.take() {
                Some(cur) => format!("{cur}\n{ctx}"),
                None => ctx,
            });
        }
        if self.stop_reason.is_none() {
            self.stop_reason = other.stop_reason;
        }
        self.system_messages.extend(other.system_messages);
        self.errors.extend(other.errors);
    }
}

#[derive(Debug, Clone)]
struct Handler {
    spec: HookSpec,
    matcher: Option<Regex>,
}

impl Handler {
    fn new(spec: HookSpec) -> Self {
        let matcher = spec
            .matcher
            .as_deref()
            .map(str::trim)
            .filter(|m| !m.is_empty() && *m != "*")
            .map(|m| {
                Regex::new(&format!("^(?:{m})$"))
                    .unwrap_or_else(|_| Regex::new(&format!("^{}$", regex::escape(m))).unwrap())
            });
        Self { spec, matcher }
    }

    fn matches(&self, subjects: &[String]) -> bool {
        match &self.matcher {
            None => true,
            // Non-tool events without a subject ignore the matcher.
            Some(_) if subjects.is_empty() => true,
            Some(re) => subjects.iter().any(|s| re.is_match(s)),
        }
    }
}

/// Configured hooks of one session.
#[derive(Debug, Clone)]
pub struct UserHooks {
    handlers: Vec<(HookEvent, Handler)>,
    root: PathBuf,
    session_id: String,
}

impl UserHooks {
    pub fn new(
        config: HooksConfig,
        project_root: impl Into<PathBuf>,
        session_id: impl Into<String>,
    ) -> Self {
        let handlers = HookEvent::ALL
            .iter()
            .flat_map(|event| {
                event
                    .specs(&config)
                    .iter()
                    .filter(|s| s.command.is_some() || s.url.is_some())
                    .map(|s| (*event, Handler::new(s.clone())))
                    .collect::<Vec<_>>()
            })
            .collect();
        Self {
            handlers,
            root: project_root.into(),
            session_id: session_id.into(),
        }
    }

    /// No hooks at all.
    pub fn empty(project_root: impl Into<PathBuf>) -> Self {
        Self::new(HooksConfig::default(), project_root, "")
    }

    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }

    /// Whether any handler is configured for `event`.
    pub fn has(&self, event: HookEvent) -> bool {
        self.handlers.iter().any(|(e, _)| *e == event)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// The JSON document a handler receives.
    pub fn input_json(&self, event: HookEvent, payload: &HookPayload) -> Value {
        let mut doc = Map::new();
        doc.insert("session_id".into(), json!(self.session_id));
        doc.insert("cwd".into(), json!(self.root.to_string_lossy()));
        doc.insert("hook_event_name".into(), json!(event.claude_name()));
        doc.insert("microclaw_event".into(), json!(event.key()));
        if let Some(tool) = &payload.tool_name {
            doc.insert("tool_name".into(), json!(claude_tool_name(tool)));
            doc.insert("microclaw_tool_name".into(), json!(tool));
        }
        if let Some(input) = &payload.tool_input {
            let mut input = input.clone();
            if let Value::Object(map) = &mut input
                && !map.contains_key("file_path")
                && let Some(path) = map.get("path").cloned()
            {
                map.insert("file_path".into(), path);
            }
            doc.insert("tool_input".into(), input);
        }
        if let Some(response) = &payload.tool_response {
            doc.insert("tool_response".into(), response.clone());
        }
        if let Some(prompt) = &payload.prompt {
            doc.insert("prompt".into(), json!(prompt));
        }
        if let Some(message) = &payload.message {
            doc.insert("message".into(), json!(message));
        }
        if let Some(file) = &payload.file {
            doc.insert("file_path".into(), json!(file.to_string_lossy()));
        }
        for (k, v) in &payload.extra {
            doc.entry(k.clone()).or_insert_with(|| v.clone());
        }
        Value::Object(doc)
    }

    fn subjects(event: HookEvent, payload: &HookPayload) -> Vec<String> {
        if event.is_tool_event() {
            return payload
                .tool_name
                .iter()
                .flat_map(|t| [t.clone(), claude_tool_name(t)])
                .collect();
        }
        ["source", "trigger"]
            .iter()
            .filter_map(|k| payload.extra.get(*k).and_then(Value::as_str))
            .map(str::to_string)
            .collect()
    }

    /// Run the handlers of `event` that match the payload.
    pub async fn run(&self, event: HookEvent, payload: HookPayload) -> HookOutcome {
        let subjects = Self::subjects(event, &payload);
        let selected: Vec<&Handler> = self
            .handlers
            .iter()
            .filter(|(e, h)| *e == event && h.matches(&subjects))
            .map(|(_, h)| h)
            .collect();
        if selected.is_empty() {
            return HookOutcome::default();
        }
        let input = self.input_json(event, &payload);
        let body = input.to_string();
        let runs = selected
            .iter()
            .map(|h| self.run_one(event, h, &body, payload.file.as_deref()));
        let results = futures_util::future::join_all(runs).await;
        let mut outcome = HookOutcome::default();
        for result in results {
            outcome.merge(result);
        }
        outcome
    }

    async fn run_one(
        &self,
        event: HookEvent,
        handler: &Handler,
        body: &str,
        file: Option<&Path>,
    ) -> HookOutcome {
        let timeout =
            Duration::from_secs(handler.spec.timeout.unwrap_or(DEFAULT_TIMEOUT_SECS).max(1));
        let label = handler
            .spec
            .command
            .as_deref()
            .or(handler.spec.url.as_deref())
            .unwrap_or_default();
        let label: String = label.chars().take(80).collect();
        let raw = if let Some(command) = &handler.spec.command {
            let command = match file {
                Some(f) => command.replace("{file}", &shell_quote(&f.to_string_lossy())),
                None => command.clone(),
            };
            self.run_command(&command, body, timeout).await
        } else if let Some(url) = &handler.spec.url {
            run_http(url, body, timeout).await
        } else {
            return HookOutcome::default();
        };
        let mut outcome = match raw {
            Ok(raw) => parse_result(event, raw),
            Err(e) => HookOutcome {
                errors: vec![e],
                ..Default::default()
            },
        };
        outcome.ran = 1;
        for e in &mut outcome.errors {
            *e = format!("{} hook `{label}`: {e}", event.key());
        }
        outcome
    }

    async fn run_command(
        &self,
        command: &str,
        body: &str,
        timeout: Duration,
    ) -> Result<RawResult, String> {
        #[cfg(windows)]
        let mut cmd = {
            let mut c = tokio::process::Command::new("cmd");
            c.arg("/C").arg(command);
            c
        };
        #[cfg(not(windows))]
        let mut cmd = {
            let mut c = tokio::process::Command::new("sh");
            c.arg("-c").arg(command);
            c
        };
        cmd.current_dir(&self.root)
            .env("MICROCLAW_PROJECT_DIR", &self.root)
            .env("CLAUDE_PROJECT_DIR", &self.root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = cmd.spawn().map_err(|e| format!("cannot start: {e}"))?;
        if let Some(mut stdin) = child.stdin.take() {
            let body = body.as_bytes().to_vec();
            // A hook may never read stdin; ignore broken pipes.
            tokio::spawn(async move {
                let _ = stdin.write_all(&body).await;
                let _ = stdin.shutdown().await;
            });
        }
        match tokio::time::timeout(timeout, child.wait_with_output()).await {
            Err(_) => Err(format!("timed out after {}s", timeout.as_secs())),
            Ok(Err(e)) => Err(e.to_string()),
            Ok(Ok(output)) => Ok(RawResult {
                code: output.status.code(),
                stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            }),
        }
    }
}

/// Quote `text` for the platform shell.
pub fn shell_quote(text: &str) -> String {
    if cfg!(windows) {
        format!("\"{}\"", text.replace('"', "\"\""))
    } else if !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "/._-+,:@%".contains(c))
    {
        text.to_string()
    } else {
        format!("'{}'", text.replace('\'', "'\\''"))
    }
}

#[derive(Debug)]
struct RawResult {
    /// `None` when killed by a signal.
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

async fn run_http(url: &str, body: &str, timeout: Duration) -> Result<RawResult, String> {
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|e| e.to_string())?;
    let response = client
        .post(url)
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = response.status();
    let text = response.text().await.map_err(|e| e.to_string())?;
    if !status.is_success() {
        return Err(format!("HTTP {status}"));
    }
    Ok(RawResult {
        code: Some(0),
        stdout: text,
        stderr: String::new(),
    })
}

fn non_empty(text: &str) -> Option<String> {
    let t = text.trim();
    (!t.is_empty()).then(|| t.to_string())
}

fn parse_decision(text: &str) -> Option<HookDecision> {
    match text.to_ascii_lowercase().as_str() {
        "allow" | "approve" => Some(HookDecision::Allow),
        "ask" => Some(HookDecision::Ask),
        "deny" | "block" => Some(HookDecision::Deny),
        _ => None,
    }
}

fn parse_result(event: HookEvent, raw: RawResult) -> HookOutcome {
    let mut out = HookOutcome::default();
    match raw.code {
        Some(0) => {}
        Some(2) => {
            out.blocked = true;
            out.reason = Some(
                non_empty(&raw.stderr)
                    .unwrap_or_else(|| format!("blocked by a {} hook", event.key())),
            );
            if matches!(event, HookEvent::PreToolUse | HookEvent::PermissionRequest) {
                out.decision = Some(HookDecision::Deny);
            }
            return out;
        }
        code => {
            let status = code.map_or_else(
                || "killed by a signal".to_string(),
                |c| format!("exit code {c}"),
            );
            let detail = non_empty(&raw.stderr)
                .map(|e| format!(": {e}"))
                .unwrap_or_default();
            out.errors.push(format!("{status}{detail}"));
            return out;
        }
    }
    let Some(doc) = non_empty(&raw.stdout)
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .filter(Value::is_object)
    else {
        // Plain stdout is context for prompt and session-start hooks.
        if matches!(event, HookEvent::UserPromptSubmit | HookEvent::SessionStart) {
            out.additional_context = non_empty(&raw.stdout);
        }
        return out;
    };
    let str_of = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).and_then(non_empty);
    if doc.get("continue").and_then(Value::as_bool) == Some(false) {
        out.stop_reason = Some(
            str_of(&doc, "stopReason")
                .unwrap_or_else(|| format!("stopped by a {} hook", event.key())),
        );
    }
    if let Some(msg) = str_of(&doc, "systemMessage") {
        out.system_messages.push(msg);
    }
    match doc.get("decision").and_then(Value::as_str) {
        Some("block") => {
            out.blocked = true;
            out.reason = Some(
                str_of(&doc, "reason")
                    .unwrap_or_else(|| format!("blocked by a {} hook", event.key())),
            );
            if matches!(event, HookEvent::PreToolUse | HookEvent::PermissionRequest) {
                out.decision = Some(HookDecision::Deny);
            }
        }
        Some("approve") if event == HookEvent::PreToolUse => {
            out.decision = Some(HookDecision::Allow);
            out.reason = str_of(&doc, "reason");
        }
        _ => {}
    }
    if let Some(specific) = doc.get("hookSpecificOutput").filter(|v| v.is_object()) {
        if let Some(d) = specific
            .get("permissionDecision")
            .and_then(Value::as_str)
            .and_then(parse_decision)
        {
            out.decision = Some(d);
            out.reason = str_of(specific, "permissionDecisionReason").or(out.reason.take());
        }
        // PermissionRequest: {"decision": {"behavior": "allow|deny", "message", "updatedInput"}}.
        if let Some(d) = specific.get("decision").filter(|v| v.is_object()) {
            if let Some(b) = d
                .get("behavior")
                .and_then(Value::as_str)
                .and_then(parse_decision)
            {
                out.decision = Some(b);
                out.reason = str_of(d, "message").or(out.reason.take());
            }
            if let Some(input) = d.get("updatedInput").filter(|v| v.is_object()) {
                out.updated_input = Some(input.clone());
            }
        }
        if let Some(input) = specific.get("updatedInput").filter(|v| v.is_object()) {
            out.updated_input = Some(input.clone());
        }
        out.additional_context = str_of(specific, "additionalContext");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(claude_tool_name("bash"), "Bash");
        assert_eq!(claude_tool_name("apply_patch"), "Edit");
        assert_eq!(
            claude_tool_name("mcp_github_list_issues"),
            "mcp__github__list_issues"
        );
        assert_eq!(claude_tool_name("todo_read"), "todo_read");
        assert_eq!(HookEvent::PostEdit.claude_name(), "PostToolUse");
        assert_eq!(HookEvent::from_claude_name("Stop"), Some(HookEvent::Stop));
        assert_eq!(shell_quote("src/a.rs"), "src/a.rs");
        assert_eq!(shell_quote("a b'c"), "'a b'\\''c'");
    }

    #[test]
    fn input_json_is_claude_compatible() {
        let hooks = UserHooks::new(HooksConfig::default(), "/repo", "s1");
        let doc = hooks.input_json(
            HookEvent::PreToolUse,
            &HookPayload::tool("edit_file", json!({"path": "src/a.rs"})),
        );
        assert_eq!(doc["hook_event_name"], "PreToolUse");
        assert_eq!(doc["tool_name"], "Edit");
        assert_eq!(doc["microclaw_tool_name"], "edit_file");
        assert_eq!(doc["tool_input"]["file_path"], "src/a.rs");
        assert_eq!(doc["session_id"], "s1");
        assert_eq!(doc["cwd"], "/repo");
    }

    #[test]
    fn parses_results() {
        let raw = |code, stdout: &str, stderr: &str| RawResult {
            code: Some(code),
            stdout: stdout.into(),
            stderr: stderr.into(),
        };
        let blocked = parse_result(HookEvent::PreToolUse, raw(2, "", "no way\n"));
        assert!(blocked.blocked);
        assert_eq!(blocked.decision, Some(HookDecision::Deny));
        assert_eq!(blocked.reason.as_deref(), Some("no way"));
        let err = parse_result(HookEvent::PreToolUse, raw(1, "", "oops"));
        assert_eq!(err.decision, None);
        assert_eq!(err.errors, vec!["exit code 1: oops"]);
        let json = r#"{"hookSpecificOutput":{"permissionDecision":"ask","permissionDecisionReason":"check","updatedInput":{"command":"ls -la"},"additionalContext":"ctx"},"systemMessage":"hi","continue":false,"stopReason":"enough"}"#;
        let o = parse_result(HookEvent::PreToolUse, raw(0, json, ""));
        assert_eq!(o.decision, Some(HookDecision::Ask));
        assert_eq!(o.reason.as_deref(), Some("check"));
        assert_eq!(o.updated_input, Some(json!({"command": "ls -la"})));
        assert_eq!(o.additional_context.as_deref(), Some("ctx"));
        assert_eq!(o.system_messages, vec!["hi"]);
        assert_eq!(o.stop_reason.as_deref(), Some("enough"));
        let legacy = parse_result(
            HookEvent::PostToolUse,
            raw(0, r#"{"decision":"block","reason":"fix lint"}"#, ""),
        );
        assert!(legacy.blocked);
        assert_eq!(legacy.decision, None);
        assert_eq!(legacy.reason.as_deref(), Some("fix lint"));
        let plain = parse_result(HookEvent::UserPromptSubmit, raw(0, "today is Monday\n", ""));
        assert_eq!(plain.additional_context.as_deref(), Some("today is Monday"));
    }

    #[test]
    fn aggregation_prefers_deny() {
        let mut o = HookOutcome::default();
        o.merge(HookOutcome {
            decision: Some(HookDecision::Allow),
            additional_context: Some("a".into()),
            ..Default::default()
        });
        o.merge(HookOutcome {
            decision: Some(HookDecision::Deny),
            reason: Some("no".into()),
            additional_context: Some("b".into()),
            ..Default::default()
        });
        o.merge(HookOutcome {
            decision: Some(HookDecision::Ask),
            reason: Some("maybe".into()),
            ..Default::default()
        });
        assert_eq!(o.decision, Some(HookDecision::Deny));
        assert_eq!(o.reason.as_deref(), Some("no"));
        assert_eq!(o.additional_context.as_deref(), Some("a\nb"));
    }

    #[cfg(unix)]
    mod process {
        use super::*;
        use crate::settings::HookSpec;

        fn spec(matcher: Option<&str>, command: &str) -> HookSpec {
            HookSpec {
                matcher: matcher.map(str::to_string),
                command: Some(command.to_string()),
                ..Default::default()
            }
        }

        #[tokio::test]
        async fn command_hooks_follow_the_protocol() {
            let dir = tempfile::tempdir().unwrap();
            let config = HooksConfig {
                pre_tool_use: vec![
                    // Reads stdin and blocks `rm`.
                    spec(
                        Some("Bash"),
                        r#"if grep -q '"rm '; then echo "no rm" >&2; exit 2; fi"#,
                    ),
                    // Only for edits: never runs for bash.
                    spec(Some("Edit|Write"), "exit 2"),
                    spec(
                        None,
                        r#"echo "{\"hookSpecificOutput\":{\"additionalContext\":\"dir=$CLAUDE_PROJECT_DIR\"}}""#,
                    ),
                ],
                post_edit: vec![spec(None, "printf %s {file} > edited.txt")],
                stop: vec![HookSpec {
                    command: Some("sleep 5".into()),
                    timeout: Some(1),
                    ..Default::default()
                }],
                ..Default::default()
            };
            let hooks = UserHooks::new(config, dir.path(), "s");
            assert!(hooks.has(HookEvent::PreToolUse));
            assert!(!hooks.has(HookEvent::SessionEnd));

            let o = hooks
                .run(
                    HookEvent::PreToolUse,
                    HookPayload::tool("bash", json!({"command": "rm -rf x"})),
                )
                .await;
            assert_eq!(o.ran, 2);
            assert_eq!(o.decision, Some(HookDecision::Deny));
            assert_eq!(o.reason.as_deref(), Some("no rm"));
            assert_eq!(
                o.additional_context,
                Some(format!("dir={}", dir.path().display()))
            );

            let ok = hooks
                .run(
                    HookEvent::PreToolUse,
                    HookPayload::tool("bash", json!({"command": "ls"})),
                )
                .await;
            assert_eq!(ok.decision, None);

            let edit = hooks
                .run(
                    HookEvent::PreToolUse,
                    HookPayload::tool("write_file", json!({"path": "a"})),
                )
                .await;
            assert_eq!(edit.decision, Some(HookDecision::Deny));

            let file = dir.path().join("it's here.rs");
            hooks
                .run(
                    HookEvent::PostEdit,
                    HookPayload {
                        file: Some(file.clone()),
                        ..HookPayload::tool("write_file", json!({"path": "x"}))
                    },
                )
                .await;
            let written = std::fs::read_to_string(dir.path().join("edited.txt")).unwrap();
            assert_eq!(written, file.to_string_lossy());

            let slow = hooks.run(HookEvent::Stop, HookPayload::default()).await;
            assert_eq!(slow.errors.len(), 1);
            assert!(slow.errors[0].contains("timed out"), "{:?}", slow.errors);
        }
    }
}
