//! Import settings from Claude Code, Codex and OpenCode.
//!
//! `mccode import claude|codex|opencode` first builds an [`ImportPlan`]
//! ([`plan_import`], a dry run that only reads), shows it, then
//! [`apply_import`] writes it into one settings layer:
//!
//! - permission rules and hooks are merged into the target layer's
//!   `settings.yaml` (lists appended without duplicates; `default_mode` only
//!   when unset);
//! - custom commands → `commands/`, agents → `agents/` (the project's
//!   `.microclaw/` or the Code home), themes → `<code home>/themes/`;
//!   existing files are never overwritten;
//! - MCP servers → the engine's `mcp.json` in the Code data directory
//!   (merged by name, existing servers kept).
//!
//! Secrets are never written into a project layer: environment blocks are
//! not imported, MCP servers (which may carry credentials) only go to the
//! per-user data directory, and hooks / files that look like they contain a
//! credential are skipped for the project target.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::Context;
use regex::Regex;
use serde_json::{Map, Value, json};

use crate::rules::{Effect, Rule, parse_rule};
use crate::settings::{HookSpec, HooksConfig, PermissionsConfig};
use crate::user_hooks::HookEvent;

/// Tool to import from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportSource {
    Claude,
    Codex,
    OpenCode,
}

impl ImportSource {
    pub fn name(self) -> &'static str {
        match self {
            Self::Claude => "Claude Code",
            Self::Codex => "Codex",
            Self::OpenCode => "OpenCode",
        }
    }
}

impl FromStr for ImportSource {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().replace(['-', '_', ' '], "").as_str() {
            "claude" | "claudecode" => Ok(Self::Claude),
            "codex" => Ok(Self::Codex),
            "opencode" => Ok(Self::OpenCode),
            other => Err(format!(
                "unknown import source `{other}` (use claude, codex or opencode)"
            )),
        }
    }
}

/// Settings layer to write into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportTarget {
    /// `~/.microclaw/code/settings.yaml` and the Code home.
    User,
    /// `<repo>/.microclaw/settings.yaml` and `<repo>/.microclaw/`.
    Project,
}

/// Kind of file an import copies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    Command,
    Agent,
    Theme,
}

impl FileKind {
    fn dir(self) -> &'static str {
        match self {
            Self::Command => "commands",
            Self::Agent => "agents",
            Self::Theme => "themes",
        }
    }
}

/// A file to write.
#[derive(Debug, Clone, PartialEq)]
pub struct ImportFile {
    pub kind: FileKind,
    /// File name (`review.md`, `tokyonight.json`).
    pub name: String,
    pub content: String,
    /// Where it came from.
    pub origin: String,
}

/// What an import would do.
#[derive(Debug, Clone)]
pub struct ImportPlan {
    pub source: ImportSource,
    pub project_root: PathBuf,
    /// Files that were read.
    pub read: Vec<PathBuf>,
    /// Rules (MicroClaw syntax) and a suggested `default_mode`.
    pub permissions: PermissionsConfig,
    pub hooks: HooksConfig,
    pub files: Vec<ImportFile>,
    /// MCP servers in the engine's `mcp.json` format, by name.
    pub mcp_servers: BTreeMap<String, Value>,
    /// Things worth telling the user (mode mapping, files read anyway, …).
    pub notes: Vec<String>,
    /// Things that cannot be imported, with the reason.
    pub skipped: Vec<String>,
}

impl ImportPlan {
    fn new(source: ImportSource, project_root: &Path) -> Self {
        Self {
            source,
            project_root: project_root.to_path_buf(),
            read: Vec::new(),
            permissions: PermissionsConfig::default(),
            hooks: HooksConfig::default(),
            files: Vec::new(),
            mcp_servers: BTreeMap::new(),
            notes: Vec::new(),
            skipped: Vec::new(),
        }
    }

    /// Nothing to write.
    pub fn is_empty(&self) -> bool {
        self.permissions.is_empty()
            && self.hooks.is_empty()
            && self.files.is_empty()
            && self.mcp_servers.is_empty()
    }

    /// Number of hook handlers in the plan.
    pub fn hook_count(&self) -> usize {
        HookEvent::ALL
            .iter()
            .map(|e| hooks_of(&self.hooks, *e).len())
            .sum()
    }

    /// Human-readable summary, one line per item.
    pub fn summary(&self) -> Vec<String> {
        let mut lines = Vec::new();
        for (name, list) in [
            ("allow", &self.permissions.allow),
            ("ask", &self.permissions.ask),
            ("deny", &self.permissions.deny),
        ] {
            for rule in list {
                lines.push(format!("rule    {name}: {rule}"));
            }
        }
        if let Some(mode) = &self.permissions.default_mode {
            lines.push(format!("mode    default_mode: {mode}"));
        }
        for event in HookEvent::ALL {
            for spec in hooks_of(&self.hooks, event) {
                let what = spec
                    .command
                    .as_deref()
                    .or(spec.url.as_deref())
                    .unwrap_or("");
                let matcher = spec
                    .matcher
                    .as_deref()
                    .map(|m| format!(" [{m}]"))
                    .unwrap_or_default();
                lines.push(format!("hook    {}{matcher}: {what}", event.key()));
            }
        }
        for file in &self.files {
            lines.push(format!(
                "file    {}/{} (from {})",
                file.kind.dir(),
                file.name,
                file.origin
            ));
        }
        for name in self.mcp_servers.keys() {
            lines.push(format!("mcp     {name}"));
        }
        lines.extend(self.notes.iter().map(|n| format!("note    {n}")));
        lines.extend(self.skipped.iter().map(|s| format!("skipped {s}")));
        lines
    }

    fn add_rule(&mut self, rule: Rule) {
        let text = rule.canonical();
        let list = match rule.effect {
            Effect::Allow => &mut self.permissions.allow,
            Effect::Ask => &mut self.permissions.ask,
            Effect::Deny => &mut self.permissions.deny,
        };
        if !list.contains(&text) {
            list.push(text);
        }
    }

    fn add_rule_text(&mut self, text: &str, effect: Effect, origin: &str) {
        match parse_rule(text, effect) {
            Ok(rule) => self.add_rule(rule),
            Err(e) => self.skipped.push(format!("{origin}: {e}")),
        }
    }

    fn add_hook(&mut self, event: HookEvent, spec: HookSpec) {
        let list = hooks_of_mut(&mut self.hooks, event);
        if !list.contains(&spec) {
            list.push(spec);
        }
    }

    fn add_file(&mut self, file: ImportFile) {
        if let Some(existing) = self
            .files
            .iter_mut()
            .find(|f| f.kind == file.kind && f.name == file.name)
        {
            self.notes.push(format!(
                "{}/{} from {} replaces the one from {}",
                file.kind.dir(),
                file.name,
                file.origin,
                existing.origin
            ));
            *existing = file;
        } else {
            self.files.push(file);
        }
    }

    fn add_mcp(&mut self, name: &str, server: Value, origin: &str) {
        if self.mcp_servers.insert(name.to_string(), server).is_some() {
            self.notes.push(format!(
                "MCP server `{name}` from {origin} replaces an earlier one"
            ));
        }
    }

    fn set_mode(&mut self, mode: &str, why: String) {
        self.permissions.default_mode = Some(mode.to_string());
        self.notes.push(why);
    }

    fn read_text(&mut self, path: &Path) -> Option<String> {
        let text = std::fs::read_to_string(path).ok()?;
        self.read.push(path.to_path_buf());
        Some(text)
    }

    fn read_json(&mut self, path: &Path, jsonc: bool) -> Option<Value> {
        let text = self.read_text(path)?;
        let text = if jsonc { strip_jsonc(&text) } else { text };
        match serde_json::from_str(&text) {
            Ok(v) => Some(v),
            Err(e) => {
                self.skipped
                    .push(format!("{}: not valid JSON ({e})", path.display()));
                None
            }
        }
    }

    /// Copy `*.md` (or other `ext`) files of `dir` as `kind`.
    fn add_dir(&mut self, dir: &Path, kind: FileKind, ext: &str) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
        paths.sort();
        for path in paths {
            if path.is_dir() {
                self.skipped.push(format!(
                    "{}: nested directories are not supported",
                    path.display()
                ));
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some(ext) {
                continue;
            }
            let Some(name) = path
                .file_name()
                .and_then(|n| n.to_str())
                .map(str::to_string)
            else {
                continue;
            };
            if let Some(content) = self.read_text(&path) {
                self.add_file(ImportFile {
                    kind,
                    name,
                    content,
                    origin: path.display().to_string(),
                });
            }
        }
    }

    fn note_if_exists(&mut self, path: &Path, note: &str) {
        if path.is_file() {
            self.notes.push(format!("{}: {note}", path.display()));
        }
    }
}

fn hooks_of(config: &HooksConfig, event: HookEvent) -> &Vec<HookSpec> {
    match event {
        HookEvent::SessionStart => &config.session_start,
        HookEvent::UserPromptSubmit => &config.user_prompt_submit,
        HookEvent::PreToolUse => &config.pre_tool_use,
        HookEvent::PostToolUse => &config.post_tool_use,
        HookEvent::PostEdit => &config.post_edit,
        HookEvent::PermissionRequest => &config.permission_request,
        HookEvent::PreCompact => &config.pre_compact,
        HookEvent::Stop => &config.stop,
        HookEvent::Notification => &config.notification,
        HookEvent::SessionEnd => &config.session_end,
    }
}

fn hooks_of_mut(config: &mut HooksConfig, event: HookEvent) -> &mut Vec<HookSpec> {
    match event {
        HookEvent::SessionStart => &mut config.session_start,
        HookEvent::UserPromptSubmit => &mut config.user_prompt_submit,
        HookEvent::PreToolUse => &mut config.pre_tool_use,
        HookEvent::PostToolUse => &mut config.post_tool_use,
        HookEvent::PostEdit => &mut config.post_edit,
        HookEvent::PermissionRequest => &mut config.permission_request,
        HookEvent::PreCompact => &mut config.pre_compact,
        HookEvent::Stop => &mut config.stop,
        HookEvent::Notification => &mut config.notification,
        HookEvent::SessionEnd => &mut config.session_end,
    }
}

/// Build the plan (reads only).
pub fn plan_import(source: ImportSource, project_root: &Path, home_dir: &Path) -> ImportPlan {
    let mut plan = ImportPlan::new(source, project_root);
    match source {
        ImportSource::Claude => plan_claude(&mut plan, project_root, home_dir),
        ImportSource::Codex => plan_codex(&mut plan, project_root, home_dir),
        ImportSource::OpenCode => plan_opencode(&mut plan, project_root, home_dir),
    }
    plan
}

// ---------------------------------------------------------------- Claude

/// Claude rule → ours. Claude path rules: `//abs` absolute, `~/x` home,
/// `/x` relative to the settings file's directory (`base`), `x` relative.
fn claude_rule(text: &str, effect: Effect, base: &str) -> Result<Rule, String> {
    let text = text.trim();
    let rewritten = match text.split_once('(') {
        Some((kind, rest))
            if matches!(
                kind.trim(),
                "Read" | "Edit" | "Write" | "MultiEdit" | "NotebookEdit"
            ) =>
        {
            let pattern = rest.strip_suffix(')').unwrap_or(rest).trim();
            let pattern = if pattern.starts_with("//") || pattern.starts_with("~/") {
                pattern.to_string()
            } else if let Some(rel) = pattern.strip_prefix('/') {
                format!("{base}{rel}")
            } else {
                pattern.to_string()
            };
            format!("{}({pattern})", kind.trim())
        }
        _ => text.to_string(),
    };
    parse_rule(&rewritten, effect).map_err(|e| e.to_string())
}

fn claude_mode(mode: &str) -> Option<&'static str> {
    match mode {
        "default" => Some("ask"),
        "acceptEdits" => Some("auto"),
        "plan" => Some("plan"),
        _ => None,
    }
}

fn claude_settings(plan: &mut ImportPlan, path: &Path, base: &str) {
    let Some(doc) = plan.read_json(path, false) else {
        return;
    };
    let origin = path.display().to_string();
    if let Some(perms) = doc.get("permissions") {
        for (key, effect) in [
            ("allow", Effect::Allow),
            ("ask", Effect::Ask),
            ("deny", Effect::Deny),
        ] {
            for text in perms
                .get(key)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                match claude_rule(text, effect, base) {
                    Ok(rule) => plan.add_rule(rule),
                    Err(e) => plan.skipped.push(format!("{origin}: {e}")),
                }
            }
        }
        if let Some(mode) = perms.get("defaultMode").and_then(Value::as_str) {
            match claude_mode(mode) {
                Some(ours) => plan.set_mode(
                    ours,
                    format!("{origin}: defaultMode {mode} → default_mode {ours}"),
                ),
                None => plan
                    .skipped
                    .push(format!("{origin}: defaultMode {mode} has no equivalent")),
            }
        }
        if let Some(dirs) = perms.get("additionalDirectories").and_then(Value::as_array)
            && !dirs.is_empty()
        {
            plan.skipped.push(format!(
                "{origin}: additionalDirectories (use sandbox.writable_roots)"
            ));
        }
    }
    if let Some(hooks) = doc.get("hooks").and_then(Value::as_object) {
        for (event_name, groups) in hooks {
            let Some(event) = HookEvent::from_claude_name(event_name) else {
                plan.skipped.push(format!(
                    "{origin}: {event_name} hooks (no MicroClaw equivalent)"
                ));
                continue;
            };
            for group in groups.as_array().into_iter().flatten() {
                let matcher = group
                    .get("matcher")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|m| !m.is_empty() && *m != "*")
                    .map(str::to_string);
                for handler in group
                    .get("hooks")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    let kind = handler
                        .get("type")
                        .and_then(Value::as_str)
                        .unwrap_or("command");
                    let timeout = handler.get("timeout").and_then(Value::as_u64);
                    let spec = match kind {
                        "command" => {
                            handler
                                .get("command")
                                .and_then(Value::as_str)
                                .map(|c| HookSpec {
                                    matcher: matcher.clone(),
                                    command: Some(c.to_string()),
                                    url: None,
                                    timeout,
                                })
                        }
                        "http" => handler
                            .get("url")
                            .and_then(Value::as_str)
                            .map(|u| HookSpec {
                                matcher: matcher.clone(),
                                command: None,
                                url: Some(u.to_string()),
                                timeout,
                            }),
                        _ => None,
                    };
                    match spec {
                        Some(spec) => plan.add_hook(event, spec),
                        None => plan.skipped.push(format!(
                            "{origin}: {event_name} hook of type `{kind}` (only command and http hooks)"
                        )),
                    }
                }
            }
        }
    }
    if let Some(env) = doc.get("env").and_then(Value::as_object)
        && !env.is_empty()
    {
        plan.skipped.push(format!(
            "{origin}: env ({} variables; may hold secrets, set them in your shell)",
            env.len()
        ));
    }
    if doc.get("apiKeyHelper").is_some() {
        plan.skipped.push(format!(
            "{origin}: apiKeyHelper (configure model credentials with `mccode setup`)"
        ));
    }
}

/// Claude / generic `mcpServers` entry → engine format.
fn claude_mcp(server: &Value) -> Result<Value, String> {
    let obj = server.as_object().ok_or("not an object")?;
    let kind = obj.get("type").and_then(Value::as_str).unwrap_or("stdio");
    let mut out = Map::new();
    match kind {
        "stdio" => {
            let command = obj
                .get("command")
                .and_then(Value::as_str)
                .ok_or("missing command")?;
            out.insert("command".into(), json!(command));
            if let Some(args) = obj.get("args").filter(|a| a.is_array()) {
                out.insert("args".into(), args.clone());
            }
            if let Some(env) = obj.get("env").filter(|e| e.is_object()) {
                out.insert("env".into(), env.clone());
            }
        }
        "http" | "sse" | "streamable_http" => {
            let url = obj
                .get("url")
                .and_then(Value::as_str)
                .ok_or("missing url")?;
            out.insert("transport".into(), json!("streamable_http"));
            out.insert("endpoint".into(), json!(url));
            if let Some(headers) = obj.get("headers").filter(|h| h.is_object()) {
                out.insert("headers".into(), headers.clone());
            }
        }
        other => return Err(format!("transport `{other}` is not supported")),
    }
    Ok(Value::Object(out))
}

fn add_mcp_servers(plan: &mut ImportPlan, servers: Option<&Value>, origin: &str) {
    for (name, server) in servers.and_then(Value::as_object).into_iter().flatten() {
        match claude_mcp(server) {
            Ok(converted) => {
                if server.get("type").and_then(Value::as_str) == Some("sse") {
                    plan.notes.push(format!(
                        "MCP server `{name}` uses SSE; imported as streamable HTTP"
                    ));
                }
                plan.add_mcp(name, converted, origin);
            }
            Err(e) => plan
                .skipped
                .push(format!("{origin}: MCP server `{name}`: {e}")),
        }
    }
}

fn plan_claude(plan: &mut ImportPlan, root: &Path, home: &Path) {
    claude_settings(plan, &home.join(".claude/settings.json"), "~/.claude/");
    claude_settings(plan, &root.join(".claude/settings.json"), "");
    claude_settings(plan, &root.join(".claude/settings.local.json"), "");
    for base in [home.join(".claude"), root.join(".claude")] {
        plan.add_dir(&base.join("commands"), FileKind::Command, "md");
        plan.add_dir(&base.join("agents"), FileKind::Agent, "md");
    }
    // MCP: ~/.claude.json (user scope and this project's local scope), .mcp.json.
    let user_json = home.join(".claude.json");
    if user_json.is_file()
        && let Some(doc) = plan.read_json(&user_json, false)
    {
        let origin = user_json.display().to_string();
        add_mcp_servers(plan, doc.get("mcpServers"), &origin);
        let project = doc
            .get("projects")
            .and_then(Value::as_object)
            .and_then(|p| {
                p.get(root.to_string_lossy().as_ref()).or_else(|| {
                    std::fs::canonicalize(root)
                        .ok()
                        .and_then(|c| p.get(c.to_string_lossy().as_ref()))
                })
            })
            .cloned();
        if let Some(project) = project {
            add_mcp_servers(plan, project.get("mcpServers"), &origin);
        }
    }
    let mcp_json = root.join(".mcp.json");
    if let Some(doc) = plan.read_json(&mcp_json, false) {
        let origin = mcp_json.display().to_string();
        add_mcp_servers(plan, doc.get("mcpServers"), &origin);
    }
    plan.note_if_exists(
        &root.join("CLAUDE.md"),
        "already loaded into the prompt in trusted projects",
    );
}

// ----------------------------------------------------------------- Codex

fn plan_codex(plan: &mut ImportPlan, root: &Path, home: &Path) {
    for path in [
        home.join(".codex/config.toml"),
        root.join(".codex/config.toml"),
    ] {
        let Some(text) = plan.read_text(&path) else {
            continue;
        };
        let origin = path.display().to_string();
        let doc: Value = match toml::from_str::<toml::Value>(&text)
            .map_err(|e| e.to_string())
            .and_then(|v| serde_json::to_value(v).map_err(|e| e.to_string()))
        {
            Ok(v) => v,
            Err(e) => {
                plan.skipped.push(format!("{origin}: not valid TOML ({e})"));
                continue;
            }
        };
        for (name, server) in doc
            .get("mcp_servers")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
        {
            if server.get("enabled").and_then(Value::as_bool) == Some(false) {
                plan.skipped
                    .push(format!("{origin}: MCP server `{name}` is disabled"));
                continue;
            }
            let mut out = Map::new();
            if let Some(url) = server.get("url").and_then(Value::as_str) {
                out.insert("transport".into(), json!("streamable_http"));
                out.insert("endpoint".into(), json!(url));
                if let Some(h) = server.get("http_headers").filter(|h| h.is_object()) {
                    out.insert("headers".into(), h.clone());
                }
                if let Some(var) = server.get("bearer_token_env_var").and_then(Value::as_str) {
                    plan.notes.push(format!(
                        "MCP server `{name}`: add an Authorization header for ${var} by hand"
                    ));
                }
            } else if let Some(command) = server.get("command").and_then(Value::as_str) {
                out.insert("command".into(), json!(command));
                if let Some(a) = server.get("args").filter(|a| a.is_array()) {
                    out.insert("args".into(), a.clone());
                }
                if let Some(e) = server.get("env").filter(|e| e.is_object()) {
                    out.insert("env".into(), e.clone());
                }
            } else {
                plan.skipped.push(format!(
                    "{origin}: MCP server `{name}` has neither command nor url"
                ));
                continue;
            }
            plan.add_mcp(name, Value::Object(out), &origin);
        }
        let approval = doc.get("approval_policy").and_then(Value::as_str);
        let sandbox = doc.get("sandbox_mode").and_then(Value::as_str);
        if approval.is_some() || sandbox.is_some() {
            let mode = match (approval, sandbox) {
                (_, Some("read-only")) => "plan",
                (Some("never"), _) | (_, Some("danger-full-access")) => "auto",
                _ => "ask",
            };
            plan.set_mode(
                mode,
                format!(
                    "{origin}: approval_policy={} sandbox_mode={} → default_mode {mode}",
                    approval.unwrap_or("-"),
                    sandbox.unwrap_or("-")
                ),
            );
        }
    }
    let rules_dir = home.join(".codex/rules");
    if let Ok(entries) = std::fs::read_dir(&rules_dir) {
        let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
        paths.sort();
        for path in paths
            .into_iter()
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("rules"))
        {
            let Some(text) = plan.read_text(&path) else {
                continue;
            };
            let origin = path.display().to_string();
            for (pattern, decision) in codex_prefix_rules(&text) {
                let effect = match decision.as_str() {
                    "allow" => Effect::Allow,
                    "prompt" => Effect::Ask,
                    "forbidden" => Effect::Deny,
                    other => {
                        plan.skipped
                            .push(format!("{origin}: decision `{other}` for `{pattern}`"));
                        continue;
                    }
                };
                plan.add_rule_text(&format!("bash({pattern})"), effect, &origin);
            }
        }
    }
    plan.add_dir(&home.join(".codex/prompts"), FileKind::Command, "md");
    plan.note_if_exists(
        &root.join("AGENTS.md"),
        "already loaded into the prompt in trusted projects",
    );
}

/// `prefix_rule(pattern = [...], decision = "...")` calls of a Codex
/// `.rules` (Starlark) file: each pattern (alternatives expanded) with its
/// decision (default `allow`).
pub fn codex_prefix_rules(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let decision_re = Regex::new(r#"decision\s*=\s*["']([A-Za-z_]+)["']"#).unwrap();
    let pattern_re = Regex::new(r"pattern\s*=\s*\[").unwrap();
    let mut rest = text;
    while let Some(pos) = rest.find("prefix_rule(") {
        let args_start = pos + "prefix_rule(".len();
        let args = &rest[args_start..];
        let end = matching_paren(args).unwrap_or(args.len());
        let call = &args[..end];
        rest = &args[end..];
        // Strip comments line by line.
        let call: String = call
            .lines()
            .map(strip_hash_comment)
            .collect::<Vec<_>>()
            .join("\n");
        let decision = decision_re
            .captures(&call)
            .map(|c| c[1].to_string())
            .unwrap_or_else(|| "allow".into());
        let Some(p) = pattern_re.find(&call) else {
            continue;
        };
        let Some((tokens, _)) = parse_list(&call[p.end() - 1..]) else {
            continue;
        };
        let mut variants: Vec<Vec<String>> = vec![Vec::new()];
        for alternatives in tokens {
            let mut next = Vec::new();
            for v in &variants {
                for alt in &alternatives {
                    let mut w = v.clone();
                    w.push(alt.clone());
                    next.push(w);
                }
            }
            variants = next;
            if variants.len() > 64 {
                break;
            }
        }
        for words in variants.into_iter().filter(|v| !v.is_empty()) {
            out.push((words.join(" "), decision.clone()));
        }
    }
    out
}

fn strip_hash_comment(line: &str) -> &str {
    let mut quote: Option<char> = None;
    for (i, c) in line.char_indices() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => {}
            None if c == '"' || c == '\'' => quote = Some(c),
            None if c == '#' => return &line[..i],
            None => {}
        }
    }
    line
}

/// Byte index of the `)` closing an already-opened call.
fn matching_paren(text: &str) -> Option<usize> {
    let mut depth = 1usize;
    let mut quote: Option<char> = None;
    for (i, c) in text.char_indices() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => {}
            None => match c {
                '"' | '\'' => quote = Some(c),
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(i);
                    }
                }
                _ => {}
            },
        }
    }
    None
}

/// Parse `["a", ["b", "c"], "d"]` → `[[a], [b, c], [d]]` and the rest.
fn parse_list(text: &str) -> Option<(Vec<Vec<String>>, &str)> {
    let mut rest = text.trim_start().strip_prefix('[')?;
    let mut items = Vec::new();
    loop {
        rest = rest.trim_start().trim_start_matches(',').trim_start();
        if let Some(r) = rest.strip_prefix(']') {
            return Some((items, r));
        }
        if rest.starts_with('[') {
            let (inner, r) = parse_list(rest)?;
            items.push(inner.into_iter().flatten().collect());
            rest = r;
        } else {
            let (s, r) = parse_string(rest)?;
            items.push(vec![s]);
            rest = r;
        }
    }
}

fn parse_string(text: &str) -> Option<(String, &str)> {
    let quote = text.chars().next().filter(|c| *c == '"' || *c == '\'')?;
    let mut out = String::new();
    let mut chars = text[1..].char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '\\' => out.push(chars.next()?.1),
            c if c == quote => return Some((out, &text[1 + i + 1..])),
            c => out.push(c),
        }
    }
    None
}

// -------------------------------------------------------------- OpenCode

/// Strip `//` and `/* */` comments and trailing commas from JSONC.
pub fn strip_jsonc(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut no_comments = String::with_capacity(text.len());
    let mut i = 0;
    let mut in_string = false;
    while i < chars.len() {
        let c = chars[i];
        if in_string {
            no_comments.push(c);
            if c == '\\' && i + 1 < chars.len() {
                no_comments.push(chars[i + 1]);
                i += 2;
                continue;
            }
            if c == '"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        match (c, chars.get(i + 1)) {
            ('"', _) => {
                in_string = true;
                no_comments.push(c);
            }
            ('/', Some('/')) => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
                continue;
            }
            ('/', Some('*')) => {
                i += 2;
                while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                    i += 1;
                }
                i += 2;
                continue;
            }
            _ => no_comments.push(c),
        }
        i += 1;
    }
    // Trailing commas.
    let chars: Vec<char> = no_comments.chars().collect();
    let mut out = String::with_capacity(chars.len());
    let mut in_string = false;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if in_string {
            out.push(c);
            if c == '\\' && i + 1 < chars.len() {
                out.push(chars[i + 1]);
                i += 2;
                continue;
            }
            in_string = c != '"';
        } else if c == '"' {
            in_string = true;
            out.push(c);
        } else if c == ',' {
            let next = chars[i + 1..].iter().find(|c| !c.is_whitespace());
            if !matches!(next, Some('}') | Some(']')) {
                out.push(c);
            }
        } else {
            out.push(c);
        }
        i += 1;
    }
    out
}

fn opencode_effect(value: &str) -> Option<Effect> {
    match value {
        "allow" => Some(Effect::Allow),
        "ask" => Some(Effect::Ask),
        "deny" => Some(Effect::Deny),
        _ => None,
    }
}

fn opencode_permissions(plan: &mut ImportPlan, perms: &Value, origin: &str) {
    let Some(map) = perms.as_object() else {
        if let Some(all) = perms.as_str() {
            plan.skipped.push(format!(
                "{origin}: permission \"{all}\" for every tool (set default_mode instead)"
            ));
        }
        return;
    };
    for (key, value) in map {
        let (kind, all) = match key.as_str() {
            "bash" => ("bash", "*"),
            "edit" | "write" | "patch" => ("edit", "**"),
            "read" => ("read", "**"),
            "webfetch" => ("net", "*"),
            "task" => ("agent", "*"),
            "websearch" => ("tool", "web_search"),
            "glob" => ("tool", "glob"),
            "grep" => ("tool", "grep"),
            other => {
                plan.skipped
                    .push(format!("{origin}: permission `{other}` (no equivalent)"));
                continue;
            }
        };
        let entries: Vec<(String, &Value)> = match value {
            Value::Object(patterns) if kind != "tool" => {
                patterns.iter().map(|(p, v)| (p.clone(), v)).collect()
            }
            other => vec![(all.to_string(), other)],
        };
        for (pattern, v) in entries {
            match v.as_str().and_then(opencode_effect) {
                Some(effect) => plan.add_rule_text(&format!("{kind}({pattern})"), effect, origin),
                None => plan
                    .skipped
                    .push(format!("{origin}: permission {key}.{pattern} = {v}")),
            }
        }
    }
}

fn front_matter_doc(description: Option<&str>, body: &str) -> String {
    match description.filter(|d| !d.trim().is_empty()) {
        Some(d) => format!(
            "---\ndescription: {}\n---\n{}\n",
            d.replace('\n', " ").trim(),
            body.trim()
        ),
        None => format!("{}\n", body.trim()),
    }
}

fn plan_opencode(plan: &mut ImportPlan, root: &Path, home: &Path) {
    let config_dir = home.join(".config/opencode");
    let candidates = [
        config_dir.join("opencode.json"),
        config_dir.join("opencode.jsonc"),
        root.join("opencode.json"),
        root.join("opencode.jsonc"),
        root.join(".opencode/opencode.json"),
        root.join(".opencode/opencode.jsonc"),
    ];
    for path in candidates {
        if !path.is_file() {
            continue;
        }
        let Some(doc) = plan.read_json(&path, true) else {
            continue;
        };
        let origin = path.display().to_string();
        if let Some(perms) = doc.get("permission") {
            opencode_permissions(plan, perms, &origin);
        }
        for (name, cmd) in doc
            .get("command")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
        {
            match cmd.get("template").and_then(Value::as_str) {
                Some(template) => plan.add_file(ImportFile {
                    kind: FileKind::Command,
                    name: format!("{name}.md"),
                    content: front_matter_doc(
                        cmd.get("description").and_then(Value::as_str),
                        template,
                    ),
                    origin: origin.clone(),
                }),
                None => plan
                    .skipped
                    .push(format!("{origin}: command `{name}` has no template")),
            }
        }
        for (name, agent) in doc
            .get("agent")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
        {
            match agent
                .get("prompt")
                .and_then(Value::as_str)
                .filter(|p| !p.trim_start().starts_with("{file:"))
            {
                Some(prompt) => plan.add_file(ImportFile {
                    kind: FileKind::Agent,
                    name: format!("{name}.md"),
                    content: front_matter_doc(
                        agent.get("description").and_then(Value::as_str),
                        prompt,
                    ),
                    origin: origin.clone(),
                }),
                None => plan.skipped.push(format!(
                    "{origin}: agent `{name}` (no inline prompt; only prompt agents are imported)"
                )),
            }
        }
        for (name, server) in doc
            .get("mcp")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
        {
            if server.get("enabled").and_then(Value::as_bool) == Some(false) {
                plan.skipped
                    .push(format!("{origin}: MCP server `{name}` is disabled"));
                continue;
            }
            let mut out = Map::new();
            match server.get("type").and_then(Value::as_str) {
                Some("remote") => {
                    let Some(url) = server.get("url").and_then(Value::as_str) else {
                        plan.skipped
                            .push(format!("{origin}: MCP server `{name}` has no url"));
                        continue;
                    };
                    out.insert("transport".into(), json!("streamable_http"));
                    out.insert("endpoint".into(), json!(url));
                    if let Some(h) = server.get("headers").filter(|h| h.is_object()) {
                        out.insert("headers".into(), h.clone());
                    }
                }
                _ => {
                    let command: Vec<String> = match server.get("command") {
                        Some(Value::Array(parts)) => parts
                            .iter()
                            .filter_map(Value::as_str)
                            .map(str::to_string)
                            .collect(),
                        Some(Value::String(s)) => vec![s.clone()],
                        _ => Vec::new(),
                    };
                    let Some((program, args)) = command.split_first() else {
                        plan.skipped
                            .push(format!("{origin}: MCP server `{name}` has no command"));
                        continue;
                    };
                    out.insert("command".into(), json!(program));
                    out.insert("args".into(), json!(args));
                    if let Some(env) = server.get("environment").filter(|e| e.is_object()) {
                        out.insert("env".into(), env.clone());
                    }
                }
            }
            plan.add_mcp(name, Value::Object(out), &origin);
        }
        if doc.get("theme").and_then(Value::as_str).is_some() {
            plan.notes.push(format!(
                "{origin}: theme `{}` (set tui.theme after importing themes)",
                doc["theme"].as_str().unwrap_or_default()
            ));
        }
    }
    for base in [config_dir.clone(), root.join(".opencode")] {
        for dir in ["command", "commands"] {
            plan.add_dir(&base.join(dir), FileKind::Command, "md");
        }
        for dir in ["agent", "agents"] {
            plan.add_dir(&base.join(dir), FileKind::Agent, "md");
        }
        plan.add_dir(&base.join("themes"), FileKind::Theme, "json");
    }
    plan.note_if_exists(
        &root.join("AGENTS.md"),
        "already loaded into the prompt in trusted projects",
    );
}

// ----------------------------------------------------------------- apply

/// What [`apply_import`] did.
#[derive(Debug, Clone, Default)]
pub struct ImportReport {
    /// The settings file written (when rules, hooks or a mode were added).
    pub settings_path: Option<PathBuf>,
    pub rules_added: usize,
    pub hooks_added: usize,
    /// `default_mode` set (only when the layer had none).
    pub default_mode: Option<String>,
    pub files_written: Vec<PathBuf>,
    /// The engine MCP config written.
    pub mcp_path: Option<PathBuf>,
    pub mcp_added: Vec<String>,
    /// Plan items that were skipped plus what was skipped while writing.
    pub skipped: Vec<String>,
}

/// Whether `text` looks like it holds a credential.
pub fn looks_secret(text: &str) -> bool {
    static PATTERNS: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    PATTERNS
        .get_or_init(|| {
            Regex::new(concat!(
                r"(sk-[A-Za-z0-9_\-]{16,}|sk-ant-[A-Za-z0-9_\-]{8,}|gh[pousr]_[A-Za-z0-9]{20,}",
                r"|github_pat_[A-Za-z0-9_]{20,}|xox[abprs]-[A-Za-z0-9\-]{10,}|AKIA[0-9A-Z]{16}",
                r"|AIza[0-9A-Za-z_\-]{30,}|-----BEGIN [A-Z ]*PRIVATE KEY-----",
                r"|(?i:bearer)\s+[A-Za-z0-9._\-]{20,}",
                r"|(?i:api[_-]?key|token|secret|password)\s*[=:]\s*['\x22]?[A-Za-z0-9._\-/+]{16,})"
            ))
            .unwrap()
        })
        .is_match(text)
}

/// Write `plan` into `target` (Code home from `MICROCLAW_CODE_HOME` or
/// `~/.microclaw/code`).
pub fn apply_import(plan: &ImportPlan, target: ImportTarget) -> anyhow::Result<ImportReport> {
    apply_import_in(plan, target, &crate::home::code_home())
}

/// [`apply_import`] with an explicit Code home.
pub fn apply_import_in(
    plan: &ImportPlan,
    target: ImportTarget,
    code_home: &Path,
) -> anyhow::Result<ImportReport> {
    let mut report = ImportReport {
        skipped: plan.skipped.clone(),
        ..Default::default()
    };
    let project_dir = plan.project_root.join(".microclaw");
    let (settings_path, layer_dir) = match target {
        ImportTarget::User => (code_home.join("settings.yaml"), code_home.to_path_buf()),
        ImportTarget::Project => (project_dir.join("settings.yaml"), project_dir.clone()),
    };
    let project = target == ImportTarget::Project;

    // Settings.
    let mut hooks = plan.hooks.clone();
    if project {
        for event in HookEvent::ALL {
            hooks_of_mut(&mut hooks, event).retain(|spec| {
                let text = format!(
                    "{} {}",
                    spec.command.as_deref().unwrap_or(""),
                    spec.url.as_deref().unwrap_or("")
                );
                let secret = looks_secret(&text);
                if secret {
                    report.skipped.push(format!(
                        "{} hook `{}`: looks like it contains a credential; not written to the project",
                        event.key(),
                        text.trim().chars().take(40).collect::<String>()
                    ));
                }
                !secret
            });
        }
    }
    if !plan.permissions.is_empty() || !hooks.is_empty() {
        merge_settings(&settings_path, &plan.permissions, &hooks, &mut report)?;
    }

    // Files.
    for file in &plan.files {
        let dir = match file.kind {
            FileKind::Theme => code_home.join("themes"),
            kind => layer_dir.join(kind.dir()),
        };
        let dest = dir.join(&file.name);
        if project && looks_secret(&file.content) {
            report.skipped.push(format!(
                "{}: looks like it contains a credential; not written to the project",
                file.origin
            ));
            continue;
        }
        match std::fs::read_to_string(&dest) {
            Ok(existing) if existing == file.content => continue,
            Ok(_) => {
                report.skipped.push(format!(
                    "{}: already exists (from {})",
                    dest.display(),
                    file.origin
                ));
                continue;
            }
            Err(_) => {}
        }
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        std::fs::write(&dest, &file.content)
            .with_context(|| format!("writing {}", dest.display()))?;
        report.files_written.push(dest);
    }

    // MCP servers: per-user engine config only.
    if !plan.mcp_servers.is_empty() {
        let path = code_home.join("data").join("mcp.json");
        let mut doc: Value = match std::fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text)
                .with_context(|| format!("{} is not valid JSON; not changed", path.display()))?,
            Err(_) => json!({}),
        };
        let obj = doc
            .as_object_mut()
            .with_context(|| format!("{} is not a JSON object", path.display()))?;
        let servers = obj
            .entry("mcpServers")
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .with_context(|| format!("{}: mcpServers is not an object", path.display()))?;
        for (name, server) in &plan.mcp_servers {
            if servers.contains_key(name) {
                report
                    .skipped
                    .push(format!("MCP server `{name}`: already configured"));
                continue;
            }
            servers.insert(name.clone(), server.clone());
            report.mcp_added.push(name.clone());
        }
        if !report.mcp_added.is_empty() {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&path, serde_json::to_string_pretty(&doc)? + "\n")
                .with_context(|| format!("writing {}", path.display()))?;
            report.mcp_path = Some(path);
        }
    }
    Ok(report)
}

fn merge_settings(
    path: &Path,
    permissions: &PermissionsConfig,
    hooks: &HooksConfig,
    report: &mut ImportReport,
) -> anyhow::Result<()> {
    use serde_yaml::{Mapping, Value as Y};
    let mut doc: Y = match std::fs::read_to_string(path) {
        Ok(text) if !text.trim().is_empty() => serde_yaml::from_str(&text)
            .with_context(|| format!("{} is not valid YAML; not changed", path.display()))?,
        _ => Y::Mapping(Mapping::new()),
    };
    let Y::Mapping(root) = &mut doc else {
        anyhow::bail!("{} is not a YAML mapping; not changed", path.display());
    };
    let before = root.clone();
    root.entry(Y::from("version"))
        .or_insert(Y::from(crate::settings::SETTINGS_VERSION));

    fn section<'a>(map: &'a mut Mapping, key: &str) -> anyhow::Result<&'a mut Mapping> {
        let entry = map
            .entry(Y::from(key))
            .or_insert_with(|| Y::Mapping(Mapping::new()));
        if entry.is_null() {
            *entry = Y::Mapping(Mapping::new());
        }
        entry
            .as_mapping_mut()
            .with_context(|| format!("`{key}` is not a mapping"))
    }
    fn append(map: &mut Mapping, key: &str, items: Vec<Y>) -> anyhow::Result<usize> {
        if items.is_empty() {
            return Ok(0);
        }
        let entry = map
            .entry(Y::from(key))
            .or_insert_with(|| Y::Sequence(Vec::new()));
        if entry.is_null() {
            *entry = Y::Sequence(Vec::new());
        }
        let seq = entry
            .as_sequence_mut()
            .with_context(|| format!("`{key}` is not a list"))?;
        let mut added = 0;
        for item in items {
            if !seq.contains(&item) {
                seq.push(item);
                added += 1;
            }
        }
        Ok(added)
    }

    if !permissions.is_empty() {
        let perms = section(root, "permissions")?;
        for (key, list) in [
            ("allow", &permissions.allow),
            ("ask", &permissions.ask),
            ("deny", &permissions.deny),
        ] {
            report.rules_added += append(
                perms,
                key,
                list.iter().map(|r| Y::from(r.as_str())).collect(),
            )?;
        }
        if let Some(mode) = &permissions.default_mode {
            let key = Y::from("default_mode");
            if perms.get(&key).is_none_or(Y::is_null) {
                perms.insert(key, Y::from(mode.as_str()));
                report.default_mode = Some(mode.clone());
            }
        }
    }
    if !hooks.is_empty() {
        let section = section(root, "hooks")?;
        for event in HookEvent::ALL {
            let specs = hooks_of(hooks, event);
            let items = specs
                .iter()
                .map(serde_yaml::to_value)
                .collect::<Result<Vec<_>, _>>()?;
            report.hooks_added += append(section, event.key(), items)?;
        }
    }
    if *root != before {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_yaml::to_string(&doc)?)
            .with_context(|| format!("writing {}", path.display()))?;
        report.settings_path = Some(path.to_path_buf());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    #[test]
    fn claude_import() {
        let tmp = tempfile::tempdir().unwrap();
        let (home, root, code) = (
            tmp.path().join("home"),
            tmp.path().join("repo"),
            tmp.path().join("code"),
        );
        write(
            &home.join(".claude/settings.json"),
            r#"{"permissions":{"allow":["Bash(npm run test:*)","Read(/notes/**)"],"defaultMode":"acceptEdits"},
                "env":{"TOKEN":"x"},
                "hooks":{"PostToolUse":[{"matcher":"Edit|Write","hooks":[{"type":"command","command":"prettier --write"}]}],
                         "SubagentStop":[{"hooks":[{"type":"command","command":"x"}]}]}}"#,
        );
        write(
            &root.join(".claude/settings.json"),
            r#"{"permissions":{"deny":["Read(./.env)","WebFetch(domain:evil.com)","mcp__github__delete_repo"],"ask":["Bash(git push:*)","Bogus(x"]},
                "hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"./guard.sh","timeout":5},{"type":"prompt","prompt":"x"}]}]}}"#,
        );
        write(
            &root.join(".claude/commands/review.md"),
            "Review $ARGUMENTS",
        );
        write(
            &home.join(".claude/agents/db.md"),
            "---\ndescription: DB\n---\nYou know SQL.",
        );
        write(
            &root.join(".mcp.json"),
            r#"{"mcpServers":{"fs":{"command":"npx","args":["-y","fs"]},"remote":{"type":"http","url":"https://x/mcp","headers":{"A":"b"}}}}"#,
        );
        write(&root.join("CLAUDE.md"), "# x");
        let plan = plan_import(ImportSource::Claude, &root, &home);
        assert_eq!(
            plan.permissions.allow,
            vec!["bash(npm run test *)", "read(~/.claude/notes/**)"]
        );
        assert_eq!(plan.permissions.ask, vec!["bash(git push *)"]);
        assert_eq!(
            plan.permissions.deny,
            vec!["read(.env)", "net(evil.com)", "mcp(github.delete_repo)"]
        );
        assert_eq!(plan.permissions.default_mode.as_deref(), Some("auto"));
        assert_eq!(plan.hooks.pre_tool_use.len(), 1);
        assert_eq!(plan.hooks.pre_tool_use[0].timeout, Some(5));
        assert_eq!(
            plan.hooks.post_tool_use[0].matcher.as_deref(),
            Some("Edit|Write")
        );
        assert_eq!(plan.files.len(), 2);
        assert_eq!(plan.mcp_servers["remote"]["transport"], "streamable_http");
        assert_eq!(plan.mcp_servers["remote"]["endpoint"], "https://x/mcp");
        let skipped = plan.skipped.join("\n");
        assert!(skipped.contains("env (1 variables"), "{skipped}");
        assert!(skipped.contains("SubagentStop"));
        assert!(skipped.contains("prompt"));
        assert!(skipped.contains("Bogus"));
        assert!(plan.notes.iter().any(|n| n.contains("CLAUDE.md")));
        assert!(!plan.summary().is_empty());

        // Existing settings and MCP servers are merged, not clobbered.
        write(
            &root.join(".microclaw/settings.yaml"),
            "permissions:\n  allow:\n    - bash(npm run test *)\n  default_mode: ask\ntui:\n  theme: dark\n",
        );
        write(
            &code.join("data/mcp.json"),
            r#"{"mcpServers":{"fs":{"command":"mine"}}}"#,
        );
        let report = apply_import_in(&plan, ImportTarget::Project, &code).unwrap();
        let text = std::fs::read_to_string(root.join(".microclaw/settings.yaml")).unwrap();
        let settings: crate::settings::CodeSettings = serde_yaml::from_str(&text).unwrap();
        assert_eq!(settings.tui.theme.as_deref(), Some("dark"));
        assert_eq!(settings.permissions.default_mode.as_deref(), Some("ask"));
        assert_eq!(settings.permissions.allow.len(), 2);
        assert_eq!(settings.permissions.deny.len(), 3);
        assert_eq!(
            settings.hooks.pre_tool_use[0].command.as_deref(),
            Some("./guard.sh")
        );
        assert_eq!(report.rules_added, 5);
        assert_eq!(report.hooks_added, 2);
        assert_eq!(report.default_mode, None);
        assert!(root.join(".microclaw/commands/review.md").is_file());
        assert!(root.join(".microclaw/agents/db.md").is_file());
        let mcp: Value =
            serde_json::from_str(&std::fs::read_to_string(code.join("data/mcp.json")).unwrap())
                .unwrap();
        assert_eq!(mcp["mcpServers"]["fs"]["command"], "mine");
        assert_eq!(mcp["mcpServers"]["remote"]["endpoint"], "https://x/mcp");
        assert_eq!(report.mcp_added, vec!["remote"]);

        // Idempotent.
        let again = apply_import_in(&plan, ImportTarget::Project, &code).unwrap();
        assert_eq!((again.rules_added, again.hooks_added), (0, 0));
        assert!(again.files_written.is_empty());
        assert!(again.settings_path.is_none());
    }

    #[test]
    fn codex_import() {
        let tmp = tempfile::tempdir().unwrap();
        let (home, root, code) = (
            tmp.path().join("home"),
            tmp.path().join("repo"),
            tmp.path().join("code"),
        );
        write(
            &home.join(".codex/config.toml"),
            "approval_policy = \"on-request\"\nsandbox_mode = \"workspace-write\"\n\n[mcp_servers.docs]\ncommand = \"docs-mcp\"\nargs = [\"--stdio\"]\n[mcp_servers.docs.env]\nKEY = \"v\"\n\n[mcp_servers.off]\ncommand = \"x\"\nenabled = false\n",
        );
        write(
            &home.join(".codex/rules/default.rules"),
            "# rules\nprefix_rule(\n    pattern = [\"git\", [\"push\", \"reset\"]],  # dangerous\n    decision = \"prompt\",\n)\nprefix_rule(pattern = [\"cargo\", \"test\"])\nprefix_rule(pattern = [\"rm\", \"-rf\"], decision = \"forbidden\", justification = \"no (really)\")\n",
        );
        write(&home.join(".codex/prompts/fix.md"), "Fix $ARGUMENTS");
        let plan = plan_import(ImportSource::Codex, &root, &home);
        assert_eq!(
            plan.permissions.ask,
            vec!["bash(git push)", "bash(git reset)"]
        );
        assert_eq!(plan.permissions.allow, vec!["bash(cargo test)"]);
        assert_eq!(plan.permissions.deny, vec!["bash(rm -rf)"]);
        assert_eq!(plan.permissions.default_mode.as_deref(), Some("ask"));
        assert_eq!(plan.mcp_servers["docs"]["args"][0], "--stdio");
        assert_eq!(plan.mcp_servers["docs"]["env"]["KEY"], "v");
        assert!(!plan.mcp_servers.contains_key("off"));
        assert_eq!(plan.files[0].name, "fix.md");
        let report = apply_import_in(&plan, ImportTarget::User, &code).unwrap();
        assert_eq!(report.default_mode.as_deref(), Some("ask"));
        assert!(code.join("commands/fix.md").is_file());
        let settings: crate::settings::CodeSettings =
            serde_yaml::from_str(&std::fs::read_to_string(code.join("settings.yaml")).unwrap())
                .unwrap();
        assert_eq!(settings.version, Some(1));
        assert_eq!(settings.permissions.deny, vec!["bash(rm -rf)"]);
    }

    #[test]
    fn opencode_import() {
        let tmp = tempfile::tempdir().unwrap();
        let (home, root, code) = (
            tmp.path().join("home"),
            tmp.path().join("repo"),
            tmp.path().join("code"),
        );
        write(
            &root.join("opencode.jsonc"),
            r#"{
              // comment with "quotes"
              "$schema": "https://opencode.ai/config.json",
              "permission": {"edit": "ask", "bash": {"git push*": "ask", "git status": "allow", "*": "ask"}, "webfetch": "deny", "doom_loop": "ask"},
              /* block */
              "command": {"test": {"template": "Run the tests for $ARGUMENTS", "description": "Test it"}},
              "agent": {"reviewer": {"description": "Reviews", "prompt": "You review code."}, "build": {"model": "x"}},
              "mcp": {"local": {"type": "local", "command": ["bun", "x", "serve"], "environment": {"A": "1"}},
                      "far": {"type": "remote", "url": "https://far/mcp",},},
              "theme": "tokyonight",
            }"#,
        );
        write(
            &home.join(".config/opencode/themes/mine.json"),
            r#"{"theme":{}}"#,
        );
        write(
            &home.join(".config/opencode/agent/docs.md"),
            "---\ndescription: d\n---\nDocs.",
        );
        write(
            &root.join(".opencode/command/leak.md"),
            "curl -H 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456' x",
        );
        let plan = plan_import(ImportSource::OpenCode, &root, &home);
        let mut ask = plan.permissions.ask.clone();
        ask.sort();
        assert_eq!(ask, vec!["bash(*)", "bash(git push*)", "edit(**)"]);
        assert_eq!(plan.permissions.allow, vec!["bash(git status)"]);
        assert_eq!(plan.permissions.deny, vec!["net(*)"]);
        assert!(plan.skipped.iter().any(|s| s.contains("doom_loop")));
        assert!(plan.skipped.iter().any(|s| s.contains("`build`")));
        assert_eq!(plan.mcp_servers["local"]["command"], "bun");
        assert_eq!(plan.mcp_servers["local"]["args"], json!(["x", "serve"]));
        assert_eq!(plan.mcp_servers["far"]["endpoint"], "https://far/mcp");
        let report = apply_import_in(&plan, ImportTarget::Project, &code).unwrap();
        let cmd = std::fs::read_to_string(root.join(".microclaw/commands/test.md")).unwrap();
        assert_eq!(
            cmd,
            "---\ndescription: Test it\n---\nRun the tests for $ARGUMENTS\n"
        );
        assert!(root.join(".microclaw/agents/reviewer.md").is_file());
        assert!(root.join(".microclaw/agents/docs.md").is_file());
        assert!(code.join("themes/mine.json").is_file());
        assert!(!root.join(".microclaw/commands/leak.md").exists());
        assert!(report.skipped.iter().any(|s| s.contains("credential")));
    }

    #[test]
    fn jsonc_and_secrets() {
        let v: Value = serde_json::from_str(&strip_jsonc(
            "{\"a\": \"// not a comment\", /* x */ \"b\": [1,2,],}",
        ))
        .unwrap();
        assert_eq!(v["a"], "// not a comment");
        assert_eq!(v["b"], json!([1, 2]));
        assert!(looks_secret(
            "export OPENAI_API_KEY=sk-abcdefghijklmnopqrstuv"
        ));
        assert!(looks_secret("token: ghp_abcdefghijklmnopqrstuvwxyz0123"));
        assert!(!looks_secret("cargo fmt -- {file}"));
        assert_eq!("claude".parse::<ImportSource>(), Ok(ImportSource::Claude));
        assert_eq!(
            "OpenCode".parse::<ImportSource>(),
            Ok(ImportSource::OpenCode)
        );
        assert!("x".parse::<ImportSource>().is_err());
    }
}
