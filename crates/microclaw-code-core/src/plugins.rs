//! Plugins in the Claude Code plugin layout.
//!
//! A plugin is a directory with an optional `.claude-plugin/plugin.json`
//! manifest and any of:
//!
//! - `commands/*.md`: slash commands (`/name`, or `/plugin:name`);
//! - `agents/*.md`: agents for `explore` and `sessions_spawn`;
//! - `skills/<name>/SKILL.md`: skills;
//! - `hooks/hooks.json`: hooks in the Claude Code format;
//! - `.mcp.json`: MCP servers.
//!
//! The manifest may point `commands`, `agents`, `skills`, `hooks` and
//! `mcpServers` elsewhere inside the plugin (or inline hooks and servers).
//! `${CLAUDE_PLUGIN_ROOT}` in hook commands, command bodies and MCP server
//! definitions is replaced by the plugin directory, and hook commands also
//! get it as an environment variable. Parts MicroClaw Code does not support
//! (output styles, LSP servers, …) are listed and skipped.
//!
//! User plugins live in `~/.mccode/plugins/<name>/` (recorded in
//! `installed.json` there); project plugins in `.microclaw/plugins/<name>/`,
//! loaded only for trusted projects. Installing copies the plugin, so later
//! changes at the source take effect only through `mccode plugin update`.
//! A repository with `.claude-plugin/marketplace.json` lists several
//! plugins; one is picked by name. There is no marketplace service.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::commands::CustomCommand;
use crate::settings::{CodeSettings, HookSpec, HooksConfig};
use crate::user_hooks::HookEvent;

/// The manifest, relative to the plugin root.
pub const MANIFEST: &str = ".claude-plugin/plugin.json";
/// A plugin catalogue, relative to a repository root.
pub const MARKETPLACE: &str = ".claude-plugin/marketplace.json";
/// Variable naming the plugin directory in hooks and MCP servers.
pub const ROOT_VAR: &str = "CLAUDE_PLUGIN_ROOT";
/// The registry file inside a plugins directory.
pub const REGISTRY_FILE: &str = "installed.json";

/// Manifest keys that are descriptive only.
const INFO_KEYS: &[&str] = &[
    "name",
    "version",
    "description",
    "author",
    "homepage",
    "repository",
    "license",
    "keywords",
    "$schema",
];
/// Manifest keys MicroClaw Code loads.
const LOADED_KEYS: &[&str] = &["commands", "agents", "skills", "hooks", "mcpServers"];

/// Where a plugin is installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PluginScope {
    /// `~/.mccode/plugins/`, for every project.
    User,
    /// `.microclaw/plugins/`, for this (trusted) project.
    Project,
}

impl PluginScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Project => "project",
        }
    }
}

/// A loaded plugin.
#[derive(Debug, Clone)]
pub struct Plugin {
    pub name: String,
    pub version: Option<String>,
    pub description: Option<String>,
    pub root: PathBuf,
    pub scope: PluginScope,
    pub command_dirs: Vec<PathBuf>,
    pub agent_dirs: Vec<PathBuf>,
    pub skill_dirs: Vec<PathBuf>,
    /// Hooks with `${CLAUDE_PLUGIN_ROOT}` resolved.
    pub hooks: Vec<(HookEvent, HookSpec)>,
    /// MCP servers in the engine's `mcp.json` format, by name.
    pub mcp_servers: BTreeMap<String, Value>,
    /// Parts that are not loaded, with the reason.
    pub skipped: Vec<String>,
}

/// Whether `name` can be a plugin (and directory) name.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('.')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

fn substitute(text: &str, root: &Path) -> String {
    let root = root.to_string_lossy();
    text.replace(&format!("${{{ROOT_VAR}}}"), &root)
        .replace(&format!("${ROOT_VAR}"), &root)
}

fn substitute_value(value: &mut Value, root: &Path) {
    match value {
        Value::String(s) => *s = substitute(s, root),
        Value::Array(items) => items.iter_mut().for_each(|v| substitute_value(v, root)),
        Value::Object(map) => map.values_mut().for_each(|v| substitute_value(v, root)),
        _ => {}
    }
}

/// `rel` inside `root`, refusing absolute paths and escapes.
fn inside(root: &Path, rel: &str) -> anyhow::Result<PathBuf> {
    let rel_path = Path::new(rel);
    if rel_path.is_absolute()
        || rel_path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        anyhow::bail!("`{rel}` points outside the plugin");
    }
    Ok(root.join(rel_path))
}

/// The paths a manifest field names (a string or a list of strings).
fn manifest_paths(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

impl Plugin {
    /// Load the plugin at `root`.
    pub fn load(root: &Path, scope: PluginScope) -> anyhow::Result<Self> {
        let manifest_path = root.join(MANIFEST);
        let manifest: Value = if manifest_path.is_file() {
            let text = std::fs::read_to_string(&manifest_path)
                .with_context(|| format!("reading {}", manifest_path.display()))?;
            serde_json::from_str(&text)
                .with_context(|| format!("{} is not valid JSON", manifest_path.display()))?
        } else {
            json!({})
        };
        let name = manifest
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| {
                root.file_name()
                    .and_then(|n| n.to_str())
                    .map(str::to_string)
            })
            .unwrap_or_default();
        if !valid_name(&name) {
            anyhow::bail!("`{name}` is not a valid plugin name (letters, digits, - _ .)");
        }
        let text = |key: &str| {
            manifest
                .get(key)
                .and_then(Value::as_str)
                .map(str::to_string)
        };
        let mut plugin = Self {
            version: text("version"),
            description: text("description"),
            name,
            root: root.to_path_buf(),
            scope,
            command_dirs: Vec::new(),
            agent_dirs: Vec::new(),
            skill_dirs: Vec::new(),
            hooks: Vec::new(),
            mcp_servers: BTreeMap::new(),
            skipped: Vec::new(),
        };
        if let Some(map) = manifest.as_object() {
            for key in map.keys() {
                if !INFO_KEYS.contains(&key.as_str()) && !LOADED_KEYS.contains(&key.as_str()) {
                    plugin.skipped.push(format!(
                        "manifest `{key}` (not supported by MicroClaw Code)"
                    ));
                }
            }
        }
        for (dir, what) in [("output-styles", "output styles"), ("monitors", "monitors")] {
            if root.join(dir).is_dir() {
                plugin
                    .skipped
                    .push(format!("{dir}/ ({what} are not supported)"));
            }
        }

        // Commands, agents and skills: the default directory plus manifest paths.
        for (key, default, list) in [
            ("commands", "commands", 0usize),
            ("agents", "agents", 1),
            ("skills", "skills", 2),
        ] {
            let mut dirs = Vec::new();
            let default_dir = root.join(default);
            if default_dir.is_dir() {
                dirs.push(default_dir);
            }
            for rel in manifest_paths(manifest.get(key)) {
                match inside(root, &rel) {
                    Ok(path) if path.is_dir() => {
                        if !dirs.contains(&path) {
                            dirs.push(path);
                        }
                    }
                    Ok(path) => plugin.skipped.push(format!(
                        "{key}: {} (only directories are supported)",
                        path.display()
                    )),
                    Err(e) => plugin.skipped.push(format!("{key}: {e}")),
                }
            }
            match list {
                0 => plugin.command_dirs = dirs,
                1 => plugin.agent_dirs = dirs,
                _ => plugin.skill_dirs = dirs,
            }
        }

        // Hooks: hooks/hooks.json, manifest paths or an inline object.
        let mut hook_docs: Vec<(Value, String)> = Vec::new();
        let read_json = |path: &Path| -> anyhow::Result<Value> {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("reading {}", path.display()))?;
            serde_json::from_str(&text)
                .with_context(|| format!("{} is not valid JSON", path.display()))
        };
        let default_hooks = root.join("hooks").join("hooks.json");
        match manifest.get("hooks") {
            Some(Value::Object(_)) => {
                hook_docs.push((manifest["hooks"].clone(), "plugin.json hooks".into()))
            }
            Some(other) => {
                for rel in manifest_paths(Some(other)) {
                    match inside(root, &rel).and_then(|p| read_json(&p).map(|v| (v, p))) {
                        Ok((doc, path)) => hook_docs.push((doc, path.display().to_string())),
                        Err(e) => plugin.skipped.push(format!("hooks: {e:#}")),
                    }
                }
            }
            None => {}
        }
        if default_hooks.is_file()
            && !hook_docs
                .iter()
                .any(|(_, origin)| Path::new(origin) == default_hooks)
        {
            match read_json(&default_hooks) {
                Ok(doc) => hook_docs.push((doc, default_hooks.display().to_string())),
                Err(e) => plugin.skipped.push(format!("hooks: {e:#}")),
            }
        }
        for (doc, origin) in hook_docs {
            let events = doc.get("hooks").cloned().unwrap_or(doc);
            let Some(map) = events.as_object() else {
                plugin
                    .skipped
                    .push(format!("{origin}: hooks must be an object"));
                continue;
            };
            let mut map = map.clone();
            map.remove("description");
            let mut found = Vec::new();
            crate::import::claude_hooks(&map, &origin, &mut found, &mut plugin.skipped);
            for (event, mut spec) in found {
                spec.command = spec.command.map(|c| substitute(&c, root));
                spec.url = spec.url.map(|u| substitute(&u, root));
                spec.env = vec![(ROOT_VAR.to_string(), root.to_string_lossy().into_owned())];
                plugin.hooks.push((event, spec));
            }
        }

        // MCP servers: .mcp.json, manifest paths or an inline object.
        let mut server_docs: Vec<(Value, String)> = Vec::new();
        match manifest.get("mcpServers") {
            Some(Value::Object(_)) => server_docs.push((
                manifest["mcpServers"].clone(),
                "plugin.json mcpServers".into(),
            )),
            Some(other) => {
                for rel in manifest_paths(Some(other)) {
                    match inside(root, &rel).and_then(|p| read_json(&p).map(|v| (v, p))) {
                        Ok((doc, path)) => server_docs.push((doc, path.display().to_string())),
                        Err(e) => plugin.skipped.push(format!("mcpServers: {e:#}")),
                    }
                }
            }
            None => {
                let default_mcp = root.join(".mcp.json");
                if default_mcp.is_file() {
                    match read_json(&default_mcp) {
                        Ok(doc) => server_docs.push((doc, default_mcp.display().to_string())),
                        Err(e) => plugin.skipped.push(format!("mcpServers: {e:#}")),
                    }
                }
            }
        }
        for (doc, origin) in server_docs {
            let servers = doc.get("mcpServers").cloned().unwrap_or(doc);
            for (name, server) in servers.as_object().into_iter().flatten() {
                let mut server = server.clone();
                substitute_value(&mut server, root);
                match crate::import::claude_mcp(&server) {
                    Ok(mut converted) => {
                        if converted.get("command").is_some()
                            && let Some(obj) = converted.as_object_mut()
                        {
                            let env = obj.entry("env").or_insert_with(|| json!({}));
                            if let Some(env) = env.as_object_mut() {
                                env.entry(ROOT_VAR)
                                    .or_insert_with(|| json!(root.to_string_lossy()));
                            }
                        }
                        plugin
                            .mcp_servers
                            .insert(format!("{}_{name}", plugin.name), converted);
                    }
                    Err(e) => plugin
                        .skipped
                        .push(format!("{origin}: MCP server `{name}`: {e}")),
                }
            }
        }
        Ok(plugin)
    }

    /// What the plugin brings, one line each: shown before it is enabled.
    pub fn describe(&self) -> Vec<String> {
        let mut lines = vec![format!(
            "plugin  {}{}{}",
            self.name,
            self.version
                .as_deref()
                .map(|v| format!(" {v}"))
                .unwrap_or_default(),
            self.description
                .as_deref()
                .map(|d| format!(" — {d}"))
                .unwrap_or_default()
        )];
        let names = |dirs: &[PathBuf], skills: bool| -> Vec<String> {
            let mut out = Vec::new();
            for dir in dirs {
                let Ok(entries) = std::fs::read_dir(dir) else {
                    continue;
                };
                for path in entries.flatten().map(|e| e.path()) {
                    let ok = if skills {
                        path.join("SKILL.md").is_file()
                    } else {
                        path.extension().is_some_and(|e| e == "md")
                    };
                    if ok
                        && let Some(stem) = if skills {
                            path.file_name()
                        } else {
                            path.file_stem()
                        }
                        .and_then(|n| n.to_str())
                    {
                        out.push(stem.to_string());
                    }
                }
            }
            out.sort();
            out
        };
        for (label, list) in [
            ("command", names(&self.command_dirs, false)),
            ("agent", names(&self.agent_dirs, false)),
            ("skill", names(&self.skill_dirs, true)),
        ] {
            if !list.is_empty() {
                lines.push(format!("{label:<7} {}", list.join(", ")));
            }
        }
        for (event, spec) in &self.hooks {
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
            lines.push(format!("hook    {}{matcher}: runs `{what}`", event.key()));
        }
        for (name, server) in &self.mcp_servers {
            let what = match server.get("command").and_then(Value::as_str) {
                Some(command) => {
                    let mut parts = vec![command.to_string()];
                    parts.extend(
                        server
                            .get("args")
                            .and_then(Value::as_array)
                            .into_iter()
                            .flatten()
                            .filter_map(Value::as_str)
                            .map(str::to_string),
                    );
                    format!("runs `{}`", parts.join(" "))
                }
                None => format!(
                    "connects to {}",
                    server
                        .get("endpoint")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                ),
            };
            lines.push(format!("mcp     {name}: {}", what.trim()));
        }
        lines.extend(self.skipped.iter().map(|s| format!("skipped {s}")));
        // Show the plugin directory as the variable plugins are written with.
        let root = self.root.to_string_lossy().into_owned();
        lines
            .into_iter()
            .map(|l| l.replace(&root, &format!("${{{ROOT_VAR}}}")))
            .collect()
    }

    /// Whether the plugin runs anything on its own (hooks or MCP commands).
    pub fn runs_commands(&self) -> bool {
        !self.hooks.is_empty() || !self.mcp_servers.is_empty()
    }

    /// The plugin's slash commands: `/name` and `/plugin:name`.
    pub fn commands(&self) -> Vec<CustomCommand> {
        let mut out = Vec::new();
        for dir in &self.command_dirs {
            for mut command in crate::commands::load_dir(dir, "plugin") {
                command.body = substitute(&command.body, &self.root);
                command.description = format!("[{}] {}", self.name, command.description);
                let mut qualified = command.clone();
                qualified.name = format!("{}:{}", self.name, command.name);
                out.push(qualified);
                out.push(command);
            }
        }
        out
    }
}

// ---------------------------------------------------------------- registry

/// One installed plugin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Installed {
    pub name: String,
    /// Where it came from: a git URL or a local path.
    pub source: String,
    /// The plugin's directory inside the source (marketplace repositories).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subdir: Option<String>,
    /// Branch, tag or commit the source was pinned to.
    #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
    pub git_ref: Option<String>,
    /// Git commit the copy was made from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    pub installed_at: String,
    #[serde(default = "enabled_default")]
    pub enabled: bool,
}

fn enabled_default() -> bool {
    true
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct RegistryFile {
    #[serde(default)]
    plugins: Vec<Installed>,
}

/// The plugins installed in one directory (user or project).
#[derive(Debug, Clone)]
pub struct Registry {
    pub dir: PathBuf,
    pub scope: PluginScope,
    pub entries: Vec<Installed>,
}

/// The user plugins directory.
pub fn user_dir() -> PathBuf {
    crate::home::code_home().join("plugins")
}

/// The project plugins directory.
pub fn project_dir(root: &Path) -> PathBuf {
    root.join(".microclaw").join("plugins")
}

impl Registry {
    pub fn load(dir: &Path, scope: PluginScope) -> Self {
        let entries = std::fs::read_to_string(dir.join(REGISTRY_FILE))
            .ok()
            .and_then(|t| serde_json::from_str::<RegistryFile>(&t).ok())
            .map(|f| f.plugins)
            .unwrap_or_default();
        Self {
            dir: dir.to_path_buf(),
            scope,
            entries,
        }
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let path = self.dir.join(REGISTRY_FILE);
        if self.entries.is_empty() {
            // Nothing installed: leave no trace (an empty directory goes too).
            let _ = std::fs::remove_file(&path);
            let _ = std::fs::remove_dir(&self.dir);
            return Ok(());
        }
        std::fs::create_dir_all(&self.dir)?;
        let file = RegistryFile {
            plugins: self.entries.clone(),
        };
        std::fs::write(&path, serde_json::to_string_pretty(&file)? + "\n")
            .with_context(|| format!("writing {}", path.display()))
    }

    pub fn get(&self, name: &str) -> Option<&Installed> {
        self.entries.iter().find(|e| e.name == name)
    }

    pub fn plugin_dir(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// Plugin directories in this registry's directory: registered ones
    /// (when enabled) plus, for a project, ones committed without an entry.
    pub fn enabled_dirs(&self) -> Vec<PathBuf> {
        let mut dirs: Vec<PathBuf> = self
            .entries
            .iter()
            .filter(|e| e.enabled)
            .map(|e| self.plugin_dir(&e.name))
            .filter(|d| d.is_dir())
            .collect();
        if self.scope == PluginScope::Project
            && let Ok(entries) = std::fs::read_dir(&self.dir)
        {
            let mut extra: Vec<PathBuf> = entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.is_dir())
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| valid_name(n) && self.get(n).is_none())
                })
                .collect();
            extra.sort();
            dirs.extend(extra);
        }
        dirs
    }
}

// ------------------------------------------------------------- installing

/// A plugin fetched and loaded, not yet installed.
pub struct Staged {
    pub plugin: Plugin,
    pub source: String,
    pub subdir: Option<String>,
    /// Branch, tag or commit asked for (marketplace entries).
    pub git_ref: Option<String>,
    pub commit: Option<String>,
    /// Keeps a cloned repository alive until the plugin is copied.
    _checkout: Option<tempfile::TempDir>,
}

/// `owner/repo` and `github:owner/repo` mean GitHub; other non-paths are
/// passed to git as they are.
fn git_url(source: &str) -> Option<String> {
    if let Some(rest) = source.strip_prefix("github:") {
        return Some(format!("https://github.com/{rest}.git"));
    }
    let shorthand = source.split('/').count() == 2
        && !source.starts_with('.')
        && source
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/'));
    if shorthand {
        return Some(format!("https://github.com/{source}.git"));
    }
    (source.contains("://") || source.starts_with("git@") || source.ends_with(".git"))
        .then(|| source.to_string())
}

fn run_git(dir: Option<&Path>, args: &[&str]) -> anyhow::Result<String> {
    let mut cmd = std::process::Command::new("git");
    cmd.args(args);
    if let Some(dir) = dir {
        cmd.current_dir(dir);
    }
    let output = cmd.output().context("running git")?;
    if !output.status.success() {
        anyhow::bail!(
            "git {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Where the plugin to install lives.
enum Located {
    /// A directory of the fetched source, with its path there.
    Here(PathBuf, Option<String>),
    /// A directory of another git repository (marketplace entries).
    Remote {
        url: String,
        path: Option<String>,
        git_ref: Option<String>,
    },
}

/// The plugin directory inside `dir`: the directory itself when it is a
/// plugin, or the one named `select` in its marketplace.
fn locate(dir: &Path, select: Option<&str>) -> anyhow::Result<Located> {
    let marketplace = dir.join(MARKETPLACE);
    let has_manifest = dir.join(MANIFEST).is_file();
    if !marketplace.is_file() || (has_manifest && select.is_none()) {
        if let Some(name) = select {
            let plugin = Plugin::load(dir, PluginScope::User)?;
            if plugin.name != name {
                anyhow::bail!("the source is the plugin `{}`, not `{name}`", plugin.name);
            }
        }
        return Ok(Located::Here(dir.to_path_buf(), None));
    }
    let text = std::fs::read_to_string(&marketplace)
        .with_context(|| format!("reading {}", marketplace.display()))?;
    let doc: Value = serde_json::from_str(&text)
        .with_context(|| format!("{} is not valid JSON", marketplace.display()))?;
    let plugins = doc
        .get("plugins")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let names: Vec<String> = plugins
        .iter()
        .filter_map(|p| p.get("name").and_then(Value::as_str))
        .map(str::to_string)
        .collect();
    let chosen = match select {
        Some(name) => plugins
            .iter()
            .find(|p| p.get("name").and_then(Value::as_str) == Some(name))
            .with_context(|| {
                format!(
                    "no plugin `{name}` in this marketplace (it has: {})",
                    names.join(", ")
                )
            })?,
        None if plugins.len() == 1 => &plugins[0],
        None => anyhow::bail!(
            "this repository lists several plugins; pick one with --plugin <name>: {}",
            names.join(", ")
        ),
    };
    let name = chosen
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let text_of = |v: &Value, key: &str| v.get(key).and_then(Value::as_str).map(str::to_string);
    match chosen.get("source") {
        Some(Value::String(source)) => {
            let rel = source.trim_start_matches("./");
            let root = inside(dir, rel)?;
            if !root.is_dir() {
                anyhow::bail!("plugin `{name}`: {} does not exist", root.display());
            }
            Ok(Located::Here(root, Some(rel.to_string())))
        }
        Some(spec @ Value::Object(_)) => {
            let kind = text_of(spec, "source").unwrap_or_default();
            let url = match kind.as_str() {
                "github" => text_of(spec, "repo").map(|r| format!("https://github.com/{r}.git")),
                "url" | "git" | "git-subdir" => text_of(spec, "url"),
                _ => None,
            }
            .with_context(|| format!("plugin `{name}`: unsupported source {spec}"))?;
            Ok(Located::Remote {
                url,
                path: text_of(spec, "path").map(|p| p.trim_start_matches("./").to_string()),
                git_ref: text_of(spec, "ref").or_else(|| text_of(spec, "sha")),
            })
        }
        _ => anyhow::bail!("plugin `{name}` has no source in the marketplace"),
    }
}

/// A shallow clone of `url` at `git_ref`, with its commit.
fn fetch(
    url: &str,
    git_ref: Option<&str>,
) -> anyhow::Result<(tempfile::TempDir, PathBuf, Option<String>)> {
    let checkout = tempfile::tempdir()?;
    let target = checkout.path().join("repo");
    let target_text = target.to_string_lossy().into_owned();
    let mut args = vec!["clone", "--depth", "1", "--quiet"];
    if let Some(r) = git_ref {
        args.extend(["--branch", r]);
    }
    args.extend([url, target_text.as_str()]);
    if let Err(e) = run_git(None, &args) {
        // A commit rather than a branch or tag: full clone, then check out.
        let Some(r) = git_ref else { return Err(e) };
        let _ = std::fs::remove_dir_all(&target);
        run_git(None, &["clone", "--quiet", url, &target_text])?;
        run_git(Some(&target), &["checkout", "--quiet", r])?;
    }
    let commit = run_git(Some(&target), &["rev-parse", "HEAD"]).ok();
    Ok((checkout, target, commit))
}

fn staged_at(
    root: &Path,
    source: String,
    subdir: Option<String>,
    git_ref: Option<String>,
    commit: Option<String>,
    checkout: Option<tempfile::TempDir>,
) -> anyhow::Result<Staged> {
    let plugin = Plugin::load(root, PluginScope::User)?;
    Ok(Staged {
        plugin,
        source,
        subdir,
        git_ref,
        commit,
        _checkout: checkout,
    })
}

/// Fetch `source` (a local directory or a git repository) and load the
/// plugin in it, picking `select` from a marketplace (which may send us on
/// to another repository).
pub fn stage(source: &str, select: Option<&str>) -> anyhow::Result<Staged> {
    let local = Path::new(source);
    let (checkout, dir, source, commit) = if local.is_dir() {
        let dir = std::fs::canonicalize(local)?;
        let commit = run_git(Some(&dir), &["rev-parse", "HEAD"]).ok();
        (
            None,
            dir.clone(),
            dir.to_string_lossy().into_owned(),
            commit,
        )
    } else {
        let url = git_url(source)
            .with_context(|| format!("`{source}` is neither a directory nor a git repository"))?;
        let (checkout, dir, commit) = fetch(&url, None)?;
        (Some(checkout), dir, url, commit)
    };
    match locate(&dir, select)? {
        Located::Here(root, subdir) => staged_at(&root, source, subdir, None, commit, checkout),
        Located::Remote { url, path, git_ref } => {
            stage_at(&url, path.as_deref(), git_ref.as_deref())
        }
    }
}

/// The plugin in directory `subdir` of `source` (a git repository or a
/// local directory) at `git_ref`: how installed plugins are updated.
pub fn stage_at(
    source: &str,
    subdir: Option<&str>,
    git_ref: Option<&str>,
) -> anyhow::Result<Staged> {
    let local = Path::new(source);
    let (checkout, dir, commit) = if local.is_dir() {
        let dir = std::fs::canonicalize(local)?;
        let commit = run_git(Some(&dir), &["rev-parse", "HEAD"]).ok();
        (None, dir, commit)
    } else {
        let (checkout, dir, commit) = fetch(source, git_ref)?;
        (Some(checkout), dir, commit)
    };
    let root = match subdir {
        Some(rel) => inside(&dir, rel)?,
        None => dir.clone(),
    };
    if !root.is_dir() {
        anyhow::bail!("{source}: {} does not exist", subdir.unwrap_or("."));
    }
    staged_at(
        &root,
        source.to_string(),
        subdir.map(str::to_string),
        git_ref.map(str::to_string),
        commit,
        checkout,
    )
}

/// Copy `src` into `dst` (no `.git`, no symbolic links).
fn copy_dir(src: &Path, dst: &Path, skipped: &mut Vec<String>) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let name = entry.file_name();
        if name == ".git" {
            continue;
        }
        let kind = entry.file_type()?;
        let to = dst.join(&name);
        if kind.is_symlink() {
            skipped.push(format!(
                "{}: symbolic link not copied",
                entry.path().display()
            ));
        } else if kind.is_dir() {
            copy_dir(&entry.path(), &to, skipped)?;
        } else {
            std::fs::copy(entry.path(), &to)?;
        }
    }
    Ok(())
}

/// Copy a staged plugin into `registry` and record it; replaces an earlier
/// copy of the same plugin. Returns the installed plugin (loaded from its
/// new place) and anything not copied.
pub fn install(staged: &Staged, registry: &mut Registry) -> anyhow::Result<(Plugin, Vec<String>)> {
    let name = staged.plugin.name.clone();
    let dest = registry.plugin_dir(&name);
    let tmp = registry.dir.join(format!(".{name}.installing"));
    let _ = std::fs::remove_dir_all(&tmp);
    let mut skipped = Vec::new();
    copy_dir(&staged.plugin.root, &tmp, &mut skipped)
        .with_context(|| format!("copying the plugin to {}", tmp.display()))?;
    if dest.exists() {
        std::fs::remove_dir_all(&dest).with_context(|| format!("replacing {}", dest.display()))?;
    }
    std::fs::rename(&tmp, &dest)?;
    let entry = Installed {
        name: name.clone(),
        source: staged.source.clone(),
        subdir: staged.subdir.clone(),
        git_ref: staged.git_ref.clone(),
        commit: staged.commit.clone(),
        installed_at: chrono::Utc::now().to_rfc3339(),
        enabled: true,
    };
    registry.entries.retain(|e| e.name != name);
    registry.entries.push(entry);
    registry.entries.sort_by(|a, b| a.name.cmp(&b.name));
    registry.save()?;
    let plugin = Plugin::load(&dest, registry.scope)?;
    Ok((plugin, skipped))
}

/// Remove `name` from `registry`: its directory, its entry and its
/// generated MCP configuration. Returns false when it is not installed.
pub fn remove(name: &str, registry: &mut Registry) -> anyhow::Result<bool> {
    let dir = registry.plugin_dir(name);
    let known = registry.get(name).is_some() || dir.is_dir();
    if !known || !valid_name(name) {
        return Ok(false);
    }
    if dir.exists() {
        std::fs::remove_dir_all(&dir).with_context(|| format!("removing {}", dir.display()))?;
    }
    registry.entries.retain(|e| e.name != name);
    registry.save()?;
    if let Ok(entries) = std::fs::read_dir(generated_dir()) {
        for path in entries.flatten().map(|e| e.path()) {
            if path
                .file_stem()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.ends_with(&format!("--{name}")))
            {
                let _ = std::fs::remove_file(path);
            }
        }
    }
    Ok(true)
}

/// Hook and MCP lines of `new` that `old` did not have (for update
/// confirmations).
pub fn new_commands(old: Option<&Plugin>, new: &Plugin) -> Vec<String> {
    // Compare with the plugin directory abstracted: the staged copy and the
    // installed one live in different places.
    let lines = |p: &Plugin| -> Vec<String> {
        let root = p.root.to_string_lossy().into_owned();
        p.describe()
            .into_iter()
            .filter(|l| l.starts_with("hook ") || l.starts_with("mcp "))
            .map(|l| l.replace(&root, &format!("${{{ROOT_VAR}}}")))
            .collect()
    };
    let old_lines = old.map(lines).unwrap_or_default();
    lines(new)
        .into_iter()
        .filter(|l| !old_lines.contains(l))
        .collect()
}

// ------------------------------------------------------------ at runtime

/// The plugins active in `project`: enabled user plugins, then (trusted
/// projects only) project plugins. A later plugin with an existing name is
/// skipped. Problems are returned as warnings.
pub fn active(project: &crate::project::Project) -> (Vec<Plugin>, Vec<String>) {
    active_in(&user_dir(), project)
}

/// [`active`] with an explicit user plugins directory.
pub fn active_in(user_dir: &Path, project: &crate::project::Project) -> (Vec<Plugin>, Vec<String>) {
    let mut plugins: Vec<Plugin> = Vec::new();
    let mut warnings = Vec::new();
    let mut registries = vec![Registry::load(user_dir, PluginScope::User)];
    let project_plugins = project_dir(&project.root);
    if project.trusted {
        registries.push(Registry::load(&project_plugins, PluginScope::Project));
    } else if project_plugins.is_dir() {
        warnings.push(format!(
            "project plugins in {} are not loaded: the project is not trusted",
            project_plugins.display()
        ));
    }
    for registry in registries {
        for dir in registry.enabled_dirs() {
            match Plugin::load(&dir, registry.scope) {
                Ok(plugin) if plugins.iter().any(|p| p.name == plugin.name) => {
                    warnings.push(format!(
                        "plugin `{}` in {} is already loaded",
                        plugin.name,
                        dir.display()
                    ))
                }
                Ok(plugin) => plugins.push(plugin),
                Err(e) => warnings.push(format!("plugin {}: {e:#}", dir.display())),
            }
        }
    }
    (plugins, warnings)
}

/// Generated MCP configurations of active plugins.
pub fn generated_dir() -> PathBuf {
    user_dir().join(".generated")
}

/// What the engine needs from `plugins`; their MCP servers are written to
/// one generated configuration file per plugin under `generated`.
pub fn engine_sources(
    plugins: &[Plugin],
    project_root: &Path,
    generated: &Path,
) -> (microclaw_sdk::PluginSources, Vec<String>) {
    let mut sources = microclaw_sdk::PluginSources::default();
    let mut warnings = Vec::new();
    for plugin in plugins {
        sources
            .agents_dirs
            .extend(plugin.agent_dirs.iter().cloned());
        sources
            .skills_dirs
            .extend(plugin.skill_dirs.iter().cloned());
        if plugin.mcp_servers.is_empty() {
            continue;
        }
        let scope = match plugin.scope {
            PluginScope::User => "user".to_string(),
            PluginScope::Project => format!("project-{}", crate::memory::project_key(project_root)),
        };
        let path = generated.join(format!("{scope}--{}.json", plugin.name));
        let doc = json!({ "mcpServers": plugin.mcp_servers });
        let written = std::fs::create_dir_all(generated).and_then(|_| {
            std::fs::write(
                &path,
                serde_json::to_string_pretty(&doc).unwrap_or_default() + "\n",
            )
        });
        match written {
            Ok(()) => sources.mcp_configs.push(path),
            Err(e) => warnings.push(format!(
                "plugin `{}`: cannot write {}: {e}",
                plugin.name,
                path.display()
            )),
        }
    }
    (sources, warnings)
}

/// Add the plugins' hooks to `settings` (after the configured ones).
pub fn apply_hooks(settings: &mut CodeSettings, plugins: &[Plugin]) {
    for plugin in plugins {
        for (event, spec) in &plugin.hooks {
            hooks_for(&mut settings.hooks, *event).push(spec.clone());
        }
    }
}

/// The hook list of `event` in `config`.
pub fn hooks_for(config: &mut HooksConfig, event: HookEvent) -> &mut Vec<HookSpec> {
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

/// Slash commands of `plugins`; a name already taken by an earlier
/// plugin keeps only its `/plugin:name` form.
pub fn commands(plugins: &[Plugin]) -> Vec<CustomCommand> {
    let mut out: Vec<CustomCommand> = Vec::new();
    for plugin in plugins {
        for command in plugin.commands() {
            if !out.iter().any(|c| c.name == command.name) {
                out.push(command);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    /// A plugin in the Claude Code layout.
    fn sample(dir: &Path) {
        write(
            &dir.join(MANIFEST),
            r#"{"name":"fmt-kit","version":"1.2.0","description":"Formatting","author":{"name":"x"},"outputStyles":"./styles"}"#,
        );
        write(
            &dir.join("commands/fmt.md"),
            "---\ndescription: Format files\n---\nRun ${CLAUDE_PLUGIN_ROOT}/fmt.sh on $ARGUMENTS",
        );
        write(
            &dir.join("agents/styler.md"),
            "---\ndescription: Styles\n---\nYou style code.",
        );
        write(
            &dir.join("skills/tidy/SKILL.md"),
            "---\nname: tidy\ndescription: Tidy up\n---\nTidy.",
        );
        write(
            &dir.join("hooks/hooks.json"),
            r#"{"description":"x","hooks":{"PostToolUse":[{"matcher":"Edit|Write","hooks":[{"type":"command","command":"${CLAUDE_PLUGIN_ROOT}/scripts/fmt.sh"}]}],"SubagentStop":[{"hooks":[{"type":"command","command":"x"}]}]}}"#,
        );
        write(
            &dir.join(".mcp.json"),
            r#"{"mcpServers":{"docs":{"command":"node","args":["${CLAUDE_PLUGIN_ROOT}/server.js"]},"web":{"type":"http","url":"https://example.com/mcp"}}}"#,
        );
    }

    #[test]
    fn loads_the_claude_code_layout() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("fmt-kit");
        sample(&root);
        let plugin = Plugin::load(&root, PluginScope::User).unwrap();
        assert_eq!(plugin.name, "fmt-kit");
        assert_eq!(plugin.version.as_deref(), Some("1.2.0"));
        assert_eq!(plugin.command_dirs, vec![root.join("commands")]);
        assert_eq!(plugin.agent_dirs, vec![root.join("agents")]);
        assert_eq!(plugin.skill_dirs, vec![root.join("skills")]);

        let (event, hook) = &plugin.hooks[0];
        assert_eq!(*event, HookEvent::PostToolUse);
        let root_text = root.to_string_lossy();
        assert_eq!(
            hook.command.as_deref(),
            Some(format!("{root_text}/scripts/fmt.sh").as_str())
        );
        assert_eq!(
            hook.env,
            vec![(ROOT_VAR.to_string(), root_text.to_string())]
        );

        let docs = &plugin.mcp_servers["fmt-kit_docs"];
        assert_eq!(docs["args"][0], format!("{root_text}/server.js"));
        assert_eq!(docs["env"][ROOT_VAR], root_text.as_ref());
        assert_eq!(
            plugin.mcp_servers["fmt-kit_web"]["endpoint"],
            "https://example.com/mcp"
        );
        assert!(plugin.skipped.iter().any(|s| s.contains("outputStyles")));
        assert!(plugin.skipped.iter().any(|s| s.contains("SubagentStop")));

        let described = plugin.describe().join("\n");
        assert!(described.contains("command fmt"), "{described}");
        assert!(described.contains("agent   styler"));
        assert!(described.contains("skill   tidy"));
        assert!(described.contains("hook    post_tool_use [Edit|Write]: runs"));
        assert!(
            described.contains("mcp     fmt-kit_docs: runs `node ${CLAUDE_PLUGIN_ROOT}/server.js`"),
            "{described}"
        );
        assert!(plugin.runs_commands());

        let commands = plugin.commands();
        let names: Vec<&str> = commands.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["fmt-kit:fmt", "fmt"]);
        assert_eq!(
            commands[1].expand("src"),
            format!("Run {root_text}/fmt.sh on src")
        );
        assert_eq!(commands[1].description, "[fmt-kit] Format files");
    }

    #[test]
    fn manifest_paths_stay_inside_the_plugin() {
        let dir = tempfile::tempdir().unwrap();
        write(
            &dir.path().join(MANIFEST),
            r#"{"name":"p","commands":["./extra","../outside"],"hooks":{"Stop":[{"hooks":[{"type":"command","command":"echo done"}]}]}}"#,
        );
        write(&dir.path().join("extra/a.md"), "A");
        let plugin = Plugin::load(dir.path(), PluginScope::User).unwrap();
        assert_eq!(plugin.command_dirs, vec![dir.path().join("extra")]);
        assert!(
            plugin
                .skipped
                .iter()
                .any(|s| s.contains("outside the plugin"))
        );
        assert_eq!(plugin.hooks.len(), 1);
        assert!(Plugin::load(dir.path(), PluginScope::User).is_ok());
        write(&dir.path().join(MANIFEST), r#"{"name":"../evil"}"#);
        assert!(Plugin::load(dir.path(), PluginScope::User).is_err());
    }

    #[test]
    fn installs_updates_and_removes_without_leaving_traces() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("src");
        sample(&source);
        let plugins_dir = tmp.path().join("plugins");
        let mut registry = Registry::load(&plugins_dir, PluginScope::User);
        let staged = stage(source.to_str().unwrap(), None).unwrap();
        assert_eq!(staged.plugin.name, "fmt-kit");
        let (installed, skipped) = install(&staged, &mut registry).unwrap();
        assert!(skipped.is_empty());
        assert_eq!(installed.root, plugins_dir.join("fmt-kit"));
        assert!(plugins_dir.join("fmt-kit/commands/fmt.md").is_file());
        // Paths now point at the installed copy.
        assert!(
            installed.hooks[0]
                .1
                .command
                .as_deref()
                .unwrap()
                .starts_with(&plugins_dir.to_string_lossy().into_owned())
        );
        let reloaded = Registry::load(&plugins_dir, PluginScope::User);
        assert_eq!(reloaded.entries.len(), 1);
        assert_eq!(reloaded.enabled_dirs(), vec![plugins_dir.join("fmt-kit")]);

        // An update that adds a hook reports the new command.
        write(
            &source.join("hooks/hooks.json"),
            r#"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"curl evil"}]}]}}"#,
        );
        let again = stage(source.to_str().unwrap(), None).unwrap();
        let added = new_commands(Some(&installed), &again.plugin);
        assert_eq!(added.len(), 1, "{added:?}");
        assert!(added[0].contains("curl evil"));

        assert!(remove("fmt-kit", &mut registry).unwrap());
        assert!(!plugins_dir.join("fmt-kit").exists());
        assert!(!plugins_dir.join(REGISTRY_FILE).exists());
        assert!(
            Registry::load(&plugins_dir, PluginScope::User)
                .entries
                .is_empty()
        );
        assert!(!remove("fmt-kit", &mut registry).unwrap());
    }

    #[test]
    fn marketplaces_need_a_choice() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("market");
        write(
            &repo.join(MARKETPLACE),
            r#"{"name":"m","plugins":[{"name":"fmt-kit","source":"./plugins/fmt-kit"},{"name":"other","source":"./plugins/other"},{"name":"remote","source":{"source":"github","repo":"a/b"}}]}"#,
        );
        sample(&repo.join("plugins/fmt-kit"));
        write(&repo.join("plugins/other/commands/x.md"), "X");
        let err = stage(repo.to_str().unwrap(), None)
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("fmt-kit, other, remote"), "{err}");
        let staged = stage(repo.to_str().unwrap(), Some("fmt-kit")).unwrap();
        assert_eq!(staged.plugin.name, "fmt-kit");
        assert_eq!(staged.subdir.as_deref(), Some("plugins/fmt-kit"));
        assert!(stage(repo.to_str().unwrap(), Some("remote")).is_err());
        assert!(stage(repo.to_str().unwrap(), Some("nope")).is_err());
    }

    #[test]
    fn project_plugins_need_trust_and_wire_into_settings_and_engine() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        sample(&project_dir(&repo).join("fmt-kit"));
        let user = tmp.path().join("user-plugins");
        let untrusted = crate::project::Project::discover(&repo, |_, _| false).unwrap();
        let (plugins, warnings) = active_in(&user, &untrusted);
        assert!(plugins.is_empty());
        assert!(warnings[0].contains("not trusted"));

        let trusted = crate::project::Project::discover(&repo, |_, _| true).unwrap();
        let (plugins, warnings) = active_in(&user, &trusted);
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(plugins.len(), 1);
        assert_eq!(plugins[0].scope, PluginScope::Project);

        let mut settings = CodeSettings::default();
        apply_hooks(&mut settings, &plugins);
        assert_eq!(settings.hooks.post_tool_use.len(), 1);

        let generated = tmp.path().join("generated");
        let (sources, warnings) = engine_sources(&plugins, &repo, &generated);
        assert!(warnings.is_empty());
        assert_eq!(sources.agents_dirs.len(), 1);
        assert_eq!(sources.skills_dirs.len(), 1);
        assert_eq!(sources.mcp_configs.len(), 1);
        let doc: Value =
            serde_json::from_str(&std::fs::read_to_string(&sources.mcp_configs[0]).unwrap())
                .unwrap();
        assert_eq!(doc["mcpServers"]["fmt-kit_docs"]["command"], "node");

        let names: Vec<String> = commands(&plugins).into_iter().map(|c| c.name).collect();
        assert_eq!(names, ["fmt-kit:fmt", "fmt"]);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn plugin_hooks_run_with_the_plugin_root() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("p");
        write(
            &root.join("hooks/hooks.json"),
            r#"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"printf %s \"$CLAUDE_PLUGIN_ROOT\" > \"${CLAUDE_PLUGIN_ROOT}/ran.txt\""}]}]}}"#,
        );
        let plugin = Plugin::load(&root, PluginScope::User).unwrap();
        let mut settings = CodeSettings::default();
        apply_hooks(&mut settings, &[plugin]);
        let hooks =
            crate::user_hooks::UserHooks::new(settings.hooks, tmp.path().to_path_buf(), "s");
        let outcome = hooks
            .run(HookEvent::Stop, crate::user_hooks::HookPayload::default())
            .await;
        assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
        assert_eq!(
            std::fs::read_to_string(root.join("ran.txt")).unwrap(),
            root.to_string_lossy()
        );
    }

    #[test]
    fn git_sources() {
        assert_eq!(
            git_url("anthropics/claude-plugins").as_deref(),
            Some("https://github.com/anthropics/claude-plugins.git")
        );
        assert_eq!(
            git_url("github:a/b").as_deref(),
            Some("https://github.com/a/b.git")
        );
        assert_eq!(
            git_url("git@example.com:a/b.git").as_deref(),
            Some("git@example.com:a/b.git")
        );
        assert_eq!(git_url("plain-word"), None);
    }
}
