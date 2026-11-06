//! Layered MicroClaw Code settings (managed, user, project, project-local).
//!
//! One file format, four layers, merged in this order (later wins for
//! scalars; lists such as permission rules and hooks are concatenated):
//!
//! 1. user — `~/.microclaw/code/settings.yaml`
//! 2. project — `<repo>/.microclaw/settings.yaml` (trusted projects only)
//! 3. project-local — `<repo>/.microclaw/settings.local.yaml` (trusted only,
//!    not committed)
//! 4. managed — `/etc/microclaw/code/managed.yaml` (macOS:
//!    `/Library/Application Support/MicroClaw/code/managed.yaml`); it can
//!    only tighten: its `deny` / `ask` rules always apply and its scalars win.
//!
//! The types below are the file schema (`version: 1`). Below them:
//! layer discovery and merging ([`load`]), provenance
//! ([`LoadedSettings::source_of`]), version migration ([`migrate`]),
//! `mccode config doctor` ([`doctor`]), `mccode config get/set/unset`
//! ([`get`], [`set_in_file`], [`unset_in_file`]), the published JSON Schema
//! ([`json_schema`]), model profile resolution ([`resolve_model`]) and the
//! `mccode config init` template ([`template`]).

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_yaml::{Mapping, Value};

/// Current settings file version.
pub const SETTINGS_VERSION: u32 = 1;

/// The whole settings document.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct CodeSettings {
    /// Settings format version (currently 1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,
    #[serde(skip_serializing_if = "ModelConfig::is_empty")]
    pub model: ModelConfig,
    #[serde(skip_serializing_if = "PermissionsConfig::is_empty")]
    pub permissions: PermissionsConfig,
    #[serde(skip_serializing_if = "SandboxConfig::is_empty")]
    pub sandbox: SandboxConfig,
    #[serde(skip_serializing_if = "HooksConfig::is_empty")]
    pub hooks: HooksConfig,
    #[serde(skip_serializing_if = "TuiConfig::is_empty")]
    pub tui: TuiConfig,
    #[serde(skip_serializing_if = "NotifyConfig::is_empty")]
    pub notify: NotifyConfig,
}

/// Models: the default, per-role overrides and Code's own provider profiles.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ModelConfig {
    /// Default model, `<profile>/<model>` or a bare model name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
    /// Per-role models.
    #[serde(skip_serializing_if = "ModelRoles::is_empty")]
    pub roles: ModelRoles,
    /// Provider profiles by name (used instead of a full MicroClaw config).
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub profiles: BTreeMap<String, ProviderProfile>,
}

impl ModelConfig {
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

/// Models for specific kinds of work; unset roles use the default model.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ModelRoles {
    /// Plan mode turns.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan: Option<String>,
    /// `/review` and `mccode review`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub review: Option<String>,
    /// Sub-agents and `explore`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subagent: Option<String>,
    /// Compaction summaries and handoffs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

impl ModelRoles {
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

/// One LLM provider endpoint.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ProviderProfile {
    /// Provider kind: `anthropic`, `openai` (any OpenAI-compatible API),
    /// `ollama`, `deepseek`, … (the MicroClaw `llm_provider` names).
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    /// Environment variable holding the API key (preferred over `api_key`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key_env: Option<String>,
    /// API key in clear text (keep this in the user layer only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    /// Model used when the profile is selected without a model name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

/// Permission rules. A rule is `<kind>(<pattern>)` with kind `bash`, `read`,
/// `edit`, `net`, `mcp`, `agent` or `tool`; deny wins over ask, ask over
/// allow.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct PermissionsConfig {
    /// Starting mode: `plan`, `ask` or `auto`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_mode: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ask: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
    /// Managed only: modes users may not select (e.g. `[auto]`).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub disabled_modes: Vec<String>,
}

impl PermissionsConfig {
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

/// Network access of sandboxed shell commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum NetworkMode {
    Off,
    Ask,
    On,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct SandboxConfig {
    /// `local` (OS sandbox, default) or `off`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkMode>,
    /// Domains web tools may reach without asking (`*.example.com` allowed).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allow_domains: Vec<String>,
    /// Extra writable directories for shell commands.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub writable_roots: Vec<String>,
}

impl SandboxConfig {
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

/// One hook handler.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct HookSpec {
    /// Regex on the tool name (ours or the Claude Code name, e.g. `Bash`,
    /// `Edit|Write`); empty matches everything. Tool events only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matcher: Option<String>,
    /// Shell command; receives the event as JSON on stdin. `{file}` is
    /// replaced by the edited file for `post_edit`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// HTTP endpoint that receives the event as a JSON POST instead.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Seconds (default 60).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
}

/// Hooks by event. Commands follow the Claude Code hook protocol: JSON on
/// stdin, exit code 2 blocks, JSON on stdout may carry `decision`,
/// `reason`, `hookSpecificOutput.permissionDecision`, `updatedInput`,
/// `additionalContext`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct HooksConfig {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub session_start: Vec<HookSpec>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub user_prompt_submit: Vec<HookSpec>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pre_tool_use: Vec<HookSpec>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub post_tool_use: Vec<HookSpec>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub post_edit: Vec<HookSpec>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub permission_request: Vec<HookSpec>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pre_compact: Vec<HookSpec>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub stop: Vec<HookSpec>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notification: Vec<HookSpec>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub session_end: Vec<HookSpec>,
}

impl HooksConfig {
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

/// Where transcript output goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ScreenMode {
    /// Fullscreen, except inline under tmux / Zellij.
    Auto,
    Fullscreen,
    Inline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum DiffStyle {
    Auto,
    Split,
    Unified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum SidebarMode {
    Auto,
    Show,
    Hide,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct TerminalNotifications {
    /// `auto`, `osc9`, `osc777`, `bell` or `off`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// `unfocused` (default) or `always`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub when: Option<String>,
}

/// Terminal UI preferences.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct TuiConfig {
    /// Theme name (`auto`, `dark`, `light`, `ansi`, a built-in or a file in
    /// `~/.microclaw/code/themes/`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub theme: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub screen: Option<ScreenMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sidebar: Option<SidebarMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff: Option<DiffStyle>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub animations: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mouse: Option<bool>,
    /// Status line items in order: `mode`, `model`, `context`, `tokens`,
    /// `cost`, `branch`, `sandbox`, `session`, `checks`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_line: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notifications: Option<TerminalNotifications>,
    /// Key bindings: action → key (e.g. `chat.steer: ctrl+s`).
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub keymap: BTreeMap<String, String>,
}

impl TuiConfig {
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

/// Push notifications and approvals to a chat through a paired MicroClaw
/// Server (`mccode remote pair`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct NotifyConfig {
    /// Chat to notify, `<channel>:<chat id>` (e.g. `telegram:123456789`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chat: Option<String>,
    /// Events: `approval`, `done`, `check_failed`, `error`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub events: Vec<String>,
    /// Send approvals to the chat only after the terminal has been
    /// unattended this many seconds (default 60; 0 = always).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after_idle_secs: Option<u64>,
}

impl NotifyConfig {
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

// ---------------------------------------------------------------------------
// Layers and paths
// ---------------------------------------------------------------------------

/// Environment variable overriding the managed settings path (tests, MDM).
pub const MANAGED_ENV: &str = "MICROCLAW_CODE_MANAGED";
/// Settings file name in the Code home and in `.microclaw/`.
pub const SETTINGS_FILE: &str = "settings.yaml";
/// Project-local (not committed) settings file name in `.microclaw/`.
pub const LOCAL_SETTINGS_FILE: &str = "settings.local.yaml";
/// `$id` of the published JSON Schema.
pub const SCHEMA_ID: &str = "https://microclaw.ai/schema/code-settings.v1.json";
/// First line written to settings files so YAML language servers validate them.
pub const SCHEMA_COMMENT: &str =
    "# yaml-language-server: $schema=https://microclaw.ai/schema/code-settings.v1.json";
const SCHEMA_COMMENT_PREFIX: &str = "# yaml-language-server:";

/// One settings layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettingsLayer {
    User,
    Project,
    ProjectLocal,
    Managed,
}

impl SettingsLayer {
    /// All layers in merge order (later layers win for scalars).
    pub const ALL: [SettingsLayer; 4] = [
        SettingsLayer::User,
        SettingsLayer::Project,
        SettingsLayer::ProjectLocal,
        SettingsLayer::Managed,
    ];

    /// Short name: `user`, `project`, `local`, `managed`.
    pub fn name(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Project => "project",
            Self::ProjectLocal => "local",
            Self::Managed => "managed",
        }
    }

    /// Parses `user`, `project`, `local` (`project-local`) or `managed`.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "user" | "global" => Some(Self::User),
            "project" => Some(Self::Project),
            "local" | "project-local" | "project_local" => Some(Self::ProjectLocal),
            "managed" => Some(Self::Managed),
            _ => None,
        }
    }

    /// Project layers come from the repository and load only when trusted.
    pub fn requires_trust(self) -> bool {
        matches!(self, Self::Project | Self::ProjectLocal)
    }

    /// The file of this layer for the project rooted at `root`.
    pub fn path(self, root: &Path) -> PathBuf {
        match self {
            Self::User => user_settings_path(),
            Self::Project => project_settings_path(root),
            Self::ProjectLocal => local_settings_path(root),
            Self::Managed => managed_settings_path(),
        }
    }
}

impl fmt::Display for SettingsLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// `~/.microclaw/code/settings.yaml` (honours `MICROCLAW_CODE_HOME`).
pub fn user_settings_path() -> PathBuf {
    crate::home::code_home().join(SETTINGS_FILE)
}

/// `<root>/.microclaw/settings.yaml`.
pub fn project_settings_path(root: &Path) -> PathBuf {
    root.join(crate::project::PROJECT_DIR).join(SETTINGS_FILE)
}

/// `<root>/.microclaw/settings.local.yaml`.
pub fn local_settings_path(root: &Path) -> PathBuf {
    root.join(crate::project::PROJECT_DIR)
        .join(LOCAL_SETTINGS_FILE)
}

/// The managed (administrator) settings file; `MICROCLAW_CODE_MANAGED`
/// overrides it.
pub fn managed_settings_path() -> PathBuf {
    if let Some(path) = std::env::var_os(MANAGED_ENV).filter(|v| !v.is_empty()) {
        return PathBuf::from(path);
    }
    default_managed_path()
}

#[cfg(target_os = "macos")]
fn default_managed_path() -> PathBuf {
    PathBuf::from("/Library/Application Support/MicroClaw/code/managed.yaml")
}

#[cfg(windows)]
fn default_managed_path() -> PathBuf {
    let base = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    base.join("MicroClaw").join("code").join("managed.yaml")
}

#[cfg(not(any(target_os = "macos", windows)))]
fn default_managed_path() -> PathBuf {
    PathBuf::from("/etc/microclaw/code/managed.yaml")
}

/// The four layer files; [`LayerPaths::discover`] for the real locations,
/// or built by hand in tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayerPaths {
    pub user: PathBuf,
    pub project: PathBuf,
    pub project_local: PathBuf,
    pub managed: PathBuf,
}

impl LayerPaths {
    pub fn discover(root: &Path) -> Self {
        Self {
            user: user_settings_path(),
            project: project_settings_path(root),
            project_local: local_settings_path(root),
            managed: managed_settings_path(),
        }
    }

    pub fn get(&self, layer: SettingsLayer) -> &Path {
        match layer {
            SettingsLayer::User => &self.user,
            SettingsLayer::Project => &self.project,
            SettingsLayer::ProjectLocal => &self.project_local,
            SettingsLayer::Managed => &self.managed,
        }
    }
}

// ---------------------------------------------------------------------------
// Loading and merging
// ---------------------------------------------------------------------------

/// The effective settings and where each part came from.
#[derive(Debug, Clone, Default)]
pub struct LoadedSettings {
    pub settings: CodeSettings,
    /// Every layer in merge order: its file and whether it was loaded.
    pub layers: Vec<(SettingsLayer, PathBuf, bool)>,
    /// Problems that did not stop loading (bad YAML, unknown keys, …).
    pub warnings: Vec<String>,
    /// Dotted key path → the last layer that set it (sections included,
    /// e.g. `tui`, `tui.theme`, `tui.keymap.chat.steer`).
    pub provenance: BTreeMap<String, SettingsLayer>,
    /// Concatenated list keys (`permissions.allow`, `hooks.stop`, …) → each
    /// item with the first layer that contributed it.
    pub list_items: BTreeMap<String, Vec<(Value, SettingsLayer)>>,
}

impl LoadedSettings {
    /// The last layer that set `key` (a dotted path such as `tui.theme`).
    pub fn source_of(&self, key: &str) -> Option<SettingsLayer> {
        self.provenance.get(key).copied()
    }

    /// The layer that contributed `item` to the list `key`, e.g.
    /// `item_source("permissions.deny", "bash(rm -rf *)")`.
    pub fn item_source(&self, key: &str, item: &str) -> Option<SettingsLayer> {
        self.list_items
            .get(key)?
            .iter()
            .find_map(|(value, layer)| (value.as_str() == Some(item)).then_some(*layer))
    }

    /// The file of `layer`.
    pub fn path_of(&self, layer: SettingsLayer) -> Option<&Path> {
        self.layers
            .iter()
            .find(|(l, _, _)| *l == layer)
            .map(|(_, path, _)| path.as_path())
    }

    /// Whether `layer` was loaded.
    pub fn is_loaded(&self, layer: SettingsLayer) -> bool {
        self.layers
            .iter()
            .any(|(l, _, loaded)| *l == layer && *loaded)
    }
}

/// Loads and merges every layer for the project rooted at `root`. The
/// project layers are read only when `trusted`. Never fails: unreadable
/// layers and invalid keys are skipped with a warning.
pub fn load(root: &Path, trusted: bool) -> LoadedSettings {
    load_from(&LayerPaths::discover(root), trusted)
}

/// [`load`] with explicit layer paths.
pub fn load_from(paths: &LayerPaths, trusted: bool) -> LoadedSettings {
    let mut out = LoadedSettings::default();
    let mut merged = Value::Mapping(Mapping::new());
    for layer in SettingsLayer::ALL {
        let path = paths.get(layer).to_path_buf();
        if layer.requires_trust() && !trusted {
            if path.exists() {
                out.warnings.push(format!(
                    "{layer} settings {} not loaded: the project is not trusted",
                    path.display()
                ));
            }
            out.layers.push((layer, path, false));
            continue;
        }
        let value = read_layer(layer, &path, &mut out.warnings);
        let loaded = value.is_some();
        if let Some(value) = value {
            record_provenance(&value, "", layer, &mut out);
            merge_value(&mut merged, value, "");
        }
        out.layers.push((layer, path, loaded));
    }
    match serde_yaml::from_value::<CodeSettings>(merged) {
        Ok(settings) => out.settings = settings,
        Err(err) => out.warnings.push(format!(
            "merged settings are invalid, using defaults: {err}"
        )),
    }
    out
}

/// Reads, migrates and sanitizes one layer; `None` when absent or unusable.
fn read_layer(layer: SettingsLayer, path: &Path, warnings: &mut Vec<String>) -> Option<Value> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return None,
        Err(err) => {
            warnings.push(format!(
                "{layer} settings {}: cannot read, layer skipped: {err}",
                path.display()
            ));
            return None;
        }
    };
    let label = format!("{layer} settings {}", path.display());
    let mut value = match parse_document(&text) {
        Ok(value) => value,
        Err(err) => {
            warnings.push(format!("{label}: {err}; layer skipped"));
            return None;
        }
    };
    if let Some(version) = document_version(&value)
        && version > SETTINGS_VERSION
    {
        warnings.push(format!(
            "{label}: newer settings format (version {version}, this mccode reads {SETTINGS_VERSION}), some keys may be ignored"
        ));
    }
    for note in migrate(&mut value) {
        warnings.push(format!("{label}: {note} (run `mccode config migrate`)"));
    }
    let (value, problems) = sanitize(value);
    for (key, err) in problems {
        warnings.push(format!("{label}: `{key}` ignored: {err}"));
    }
    Some(value)
}

/// Parses a settings document: empty → `{}`, nulls removed, top level must
/// be a mapping.
fn parse_document(text: &str) -> Result<Value, String> {
    let mut value: Value =
        serde_yaml::from_str(text).map_err(|err| format!("invalid YAML: {err}"))?;
    if value.is_null() {
        value = Value::Mapping(Mapping::new());
    }
    if !value.is_mapping() {
        return Err("expected a mapping at the top level".into());
    }
    prune_nulls(&mut value);
    Ok(value)
}

/// Removes `null` values (an empty `key:` means "not set").
fn prune_nulls(value: &mut Value) {
    match value {
        Value::Mapping(map) => {
            map.retain(|_, v| !v.is_null());
            for (_, v) in map.iter_mut() {
                prune_nulls(v);
            }
        }
        Value::Sequence(items) => {
            items.retain(|v| !v.is_null());
            items.iter_mut().for_each(prune_nulls);
        }
        Value::Tagged(tagged) => prune_nulls(&mut tagged.value),
        _ => {}
    }
}

/// Keys whose lists are concatenated across layers instead of replaced.
pub fn is_concatenated_key(path: &str) -> bool {
    matches!(
        path,
        "permissions.allow"
            | "permissions.ask"
            | "permissions.deny"
            | "permissions.disabled_modes"
            | "sandbox.allow_domains"
            | "sandbox.writable_roots"
            | "notify.events"
    ) || path
        .strip_prefix("hooks.")
        .is_some_and(|event| !event.is_empty() && !event.contains('.'))
}

fn key_text(key: &Value) -> String {
    match key {
        Value::String(s) => s.clone(),
        other => serde_yaml::to_string(other)
            .map(|s| s.trim().to_string())
            .unwrap_or_default(),
    }
}

fn join_key(prefix: &str, key: &str) -> String {
    if prefix.is_empty() {
        key.to_string()
    } else {
        format!("{prefix}.{key}")
    }
}

/// Deep merge: maps merge key by key, concatenated lists append (deduped),
/// everything else is replaced by the overlay.
fn merge_value(base: &mut Value, overlay: Value, path: &str) {
    match (base, overlay) {
        (Value::Mapping(base), Value::Mapping(overlay)) => {
            for (key, value) in overlay {
                let child = join_key(path, &key_text(&key));
                match base.get_mut(&key) {
                    Some(existing) => merge_value(existing, value, &child),
                    None => {
                        base.insert(key, value);
                    }
                }
            }
        }
        (Value::Sequence(base), Value::Sequence(overlay)) if is_concatenated_key(path) => {
            for item in overlay {
                if !base.contains(&item) {
                    base.push(item);
                }
            }
        }
        (base, overlay) => *base = overlay,
    }
}

fn record_provenance(value: &Value, path: &str, layer: SettingsLayer, out: &mut LoadedSettings) {
    if !path.is_empty() {
        out.provenance.insert(path.to_string(), layer);
    }
    match value {
        Value::Mapping(map) => {
            for (key, child) in map {
                record_provenance(child, &join_key(path, &key_text(key)), layer, out);
            }
        }
        Value::Sequence(items) if is_concatenated_key(path) => {
            let entry = out.list_items.entry(path.to_string()).or_default();
            for item in items {
                if !entry.iter().any(|(existing, _)| existing == item) {
                    entry.push((item.clone(), layer));
                }
            }
        }
        _ => {}
    }
}

/// Builds `{p0: {p1: … leaf}}`.
fn wrap(path: &[Value], leaf: Value) -> Value {
    path.iter().rev().fold(leaf, |inner, key| {
        let mut map = Mapping::new();
        map.insert(key.clone(), inner);
        Value::Mapping(map)
    })
}

fn dotted(path: &[Value]) -> String {
    path.iter().map(key_text).collect::<Vec<_>>().join(".")
}

fn schema_check(value: &Value) -> Result<(), String> {
    serde_yaml::from_value::<CodeSettings>(value.clone())
        .map(|_| ())
        .map_err(|err| err.to_string())
}

/// Splits a document into the part that matches the schema and the keys
/// that do not (`(dotted key, error)`), so one typo does not drop a layer.
fn sanitize(value: Value) -> (Value, Vec<(String, String)>) {
    let mut problems = Vec::new();
    let mut path = Vec::new();
    let kept = sanitize_at(&mut path, value, &mut problems)
        .unwrap_or_else(|| Value::Mapping(Mapping::new()));
    (kept, problems)
}

fn sanitize_at(
    path: &mut Vec<Value>,
    value: Value,
    problems: &mut Vec<(String, String)>,
) -> Option<Value> {
    let err = match schema_check(&wrap(path, value.clone())) {
        Ok(()) => return Some(value),
        Err(err) => err,
    };
    let fail = |problems: &mut Vec<(String, String)>, path: &[Value], err: String| {
        let key = if path.is_empty() {
            "(top level)".to_string()
        } else {
            dotted(path)
        };
        problems.push((key, err));
        None
    };
    match value {
        Value::Mapping(map) => {
            // An unknown key, or a key that is not a section, fails even empty.
            if let Err(err) = schema_check(&wrap(path, Value::Mapping(Mapping::new()))) {
                return fail(problems, path, err);
            }
            let mut kept = Mapping::new();
            for (key, child) in map {
                path.push(key.clone());
                if let Some(child) = sanitize_at(path, child, problems) {
                    kept.insert(key, child);
                }
                path.pop();
            }
            let kept = Value::Mapping(kept);
            match schema_check(&wrap(path, kept.clone())) {
                Ok(()) => Some(kept),
                Err(err) => fail(problems, path, err),
            }
        }
        Value::Sequence(items) => {
            if let Err(err) = schema_check(&wrap(path, Value::Sequence(Vec::new()))) {
                return fail(problems, path, err);
            }
            let mut kept = Vec::new();
            for (index, item) in items.into_iter().enumerate() {
                match schema_check(&wrap(path, Value::Sequence(vec![item.clone()]))) {
                    Ok(()) => kept.push(item),
                    Err(err) => {
                        problems.push((format!("{}[{index}]", dotted(path)), err));
                    }
                }
            }
            Some(Value::Sequence(kept))
        }
        _ => fail(problems, path, err),
    }
}

// ---------------------------------------------------------------------------
// Versions and migration
// ---------------------------------------------------------------------------

/// A step that rewrites a document of version `from` into `from + 1`,
/// returning human-readable notes about what changed.
type Migration = fn(&mut Value) -> Vec<String>;

/// Migrations by source version. Version 1 is current, so none yet; a v2
/// format adds `(1, migrate_v1_to_v2)` here.
const MIGRATIONS: &[(u32, Migration)] = &[];

/// The document's `version` (missing = 1); `None` when it is not a number.
fn document_version(value: &Value) -> Option<u32> {
    match value.get("version") {
        None => Some(1),
        Some(v) => v.as_u64().and_then(|v| u32::try_from(v).ok()),
    }
}

/// Upgrades a settings document in place to [`SETTINGS_VERSION`]; returns
/// one note per change (empty when already current, or when the document is
/// newer than this build understands).
pub fn migrate(value: &mut Value) -> Vec<String> {
    let mut notes = Vec::new();
    let Some(mut version) = document_version(value) else {
        return notes;
    };
    if version >= SETTINGS_VERSION {
        return notes;
    }
    while version < SETTINGS_VERSION {
        if let Some((_, step)) = MIGRATIONS.iter().find(|(from, _)| *from == version) {
            notes.extend(step(value));
        }
        version += 1;
    }
    if let Value::Mapping(map) = value {
        map.insert(Value::from("version"), Value::from(SETTINGS_VERSION));
    }
    notes.push(format!("upgraded to settings version {SETTINGS_VERSION}"));
    notes
}

/// `mccode config migrate`: upgrades one settings file in place. Writes an
/// explicit `version:` when missing. Returns the notes (empty when the file
/// is absent or already current).
pub fn migrate_file(path: &Path) -> anyhow::Result<Vec<String>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let (header, mut doc) = read_doc(path)?;
    if let Some(version) = document_version(&doc)
        && version > SETTINGS_VERSION
    {
        anyhow::bail!(
            "{} has settings version {version}, newer than this mccode ({SETTINGS_VERSION}); update mccode",
            path.display()
        );
    }
    let mut notes = migrate(&mut doc);
    if doc.get("version").is_none() {
        prepend_version(&mut doc);
        notes.push(format!("added `version: {SETTINGS_VERSION}`"));
    }
    if !notes.is_empty() {
        write_doc(path, header.as_deref(), &doc)?;
    }
    Ok(notes)
}

fn prepend_version(doc: &mut Value) {
    if let Value::Mapping(map) = doc {
        let mut out = Mapping::new();
        out.insert(Value::from("version"), Value::from(SETTINGS_VERSION));
        for (key, value) in std::mem::take(map) {
            if key.as_str() != Some("version") {
                out.insert(key, value);
            }
        }
        *map = out;
    }
}

// ---------------------------------------------------------------------------
// Doctor
// ---------------------------------------------------------------------------

/// How serious a [`Diagnostic`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Error,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
        })
    }
}

/// One `mccode config doctor` finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Diagnostic {
    pub layer: SettingsLayer,
    pub path: PathBuf,
    pub severity: Severity,
    pub message: String,
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} ({}): {}",
            self.severity,
            self.layer,
            self.path.display(),
            self.message
        )
    }
}

/// Permission rule kinds: `<kind>(<pattern>)`.
pub const RULE_KINDS: &[&str] = &["bash", "read", "edit", "net", "mcp", "agent", "tool"];
/// Valid `tui.status_line` items.
pub const STATUS_LINE_ITEMS: &[&str] = &[
    "mode", "model", "context", "tokens", "cost", "branch", "sandbox", "session", "checks",
];
/// Valid `notify.events`.
pub const NOTIFY_EVENTS: &[&str] = &["approval", "done", "check_failed", "error"];
/// Hook events that run around a tool call (the only ones `matcher` applies to).
pub const TOOL_HOOK_EVENTS: &[&str] = &[
    "pre_tool_use",
    "post_tool_use",
    "post_edit",
    "permission_request",
];

/// Syntax-only check of a permission rule: `<kind>(<pattern>)` with a known
/// kind and a non-empty pattern.
pub fn check_rule_syntax(rule: &str) -> Result<(), String> {
    let rule = rule.trim();
    let expected = format!(
        "expected `<kind>(<pattern>)` with kind one of {}",
        RULE_KINDS.join(", ")
    );
    let Some(open) = rule.find('(') else {
        return Err(expected);
    };
    if !rule.ends_with(')') {
        return Err("missing closing `)`".into());
    }
    let kind = rule[..open].trim();
    if !RULE_KINDS.contains(&kind) {
        let lower = kind.to_ascii_lowercase();
        if RULE_KINDS.contains(&lower.as_str()) {
            return Err(format!("rule kind `{kind}` must be lowercase `{lower}`"));
        }
        return Err(format!("unknown rule kind `{kind}`; {expected}"));
    }
    if rule[open + 1..rule.len() - 1].trim().is_empty() {
        return Err("empty pattern; use `*` to match everything".into());
    }
    Ok(())
}

/// Value-level checks of one layer document (rules, regexes, enumerations,
/// secrets). Schema errors are reported separately.
fn check_values(layer: SettingsLayer, doc: &Value) -> Vec<(Severity, String)> {
    let mut out = Vec::new();
    let strings = |value: Option<&Value>| -> Vec<String> {
        value
            .and_then(Value::as_sequence)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };

    if let Some(perms) = doc.get("permissions") {
        for list in ["allow", "ask", "deny"] {
            for rule in strings(perms.get(list)) {
                if let Err(err) = check_rule_syntax(&rule) {
                    out.push((
                        Severity::Error,
                        format!("permissions.{list}: `{rule}`: {err}"),
                    ));
                }
            }
        }
        if let Some(mode) = perms.get("default_mode").and_then(Value::as_str)
            && crate::project::Mode::parse(mode).is_none()
        {
            out.push((
                Severity::Error,
                format!("permissions.default_mode: unknown mode `{mode}` (plan, ask or auto)"),
            ));
        }
        let disabled = strings(perms.get("disabled_modes"));
        for mode in &disabled {
            if crate::project::Mode::parse(mode).is_none() {
                out.push((
                    Severity::Error,
                    format!("permissions.disabled_modes: unknown mode `{mode}`"),
                ));
            }
        }
        if !disabled.is_empty() && layer != SettingsLayer::Managed {
            out.push((
                Severity::Warning,
                "permissions.disabled_modes is only honoured in the managed layer".into(),
            ));
        }
    }

    if let Some(Value::Mapping(hooks)) = doc.get("hooks") {
        for (event, specs) in hooks {
            let event = key_text(event);
            let Some(specs) = specs.as_sequence() else {
                continue;
            };
            for (index, spec) in specs.iter().enumerate() {
                let at = format!("hooks.{event}[{index}]");
                if let Some(matcher) = spec.get("matcher").and_then(Value::as_str) {
                    if let Err(err) = regex::Regex::new(matcher) {
                        out.push((
                            Severity::Error,
                            format!("{at}.matcher: invalid regex `{matcher}`: {err}"),
                        ));
                    }
                    if !matcher.is_empty() && !TOOL_HOOK_EVENTS.contains(&event.as_str()) {
                        out.push((
                            Severity::Warning,
                            format!(
                                "{at}.matcher: `{event}` is not a tool event; matcher is ignored"
                            ),
                        ));
                    }
                }
                let command = spec.get("command").and_then(Value::as_str);
                let url = spec.get("url").and_then(Value::as_str);
                match (command, url) {
                    (None, None) => out.push((
                        Severity::Error,
                        format!("{at}: needs a `command` or a `url`"),
                    )),
                    (Some(_), Some(_)) => out.push((
                        Severity::Warning,
                        format!("{at}: both `command` and `url` set"),
                    )),
                    _ => {}
                }
                if let Some(url) = url
                    && !(url.starts_with("http://") || url.starts_with("https://"))
                {
                    out.push((
                        Severity::Error,
                        format!("{at}.url: `{url}` is not an http(s) URL"),
                    ));
                }
            }
        }
    }

    if let Some(tui) = doc.get("tui") {
        for item in strings(tui.get("status_line")) {
            if !STATUS_LINE_ITEMS.contains(&item.as_str()) {
                out.push((
                    Severity::Error,
                    format!(
                        "tui.status_line: unknown item `{item}` (one of {})",
                        STATUS_LINE_ITEMS.join(", ")
                    ),
                ));
            }
        }
        if let Some(notifications) = tui.get("notifications") {
            let checks: [(&str, &[&str]); 2] = [
                ("method", &["auto", "osc9", "osc777", "bell", "off"]),
                ("when", &["unfocused", "always"]),
            ];
            for (key, allowed) in checks {
                if let Some(value) = notifications.get(key).and_then(Value::as_str)
                    && !allowed.contains(&value)
                {
                    out.push((
                        Severity::Error,
                        format!(
                            "tui.notifications.{key}: unknown value `{value}` (one of {})",
                            allowed.join(", ")
                        ),
                    ));
                }
            }
        }
    }

    if let Some(backend) = doc
        .get("sandbox")
        .and_then(|s| s.get("backend"))
        .and_then(Value::as_str)
        && !matches!(backend, "local" | "off")
    {
        out.push((
            Severity::Error,
            format!("sandbox.backend: unknown backend `{backend}` (local or off)"),
        ));
    }

    if let Some(notify) = doc.get("notify") {
        for event in strings(notify.get("events")) {
            if !NOTIFY_EVENTS.contains(&event.as_str()) {
                out.push((
                    Severity::Error,
                    format!(
                        "notify.events: unknown event `{event}` (one of {})",
                        NOTIFY_EVENTS.join(", ")
                    ),
                ));
            }
        }
        if let Some(chat) = notify.get("chat").and_then(Value::as_str) {
            let valid = chat
                .split_once(':')
                .is_some_and(|(channel, id)| !channel.trim().is_empty() && !id.trim().is_empty());
            if !valid {
                out.push((
                    Severity::Error,
                    format!("notify.chat: `{chat}` is not `<channel>:<chat id>`"),
                ));
            }
        }
    }

    if layer == SettingsLayer::Project
        && let Some(Value::Mapping(profiles)) = doc.get("model").and_then(|m| m.get("profiles"))
    {
        for (name, profile) in profiles {
            if profile.get("api_key").is_some() {
                out.push((
                    Severity::Warning,
                    format!(
                        "model.profiles.{}.api_key: API key in a committed project file; use `api_key_env` or the user layer",
                        key_text(name)
                    ),
                ));
            }
        }
    }
    out
}

/// `mccode config doctor` for the project rooted at `root`.
pub fn doctor(root: &Path, trusted: bool) -> Vec<Diagnostic> {
    doctor_from(&LayerPaths::discover(root), root, trusted)
}

/// [`doctor`] with explicit layer paths. Legacy files are looked up next to
/// `paths.user` (`allow-rules.json`) and under `root` (`project.yaml`).
pub fn doctor_from(paths: &LayerPaths, root: &Path, trusted: bool) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    for layer in SettingsLayer::ALL {
        let path = paths.get(layer).to_path_buf();
        let mut push = |severity, message: String| {
            out.push(Diagnostic {
                layer,
                path: path.clone(),
                severity,
                message,
            })
        };
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => {
                push(Severity::Error, format!("cannot read: {err}"));
                continue;
            }
        };
        if layer.requires_trust() && !trusted {
            push(
                Severity::Info,
                "not loaded: the project is not trusted (run `mccode trust`)".into(),
            );
        }
        let mut doc = match parse_document(&text) {
            Ok(doc) => doc,
            Err(err) => {
                push(Severity::Error, format!("{err}; the whole file is ignored"));
                continue;
            }
        };
        match document_version(&doc) {
            Some(version) if version > SETTINGS_VERSION => push(
                Severity::Warning,
                format!(
                    "newer settings format (version {version}, this mccode reads {SETTINGS_VERSION}), some keys may be ignored"
                ),
            ),
            _ => {}
        }
        let notes = migrate(&mut doc);
        if !notes.is_empty() {
            push(
                Severity::Warning,
                format!(
                    "old settings format ({}); run `mccode config migrate`",
                    notes.join("; ")
                ),
            );
        }
        let (_, problems) = sanitize(doc.clone());
        for (key, err) in problems {
            push(Severity::Error, format!("`{key}` is ignored: {err}"));
        }
        for (severity, message) in check_values(layer, &doc) {
            push(severity, message);
        }
    }

    // Cross-layer: model references.
    let loaded = load_from(paths, trusted);
    let settings = &loaded.settings;
    let model_keys = std::iter::once(("model.default", settings.model.default.clone())).chain(
        ["plan", "review", "subagent", "summary"]
            .into_iter()
            .map(|role| (role_key(role), role_value(&settings.model.roles, role))),
    );
    for (key, value) in model_keys {
        let Some(value) = value else {
            continue;
        };
        if settings.model.profiles.is_empty() {
            continue;
        }
        if resolve_model(settings, Some(&value)).is_none() {
            let layer = loaded.source_of(key).unwrap_or(SettingsLayer::User);
            out.push(Diagnostic {
                layer,
                path: paths.get(layer).to_path_buf(),
                severity: Severity::Warning,
                message: format!(
                    "{key}: `{value}` does not name a profile (`<profile>/<model>` or `<profile>`) among {}",
                    settings.model.profiles.keys().cloned().collect::<Vec<_>>().join(", ")
                ),
            });
        }
    }
    for (name, profile) in &settings.model.profiles {
        if let Some(var) = &profile.api_key_env
            && std::env::var(var)
                .map(|v| v.trim().is_empty())
                .unwrap_or(true)
            && profile.api_key.is_none()
        {
            let key = format!("model.profiles.{name}.api_key_env");
            let layer = loaded.source_of(&key).unwrap_or(SettingsLayer::User);
            out.push(Diagnostic {
                layer,
                path: paths.get(layer).to_path_buf(),
                severity: Severity::Info,
                message: format!("{key}: environment variable `{var}` is not set"),
            });
        }
    }

    // Legacy files that are still honoured.
    let legacy_project = root
        .join(crate::project::PROJECT_DIR)
        .join(crate::project::PROJECT_FILE);
    if legacy_project.exists() {
        out.push(Diagnostic {
            layer: SettingsLayer::Project,
            path: legacy_project,
            severity: Severity::Warning,
            message: "legacy `.microclaw/project.yaml` is still honoured (mode, checks); new options belong in `.microclaw/settings.yaml`".into(),
        });
    }
    if let Some(home) = paths.user.parent() {
        let legacy_rules = home.join("allow-rules.json");
        if legacy_rules.exists() {
            out.push(Diagnostic {
                layer: SettingsLayer::User,
                path: legacy_rules,
                severity: Severity::Warning,
                message: "legacy `allow-rules.json` is still honoured; new rules belong in `permissions.allow`".into(),
            });
        }
    }
    out
}

fn role_key(role: &str) -> &'static str {
    match role {
        "plan" => "model.roles.plan",
        "review" => "model.roles.review",
        "subagent" => "model.roles.subagent",
        _ => "model.roles.summary",
    }
}

fn role_value(roles: &ModelRoles, role: &str) -> Option<String> {
    match role {
        "plan" => roles.plan.clone(),
        "review" => roles.review.clone(),
        "subagent" => roles.subagent.clone(),
        "summary" => roles.summary.clone(),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// get / set / unset
// ---------------------------------------------------------------------------

/// The effective value of a dotted key (`tui.theme`, `permissions.allow`,
/// `tui.keymap.chat.steer`); `None` when unset.
pub fn get(loaded: &LoadedSettings, key: &str) -> Option<Value> {
    let value = serde_yaml::to_value(&loaded.settings).ok()?;
    let key = key.trim();
    if key.is_empty() {
        return Some(value);
    }
    let segments: Vec<&str> = key.split('.').collect();
    lookup(&value, &segments).cloned()
}

/// Walks `segments`; map keys may themselves contain dots (`chat.steer`).
fn lookup<'a>(value: &'a Value, segments: &[&str]) -> Option<&'a Value> {
    if segments.is_empty() {
        return Some(value);
    }
    match value {
        Value::Mapping(map) => (1..=segments.len()).find_map(|n| {
            let key = segments[..n].join(".");
            map.get(key.as_str())
                .and_then(|child| lookup(child, &segments[n..]))
        }),
        Value::Sequence(items) => {
            let index: usize = segments[0].parse().ok()?;
            lookup(items.get(index)?, &segments[1..])
        }
        _ => None,
    }
}

/// Splits a dotted key for writing; everything after `tui.keymap.` is one
/// key (`tui.keymap.chat.steer` → `tui`, `keymap`, `chat.steer`).
fn split_key(key: &str) -> anyhow::Result<Vec<String>> {
    let key = key.trim();
    let mut parts: Vec<String> = key.split('.').map(str::to_string).collect();
    if parts.len() > 3 && parts[0] == "tui" && parts[1] == "keymap" {
        let action = parts[2..].join(".");
        parts.truncate(2);
        parts.push(action);
    }
    if key.is_empty() || parts.iter().any(|p| p.trim().is_empty()) {
        anyhow::bail!("invalid settings key `{key}`");
    }
    Ok(parts)
}

/// Parses a command-line value as YAML (`true`, `42`, `[a, b]`,
/// `{type: openai}`); anything that is not valid YAML is a string.
fn parse_cli_value(raw: &str) -> Value {
    match serde_yaml::from_str::<Value>(raw) {
        Ok(Value::Null) | Err(_) => Value::String(raw.to_string()),
        Ok(value) => value,
    }
}

/// Reads a settings file for editing: its schema comment line (if any) and
/// the document (`{}` when the file does not exist).
fn read_doc(path: &Path) -> anyhow::Result<(Option<String>, Value)> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok((None, Value::Mapping(Mapping::new())));
        }
        Err(err) => return Err(anyhow::anyhow!("cannot read {}: {err}", path.display())),
    };
    let header = text
        .lines()
        .next()
        .filter(|line| line.trim_start().starts_with(SCHEMA_COMMENT_PREFIX))
        .map(|line| line.trim_end().to_string());
    let doc = parse_document(&text).map_err(|err| anyhow::anyhow!("{}: {err}", path.display()))?;
    Ok((header, doc))
}

/// Writes a settings document, keeping (or adding) the schema comment line.
fn write_doc(path: &Path, header: Option<&str>, doc: &Value) -> anyhow::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let body = serde_yaml::to_string(doc)?;
    let text = format!("{}\n{body}", header.unwrap_or(SCHEMA_COMMENT));
    let tmp = path.with_extension("yaml.tmp");
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Strict check of a document before it is written: schema plus
/// value-level errors (warnings do not block).
fn validate_doc(layer: SettingsLayer, doc: &Value) -> Result<(), String> {
    let mut doc = doc.clone();
    prune_nulls(&mut doc);
    schema_check(&doc)?;
    let errors: Vec<String> = check_values(layer, &doc)
        .into_iter()
        .filter(|(severity, _)| *severity == Severity::Error)
        .map(|(_, message)| message)
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

/// The layer a file belongs to, guessed from its name (for layer-specific
/// checks while editing).
fn layer_of_file(path: &Path) -> SettingsLayer {
    match path.file_name().and_then(|n| n.to_str()) {
        Some(LOCAL_SETTINGS_FILE) => SettingsLayer::ProjectLocal,
        Some("managed.yaml") => SettingsLayer::Managed,
        _ if path
            .parent()
            .and_then(|p| p.file_name())
            .is_some_and(|n| n == crate::project::PROJECT_DIR) =>
        {
            SettingsLayer::Project
        }
        _ => SettingsLayer::User,
    }
}

fn set_path(doc: &mut Value, parts: &[String], value: Value) -> anyhow::Result<()> {
    let (last, parents) = parts.split_last().expect("split_key never returns empty");
    let mut node = doc;
    for (depth, part) in parents.iter().enumerate() {
        let Value::Mapping(map) = node else {
            anyhow::bail!("`{}` is not a section", parts[..depth].join("."));
        };
        node = map
            .entry(Value::from(part.as_str()))
            .or_insert_with(|| Value::Mapping(Mapping::new()));
    }
    let Value::Mapping(map) = node else {
        anyhow::bail!("`{}` is not a section", parents.join("."));
    };
    map.insert(Value::from(last.as_str()), value);
    Ok(())
}

/// `mccode config set <key> <value>`: sets a dotted key in one settings
/// file (created with its parent directories when missing). `value_str` is
/// parsed as YAML (`true`, `[a, b]`, …). The result is validated first;
/// an invalid result is refused and the file is left untouched. Comments
/// other than the schema line are not preserved.
pub fn set_in_file(path: &Path, key: &str, value_str: &str) -> anyhow::Result<()> {
    let parts = split_key(key)?;
    let (header, mut doc) = read_doc(path)?;
    if !path.exists() {
        prepend_version(&mut doc);
    }
    let layer = layer_of_file(path);
    let parsed = parse_cli_value(value_str);
    let mut candidate = doc.clone();
    set_path(&mut candidate, &parts, parsed.clone())?;
    let mut result = validate_doc(layer, &candidate);
    if result.is_err() && !parsed.is_string() {
        // `notify.chat: 12345` and friends: retry as a plain string.
        let mut as_string = doc.clone();
        set_path(&mut as_string, &parts, Value::String(value_str.to_string()))?;
        if validate_doc(layer, &as_string).is_ok() {
            candidate = as_string;
            result = Ok(());
        }
    }
    if let Err(err) = result {
        anyhow::bail!("refusing to set `{key}` in {}: {err}", path.display());
    }
    write_doc(path, header.as_deref(), &candidate)
}

/// Appends one item to a list key (e.g. an `always allow` rule into
/// `permissions.allow`); `Ok(false)` when it is already there.
pub fn append_in_file(path: &Path, key: &str, item_str: &str) -> anyhow::Result<bool> {
    let parts = split_key(key)?;
    let (header, mut doc) = read_doc(path)?;
    if !path.exists() {
        prepend_version(&mut doc);
    }
    let item = match parse_cli_value(item_str) {
        Value::Sequence(_) => Value::String(item_str.to_string()),
        other => other,
    };
    let segments: Vec<&str> = parts.iter().map(String::as_str).collect();
    let mut items = match lookup(&doc, &segments) {
        Some(Value::Sequence(items)) => items.clone(),
        Some(_) => anyhow::bail!("`{key}` is not a list"),
        None => Vec::new(),
    };
    if items.contains(&item) {
        return Ok(false);
    }
    items.push(item);
    set_path(&mut doc, &parts, Value::Sequence(items))?;
    if let Err(err) = validate_doc(layer_of_file(path), &doc) {
        anyhow::bail!("refusing to add to `{key}` in {}: {err}", path.display());
    }
    write_doc(path, header.as_deref(), &doc)?;
    Ok(true)
}

/// `mccode config unset <key>`: removes a dotted key (and sections left
/// empty). `Ok(false)` when the key was not set.
pub fn unset_in_file(path: &Path, key: &str) -> anyhow::Result<bool> {
    let parts = split_key(key)?;
    if !path.exists() {
        return Ok(false);
    }
    let (header, mut doc) = read_doc(path)?;
    if !remove_path(&mut doc, &parts) {
        return Ok(false);
    }
    if let Err(err) = validate_doc(layer_of_file(path), &doc) {
        anyhow::bail!("refusing to unset `{key}` in {}: {err}", path.display());
    }
    write_doc(path, header.as_deref(), &doc)?;
    Ok(true)
}

fn remove_path(node: &mut Value, parts: &[String]) -> bool {
    let Value::Mapping(map) = node else {
        return false;
    };
    let Some((first, rest)) = parts.split_first() else {
        return false;
    };
    if rest.is_empty() {
        return map.remove(first.as_str()).is_some();
    }
    let Some(child) = map.get_mut(first.as_str()) else {
        return false;
    };
    let removed = remove_path(child, rest);
    if removed && child.as_mapping().is_some_and(Mapping::is_empty) {
        map.remove(first.as_str());
    }
    removed
}

// ---------------------------------------------------------------------------
// JSON Schema
// ---------------------------------------------------------------------------

/// The JSON Schema of the settings file (published at [`SCHEMA_ID`], checked
/// in as `docs/schema/code-settings.v1.json`).
pub fn json_schema() -> String {
    let mut schema = schemars::schema_for!(CodeSettings);
    schema.insert("$id".into(), serde_json::Value::from(SCHEMA_ID));
    let mut text = serde_json::to_string_pretty(&schema).expect("schema serializes");
    text.push('\n');
    text
}

// ---------------------------------------------------------------------------
// Model profiles
// ---------------------------------------------------------------------------

/// A model chosen through a settings profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedModel {
    /// Provider kind (the profile's `type`, else the profile name).
    pub provider: String,
    pub model: String,
    /// From `api_key_env`, else `api_key`; empty when neither is set.
    pub api_key: String,
    pub base_url: Option<String>,
    /// Profile name.
    pub profile: String,
}

/// Resolves `requested` (or `model.default`) against `model.profiles`:
/// `<profile>/<model>`, `<profile>` (its `model`), or a bare model name when
/// exactly one profile exists. `None` when nothing matches.
pub fn resolve_model(settings: &CodeSettings, requested: Option<&str>) -> Option<ResolvedModel> {
    let profiles = &settings.model.profiles;
    let only = || {
        (profiles.len() == 1)
            .then(|| profiles.iter().next())
            .flatten()
    };
    let spec = requested
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| settings.model.default.clone());
    let (name, profile, model) = match spec.as_deref() {
        Some(spec) => {
            if let Some((name, model)) = spec.split_once('/')
                && let Some(profile) = profiles.get(name)
                && !model.trim().is_empty()
            {
                (name, profile, model.trim().to_string())
            } else if let Some((name, profile)) = profiles.get_key_value(spec) {
                (name.as_str(), profile, profile.model.clone()?)
            } else {
                let (name, profile) = only()?;
                (name.as_str(), profile, spec.to_string())
            }
        }
        None => {
            let (name, profile) = only()?;
            (name.as_str(), profile, profile.model.clone()?)
        }
    };
    let api_key = profile
        .api_key_env
        .as_deref()
        .and_then(|var| std::env::var(var).ok())
        .filter(|key| !key.trim().is_empty())
        .or_else(|| profile.api_key.clone())
        .unwrap_or_default();
    let provider = if profile.kind.trim().is_empty() {
        name.to_string()
    } else {
        profile.kind.trim().to_string()
    };
    Some(ResolvedModel {
        provider,
        model,
        api_key,
        base_url: profile.base_url.clone(),
        profile: name.to_string(),
    })
}

/// The model spec for a role (`plan`, `review`, `subagent`, `summary`),
/// falling back to `model.default`.
pub fn role_model(settings: &CodeSettings, role: &str) -> Option<String> {
    role_value(&settings.model.roles, role).or_else(|| settings.model.default.clone())
}

/// [`role_model`] resolved through the profiles.
pub fn resolve_role(settings: &CodeSettings, role: &str) -> Option<ResolvedModel> {
    resolve_model(settings, role_model(settings, role).as_deref())
}

// ---------------------------------------------------------------------------
// Template
// ---------------------------------------------------------------------------

/// A commented example `settings.yaml` (`mccode config init`).
pub fn template() -> &'static str {
    TEMPLATE
}

const TEMPLATE: &str = r#"# yaml-language-server: $schema=https://microclaw.ai/schema/code-settings.v1.json
# MicroClaw Code settings. The same format is read from four layers, merged
# in this order (later wins for single values; lists are concatenated):
#   ~/.microclaw/code/settings.yaml          user
#   <repo>/.microclaw/settings.yaml          project (trusted projects only)
#   <repo>/.microclaw/settings.local.yaml    project-local, not committed
#   managed.yaml                             administrator, always wins
# Check with `mccode config doctor`; edit with `mccode config set <key> <value>`.
version: 1

model:
  # `<profile>/<model>`, `<profile>` (uses the profile's model) or a bare
  # model name when there is exactly one profile.
  default: deepseek/deepseek-v4-pro
  roles:
    plan: deepseek/deepseek-v4-pro
    review: deepseek/deepseek-v4-pro
    subagent: deepseek/deepseek-flash
    # summary: deepseek/deepseek-flash
  profiles:
    deepseek:
      type: openai                 # any OpenAI-compatible API
      base_url: https://api.deepseek.com/v1
      api_key_env: DEEPSEEK_API_KEY
    # anthropic:
    #   type: anthropic
    #   api_key_env: ANTHROPIC_API_KEY
    #   model: claude-sonnet-4-6
    # ollama:
    #   type: ollama
    #   base_url: http://127.0.0.1:11434/v1
    #   model: qwen3.6

permissions:
  default_mode: ask                # plan | ask | auto
  # Rules are `<kind>(<pattern>)`, kind: bash, read, edit, net, mcp, agent,
  # tool. deny wins over ask, ask over allow.
  allow:
    - bash(cargo test *)
    - bash(git status)
    - edit(src/**)
  ask:
    - bash(git push *)
    - net(*)
  deny:
    - read(**/.env)
    - bash(rm -rf /*)

sandbox:
  backend: local                   # local | off
  network: ask                     # off | ask | on
  allow_domains: [crates.io, static.crates.io, github.com]
  # writable_roots: [/tmp/build-cache]

hooks:
  # Claude Code hook protocol: the event as JSON on stdin, exit code 2
  # blocks, JSON on stdout may carry a decision.
  pre_tool_use:
    - matcher: "bash"
      command: ./scripts/guard.sh
  post_edit:
    - command: cargo fmt -- {file}
  # stop:
  #   - command: ./scripts/notify.sh

tui:
  theme: auto
  screen: auto                     # auto | fullscreen | inline
  sidebar: auto                    # auto | show | hide
  diff: auto                       # auto | split | unified
  animations: true
  mouse: true
  status_line: [mode, model, context, cost, branch, sandbox]
  notifications: { method: auto, when: unfocused }
  keymap:
    chat.steer: ctrl+s

# Push approvals and results to a chat through a paired MicroClaw Server
# (`mccode remote pair`).
# notify:
#   chat: telegram:123456789
#   events: [approval, done, check_failed]
#   after_idle_secs: 60
"#;

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        _dir: tempfile::TempDir,
        root: PathBuf,
        paths: LayerPaths,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("repo");
        let home = dir.path().join("home");
        std::fs::create_dir_all(root.join(".microclaw")).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        let paths = LayerPaths {
            user: home.join(SETTINGS_FILE),
            project: project_settings_path(&root),
            project_local: local_settings_path(&root),
            managed: dir.path().join("managed.yaml"),
        };
        Fixture {
            _dir: dir,
            root,
            paths,
        }
    }

    impl Fixture {
        fn write(&self, layer: SettingsLayer, text: &str) {
            std::fs::write(self.paths.get(layer), text).unwrap();
        }
    }

    #[test]
    fn layers_merge_in_order_and_record_provenance() {
        let f = fixture();
        f.write(
            SettingsLayer::User,
            "tui: {theme: dark, mouse: false}\nmodel: {default: a/x}\n",
        );
        f.write(SettingsLayer::Project, "tui: {theme: light}\n");
        f.write(SettingsLayer::ProjectLocal, "tui: {animations: false}\n");
        let loaded = load_from(&f.paths, true);
        assert!(loaded.warnings.is_empty(), "{:?}", loaded.warnings);
        let tui = &loaded.settings.tui;
        assert_eq!(tui.theme.as_deref(), Some("light"));
        assert_eq!(tui.mouse, Some(false));
        assert_eq!(tui.animations, Some(false));
        assert_eq!(loaded.settings.model.default.as_deref(), Some("a/x"));
        assert_eq!(loaded.source_of("tui.theme"), Some(SettingsLayer::Project));
        assert_eq!(loaded.source_of("tui.mouse"), Some(SettingsLayer::User));
        assert_eq!(
            loaded.source_of("tui.animations"),
            Some(SettingsLayer::ProjectLocal)
        );
        assert_eq!(loaded.source_of("tui"), Some(SettingsLayer::ProjectLocal));
        assert_eq!(loaded.source_of("tui.diff"), None);
        assert!(
            loaded
                .layers
                .iter()
                .all(|(layer, _, loaded)| { *loaded == (*layer != SettingsLayer::Managed) })
        );
    }

    #[test]
    fn lists_concatenate_with_dedupe_and_item_sources() {
        let f = fixture();
        f.write(
            SettingsLayer::User,
            "permissions: {allow: ['bash(ls)'], deny: ['read(**/.env)']}\nhooks: {stop: [{command: a}]}\nsandbox: {allow_domains: [crates.io]}\n",
        );
        f.write(
            SettingsLayer::Project,
            "permissions: {allow: ['bash(ls)', 'bash(cargo test *)']}\nhooks: {stop: [{command: b}]}\nsandbox: {allow_domains: [github.com]}\n",
        );
        let loaded = load_from(&f.paths, true);
        let perms = &loaded.settings.permissions;
        assert_eq!(perms.allow, vec!["bash(ls)", "bash(cargo test *)"]);
        assert_eq!(perms.deny, vec!["read(**/.env)"]);
        let stops: Vec<_> = loaded
            .settings
            .hooks
            .stop
            .iter()
            .map(|h| h.command.clone().unwrap())
            .collect();
        assert_eq!(stops, vec!["a", "b"]);
        assert_eq!(
            loaded.settings.sandbox.allow_domains,
            vec!["crates.io", "github.com"]
        );
        assert_eq!(
            loaded.item_source("permissions.allow", "bash(ls)"),
            Some(SettingsLayer::User)
        );
        assert_eq!(
            loaded.item_source("permissions.allow", "bash(cargo test *)"),
            Some(SettingsLayer::Project)
        );
    }

    #[test]
    fn managed_scalars_win_and_its_rules_are_added() {
        let f = fixture();
        f.write(
            SettingsLayer::User,
            "permissions: {default_mode: auto, deny: ['bash(a *)']}\n",
        );
        f.write(
            SettingsLayer::ProjectLocal,
            "permissions: {default_mode: auto}\n",
        );
        f.write(
            SettingsLayer::Managed,
            "permissions: {default_mode: ask, deny: ['bash(curl *)'], disabled_modes: [auto]}\n",
        );
        let loaded = load_from(&f.paths, true);
        let perms = &loaded.settings.permissions;
        assert_eq!(perms.default_mode.as_deref(), Some("ask"));
        assert_eq!(perms.deny, vec!["bash(a *)", "bash(curl *)"]);
        assert_eq!(perms.disabled_modes, vec!["auto"]);
        assert_eq!(
            loaded.source_of("permissions.default_mode"),
            Some(SettingsLayer::Managed)
        );
    }

    #[test]
    fn project_layers_need_trust() {
        let f = fixture();
        f.write(SettingsLayer::User, "tui: {theme: dark}\n");
        f.write(SettingsLayer::Project, "tui: {theme: light}\n");
        f.write(
            SettingsLayer::ProjectLocal,
            "permissions: {allow: ['bash(*)']}\n",
        );
        let loaded = load_from(&f.paths, false);
        assert_eq!(loaded.settings.tui.theme.as_deref(), Some("dark"));
        assert!(loaded.settings.permissions.allow.is_empty());
        assert!(!loaded.is_loaded(SettingsLayer::Project));
        assert!(!loaded.is_loaded(SettingsLayer::ProjectLocal));
        assert_eq!(loaded.warnings.len(), 2, "{:?}", loaded.warnings);
        assert!(loaded.warnings[0].contains("not trusted"));
    }

    #[test]
    fn bad_layer_is_skipped_with_warning() {
        let f = fixture();
        f.write(SettingsLayer::User, "tui: {theme: dark}\n");
        f.write(SettingsLayer::Project, "tui: [unclosed\n");
        let loaded = load_from(&f.paths, true);
        assert_eq!(loaded.settings.tui.theme.as_deref(), Some("dark"));
        assert!(!loaded.is_loaded(SettingsLayer::Project));
        assert_eq!(loaded.warnings.len(), 1);
        assert!(
            loaded.warnings[0].contains("invalid YAML"),
            "{:?}",
            loaded.warnings
        );
    }

    #[test]
    fn unknown_keys_and_bad_values_drop_only_themselves() {
        let f = fixture();
        f.write(
            SettingsLayer::User,
            "tui: {thme: dark, mouse: false, diff: sideways}\nbogus: 1\npermissions: {allow: ['bash(ls)', 42, {x: 1}]}\n",
        );
        let loaded = load_from(&f.paths, true);
        assert_eq!(loaded.settings.tui.mouse, Some(false));
        assert_eq!(loaded.settings.tui.diff, None);
        assert_eq!(loaded.settings.permissions.allow, vec!["bash(ls)"]);
        let all = loaded.warnings.join("\n");
        assert!(all.contains("`permissions.allow[1]`"), "{all}");
        assert!(all.contains("`tui.thme`"), "{all}");
        assert!(all.contains("`tui.diff`"), "{all}");
        assert!(all.contains("`bogus`"), "{all}");
        assert!(all.contains("`permissions.allow[2]`"), "{all}");
    }

    #[test]
    fn newer_version_warns_and_migrate_is_a_noop_for_v1() {
        let f = fixture();
        f.write(SettingsLayer::User, "version: 9\ntui: {theme: dark}\n");
        let loaded = load_from(&f.paths, true);
        assert_eq!(loaded.settings.tui.theme.as_deref(), Some("dark"));
        assert!(loaded.warnings[0].contains("newer settings format"));

        let mut doc: Value = serde_yaml::from_str("tui: {theme: dark}").unwrap();
        assert!(migrate(&mut doc).is_empty());
        let mut old: Value = serde_yaml::from_str("version: 0").unwrap();
        assert!(!migrate(&mut old).is_empty());
        assert_eq!(old.get("version").and_then(Value::as_u64), Some(1));

        let path = &f.paths.project;
        std::fs::write(path, "tui: {theme: dark}\n").unwrap();
        let notes = migrate_file(path).unwrap();
        assert_eq!(notes.len(), 1);
        let text = std::fs::read_to_string(path).unwrap();
        assert!(text.contains("version: 1"), "{text}");
        assert!(migrate_file(path).unwrap().is_empty());
    }

    #[test]
    fn set_get_unset_round_trip() {
        let f = fixture();
        let path = f.paths.project_local.clone();
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
        set_in_file(&path, "tui.theme", "light").unwrap();
        set_in_file(&path, "tui.mouse", "false").unwrap();
        set_in_file(&path, "tui.keymap.chat.steer", "ctrl+s").unwrap();
        set_in_file(&path, "permissions.allow", "['bash(ls)']").unwrap();
        set_in_file(&path, "notify.chat", "telegram:42").unwrap();
        set_in_file(&path, "sandbox.network", "off").unwrap();
        assert!(append_in_file(&path, "permissions.allow", "bash(cargo test *)").unwrap());
        assert!(!append_in_file(&path, "permissions.allow", "bash(ls)").unwrap());

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with(SCHEMA_COMMENT), "{text}");
        assert!(text.contains("version: 1"), "{text}");

        let loaded = load_from(&f.paths, true);
        assert_eq!(get(&loaded, "tui.theme"), Some(Value::from("light")));
        assert_eq!(get(&loaded, "tui.mouse"), Some(Value::from(false)));
        assert_eq!(
            get(&loaded, "tui.keymap.chat.steer"),
            Some(Value::from("ctrl+s"))
        );
        assert_eq!(
            get(&loaded, "notify.chat"),
            Some(Value::from("telegram:42"))
        );
        assert_eq!(
            loaded.settings.permissions.allow,
            vec!["bash(ls)", "bash(cargo test *)"]
        );
        assert_eq!(loaded.settings.sandbox.network, Some(NetworkMode::Off));
        assert_eq!(
            get(&loaded, "permissions.allow.1"),
            Some(Value::from("bash(cargo test *)"))
        );
        assert_eq!(get(&loaded, "tui.diff"), None);

        // Invalid values are refused and the file is untouched.
        let before = std::fs::read_to_string(&path).unwrap();
        assert!(set_in_file(&path, "tui.thme", "dark").is_err());
        assert!(set_in_file(&path, "tui.diff", "sideways").is_err());
        assert!(set_in_file(&path, "permissions.deny", "['rm -rf']").is_err());
        assert!(set_in_file(&path, "tui.status_line", "[mode, weather]").is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);

        assert!(unset_in_file(&path, "tui.keymap.chat.steer").unwrap());
        assert!(!unset_in_file(&path, "tui.keymap.chat.steer").unwrap());
        assert!(unset_in_file(&path, "notify.chat").unwrap());
        let loaded = load_from(&f.paths, true);
        assert!(loaded.settings.tui.keymap.is_empty());
        assert!(loaded.settings.notify.is_empty());
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("notify"), "{text}");
    }

    #[test]
    fn set_keeps_existing_schema_comment() {
        let f = fixture();
        let path = f.paths.user.clone();
        std::fs::write(
            &path,
            "# yaml-language-server: $schema=./custom.json\n# my notes\ntui:\n  theme: dark\n",
        )
        .unwrap();
        set_in_file(&path, "tui.mouse", "true").unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("# yaml-language-server: $schema=./custom.json\n"));
        assert!(text.contains("theme: dark"));
    }

    fn messages(diags: &[Diagnostic], severity: Severity) -> String {
        diags
            .iter()
            .filter(|d| d.severity == severity)
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn doctor_reports_unknown_keys_bad_rules_and_secrets() {
        let f = fixture();
        f.write(
            SettingsLayer::User,
            "tui: {thme: dark, status_line: [mode, weather]}\npermissions: {default_mode: yolo-ish, allow: ['Bash(ls)', 'shell(ls)', 'bash()'], disabled_modes: [auto]}\nhooks:\n  pre_tool_use: [{matcher: '(', command: x}]\n  stop: [{matcher: Bash, command: y}, {timeout: 3}]\n",
        );
        f.write(
            SettingsLayer::Project,
            "model: {profiles: {p: {type: openai, api_key: sk-123}}}\n",
        );
        std::fs::write(
            f.root.join(".microclaw").join("project.yaml"),
            "mode: ask\n",
        )
        .unwrap();
        let diags = doctor_from(&f.paths, &f.root, true);
        let errors = messages(&diags, Severity::Error);
        let warnings = messages(&diags, Severity::Warning);
        assert!(
            errors.contains("`tui.thme`") && errors.contains("unknown field"),
            "{errors}"
        );
        assert!(errors.contains("unknown item `weather`"), "{errors}");
        assert!(errors.contains("unknown mode `yolo-ish`"), "{errors}");
        assert!(errors.contains("must be lowercase `bash`"), "{errors}");
        assert!(errors.contains("unknown rule kind `shell`"), "{errors}");
        assert!(errors.contains("empty pattern"), "{errors}");
        assert!(errors.contains("invalid regex"), "{errors}");
        assert!(
            errors.contains("hooks.stop[1]: needs a `command` or a `url`"),
            "{errors}"
        );
        assert!(warnings.contains("not a tool event"), "{warnings}");
        assert!(
            warnings.contains("only honoured in the managed layer"),
            "{warnings}"
        );
        assert!(warnings.contains("api_key"), "{warnings}");
        assert!(warnings.contains("project.yaml"), "{warnings}");
        assert!(diags.iter().any(|d| d.layer == SettingsLayer::Project
            && d.path == f.paths.project
            && d.message.contains("api_key")));
    }

    #[test]
    fn doctor_is_quiet_for_the_template() {
        let f = fixture();
        f.write(SettingsLayer::User, template());
        let diags = doctor_from(&f.paths, &f.root, true);
        let problems: Vec<_> = diags
            .iter()
            .filter(|d| d.severity != Severity::Info)
            .collect();
        assert!(problems.is_empty(), "{problems:?}");
        let loaded = load_from(&f.paths, true);
        assert!(loaded.warnings.is_empty(), "{:?}", loaded.warnings);
        assert_eq!(
            loaded.settings.model.default.as_deref(),
            Some("deepseek/deepseek-v4-pro")
        );
        assert_eq!(
            loaded
                .settings
                .tui
                .keymap
                .get("chat.steer")
                .map(String::as_str),
            Some("ctrl+s")
        );
    }

    fn profile(kind: &str, model: Option<&str>) -> ProviderProfile {
        ProviderProfile {
            kind: kind.into(),
            base_url: Some(format!("https://{kind}.example")),
            api_key_env: None,
            api_key: Some(format!("key-{kind}")),
            model: model.map(str::to_string),
        }
    }

    #[test]
    fn resolve_model_cases() {
        let mut settings = CodeSettings::default();
        assert_eq!(resolve_model(&settings, Some("x")), None);

        settings
            .model
            .profiles
            .insert("ds".into(), profile("openai", Some("deepseek-v4-pro")));
        // Bare model with exactly one profile; no request → profile model.
        let r = resolve_model(&settings, Some("deepseek-flash")).unwrap();
        assert_eq!(
            (r.profile.as_str(), r.model.as_str()),
            ("ds", "deepseek-flash")
        );
        assert_eq!(r.provider, "openai");
        assert_eq!(r.api_key, "key-openai");
        assert_eq!(r.base_url.as_deref(), Some("https://openai.example"));
        let r = resolve_model(&settings, None).unwrap();
        assert_eq!(r.model, "deepseek-v4-pro");

        settings
            .model
            .profiles
            .insert("claude".into(), profile("anthropic", None));
        settings.model.default = Some("claude/claude-sonnet-4-6".into());
        let r = resolve_model(&settings, None).unwrap();
        assert_eq!(
            (r.provider.as_str(), r.model.as_str()),
            ("anthropic", "claude-sonnet-4-6")
        );
        // `<profile>` uses the profile's model; none set → None.
        assert_eq!(
            resolve_model(&settings, Some("ds")).unwrap().model,
            "deepseek-v4-pro"
        );
        assert_eq!(resolve_model(&settings, Some("claude")), None);
        // Bare model with two profiles is ambiguous; a slash in the model
        // name is fine when the prefix is not a profile.
        assert_eq!(resolve_model(&settings, Some("gpt-5")), None);
        assert_eq!(
            resolve_model(&settings, Some("ds/deepseek-ai/DeepSeek-V3.2"))
                .unwrap()
                .model,
            "deepseek-ai/DeepSeek-V3.2"
        );

        // api_key_env wins over api_key when the variable is set.
        let p = settings.model.profiles.get_mut("ds").unwrap();
        p.api_key_env = Some("PATH".into());
        let path = std::env::var("PATH").unwrap();
        assert_eq!(resolve_model(&settings, Some("ds")).unwrap().api_key, path);
        let p = settings.model.profiles.get_mut("ds").unwrap();
        p.api_key_env = Some("MICROCLAW_TEST_SURELY_UNSET_KEY_VAR".into());
        assert_eq!(
            resolve_model(&settings, Some("ds")).unwrap().api_key,
            "key-openai"
        );

        settings.model.roles.review = Some("ds".into());
        assert_eq!(role_model(&settings, "review").as_deref(), Some("ds"));
        assert_eq!(
            role_model(&settings, "plan").as_deref(),
            Some("claude/claude-sonnet-4-6")
        );
        assert_eq!(resolve_role(&settings, "review").unwrap().profile, "ds");
    }

    #[test]
    fn rule_syntax() {
        assert!(check_rule_syntax("bash(cargo test *)").is_ok());
        assert!(check_rule_syntax("mcp(github.delete_*)").is_ok());
        assert!(check_rule_syntax("bash(echo \"(x)\")").is_ok());
        assert!(check_rule_syntax("bash").is_err());
        assert!(check_rule_syntax("bash(ls").is_err());
        assert!(check_rule_syntax("web(x)").is_err());
    }

    #[test]
    fn layer_names_and_paths() {
        for layer in SettingsLayer::ALL {
            assert_eq!(SettingsLayer::parse(layer.name()), Some(layer));
        }
        let root = Path::new("/repo");
        assert_eq!(
            SettingsLayer::Project.path(root),
            PathBuf::from("/repo/.microclaw/settings.yaml")
        );
        assert_eq!(
            SettingsLayer::ProjectLocal.path(root),
            PathBuf::from("/repo/.microclaw/settings.local.yaml")
        );
        assert!(is_concatenated_key("hooks.pre_tool_use"));
        assert!(!is_concatenated_key("tui.status_line"));
    }

    #[test]
    fn checked_in_schema_is_current() {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/schema/code-settings.v1.json");
        let schema = json_schema();
        assert!(schema.contains(SCHEMA_ID));
        if std::env::var_os("UPDATE_SCHEMA").is_some() {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, &schema).unwrap();
        }
        let checked_in = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(
            checked_in == schema,
            "docs/schema/code-settings.v1.json is out of date; regenerate it with \
             `UPDATE_SCHEMA=1 cargo test -p microclaw-code-core settings::tests::checked_in_schema_is_current`"
        );
    }
}
