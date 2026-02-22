use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use microclaw_core::llm_types::ToolDefinition;
use microclaw_tools::sandbox::{SandboxExecOptions, SandboxExecResult, SandboxMode, SandboxRouter};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::warn;

use crate::config::{Config, WorkingDirIsolation};
use crate::tools::{auth_context_from_input, schema_object, Tool, ToolResult};

fn default_plugin_enabled() -> bool {
    true
}

fn default_plugin_tool_schema() -> serde_json::Value {
    schema_object(json!({}), &[])
}

fn default_plugin_timeout_secs() -> u64 {
    30
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PluginExecutionPolicy {
    HostOnly,
    SandboxOnly,
    Dual,
}

impl PluginExecutionPolicy {
    fn is_allowed(self, sandbox_mode: SandboxMode, sandbox_runtime_available: bool) -> bool {
        match self {
            PluginExecutionPolicy::HostOnly => true,
            PluginExecutionPolicy::Dual => true,
            PluginExecutionPolicy::SandboxOnly => {
                sandbox_mode == SandboxMode::All && sandbox_runtime_available
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PluginsConfig {
    #[serde(default = "default_plugin_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub dir: Option<String>,
}

impl Default for PluginsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            dir: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct PluginManifest {
    pub name: String,
    #[serde(default = "default_plugin_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub commands: Vec<PluginCommandSpec>,
    #[serde(default)]
    pub tools: Vec<PluginToolSpec>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct PluginCommandPermissions {
    #[serde(default)]
    pub allowed_channels: Vec<String>,
    #[serde(default)]
    pub require_control_chat: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PluginCommandSpec {
    pub command: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub response: Option<String>,
    #[serde(default)]
    pub run: Option<PluginExecSpec>,
    #[serde(default)]
    pub permissions: PluginCommandPermissions,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PluginExecSpec {
    pub command: String,
    #[serde(default = "default_plugin_timeout_secs")]
    pub timeout_secs: u64,
    #[serde(default)]
    pub execution_policy: Option<PluginExecutionPolicy>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct PluginToolPermissions {
    #[serde(default)]
    pub allowed_channels: Vec<String>,
    #[serde(default)]
    pub require_control_chat: bool,
    #[serde(default)]
    pub execution_policy: Option<PluginExecutionPolicy>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PluginToolSpec {
    pub name: String,
    pub description: String,
    #[serde(default = "default_plugin_tool_schema")]
    pub input_schema: serde_json::Value,
    pub run: PluginExecSpec,
    #[serde(default)]
    pub permissions: PluginToolPermissions,
}

#[derive(Clone)]
pub struct LoadedPluginTool {
    pub plugin_name: String,
    pub spec: PluginToolSpec,
}

#[derive(Clone, Debug, Default)]
pub struct PluginLoadReport {
    pub manifests: Vec<PluginManifest>,
    pub errors: Vec<String>,
}

pub fn plugins_dir(config: &Config) -> PathBuf {
    if let Some(dir) = &config.plugins.dir {
        let trimmed = dir.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    config.data_root_dir().join("plugins")
}

pub fn load_plugin_report(config: &Config) -> PluginLoadReport {
    if !config.plugins.enabled {
        return PluginLoadReport::default();
    }
    let dir = plugins_dir(config);
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(_) => return PluginLoadReport::default(),
    };

    let mut report = PluginLoadReport::default();
    let mut plugin_names = HashSet::new();
    let mut manifests = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let ext = path
            .extension()
            .and_then(|v| v.to_str())
            .map(|v| v.to_ascii_lowercase())
            .unwrap_or_default();
        if ext != "yaml" && ext != "yml" && ext != "json" {
            continue;
        }
        match load_manifest_file(&path) {
            Ok(mut manifest) => {
                normalize_manifest(&mut manifest);
                if manifest.name.is_empty() {
                    report
                        .errors
                        .push(format!("{}: plugin name is empty", path.display()));
                    continue;
                }
                let normalized_name = manifest.name.to_ascii_lowercase();
                if !plugin_names.insert(normalized_name) {
                    report.errors.push(format!(
                        "{}: duplicate plugin name '{}'",
                        path.display(),
                        manifest.name
                    ));
                    continue;
                }
                validate_manifest(&manifest, &path, &mut report.errors);
                if manifest.enabled {
                    manifests.push(manifest);
                }
            }
            Err(e) => {
                warn!(path = %path.display(), error = %e, "failed to load plugin manifest");
            }
        }
    }
    report.manifests = manifests;
    report
}

pub fn load_plugin_manifests(config: &Config) -> Vec<PluginManifest> {
    let report = load_plugin_report(config);
    for err in &report.errors {
        warn!(error = err.as_str(), "plugin manifest validation issue");
    }
    report.manifests
}

fn load_manifest_file(path: &Path) -> anyhow::Result<PluginManifest> {
    let content = std::fs::read_to_string(path)?;
    let ext = path
        .extension()
        .and_then(|v| v.to_str())
        .map(|v| v.to_ascii_lowercase())
        .unwrap_or_default();
    if ext == "json" {
        Ok(serde_json::from_str(&content)?)
    } else {
        Ok(serde_yaml::from_str(&content)?)
    }
}

fn normalize_manifest(manifest: &mut PluginManifest) {
    manifest.name = manifest.name.trim().to_string();
    for command in &mut manifest.commands {
        let trimmed = command.command.trim();
        command.command = if trimmed.starts_with('/') {
            trimmed.to_string()
        } else {
            format!("/{trimmed}")
        };
        command.description = command.description.trim().to_string();
        normalize_channels(&mut command.permissions.allowed_channels);
    }
    for tool in &mut manifest.tools {
        tool.name = tool.name.trim().to_string();
        tool.description = tool.description.trim().to_string();
        normalize_channels(&mut tool.permissions.allowed_channels);
    }
}

fn normalize_channels(channels: &mut Vec<String>) {
    let mut deduped = Vec::new();
    let mut seen = HashSet::new();
    for channel in channels.drain(..) {
        let normalized = channel.trim().to_ascii_lowercase();
        if normalized.is_empty() || !seen.insert(normalized.clone()) {
            continue;
        }
        deduped.push(normalized);
    }
    *channels = deduped;
}

fn validate_manifest(manifest: &PluginManifest, path: &Path, errors: &mut Vec<String>) {
    let mut command_names = HashSet::new();
    for command in &manifest.commands {
        if command.command.trim() == "/" {
            errors.push(format!(
                "{}: plugin '{}' has invalid command '/'",
                path.display(),
                manifest.name
            ));
        }
        let normalized = command.command.to_ascii_lowercase();
        if !command_names.insert(normalized) {
            errors.push(format!(
                "{}: plugin '{}' has duplicate command '{}'",
                path.display(),
                manifest.name,
                command.command
            ));
        }
        if let Some(run) = &command.run {
            if run.command.trim().is_empty() {
                errors.push(format!(
                    "{}: plugin '{}' command '{}' has empty run.command",
                    path.display(),
                    manifest.name,
                    command.command
                ));
            }
        }
    }

    let mut tool_names = HashSet::new();
    for tool in &manifest.tools {
        let normalized = tool.name.to_ascii_lowercase();
        if normalized.is_empty() {
            errors.push(format!(
                "{}: plugin '{}' contains tool with empty name",
                path.display(),
                manifest.name
            ));
            continue;
        }
        if !tool_names.insert(normalized) {
            errors.push(format!(
                "{}: plugin '{}' has duplicate tool '{}'",
                path.display(),
                manifest.name,
                tool.name
            ));
        }
        if tool.run.command.trim().is_empty() {
            errors.push(format!(
                "{}: plugin '{}' tool '{}' has empty run.command",
                path.display(),
                manifest.name,
                tool.name
            ));
        }
        if !tool.input_schema.is_object() {
            errors.push(format!(
                "{}: plugin '{}' tool '{}' input_schema must be an object",
                path.display(),
                manifest.name,
                tool.name
            ));
        }
    }
}

pub fn load_plugin_tools(config: &Config) -> Vec<LoadedPluginTool> {
    let mut out = Vec::new();
    let report = load_plugin_report(config);
    for err in &report.errors {
        warn!(error = err.as_str(), "plugin manifest validation issue");
    }
    for manifest in report.manifests {
        let plugin_name = manifest.name;
        for spec in manifest.tools {
            if spec.name.is_empty() || spec.run.command.trim().is_empty() {
                continue;
            }
            out.push(LoadedPluginTool {
                plugin_name: plugin_name.clone(),
                spec,
            });
        }
    }
    out
}

pub fn dynamic_plugin_tool_definitions(config: &Config) -> Vec<ToolDefinition> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for manifest in load_plugin_manifests(config) {
        for spec in manifest.tools {
            let normalized = spec.name.to_ascii_lowercase();
            if normalized.is_empty() || !seen.insert(normalized) {
                continue;
            }
            out.push(ToolDefinition {
                name: spec.name,
                description: format!("[plugin:{}] {}", manifest.name, spec.description),
                input_schema: if spec.input_schema.is_object() {
                    spec.input_schema
                } else {
                    default_plugin_tool_schema()
                },
            });
        }
    }
    out
}

pub async fn execute_dynamic_plugin_tool(
    config: &Config,
    tool_name: &str,
    input: serde_json::Value,
) -> Option<ToolResult> {
    let mut matched: Option<(String, PluginToolSpec)> = None;
    for manifest in load_plugin_manifests(config) {
        if let Some(spec) = manifest
            .tools
            .into_iter()
            .find(|t| t.name.eq_ignore_ascii_case(tool_name))
        {
            matched = Some((manifest.name, spec));
            break;
        }
    }
    let Some((plugin_name, spec)) = matched else {
        return None;
    };

    Some(execute_plugin_tool_spec(config, &plugin_name, &spec, input).await)
}

pub fn handle_plugins_admin_command(
    config: &Config,
    caller_chat_id: i64,
    command_text: &str,
) -> Option<String> {
    let trimmed = command_text.trim();
    let is_plugins_cmd =
        trimmed == "/plugins" || trimmed.starts_with("/plugins ") || trimmed == "/plugins@bot";
    if !is_plugins_cmd {
        return None;
    }
    if !config.control_chat_ids.contains(&caller_chat_id) {
        return Some("Plugin admin commands require control chat permission.".to_string());
    }

    let arg = trimmed
        .split_whitespace()
        .nth(1)
        .unwrap_or("list")
        .to_ascii_lowercase();
    let report = load_plugin_report(config);
    match arg.as_str() {
        "list" => {
            if report.manifests.is_empty() {
                return Some("No enabled plugins found.".to_string());
            }
            let mut lines = Vec::new();
            lines.push(format!("Plugins ({}):", report.manifests.len()));
            for manifest in &report.manifests {
                lines.push(format!(
                    "- {} (commands: {}, tools: {})",
                    manifest.name,
                    manifest.commands.len(),
                    manifest.tools.len()
                ));
            }
            if !report.errors.is_empty() {
                lines.push(format!("Validation issues: {}", report.errors.len()));
            }
            Some(lines.join("\n"))
        }
        "validate" => {
            if report.errors.is_empty() {
                Some("Plugin validation OK.".to_string())
            } else {
                let mut lines = Vec::new();
                lines.push(format!(
                    "Plugin validation found {} issue(s):",
                    report.errors.len()
                ));
                for err in report.errors.iter().take(20) {
                    lines.push(format!("- {err}"));
                }
                if report.errors.len() > 20 {
                    lines.push(format!(
                        "... and {} more issue(s)",
                        report.errors.len() - 20
                    ));
                }
                Some(lines.join("\n"))
            }
        }
        "reload" => Some(
            "Plugin manifests are loaded dynamically; command and tool changes apply immediately."
                .to_string(),
        ),
        _ => Some("Usage: /plugins [list|validate|reload]".to_string()),
    }
}

pub fn command_matches(input: &str, configured: &str) -> bool {
    let trimmed = input.trim();
    let first_token = trimmed.split_whitespace().next().unwrap_or("");
    first_token.eq_ignore_ascii_case(configured)
}

pub async fn execute_plugin_slash_command(
    config: &Config,
    caller_channel: &str,
    caller_chat_id: i64,
    command_text: &str,
) -> Option<String> {
    let trimmed = command_text.trim();
    if !trimmed.starts_with('/') {
        return None;
    }

    let manifests = load_plugin_manifests(config);
    for manifest in manifests {
        for command in manifest.commands {
            if !command_matches(trimmed, &command.command) {
                continue;
            }
            if !is_channel_allowed(caller_channel, &command.permissions.allowed_channels) {
                return Some(format!(
                    "Plugin command '{}' is not allowed in channel '{}'.",
                    command.command, caller_channel
                ));
            }
            if command.permissions.require_control_chat
                && !config.control_chat_ids.contains(&caller_chat_id)
            {
                return Some(format!(
                    "Plugin command '{}' requires control chat permission.",
                    command.command
                ));
            }

            let args = trimmed
                .strip_prefix(command.command.as_str())
                .unwrap_or("")
                .trim()
                .to_string();

            let mut vars = HashMap::new();
            vars.insert("channel".to_string(), caller_channel.to_string());
            vars.insert("chat_id".to_string(), caller_chat_id.to_string());
            vars.insert("command".to_string(), command.command.clone());
            vars.insert("args".to_string(), args);

            let mut response_chunks = Vec::new();
            if let Some(response) = &command.response {
                match render_template_checked(response, &vars, false) {
                    Ok(text) => response_chunks.push(text),
                    Err(e) => {
                        return Some(format!("Plugin command response template error: {e}"));
                    }
                }
            }

            if let Some(run) = &command.run {
                match execute_with_template(
                    config,
                    caller_channel,
                    caller_chat_id,
                    &run.command,
                    run.timeout_secs,
                    run.execution_policy
                        .unwrap_or(PluginExecutionPolicy::HostOnly),
                    &vars,
                )
                .await
                {
                    Ok(result) => {
                        vars.insert("stdout".into(), result.stdout.clone());
                        vars.insert("stderr".into(), result.stderr.clone());
                        vars.insert("exit_code".into(), result.exit_code.to_string());
                        vars.insert(
                            "success".into(),
                            if result.exit_code == 0 {
                                "true".into()
                            } else {
                                "false".into()
                            },
                        );
                        if command.response.is_none() {
                            response_chunks.push(format_exec_result(&result));
                        }
                    }
                    Err(e) => {
                        response_chunks.push(format!("Plugin command execution failed: {e}"));
                    }
                }
            }

            if response_chunks.is_empty() {
                response_chunks.push(format!("Executed plugin command '{}'.", command.command));
            }
            return Some(response_chunks.join("\n\n"));
        }
    }

    None
}

fn is_channel_allowed(channel: &str, allowed: &[String]) -> bool {
    if allowed.is_empty() {
        return true;
    }
    let normalized = channel.trim().to_ascii_lowercase();
    allowed.iter().any(|v| v == &normalized)
}

fn render_template(template: &str, vars: &HashMap<String, String>, shell_escape: bool) -> String {
    let mut out = String::with_capacity(template.len());
    let mut i = 0usize;
    while let Some(start_rel) = template[i..].find("{{") {
        let start = i + start_rel;
        out.push_str(&template[i..start]);
        let Some(end_rel) = template[start + 2..].find("}}") else {
            out.push_str(&template[start..]);
            return out;
        };
        let end = start + 2 + end_rel;
        let key = template[start + 2..end].trim();
        if let Some(value) = vars.get(key) {
            if shell_escape {
                out.push_str(&shell_escape_single(value));
            } else {
                out.push_str(value);
            }
        }
        i = end + 2;
    }
    out.push_str(&template[i..]);
    out
}

fn template_keys(template: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while let Some(start_rel) = template[i..].find("{{") {
        let start = i + start_rel;
        let Some(end_rel) = template[start + 2..].find("}}") else {
            break;
        };
        let end = start + 2 + end_rel;
        let key = template[start + 2..end].trim();
        if !key.is_empty() {
            out.push(key.to_string());
        }
        i = end + 2;
    }
    out
}

fn render_template_checked(
    template: &str,
    vars: &HashMap<String, String>,
    shell_escape: bool,
) -> anyhow::Result<String> {
    let missing: Vec<String> = template_keys(template)
        .into_iter()
        .filter(|k| !vars.contains_key(k))
        .collect();
    if !missing.is_empty() {
        anyhow::bail!("missing template variable(s): {}", missing.join(", "));
    }
    Ok(render_template(template, vars, shell_escape))
}

fn shell_escape_single(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }
    let replaced = value.replace('\'', "'\\''");
    format!("'{replaced}'")
}

fn make_tool_working_dir(
    base_working_dir: &Path,
    isolation: WorkingDirIsolation,
    caller_channel: &str,
    caller_chat_id: i64,
) -> PathBuf {
    let mut auth = serde_json::Map::new();
    auth.insert("caller_channel".to_string(), json!(caller_channel));
    auth.insert("caller_chat_id".to_string(), json!(caller_chat_id));
    auth.insert("control_chat_ids".to_string(), json!([]));

    let mut input = serde_json::Map::new();
    input.insert(
        "__microclaw_auth".to_string(),
        serde_json::Value::Object(auth),
    );

    crate::tools::resolve_tool_working_dir(
        base_working_dir,
        isolation,
        &serde_json::Value::Object(input),
    )
}

async fn execute_with_template(
    config: &Config,
    caller_channel: &str,
    caller_chat_id: i64,
    command_template: &str,
    timeout_secs: u64,
    execution_policy: PluginExecutionPolicy,
    vars: &HashMap<String, String>,
) -> anyhow::Result<SandboxExecResult> {
    let command = render_template_checked(command_template, vars, true)?;

    let base_working_dir = PathBuf::from(&config.working_dir);
    let working_dir = make_tool_working_dir(
        &base_working_dir,
        config.working_dir_isolation,
        caller_channel,
        caller_chat_id,
    );
    tokio::fs::create_dir_all(&working_dir).await?;

    let router = Arc::new(SandboxRouter::new(
        config.sandbox.clone(),
        &base_working_dir,
    ));
    execute_command_with_policy(
        router,
        caller_channel,
        caller_chat_id,
        &command,
        timeout_secs,
        working_dir,
        execution_policy,
    )
    .await
}

async fn execute_command_with_policy(
    router: Arc<SandboxRouter>,
    caller_channel: &str,
    caller_chat_id: i64,
    command: &str,
    timeout_secs: u64,
    working_dir: PathBuf,
    execution_policy: PluginExecutionPolicy,
) -> anyhow::Result<SandboxExecResult> {
    let opts = SandboxExecOptions {
        timeout: std::time::Duration::from_secs(timeout_secs.max(1)),
        working_dir: Some(working_dir),
    };

    if !execution_policy.is_allowed(router.mode(), router.runtime_available()) {
        anyhow::bail!(
            "execution policy '{:?}' denied: sandbox runtime unavailable or disabled",
            execution_policy
        );
    }

    let session_key = format!("{}-{}", caller_channel, caller_chat_id);
    match execution_policy {
        PluginExecutionPolicy::HostOnly => {
            microclaw_tools::sandbox::exec_host_command(command, &opts).await
        }
        PluginExecutionPolicy::SandboxOnly => router.exec(&session_key, command, &opts).await,
        PluginExecutionPolicy::Dual => {
            if router.mode() == SandboxMode::All {
                router.exec(&session_key, command, &opts).await
            } else {
                microclaw_tools::sandbox::exec_host_command(command, &opts).await
            }
        }
    }
}

fn format_exec_result(result: &SandboxExecResult) -> String {
    let mut out = String::new();
    if !result.stdout.trim().is_empty() {
        out.push_str(result.stdout.trim_end());
    }
    if !result.stderr.trim().is_empty() {
        if !out.is_empty() {
            out.push_str("\n\n");
        }
        out.push_str("STDERR:\n");
        out.push_str(result.stderr.trim_end());
    }
    if out.is_empty() {
        out = format!("Command completed with exit code {}", result.exit_code);
    }
    out
}

async fn execute_plugin_tool_spec(
    config: &Config,
    _plugin_name: &str,
    spec: &PluginToolSpec,
    input: serde_json::Value,
) -> ToolResult {
    let auth = auth_context_from_input(&input);
    let caller_channel = auth
        .as_ref()
        .map(|a| a.caller_channel.as_str())
        .unwrap_or("unknown");
    let caller_chat_id = auth.as_ref().map(|a| a.caller_chat_id).unwrap_or(0);

    if !is_channel_allowed(caller_channel, &spec.permissions.allowed_channels) {
        return ToolResult::error(format!(
            "Plugin tool '{}' is not allowed in channel '{}'.",
            spec.name, caller_channel
        ))
        .with_error_type("plugin_permission_denied");
    }
    if spec.permissions.require_control_chat && !config.control_chat_ids.contains(&caller_chat_id) {
        return ToolResult::error(format!(
            "Plugin tool '{}' requires control chat permission.",
            spec.name
        ))
        .with_error_type("plugin_permission_denied");
    }

    let mut vars = HashMap::new();
    vars.insert("channel".to_string(), caller_channel.to_string());
    vars.insert("chat_id".to_string(), caller_chat_id.to_string());
    if let Some(map) = input.as_object() {
        for (k, v) in map {
            if k == "__microclaw_auth" {
                continue;
            }
            let value = if let Some(s) = v.as_str() {
                s.to_string()
            } else if v.is_number() || v.is_boolean() {
                v.to_string()
            } else {
                serde_json::to_string(v).unwrap_or_default()
            };
            vars.insert(k.clone(), value);
        }
    }

    let rendered = match render_template_checked(&spec.run.command, &vars, true) {
        Ok(v) => v,
        Err(e) => {
            return ToolResult::error(format!("Plugin tool template error: {e}"))
                .with_error_type("plugin_template_error");
        }
    };

    let base_working_dir = PathBuf::from(&config.working_dir);
    let working_dir = make_tool_working_dir(
        &base_working_dir,
        config.working_dir_isolation,
        caller_channel,
        caller_chat_id,
    );
    if let Err(e) = tokio::fs::create_dir_all(&working_dir).await {
        return ToolResult::error(format!(
            "Failed to create plugin working directory {}: {e}",
            working_dir.display()
        ))
        .with_error_type("plugin_spawn_error");
    }

    let router = Arc::new(SandboxRouter::new(
        config.sandbox.clone(),
        &base_working_dir,
    ));
    let result = execute_command_with_policy(
        router,
        caller_channel,
        caller_chat_id,
        &rendered,
        spec.run.timeout_secs,
        working_dir,
        PluginTool::resolve_policy(spec),
    )
    .await;

    match result {
        Ok(exec_result) => {
            let text = format_exec_result(&exec_result);
            if exec_result.exit_code == 0 {
                ToolResult::success(text).with_status_code(exec_result.exit_code)
            } else {
                ToolResult::error(format!("Exit code {}\n{}", exec_result.exit_code, text))
                    .with_status_code(exec_result.exit_code)
                    .with_error_type("plugin_process_exit")
            }
        }
        Err(e) => ToolResult::error(format!("Plugin tool execution failed: {e}"))
            .with_error_type("plugin_spawn_error"),
    }
}

pub struct PluginTool {
    plugin_name: String,
    config: Config,
    spec: PluginToolSpec,
}

impl PluginTool {
    pub fn new(config: &Config, plugin_name: String, spec: PluginToolSpec) -> Self {
        Self {
            plugin_name,
            config: config.clone(),
            spec,
        }
    }

    fn resolve_runtime_spec(&self) -> PluginToolSpec {
        let manifests = load_plugin_manifests(&self.config);
        manifests
            .into_iter()
            .find(|m| m.name == self.plugin_name)
            .and_then(|m| {
                m.tools
                    .into_iter()
                    .find(|t| t.name.eq_ignore_ascii_case(&self.spec.name))
            })
            .unwrap_or_else(|| self.spec.clone())
    }

    fn resolve_policy(spec: &PluginToolSpec) -> PluginExecutionPolicy {
        spec.permissions
            .execution_policy
            .or(spec.run.execution_policy)
            .unwrap_or(PluginExecutionPolicy::HostOnly)
    }
}

#[async_trait]
impl Tool for PluginTool {
    fn name(&self) -> &str {
        &self.spec.name
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: self.spec.name.clone(),
            description: format!("[plugin:{}] {}", self.plugin_name, self.spec.description),
            input_schema: if self.spec.input_schema.is_object() {
                self.spec.input_schema.clone()
            } else {
                default_plugin_tool_schema()
            },
        }
    }

    async fn execute(&self, input: serde_json::Value) -> ToolResult {
        let runtime_spec = self.resolve_runtime_spec();
        execute_plugin_tool_spec(&self.config, &self.plugin_name, &runtime_spec, input).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::path::PathBuf;

    fn make_temp_plugins_dir(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "microclaw_plugin_tests_{}_{}",
            name,
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn config_with_plugins_dir(dir: &Path) -> Config {
        let mut cfg = crate::config::Config::test_defaults();
        cfg.plugins.enabled = true;
        cfg.plugins.dir = Some(dir.to_string_lossy().to_string());
        cfg.working_dir = dir.join("work").to_string_lossy().to_string();
        cfg
    }

    #[test]
    fn test_command_matches_first_token() {
        assert!(command_matches("/hello world", "/hello"));
        assert!(command_matches(" /HELLO   world", "/hello"));
        assert!(!command_matches("/hello-world", "/hello"));
        assert!(!command_matches("hello", "/hello"));
    }

    #[test]
    fn test_normalize_manifest_adds_slash_and_channels() {
        let mut manifest = PluginManifest {
            name: " demo ".to_string(),
            enabled: true,
            commands: vec![PluginCommandSpec {
                command: "ping".to_string(),
                description: " test ".to_string(),
                response: None,
                run: None,
                permissions: PluginCommandPermissions {
                    allowed_channels: vec![" Telegram ".to_string(), "".to_string()],
                    require_control_chat: false,
                },
            }],
            tools: vec![],
        };
        normalize_manifest(&mut manifest);
        assert_eq!(manifest.name, "demo");
        assert_eq!(manifest.commands[0].command, "/ping");
        assert_eq!(
            manifest.commands[0].permissions.allowed_channels,
            vec!["telegram".to_string()]
        );
    }

    #[test]
    fn test_render_template_checked_missing_var() {
        let vars = HashMap::from([(String::from("a"), String::from("1"))]);
        let err = render_template_checked("x {{a}} {{b}}", &vars, false).unwrap_err();
        assert!(err.to_string().contains("missing template variable"));
        assert!(err.to_string().contains("b"));
    }

    #[test]
    fn test_validate_manifest_reports_duplicates() {
        let manifest = PluginManifest {
            name: "dup".to_string(),
            enabled: true,
            commands: vec![
                PluginCommandSpec {
                    command: "/a".to_string(),
                    description: String::new(),
                    response: None,
                    run: Some(PluginExecSpec {
                        command: "echo 1".to_string(),
                        timeout_secs: 3,
                        execution_policy: None,
                    }),
                    permissions: PluginCommandPermissions::default(),
                },
                PluginCommandSpec {
                    command: "/a".to_string(),
                    description: String::new(),
                    response: None,
                    run: None,
                    permissions: PluginCommandPermissions::default(),
                },
            ],
            tools: vec![
                PluginToolSpec {
                    name: "t".to_string(),
                    description: "d".to_string(),
                    input_schema: schema_object(json!({}), &[]),
                    run: PluginExecSpec {
                        command: "echo 1".to_string(),
                        timeout_secs: 3,
                        execution_policy: None,
                    },
                    permissions: PluginToolPermissions::default(),
                },
                PluginToolSpec {
                    name: "t".to_string(),
                    description: "d".to_string(),
                    input_schema: schema_object(json!({}), &[]),
                    run: PluginExecSpec {
                        command: "echo 1".to_string(),
                        timeout_secs: 3,
                        execution_policy: None,
                    },
                    permissions: PluginToolPermissions::default(),
                },
            ],
        };

        let mut errors = Vec::new();
        validate_manifest(&manifest, Path::new("/tmp/dup.yaml"), &mut errors);
        assert!(!errors.is_empty());
        assert!(errors.iter().any(|e| e.contains("duplicate command")));
        assert!(errors.iter().any(|e| e.contains("duplicate tool")));
    }

    #[test]
    fn test_plugin_admin_requires_control_chat() {
        let root = make_temp_plugins_dir("admin_perm");
        let cfg = config_with_plugins_dir(&root);
        let out = handle_plugins_admin_command(&cfg, 123, "/plugins list").unwrap();
        assert!(out.contains("require control chat"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn test_plugin_admin_list_and_validate() {
        let root = make_temp_plugins_dir("admin_list_validate");
        std::fs::write(
            root.join("good.yaml"),
            r#"
name: good
enabled: true
commands:
  - command: /ok
    response: "ok"
"#,
        )
        .unwrap();
        std::fs::write(
            root.join("bad.yaml"),
            r#"
name: bad
enabled: true
commands:
  - command: /
    run:
      command: ""
"#,
        )
        .unwrap();

        let mut cfg = config_with_plugins_dir(&root);
        cfg.control_chat_ids = vec![42];
        let list = handle_plugins_admin_command(&cfg, 42, "/plugins list").unwrap();
        assert!(list.contains("Plugins"));
        assert!(list.contains("good"));
        let validate = handle_plugins_admin_command(&cfg, 42, "/plugins validate").unwrap();
        assert!(validate.contains("issue"));
        assert!(validate.contains("invalid command"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn test_plugin_slash_command_permissions_matrix() {
        let root = make_temp_plugins_dir("slash_perm");
        std::fs::write(
            root.join("cmd.yaml"),
            r#"
name: cmds
enabled: true
commands:
  - command: /hello
    response: "hello {{channel}}"
    permissions:
      allowed_channels: ["telegram"]
  - command: /secure
    response: "secure-ok"
    permissions:
      require_control_chat: true
"#,
        )
        .unwrap();

        let mut cfg = config_with_plugins_dir(&root);
        cfg.control_chat_ids = vec![100];

        let denied_channel = execute_plugin_slash_command(&cfg, "discord", 100, "/hello")
            .await
            .unwrap();
        assert!(denied_channel.contains("not allowed"));

        let allowed_channel = execute_plugin_slash_command(&cfg, "telegram", 100, "/hello")
            .await
            .unwrap();
        assert!(allowed_channel.contains("hello telegram"));

        let denied_control = execute_plugin_slash_command(&cfg, "telegram", 101, "/secure")
            .await
            .unwrap();
        assert!(denied_control.contains("requires control chat"));

        let allowed_control = execute_plugin_slash_command(&cfg, "telegram", 100, "/secure")
            .await
            .unwrap();
        assert_eq!(allowed_control, "secure-ok");
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn test_plugin_slash_command_run_command_can_use_args_variable() {
        let root = make_temp_plugins_dir("slash_args");
        std::fs::write(
            root.join("cmd.yaml"),
            r#"
name: argsplug
enabled: true
commands:
  - command: /echo
    run:
      command: "printf 'echo=%s\n' {{args}}"
      timeout_secs: 5
      execution_policy: host_only
"#,
        )
        .unwrap();
        let cfg = config_with_plugins_dir(&root);
        let out = execute_plugin_slash_command(&cfg, "web", 7, "/echo hello world")
            .await
            .unwrap();
        assert!(out.contains("echo=hello world"), "got: {out}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn test_plugin_tool_execution_policy_matrix() {
        let root = make_temp_plugins_dir("tool_policy");
        std::fs::write(
            root.join("tool.yaml"),
            r#"
name: tools
enabled: true
tools:
  - name: sandbox_tool
    description: sandbox only
    input_schema:
      type: object
      properties: {}
      required: []
    run:
      command: "printf sandbox"
      timeout_secs: 5
      execution_policy: sandbox_only
  - name: dual_tool
    description: dual mode
    input_schema:
      type: object
      properties: {}
      required: []
    run:
      command: "printf dual-ok"
      timeout_secs: 5
      execution_policy: dual
"#,
        )
        .unwrap();

        let cfg = config_with_plugins_dir(&root);
        let auth_input = json!({
            "__microclaw_auth": {
                "caller_channel": "web",
                "caller_chat_id": 9,
                "control_chat_ids": []
            }
        });

        let blocked = execute_dynamic_plugin_tool(&cfg, "sandbox_tool", auth_input.clone())
            .await
            .unwrap();
        assert!(blocked.is_error);
        assert_eq!(blocked.error_type.as_deref(), Some("plugin_spawn_error"));
        assert!(blocked.content.contains("execution policy"));

        let dual = execute_dynamic_plugin_tool(&cfg, "dual_tool", auth_input)
            .await
            .unwrap();
        assert!(!dual.is_error, "{}", dual.content);
        assert!(dual.content.contains("dual-ok"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn test_plugin_report_detects_duplicate_plugin_names_across_files() {
        let root = make_temp_plugins_dir("dupe_plugin_names");
        std::fs::write(
            root.join("a.yaml"),
            r#"
name: dup
enabled: true
commands:
  - command: /a
    response: "a"
"#,
        )
        .unwrap();
        std::fs::write(
            root.join("b.yaml"),
            r#"
name: dup
enabled: true
commands:
  - command: /b
    response: "b"
"#,
        )
        .unwrap();

        let cfg = config_with_plugins_dir(&root);
        let report = load_plugin_report(&cfg);
        assert!(report
            .errors
            .iter()
            .any(|e| e.contains("duplicate plugin name")));
        let _ = std::fs::remove_dir_all(root);
    }
}
