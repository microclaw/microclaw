use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use microclaw_storage::db::{call_blocking, Database};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::io::AsyncWriteExt;
use tokio::sync::RwLock;
use tracing::warn;

use crate::config::Config;
use crate::tools::ToolResult;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HookEvent {
    BeforeLLMCall,
    BeforeToolCall,
    AfterToolCall,
}

impl HookEvent {
    fn as_str(self) -> &'static str {
        match self {
            HookEvent::BeforeLLMCall => "BeforeLLMCall",
            HookEvent::BeforeToolCall => "BeforeToolCall",
            HookEvent::AfterToolCall => "AfterToolCall",
        }
    }

    fn from_str(v: &str) -> Option<Self> {
        match v.trim() {
            "BeforeLLMCall" => Some(HookEvent::BeforeLLMCall),
            "BeforeToolCall" => Some(HookEvent::BeforeToolCall),
            "AfterToolCall" => Some(HookEvent::AfterToolCall),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct HookInfo {
    pub name: String,
    pub description: String,
    pub events: Vec<String>,
    pub command: String,
    pub timeout_ms: u64,
    pub enabled: bool,
    pub path: String,
}

#[derive(Debug, Clone, Deserialize)]
struct HookFrontmatter {
    name: Option<String>,
    description: Option<String>,
    #[serde(default)]
    events: Vec<String>,
    command: Option<String>,
    enabled: Option<bool>,
    timeout_ms: Option<u64>,
    priority: Option<i32>,
}

#[derive(Debug, Clone)]
struct HookDef {
    name: String,
    description: String,
    events: Vec<HookEvent>,
    command: String,
    timeout_ms: u64,
    enabled_by_default: bool,
    priority: i32,
    dir: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
struct HookResponse {
    action: Option<String>,
    reason: Option<String>,
    patch: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub enum HookOutcome {
    Allow { patches: Vec<serde_json::Value> },
    Block { reason: String },
}

#[derive(Clone)]
pub struct HookManager {
    hooks_dir_candidates: Vec<PathBuf>,
    state_file: PathBuf,
    hooks: Arc<RwLock<Vec<HookDef>>>,
    state_overrides: Arc<RwLock<HashMap<String, bool>>>,
    db: Option<Arc<Database>>,
    enabled: bool,
    max_input_bytes: usize,
    max_output_bytes: usize,
}

impl HookManager {
    pub fn from_config(config: &Config) -> Self {
        let data_dir = PathBuf::from(&config.data_dir);
        let root_dir = if data_dir.ends_with("runtime") {
            data_dir
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| data_dir.clone())
        } else {
            data_dir.clone()
        };
        let runtime_dir = if data_dir.ends_with("runtime") {
            data_dir.clone()
        } else {
            data_dir.join("runtime")
        };
        let hooks_root = root_dir.join("hooks");
        let local_hooks = PathBuf::from("hooks");
        let state_file = runtime_dir.join("hooks_state.json");

        let (enabled, max_input_bytes, max_output_bytes) = hooks_runtime_settings(config);
        let manager = Self {
            hooks_dir_candidates: vec![hooks_root, local_hooks],
            state_file,
            hooks: Arc::new(RwLock::new(Vec::new())),
            state_overrides: Arc::new(RwLock::new(HashMap::new())),
            db: None,
            enabled,
            max_input_bytes,
            max_output_bytes,
        };
        manager.reload_sync();
        manager
    }

    pub fn with_db(mut self, db: Arc<Database>) -> Self {
        self.db = Some(db);
        self
    }

    #[cfg(test)]
    pub fn for_tests() -> Self {
        let tmp = std::env::temp_dir().join(format!("microclaw-hooks-{}", uuid::Uuid::new_v4()));
        let _ = std::fs::create_dir_all(&tmp);
        let manager = Self {
            hooks_dir_candidates: vec![tmp.join("hooks")],
            state_file: tmp.join("runtime").join("hooks_state.json"),
            hooks: Arc::new(RwLock::new(Vec::new())),
            state_overrides: Arc::new(RwLock::new(HashMap::new())),
            db: None,
            enabled: true,
            max_input_bytes: 128 * 1024,
            max_output_bytes: 64 * 1024,
        };
        manager.reload_sync();
        manager
    }

    #[cfg(test)]
    pub fn from_test_paths(hooks_dir: PathBuf, state_file: PathBuf) -> Self {
        let manager = Self {
            hooks_dir_candidates: vec![hooks_dir],
            state_file,
            hooks: Arc::new(RwLock::new(Vec::new())),
            state_overrides: Arc::new(RwLock::new(HashMap::new())),
            db: None,
            enabled: true,
            max_input_bytes: 128 * 1024,
            max_output_bytes: 64 * 1024,
        };
        manager.reload_sync();
        manager
    }

    pub fn reload_sync(&self) {
        let hooks = discover_hooks(&self.hooks_dir_candidates);
        let state = read_state_file(&self.state_file).unwrap_or_default();
        if let Some(parent) = self.state_file.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if self.state_file.exists() {
            // noop
        } else {
            let _ = write_state_file(&self.state_file, &state);
        }
        if let Ok(mut g) = self.hooks.try_write() {
            *g = hooks;
        }
        if let Ok(mut g) = self.state_overrides.try_write() {
            *g = state;
        }
    }

    pub async fn list(&self) -> Vec<HookInfo> {
        let hooks = self.hooks.read().await;
        let state = self.state_overrides.read().await;
        let mut out = hooks
            .iter()
            .map(|h| HookInfo {
                name: h.name.clone(),
                description: h.description.clone(),
                events: h.events.iter().map(|e| e.as_str().to_string()).collect(),
                command: h.command.clone(),
                timeout_ms: h.timeout_ms,
                enabled: state.get(&h.name).copied().unwrap_or(h.enabled_by_default),
                path: h.dir.join("HOOK.md").to_string_lossy().to_string(),
            })
            .collect::<Vec<_>>();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    pub async fn info(&self, name: &str) -> Option<HookInfo> {
        self.list().await.into_iter().find(|h| h.name == name)
    }

    pub async fn set_enabled(&self, name: &str, enabled: bool) -> Result<()> {
        let hooks = self.hooks.read().await;
        if hooks.iter().all(|h| h.name != name) {
            return Err(anyhow!("hook not found: {name}"));
        }
        drop(hooks);
        {
            let mut state = self.state_overrides.write().await;
            state.insert(name.to_string(), enabled);
            write_state_file(&self.state_file, &state)?;
        }
        Ok(())
    }

    pub async fn run(&self, event: HookEvent, payload: serde_json::Value) -> Result<HookOutcome> {
        if !self.enabled {
            return Ok(HookOutcome::Allow {
                patches: Vec::new(),
            });
        }
        let hooks = self.hooks.read().await.clone();
        let states = self.state_overrides.read().await.clone();

        let mut matched = hooks
            .into_iter()
            .filter(|h| h.events.contains(&event))
            .collect::<Vec<_>>();
        matched.sort_by(|a, b| {
            a.priority
                .cmp(&b.priority)
                .then_with(|| a.name.cmp(&b.name))
        });

        let mut patches = Vec::new();
        for hook in matched {
            let enabled = states
                .get(&hook.name)
                .copied()
                .unwrap_or(hook.enabled_by_default);
            if !enabled {
                continue;
            }
            let output = run_hook_command(
                &hook,
                event,
                &payload,
                self.max_input_bytes,
                self.max_output_bytes,
            )
            .await;
            let response = match output {
                Ok(r) => r,
                Err(e) => {
                    warn!("hook '{}' failed: {}", hook.name, e);
                    let detail = e.to_string();
                    self.log_hook_audit(&hook.name, event.as_str(), "error", Some(&detail))
                        .await;
                    continue;
                }
            };
            let action = response
                .action
                .as_deref()
                .unwrap_or("allow")
                .trim()
                .to_ascii_lowercase();
            match action.as_str() {
                "allow" => {}
                "block" => {
                    let reason = response
                        .reason
                        .filter(|s| !s.trim().is_empty())
                        .unwrap_or_else(|| format!("blocked by hook {}", hook.name));
                    self.log_hook_audit(&hook.name, event.as_str(), "block", Some(&reason))
                        .await;
                    return Ok(HookOutcome::Block { reason });
                }
                "modify" => {
                    if let Some(p) = response.patch {
                        patches.push(p);
                    }
                    self.log_hook_audit(&hook.name, event.as_str(), "modify", None)
                        .await;
                }
                _ => {}
            }
        }
        Ok(HookOutcome::Allow { patches })
    }

    async fn log_hook_audit(&self, actor: &str, action: &str, status: &str, detail: Option<&str>) {
        let Some(db) = self.db.clone() else {
            return;
        };
        let actor = actor.to_string();
        let action = action.to_string();
        let status = status.to_string();
        let detail = detail.map(str::to_string);
        let _ = call_blocking(db, move |d| {
            d.log_audit_event("hook", &actor, &action, None, &status, detail.as_deref())
                .map(|_| ())
        })
        .await;
    }

    pub async fn run_before_llm(
        &self,
        chat_id: i64,
        caller_channel: &str,
        iteration: usize,
        system_prompt: &str,
        messages_len: usize,
        tools_len: usize,
    ) -> Result<HookOutcome> {
        self.run(
            HookEvent::BeforeLLMCall,
            json!({
                "event": HookEvent::BeforeLLMCall.as_str(),
                "chat_id": chat_id,
                "caller_channel": caller_channel,
                "iteration": iteration,
                "system_prompt": system_prompt,
                "messages_len": messages_len,
                "tools_len": tools_len
            }),
        )
        .await
    }

    pub async fn run_before_tool(
        &self,
        chat_id: i64,
        caller_channel: &str,
        iteration: usize,
        tool_name: &str,
        tool_input: &serde_json::Value,
    ) -> Result<HookOutcome> {
        self.run(
            HookEvent::BeforeToolCall,
            json!({
                "event": HookEvent::BeforeToolCall.as_str(),
                "chat_id": chat_id,
                "caller_channel": caller_channel,
                "iteration": iteration,
                "tool_name": tool_name,
                "tool_input": tool_input
            }),
        )
        .await
    }

    pub async fn run_after_tool(
        &self,
        chat_id: i64,
        caller_channel: &str,
        iteration: usize,
        tool_name: &str,
        tool_input: &serde_json::Value,
        result: &ToolResult,
    ) -> Result<HookOutcome> {
        self.run(
            HookEvent::AfterToolCall,
            json!({
                "event": HookEvent::AfterToolCall.as_str(),
                "chat_id": chat_id,
                "caller_channel": caller_channel,
                "iteration": iteration,
                "tool_name": tool_name,
                "tool_input": tool_input,
                "result": {
                    "content": result.content,
                    "is_error": result.is_error,
                    "status_code": result.status_code,
                    "bytes": result.bytes,
                    "duration_ms": result.duration_ms,
                    "error_type": result.error_type
                }
            }),
        )
        .await
    }
}

async fn run_hook_command(
    hook: &HookDef,
    event: HookEvent,
    payload: &serde_json::Value,
    max_input_bytes: usize,
    max_output_bytes: usize,
) -> Result<HookResponse> {
    let shell = if cfg!(windows) { "cmd" } else { "sh" };
    let shell_arg = if cfg!(windows) { "/C" } else { "-lc" };

    let mut command = tokio::process::Command::new(shell);
    command
        .arg(shell_arg)
        .arg(&hook.command)
        .current_dir(&hook.dir)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .env("MICROCLAW_HOOK_EVENT", event.as_str())
        .env("MICROCLAW_HOOK_NAME", &hook.name);

    let mut child = command.spawn()?;
    if let Some(stdin) = child.stdin.as_mut() {
        let body = serde_json::to_vec(payload)?;
        if body.len() > max_input_bytes {
            return Err(anyhow!("hook input exceeds max bytes"));
        }
        stdin.write_all(&body).await?;
    }
    let timeout = Duration::from_millis(hook.timeout_ms.clamp(10, 120_000));
    let output = tokio::time::timeout(timeout, child.wait_with_output())
        .await
        .map_err(|_| anyhow!("hook timed out after {}ms", hook.timeout_ms))??;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        return Err(anyhow!("hook exit {}: {}", output.status, stderr));
    }
    if output.stdout.len() > max_output_bytes {
        return Err(anyhow!("hook output exceeds max bytes"));
    }
    if output.stdout.is_empty() {
        return Ok(HookResponse {
            action: Some("allow".to_string()),
            reason: None,
            patch: None,
        });
    }
    let response: HookResponse = serde_json::from_slice(&output.stdout)?;
    Ok(response)
}

fn hooks_runtime_settings(config: &Config) -> (bool, usize, usize) {
    let mut enabled = true;
    let mut max_input = 128 * 1024;
    let mut max_output = 64 * 1024;
    if let Some(v) = config.channels.get("hooks").and_then(|v| v.as_mapping()) {
        let get_bool = |k: &str| {
            v.get(serde_yaml::Value::String(k.to_string()))
                .and_then(|x| x.as_bool())
        };
        let get_u64 = |k: &str| {
            v.get(serde_yaml::Value::String(k.to_string()))
                .and_then(|x| x.as_u64())
        };
        if let Some(e) = get_bool("enabled") {
            enabled = e;
        }
        if let Some(n) = get_u64("max_input_bytes") {
            max_input = n as usize;
        }
        if let Some(n) = get_u64("max_output_bytes") {
            max_output = n as usize;
        }
    }
    (
        enabled,
        max_input.clamp(1024, 4 * 1024 * 1024),
        max_output.clamp(512, 2 * 1024 * 1024),
    )
}

fn write_state_file(path: &Path, state: &HashMap<String, bool>) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let body = serde_json::to_string_pretty(state)?;
    std::fs::write(path, body)?;
    Ok(())
}

fn read_state_file(path: &Path) -> Result<HashMap<String, bool>> {
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let raw = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str::<HashMap<String, bool>>(&raw).unwrap_or_default())
}

fn discover_hooks(candidates: &[PathBuf]) -> Vec<HookDef> {
    let mut out = Vec::new();
    for root in candidates {
        let rd = match std::fs::read_dir(root) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for entry in rd.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let hook_md = path.join("HOOK.md");
            if !hook_md.exists() {
                continue;
            }
            match parse_hook_md(&hook_md, &path) {
                Some(h) => out.push(h),
                None => warn!("invalid hook metadata at {}", hook_md.display()),
            }
        }
    }
    out
}

fn parse_hook_md(hook_md_path: &Path, dir: &Path) -> Option<HookDef> {
    let content = std::fs::read_to_string(hook_md_path).ok()?;
    let trimmed = content.trim_start_matches('\u{feff}');
    if !trimmed.starts_with("---") {
        return None;
    }
    let mut lines = trimmed.lines();
    let _ = lines.next()?;
    let mut yaml = String::new();
    for line in lines {
        if line.trim() == "---" || line.trim() == "..." {
            break;
        }
        yaml.push_str(line);
        yaml.push('\n');
    }
    let fm: HookFrontmatter = serde_yaml::from_str(&yaml).ok()?;
    let command = fm.command?.trim().to_string();
    if command.is_empty() {
        return None;
    }
    let events = fm
        .events
        .into_iter()
        .filter_map(|e| HookEvent::from_str(&e))
        .collect::<Vec<_>>();
    if events.is_empty() {
        return None;
    }
    let name = fm.name.filter(|s| !s.trim().is_empty()).unwrap_or_else(|| {
        dir.file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string()
    });
    Some(HookDef {
        name,
        description: fm.description.unwrap_or_default(),
        events,
        command,
        timeout_ms: fm.timeout_ms.unwrap_or(1500),
        enabled_by_default: fm.enabled.unwrap_or(true),
        priority: fm.priority.unwrap_or(100),
        dir: dir.to_path_buf(),
    })
}

pub async fn handle_hooks_cli(args: &[String]) -> Result<()> {
    let cli = match HooksCli::try_parse_from(
        std::iter::once("hooks").chain(args.iter().map(std::string::String::as_str)),
    ) {
        Ok(cli) => cli,
        Err(err)
            if matches!(
                err.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) =>
        {
            err.print()?;
            return Ok(());
        }
        Err(err) => return Err(anyhow!(err.to_string())),
    };
    let cmd = cli.command.unwrap_or(HooksCommand::List);
    let config = Config::load()?;
    let mgr = HookManager::from_config(&config);
    match cmd {
        HooksCommand::List => {
            let hooks = mgr.list().await;
            if hooks.is_empty() {
                println!("No hooks discovered.");
                return Ok(());
            }
            for h in hooks {
                println!(
                    "{}\tenabled={}\tevents={}\tcommand={}",
                    h.name,
                    h.enabled,
                    h.events.join(","),
                    h.command
                );
            }
            Ok(())
        }
        HooksCommand::Info { name } => {
            let Some(info) = mgr.info(&name).await else {
                return Err(anyhow!("hook not found: {name}"));
            };
            println!("{}", serde_json::to_string_pretty(&info)?);
            Ok(())
        }
        HooksCommand::Enable { name } => {
            mgr.set_enabled(&name, true).await?;
            println!("enabled: {name}");
            Ok(())
        }
        HooksCommand::Disable { name } => {
            mgr.set_enabled(&name, false).await?;
            println!("disabled: {name}");
            Ok(())
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "microclaw hooks",
    about = "Manage runtime hooks",
    disable_help_subcommand = true
)]
struct HooksCli {
    #[command(subcommand)]
    command: Option<HooksCommand>,
}

#[derive(Debug, Subcommand)]
enum HooksCommand {
    /// List discovered hooks
    List,
    /// Show hook detail by name
    Info { name: String },
    /// Enable a hook by name
    Enable { name: String },
    /// Disable a hook by name
    Disable { name: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_parse_hook_md() {
        let dir = std::env::temp_dir().join(format!("hook_parse_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("HOOK.md");
        std::fs::write(
            &file,
            r#"---
name: test-hook
description: test
events: [BeforeLLMCall, BeforeToolCall]
command: "echo '{\"action\":\"allow\"}'"
enabled: true
timeout_ms: 1000
---
body
"#,
        )
        .unwrap();
        let parsed = parse_hook_md(&file, &dir).unwrap();
        assert_eq!(parsed.name, "test-hook");
        assert_eq!(parsed.events.len(), 2);
    }

    #[tokio::test]
    async fn test_hook_run_block_and_state_toggle() {
        let root = std::env::temp_dir().join(format!("hook_run_{}", uuid::Uuid::new_v4()));
        let hooks_dir = root.join("hooks");
        let hook_dir = hooks_dir.join("block-bash");
        std::fs::create_dir_all(&hook_dir).unwrap();
        #[cfg(windows)]
        let hook_command = "hook.cmd";
        #[cfg(not(windows))]
        let hook_command = "sh hook.sh";
        std::fs::write(
            hook_dir.join("HOOK.md"),
            format!(
                r#"---
name: block-bash
description: block bash
events: [BeforeToolCall]
command: "{}"
enabled: true
timeout_ms: 2000
---
"#,
                hook_command
            ),
        )
        .unwrap();
        #[cfg(windows)]
        std::fs::write(
            hook_dir.join("hook.cmd"),
            r#"@echo off
setlocal enableextensions enabledelayedexpansion
set payload=
for /f "usebackq delims=" %%A in (`more`) do set payload=%%A
echo !payload! | findstr /C:"\"tool_name\":\"bash\"" >nul
if %errorlevel%==0 (
  echo {"action":"block","reason":"bash blocked"}
) else (
  echo {"action":"allow"}
)
"#,
        )
        .unwrap();
        #[cfg(not(windows))]
        std::fs::write(
            hook_dir.join("hook.sh"),
            r#"#!/bin/sh
payload="$(cat)"
echo "$payload" | grep -q '"tool_name":"bash"'
if [ $? -eq 0 ]; then
  echo '{"action":"block","reason":"bash blocked"}'
else
  echo '{"action":"allow"}'
fi
"#,
        )
        .unwrap();

        let manager =
            HookManager::from_test_paths(hooks_dir, root.join("runtime/hooks_state.json"));
        let first = manager
            .run(
                HookEvent::BeforeToolCall,
                json!({"tool_name":"bash","tool_input":{"cmd":"ls"}}),
            )
            .await
            .unwrap();
        match first {
            HookOutcome::Block { reason } => assert!(reason.contains("blocked")),
            _ => panic!("expected block"),
        }

        manager.set_enabled("block-bash", false).await.unwrap();
        let second = manager
            .run(
                HookEvent::BeforeToolCall,
                json!({"tool_name":"bash","tool_input":{"cmd":"ls"}}),
            )
            .await
            .unwrap();
        match second {
            HookOutcome::Allow { .. } => {}
            _ => panic!("expected allow after disable"),
        }
    }
}
