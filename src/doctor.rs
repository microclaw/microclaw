use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::config::Config;
use crate::config::SandboxMode;
use crate::mcp::McpConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Pass,
    Miss,
    Warn,
    Fail,
}

impl CheckStatus {
    fn as_label(self) -> &'static str {
        match self {
            CheckStatus::Pass => "PASS",
            CheckStatus::Miss => "MISS",
            CheckStatus::Warn => "WARN",
            CheckStatus::Fail => "FAIL",
        }
    }

    fn as_emoji(self) -> &'static str {
        match self {
            CheckStatus::Pass => "✅",
            CheckStatus::Miss => "🌿",
            CheckStatus::Warn => "⚠️",
            CheckStatus::Fail => "❌",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorCheck {
    pub id: String,
    pub title: String,
    pub status: CheckStatus,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    pub platform: String,
    pub arch: String,
    pub in_wsl: bool,
    pub checks: Vec<DoctorCheck>,
}

impl DoctorReport {
    fn new() -> Self {
        Self {
            platform: current_platform().to_string(),
            arch: std::env::consts::ARCH.to_string(),
            in_wsl: is_wsl(),
            checks: Vec::new(),
        }
    }

    fn push(
        &mut self,
        id: impl Into<String>,
        title: impl Into<String>,
        status: CheckStatus,
        detail: impl Into<String>,
        fix: Option<String>,
    ) {
        self.checks.push(DoctorCheck {
            id: id.into(),
            title: title.into(),
            status,
            detail: detail.into(),
            fix,
        });
    }

    fn summary(&self) -> (usize, usize, usize, usize) {
        let mut pass = 0usize;
        let mut miss = 0usize;
        let mut warn = 0usize;
        let mut fail = 0usize;
        for check in &self.checks {
            match check.status {
                CheckStatus::Pass => pass += 1,
                CheckStatus::Miss => miss += 1,
                CheckStatus::Warn => warn += 1,
                CheckStatus::Fail => fail += 1,
            }
        }
        (pass, miss, warn, fail)
    }
}

pub fn run_cli(args: &[String]) -> anyhow::Result<()> {
    let json_output = args.iter().any(|a| a == "--json");
    let sandbox_only = args.iter().any(|a| a == "sandbox");
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!(
            "Usage: microclaw doctor [sandbox] [--json]\n\nChecks PATH, shell/runtime dependencies, browser automation prerequisites, MCP command dependencies, and sandbox readiness."
        );
        return Ok(());
    }

    match migrate_channels_config() {
        Ok(Some((path, changed))) => {
            if changed > 0 && !json_output {
                println!(
                    "Applied automatic channel migration ({changed} block(s)) in {}.",
                    path.display()
                );
            }
        }
        Ok(None) => {}
        Err(err) => {
            if !json_output {
                // Non-fatal: doctor checks should still run even if migration fails.
                eprintln!("Channel migration skipped: {err}");
            }
        }
    }

    let report = if sandbox_only {
        build_sandbox_report()
    } else {
        build_report()
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_report(&report);
    }

    let (_, _, _, fail) = report.summary();
    if fail > 0 {
        std::process::exit(2);
    }

    Ok(())
}

fn migrate_channels_config() -> anyhow::Result<Option<(PathBuf, usize)>> {
    let Some(path) = Config::resolve_config_path()? else {
        return Ok(None);
    };
    let mut cfg = Config::load()?;
    let changed = migrate_channels_to_accounts(&mut cfg);
    if changed > 0 {
        cfg.save_yaml(&path.to_string_lossy())?;
    }
    Ok(Some((path, changed)))
}

fn channel_default_account_id(channel_cfg: &serde_yaml::Mapping) -> String {
    channel_cfg
        .get(serde_yaml::Value::String("default_account".to_string()))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| "main".to_string())
}

fn migrate_channel_accounts(
    channel_cfg: &mut serde_yaml::Mapping,
    legacy_keys: &[&str],
    default_account: &str,
) -> bool {
    let has_accounts = channel_cfg
        .get(serde_yaml::Value::String("accounts".to_string()))
        .and_then(|v| v.as_mapping())
        .is_some_and(|m| !m.is_empty());
    if has_accounts {
        return false;
    }

    let mut account_map = serde_yaml::Mapping::new();
    for key in legacy_keys {
        let yaml_key = serde_yaml::Value::String((*key).to_string());
        if let Some(value) = channel_cfg.get(&yaml_key).cloned() {
            let present = !matches!(&value, serde_yaml::Value::Null)
                && match &value {
                    serde_yaml::Value::String(s) => !s.trim().is_empty(),
                    serde_yaml::Value::Sequence(seq) => !seq.is_empty(),
                    _ => true,
                };
            if present {
                account_map.insert(yaml_key, value);
            }
        }
    }
    if account_map.is_empty() {
        return false;
    }
    account_map.insert(
        serde_yaml::Value::String("enabled".to_string()),
        serde_yaml::Value::Bool(true),
    );

    let mut accounts_map = serde_yaml::Mapping::new();
    accounts_map.insert(
        serde_yaml::Value::String(default_account.to_string()),
        serde_yaml::Value::Mapping(account_map),
    );
    channel_cfg.insert(
        serde_yaml::Value::String("default_account".to_string()),
        serde_yaml::Value::String(default_account.to_string()),
    );
    channel_cfg.insert(
        serde_yaml::Value::String("accounts".to_string()),
        serde_yaml::Value::Mapping(accounts_map),
    );

    for key in legacy_keys {
        channel_cfg.remove(serde_yaml::Value::String((*key).to_string()));
    }
    true
}

fn ensure_channel_mapping<'a>(cfg: &'a mut Config, name: &str) -> &'a mut serde_yaml::Mapping {
    let entry = cfg
        .channels
        .entry(name.to_string())
        .or_insert_with(|| serde_yaml::Value::Mapping(Default::default()));
    if !entry.is_mapping() {
        *entry = serde_yaml::Value::Mapping(Default::default());
    }
    entry
        .as_mapping_mut()
        .expect("channel config should be mapping")
}

fn migrate_channels_to_accounts(cfg: &mut Config) -> usize {
    let mut changed = 0usize;

    let telegram_token_legacy = cfg.telegram_bot_token.clone();
    let telegram_bot_username_legacy = cfg.bot_username.clone();
    let telegram_allowed_groups_legacy = cfg.allowed_groups.clone();
    let discord_token_legacy = cfg.discord_bot_token.clone();
    let discord_allowed_channels_legacy = cfg.discord_allowed_channels.clone();

    if !telegram_token_legacy.trim().is_empty() {
        let telegram = ensure_channel_mapping(cfg, "telegram");
        telegram.insert(
            serde_yaml::Value::String("bot_token".to_string()),
            serde_yaml::Value::String(telegram_token_legacy),
        );
    }
    if !telegram_bot_username_legacy.trim().is_empty() {
        let telegram = ensure_channel_mapping(cfg, "telegram");
        telegram
            .entry(serde_yaml::Value::String("bot_username".to_string()))
            .or_insert_with(|| serde_yaml::Value::String(telegram_bot_username_legacy));
    }
    if !telegram_allowed_groups_legacy.is_empty() {
        let telegram = ensure_channel_mapping(cfg, "telegram");
        let groups = telegram_allowed_groups_legacy
            .iter()
            .map(|v| serde_yaml::Value::Number(serde_yaml::Number::from(*v)))
            .collect::<Vec<_>>();
        telegram
            .entry(serde_yaml::Value::String("allowed_groups".to_string()))
            .or_insert_with(|| serde_yaml::Value::Sequence(groups));
    }
    if let Some(token) = discord_token_legacy.filter(|v| !v.trim().is_empty()) {
        let discord = ensure_channel_mapping(cfg, "discord");
        discord.insert(
            serde_yaml::Value::String("bot_token".to_string()),
            serde_yaml::Value::String(token),
        );
    }
    if !discord_allowed_channels_legacy.is_empty() {
        let discord = ensure_channel_mapping(cfg, "discord");
        let channels = discord_allowed_channels_legacy
            .iter()
            .map(|v| serde_yaml::Value::Number(serde_yaml::Number::from(*v)))
            .collect::<Vec<_>>();
        discord
            .entry(serde_yaml::Value::String("allowed_channels".to_string()))
            .or_insert_with(|| serde_yaml::Value::Sequence(channels));
    }
    if cfg.discord_no_mention {
        let discord = ensure_channel_mapping(cfg, "discord");
        discord
            .entry(serde_yaml::Value::String("no_mention".to_string()))
            .or_insert_with(|| serde_yaml::Value::Bool(true));
    }

    let channels_to_migrate: [(&str, &[&str]); 4] = [
        (
            "telegram",
            &["bot_token", "bot_username", "allowed_groups", "no_mention"],
        ),
        (
            "discord",
            &[
                "bot_token",
                "bot_username",
                "allowed_channels",
                "no_mention",
            ],
        ),
        (
            "slack",
            &["bot_token", "app_token", "bot_username", "allowed_channels"],
        ),
        (
            "feishu",
            &[
                "app_id",
                "app_secret",
                "connection_mode",
                "domain",
                "allowed_chats",
                "webhook_path",
                "verification_token",
                "encrypt_key",
                "bot_username",
            ],
        ),
    ];

    for (channel_name, keys) in channels_to_migrate {
        let Some(channel_cfg) = cfg.channels.get_mut(channel_name) else {
            continue;
        };
        let Some(channel_map) = channel_cfg.as_mapping_mut() else {
            continue;
        };
        let default_account = channel_default_account_id(channel_map);
        if migrate_channel_accounts(channel_map, keys, &default_account) {
            changed += 1;
            if channel_name == "telegram" {
                cfg.telegram_bot_token.clear();
                cfg.allowed_groups.clear();
            }
            if channel_name == "discord" {
                cfg.discord_bot_token = None;
                cfg.discord_allowed_channels.clear();
                cfg.discord_no_mention = false;
            }
        }
    }

    changed
}

fn build_report() -> DoctorReport {
    let mut report = DoctorReport::new();

    report.push(
        "env.platform",
        "Platform",
        CheckStatus::Pass,
        format!(
            "os={} arch={} wsl={}",
            report.platform, report.arch, report.in_wsl
        ),
        None,
    );

    check_config(&mut report);
    check_path(&mut report);
    check_shell(&mut report);
    check_browser_dependency(&mut report);
    check_mcp_dependencies(&mut report);

    report
}

fn build_sandbox_report() -> DoctorReport {
    let mut report = DoctorReport::new();
    report.push(
        "env.platform",
        "Platform",
        CheckStatus::Pass,
        format!(
            "os={} arch={} wsl={}",
            report.platform, report.arch, report.in_wsl
        ),
        None,
    );
    check_config(&mut report);
    check_sandbox_config(&mut report);
    check_docker_runtime(&mut report);
    check_sandbox_image(&mut report);
    check_mount_allowlist(&mut report);
    report
}

fn check_config(report: &mut DoctorReport) {
    match Config::resolve_config_path() {
        Ok(Some(path)) => report.push(
            "config.file",
            "Config file",
            CheckStatus::Pass,
            format!("found {}", path.display()),
            None,
        ),
        Ok(None) => report.push(
            "config.file",
            "Config file",
            CheckStatus::Warn,
            "microclaw.config.yaml not found".to_string(),
            Some("Run `microclaw setup` to create configuration.".to_string()),
        ),
        Err(err) => report.push(
            "config.file",
            "Config file",
            CheckStatus::Fail,
            err.to_string(),
            Some("Fix MICROCLAW_CONFIG or create a valid config file.".to_string()),
        ),
    }
}

fn check_path(report: &mut DoctorReport) {
    let target = if cfg!(target_os = "windows") {
        user_home_dir().map(|h| h.join(".local").join("bin"))
    } else {
        None
    };

    if let Some(dir) = target {
        if path_contains(&dir) {
            report.push(
                "path.install_dir",
                "Install dir in PATH",
                CheckStatus::Pass,
                format!("{} is in PATH", dir.display()),
                None,
            );
        } else {
            report.push(
                "path.install_dir",
                "Install dir in PATH",
                CheckStatus::Warn,
                format!("{} is not in PATH", dir.display()),
                Some(
                    "Re-run install.ps1 or add `%USERPROFILE%\\.local\\bin` to user PATH and restart terminal."
                        .to_string(),
                ),
            );
        }
    } else if command_exists("microclaw") {
        report.push(
            "path.microclaw",
            "microclaw in PATH",
            CheckStatus::Pass,
            "microclaw is discoverable in PATH".to_string(),
            None,
        );
    } else {
        report.push(
            "path.microclaw",
            "microclaw in PATH",
            CheckStatus::Warn,
            "microclaw is not discoverable in PATH".to_string(),
            Some("Add the microclaw binary directory to PATH.".to_string()),
        );
    }
}

fn check_shell(report: &mut DoctorReport) {
    if cfg!(target_os = "windows") {
        let status = if command_exists("pwsh") || command_exists("powershell") {
            CheckStatus::Pass
        } else {
            CheckStatus::Fail
        };

        let detail = if status == CheckStatus::Pass {
            "PowerShell runtime detected".to_string()
        } else {
            "PowerShell runtime not found".to_string()
        };

        let fix = if status == CheckStatus::Pass {
            None
        } else {
            Some("Install PowerShell 7+ or ensure Windows PowerShell is available.".to_string())
        };

        report.push("shell.runtime", "Shell runtime", status, detail, fix);

        match detect_execution_policy() {
            Ok(policy) => {
                let (status, detail, fix) = classify_execution_policy(&policy);
                report.push(
                    "powershell.policy",
                    "PowerShell execution policy",
                    status,
                    detail,
                    fix,
                );
            }
            Err(err) => {
                report.push(
                    "powershell.policy",
                    "PowerShell execution policy",
                    CheckStatus::Warn,
                    format!("failed to read policy: {err}"),
                    Some(
                        "Run `Get-ExecutionPolicy -Scope CurrentUser` manually in PowerShell."
                            .to_string(),
                    ),
                );
            }
        }
    } else {
        let shell_ok = command_exists("bash") || command_exists("sh");
        report.push(
            "shell.runtime",
            "Shell runtime",
            if shell_ok {
                CheckStatus::Pass
            } else {
                CheckStatus::Fail
            },
            if shell_ok {
                "bash/sh runtime detected".to_string()
            } else {
                "bash/sh runtime not found".to_string()
            },
            if shell_ok {
                None
            } else {
                Some("Install a POSIX shell (bash or sh).".to_string())
            },
        );
    }
}

fn check_browser_dependency(report: &mut DoctorReport) {
    let browser_cmd = if cfg!(target_os = "windows") {
        command_exists("agent-browser.cmd") || command_exists("agent-browser")
    } else {
        command_exists("agent-browser")
    };

    report.push(
        "deps.agent_browser",
        "agent-browser",
        if browser_cmd {
            CheckStatus::Pass
        } else {
            CheckStatus::Miss
        },
        if browser_cmd {
            "agent-browser command found".to_string()
        } else {
            "agent-browser command not found".to_string()
        },
        if browser_cmd {
            None
        } else {
            Some("Run `npm install -g agent-browser && agent-browser install`.".to_string())
        },
    );
}

fn check_mcp_dependencies(report: &mut DoctorReport) {
    let data_root = match Config::load() {
        Ok(cfg) => cfg.data_root_dir(),
        Err(_) => PathBuf::from("./microclaw.data"),
    };

    let mcp_paths = collect_mcp_config_paths(&data_root);
    let existing_paths = mcp_paths
        .into_iter()
        .filter(|path| path.exists())
        .collect::<Vec<_>>();
    if existing_paths.is_empty() {
        report.push(
            "mcp.config",
            "MCP config",
            CheckStatus::Miss,
            format!(
                "{} and {} not found",
                data_root.join("mcp.json").display(),
                data_root.join("mcp.d").display()
            ),
            Some("Create mcp.json or mcp.d/*.json if you need MCP servers.".to_string()),
        );
        return;
    }

    let mut merged_servers: HashMap<String, crate::mcp::McpServerConfig> = HashMap::new();
    let mut loaded_sources = 0usize;
    for path in &existing_paths {
        let content = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(err) => {
                report.push(
                    "mcp.config",
                    "MCP config",
                    CheckStatus::Fail,
                    format!("failed reading {}: {err}", path.display()),
                    None,
                );
                continue;
            }
        };
        let parsed: McpConfig = match serde_json::from_str(&content) {
            Ok(cfg) => cfg,
            Err(err) => {
                report.push(
                    "mcp.config",
                    "MCP config",
                    CheckStatus::Fail,
                    format!("invalid JSON in {}: {err}", path.display()),
                    Some("Validate MCP JSON format and key names.".to_string()),
                );
                continue;
            }
        };
        loaded_sources += 1;
        for (name, server) in parsed.mcp_servers {
            merged_servers.insert(name, server);
        }
    }
    if loaded_sources == 0 {
        return;
    }

    report.push(
        "mcp.config",
        "MCP config",
        CheckStatus::Pass,
        format!(
            "loaded {} source file(s) with {} merged server(s)",
            loaded_sources,
            merged_servers.len()
        ),
        None,
    );

    let mut names = merged_servers.keys().cloned().collect::<Vec<_>>();
    names.sort();
    for name in names {
        let Some(server) = merged_servers.get(&name) else {
            continue;
        };
        let transport = server.transport.trim().to_ascii_lowercase();
        if transport == "streamable_http" || transport == "http" {
            if server.endpoint.trim().is_empty() {
                report.push(
                    format!("mcp.{name}.endpoint"),
                    format!("MCP server '{name}' endpoint"),
                    CheckStatus::Fail,
                    "endpoint is empty".to_string(),
                    Some("Set endpoint/url for streamable_http transport.".to_string()),
                );
            } else {
                report.push(
                    format!("mcp.{name}.endpoint"),
                    format!("MCP server '{name}' endpoint"),
                    CheckStatus::Pass,
                    server.endpoint.to_string(),
                    None,
                );
            }
            continue;
        }

        let command = server.command.trim();
        if command.is_empty() {
            report.push(
                format!("mcp.{name}.command"),
                format!("MCP server '{name}' command"),
                CheckStatus::Fail,
                "command is empty for stdio transport".to_string(),
                Some("Set command/args for stdio MCP server.".to_string()),
            );
            continue;
        }

        if command_exists(command) {
            report.push(
                format!("mcp.{name}.command"),
                format!("MCP server '{name}' command"),
                CheckStatus::Pass,
                format!("{command} found"),
                None,
            );
        } else {
            report.push(
                format!("mcp.{name}.command"),
                format!("MCP server '{name}' command"),
                CheckStatus::Fail,
                format!("{command} not found in PATH"),
                Some("Install the MCP command dependency or use absolute path.".to_string()),
            );
        }
    }
}

fn collect_mcp_config_paths(data_root: &Path) -> Vec<PathBuf> {
    let mut paths = vec![data_root.join("mcp.json")];
    let mcp_dir = data_root.join("mcp.d");
    let mut fragments = match std::fs::read_dir(&mcp_dir) {
        Ok(entries) => entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|s| s.to_str()) == Some("json"))
            .collect::<Vec<_>>(),
        Err(_) => Vec::new(),
    };
    fragments.sort();
    paths.extend(fragments);
    paths
}

fn check_sandbox_config(report: &mut DoctorReport) {
    let config = match Config::load() {
        Ok(cfg) => cfg,
        Err(err) => {
            report.push(
                "sandbox.config",
                "Sandbox config",
                CheckStatus::Warn,
                format!("config unavailable: {err}"),
                Some("Run `microclaw setup` first.".to_string()),
            );
            return;
        }
    };
    let mode_label = match config.sandbox.mode {
        SandboxMode::Off => "off",
        SandboxMode::All => "all",
    };
    report.push(
        "sandbox.mode",
        "Sandbox mode",
        if matches!(config.sandbox.mode, SandboxMode::All) {
            CheckStatus::Pass
        } else {
            CheckStatus::Warn
        },
        format!(
            "mode={} backend={:?} no_network={} require_runtime={}",
            mode_label,
            config.sandbox.backend,
            config.sandbox.no_network,
            config.sandbox.require_runtime
        ),
        if matches!(config.sandbox.mode, SandboxMode::Off) {
            Some("Enable quickly: `microclaw setup --enable-sandbox`.".to_string())
        } else {
            None
        },
    );
}

fn check_docker_runtime(report: &mut DoctorReport) {
    if !command_exists("docker") {
        report.push(
            "sandbox.docker_cli",
            "Docker CLI",
            CheckStatus::Fail,
            "docker command not found".to_string(),
            Some(
                "Install Docker Desktop or docker engine and ensure `docker` is in PATH."
                    .to_string(),
            ),
        );
        return;
    }
    report.push(
        "sandbox.docker_cli",
        "Docker CLI",
        CheckStatus::Pass,
        "docker command found".to_string(),
        None,
    );
    let output = std::process::Command::new("docker")
        .args(["info", "--format", "{{.ServerVersion}}"])
        .output();
    match output {
        Ok(out) if out.status.success() => {
            let version = String::from_utf8_lossy(&out.stdout).trim().to_string();
            report.push(
                "sandbox.docker_runtime",
                "Docker runtime",
                CheckStatus::Pass,
                format!("running (server={version})"),
                None,
            );
        }
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
            report.push(
                "sandbox.docker_runtime",
                "Docker runtime",
                CheckStatus::Fail,
                if err.is_empty() {
                    "docker info failed".to_string()
                } else {
                    format!("docker info failed: {err}")
                },
                Some("Start Docker runtime and verify local permissions.".to_string()),
            );
        }
        Err(err) => {
            report.push(
                "sandbox.docker_runtime",
                "Docker runtime",
                CheckStatus::Fail,
                format!("docker info failed: {err}"),
                Some("Start Docker runtime and verify local permissions.".to_string()),
            );
        }
    }
}

fn check_sandbox_image(report: &mut DoctorReport) {
    let config = match Config::load() {
        Ok(cfg) => cfg,
        Err(_) => return,
    };
    let image = config.sandbox.image.trim();
    if image.is_empty() {
        report.push(
            "sandbox.image",
            "Sandbox image",
            CheckStatus::Warn,
            "sandbox.image is empty".to_string(),
            Some("Set sandbox.image to a valid image tag (for example: ubuntu:25.10).".to_string()),
        );
        return;
    }
    if !command_exists("docker") {
        report.push(
            "sandbox.image",
            "Sandbox image",
            CheckStatus::Warn,
            format!("image={image} (docker unavailable, skipped image check)"),
            Some("Install/start Docker, then run `docker pull {image}`.".to_string()),
        );
        return;
    }
    let output = std::process::Command::new("docker")
        .args(["image", "inspect", image])
        .output();
    match output {
        Ok(out) if out.status.success() => report.push(
            "sandbox.image",
            "Sandbox image",
            CheckStatus::Pass,
            format!("{image} is available locally"),
            None,
        ),
        Ok(_) => report.push(
            "sandbox.image",
            "Sandbox image",
            CheckStatus::Warn,
            format!("{image} is not present locally"),
            Some(format!("Pull image: `docker pull {image}`")),
        ),
        Err(err) => report.push(
            "sandbox.image",
            "Sandbox image",
            CheckStatus::Warn,
            format!("failed to check image '{image}': {err}"),
            Some(format!("Pull image manually: `docker pull {image}`")),
        ),
    }
}

fn check_mount_allowlist(report: &mut DoctorReport) {
    let config = match Config::load() {
        Ok(cfg) => cfg,
        Err(_) => return,
    };
    let allowlist = config
        .sandbox
        .mount_allowlist_path
        .map(PathBuf::from)
        .or_else(default_mount_allowlist_path);
    let Some(path) = allowlist else {
        report.push(
            "sandbox.mount_allowlist",
            "Mount allowlist",
            CheckStatus::Miss,
            "no allowlist path configured".to_string(),
            Some("Set sandbox.mount_allowlist_path to an external file with one allowed root path per line.".to_string()),
        );
        return;
    };
    if path.exists() {
        let has_entries = std::fs::read_to_string(&path)
            .ok()
            .map(|s| {
                s.lines()
                    .map(str::trim)
                    .any(|line| !line.is_empty() && !line.starts_with('#'))
            })
            .unwrap_or(false);
        report.push(
            "sandbox.mount_allowlist",
            "Mount allowlist",
            if has_entries {
                CheckStatus::Pass
            } else {
                CheckStatus::Warn
            },
            format!("allowlist file: {}", path.display()),
            if has_entries {
                None
            } else {
                Some("Add at least one allowed root path to the allowlist file.".to_string())
            },
        );
    } else {
        report.push(
            "sandbox.mount_allowlist",
            "Mount allowlist",
            CheckStatus::Miss,
            format!("allowlist file not found: {}", path.display()),
            Some("Create the file and list one allowed root path per line.".to_string()),
        );
    }
}

fn default_mount_allowlist_path() -> Option<PathBuf> {
    user_home_dir().map(|h| h.join(".config/microclaw/mount-allowlist.txt"))
}

fn print_report(report: &DoctorReport) {
    println!("MicroClaw Doctor");
    println!(
        "Environment: os={} arch={} wsl={}",
        report.platform, report.arch, report.in_wsl
    );
    println!();

    let mut prev_optional: Option<bool> = None;
    for check in &report.checks {
        let is_optional = check.status == CheckStatus::Miss;
        if let Some(prev) = prev_optional {
            if prev != is_optional {
                println!();
            }
        }
        prev_optional = Some(is_optional);

        let id_label = if check.status == CheckStatus::Miss {
            format!("optional, {}", check.id)
        } else {
            check.id.clone()
        };

        println!(
            "[{} {:<4}] {:<28} ({}) {}",
            check.status.as_emoji(),
            check.status.as_label(),
            check.title,
            id_label,
            check.detail
        );
        if let Some(fix) = &check.fix {
            println!("        fix: {}", fix);
        }
    }

    let (pass, miss, warn, fail) = report.summary();
    println!();
    println!(
        "Summary: pass={} miss={} warn={} fail={}",
        pass, miss, warn, fail
    );
    if fail > 0 {
        println!("Doctor exit code: 2 (hard failures present)");
    } else {
        println!("Doctor exit code: 0");
    }
}

fn current_platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "unknown"
    }
}

fn is_wsl() -> bool {
    if !cfg!(target_os = "linux") {
        return false;
    }

    if std::env::var_os("WSL_INTEROP").is_some() || std::env::var_os("WSL_DISTRO_NAME").is_some() {
        return true;
    }

    if let Ok(content) = std::fs::read_to_string("/proc/version") {
        let lower = content.to_ascii_lowercase();
        return lower.contains("microsoft") || lower.contains("wsl");
    }

    false
}

fn user_home_dir() -> Option<PathBuf> {
    if cfg!(target_os = "windows") {
        std::env::var_os("USERPROFILE").map(PathBuf::from)
    } else {
        std::env::var_os("HOME").map(PathBuf::from)
    }
}

fn path_contains(dir: &Path) -> bool {
    let Ok(path_var) = std::env::var("PATH") else {
        return false;
    };

    let want = normalize_path_for_compare(dir);
    for entry in std::env::split_paths(&path_var) {
        if normalize_path_for_compare(&entry) == want {
            return true;
        }
    }
    false
}

fn normalize_path_for_compare(path: &Path) -> String {
    let s = path
        .to_string_lossy()
        .trim()
        .trim_end_matches(['/', '\\'])
        .to_string();
    if cfg!(target_os = "windows") {
        s.to_ascii_lowercase()
    } else {
        s
    }
}

fn command_exists(command: &str) -> bool {
    if command.trim().is_empty() {
        return false;
    }

    let path_var = std::env::var_os("PATH").unwrap_or_default();

    #[cfg(target_os = "windows")]
    let candidates: Vec<String> = {
        let exts = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into());
        let ext_list: Vec<String> = exts
            .split(';')
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();

        let mut out = vec![command.to_string()];
        let lower = command.to_ascii_lowercase();
        if !ext_list.iter().any(|ext| lower.ends_with(ext)) {
            for ext in ext_list {
                out.push(format!("{command}{ext}"));
            }
        }
        out
    };

    #[cfg(not(target_os = "windows"))]
    let candidates: Vec<String> = vec![command.to_string()];

    for base in std::env::split_paths(&path_var) {
        for candidate in &candidates {
            let full = base.join(candidate);
            if full.is_file() {
                return true;
            }
        }
    }
    false
}

fn detect_execution_policy() -> Result<String, String> {
    if !cfg!(target_os = "windows") {
        return Ok("NotApplicable".to_string());
    }

    let output = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-ExecutionPolicy -Scope CurrentUser",
        ])
        .output()
        .map_err(|e| e.to_string())?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn classify_execution_policy(policy: &str) -> (CheckStatus, String, Option<String>) {
    let p = policy.trim().to_ascii_lowercase();
    match p.as_str() {
        "remotesigned" | "allsigned" | "bypass" | "unrestricted" => {
            (CheckStatus::Pass, format!("CurrentUser={policy}"), None)
        }
        "undefined" => (
            CheckStatus::Warn,
            format!("CurrentUser={policy}"),
            Some(
                "Set execution policy: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`"
                    .into(),
            ),
        ),
        "restricted" => (
            CheckStatus::Fail,
            format!("CurrentUser={policy}"),
            Some("Run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` in PowerShell.".into()),
        ),
        _ => (
            CheckStatus::Warn,
            format!("CurrentUser={policy}"),
            Some("Verify policy allows running local install scripts.".into()),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use chrono::Utc;

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::test_support::env_lock()
    }

    #[test]
    fn test_classify_execution_policy_restricted() {
        let (status, detail, fix) = classify_execution_policy("Restricted");
        assert_eq!(status, CheckStatus::Fail);
        assert!(detail.contains("Restricted"));
        assert!(fix.unwrap().contains("RemoteSigned"));
    }

    #[test]
    fn test_classify_execution_policy_remotesigned() {
        let (status, _detail, fix) = classify_execution_policy("RemoteSigned");
        assert_eq!(status, CheckStatus::Pass);
        assert!(fix.is_none());
    }

    #[test]
    fn test_normalize_path_compare() {
        let p = PathBuf::from("/tmp/abc/");
        let normalized = normalize_path_for_compare(&p);
        assert!(!normalized.ends_with('/'));
    }

    #[test]
    fn test_build_sandbox_report_has_mode_check() {
        let _guard = env_lock();
        let path = std::env::temp_dir().join(format!(
            "microclaw_doctor_test_{}.yaml",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let cfg = Config::test_defaults();
        cfg.save_yaml(path.to_string_lossy().as_ref()).unwrap();
        std::env::set_var("MICROCLAW_CONFIG", &path);
        let report = build_sandbox_report();
        std::env::remove_var("MICROCLAW_CONFIG");
        let _ = std::fs::remove_file(path);
        assert!(report.checks.iter().any(|c| c.id == "sandbox.mode"));
    }

    #[test]
    fn test_migrate_channels_to_accounts_telegram_and_discord() {
        let mut cfg = Config::test_defaults();
        cfg.telegram_bot_token = "tg_token".to_string();
        cfg.bot_username = "tg_bot".to_string();
        cfg.allowed_groups = vec![1, 2];
        cfg.discord_bot_token = Some("dc_token".to_string());
        cfg.discord_allowed_channels = vec![10, 20];
        cfg.discord_no_mention = true;
        cfg.channels.clear();

        let changed = migrate_channels_to_accounts(&mut cfg);
        assert_eq!(changed, 2);

        let telegram = cfg.channels.get("telegram").unwrap();
        let telegram_default = telegram
            .get("default_account")
            .and_then(|v| v.as_str())
            .unwrap();
        assert_eq!(telegram_default, "main");
        let telegram_account = telegram
            .get("accounts")
            .and_then(|v| v.get("main"))
            .unwrap();
        assert_eq!(
            telegram_account
                .get("bot_token")
                .and_then(|v| v.as_str())
                .unwrap(),
            "tg_token"
        );
        assert_eq!(
            telegram_account
                .get("bot_username")
                .and_then(|v| v.as_str())
                .unwrap(),
            "tg_bot"
        );
        assert!(telegram_account
            .get("allowed_groups")
            .and_then(|v| v.as_sequence())
            .is_some());

        let discord = cfg.channels.get("discord").unwrap();
        let discord_account = discord.get("accounts").and_then(|v| v.get("main")).unwrap();
        assert_eq!(
            discord_account
                .get("bot_token")
                .and_then(|v| v.as_str())
                .unwrap(),
            "dc_token"
        );
        assert!(discord_account
            .get("allowed_channels")
            .and_then(|v| v.as_sequence())
            .is_some());
        assert!(discord_account
            .get("no_mention")
            .and_then(|v| v.as_bool())
            .unwrap_or(false));

        assert!(cfg.telegram_bot_token.is_empty());
        assert!(cfg.discord_bot_token.is_none());
        assert!(cfg.allowed_groups.is_empty());
        assert!(cfg.discord_allowed_channels.is_empty());
        assert!(!cfg.discord_no_mention);
    }

    #[test]
    fn test_migrate_channels_to_accounts_is_idempotent() {
        let mut cfg = Config::test_defaults();
        cfg.channels = serde_yaml::from_str(
            r#"
telegram:
  enabled: true
  default_account: "ops"
  accounts:
    ops:
      enabled: true
      bot_token: "already"
"#,
        )
        .unwrap();
        cfg.telegram_bot_token = String::new();

        let changed = migrate_channels_to_accounts(&mut cfg);
        assert_eq!(changed, 0);
        let telegram = cfg.channels.get("telegram").unwrap();
        assert_eq!(
            telegram
                .get("accounts")
                .and_then(|v| v.get("ops"))
                .and_then(|v| v.get("bot_token"))
                .and_then(|v| v.as_str()),
            Some("already")
        );
    }
}
