use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::config::Config;
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
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!(
            "Usage: microclaw doctor [--json]\n\nChecks PATH, shell/runtime dependencies, browser automation prerequisites, and MCP command dependencies."
        );
        return Ok(());
    }

    let report = build_report();

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

    let mcp_path = data_root.join("mcp.json");
    if !mcp_path.exists() {
        report.push(
            "mcp.config",
            "MCP config",
            CheckStatus::Miss,
            format!("{} not found", mcp_path.display()),
            Some("Create mcp.json if you need MCP servers.".to_string()),
        );
        return;
    }

    let content = match std::fs::read_to_string(&mcp_path) {
        Ok(s) => s,
        Err(err) => {
            report.push(
                "mcp.config",
                "MCP config",
                CheckStatus::Fail,
                format!("failed reading {}: {err}", mcp_path.display()),
                None,
            );
            return;
        }
    };

    let parsed: McpConfig = match serde_json::from_str(&content) {
        Ok(cfg) => cfg,
        Err(err) => {
            report.push(
                "mcp.config",
                "MCP config",
                CheckStatus::Fail,
                format!("invalid JSON in {}: {err}", mcp_path.display()),
                Some("Validate mcp.json format and key names.".to_string()),
            );
            return;
        }
    };

    report.push(
        "mcp.config",
        "MCP config",
        CheckStatus::Pass,
        format!(
            "loaded {} with {} server(s)",
            mcp_path.display(),
            parsed.mcp_servers.len()
        ),
        None,
    );

    for (name, server) in &parsed.mcp_servers {
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
}
