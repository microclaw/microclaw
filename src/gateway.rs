use crate::config::Config;
use crate::logging;
use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use serde_json::json;
use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Command;

const LINUX_SERVICE_NAME: &str = "microclaw-gateway.service";
const MAC_LABEL: &str = "ai.microclaw.gateway";
const LOG_STDOUT_FILE: &str = "microclaw-gateway.log";
const LOG_STDERR_FILE: &str = "microclaw-gateway.error.log";
const DEFAULT_LOG_LINES: usize = 200;

#[derive(Debug, Clone)]
struct ServiceContext {
    exe_path: PathBuf,
    working_dir: PathBuf,
    config_path: Option<PathBuf>,
    runtime_logs_dir: PathBuf,
    service_env: BTreeMap<String, String>,
}

#[derive(Debug, Default)]
struct InstallOptions {
    force: bool,
}

#[derive(Debug, Default)]
struct StatusOptions {
    json: bool,
    deep: bool,
}

#[derive(Debug, Default)]
struct MacRuntimeStatus {
    state: Option<String>,
    pid: Option<i64>,
    last_exit_status: Option<i64>,
    last_exit_reason: Option<String>,
}

#[derive(Debug, Default)]
struct LinuxRuntimeStatus {
    load_state: Option<String>,
    active_state: Option<String>,
    sub_state: Option<String>,
    main_pid: Option<i64>,
    exec_main_status: Option<i64>,
    exec_main_code: Option<String>,
    fragment_path: Option<String>,
}

pub fn handle_gateway_cli(args: &[String]) -> Result<()> {
    let cli = match GatewayCli::try_parse_from(
        std::iter::once("gateway").chain(args.iter().map(std::string::String::as_str)),
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
    let Some(action) = cli.action else {
        print_gateway_help();
        return Ok(());
    };

    match action {
        GatewayAction::Install { force } => install(InstallOptions { force }),
        GatewayAction::Uninstall => uninstall(),
        GatewayAction::Start => start(),
        GatewayAction::Stop => stop(),
        GatewayAction::Restart => restart(),
        GatewayAction::Status { json, deep } => status(StatusOptions { json, deep }),
        GatewayAction::Logs { lines } => logs(lines),
    }
}

pub fn print_gateway_help() {
    println!(
        r#"Gateway service management

USAGE:
    microclaw gateway <ACTION>

ACTIONS:
    install [--force]           Install and enable persistent gateway service
    uninstall                   Disable and remove persistent gateway service
    start                       Start gateway service
    stop                        Stop gateway service
    restart                     Restart gateway service
    status [--json] [--deep]    Show gateway service status
    logs [N]                    Show last N lines of gateway logs (default: 200)
"#
    );
}

#[derive(Debug, Parser)]
#[command(
    name = "microclaw gateway",
    about = "Gateway service management",
    disable_help_subcommand = true
)]
struct GatewayCli {
    #[command(subcommand)]
    action: Option<GatewayAction>,
}

#[derive(Debug, Subcommand)]
enum GatewayAction {
    /// Install and enable persistent gateway service
    Install {
        /// Force reinstall and overwrite existing service files
        #[arg(long)]
        force: bool,
    },
    /// Disable and remove persistent gateway service
    Uninstall,
    /// Start gateway service
    Start,
    /// Stop gateway service
    Stop,
    /// Restart gateway service
    Restart,
    /// Show gateway service status
    Status {
        /// Print machine-readable JSON status
        #[arg(long)]
        json: bool,
        /// Run deeper service audits
        #[arg(long)]
        deep: bool,
    },
    /// Show last N lines of gateway logs (default: 200)
    Logs { lines: Option<usize> },
}

fn install(opts: InstallOptions) -> Result<()> {
    let ctx = build_context()?;
    if cfg!(target_os = "macos") {
        install_macos(&ctx, &opts)
    } else if cfg!(target_os = "linux") {
        install_linux(&ctx, &opts)
    } else {
        Err(anyhow!(
            "Gateway service is only supported on macOS and Linux"
        ))
    }
}

fn uninstall() -> Result<()> {
    if cfg!(target_os = "macos") {
        uninstall_macos()
    } else if cfg!(target_os = "linux") {
        uninstall_linux()
    } else {
        Err(anyhow!(
            "Gateway service is only supported on macOS and Linux"
        ))
    }
}

fn start() -> Result<()> {
    if cfg!(target_os = "macos") {
        start_macos()
    } else if cfg!(target_os = "linux") {
        start_linux()
    } else {
        Err(anyhow!(
            "Gateway service is only supported on macOS and Linux"
        ))
    }
}

fn stop() -> Result<()> {
    if cfg!(target_os = "macos") {
        stop_macos()
    } else if cfg!(target_os = "linux") {
        stop_linux()
    } else {
        Err(anyhow!(
            "Gateway service is only supported on macOS and Linux"
        ))
    }
}

fn restart() -> Result<()> {
    if cfg!(target_os = "macos") {
        restart_macos()
    } else if cfg!(target_os = "linux") {
        restart_linux()
    } else {
        Err(anyhow!(
            "Gateway service is only supported on macOS and Linux"
        ))
    }
}

fn status(opts: StatusOptions) -> Result<()> {
    let ctx = build_context()?;

    if cfg!(target_os = "macos") {
        status_macos(&ctx, &opts)
    } else if cfg!(target_os = "linux") {
        status_linux(&ctx, &opts)
    } else {
        Err(anyhow!(
            "Gateway service is only supported on macOS and Linux"
        ))
    }
}

fn logs(lines: Option<usize>) -> Result<()> {
    let lines = parse_log_lines(lines)?;
    let ctx = build_context()?;
    println!("== gateway logs: {} ==", ctx.runtime_logs_dir.display());
    let tailed = logging::read_last_lines_from_logs(&ctx.runtime_logs_dir, lines)?;
    if tailed.is_empty() {
        println!("(no log lines found)");
    } else {
        println!("{}", tailed.join("\n"));
    }
    Ok(())
}

fn parse_log_lines(lines: Option<usize>) -> Result<usize> {
    let parsed = lines.unwrap_or(DEFAULT_LOG_LINES);
    if parsed == 0 {
        return Err(anyhow!("Log line count must be greater than 0"));
    }
    Ok(parsed)
}

fn build_context() -> Result<ServiceContext> {
    let exe_path = std::env::current_exe().context("Failed to resolve current binary path")?;
    let working_dir = std::env::current_dir().context("Failed to resolve current directory")?;
    let config_path = resolve_config_path(&working_dir);
    let runtime_logs_dir = resolve_runtime_logs_dir(&working_dir);
    let service_env = build_service_env(config_path.as_ref());

    Ok(ServiceContext {
        exe_path,
        working_dir,
        config_path,
        runtime_logs_dir,
        service_env,
    })
}

fn resolve_config_path(cwd: &Path) -> Option<PathBuf> {
    if let Ok(from_env) = std::env::var("MICROCLAW_CONFIG") {
        let path = PathBuf::from(from_env);
        return Some(if path.is_absolute() {
            path
        } else {
            cwd.join(path)
        });
    }

    for candidate in ["microclaw.config.yaml", "microclaw.config.yml"] {
        let path = cwd.join(candidate);
        if path.exists() {
            return Some(path);
        }
    }
    None
}

fn resolve_runtime_logs_dir(cwd: &Path) -> PathBuf {
    match Config::load() {
        Ok(cfg) => PathBuf::from(cfg.runtime_data_dir()).join("logs"),
        Err(_) => cwd.join("runtime").join("logs"),
    }
}

fn build_service_env(config_path: Option<&PathBuf>) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    env.insert("MICROCLAW_GATEWAY".to_string(), "1".to_string());

    if let Some(path) = config_path {
        env.insert(
            "MICROCLAW_CONFIG".to_string(),
            path.to_string_lossy().to_string(),
        );
    }

    if let Ok(home) = std::env::var("HOME") {
        if !home.trim().is_empty() {
            env.insert("HOME".to_string(), home.clone());
            let mut parts: Vec<String> = vec![
                format!("{home}/.local/bin"),
                format!("{home}/.npm-global/bin"),
                format!("{home}/bin"),
                format!("{home}/.volta/bin"),
                format!("{home}/.asdf/shims"),
                format!("{home}/.bun/bin"),
            ];

            for var in [
                "PNPM_HOME",
                "NPM_CONFIG_PREFIX",
                "BUN_INSTALL",
                "VOLTA_HOME",
                "ASDF_DATA_DIR",
            ] {
                if let Ok(value) = std::env::var(var) {
                    let trimmed = value.trim();
                    if !trimmed.is_empty() {
                        if var == "NPM_CONFIG_PREFIX" || var == "BUN_INSTALL" || var == "VOLTA_HOME"
                        {
                            parts.push(format!("{trimmed}/bin"));
                        } else if var == "ASDF_DATA_DIR" {
                            parts.push(format!("{trimmed}/shims"));
                        } else {
                            parts.push(trimmed.to_string());
                        }
                    }
                }
            }

            for sys in ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin"] {
                parts.push(sys.to_string());
            }

            let mut dedup = Vec::new();
            for p in parts {
                if !p.is_empty() && !dedup.iter().any(|v: &String| v == &p) {
                    dedup.push(p);
                }
            }
            env.insert("PATH".to_string(), dedup.join(":"));
        }
    }

    let tmpdir = std::env::var("TMPDIR")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| std::env::temp_dir().to_string_lossy().to_string());
    env.insert("TMPDIR".to_string(), tmpdir);

    env
}

fn run_command(cmd: &str, args: &[&str]) -> Result<std::process::Output> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("Failed to execute command: {} {}", cmd, args.join(" ")))?;
    Ok(output)
}

fn ensure_success(output: std::process::Output, cmd: &str, args: &[&str]) -> Result<()> {
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    Err(anyhow!(
        "Command failed: {} {}\nstdout: {}\nstderr: {}",
        cmd,
        args.join(" "),
        stdout.trim(),
        stderr.trim()
    ))
}

fn assert_command_exists(cmd: &str) -> Result<()> {
    match Command::new(cmd).arg("--help").output() {
        Ok(_) => Ok(()),
        Err(err) if err.kind() == ErrorKind::NotFound => {
            Err(anyhow!("Required command not found: {}", cmd))
        }
        Err(_) => Ok(()),
    }
}

fn assert_systemd_user_available() -> Result<()> {
    assert_command_exists("systemctl")?;
    let output = run_command("systemctl", &["--user", "status"])?;
    if output.status.success() {
        return Ok(());
    }

    let detail = format!(
        "{} {}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    )
    .trim()
    .to_string();

    if detail.to_lowercase().contains("not found") {
        return Err(anyhow!(
            "systemctl is not available; systemd user services are required"
        ));
    }

    Err(anyhow!("systemctl --user unavailable: {}", detail))
}

fn linux_unit_path() -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home)
        .join(".config")
        .join("systemd")
        .join("user")
        .join(LINUX_SERVICE_NAME))
}

fn assert_no_line_breaks(value: &str, label: &str) -> Result<()> {
    if value.contains('\n') || value.contains('\r') {
        return Err(anyhow!("{} cannot contain CR or LF", label));
    }
    Ok(())
}

fn systemd_escape_arg(value: &str) -> Result<String> {
    assert_no_line_breaks(value, "Systemd unit value")?;
    if !value
        .chars()
        .any(|ch| ch.is_whitespace() || ch == '"' || ch == '\\')
    {
        return Ok(value.to_string());
    }

    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    Ok(format!("\"{}\"", escaped))
}

fn render_linux_unit(ctx: &ServiceContext) -> Result<String> {
    let mut unit = String::new();
    unit.push_str("[Unit]\n");
    unit.push_str("Description=MicroClaw Gateway Service\n");
    unit.push_str("After=network-online.target\n");
    unit.push_str("Wants=network-online.target\n\n");
    unit.push_str("[Service]\n");
    unit.push_str("Type=simple\n");
    unit.push_str(&format!(
        "WorkingDirectory={}\n",
        systemd_escape_arg(&ctx.working_dir.to_string_lossy())?
    ));

    let exec_args = [
        ctx.exe_path.to_string_lossy().to_string(),
        "start".to_string(),
    ];
    let escaped_exec = exec_args
        .iter()
        .map(|s| systemd_escape_arg(s))
        .collect::<Result<Vec<_>>>()?
        .join(" ");
    unit.push_str(&format!("ExecStart={}\n", escaped_exec));

    for (key, value) in &ctx.service_env {
        assert_no_line_breaks(key, "Systemd environment variable name")?;
        assert_no_line_breaks(value, "Systemd environment variable value")?;
        let kv = format!("{}={}", key, value);
        unit.push_str(&format!("Environment={}\n", systemd_escape_arg(&kv)?));
    }

    unit.push_str("Restart=always\n");
    unit.push_str("RestartSec=5\n");
    unit.push_str("KillMode=process\n\n");
    unit.push_str("[Install]\n");
    unit.push_str("WantedBy=default.target\n");
    Ok(unit)
}

fn install_linux(ctx: &ServiceContext, opts: &InstallOptions) -> Result<()> {
    assert_systemd_user_available()?;

    let unit_path = linux_unit_path()?;
    if unit_path.exists() && !opts.force {
        println!(
            "Gateway service already installed at {}. Use --force to reinstall.",
            unit_path.display()
        );
        return Ok(());
    }

    let unit_dir = unit_path
        .parent()
        .ok_or_else(|| anyhow!("Invalid unit path"))?;
    std::fs::create_dir_all(unit_dir)
        .with_context(|| format!("Failed to create {}", unit_dir.display()))?;
    std::fs::create_dir_all(&ctx.runtime_logs_dir)
        .with_context(|| format!("Failed to create {}", ctx.runtime_logs_dir.display()))?;

    std::fs::write(&unit_path, render_linux_unit(ctx)?)
        .with_context(|| format!("Failed to write {}", unit_path.display()))?;

    ensure_success(
        run_command("systemctl", &["--user", "daemon-reload"])?,
        "systemctl",
        &["--user", "daemon-reload"],
    )?;
    ensure_success(
        run_command(
            "systemctl",
            &["--user", "enable", "--now", LINUX_SERVICE_NAME],
        )?,
        "systemctl",
        &["--user", "enable", "--now", LINUX_SERVICE_NAME],
    )?;

    println!(
        "Installed and started gateway service: {}",
        unit_path.display()
    );
    Ok(())
}

fn uninstall_linux() -> Result<()> {
    assert_systemd_user_available()?;

    let _ = run_command(
        "systemctl",
        &["--user", "disable", "--now", LINUX_SERVICE_NAME],
    );
    let _ = run_command("systemctl", &["--user", "daemon-reload"]);

    let unit_path = linux_unit_path()?;
    if unit_path.exists() {
        std::fs::remove_file(&unit_path)
            .with_context(|| format!("Failed to remove {}", unit_path.display()))?;
    }
    let _ = run_command("systemctl", &["--user", "daemon-reload"]);
    println!("Uninstalled gateway service");
    Ok(())
}

fn start_linux() -> Result<()> {
    assert_systemd_user_available()?;
    ensure_success(
        run_command("systemctl", &["--user", "start", LINUX_SERVICE_NAME])?,
        "systemctl",
        &["--user", "start", LINUX_SERVICE_NAME],
    )?;
    println!("Gateway service started");
    Ok(())
}

fn stop_linux() -> Result<()> {
    assert_systemd_user_available()?;
    ensure_success(
        run_command("systemctl", &["--user", "stop", LINUX_SERVICE_NAME])?,
        "systemctl",
        &["--user", "stop", LINUX_SERVICE_NAME],
    )?;
    println!("Gateway service stopped");
    Ok(())
}

fn restart_linux() -> Result<()> {
    assert_systemd_user_available()?;
    ensure_success(
        run_command("systemctl", &["--user", "restart", LINUX_SERVICE_NAME])?,
        "systemctl",
        &["--user", "restart", LINUX_SERVICE_NAME],
    )?;
    println!("Gateway service restarted");
    Ok(())
}

fn parse_key_values(output: &str) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    for line in output.lines() {
        if let Some((k, v)) = line.split_once('=') {
            values.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    values
}

fn parse_linux_runtime_status(output: &str) -> LinuxRuntimeStatus {
    let map = parse_key_values(output);
    LinuxRuntimeStatus {
        load_state: map.get("LoadState").cloned(),
        active_state: map.get("ActiveState").cloned(),
        sub_state: map.get("SubState").cloned(),
        main_pid: map.get("MainPID").and_then(|v| v.parse::<i64>().ok()),
        exec_main_status: map
            .get("ExecMainStatus")
            .and_then(|v| v.parse::<i64>().ok()),
        exec_main_code: map.get("ExecMainCode").cloned(),
        fragment_path: map.get("FragmentPath").cloned(),
    }
}

fn audit_linux_unit(ctx: &ServiceContext, runtime: &LinuxRuntimeStatus) -> Vec<String> {
    let unit_path = runtime
        .fragment_path
        .as_ref()
        .filter(|p| !p.trim().is_empty())
        .map(PathBuf::from)
        .or_else(|| linux_unit_path().ok());

    let Some(unit_path) = unit_path else {
        return vec!["Unable to locate systemd unit file for drift audit".to_string()];
    };

    let content = match std::fs::read_to_string(&unit_path) {
        Ok(c) => c,
        Err(err) => {
            return vec![format!(
                "Failed to read systemd unit for drift audit ({}): {}",
                unit_path.display(),
                err
            )]
        }
    };

    let mut issues = Vec::new();
    if !content.contains("After=network-online.target") {
        issues.push("Missing After=network-online.target".to_string());
    }
    if !content.contains("Wants=network-online.target") {
        issues.push("Missing Wants=network-online.target".to_string());
    }
    if !content.contains("RestartSec=5") {
        issues.push("Missing or non-default RestartSec=5".to_string());
    }
    if !content.contains("KillMode=process") {
        issues.push("Missing KillMode=process".to_string());
    }

    let expected_exec = format!(
        "ExecStart={} start",
        systemd_escape_arg(&ctx.exe_path.to_string_lossy()).unwrap_or_default()
    );
    if !content.contains(&expected_exec) {
        issues.push("Service ExecStart does not match current microclaw binary".to_string());
    }

    if let Some(config_path) = &ctx.config_path {
        let config_kv = format!("MICROCLAW_CONFIG={}", config_path.display());
        if !content.contains(&config_kv) {
            issues.push("Service MICROCLAW_CONFIG differs from current config path".to_string());
        }
    }

    issues
}

fn print_linux_status_text(
    runtime: &LinuxRuntimeStatus,
    issues: &[String],
    raw_status: Option<&str>,
    deep: bool,
) {
    println!("Gateway service: linux/systemd");
    println!(
        "  load_state: {}",
        runtime
            .load_state
            .clone()
            .unwrap_or_else(|| "unknown".to_string())
    );
    println!(
        "  active_state: {}",
        runtime
            .active_state
            .clone()
            .unwrap_or_else(|| "unknown".to_string())
    );
    println!(
        "  sub_state: {}",
        runtime
            .sub_state
            .clone()
            .unwrap_or_else(|| "unknown".to_string())
    );
    if let Some(pid) = runtime.main_pid {
        if pid > 0 {
            println!("  main_pid: {}", pid);
        }
    }
    if let Some(code) = &runtime.exec_main_code {
        println!("  exec_main_code: {}", code);
    }
    if let Some(status) = runtime.exec_main_status {
        println!("  exec_main_status: {}", status);
    }

    if issues.is_empty() {
        println!("  drift_audit: clean");
    } else {
        println!("  drift_audit: {} issue(s)", issues.len());
        for issue in issues {
            println!("    - {}", issue);
        }
    }

    if deep {
        if let Some(raw) = raw_status {
            println!("\n-- systemctl status --");
            println!("{}", raw.trim_end());
        }
    }
}

fn status_linux(ctx: &ServiceContext, opts: &StatusOptions) -> Result<()> {
    assert_systemd_user_available()?;

    let show = run_command(
        "systemctl",
        &[
            "--user",
            "show",
            LINUX_SERVICE_NAME,
            "--property=LoadState,ActiveState,SubState,MainPID,ExecMainStatus,ExecMainCode,FragmentPath",
            "--no-pager",
        ],
    )?;

    let show_text = format!(
        "{}{}",
        String::from_utf8_lossy(&show.stdout),
        String::from_utf8_lossy(&show.stderr)
    );
    let runtime = parse_linux_runtime_status(&show_text);
    let issues = audit_linux_unit(ctx, &runtime);

    let deep_output = if opts.deep {
        let output = run_command(
            "systemctl",
            &["--user", "status", LINUX_SERVICE_NAME, "--no-pager"],
        )?;
        Some(format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ))
    } else {
        None
    };

    let running = runtime.active_state.as_deref() == Some("active");

    if opts.json {
        let value = json!({
            "platform": "linux",
            "service": LINUX_SERVICE_NAME,
            "running": running,
            "load_state": runtime.load_state,
            "active_state": runtime.active_state,
            "sub_state": runtime.sub_state,
            "main_pid": runtime.main_pid,
            "exec_main_code": runtime.exec_main_code,
            "exec_main_status": runtime.exec_main_status,
            "fragment_path": runtime.fragment_path,
            "drift_issues": issues,
            "deep_status": deep_output,
        });
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        print_linux_status_text(&runtime, &issues, deep_output.as_deref(), opts.deep);
    }

    if running {
        Ok(())
    } else {
        Err(anyhow!("Gateway service is not running"))
    }
}

fn mac_plist_path() -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home)
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{MAC_LABEL}.plist")))
}

fn current_uid() -> Result<String> {
    if let Ok(uid) = std::env::var("UID") {
        if !uid.trim().is_empty() {
            return Ok(uid);
        }
    }
    let output = run_command("id", &["-u"])?;
    if !output.status.success() {
        return Err(anyhow!("Failed to determine user id"));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn render_macos_plist(ctx: &ServiceContext) -> String {
    let mut items = vec![
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>".to_string(),
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">".to_string(),
        "<plist version=\"1.0\">".to_string(),
        "<dict>".to_string(),
        "  <key>Label</key>".to_string(),
        format!("  <string>{MAC_LABEL}</string>"),
        "  <key>ProgramArguments</key>".to_string(),
        "  <array>".to_string(),
        format!("    <string>{}</string>", xml_escape(&ctx.exe_path.to_string_lossy())),
        "    <string>start</string>".to_string(),
        "  </array>".to_string(),
        "  <key>WorkingDirectory</key>".to_string(),
        format!(
            "  <string>{}</string>",
            xml_escape(&ctx.working_dir.to_string_lossy())
        ),
        "  <key>RunAtLoad</key>".to_string(),
        "  <true/>".to_string(),
        "  <key>KeepAlive</key>".to_string(),
        "  <true/>".to_string(),
        "  <key>StandardOutPath</key>".to_string(),
        format!(
            "  <string>{}</string>",
            xml_escape(&ctx.runtime_logs_dir.join(LOG_STDOUT_FILE).to_string_lossy())
        ),
        "  <key>StandardErrorPath</key>".to_string(),
        format!(
            "  <string>{}</string>",
            xml_escape(&ctx.runtime_logs_dir.join(LOG_STDERR_FILE).to_string_lossy())
        ),
    ];

    items.push("  <key>EnvironmentVariables</key>".to_string());
    items.push("  <dict>".to_string());
    for (key, value) in &ctx.service_env {
        items.push(format!("    <key>{}</key>", xml_escape(key)));
        items.push(format!("    <string>{}</string>", xml_escape(value)));
    }
    items.push("  </dict>".to_string());

    items.push("</dict>".to_string());
    items.push("</plist>".to_string());
    items.join("\n")
}

fn xml_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn mac_target_label() -> Result<String> {
    let uid = current_uid()?;
    Ok(format!("gui/{uid}/{MAC_LABEL}"))
}

fn install_macos(ctx: &ServiceContext, opts: &InstallOptions) -> Result<()> {
    assert_command_exists("launchctl")?;

    let plist_path = mac_plist_path()?;
    if plist_path.exists() && !opts.force {
        println!(
            "Gateway service already installed at {}. Use --force to reinstall.",
            plist_path.display()
        );
        return Ok(());
    }

    let launch_agents = plist_path
        .parent()
        .ok_or_else(|| anyhow!("Invalid plist path"))?;
    std::fs::create_dir_all(launch_agents)
        .with_context(|| format!("Failed to create {}", launch_agents.display()))?;
    std::fs::create_dir_all(&ctx.runtime_logs_dir)
        .with_context(|| format!("Failed to create {}", ctx.runtime_logs_dir.display()))?;

    std::fs::write(&plist_path, render_macos_plist(ctx))
        .with_context(|| format!("Failed to write {}", plist_path.display()))?;

    let _ = stop_macos();
    start_macos()?;
    println!(
        "Installed and started gateway service: {}",
        plist_path.display()
    );
    Ok(())
}

fn uninstall_macos() -> Result<()> {
    assert_command_exists("launchctl")?;

    let _ = stop_macos();
    let plist_path = mac_plist_path()?;
    if plist_path.exists() {
        std::fs::remove_file(&plist_path)
            .with_context(|| format!("Failed to remove {}", plist_path.display()))?;
    }
    println!("Uninstalled gateway service");
    Ok(())
}

fn start_macos() -> Result<()> {
    assert_command_exists("launchctl")?;

    let target = mac_target_label()?;
    let plist_path = mac_plist_path()?;
    if !plist_path.exists() {
        return Err(anyhow!(
            "Service not installed. Run: microclaw gateway install"
        ));
    }
    let gui_target = format!("gui/{}", current_uid()?);
    let plist_path_str = plist_path.to_string_lossy().to_string();
    let bootstrap = run_command("launchctl", &["bootstrap", &gui_target, &plist_path_str])?;
    if !bootstrap.status.success() {
        let stderr = String::from_utf8_lossy(&bootstrap.stderr);
        if !(stderr.contains("already loaded") || stderr.contains("already exists")) {
            return Err(anyhow!(
                "Command failed: launchctl bootstrap {} {}\nstderr: {}",
                gui_target,
                plist_path_str,
                stderr.trim()
            ));
        }
    }

    ensure_success(
        run_command("launchctl", &["kickstart", "-k", &target])?,
        "launchctl",
        &["kickstart", "-k", &target],
    )?;
    println!("Gateway service started");
    Ok(())
}

fn stop_macos() -> Result<()> {
    assert_command_exists("launchctl")?;

    let target = mac_target_label()?;
    let output = run_command("launchctl", &["bootout", &target])?;
    if output.status.success() {
        println!("Gateway service stopped");
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("No such process")
        || stderr.contains("Could not find specified service")
        || stderr.contains("not found")
    {
        return Ok(());
    }

    Err(anyhow!(
        "Failed to stop service: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

fn restart_macos() -> Result<()> {
    start_macos()?;
    println!("Gateway service restarted");
    Ok(())
}

fn parse_macos_runtime_status(output: &str) -> MacRuntimeStatus {
    let mut status = MacRuntimeStatus::default();
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some((key, value)) = trimmed.split_once("=") {
            let key = key.trim().to_lowercase();
            let value = value.trim().trim_end_matches(';').to_string();
            match key.as_str() {
                "state" => status.state = Some(value),
                "pid" => status.pid = value.parse::<i64>().ok(),
                "last exit status" => status.last_exit_status = value.parse::<i64>().ok(),
                "last exit reason" => status.last_exit_reason = Some(value),
                _ => {}
            }
        }
    }
    status
}

fn audit_macos_plist(ctx: &ServiceContext) -> Vec<String> {
    let plist_path = match mac_plist_path() {
        Ok(path) => path,
        Err(err) => {
            return vec![format!("Unable to resolve LaunchAgent plist path: {}", err)];
        }
    };

    let content = match std::fs::read_to_string(&plist_path) {
        Ok(c) => c,
        Err(err) => {
            return vec![format!(
                "Failed to read LaunchAgent plist for drift audit ({}): {}",
                plist_path.display(),
                err
            )]
        }
    };

    let mut issues = Vec::new();
    if !plist_key_has_true(&content, "RunAtLoad") {
        issues.push("LaunchAgent is missing RunAtLoad=true".to_string());
    }
    if !plist_key_has_true(&content, "KeepAlive") {
        issues.push("LaunchAgent is missing KeepAlive=true".to_string());
    }

    let stdout_path = ctx
        .runtime_logs_dir
        .join(LOG_STDOUT_FILE)
        .to_string_lossy()
        .to_string();
    if !content.contains(&stdout_path) {
        issues.push("StandardOutPath does not match runtime logs directory".to_string());
    }

    let stderr_path = ctx
        .runtime_logs_dir
        .join(LOG_STDERR_FILE)
        .to_string_lossy()
        .to_string();
    if !content.contains(&stderr_path) {
        issues.push("StandardErrorPath does not match runtime logs directory".to_string());
    }

    issues
}

fn plist_key_has_true(content: &str, key: &str) -> bool {
    let pattern = format!("<key>{}</key>", key);
    let Some(pos) = content.find(&pattern) else {
        return false;
    };
    content[pos..].contains("<true/>")
}

fn print_macos_status_text(
    runtime: &MacRuntimeStatus,
    issues: &[String],
    raw_status: Option<&str>,
    deep: bool,
) {
    println!("Gateway service: macOS/launchd");
    println!(
        "  state: {}",
        runtime
            .state
            .clone()
            .unwrap_or_else(|| "unknown".to_string())
    );
    if let Some(pid) = runtime.pid {
        if pid > 0 {
            println!("  pid: {}", pid);
        }
    }
    if let Some(status) = runtime.last_exit_status {
        println!("  last_exit_status: {}", status);
    }
    if let Some(reason) = &runtime.last_exit_reason {
        println!("  last_exit_reason: {}", reason);
    }

    if issues.is_empty() {
        println!("  drift_audit: clean");
    } else {
        println!("  drift_audit: {} issue(s)", issues.len());
        for issue in issues {
            println!("    - {}", issue);
        }
    }

    if deep {
        if let Some(raw) = raw_status {
            println!("\n-- launchctl print --");
            println!("{}", raw.trim_end());
        }
    }
}

fn status_macos(ctx: &ServiceContext, opts: &StatusOptions) -> Result<()> {
    assert_command_exists("launchctl")?;

    let target = mac_target_label()?;
    let output = run_command("launchctl", &["print", &target])?;
    let raw = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let runtime = parse_macos_runtime_status(&raw);
    let issues = audit_macos_plist(ctx);
    let running = runtime
        .state
        .as_ref()
        .map(|s| s.eq_ignore_ascii_case("running"))
        .unwrap_or(false)
        || runtime.pid.unwrap_or(0) > 0;

    let deep_raw = if opts.deep { Some(raw.clone()) } else { None };

    if opts.json {
        let value = json!({
            "platform": "macos",
            "label": MAC_LABEL,
            "running": running,
            "state": runtime.state,
            "pid": runtime.pid,
            "last_exit_status": runtime.last_exit_status,
            "last_exit_reason": runtime.last_exit_reason,
            "drift_issues": issues,
            "deep_status": deep_raw,
        });
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        print_macos_status_text(&runtime, &issues, deep_raw.as_deref(), opts.deep);
    }

    if running {
        Ok(())
    } else {
        Err(anyhow!("Gateway service is not running"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ctx() -> ServiceContext {
        let mut service_env = BTreeMap::new();
        service_env.insert("MICROCLAW_GATEWAY".to_string(), "1".to_string());
        service_env.insert(
            "MICROCLAW_CONFIG".to_string(),
            "/tmp/microclaw/microclaw.config.yaml".to_string(),
        );

        ServiceContext {
            exe_path: PathBuf::from("/usr/local/bin/microclaw"),
            working_dir: PathBuf::from("/tmp/microclaw"),
            config_path: Some(PathBuf::from("/tmp/microclaw/microclaw.config.yaml")),
            runtime_logs_dir: PathBuf::from("/tmp/microclaw/runtime/logs"),
            service_env,
        }
    }

    #[test]
    fn test_xml_escape() {
        let input = "a&b<c>d\"e'f";
        let escaped = xml_escape(input);
        assert_eq!(escaped, "a&amp;b&lt;c&gt;d&quot;e&apos;f");
    }

    #[test]
    fn test_systemd_escape_arg() {
        assert_eq!(systemd_escape_arg("abc").unwrap(), "abc");
        assert_eq!(
            systemd_escape_arg("/path with spaces/bin").unwrap(),
            "\"/path with spaces/bin\""
        );
        assert!(systemd_escape_arg("a\nb").is_err());
    }

    #[test]
    fn test_render_linux_unit_contains_expected_fields() {
        let unit = render_linux_unit(&test_ctx()).unwrap();
        assert!(unit.contains("After=network-online.target"));
        assert!(unit.contains("Wants=network-online.target"));
        assert!(unit.contains("Restart=always"));
        assert!(unit.contains("RestartSec=5"));
        assert!(unit.contains("KillMode=process"));
        assert!(unit.contains("ExecStart=/usr/local/bin/microclaw start"));
        assert!(unit.contains("Environment=MICROCLAW_GATEWAY=1"));
        assert!(unit.contains("MICROCLAW_CONFIG=/tmp/microclaw/microclaw.config.yaml"));
    }

    #[test]
    fn test_render_macos_plist_contains_required_fields() {
        let ctx = test_ctx();
        let plist = render_macos_plist(&ctx);
        let normalized = plist.replace('\\', "/");
        assert!(plist.contains("<key>Label</key>"));
        assert!(plist.contains(MAC_LABEL));
        assert!(plist.contains("<string>start</string>"));
        assert!(plist.contains("MICROCLAW_GATEWAY"));
        assert!(plist.contains("MICROCLAW_CONFIG"));
        assert!(normalized.contains("/tmp/microclaw/runtime/logs/microclaw-gateway.log"));
        assert!(normalized.contains("/tmp/microclaw/runtime/logs/microclaw-gateway.error.log"));
    }

    #[test]
    fn test_parse_log_lines_default_and_custom() {
        assert_eq!(parse_log_lines(None).unwrap(), DEFAULT_LOG_LINES);
        assert_eq!(parse_log_lines(Some(20)).unwrap(), 20);
        assert!(parse_log_lines(Some(0)).is_err());
    }

    #[test]
    fn test_parse_options_with_clap() {
        let install =
            GatewayCli::try_parse_from(["gateway", "install", "--force"]).expect("parse install");
        match install.action {
            Some(GatewayAction::Install { force }) => assert!(force),
            _ => panic!("expected install action"),
        }
        assert!(GatewayCli::try_parse_from(["gateway", "install", "--bad"]).is_err());

        let status = GatewayCli::try_parse_from(["gateway", "status", "--json", "--deep"])
            .expect("parse status");
        match status.action {
            Some(GatewayAction::Status { json, deep }) => {
                assert!(json);
                assert!(deep);
            }
            _ => panic!("expected status action"),
        }
        assert!(GatewayCli::try_parse_from(["gateway", "status", "--bad"]).is_err());
    }

    #[test]
    fn test_parse_linux_runtime_status() {
        let status = parse_linux_runtime_status(
            "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=123\nExecMainStatus=0\nExecMainCode=exited\n",
        );
        assert_eq!(status.load_state.as_deref(), Some("loaded"));
        assert_eq!(status.active_state.as_deref(), Some("active"));
        assert_eq!(status.sub_state.as_deref(), Some("running"));
        assert_eq!(status.main_pid, Some(123));
        assert_eq!(status.exec_main_status, Some(0));
        assert_eq!(status.exec_main_code.as_deref(), Some("exited"));
    }

    #[test]
    fn test_parse_macos_runtime_status() {
        let status = parse_macos_runtime_status(
            "state = running\npid = 99\nlast exit status = 0\nlast exit reason = exited\n",
        );
        assert_eq!(status.state.as_deref(), Some("running"));
        assert_eq!(status.pid, Some(99));
        assert_eq!(status.last_exit_status, Some(0));
        assert_eq!(status.last_exit_reason.as_deref(), Some("exited"));
    }

    #[test]
    fn test_resolve_runtime_logs_dir_fallback() {
        let dir = resolve_runtime_logs_dir(Path::new("/tmp/microclaw"));
        assert!(
            dir.ends_with("runtime/logs") || dir.ends_with("microclaw.data/runtime/logs"),
            "unexpected logs dir: {}",
            dir.display()
        );
    }
}
