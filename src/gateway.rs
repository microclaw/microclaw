use crate::config::Config;
use crate::logging;
use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};
use tokio_tungstenite::tungstenite::Message;

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const LINUX_SERVICE_NAME: &str = "microclaw-gateway.service";
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const MAC_LABEL: &str = "ai.microclaw.gateway";
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const WINDOWS_SERVICE_NAME: &str = "MicroClawGateway";
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const WINDOWS_SERVICE_DISPLAY_NAME: &str = "MicroClaw Gateway";
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const WINDOWS_SERVICE_DESCRIPTION: &str = "MicroClaw Gateway Service";
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const WINDOWS_SERVICE_STATE_STOPPED: i64 = 1;
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const WINDOWS_SERVICE_STATE_RUNNING: i64 = 4;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const LOG_STDOUT_FILE: &str = "microclaw-gateway.log";
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const LOG_STDERR_FILE: &str = "microclaw-gateway.error.log";
const DEFAULT_LOG_LINES: usize = 200;

#[derive(Debug, Clone)]
struct ServiceContext {
    exe_path: PathBuf,
    working_dir: PathBuf,
    config_path: Option<PathBuf>,
    runtime_logs_dir: PathBuf,
    #[cfg_attr(target_os = "windows", allow(dead_code))]
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

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
#[derive(Debug, Default)]
struct MacRuntimeStatus {
    state: Option<String>,
    pid: Option<i64>,
    last_exit_status: Option<i64>,
    last_exit_reason: Option<String>,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, Default)]
struct LinuxRuntimeStatus {
    load_state: Option<String>,
    active_state: Option<String>,
    sub_state: Option<String>,
    main_pid: Option<i64>,
    exec_main_status: Option<i64>,
    exec_main_code: Option<String>,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fragment_path: Option<String>,
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
#[derive(Debug, Default)]
struct WindowsRuntimeStatus {
    installed: bool,
    state: Option<String>,
    state_code: Option<i64>,
    pid: Option<i64>,
    start_type: Option<String>,
    start_type_code: Option<i64>,
    binary_path_name: Option<String>,
    service_start_name: Option<String>,
    display_name: Option<String>,
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct WindowsServiceLaunchInfo {
    executable_path: Option<PathBuf>,
    config_path: Option<PathBuf>,
    working_dir: Option<PathBuf>,
    is_service_run: bool,
}

#[derive(Debug)]
struct GatewayCallOptions {
    method: String,
    params: String,
    timeout_ms: u64,
    json: bool,
}

#[derive(Debug, Serialize)]
struct GatewayConnectRequest<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    id: &'a str,
    method: &'static str,
    params: GatewayConnectParams<'a>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GatewayConnectParams<'a> {
    min_protocol: u64,
    max_protocol: u64,
    auth: GatewayConnectAuth<'a>,
}

#[derive(Debug, Serialize)]
struct GatewayConnectAuth<'a> {
    token: &'a str,
}

#[derive(Debug, Serialize)]
struct GatewayRpcRequest {
    #[serde(rename = "type")]
    kind: &'static str,
    id: &'static str,
    method: String,
    params: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct GatewayRpcError {
    code: Option<String>,
    message: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GatewayRpcFrame {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    event: Option<String>,
    #[serde(default)]
    ok: Option<bool>,
    #[serde(default)]
    payload: Option<serde_json::Value>,
    #[serde(default)]
    error: Option<GatewayRpcError>,
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
        GatewayAction::Call {
            method,
            params,
            timeout,
            json,
        } => call(GatewayCallOptions {
            method,
            params,
            timeout_ms: timeout,
            json,
        }),
        GatewayAction::ServiceRun { .. } => run_windows_service_host(),
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
    call <METHOD>               Call gateway RPC over the local/configured WebSocket bridge
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
    /// Call gateway RPC over the configured bridge
    Call {
        /// RPC method name
        method: String,
        /// JSON params object
        #[arg(long, default_value = "{}")]
        params: String,
        /// Timeout in milliseconds
        #[arg(long, default_value_t = 10_000)]
        timeout: u64,
        /// Print machine-readable JSON output
        #[arg(long)]
        json: bool,
    },
    #[command(hide = true)]
    ServiceRun {
        #[arg(long, value_name = "PATH")]
        working_dir: Option<PathBuf>,
    },
}

fn call(opts: GatewayCallOptions) -> Result<()> {
    let payload = if let Ok(handle) = tokio::runtime::Handle::try_current() {
        tokio::task::block_in_place(|| handle.block_on(call_async(&opts)))?
    } else {
        let runtime = tokio::runtime::Runtime::new().context("failed to create tokio runtime")?;
        runtime.block_on(call_async(&opts))?
    };
    if opts.json {
        println!("{}", serde_json::to_string(&payload)?);
    } else {
        println!("{}", serde_json::to_string_pretty(&payload)?);
    }
    Ok(())
}

async fn call_async(opts: &GatewayCallOptions) -> Result<serde_json::Value> {
    let ws_url = resolve_gateway_call_ws_url()?;
    let token = resolve_gateway_call_token()?;
    let params: serde_json::Value = serde_json::from_str(&opts.params)
        .with_context(|| format!("invalid JSON for --params: {}", opts.params))?;
    let timeout = Duration::from_millis(opts.timeout_ms.max(1_000));

    crate::tls::ensure_rustls_crypto_provider()
        .map_err(anyhow::Error::msg)
        .context("failed to initialize rustls crypto provider")?;

    let (mut ws, _) = tokio::time::timeout(timeout, tokio_tungstenite::connect_async(&ws_url))
        .await
        .context("gateway websocket connect timed out")?
        .context("failed to connect to gateway websocket")?;

    let challenge = tokio::time::timeout(timeout, recv_gateway_frame(&mut ws))
        .await
        .context("timed out waiting for connect.challenge")??;
    if challenge.kind != "event" || challenge.event.as_deref() != Some("connect.challenge") {
        return Err(anyhow!(
            "expected connect.challenge, got type={} event={:?}",
            challenge.kind,
            challenge.event
        ));
    }

    let connect = GatewayConnectRequest {
        kind: "req",
        id: "connect-1",
        method: "connect",
        params: GatewayConnectParams {
            min_protocol: 3,
            max_protocol: 3,
            auth: GatewayConnectAuth { token: &token },
        },
    };
    ws.send(Message::Text(serde_json::to_string(&connect)?))
        .await
        .context("failed to send gateway connect frame")?;

    let hello = tokio::time::timeout(timeout, recv_gateway_frame(&mut ws))
        .await
        .context("timed out waiting for gateway hello")??;
    if hello.kind != "res" || hello.ok != Some(true) {
        return Err(anyhow!(format_gateway_error(
            "gateway connect failed",
            hello.error.as_ref()
        )));
    }

    let request = GatewayRpcRequest {
        kind: "req",
        id: "call-1",
        method: opts.method.clone(),
        params,
    };
    ws.send(Message::Text(serde_json::to_string(&request)?))
        .await
        .with_context(|| format!("failed to send gateway method '{}'", opts.method))?;

    loop {
        let frame = tokio::time::timeout(timeout, recv_gateway_frame(&mut ws))
            .await
            .with_context(|| format!("timed out waiting for gateway method '{}'", opts.method))??;
        if frame.kind != "res" || frame.id.as_deref() != Some("call-1") {
            continue;
        }
        if frame.ok == Some(true) {
            return Ok(frame.payload.unwrap_or_else(|| json!({})));
        }
        return Err(anyhow!(format_gateway_error(
            &format!("gateway method '{}' failed", opts.method),
            frame.error.as_ref()
        )));
    }
}

async fn recv_gateway_frame(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> Result<GatewayRpcFrame> {
    while let Some(message) = ws.next().await {
        let message = message.context("gateway websocket read failed")?;
        match message {
            Message::Text(text) => {
                let frame: GatewayRpcFrame =
                    serde_json::from_str(&text).context("invalid gateway websocket JSON")?;
                return Ok(frame);
            }
            Message::Binary(bytes) => {
                let frame: GatewayRpcFrame = serde_json::from_slice(&bytes)
                    .context("invalid binary gateway websocket JSON")?;
                return Ok(frame);
            }
            Message::Ping(_) | Message::Pong(_) => continue,
            Message::Close(_) => return Err(anyhow!("gateway websocket closed")),
            _ => continue,
        }
    }
    Err(anyhow!("gateway websocket closed"))
}

fn resolve_gateway_call_ws_url() -> Result<String> {
    if let Some(raw) = env_string(&[
        "MICROCLAW_GATEWAY_URL",
        "OPENCLAW_GATEWAY_URL",
        "GATEWAY_URL",
    ]) {
        return Ok(normalize_gateway_ws_url(&raw));
    }

    let cfg = Config::load().ok();
    let host = env_string(&[
        "MICROCLAW_GATEWAY_HOST",
        "OPENCLAW_GATEWAY_HOST",
        "GATEWAY_HOST",
    ])
    .unwrap_or_else(|| "127.0.0.1".to_string());
    let port = env_string(&[
        "MICROCLAW_GATEWAY_PORT",
        "OPENCLAW_GATEWAY_PORT",
        "GATEWAY_PORT",
    ])
    .and_then(|s| s.parse::<u16>().ok())
    .or_else(|| cfg.as_ref().map(|c| c.web_port))
    .unwrap_or(10961);
    Ok(format!("ws://{host}:{port}/"))
}

fn resolve_gateway_call_token() -> Result<String> {
    env_string(&[
        "MICROCLAW_GATEWAY_TOKEN",
        "OPENCLAW_GATEWAY_TOKEN",
        "GATEWAY_TOKEN",
        "MICROCLAW_API_KEY",
    ])
    .ok_or_else(|| {
        anyhow!(
            "missing gateway token; set MICROCLAW_GATEWAY_TOKEN, OPENCLAW_GATEWAY_TOKEN, or GATEWAY_TOKEN"
        )
    })
}

fn env_string(keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        std::env::var(key)
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    })
}

fn normalize_gateway_ws_url(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('/');
    if let Some(rest) = trimmed.strip_prefix("http://") {
        return format!("ws://{rest}/");
    }
    if let Some(rest) = trimmed.strip_prefix("https://") {
        return format!("wss://{rest}/");
    }
    if trimmed.starts_with("ws://") || trimmed.starts_with("wss://") {
        return format!("{trimmed}/");
    }
    format!("ws://{trimmed}/")
}

fn format_gateway_error(prefix: &str, err: Option<&GatewayRpcError>) -> String {
    match err {
        Some(err) => match (&err.code, &err.message) {
            (Some(code), Some(message)) => format!("{prefix}: {code}: {message}"),
            (_, Some(message)) => format!("{prefix}: {message}"),
            (Some(code), None) => format!("{prefix}: {code}"),
            (None, None) => prefix.to_string(),
        },
        None => prefix.to_string(),
    }
}

fn install(opts: InstallOptions) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let ctx = build_context()?;
        install_macos(&ctx, &opts)
    }
    #[cfg(target_os = "linux")]
    {
        let ctx = build_context()?;
        install_linux(&ctx, &opts)
    }
    #[cfg(target_os = "windows")]
    {
        let ctx = build_context()?;
        install_windows(&ctx, &opts)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Err(anyhow!(
            "Gateway service is only supported on macOS, Linux, and Windows"
        ))
    }
}

fn uninstall() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        uninstall_macos()
    }
    #[cfg(target_os = "linux")]
    {
        uninstall_linux()
    }
    #[cfg(target_os = "windows")]
    {
        uninstall_windows()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Err(anyhow!(
            "Gateway service is only supported on macOS, Linux, and Windows"
        ))
    }
}

fn start() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        start_macos()
    }
    #[cfg(target_os = "linux")]
    {
        start_linux()
    }
    #[cfg(target_os = "windows")]
    {
        start_windows()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Err(anyhow!(
            "Gateway service is only supported on macOS, Linux, and Windows"
        ))
    }
}

fn stop() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        stop_macos()
    }
    #[cfg(target_os = "linux")]
    {
        stop_linux()
    }
    #[cfg(target_os = "windows")]
    {
        stop_windows()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Err(anyhow!(
            "Gateway service is only supported on macOS, Linux, and Windows"
        ))
    }
}

fn restart() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        restart_macos()
    }
    #[cfg(target_os = "linux")]
    {
        restart_linux()
    }
    #[cfg(target_os = "windows")]
    {
        restart_windows()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Err(anyhow!(
            "Gateway service is only supported on macOS, Linux, and Windows"
        ))
    }
}

fn status(opts: StatusOptions) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let ctx = build_context()?;
        status_macos(&ctx, &opts)
    }
    #[cfg(target_os = "linux")]
    {
        let ctx = build_context()?;
        status_linux(&ctx, &opts)
    }
    #[cfg(target_os = "windows")]
    {
        let ctx = build_context()?;
        status_windows(&ctx, &opts)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Err(anyhow!(
            "Gateway service is only supported on macOS, Linux, and Windows"
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
    let current_dir = std::env::current_dir().context("Failed to resolve current directory")?;
    #[cfg(target_os = "windows")]
    let (working_dir, config_path) = {
        let mut working_dir = current_dir.clone();
        let mut config_path = resolve_config_path(&current_dir);
        if config_path.is_none() {
            if let Some(launch) = resolve_windows_installed_service_launch_info() {
                if let Some(installed_working_dir) = launch.working_dir {
                    working_dir = installed_working_dir;
                }
                config_path = launch.config_path;
            }
        }
        (working_dir, config_path)
    };
    #[cfg(not(target_os = "windows"))]
    let (working_dir, config_path) = (current_dir.clone(), resolve_config_path(&current_dir));
    let runtime_logs_dir = resolve_runtime_logs_dir(&working_dir, config_path.as_deref());
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

fn load_config_from_path(path: &Path) -> Result<Config> {
    let path_str = path.to_string_lossy().to_string();
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    let mut config: Config = serde_yaml::from_str(&content)
        .with_context(|| format!("Failed to parse {}", path.display()))?;
    config
        .post_deserialize()
        .map_err(|e| anyhow!("Failed to normalize {}: {}", path_str, e))?;
    Ok(config)
}

fn resolve_runtime_logs_dir(cwd: &Path, config_path: Option<&Path>) -> PathBuf {
    if let Some(path) = config_path {
        if let Ok(cfg) = load_config_from_path(path) {
            return PathBuf::from(cfg.runtime_data_dir()).join("logs");
        }
    }

    match Config::load() {
        Ok(cfg) => PathBuf::from(cfg.runtime_data_dir()).join("logs"),
        Err(_) => cwd.join("runtime").join("logs"),
    }
}

#[cfg_attr(target_os = "windows", allow(dead_code))]
fn build_service_env(config_path: Option<&PathBuf>) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    env.insert("MICROCLAW_GATEWAY".to_string(), "1".to_string());

    if let Some(path) = config_path {
        env.insert(
            "MICROCLAW_CONFIG".to_string(),
            path.to_string_lossy().to_string(),
        );
    }

    if let Ok(rust_log) = std::env::var("RUST_LOG") {
        if !rust_log.trim().is_empty() {
            env.insert("RUST_LOG".to_string(), rust_log);
        }
    }

    if cfg!(windows) {
        for key in [
            "PATH",
            "HOME",
            "USERPROFILE",
            "HOMEDRIVE",
            "HOMEPATH",
            "APPDATA",
            "LOCALAPPDATA",
            "PROGRAMDATA",
            "SystemRoot",
            "COMSPEC",
            "PATHEXT",
        ] {
            if let Ok(value) = std::env::var(key) {
                if !value.trim().is_empty() {
                    env.insert(key.to_string(), value);
                }
            }
        }

        let tempdir = std::env::temp_dir().to_string_lossy().to_string();
        env.insert("TMP".to_string(), tempdir.clone());
        env.insert("TEMP".to_string(), tempdir.clone());
        env.insert("TMPDIR".to_string(), tempdir);
        return env;
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

#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
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

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
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

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn linux_unit_path() -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home)
        .join(".config")
        .join("systemd")
        .join("user")
        .join(LINUX_SERVICE_NAME))
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn assert_no_line_breaks(value: &str, label: &str) -> Result<()> {
    if value.contains('\n') || value.contains('\r') {
        return Err(anyhow!("{} cannot contain CR or LF", label));
    }
    Ok(())
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
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

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn linux_pid_file_path() -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home).join(".microclaw").join("microclaw.pid"))
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn linux_check_script_path() -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home)
        .join(".microclaw")
        .join("check-single.sh"))
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn render_linux_unit(ctx: &ServiceContext) -> Result<String> {
    let pid_file = linux_pid_file_path()?;
    let check_script = linux_check_script_path()?;

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

    // Single instance protection - check before start
    unit.push_str(&format!(
        "ExecStartPre={}\n",
        systemd_escape_arg(&check_script.to_string_lossy())?
    ));

    let mut exec_args = vec![
        ctx.exe_path.to_string_lossy().to_string(),
        "start".to_string(),
    ];
    if let Some(config_path) = &ctx.config_path {
        exec_args.push("--config".to_string());
        exec_args.push(config_path.to_string_lossy().to_string());
    }
    let escaped_exec = exec_args
        .iter()
        .map(|s| systemd_escape_arg(s))
        .collect::<Result<Vec<_>>>()?
        .join(" ");
    unit.push_str(&format!("ExecStart={}\n", escaped_exec));

    // Write PID file after start
    unit.push_str(&format!(
        "ExecStartPost=/bin/sh -c 'echo $MAINPID > {}'\n",
        pid_file.to_string_lossy()
    ));

    // Cleanup PID file after stop
    unit.push_str(&format!(
        "ExecStopPost=/bin/rm -f {}\n",
        pid_file.to_string_lossy()
    ));

    for (key, value) in &ctx.service_env {
        assert_no_line_breaks(key, "Systemd environment variable name")?;
        assert_no_line_breaks(value, "Systemd environment variable value")?;
        let kv = format!("{}={}", key, value);
        unit.push_str(&format!("Environment={}\n", systemd_escape_arg(&kv)?));
    }

    // PID file for single instance control
    unit.push_str(&format!(
        "PIDFile={}\n",
        systemd_escape_arg(&pid_file.to_string_lossy())?
    ));

    // Smarter restart policy - only restart on failure, with rate limiting
    unit.push_str("Restart=on-failure\n");
    unit.push_str("RestartSec=10\n");
    unit.push_str("StartLimitInterval=60\n");
    unit.push_str("StartLimitBurst=3\n");

    // Ensure processes are properly killed
    unit.push_str("KillMode=mixed\n");
    unit.push_str("KillSignal=SIGTERM\n");
    unit.push_str("TimeoutStopSec=10\n\n");

    unit.push_str("[Install]\n");
    unit.push_str("WantedBy=default.target\n");
    Ok(unit)
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
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

    // Create single instance check script
    let check_script_path = linux_check_script_path()?;
    let pid_file_path = linux_pid_file_path()?;

    // Ensure .microclaw directory exists
    if let Some(parent) = check_script_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    let check_script_content = format!(
        r###"#!/bin/bash
# Single instance check for MicroClaw Gateway
# Auto-generated by `microclaw gateway install`

PID_FILE="{}"
MAX_WAIT=10

# Check if PID file exists and process is running
if [ -f "$PID_FILE" ]; then
    OLD_PID=$(cat "$PID_FILE")
    if ps -p "$OLD_PID" > /dev/null 2>&1; then
        # Check if this is a systemd restart - give the old process time to exit
        WAIT_COUNT=0
        while [ $WAIT_COUNT -lt $MAX_WAIT ]; do
            if ! ps -p "$OLD_PID" > /dev/null 2>&1; then
                # Process has exited, we can proceed
                break
            fi
            sleep 1
            WAIT_COUNT=$((WAIT_COUNT + 1))
        done

        # If process is still running after wait, it's a real duplicate
        if ps -p "$OLD_PID" > /dev/null 2>&1; then
            echo "MicroClaw is already running (PID: $OLD_PID)"
            echo "To prevent duplicate instances (which cause Telegram long polling conflicts),"
            echo "this service will not start until the existing instance is stopped."
            exit 1
        fi
    fi
fi

# Double check with pgrep - but give time for old process to exit
WAIT_COUNT=0
while [ $WAIT_COUNT -lt $MAX_WAIT ]; do
    if ! pgrep -x "microclaw" > /dev/null 2>&1; then
        # No process found, we can proceed
        exit 0
    fi
    sleep 1
    WAIT_COUNT=$((WAIT_COUNT + 1))
done

# If process is still running after max wait
echo "Found microclaw process already running (waited 10s for it to exit)"
exit 1
"###,
        pid_file_path.to_string_lossy()
    );

    std::fs::write(&check_script_path, check_script_content)
        .with_context(|| format!("Failed to write {}", check_script_path.display()))?;

    // Make script executable
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&check_script_path, std::fs::Permissions::from_mode(0o755))
        .with_context(|| format!("Failed to make {} executable", check_script_path.display()))?;

    println!("Created single instance protection script: {}", check_script_path.display());

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

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
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

    // Cleanup single instance protection files
    let check_script_path = linux_check_script_path()?;
    let pid_file_path = linux_pid_file_path()?;

    if check_script_path.exists() {
        std::fs::remove_file(&check_script_path).ok();
        println!("Removed single instance protection script");
    }

    if pid_file_path.exists() {
        std::fs::remove_file(&pid_file_path).ok();
    }

    let _ = run_command("systemctl", &["--user", "daemon-reload"]);
    println!("Uninstalled gateway service");
    Ok(())
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
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

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
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

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
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

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_key_values(output: &str) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    for line in output.lines() {
        if let Some((k, v)) = line.split_once('=') {
            values.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    values
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn parse_colon_key_values(output: &str) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    for line in output.lines() {
        if let Some((k, v)) = line.split_once(':') {
            values.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    values
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn parse_numbered_state(value: Option<&String>) -> (Option<i64>, Option<String>) {
    let Some(value) = value else {
        return (None, None);
    };

    let mut parts = value.split_whitespace();
    let code = parts.next().and_then(|v| v.parse::<i64>().ok());
    let state = parts.collect::<Vec<_>>().join(" ");
    let state = if state.is_empty() { None } else { Some(state) };
    (code, state)
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
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

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
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
    if !content.contains("RestartSec=10") {
        issues.push("Missing or non-default RestartSec=10".to_string());
    }
    if !content.contains("KillMode=mixed") {
        issues.push("Missing KillMode=mixed".to_string());
    }
    if !content.contains("PIDFile=") {
        issues.push("Missing PIDFile for single instance control".to_string());
    }
    if !content.contains("ExecStartPre=") {
        issues.push("Missing ExecStartPre single instance check".to_string());
    }
    if !content.contains("StartLimitInterval=60") {
        issues.push("Missing StartLimitInterval=60 rate limiting".to_string());
    }
    if !content.contains("StartLimitBurst=3") {
        issues.push("Missing StartLimitBurst=3 rate limiting".to_string());
    }
    if !content.contains("Restart=on-failure") {
        issues.push("Restart policy should be 'on-failure', not 'always'".to_string());
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

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
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

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
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

#[cfg(windows)]
fn legacy_windows_service_root() -> PathBuf {
    std::env::var("ProgramData")
        .or_else(|_| std::env::var("PROGRAMDATA"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(r"C:\ProgramData"))
        .join("MicroClaw")
        .join("gateway")
}

#[cfg(windows)]
fn legacy_windows_wrapper_exe_path() -> PathBuf {
    legacy_windows_service_root().join(format!("{WINDOWS_SERVICE_NAME}.exe"))
}

#[cfg(windows)]
fn legacy_windows_wrapper_xml_path() -> PathBuf {
    legacy_windows_service_root().join(format!("{WINDOWS_SERVICE_NAME}.xml"))
}

#[cfg(windows)]
fn cleanup_legacy_windows_wrapper_artifacts() -> Result<()> {
    for path in [
        legacy_windows_wrapper_exe_path(),
        legacy_windows_wrapper_xml_path(),
    ] {
        if path.exists() {
            std::fs::remove_file(&path)
                .with_context(|| format!("Failed to remove {}", path.display()))?;
        }
    }
    Ok(())
}

#[cfg(windows)]
fn resolve_windows_installed_service_launch_info() -> Option<WindowsServiceLaunchInfo> {
    let output = run_command("sc.exe", &["qc", WINDOWS_SERVICE_NAME]).ok()?;
    if windows_service_missing(&output) {
        return None;
    }
    let qc = parse_windows_runtime_status("", &windows_service_text(&output));
    let binary_path = qc.binary_path_name?;
    Some(parse_windows_service_launch_info(&binary_path))
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn parse_windows_command_line(command_line: &str) -> Vec<String> {
    let chars: Vec<char> = command_line.chars().collect();
    let mut args = Vec::new();
    let mut index = 0usize;

    while index < chars.len() {
        while index < chars.len() && chars[index].is_whitespace() {
            index += 1;
        }
        if index >= chars.len() {
            break;
        }

        let mut arg = String::new();
        let mut in_quotes = false;
        let mut backslashes = 0usize;

        while index < chars.len() {
            let ch = chars[index];
            if ch == '\\' {
                backslashes += 1;
                index += 1;
                continue;
            }
            if ch == '"' {
                arg.push_str(&"\\".repeat(backslashes / 2));
                if backslashes.is_multiple_of(2) {
                    if in_quotes && index + 1 < chars.len() && chars[index + 1] == '"' {
                        arg.push('"');
                        index += 1;
                    } else {
                        in_quotes = !in_quotes;
                    }
                } else {
                    arg.push('"');
                }
                backslashes = 0;
                index += 1;
                continue;
            }
            if backslashes > 0 {
                arg.push_str(&"\\".repeat(backslashes));
                backslashes = 0;
            }
            if ch.is_whitespace() && !in_quotes {
                break;
            }
            arg.push(ch);
            index += 1;
        }

        if backslashes > 0 {
            arg.push_str(&"\\".repeat(backslashes));
        }
        args.push(arg);

        while index < chars.len() && chars[index].is_whitespace() {
            index += 1;
        }
    }

    args
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn extract_windows_flag_path(args: &[String], flag: &str) -> Option<PathBuf> {
    let mut index = 0usize;
    while index < args.len() {
        let arg = &args[index];
        if arg == flag {
            if let Some(value) = args.get(index + 1) {
                return Some(PathBuf::from(value));
            }
        } else if let Some(value) = arg.strip_prefix(&(flag.to_string() + "=")) {
            if !value.trim().is_empty() {
                return Some(PathBuf::from(value));
            }
        }
        index += 1;
    }
    None
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn parse_windows_service_launch_info(command_line: &str) -> WindowsServiceLaunchInfo {
    let args = parse_windows_command_line(command_line);
    let executable_path = args.first().map(PathBuf::from);
    let is_service_run = args
        .windows(2)
        .any(|window| window[0] == "gateway" && window[1] == "service-run");

    WindowsServiceLaunchInfo {
        executable_path,
        config_path: extract_windows_flag_path(&args, "--config"),
        working_dir: extract_windows_flag_path(&args, "--working-dir"),
        is_service_run,
    }
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn windows_service_missing(output: &std::process::Output) -> bool {
    if output.status.code() == Some(1060) {
        return true;
    }

    let detail = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
    .to_lowercase();

    detail.contains("1060") || detail.contains("does not exist as an installed service")
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn windows_service_text(output: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn parse_windows_runtime_status(query_output: &str, qc_output: &str) -> WindowsRuntimeStatus {
    let query = parse_colon_key_values(query_output);
    let qc = parse_colon_key_values(qc_output);
    let (state_code, state) = parse_numbered_state(query.get("STATE"));
    let (start_type_code, start_type) = parse_numbered_state(qc.get("START_TYPE"));
    WindowsRuntimeStatus {
        installed: !query.is_empty() || !qc.is_empty(),
        state,
        state_code,
        pid: query.get("PID").and_then(|v| v.parse::<i64>().ok()),
        start_type,
        start_type_code,
        binary_path_name: qc.get("BINARY_PATH_NAME").cloned(),
        service_start_name: qc.get("SERVICE_START_NAME").cloned(),
        display_name: qc.get("DISPLAY_NAME").cloned(),
    }
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn wait_for_windows_service_state(expected_state: i64, timeout_secs: u64) -> Result<()> {
    let started = Instant::now();
    loop {
        let output = run_command("sc.exe", &["queryex", WINDOWS_SERVICE_NAME])?;
        if windows_service_missing(&output) {
            return Err(anyhow!("Gateway service is not installed"));
        }
        let runtime = parse_windows_runtime_status(&windows_service_text(&output), "");
        if runtime.state_code == Some(expected_state) {
            return Ok(());
        }

        if started.elapsed() >= Duration::from_secs(timeout_secs) {
            return Err(anyhow!(
                "Timed out waiting for Windows service to reach state {}",
                expected_state
            ));
        }
        thread::sleep(Duration::from_millis(500));
    }
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn wait_for_windows_service_removed(timeout_secs: u64) -> Result<()> {
    let started = Instant::now();
    loop {
        let output = run_command("sc.exe", &["queryex", WINDOWS_SERVICE_NAME])?;
        if windows_service_missing(&output) {
            return Ok(());
        }
        if started.elapsed() >= Duration::from_secs(timeout_secs) {
            return Err(anyhow!(
                "Timed out waiting for Windows service '{}' to be removed",
                WINDOWS_SERVICE_NAME
            ));
        }
        thread::sleep(Duration::from_millis(500));
    }
}

fn run_windows_service_host() -> Result<()> {
    windows_native_service::run_service_dispatcher()
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn install_windows(ctx: &ServiceContext, opts: &InstallOptions) -> Result<()> {
    windows_native_service::install(ctx, opts)
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn uninstall_windows() -> Result<()> {
    windows_native_service::uninstall()
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn start_windows() -> Result<()> {
    assert_command_exists("sc.exe")?;
    let output = run_command("sc.exe", &["start", WINDOWS_SERVICE_NAME])?;
    let detail = windows_service_text(&output);
    if !output.status.success()
        && !detail.contains("1056")
        && !detail.to_lowercase().contains("already running")
    {
        return Err(anyhow!("Failed to start service: {}", detail.trim()));
    }
    wait_for_windows_service_state(WINDOWS_SERVICE_STATE_RUNNING, 30)?;
    println!("Gateway service started");
    Ok(())
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn stop_windows() -> Result<()> {
    assert_command_exists("sc.exe")?;
    let output = run_command("sc.exe", &["stop", WINDOWS_SERVICE_NAME])?;
    let detail = windows_service_text(&output);
    if windows_service_missing(&output) {
        return Ok(());
    }
    if !output.status.success()
        && !detail.contains("1062")
        && !detail
            .to_lowercase()
            .contains("service has not been started")
    {
        return Err(anyhow!("Failed to stop service: {}", detail.trim()));
    }
    wait_for_windows_service_state(WINDOWS_SERVICE_STATE_STOPPED, 30)?;
    println!("Gateway service stopped");
    Ok(())
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn restart_windows() -> Result<()> {
    let _ = stop_windows();
    start_windows()?;
    println!("Gateway service restarted");
    Ok(())
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn audit_windows_service(
    ctx: &ServiceContext,
    runtime: &WindowsRuntimeStatus,
    launch: Option<&WindowsServiceLaunchInfo>,
) -> Vec<String> {
    let mut issues = Vec::new();
    if runtime.start_type_code != Some(2) {
        issues.push("Windows service is not configured for automatic start".to_string());
    }

    let Some(launch) = launch else {
        issues.push("Unable to inspect installed Windows service command line".to_string());
        return issues;
    };

    if !launch.is_service_run {
        issues.push("Service command line is not using `gateway service-run`".to_string());
    }

    if launch.executable_path.as_deref() != Some(ctx.exe_path.as_path()) {
        issues.push("Service executable does not match current microclaw binary".to_string());
    }

    if launch.working_dir.as_deref() != Some(ctx.working_dir.as_path()) {
        issues.push("Service working directory does not match expected directory".to_string());
    }

    if let Some(config_path) = &ctx.config_path {
        if launch.config_path.as_deref() != Some(config_path.as_path()) {
            issues.push("Service config path differs from current config path".to_string());
        }
    }

    issues
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn print_windows_status_text(
    runtime: &WindowsRuntimeStatus,
    issues: &[String],
    raw_query: Option<&str>,
    raw_qc: Option<&str>,
    deep: bool,
) {
    println!("Gateway service: windows/service");
    println!(
        "  installed: {}",
        if runtime.installed { "yes" } else { "no" }
    );
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
    if let Some(start_type) = &runtime.start_type {
        println!("  start_type: {}", start_type);
    }
    if let Some(start_name) = &runtime.service_start_name {
        println!("  service_account: {}", start_name);
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
        if let Some(raw) = raw_query {
            println!("\n-- sc.exe queryex --");
            println!("{}", raw.trim_end());
        }
        if let Some(raw) = raw_qc {
            println!("\n-- sc.exe qc --");
            println!("{}", raw.trim_end());
        }
    }
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn status_windows(ctx: &ServiceContext, opts: &StatusOptions) -> Result<()> {
    assert_command_exists("sc.exe")?;

    let query = run_command("sc.exe", &["queryex", WINDOWS_SERVICE_NAME])?;
    if windows_service_missing(&query) {
        let issues = vec!["Service is not installed".to_string()];
        if opts.json {
            let value = json!({
                "platform": "windows",
                "service": WINDOWS_SERVICE_NAME,
                "running": false,
                "installed": false,
                "drift_issues": issues,
            });
            println!("{}", serde_json::to_string_pretty(&value)?);
        } else {
            let deep_query = if opts.deep {
                Some(windows_service_text(&query))
            } else {
                None
            };
            print_windows_status_text(
                &WindowsRuntimeStatus::default(),
                &issues,
                deep_query.as_deref(),
                None,
                opts.deep,
            );
        }
        return Err(anyhow!("Gateway service is not installed"));
    }

    let qc = run_command("sc.exe", &["qc", WINDOWS_SERVICE_NAME])?;
    let query_text = windows_service_text(&query);
    let qc_text = windows_service_text(&qc);
    let runtime = parse_windows_runtime_status(&query_text, &qc_text);
    let launch = runtime
        .binary_path_name
        .as_deref()
        .map(parse_windows_service_launch_info);
    let issues = audit_windows_service(ctx, &runtime, launch.as_ref());
    let running = runtime.state_code == Some(WINDOWS_SERVICE_STATE_RUNNING);

    if opts.json {
        let value = json!({
            "platform": "windows",
            "service": WINDOWS_SERVICE_NAME,
            "service_host": "native",
            "running": running,
            "installed": runtime.installed,
            "state": runtime.state,
            "state_code": runtime.state_code,
            "pid": runtime.pid,
            "start_type": runtime.start_type,
            "start_type_code": runtime.start_type_code,
            "binary_path_name": runtime.binary_path_name,
            "service_start_name": runtime.service_start_name,
            "display_name": runtime.display_name,
            "configured_executable_path": launch.as_ref().and_then(|info| info.executable_path.clone()),
            "configured_config_path": launch.as_ref().and_then(|info| info.config_path.clone()),
            "configured_working_dir": launch.as_ref().and_then(|info| info.working_dir.clone()),
            "is_service_run": launch.as_ref().map(|info| info.is_service_run).unwrap_or(false),
            "drift_issues": issues,
            "deep_query": if opts.deep { Some(query_text.clone()) } else { None },
            "deep_qc": if opts.deep { Some(qc_text.clone()) } else { None },
        });
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        print_windows_status_text(
            &runtime,
            &issues,
            if opts.deep { Some(&query_text) } else { None },
            if opts.deep { Some(&qc_text) } else { None },
            opts.deep,
        );
    }

    if running {
        Ok(())
    } else {
        Err(anyhow!("Gateway service is not running"))
    }
}

#[cfg(windows)]
mod windows_native_service {
    use super::{
        cleanup_legacy_windows_wrapper_artifacts, run_command, start_windows, stop_windows,
        wait_for_windows_service_removed, windows_service_missing, InstallOptions, ServiceContext,
        WINDOWS_SERVICE_DESCRIPTION, WINDOWS_SERVICE_DISPLAY_NAME, WINDOWS_SERVICE_NAME,
    };
    use anyhow::{anyhow, Context, Result};
    use std::ffi::OsString;
    use std::path::PathBuf;
    use std::process::{Child, Command};
    use std::sync::mpsc;
    use std::time::Duration;
    use windows_service::{
        define_windows_service,
        service::{
            ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
            ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
            ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
        service_manager::{ServiceManager, ServiceManagerAccess},
    };

    const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;
    const SERVICE_WAIT_HINT: Duration = Duration::from_secs(15);

    pub fn install(ctx: &ServiceContext, opts: &InstallOptions) -> Result<()> {
        super::assert_command_exists("sc.exe")?;

        let Some(config_path) = ctx.config_path.as_ref() else {
            return Err(anyhow!(
                "Windows gateway service requires an explicit config file. Run `microclaw setup` first, then run `microclaw gateway install` from that directory or set MICROCLAW_CONFIG."
            ));
        };

        let existing = run_command("sc.exe", &["queryex", WINDOWS_SERVICE_NAME])?;
        let service_exists = !windows_service_missing(&existing);
        if service_exists && !opts.force {
            println!("Gateway service already installed. Use --force to reinstall.");
            return Ok(());
        }

        if service_exists {
            let _ = stop_windows();
            uninstall()?;
        }

        std::fs::create_dir_all(&ctx.runtime_logs_dir)
            .with_context(|| format!("Failed to create {}", ctx.runtime_logs_dir.display()))?;

        let service_manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
        )
        .context("Failed to connect to Windows Service Control Manager")?;

        let service_info = ServiceInfo {
            name: OsString::from(WINDOWS_SERVICE_NAME),
            display_name: OsString::from(WINDOWS_SERVICE_DISPLAY_NAME),
            service_type: SERVICE_TYPE,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: ctx.exe_path.clone(),
            launch_arguments: build_launch_arguments(ctx),
            dependencies: vec![],
            account_name: None,
            account_password: None,
        };

        let service = service_manager
            .create_service(
                &service_info,
                ServiceAccess::CHANGE_CONFIG | ServiceAccess::DELETE | ServiceAccess::QUERY_CONFIG,
            )
            .context("Failed to create Windows service")?;
        service
            .set_description(WINDOWS_SERVICE_DESCRIPTION)
            .context("Failed to set Windows service description")?;
        service
            .update_failure_actions(ServiceFailureActions {
                reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(3600)),
                reboot_msg: None,
                command: None,
                actions: Some(vec![
                    ServiceAction {
                        action_type: ServiceActionType::Restart,
                        delay: Duration::from_secs(5),
                    },
                    ServiceAction {
                        action_type: ServiceActionType::Restart,
                        delay: Duration::from_secs(15),
                    },
                ]),
            })
            .context("Failed to configure Windows service restart policy")?;
        service
            .set_failure_actions_on_non_crash_failures(true)
            .context("Failed to enable restart policy for service failures")?;

        cleanup_legacy_windows_wrapper_artifacts()?;
        start_windows()?;
        println!(
            "Installed and started gateway service: {} (config: {}, working dir: {})",
            WINDOWS_SERVICE_NAME,
            config_path.display(),
            ctx.working_dir.display()
        );
        Ok(())
    }

    pub fn uninstall() -> Result<()> {
        super::assert_command_exists("sc.exe")?;

        let output = run_command("sc.exe", &["queryex", WINDOWS_SERVICE_NAME])?;
        if windows_service_missing(&output) {
            cleanup_legacy_windows_wrapper_artifacts()?;
            println!("Gateway service is not installed");
            return Ok(());
        }

        let _ = stop_windows();

        let service_manager =
            ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
                .context("Failed to connect to Windows Service Control Manager")?;
        let service = service_manager
            .open_service(WINDOWS_SERVICE_NAME, ServiceAccess::DELETE)
            .context("Failed to open Windows service for deletion")?;
        service
            .delete()
            .context("Failed to delete Windows service")?;
        wait_for_windows_service_removed(30)?;
        cleanup_legacy_windows_wrapper_artifacts()?;
        println!("Uninstalled gateway service");
        Ok(())
    }

    pub fn run_service_dispatcher() -> Result<()> {
        service_dispatcher::start(WINDOWS_SERVICE_NAME, ffi_service_main)
            .context("Failed to start native Windows service host")?;
        Ok(())
    }

    fn build_launch_arguments(ctx: &ServiceContext) -> Vec<OsString> {
        let mut args = Vec::new();
        if let Some(config_path) = &ctx.config_path {
            args.push(OsString::from("--config"));
            args.push(config_path.as_os_str().to_os_string());
        }
        args.push(OsString::from("gateway"));
        args.push(OsString::from("service-run"));
        args.push(OsString::from("--working-dir"));
        args.push(ctx.working_dir.as_os_str().to_os_string());
        args
    }

    define_windows_service!(ffi_service_main, service_main);

    pub fn service_main(_arguments: Vec<OsString>) {
        let _ = run_service();
    }

    fn run_service() -> windows_service::Result<()> {
        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();

        let status_handle = service_control_handler::register(
            WINDOWS_SERVICE_NAME,
            move |control_event| -> ServiceControlHandlerResult {
                match control_event {
                    ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                    ServiceControl::Stop | ServiceControl::Shutdown => {
                        let _ = shutdown_tx.send(());
                        ServiceControlHandlerResult::NoError
                    }
                    _ => ServiceControlHandlerResult::NotImplemented,
                }
            },
        )?;

        set_status(
            &status_handle,
            ServiceState::StartPending,
            ServiceControlAccept::empty(),
            ServiceExitCode::NO_ERROR,
            1,
            SERVICE_WAIT_HINT,
        )?;

        let mut child = match spawn_runtime_child() {
            Ok(child) => child,
            Err(_) => {
                set_status(
                    &status_handle,
                    ServiceState::Stopped,
                    ServiceControlAccept::empty(),
                    ServiceExitCode::ServiceSpecific(1),
                    0,
                    Duration::default(),
                )?;
                return Ok(());
            }
        };

        set_status(
            &status_handle,
            ServiceState::Running,
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            ServiceExitCode::NO_ERROR,
            0,
            Duration::default(),
        )?;

        loop {
            match shutdown_rx.recv_timeout(Duration::from_secs(1)) {
                Ok(_) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                    set_status(
                        &status_handle,
                        ServiceState::StopPending,
                        ServiceControlAccept::empty(),
                        ServiceExitCode::NO_ERROR,
                        1,
                        SERVICE_WAIT_HINT,
                    )?;
                    let _ = child.kill();
                    let _ = child.wait();
                    set_status(
                        &status_handle,
                        ServiceState::Stopped,
                        ServiceControlAccept::empty(),
                        ServiceExitCode::NO_ERROR,
                        0,
                        Duration::default(),
                    )?;
                    return Ok(());
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }

            match child.try_wait() {
                Ok(Some(status)) => {
                    let exit_code = status
                        .code()
                        .and_then(|code| u32::try_from(code).ok())
                        .filter(|code| *code != 0)
                        .map(ServiceExitCode::ServiceSpecific)
                        .unwrap_or(ServiceExitCode::ServiceSpecific(1));
                    set_status(
                        &status_handle,
                        ServiceState::Stopped,
                        ServiceControlAccept::empty(),
                        exit_code,
                        0,
                        Duration::default(),
                    )?;
                    return Ok(());
                }
                Ok(None) => {}
                Err(_) => {
                    set_status(
                        &status_handle,
                        ServiceState::Stopped,
                        ServiceControlAccept::empty(),
                        ServiceExitCode::ServiceSpecific(1),
                        0,
                        Duration::default(),
                    )?;
                    return Ok(());
                }
            }
        }
    }

    fn spawn_runtime_child() -> std::io::Result<Child> {
        let exe = std::env::current_exe()?;
        let mut cmd = Command::new(exe);
        if let Some(config_path) = std::env::var_os("MICROCLAW_CONFIG") {
            cmd.arg("--config").arg(config_path.clone());
            cmd.env("MICROCLAW_CONFIG", config_path);
        }
        if let Some(working_dir) = current_service_working_dir() {
            cmd.current_dir(working_dir);
        }
        cmd.env("MICROCLAW_GATEWAY", "1");
        cmd.arg("start");
        cmd.spawn()
    }

    fn current_service_working_dir() -> Option<PathBuf> {
        let args: Vec<OsString> = std::env::args_os().skip(1).collect();
        let mut index = 0usize;
        while index < args.len() {
            let arg = args[index].to_string_lossy();
            if arg == "--working-dir" {
                return args.get(index + 1).map(PathBuf::from);
            }
            if let Some(value) = arg.strip_prefix("--working-dir=") {
                if !value.trim().is_empty() {
                    return Some(PathBuf::from(value));
                }
            }
            index += 1;
        }
        None
    }

    fn set_status(
        status_handle: &service_control_handler::ServiceStatusHandle,
        state: ServiceState,
        controls_accepted: ServiceControlAccept,
        exit_code: ServiceExitCode,
        checkpoint: u32,
        wait_hint: Duration,
    ) -> windows_service::Result<()> {
        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: state,
            controls_accepted,
            exit_code,
            checkpoint,
            wait_hint,
            process_id: None,
        })
    }
}

#[cfg(not(windows))]
mod windows_native_service {
    use super::{InstallOptions, ServiceContext};
    use anyhow::{anyhow, Result};

    pub fn install(_ctx: &ServiceContext, _opts: &InstallOptions) -> Result<()> {
        Err(anyhow!("Gateway service is only supported on Windows"))
    }

    pub fn uninstall() -> Result<()> {
        Err(anyhow!("Gateway service is only supported on Windows"))
    }

    pub fn run_service_dispatcher() -> Result<()> {
        Err(anyhow!("Gateway service is only supported on Windows"))
    }
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn mac_plist_path() -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home)
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{MAC_LABEL}.plist")))
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
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

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
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

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn xml_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn mac_target_label() -> Result<String> {
    let uid = current_uid()?;
    Ok(format!("gui/{uid}/{MAC_LABEL}"))
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn format_macos_launchagents_permission_hint(path: &Path) -> String {
    format!(
        "Permission denied while writing {}. Check ownership/permissions of ~/Library/LaunchAgents (and existing {}), then retry without sudo.",
        path.display(),
        path.file_name().and_then(|v| v.to_str()).unwrap_or("plist")
    )
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
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
    std::fs::create_dir_all(launch_agents).map_err(|e| {
        if e.kind() == ErrorKind::PermissionDenied {
            anyhow!(format_macos_launchagents_permission_hint(&plist_path))
        } else {
            anyhow!("Failed to create {}: {}", launch_agents.display(), e)
        }
    })?;
    std::fs::create_dir_all(&ctx.runtime_logs_dir)
        .with_context(|| format!("Failed to create {}", ctx.runtime_logs_dir.display()))?;

    std::fs::write(&plist_path, render_macos_plist(ctx)).map_err(|e| {
        if e.kind() == ErrorKind::PermissionDenied {
            anyhow!(format_macos_launchagents_permission_hint(&plist_path))
        } else {
            anyhow!("Failed to write {}: {}", plist_path.display(), e)
        }
    })?;

    let _ = stop_macos();
    start_macos()?;
    println!(
        "Installed and started gateway service: {}",
        plist_path.display()
    );
    Ok(())
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
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

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
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

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
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

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn restart_macos() -> Result<()> {
    start_macos()?;
    println!("Gateway service restarted");
    Ok(())
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
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

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
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

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn plist_key_has_true(content: &str, key: &str) -> bool {
    let pattern = format!("<key>{}</key>", key);
    let Some(pos) = content.find(&pattern) else {
        return false;
    };
    content[pos..].contains("<true/>")
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
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

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
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
        .map(|s| s.eq_ignore_ascii_case("running") || s.eq_ignore_ascii_case("active"))
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

        let call = GatewayCli::try_parse_from([
            "gateway",
            "call",
            "node.list",
            "--params",
            "{}",
            "--timeout",
            "5000",
            "--json",
        ])
        .expect("parse call");
        match call.action {
            Some(GatewayAction::Call {
                method,
                params,
                timeout,
                json,
            }) => {
                assert_eq!(method, "node.list");
                assert_eq!(params, "{}");
                assert_eq!(timeout, 5000);
                assert!(json);
            }
            _ => panic!("expected call action"),
        }
    }

    #[test]
    fn test_parse_hidden_service_run_with_clap() {
        let service_run = GatewayCli::try_parse_from([
            "gateway",
            "service-run",
            "--working-dir",
            r#"C:\microclaw-runtime"#,
        ])
        .expect("parse hidden service-run");
        match service_run.action {
            Some(GatewayAction::ServiceRun { working_dir }) => {
                assert_eq!(working_dir, Some(PathBuf::from(r#"C:\microclaw-runtime"#)));
            }
            _ => panic!("expected service-run action"),
        }
    }

    #[test]
    fn test_normalize_gateway_ws_url_supports_http_and_ws_inputs() {
        assert_eq!(
            normalize_gateway_ws_url("http://127.0.0.1:10961"),
            "ws://127.0.0.1:10961/"
        );
        assert_eq!(
            normalize_gateway_ws_url("https://gateway.example.com/"),
            "wss://gateway.example.com/"
        );
        assert_eq!(
            normalize_gateway_ws_url("ws://localhost:9000"),
            "ws://localhost:9000/"
        );
        assert_eq!(
            normalize_gateway_ws_url("gateway.example.com:9000"),
            "ws://gateway.example.com:9000/"
        );
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
    fn test_macos_active_state_is_treated_as_running() {
        let runtime = parse_macos_runtime_status("state = active\npid = 0\n");
        let running = runtime
            .state
            .as_ref()
            .map(|s| s.eq_ignore_ascii_case("running") || s.eq_ignore_ascii_case("active"))
            .unwrap_or(false)
            || runtime.pid.unwrap_or(0) > 0;
        assert!(running);
    }

    #[test]
    fn test_format_macos_launchagents_permission_hint_contains_target_path() {
        let p = Path::new("/Users/u/Library/LaunchAgents/ai.microclaw.gateway.plist");
        let msg = format_macos_launchagents_permission_hint(p);
        assert!(msg.contains("Permission denied"));
        assert!(msg.contains("LaunchAgents"));
        assert!(msg.contains("ai.microclaw.gateway.plist"));
    }

    #[test]
    fn test_resolve_runtime_logs_dir_fallback() {
        let dir = resolve_runtime_logs_dir(Path::new("/tmp/microclaw"), None);
        assert!(
            dir.ends_with("runtime/logs") || dir.ends_with("microclaw.data/runtime/logs"),
            "unexpected logs dir: {}",
            dir.display()
        );
    }

    #[test]
    fn test_parse_windows_service_launch_info() {
        let launch = parse_windows_service_launch_info(
            r#""C:\Program Files\MicroClaw\microclaw.exe" --config "D:\runtime\microclaw.config.yaml" gateway service-run --working-dir "D:\runtime""#,
        );
        assert_eq!(
            launch.executable_path,
            Some(PathBuf::from(r#"C:\Program Files\MicroClaw\microclaw.exe"#))
        );
        assert_eq!(
            launch.config_path,
            Some(PathBuf::from(r#"D:\runtime\microclaw.config.yaml"#))
        );
        assert_eq!(launch.working_dir, Some(PathBuf::from(r#"D:\runtime"#)));
        assert!(launch.is_service_run);
    }

    #[test]
    fn test_parse_windows_runtime_status() {
        let runtime = parse_windows_runtime_status(
            "SERVICE_NAME: MicroClawGateway\n        STATE              : 4  RUNNING\n        PID                : 4242\n",
            "SERVICE_NAME: MicroClawGateway\n        DISPLAY_NAME       : MicroClaw Gateway\n        START_TYPE         : 2   AUTO_START\n        BINARY_PATH_NAME   : \"C:\\Program Files\\MicroClaw\\microclaw.exe\" --config \"D:\\runtime\\microclaw.config.yaml\" gateway service-run --working-dir \"D:\\runtime\"\n        SERVICE_START_NAME : LocalSystem\n",
        );
        assert!(runtime.installed);
        assert_eq!(runtime.state_code, Some(4));
        assert_eq!(runtime.state.as_deref(), Some("RUNNING"));
        assert_eq!(runtime.pid, Some(4242));
        assert_eq!(runtime.start_type_code, Some(2));
        assert_eq!(runtime.start_type.as_deref(), Some("AUTO_START"));
        assert_eq!(runtime.service_start_name.as_deref(), Some("LocalSystem"));
    }

    #[test]
    fn test_audit_windows_service_detects_clean_native_config() {
        let ctx = test_ctx();
        let runtime = WindowsRuntimeStatus {
            installed: true,
            start_type_code: Some(2),
            ..WindowsRuntimeStatus::default()
        };
        let launch = parse_windows_service_launch_info(
            r#""/usr/local/bin/microclaw" --config "/tmp/microclaw/microclaw.config.yaml" gateway service-run --working-dir "/tmp/microclaw""#,
        );
        let issues = audit_windows_service(&ctx, &runtime, Some(&launch));
        assert!(issues.is_empty(), "unexpected issues: {issues:?}");
    }

    #[test]
    fn test_parse_windows_command_line_preserves_escaped_trailing_backslash() {
        let args = parse_windows_command_line(
            r#""C:\Program Files\MicroClaw\microclaw.exe" --working-dir "C:\runtime\\""#,
        );
        assert_eq!(
            args,
            vec![
                r#"C:\Program Files\MicroClaw\microclaw.exe"#.to_string(),
                "--working-dir".to_string(),
                r#"C:\runtime\"#.to_string(),
            ]
        );
    }
}
