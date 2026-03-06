use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use http::{HeaderName, HeaderValue};
use rmcp::model::{CallToolRequestParams, ClientInfo, ProtocolVersion, RawContent};
use rmcp::transport::child_process::ConfigureCommandExt;
use rmcp::transport::streamable_http_client::{
    StreamableHttpClientTransport, StreamableHttpClientTransportConfig,
};
use rmcp::transport::TokioChildProcess;
use rmcp::ServiceExt;
use serde::Deserialize;
use tokio::process::Command;
use tokio::sync::Semaphore;
use tracing::{error, info, warn};

const DEFAULT_HEALTH_INTERVAL_SECS: u64 = 60;
const TOOLS_CACHE_TTL_SECS: u64 = 300;
const DEFAULT_CIRCUIT_BREAKER_FAILURE_THRESHOLD: u32 = 5;
const DEFAULT_CIRCUIT_BREAKER_COOLDOWN_SECS: u64 = 30;
const DEFAULT_MAX_CONCURRENT_REQUESTS: u32 = 4;
const DEFAULT_QUEUE_WAIT_MS: u64 = 200;
const DEFAULT_RATE_LIMIT_PER_MINUTE: u32 = 120;

// --- MCP config types ---

fn default_transport() -> String {
    "stdio".to_string()
}

fn resolve_request_timeout_secs(
    config_timeout_secs: Option<u64>,
    default_request_timeout_secs: u64,
) -> u64 {
    config_timeout_secs
        .unwrap_or(default_request_timeout_secs)
        .max(1)
}

#[derive(Debug, Clone, Deserialize)]
pub struct McpServerConfig {
    #[serde(default = "default_transport")]
    pub transport: String,
    #[serde(default, alias = "protocolVersion")]
    pub protocol_version: Option<String>,
    #[serde(default)]
    pub request_timeout_secs: Option<u64>,
    #[serde(default)]
    pub max_retries: Option<u32>,
    #[serde(default)]
    pub health_interval_secs: Option<u64>,
    #[serde(default, alias = "circuitBreakerFailureThreshold")]
    pub circuit_breaker_failure_threshold: Option<u32>,
    #[serde(default, alias = "circuitBreakerCooldownSecs")]
    pub circuit_breaker_cooldown_secs: Option<u64>,
    #[serde(default, alias = "maxConcurrentRequests")]
    pub max_concurrent_requests: Option<u32>,
    #[serde(default, alias = "queueWaitMs")]
    pub queue_wait_ms: Option<u64>,
    #[serde(default, alias = "rateLimitPerMinute")]
    pub rate_limit_per_minute: Option<u32>,

    // stdio transport
    #[serde(default)]
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: HashMap<String, String>,

    // streamable_http transport
    #[serde(default, alias = "url")]
    pub endpoint: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
pub struct McpConfig {
    #[serde(default, alias = "defaultProtocolVersion")]
    pub default_protocol_version: Option<String>,
    #[serde(rename = "mcpServers")]
    pub mcp_servers: HashMap<String, McpServerConfig>,
}

#[derive(Debug, Clone)]
pub struct McpToolInfo {
    pub server_name: String,
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
}

// --- Resilience primitives (unchanged from before) ---

#[derive(Debug)]
struct CircuitBreakerState {
    threshold: u32,
    cooldown: Duration,
    consecutive_failures: u32,
    open_until: Option<Instant>,
}

impl CircuitBreakerState {
    fn new(threshold: u32, cooldown_secs: u64) -> Self {
        Self {
            threshold,
            cooldown: Duration::from_secs(cooldown_secs.max(1)),
            consecutive_failures: 0,
            open_until: None,
        }
    }

    fn check_ready(&mut self, now: Instant) -> Result<(), u64> {
        if self.threshold == 0 {
            return Ok(());
        }
        if let Some(open_until) = self.open_until {
            if now < open_until {
                return Err((open_until - now).as_secs().max(1));
            }
            self.open_until = None;
            self.consecutive_failures = 0;
        }
        Ok(())
    }

    fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.open_until = None;
    }

    fn record_failure(&mut self, now: Instant) -> bool {
        if self.threshold == 0 {
            return false;
        }
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        if self.consecutive_failures >= self.threshold {
            self.open_until = Some(now + self.cooldown);
            self.consecutive_failures = 0;
            return true;
        }
        false
    }
}

#[derive(Debug)]
struct FixedWindowRateLimiter {
    limit_per_minute: u32,
    window_started_at: Instant,
    used_in_window: u32,
}

impl FixedWindowRateLimiter {
    fn new(limit_per_minute: u32) -> Self {
        Self {
            limit_per_minute,
            window_started_at: Instant::now(),
            used_in_window: 0,
        }
    }

    fn consume_or_retry_after_secs(&mut self, now: Instant) -> Result<(), u64> {
        if self.limit_per_minute == 0 {
            return Ok(());
        }
        let window = Duration::from_secs(60);
        if now.duration_since(self.window_started_at) >= window {
            self.window_started_at = now;
            self.used_in_window = 0;
        }
        if self.used_in_window < self.limit_per_minute {
            self.used_in_window = self.used_in_window.saturating_add(1);
            return Ok(());
        }
        let retry_after = window
            .saturating_sub(now.duration_since(self.window_started_at))
            .as_secs()
            .max(1);
        Err(retry_after)
    }
}

// --- rmcp peer wrapper ---

enum McpPeer {
    Stdio(rmcp::service::RunningService<rmcp::RoleClient, ClientInfo>),
    Http(rmcp::service::RunningService<rmcp::RoleClient, ClientInfo>),
}

impl McpPeer {
    fn peer(&self) -> &rmcp::Peer<rmcp::RoleClient> {
        match self {
            McpPeer::Stdio(s) => s.peer(),
            McpPeer::Http(s) => s.peer(),
        }
    }
}

// --- MCP server connection ---

pub struct McpServer {
    name: String,
    peer: McpPeer,
    request_timeout: Duration,
    max_retries: u32,
    tools_cache: StdMutex<Vec<McpToolInfo>>,
    tools_cache_updated_at: StdMutex<Option<Instant>>,
    circuit_breaker: StdMutex<CircuitBreakerState>,
    inflight_limiter: Arc<Semaphore>,
    queue_wait: Duration,
    rate_limiter: StdMutex<FixedWindowRateLimiter>,
}

impl McpServer {
    pub async fn connect(
        name: &str,
        config: &McpServerConfig,
        default_protocol_version: Option<&str>,
        default_request_timeout_secs: u64,
    ) -> Result<Self, String> {
        let request_timeout = Duration::from_secs(resolve_request_timeout_secs(
            config.request_timeout_secs,
            default_request_timeout_secs,
        ));
        let max_retries = config.max_retries.unwrap_or(0);
        let requested_protocol = config
            .protocol_version
            .clone()
            .or_else(|| default_protocol_version.map(|v| v.to_string()));
        let client_info = build_client_info(requested_protocol);
        let circuit_breaker_threshold = config
            .circuit_breaker_failure_threshold
            .unwrap_or(DEFAULT_CIRCUIT_BREAKER_FAILURE_THRESHOLD);
        let circuit_breaker_cooldown_secs = config
            .circuit_breaker_cooldown_secs
            .unwrap_or(DEFAULT_CIRCUIT_BREAKER_COOLDOWN_SECS);
        let max_concurrent_requests = config
            .max_concurrent_requests
            .unwrap_or(DEFAULT_MAX_CONCURRENT_REQUESTS)
            .max(1);
        let queue_wait =
            Duration::from_millis(config.queue_wait_ms.unwrap_or(DEFAULT_QUEUE_WAIT_MS).max(1));
        let rate_limit_per_minute = config
            .rate_limit_per_minute
            .unwrap_or(DEFAULT_RATE_LIMIT_PER_MINUTE);
        let transport_name = config.transport.trim().to_ascii_lowercase();

        let peer = match transport_name.as_str() {
            "stdio" | "" => {
                if config.command.trim().is_empty() {
                    return Err(format!(
                        "MCP server '{name}' requires `command` when transport=stdio"
                    ));
                }
                let resolved = resolve_command(&config.command);
                let transport = TokioChildProcess::new(Command::new(&resolved).configure(|cmd| {
                    cmd.args(&config.args);
                    cmd.envs(&config.env);
                    cmd.stderr(std::process::Stdio::null());
                }))
                .map_err(|e| format!("Failed to spawn MCP server '{name}': {e}"))?;

                let running = client_info.clone().serve(transport).await.map_err(|e| {
                    format!("Failed to initialize MCP server '{name}' (stdio): {e}")
                })?;
                McpPeer::Stdio(running)
            }
            "streamable_http" | "http" => {
                if config.endpoint.trim().is_empty() {
                    return Err(format!(
                        "MCP server '{name}' requires `endpoint` when transport=streamable_http"
                    ));
                }
                let mut custom_headers: HashMap<HeaderName, HeaderValue> = HashMap::new();
                for (k, v) in &config.headers {
                    let header_name = HeaderName::from_bytes(k.as_bytes())
                        .map_err(|e| format!("Invalid header name '{k}' for MCP '{name}': {e}"))?;
                    let header_value = HeaderValue::from_str(v).map_err(|e| {
                        format!("Invalid header value for '{k}' in MCP '{name}': {e}")
                    })?;
                    custom_headers.insert(header_name, header_value);
                }
                let http_config =
                    StreamableHttpClientTransportConfig::with_uri(config.endpoint.as_str())
                        .custom_headers(custom_headers);
                let transport = StreamableHttpClientTransport::from_config(http_config);
                let running =
                    client_info.clone().serve(transport).await.map_err(|e| {
                        format!("Failed to initialize MCP server '{name}' (http): {e}")
                    })?;
                McpPeer::Http(running)
            }
            other => {
                return Err(format!(
                    "MCP server '{name}' has unsupported transport '{other}'"
                ));
            }
        };

        let server = McpServer {
            name: name.to_string(),
            peer,
            request_timeout,
            max_retries,
            tools_cache: StdMutex::new(Vec::new()),
            tools_cache_updated_at: StdMutex::new(None),
            circuit_breaker: StdMutex::new(CircuitBreakerState::new(
                circuit_breaker_threshold,
                circuit_breaker_cooldown_secs,
            )),
            inflight_limiter: Arc::new(Semaphore::new(max_concurrent_requests as usize)),
            queue_wait,
            rate_limiter: StdMutex::new(FixedWindowRateLimiter::new(rate_limit_per_minute)),
        };

        let _ = server.refresh_tools_cache(true).await?;

        Ok(server)
    }

    fn is_cache_fresh(&self) -> bool {
        let guard = self
            .tools_cache_updated_at
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(ts) = *guard {
            ts.elapsed() < Duration::from_secs(TOOLS_CACHE_TTL_SECS)
        } else {
            false
        }
    }

    fn set_tools_cache(&self, tools: Vec<McpToolInfo>) {
        {
            let mut guard = self.tools_cache.lock().unwrap_or_else(|e| e.into_inner());
            *guard = tools;
        }
        let mut ts = self
            .tools_cache_updated_at
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *ts = Some(Instant::now());
    }

    pub fn tools_snapshot(&self) -> Vec<McpToolInfo> {
        self.tools_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn is_tool_not_found_error(err: &str) -> bool {
        let lower = err.to_ascii_lowercase();
        lower.contains("not found")
            || lower.contains("unknown tool")
            || lower.contains("tool not found")
    }

    fn should_retry_error(err: &str) -> bool {
        let lower = err.to_ascii_lowercase();
        lower.contains("timeout")
            || lower.contains("request timeout")
            || lower.contains("transport closed")
            || lower.contains("closed connection")
            || lower.contains("broken pipe")
            || lower.contains("connection reset")
            || lower.contains("temporarily unavailable")
    }

    fn invalidate_tools_cache(&self) {
        {
            let mut cache = self.tools_cache.lock().unwrap_or_else(|e| e.into_inner());
            cache.clear();
        }
        let mut ts = self
            .tools_cache_updated_at
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *ts = None;
    }

    async fn list_tools_uncached(&self) -> Result<Vec<McpToolInfo>, String> {
        let rmcp_tools = self.peer.peer().list_all_tools();
        let rmcp_tools = tokio::time::timeout(self.request_timeout, rmcp_tools)
            .await
            .map_err(|_| {
                format!(
                    "MCP list tools timed out for '{}' after {:?}",
                    self.name, self.request_timeout
                )
            })?
            .map_err(|e| format!("Failed to list tools for '{}': {e}", self.name))?;

        let tools = rmcp_tools
            .into_iter()
            .map(|t| {
                let input_schema = serde_json::to_value(&*t.input_schema)
                    .unwrap_or_else(|_| serde_json::json!({"type": "object", "properties": {}}));
                McpToolInfo {
                    server_name: self.name.clone(),
                    name: t.name.into_owned(),
                    description: t.description.map(|d| d.into_owned()).unwrap_or_default(),
                    input_schema,
                }
            })
            .collect();

        Ok(tools)
    }

    pub async fn refresh_tools_cache(&self, force: bool) -> Result<Vec<McpToolInfo>, String> {
        if !force && self.is_cache_fresh() {
            return Ok(self.tools_snapshot());
        }

        let tools = self.list_tools_uncached().await?;
        self.set_tools_cache(tools.clone());
        Ok(tools)
    }

    pub async fn health_probe(&self) -> Result<(), String> {
        let _ = self.refresh_tools_cache(true).await?;
        Ok(())
    }

    pub fn start_health_probe(self: Arc<Self>, interval_secs: u64) {
        if interval_secs == 0 {
            return;
        }

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(interval_secs)).await;
                if let Err(e) = self.health_probe().await {
                    warn!("MCP health probe failed for '{}': {}", self.name, e);
                }
            }
        });
    }

    async fn call_tool_inner(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
    ) -> Result<String, String> {
        let args_map = arguments.as_object().cloned().unwrap_or_default();

        let params = CallToolRequestParams::new(tool_name.to_string()).with_arguments(args_map);

        let result = self.peer.peer().call_tool(params);
        let result = tokio::time::timeout(self.request_timeout, result)
            .await
            .map_err(|_| {
                format!(
                    "MCP tool call timed out for '{}' after {:?}",
                    self.name, self.request_timeout
                )
            })?
            .map_err(|e| format!("MCP tool call error: {e}"))?;

        let is_error = result.is_error.unwrap_or(false);

        let mut output = String::new();
        for item in &result.content {
            if let RawContent::Text(text_content) = &item.raw {
                if !output.is_empty() {
                    output.push('\n');
                }
                output.push_str(&text_content.text);
            }
        }

        if output.is_empty() {
            output = serde_json::to_string_pretty(&result.content).unwrap_or_default();
        }

        if is_error {
            if Self::is_tool_not_found_error(&output) {
                self.invalidate_tools_cache();
                let _ = self.refresh_tools_cache(true).await;
            }
            Err(output)
        } else {
            Ok(output)
        }
    }

    pub async fn call_tool(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
    ) -> Result<String, String> {
        // Refresh cache if tool not known, else lazy refresh
        let snapshot = self.tools_snapshot();
        if !snapshot.iter().any(|t| t.name == tool_name) {
            let _ = self.refresh_tools_cache(true).await;
        } else {
            let _ = self.refresh_tools_cache(false).await;
        }

        // Rate limiter
        {
            let mut rate = self.rate_limiter.lock().unwrap_or_else(|e| e.into_inner());
            if let Err(retry_after_secs) = rate.consume_or_retry_after_secs(Instant::now()) {
                return Err(format!(
                    "MCP server '{}' rate-limited; retry in ~{}s",
                    self.name, retry_after_secs
                ));
            }
        }

        // Bulkhead
        let permit = tokio::time::timeout(
            self.queue_wait,
            self.inflight_limiter.clone().acquire_owned(),
        )
        .await
        .map_err(|_| {
            format!(
                "MCP server '{}' busy; exceeded queue wait of {:?}",
                self.name, self.queue_wait
            )
        })?
        .map_err(|_| format!("MCP server '{}' limiter is closed", self.name))?;

        // Circuit breaker check
        {
            let mut breaker = self
                .circuit_breaker
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Err(remaining_secs) = breaker.check_ready(Instant::now()) {
                return Err(format!(
                    "MCP server '{}' circuit open; retry in ~{}s",
                    self.name, remaining_secs
                ));
            }
        }

        let mut attempt: u32 = 0;
        let result = loop {
            let result = self.call_tool_inner(tool_name, arguments.clone()).await;
            match &result {
                Ok(_) => break result,
                Err(err) if attempt < self.max_retries && Self::should_retry_error(err) => {
                    let backoff_ms = 200u64.saturating_mul(2u64.saturating_pow(attempt.min(8)));
                    warn!(
                        "MCP server '{}' call failed (attempt {}/{}), retrying in {}ms: {}",
                        self.name,
                        attempt + 1,
                        self.max_retries + 1,
                        backoff_ms,
                        err
                    );
                    tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                    attempt = attempt.saturating_add(1);
                }
                _ => break result,
            }
        };
        drop(permit);

        // Update circuit breaker
        let mut breaker = self
            .circuit_breaker
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        match &result {
            Ok(_) => breaker.record_success(),
            Err(_) => {
                if breaker.record_failure(Instant::now()) {
                    warn!(
                        "MCP server '{}' circuit opened after consecutive failures",
                        self.name
                    );
                }
            }
        }

        result
    }
}

// --- MCP manager ---

pub struct McpManager {
    servers: Vec<Arc<McpServer>>,
}

impl McpManager {
    pub async fn from_config_file(path: &str, default_request_timeout_secs: u64) -> Self {
        Self::from_config_paths(&[PathBuf::from(path)], default_request_timeout_secs).await
    }

    pub async fn from_config_paths(paths: &[PathBuf], default_request_timeout_secs: u64) -> Self {
        let default_request_timeout_secs =
            resolve_request_timeout_secs(None, default_request_timeout_secs);
        let (loaded_any_config, merged_default_protocol_version, merged_servers) =
            merge_config_sources(paths);
        if !loaded_any_config {
            return McpManager {
                servers: Vec::new(),
            };
        }

        let mut servers = Vec::new();
        let mut entries: Vec<(String, McpServerConfig)> = merged_servers.into_iter().collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        for (name, server_config) in entries {
            info!("Connecting to MCP server '{name}'...");
            match tokio::time::timeout(
                Duration::from_secs(30),
                McpServer::connect(
                    &name,
                    &server_config,
                    merged_default_protocol_version.as_deref(),
                    default_request_timeout_secs,
                ),
            )
            .await
            {
                Ok(Ok(server)) => {
                    let server = Arc::new(server);
                    let interval = server_config
                        .health_interval_secs
                        .unwrap_or(DEFAULT_HEALTH_INTERVAL_SECS);
                    server.clone().start_health_probe(interval);

                    info!(
                        "MCP server '{name}' connected ({} tools)",
                        server.tools_snapshot().len(),
                    );
                    servers.push(server);
                }
                Ok(Err(e)) => {
                    warn!("Failed to connect MCP server '{name}': {e}");
                }
                Err(_) => {
                    warn!("MCP server '{name}' connection timed out (30s)");
                }
            }
        }

        McpManager { servers }
    }

    #[allow(dead_code)]
    pub fn servers(&self) -> &[Arc<McpServer>] {
        &self.servers
    }

    pub fn all_tools(&self) -> Vec<(Arc<McpServer>, McpToolInfo)> {
        let mut tools = Vec::new();
        for server in &self.servers {
            for tool in server.tools_snapshot() {
                tools.push((server.clone(), tool));
            }
        }
        tools
    }
}

fn merge_config_sources(
    paths: &[PathBuf],
) -> (bool, Option<String>, HashMap<String, McpServerConfig>) {
    let mut merged_default_protocol_version: Option<String> = None;
    let mut merged_servers: HashMap<String, McpServerConfig> = HashMap::new();
    let mut loaded_any_config = false;
    for path in paths {
        let Some(config) = load_config_from_path(path) else {
            continue;
        };
        loaded_any_config = true;
        if let Some(protocol_version) = config.default_protocol_version {
            merged_default_protocol_version = Some(protocol_version);
        }
        for (name, server_cfg) in config.mcp_servers {
            if merged_servers.insert(name.clone(), server_cfg).is_some() {
                warn!(
                    "MCP server '{}' overridden by later config source '{}'",
                    name,
                    path.display()
                );
            }
        }
    }
    (
        loaded_any_config,
        merged_default_protocol_version,
        merged_servers,
    )
}

fn load_config_from_path(path: &Path) -> Option<McpConfig> {
    let config_str = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return None,
    };
    match serde_json::from_str::<McpConfig>(&config_str) {
        Ok(cfg) => Some(cfg),
        Err(e) => {
            error!("Failed to parse MCP config {}: {e}", path.display());
            None
        }
    }
}

fn build_client_info(requested_protocol: Option<String>) -> ClientInfo {
    let mut info = ClientInfo::default();
    if let Some(protocol_version) = requested_protocol {
        let parsed = serde_json::from_value::<ProtocolVersion>(serde_json::json!(protocol_version))
            .unwrap_or_else(|_| ProtocolVersion::default());
        info = info.with_protocol_version(parsed);
    }
    info
}

/// Resolve a command name to its full path.
fn resolve_command(command: &str) -> String {
    if std::path::Path::new(command).is_absolute() {
        return command.to_string();
    }

    if let Ok(output) = std::process::Command::new(if cfg!(windows) { "where" } else { "which" })
        .arg(command)
        .output()
    {
        if output.status.success() {
            let resolved = String::from_utf8_lossy(&output.stdout)
                .lines()
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            if !resolved.is_empty() {
                return resolved;
            }
        }
    }

    #[cfg(windows)]
    {
        let candidates = [
            format!("C:\\Program Files\\nodejs\\{command}.cmd"),
            format!("C:\\Program Files\\nodejs\\{command}.exe"),
            format!("C:\\Program Files\\nodejs\\{command}"),
        ];
        for candidate in &candidates {
            if std::path::Path::new(candidate).exists() {
                return candidate.clone();
            }
        }
    }

    command.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mcp_config_defaults() {
        let json = r#"{
          "mcpServers": {
            "demo": {
              "command": "npx",
              "args": ["-y", "@modelcontextprotocol/server-filesystem", "."]
            }
          }
        }"#;

        let cfg: McpConfig = serde_json::from_str(json).unwrap();
        let server = cfg.mcp_servers.get("demo").unwrap();
        assert_eq!(server.transport, "stdio");
        assert!(server.protocol_version.is_none());
        assert!(server.max_retries.is_none());
        assert!(server.circuit_breaker_failure_threshold.is_none());
        assert!(server.circuit_breaker_cooldown_secs.is_none());
        assert!(server.max_concurrent_requests.is_none());
        assert!(server.queue_wait_ms.is_none());
        assert!(server.rate_limit_per_minute.is_none());
    }

    #[test]
    fn test_tool_not_found_error_detection() {
        assert!(McpServer::is_tool_not_found_error("Tool not found"));
        assert!(McpServer::is_tool_not_found_error("unknown tool: x"));
        assert!(!McpServer::is_tool_not_found_error("permission denied"));
    }

    #[test]
    fn test_mcp_http_config_parse() {
        let json = r#"{
          "default_protocol_version": "2024-11-05",
          "mcpServers": {
            "remote": {
              "transport": "streamable_http",
              "endpoint": "http://127.0.0.1:8080/mcp",
              "headers": {"Authorization": "Bearer test"},
              "max_retries": 3,
              "health_interval_secs": 15
            }
          }
        }"#;

        let cfg: McpConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.default_protocol_version.unwrap(), "2024-11-05");
        let remote = cfg.mcp_servers.get("remote").unwrap();
        assert_eq!(remote.transport, "streamable_http");
        assert_eq!(remote.endpoint, "http://127.0.0.1:8080/mcp");
        assert_eq!(remote.max_retries, Some(3));
        assert_eq!(remote.health_interval_secs, Some(15));
    }

    #[test]
    fn test_resolve_request_timeout_secs_prefers_server_override() {
        assert_eq!(resolve_request_timeout_secs(Some(25), 90), 25);
        assert_eq!(resolve_request_timeout_secs(None, 90), 90);
        assert_eq!(resolve_request_timeout_secs(Some(0), 90), 1);
        assert_eq!(resolve_request_timeout_secs(None, 0), 1);
    }

    #[test]
    fn test_mcp_bulkhead_and_rate_limit_parse() {
        let json = r#"{
          "mcpServers": {
            "remote": {
              "transport": "streamable_http",
              "endpoint": "http://127.0.0.1:8080/mcp",
              "max_concurrent_requests": 6,
              "queue_wait_ms": 500,
              "rate_limit_per_minute": 240
            }
          }
        }"#;

        let cfg: McpConfig = serde_json::from_str(json).unwrap();
        let remote = cfg.mcp_servers.get("remote").unwrap();
        assert_eq!(remote.max_concurrent_requests, Some(6));
        assert_eq!(remote.queue_wait_ms, Some(500));
        assert_eq!(remote.rate_limit_per_minute, Some(240));
    }

    #[test]
    fn test_merge_config_sources_later_overrides_earlier() {
        let dir =
            std::env::temp_dir().join(format!("microclaw_mcp_merge_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let base = dir.join("00-base.json");
        let override_cfg = dir.join("10-override.json");
        std::fs::write(
            &base,
            r#"{
              "defaultProtocolVersion": "2024-11-05",
              "mcpServers": {
                "shared": {
                  "transport": "streamable_http",
                  "endpoint": "http://127.0.0.1:7001/mcp"
                }
              }
            }"#,
        )
        .unwrap();
        std::fs::write(
            &override_cfg,
            r#"{
              "defaultProtocolVersion": "2025-12-01",
              "mcpServers": {
                "shared": {
                  "transport": "streamable_http",
                  "endpoint": "http://127.0.0.1:7002/mcp"
                },
                "extra": {
                  "transport": "streamable_http",
                  "endpoint": "http://127.0.0.1:7003/mcp"
                }
              }
            }"#,
        )
        .unwrap();

        let (loaded, protocol, servers) = merge_config_sources(&[base, override_cfg]);
        assert!(loaded);
        assert_eq!(protocol.as_deref(), Some("2025-12-01"));
        assert_eq!(servers.len(), 2);
        assert_eq!(
            servers.get("shared").map(|s| s.endpoint.as_str()),
            Some("http://127.0.0.1:7002/mcp")
        );
        assert_eq!(
            servers.get("extra").map(|s| s.endpoint.as_str()),
            Some("http://127.0.0.1:7003/mcp")
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_rate_limiter_blocks_after_limit() {
        let mut limiter = FixedWindowRateLimiter::new(2);
        let now = Instant::now();
        assert!(limiter.consume_or_retry_after_secs(now).is_ok());
        assert!(limiter.consume_or_retry_after_secs(now).is_ok());
        assert!(limiter.consume_or_retry_after_secs(now).is_err());
    }

    #[test]
    fn test_rate_limiter_can_be_disabled() {
        let mut limiter = FixedWindowRateLimiter::new(0);
        let now = Instant::now();
        for _ in 0..10 {
            assert!(limiter.consume_or_retry_after_secs(now).is_ok());
        }
    }

    #[test]
    fn test_circuit_breaker_trips_and_recovers() {
        let mut breaker = CircuitBreakerState::new(2, 1);
        let now = Instant::now();

        assert!(breaker.check_ready(now).is_ok());
        assert!(!breaker.record_failure(now));
        assert!(breaker.check_ready(Instant::now()).is_ok());
        assert!(breaker.record_failure(Instant::now()));

        let blocked = breaker.check_ready(Instant::now());
        assert!(blocked.is_err());

        std::thread::sleep(Duration::from_millis(1100));
        assert!(breaker.check_ready(Instant::now()).is_ok());
    }

    #[test]
    fn test_circuit_breaker_can_be_disabled() {
        let mut breaker = CircuitBreakerState::new(0, 1);
        assert!(breaker.check_ready(Instant::now()).is_ok());
        assert!(!breaker.record_failure(Instant::now()));
        assert!(breaker.check_ready(Instant::now()).is_ok());
    }
}
