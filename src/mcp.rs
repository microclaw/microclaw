use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tracing::{error, info, warn};

const DEFAULT_PROTOCOL_VERSION: &str = "2025-11-05";
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 120;
const DEFAULT_MAX_RETRIES: u32 = 2;
const DEFAULT_HEALTH_INTERVAL_SECS: u64 = 60;
const TOOLS_CACHE_TTL_SECS: u64 = 300;
const DEFAULT_CIRCUIT_BREAKER_FAILURE_THRESHOLD: u32 = 5;
const DEFAULT_CIRCUIT_BREAKER_COOLDOWN_SECS: u64 = 30;

// --- JSON-RPC 2.0 types ---

#[derive(Debug, Serialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<u64>,
    method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcResponse {
    #[allow(dead_code)]
    jsonrpc: Option<String>,
    #[allow(dead_code)]
    id: Option<serde_json::Value>,
    result: Option<serde_json::Value>,
    error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

// --- MCP config types ---

fn default_transport() -> String {
    "stdio".to_string()
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

#[derive(Clone)]
struct McpStdioSpawnSpec {
    command: String,
    args: Vec<String>,
    env: HashMap<String, String>,
}

// --- MCP server connection ---

struct McpStdioInner {
    stdin: tokio::process::ChildStdin,
    stdout: BufReader<tokio::process::ChildStdout>,
    _child: Child,
    next_id: u64,
}

struct McpHttpInner {
    client: reqwest::Client,
    endpoint: String,
    headers: HashMap<String, String>,
    next_id: u64,
}

enum McpTransport {
    Stdio(Box<Mutex<McpStdioInner>>),
    StreamableHttp(Box<Mutex<McpHttpInner>>),
}

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

pub struct McpServer {
    name: String,
    requested_protocol: String,
    negotiated_protocol: StdMutex<String>,
    request_timeout: Duration,
    max_retries: u32,
    transport: McpTransport,
    stdio_spawn: Option<McpStdioSpawnSpec>,
    tools_cache: StdMutex<Vec<McpToolInfo>>,
    tools_cache_updated_at: StdMutex<Option<Instant>>,
    circuit_breaker: StdMutex<CircuitBreakerState>,
}

/// Resolve a command name to its full path. On Windows, also checks for
/// `.cmd` and `.exe` variants in common locations when PATH lookup fails.
fn resolve_command(command: &str) -> String {
    // Already a full path — use as-is
    if std::path::Path::new(command).is_absolute() {
        return command.to_string();
    }

    // Try PATH lookup via `which` (Unix) or `where` (Windows)
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

    // Windows fallback: check common locations for .cmd/.exe variants
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

    // Return original and let the OS try
    command.to_string()
}

fn spawn_stdio_inner(spec: &McpStdioSpawnSpec, server_name: &str) -> Result<McpStdioInner, String> {
    let resolved_command = resolve_command(&spec.command);
    let mut cmd = Command::new(&resolved_command);
    cmd.args(&spec.args);
    cmd.envs(&spec.env);
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::null());

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("Failed to spawn MCP server '{server_name}': {e}"))?;

    let stdin = child.stdin.take().ok_or("Failed to get stdin")?;
    let stdout = child.stdout.take().ok_or("Failed to get stdout")?;
    let stdout = BufReader::new(stdout);

    Ok(McpStdioInner {
        stdin,
        stdout,
        _child: child,
        next_id: 1,
    })
}

impl McpServer {
    pub async fn connect(
        name: &str,
        config: &McpServerConfig,
        default_protocol_version: Option<&str>,
    ) -> Result<Self, String> {
        let requested_protocol = config
            .protocol_version
            .clone()
            .or_else(|| default_protocol_version.map(|v| v.to_string()))
            .unwrap_or_else(|| DEFAULT_PROTOCOL_VERSION.to_string());

        let request_timeout = Duration::from_secs(
            config
                .request_timeout_secs
                .unwrap_or(DEFAULT_REQUEST_TIMEOUT_SECS),
        );
        let max_retries = config.max_retries.unwrap_or(DEFAULT_MAX_RETRIES);
        let circuit_breaker_threshold = config
            .circuit_breaker_failure_threshold
            .unwrap_or(DEFAULT_CIRCUIT_BREAKER_FAILURE_THRESHOLD);
        let circuit_breaker_cooldown_secs = config
            .circuit_breaker_cooldown_secs
            .unwrap_or(DEFAULT_CIRCUIT_BREAKER_COOLDOWN_SECS);
        let transport_name = config.transport.trim().to_ascii_lowercase();

        let (transport, stdio_spawn) = match transport_name.as_str() {
            "stdio" | "" => {
                if config.command.trim().is_empty() {
                    return Err(format!(
                        "MCP server '{name}' requires `command` when transport=stdio"
                    ));
                }
                let spec = McpStdioSpawnSpec {
                    command: config.command.clone(),
                    args: config.args.clone(),
                    env: config.env.clone(),
                };
                let inner = spawn_stdio_inner(&spec, name)?;
                (McpTransport::Stdio(Box::new(Mutex::new(inner))), Some(spec))
            }
            "streamable_http" | "http" => {
                if config.endpoint.trim().is_empty() {
                    return Err(format!(
                        "MCP server '{name}' requires `endpoint` when transport=streamable_http"
                    ));
                }

                let client = reqwest::Client::builder()
                    .timeout(request_timeout)
                    .build()
                    .map_err(|e| format!("Failed to build HTTP client for MCP '{name}': {e}"))?;

                (
                    McpTransport::StreamableHttp(Box::new(Mutex::new(McpHttpInner {
                        client,
                        endpoint: config.endpoint.clone(),
                        headers: config.headers.clone(),
                        next_id: 1,
                    }))),
                    None,
                )
            }
            other => {
                return Err(format!(
                    "MCP server '{name}' has unsupported transport '{other}'"
                ));
            }
        };

        let server = McpServer {
            name: name.to_string(),
            requested_protocol: requested_protocol.clone(),
            negotiated_protocol: StdMutex::new(requested_protocol),
            request_timeout,
            max_retries,
            transport,
            stdio_spawn,
            tools_cache: StdMutex::new(Vec::new()),
            tools_cache_updated_at: StdMutex::new(None),
            circuit_breaker: StdMutex::new(CircuitBreakerState::new(
                circuit_breaker_threshold,
                circuit_breaker_cooldown_secs,
            )),
        };

        server.initialize_connection().await?;
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

    pub fn protocol_version(&self) -> String {
        self.negotiated_protocol
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn should_attempt_reconnect(err: &str) -> bool {
        let lower = err.to_ascii_lowercase();
        lower.contains("write error")
            || lower.contains("read error")
            || lower.contains("closed connection")
            || lower.contains("timeout")
            || lower.contains("broken pipe")
    }

    fn is_tool_not_found_error(err: &str) -> bool {
        let lower = err.to_ascii_lowercase();
        lower.contains("not found")
            || lower.contains("unknown tool")
            || lower.contains("tool not found")
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

    async fn reconnect_stdio(&self, attempt: u32) -> Result<(), String> {
        let Some(spec) = self.stdio_spawn.as_ref() else {
            return Err("No stdio spawn spec available for reconnect".into());
        };

        let backoff_ms = 200u64.saturating_mul(2u64.saturating_pow(attempt.min(8)));
        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;

        let new_inner = spawn_stdio_inner(spec, &self.name)?;
        match &self.transport {
            McpTransport::Stdio(inner) => {
                let mut guard = inner.lock().await;
                *guard = new_inner;
            }
            McpTransport::StreamableHttp(_) => {
                return Err("Reconnect is only supported for stdio transport".into());
            }
        }

        self.initialize_stdio_after_spawn().await?;
        Ok(())
    }

    async fn send_request_stdio_once(
        &self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, String> {
        let inner = match &self.transport {
            McpTransport::Stdio(inner) => inner,
            McpTransport::StreamableHttp(_) => {
                return Err("Internal error: stdio request on http transport".into());
            }
        };

        let mut inner = inner.lock().await;
        let id = inner.next_id;
        inner.next_id += 1;

        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(id),
            method: method.to_string(),
            params,
        };

        let mut json = serde_json::to_string(&request).map_err(|e| e.to_string())?;
        json.push('\n');

        inner
            .stdin
            .write_all(json.as_bytes())
            .await
            .map_err(|e| format!("Write error: {e}"))?;
        inner
            .stdin
            .flush()
            .await
            .map_err(|e| format!("Flush error: {e}"))?;

        let mut line = String::new();
        let deadline = tokio::time::Instant::now() + self.request_timeout;

        loop {
            line.clear();
            let read_result =
                tokio::time::timeout_at(deadline, inner.stdout.read_line(&mut line)).await;

            match read_result {
                Err(_) => {
                    return Err(format!(
                        "MCP server response timeout ({:?})",
                        self.request_timeout
                    ))
                }
                Ok(Err(e)) => return Err(format!("Read error: {e}")),
                Ok(Ok(0)) => return Err("MCP server closed connection".into()),
                Ok(Ok(_)) => {}
            }

            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            if let Ok(response) = serde_json::from_str::<JsonRpcResponse>(trimmed) {
                let is_response = match &response.id {
                    Some(serde_json::Value::Number(n)) => n.as_u64() == Some(id),
                    _ => response.result.is_some() || response.error.is_some(),
                };
                if !is_response {
                    continue;
                }
                if let Some(err) = response.error {
                    return Err(format!("MCP error ({}): {}", err.code, err.message));
                }
                return Ok(response.result.unwrap_or(serde_json::Value::Null));
            }
        }
    }

    async fn send_notification_stdio_once(
        &self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> Result<(), String> {
        let inner = match &self.transport {
            McpTransport::Stdio(inner) => inner,
            McpTransport::StreamableHttp(_) => {
                return Err("Internal error: stdio notification on http transport".into());
            }
        };

        let mut inner = inner.lock().await;
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: None,
            method: method.to_string(),
            params,
        };
        let mut json = serde_json::to_string(&request).map_err(|e| e.to_string())?;
        json.push('\n');
        inner
            .stdin
            .write_all(json.as_bytes())
            .await
            .map_err(|e| format!("Write error: {e}"))?;
        inner
            .stdin
            .flush()
            .await
            .map_err(|e| format!("Flush error: {e}"))?;
        Ok(())
    }

    async fn initialize_stdio_after_spawn(&self) -> Result<(), String> {
        let params = serde_json::json!({
            "protocolVersion": self.requested_protocol,
            "capabilities": {},
            "clientInfo": {
                "name": "microclaw",
                "version": env!("CARGO_PKG_VERSION")
            }
        });

        let result = self
            .send_request_stdio_once("initialize", Some(params))
            .await?;
        let negotiated = result
            .get("protocolVersion")
            .and_then(|v| v.as_str())
            .unwrap_or(&self.requested_protocol)
            .to_string();

        {
            let mut guard = self
                .negotiated_protocol
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            *guard = negotiated;
        }

        self.send_notification_stdio_once("notifications/initialized", None)
            .await?;
        Ok(())
    }

    async fn send_request_stdio_with_retries(
        &self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, String> {
        let mut last_err: Option<String> = None;

        for attempt in 0..=self.max_retries {
            match self.send_request_stdio_once(method, params.clone()).await {
                Ok(result) => return Ok(result),
                Err(err) => {
                    last_err = Some(err.clone());
                    if attempt >= self.max_retries
                        || self.stdio_spawn.is_none()
                        || !Self::should_attempt_reconnect(&err)
                    {
                        break;
                    }

                    warn!(
                        "MCP server '{}' request failed (attempt {}): {}. Reconnecting...",
                        self.name,
                        attempt + 1,
                        err
                    );
                    if let Err(reconnect_err) = self.reconnect_stdio(attempt).await {
                        return Err(format!(
                            "{err}; reconnect failed for '{}': {reconnect_err}",
                            self.name
                        ));
                    }
                }
            }
        }

        Err(last_err.unwrap_or_else(|| "Unknown MCP stdio error".to_string()))
    }

    async fn send_request_http(
        &self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, String> {
        let inner = match &self.transport {
            McpTransport::StreamableHttp(inner) => inner,
            McpTransport::Stdio(_) => {
                return Err("Internal error: http request on stdio transport".into());
            }
        };

        let mut inner = inner.lock().await;
        let id = inner.next_id;
        inner.next_id += 1;

        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(id),
            method: method.to_string(),
            params,
        };

        let mut req = inner.client.post(&inner.endpoint).json(&request);
        for (k, v) in &inner.headers {
            req = req.header(k, v);
        }

        let response = req
            .send()
            .await
            .map_err(|e| format!("HTTP request failed: {e}"))?;
        let status = response.status();
        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse HTTP MCP response: {e}"))?;

        if !status.is_success() {
            return Err(format!("HTTP MCP request failed with {status}: {body}"));
        }

        if let Ok(parsed) = serde_json::from_value::<JsonRpcResponse>(body.clone()) {
            if let Some(err) = parsed.error {
                return Err(format!("MCP error ({}): {}", err.code, err.message));
            }
            return Ok(parsed.result.unwrap_or(serde_json::Value::Null));
        }

        if let Some(result) = body.get("result") {
            return Ok(result.clone());
        }

        Ok(body)
    }

    async fn send_request(
        &self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, String> {
        let now = Instant::now();
        {
            let mut breaker = self
                .circuit_breaker
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Err(remaining_secs) = breaker.check_ready(now) {
                return Err(format!(
                    "MCP server '{}' circuit open; retry in ~{}s",
                    self.name, remaining_secs
                ));
            }
        }

        let result = match &self.transport {
            McpTransport::Stdio(_) => self.send_request_stdio_with_retries(method, params).await,
            McpTransport::StreamableHttp(_) => self.send_request_http(method, params).await,
        };

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

    async fn send_notification(
        &self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> Result<(), String> {
        match &self.transport {
            McpTransport::Stdio(_) => self.send_notification_stdio_once(method, params).await,
            McpTransport::StreamableHttp(inner) => {
                let inner = inner.lock().await;
                let request = JsonRpcRequest {
                    jsonrpc: "2.0".to_string(),
                    id: None,
                    method: method.to_string(),
                    params,
                };

                let mut req = inner.client.post(&inner.endpoint).json(&request);
                for (k, v) in &inner.headers {
                    req = req.header(k, v);
                }

                let response = req
                    .send()
                    .await
                    .map_err(|e| format!("HTTP notification failed: {e}"))?;
                if response.status().is_success() {
                    Ok(())
                } else {
                    Err(format!(
                        "HTTP notification failed with status {}",
                        response.status()
                    ))
                }
            }
        }
    }

    async fn initialize_connection(&self) -> Result<(), String> {
        let params = serde_json::json!({
            "protocolVersion": self.requested_protocol,
            "capabilities": {},
            "clientInfo": {
                "name": "microclaw",
                "version": env!("CARGO_PKG_VERSION")
            }
        });

        let result = self.send_request("initialize", Some(params)).await?;
        let negotiated = result
            .get("protocolVersion")
            .and_then(|v| v.as_str())
            .unwrap_or(&self.requested_protocol)
            .to_string();

        {
            let mut guard = self
                .negotiated_protocol
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if negotiated != self.requested_protocol {
                info!(
                    "MCP server '{}' negotiated protocol {} (requested {})",
                    self.name, negotiated, self.requested_protocol
                );
            }
            *guard = negotiated;
        }

        self.send_notification("notifications/initialized", None)
            .await?;

        Ok(())
    }

    async fn list_tools_uncached(&self) -> Result<Vec<McpToolInfo>, String> {
        let result = self
            .send_request("tools/list", Some(serde_json::json!({})))
            .await?;

        let tools_value = result.get("tools").ok_or("No tools in response")?;
        let tools_array = tools_value.as_array().ok_or("tools is not an array")?;

        let mut tools = Vec::new();
        for tool in tools_array {
            let name = tool
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let description = tool
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let input_schema = tool
                .get("inputSchema")
                .cloned()
                .unwrap_or_else(|| serde_json::json!({"type": "object", "properties": {}}));

            tools.push(McpToolInfo {
                server_name: self.name.clone(),
                name,
                description,
                input_schema,
            });
        }

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

    pub async fn call_tool(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
    ) -> Result<String, String> {
        let snapshot = self.tools_snapshot();
        if !snapshot.iter().any(|t| t.name == tool_name) {
            let _ = self.refresh_tools_cache(true).await;
        } else {
            let _ = self.refresh_tools_cache(false).await;
        }

        let params = serde_json::json!({
            "name": tool_name,
            "arguments": arguments
        });

        let result = match self.send_request("tools/call", Some(params)).await {
            Ok(result) => result,
            Err(err) => {
                if Self::is_tool_not_found_error(&err) {
                    self.invalidate_tools_cache();
                    let _ = self.refresh_tools_cache(true).await;
                }
                return Err(err);
            }
        };

        let is_error = result
            .get("isError")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if let Some(content) = result.get("content") {
            if let Some(array) = content.as_array() {
                let mut output = String::new();
                for item in array {
                    if let Some(text) = item.get("text").and_then(|v| v.as_str()) {
                        if !output.is_empty() {
                            output.push('\n');
                        }
                        output.push_str(text);
                    }
                }
                if is_error {
                    if Self::is_tool_not_found_error(&output) {
                        self.invalidate_tools_cache();
                        let _ = self.refresh_tools_cache(true).await;
                    }
                    return Err(output);
                }
                return Ok(output);
            }
        }

        let output = serde_json::to_string_pretty(&result).unwrap_or_default();
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
}

// --- MCP manager ---

pub struct McpManager {
    servers: Vec<Arc<McpServer>>,
}

impl McpManager {
    pub async fn from_config_file(path: &str) -> Self {
        let config_str = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => {
                // Config file not found is normal — MCP is optional
                return McpManager {
                    servers: Vec::new(),
                };
            }
        };

        let config: McpConfig = match serde_json::from_str(&config_str) {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to parse MCP config {path}: {e}");
                return McpManager {
                    servers: Vec::new(),
                };
            }
        };

        let mut servers = Vec::new();
        for (name, server_config) in &config.mcp_servers {
            info!("Connecting to MCP server '{name}'...");
            match tokio::time::timeout(
                Duration::from_secs(30),
                McpServer::connect(
                    name,
                    server_config,
                    config.default_protocol_version.as_deref(),
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
                        "MCP server '{name}' connected ({} tools, protocol {})",
                        server.tools_snapshot().len(),
                        server.protocol_version()
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
          "default_protocol_version": "2025-11-05",
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
        assert_eq!(cfg.default_protocol_version.unwrap(), "2025-11-05");
        let remote = cfg.mcp_servers.get("remote").unwrap();
        assert_eq!(remote.transport, "streamable_http");
        assert_eq!(remote.endpoint, "http://127.0.0.1:8080/mcp");
        assert_eq!(remote.max_retries, Some(3));
        assert_eq!(remote.health_interval_secs, Some(15));
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
