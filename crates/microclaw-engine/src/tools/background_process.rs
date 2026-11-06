//! Background shell processes for long-running commands.
//!
//! `bash` with `run_in_background: true` starts a host process (dev server,
//! file watcher, long test suite) and returns immediately with an id. The
//! `bash_output` tool returns output produced since the previous read plus the
//! exit status, and `bash_kill` stops the process. Processes are scoped to the
//! session that started them. The registry belongs to a `ToolRegistry`, so
//! every process still running is killed when that registry is dropped.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::json;
use tokio::io::AsyncReadExt;

use microclaw_core::llm_types::ToolDefinition;
use microclaw_core::text::floor_char_boundary;

use super::{schema_object, Tool, ToolResult};

/// Retained output per process; older bytes are dropped first.
const MAX_BUFFERED_BYTES: usize = 512 * 1024;
/// Output returned by a single `bash_output` call.
const MAX_RETURNED_BYTES: usize = 30_000;
/// Concurrent background processes per session.
const MAX_PROCESSES_PER_SESSION: usize = 8;

#[derive(Default)]
struct OutputBuffer {
    text: String,
    /// Absolute offset of `text[0]` in the full output stream.
    base: usize,
    /// Absolute offset the agent has read up to.
    cursor: usize,
}

impl OutputBuffer {
    fn push(&mut self, chunk: &str) {
        self.text.push_str(chunk);
        if self.text.len() > MAX_BUFFERED_BYTES {
            let excess = self.text.len() - MAX_BUFFERED_BYTES;
            let cut = floor_char_boundary(&self.text, excess);
            self.text.drain(..cut);
            self.base += cut;
        }
    }

    /// Return unread output (bounded) and whether earlier output was dropped.
    fn take_unread(&mut self) -> (String, bool) {
        let mut dropped = false;
        if self.cursor < self.base {
            self.cursor = self.base;
            dropped = true;
        }
        let start = self.cursor - self.base;
        let mut end = self.text.len();
        if end - start > MAX_RETURNED_BYTES {
            end = floor_char_boundary(&self.text, start + MAX_RETURNED_BYTES);
        }
        let out = self.text[start..end].to_string();
        self.cursor = self.base + end;
        (out, dropped)
    }

    fn has_unread(&self) -> bool {
        self.base + self.text.len() > self.cursor
    }
}

struct BackgroundProcess {
    session: String,
    command: String,
    started_at: chrono::DateTime<chrono::Utc>,
    output: Arc<Mutex<OutputBuffer>>,
    exit_code: Arc<Mutex<Option<i32>>>,
    kill_tx: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    /// The process's stdin, for `bash_input` (`None` once closed).
    stdin: tokio::sync::Mutex<Option<tokio::process::ChildStdin>>,
}

/// Background processes started through one tool registry.
#[derive(Default)]
pub struct ProcessRegistry {
    processes: Mutex<HashMap<String, Arc<BackgroundProcess>>>,
}

impl Drop for ProcessRegistry {
    fn drop(&mut self) {
        let processes = self.processes.get_mut().unwrap_or_else(|e| e.into_inner());
        for process in processes.values() {
            if let Some(tx) = lock(&process.kill_tx).take() {
                let _ = tx.send(());
            }
        }
    }
}

/// SIGKILL the process group led by `pid` (see `process_group(0)`).
fn kill_group(pid: Option<u32>) {
    #[cfg(unix)]
    if let Some(pid) = pid.and_then(|p| libc::pid_t::try_from(p).ok()) {
        // SAFETY: plain syscall on a group id this registry created.
        unsafe {
            libc::killpg(pid, libc::SIGKILL);
        }
    }
    #[cfg(not(unix))]
    let _ = pid;
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

fn next_id() -> String {
    let short = uuid::Uuid::new_v4().simple().to_string();
    format!("bg_{}", &short[..8])
}

/// Session key used to scope background processes to the chat that owns them.
pub fn session_key(input: &serde_json::Value) -> String {
    super::auth_context_from_input(input)
        .map(|auth| format!("{}-{}", auth.caller_channel, auth.caller_chat_id))
        .unwrap_or_else(|| "shared".to_string())
}

impl ProcessRegistry {
    /// Spawn `command` in `working_dir` on the host and register it.
    pub fn spawn(
        &self,
        session: &str,
        command: &str,
        working_dir: &Path,
        envs: &HashMap<String, String>,
    ) -> Result<String, String> {
        let spec = crate::internal::tool_runtime::command_runner::shell_command(command);
        self.spawn_spec(session, command, &spec, working_dir, envs)
    }

    /// Spawn an already-built command line (e.g. wrapped by the local OS
    /// sandbox) and register it.
    pub fn spawn_spec(
        &self,
        session: &str,
        command: &str,
        spec: &crate::internal::tool_runtime::command_runner::CommandSpec,
        working_dir: &Path,
        envs: &HashMap<String, String>,
    ) -> Result<String, String> {
        let running = lock(&self.processes)
            .values()
            .filter(|p| p.session == session && lock(&p.exit_code).is_none())
            .count();
        if running >= MAX_PROCESSES_PER_SESSION {
            return Err(format!(
            "Too many background processes are running ({running}). Stop one with bash_kill first."
        ));
        }
        let mut cmd =
            crate::internal::tool_runtime::command_runner::build_command(spec, Some(working_dir));
        for (k, v) in envs {
            cmd.env(k, v);
        }
        cmd.stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .stdin(std::process::Stdio::piped())
            .kill_on_drop(true);
        // Its own process group, so bash_kill stops the whole command
        // (`cd app && npm run dev` leaves node as a grandchild that holds the
        // output pipes), not only the shell.
        #[cfg(unix)]
        cmd.process_group(0);
        let mut child = cmd
            .spawn()
            .map_err(|e| format!("Failed to start background command: {e}"))?;
        let stdin = child.stdin.take();
        let pid = child.id();

        let id = next_id();
        let output = Arc::new(Mutex::new(OutputBuffer::default()));
        let exit_code = Arc::new(Mutex::new(None));
        let (kill_tx, mut kill_rx) = tokio::sync::oneshot::channel::<()>();

        let readers: Vec<_> = [
            child
                .stdout
                .take()
                .map(|s| Box::new(s) as Box<dyn tokio::io::AsyncRead + Unpin + Send>),
            child
                .stderr
                .take()
                .map(|s| Box::new(s) as Box<dyn tokio::io::AsyncRead + Unpin + Send>),
        ]
        .into_iter()
        .flatten()
        .map(|mut stream| {
            let output = output.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => lock(&output).push(&String::from_utf8_lossy(&buf[..n])),
                    }
                }
            })
        })
        .collect();

        {
            let exit_code = exit_code.clone();
            tokio::spawn(async move {
                let status = tokio::select! {
                    status = child.wait() => status.ok().and_then(|s| s.code()).unwrap_or(-1),
                    _ = &mut kill_rx => {
                        kill_group(pid);
                        let _ = child.kill().await;
                        -9
                    }
                };
                // A process that left the group can keep the pipes open;
                // after a kill, do not wait for it.
                for reader in readers {
                    if status == -9 {
                        let _ =
                            tokio::time::timeout(std::time::Duration::from_secs(2), reader).await;
                    } else {
                        let _ = reader.await;
                    }
                }
                *lock(&exit_code) = Some(status);
            });
        }

        lock(&self.processes).insert(
            id.clone(),
            Arc::new(BackgroundProcess {
                session: session.to_string(),
                command: command.to_string(),
                started_at: chrono::Utc::now(),
                output,
                exit_code,
                kill_tx: Mutex::new(Some(kill_tx)),
                stdin: tokio::sync::Mutex::new(stdin),
            }),
        );
        Ok(id)
    }

    fn lookup(&self, session: &str, id: &str) -> Result<Arc<BackgroundProcess>, String> {
        let registry = lock(&self.processes);
        match registry.get(id) {
            Some(process) if process.session == session => Ok(process.clone()),
            _ => {
                let known: Vec<_> = registry
                    .iter()
                    .filter(|(_, p)| p.session == session)
                    .map(|(id, p)| format!("{id} ({})", p.command))
                    .collect();
                let hint = if known.is_empty() {
                    "No background processes exist in this session.".to_string()
                } else {
                    format!("Known processes: {}", known.join(", "))
                };
                Err(format!("Unknown background process '{id}'. {hint}"))
            }
        }
    }
}

fn status_line(process: &BackgroundProcess) -> String {
    let elapsed = (chrono::Utc::now() - process.started_at)
        .num_seconds()
        .max(0);
    match *lock(&process.exit_code) {
        Some(code) => format!("status: exited with code {code} (after {elapsed}s)"),
        None => format!("status: running ({elapsed}s)"),
    }
}

/// Write to a background process's stdin: answer prompts, drive a REPL or an
/// interactive CLI started with `run_in_background`.
pub struct BashInputTool(pub Arc<ProcessRegistry>);

/// How long `bash_input` waits for the process to answer.
const INPUT_SETTLE_MS: u64 = 400;

#[async_trait]
impl Tool for BashInputTool {
    fn name(&self) -> &str {
        "bash_input"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "bash_input".into(),
            description: "Send text to the stdin of a background process started with bash run_in_background (a REPL, a debugger, a command waiting for an answer), then return the output it produced. Include a trailing newline to submit a line. Set close to true to send end-of-input. The process has no terminal, so start REPLs in a line-oriented, unbuffered mode (e.g. `python3 -u -i`, `node -i`).".into(),
            input_schema: schema_object(
                json!({
                    "id": {
                        "type": "string",
                        "description": "Background process id returned by bash (e.g. bg_1a2b3c4d)"
                    },
                    "input": {
                        "type": "string",
                        "description": "Text to write; usually ends with \\n"
                    },
                    "close": {
                        "type": "boolean",
                        "description": "Close stdin after writing (end of input)"
                    },
                    "wait_ms": {
                        "type": "integer",
                        "description": "How long to wait for output before returning (default 400, max 10000)"
                    }
                }),
                &["id"],
            ),
        }
    }

    async fn execute(&self, input: serde_json::Value) -> ToolResult {
        let session = session_key(&input);
        let Some(id) = input.get("id").and_then(|v| v.as_str()) else {
            return ToolResult::error("Missing 'id' parameter".into());
        };
        let process = match self.0.lookup(&session, id) {
            Ok(process) => process,
            Err(msg) => return ToolResult::error(msg),
        };
        let text = input.get("input").and_then(|v| v.as_str()).unwrap_or("");
        let close = input
            .get("close")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        {
            let mut stdin = process.stdin.lock().await;
            let Some(pipe) = stdin.as_mut() else {
                return ToolResult::error(format!("{id}: stdin is already closed"));
            };
            if !text.is_empty() {
                use tokio::io::AsyncWriteExt;
                if let Err(e) = pipe.write_all(text.as_bytes()).await {
                    return ToolResult::error(format!(
                        "{id}: could not write to stdin ({e}); {}",
                        status_line(&process)
                    ));
                }
                let _ = pipe.flush().await;
            }
            if close {
                *stdin = None;
            }
        }
        let wait = input
            .get("wait_ms")
            .and_then(|v| v.as_u64())
            .unwrap_or(INPUT_SETTLE_MS)
            .min(10_000);
        tokio::time::sleep(std::time::Duration::from_millis(wait)).await;
        let (output, dropped) = lock(&process.output).take_unread();
        let mut text = format!("{}\n", status_line(&process));
        if dropped {
            text.push_str("[earlier output was dropped]\n");
        }
        if output.is_empty() {
            text.push_str("(no new output yet; read it later with bash_output)");
        } else {
            text.push_str(&output);
        }
        ToolResult::success(text)
    }
}

pub struct BashOutputTool(pub Arc<ProcessRegistry>);

#[async_trait]
impl Tool for BashOutputTool {
    fn name(&self) -> &str {
        "bash_output"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "bash_output".into(),
            description: "Read new output from a background process started with bash run_in_background. Returns output produced since the previous read and whether the process is still running. Omit id to list this session's background processes.".into(),
            input_schema: schema_object(
                json!({
                    "id": {
                        "type": "string",
                        "description": "Background process id returned by bash (e.g. bg_1a2b3c4d)"
                    },
                    "filter": {
                        "type": "string",
                        "description": "Optional regex; only matching output lines are returned"
                    }
                }),
                &[],
            ),
        }
    }

    async fn execute(&self, input: serde_json::Value) -> ToolResult {
        let session = session_key(&input);
        let Some(id) = input.get("id").and_then(|v| v.as_str()) else {
            let registry = lock(&self.0.processes);
            let mut rows: Vec<_> = registry
                .iter()
                .filter(|(_, p)| p.session == session)
                .map(|(id, p)| {
                    (
                        p.started_at,
                        format!("{id}  {}  {}", status_line(p), p.command),
                    )
                })
                .collect();
            rows.sort();
            return if rows.is_empty() {
                ToolResult::success("No background processes in this session.".into())
            } else {
                ToolResult::success(
                    rows.into_iter()
                        .map(|(_, row)| row)
                        .collect::<Vec<_>>()
                        .join("\n"),
                )
            };
        };
        let process = match self.0.lookup(&session, id) {
            Ok(p) => p,
            Err(msg) => return ToolResult::error(msg),
        };
        let filter = match input.get("filter").and_then(|v| v.as_str()) {
            Some(raw) => match regex::Regex::new(raw) {
                Ok(re) => Some(re),
                Err(e) => return ToolResult::error(format!("Invalid filter regex: {e}")),
            },
            None => None,
        };
        let (mut text, dropped) = lock(&process.output).take_unread();
        if let Some(re) = filter {
            text = text
                .lines()
                .filter(|line| re.is_match(line))
                .collect::<Vec<_>>()
                .join("\n");
        }
        let more = lock(&process.output).has_unread();
        let mut out = format!("{id}  {}\n", status_line(&process));
        if dropped {
            out.push_str("(older output was dropped; only the most recent output is retained)\n");
        }
        if text.is_empty() {
            out.push_str("(no new output)");
        } else {
            out.push_str(&text);
        }
        if more {
            out.push_str("\n... (more output available; call bash_output again)");
        }
        ToolResult::success(out)
    }
}

pub struct BashKillTool(pub Arc<ProcessRegistry>);

#[async_trait]
impl Tool for BashKillTool {
    fn name(&self) -> &str {
        "bash_kill"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "bash_kill".into(),
            description: "Stop a background process started with bash run_in_background.".into(),
            input_schema: schema_object(
                json!({
                    "id": {
                        "type": "string",
                        "description": "Background process id returned by bash"
                    }
                }),
                &["id"],
            ),
        }
    }

    async fn execute(&self, input: serde_json::Value) -> ToolResult {
        let session = session_key(&input);
        let Some(id) = input.get("id").and_then(|v| v.as_str()) else {
            return ToolResult::error("Missing 'id' parameter".into());
        };
        let process = match self.0.lookup(&session, id) {
            Ok(p) => p,
            Err(msg) => return ToolResult::error(msg),
        };
        if lock(&process.exit_code).is_some() {
            return ToolResult::success(format!(
                "{id} already finished; {}",
                status_line(&process)
            ));
        }
        if let Some(tx) = lock(&process.kill_tx).take() {
            let _ = tx.send(());
        }
        for _ in 0..50 {
            if lock(&process.exit_code).is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        ToolResult::success(format!("Stopped {id}; {}", status_line(&process)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_buffer_tracks_cursor_and_drops_oldest() {
        let mut buf = OutputBuffer::default();
        buf.push("hello ");
        buf.push("world");
        assert_eq!(buf.take_unread(), ("hello world".to_string(), false));
        assert!(!buf.has_unread());
        buf.push(&"x".repeat(MAX_BUFFERED_BYTES + 10));
        let (text, dropped) = buf.take_unread();
        assert!(dropped);
        assert_eq!(text.len(), MAX_RETURNED_BYTES);
        assert!(buf.has_unread());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn bash_input_drives_an_interactive_process() {
        let dir = tempfile::tempdir().unwrap();
        let auth = json!({"caller_channel": "test", "caller_chat_id": 7, "control_chat_ids": []});
        let session = session_key(&json!({"__microclaw_auth": auth.clone()}));
        let registry = Arc::new(ProcessRegistry::default());
        let input_tool = BashInputTool(registry.clone());
        // A line-oriented "REPL": echoes each line upper-cased until EOF.
        let id = registry
            .spawn(
                &session,
                "while read line; do echo \"got:$line\" | tr a-z A-Z; done; echo bye",
                dir.path(),
                &HashMap::new(),
            )
            .unwrap();
        let first = input_tool
            .execute(json!({"id": id, "input": "hello\n", "wait_ms": 1000, "__microclaw_auth": auth.clone()}))
            .await;
        assert!(!first.is_error, "{}", first.content);
        assert!(first.content.contains("GOT:HELLO"), "{}", first.content);
        let last = input_tool
            .execute(json!({"id": id, "input": "again\n", "close": true, "wait_ms": 1000, "__microclaw_auth": auth.clone()}))
            .await;
        assert!(last.content.contains("GOT:AGAIN"), "{}", last.content);
        assert!(last.content.contains("bye"), "{}", last.content);
        let closed = input_tool
            .execute(json!({"id": id, "input": "x\n", "__microclaw_auth": auth}))
            .await;
        assert!(closed.is_error);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn background_process_streams_output_and_can_be_killed() {
        let dir = tempfile::tempdir().unwrap();
        let input = |extra: serde_json::Value| {
            let mut value = json!({
                "__microclaw_auth": {
                    "caller_channel": "test",
                    "caller_chat_id": 1,
                    "control_chat_ids": []
                }
            });
            if let (Some(map), Some(extra)) = (value.as_object_mut(), extra.as_object()) {
                map.extend(extra.clone());
            }
            value
        };
        let session = session_key(&input(json!({})));
        let registry = Arc::new(ProcessRegistry::default());
        let output_tool = BashOutputTool(registry.clone());
        let kill_tool = BashKillTool(registry.clone());
        let id = registry
            .spawn(
                &session,
                "echo started; sleep 30",
                dir.path(),
                &HashMap::new(),
            )
            .unwrap();
        let mut seen = String::new();
        for _ in 0..100 {
            let result = output_tool.execute(input(json!({"id": id}))).await;
            seen.push_str(&result.content);
            if seen.contains("started") {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(seen.contains("started"), "{seen}");
        assert!(seen.contains("running"));

        let listed = output_tool.execute(input(json!({}))).await;
        assert!(listed.content.contains(&id));

        let killed = kill_tool.execute(input(json!({"id": id}))).await;
        assert!(killed.content.contains("exited"), "{}", killed.content);

        let other_session = output_tool
            .execute(json!({"id": id, "__microclaw_auth": {"caller_channel": "other", "caller_chat_id": 2, "control_chat_ids": []}}))
            .await;
        assert!(other_session.is_error);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn dropping_the_registry_kills_running_processes() {
        let dir = tempfile::tempdir().unwrap();
        let registry = Arc::new(ProcessRegistry::default());
        let id = registry
            .spawn("s", "sleep 30", dir.path(), &HashMap::new())
            .unwrap();
        let process = registry.lookup("s", &id).unwrap();
        drop(registry);
        for _ in 0..100 {
            if lock(&process.exit_code).is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(
            lock(&process.exit_code).is_some(),
            "process should be killed"
        );
    }
}
