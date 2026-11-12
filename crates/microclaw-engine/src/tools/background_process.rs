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
use std::sync::atomic::{AtomicBool, Ordering};
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
    /// A foreground `bash` call is still waiting for this process. Cleared
    /// when the user moves it to the background ([`ProcessRegistry::detach_foreground`]).
    foreground: AtomicBool,
}

impl BackgroundProcess {
    fn is_foreground(&self) -> bool {
        self.foreground.load(Ordering::SeqCst)
    }

    fn request_kill(&self) {
        if let Some(tx) = lock(&self.kill_tx).take() {
            let _ = tx.send(());
        }
    }
}

/// How a foreground command run through the registry ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForegroundOutcome {
    /// The command finished; its combined output.
    Exited { code: i32, output: String },
    /// The user moved the command to the background; it keeps running under `id`.
    Detached { id: String },
    /// The timeout passed; the command was stopped.
    TimedOut { output: String },
}

/// A background process as listed for the user (`/jobs`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackgroundJob {
    pub id: String,
    pub command: String,
    pub started_at: chrono::DateTime<chrono::Utc>,
    /// `None` while running.
    pub exit_code: Option<i32>,
}

/// Stops a foreground process whose `bash` call went away (the run was
/// cancelled) while it was still in the foreground.
struct ForegroundGuard<'a> {
    registry: &'a ProcessRegistry,
    id: String,
    process: Arc<BackgroundProcess>,
    done: bool,
}

impl Drop for ForegroundGuard<'_> {
    fn drop(&mut self) {
        if !self.done && self.process.is_foreground() {
            self.process.request_kill();
            lock(&self.registry.processes).remove(&self.id);
        }
    }
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
            process.request_kill();
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
        .map(|auth| session_key_for(&auth.caller_channel, auth.caller_chat_id))
        .unwrap_or_else(|| "shared".to_string())
}

/// The session key of one chat (see [`session_key`]).
pub fn session_key_for(caller_channel: &str, chat_id: i64) -> String {
    format!("{caller_channel}-{chat_id}")
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
            .filter(|p| p.session == session && !p.is_foreground() && lock(&p.exit_code).is_none())
            .count();
        if running >= MAX_PROCESSES_PER_SESSION {
            return Err(format!(
            "Too many background processes are running ({running}). Stop one with bash_kill first."
        ));
        }
        self.spawn_inner(session, command, spec, working_dir, envs, false)
            .map(|(id, _)| id)
    }

    /// Run a command in the foreground: wait until it exits, the timeout
    /// passes (the command is stopped) or the user moves it to the background
    /// with [`Self::detach_foreground`] (it keeps running as a background
    /// process). Dropping the returned future stops a command that is still
    /// in the foreground.
    pub async fn run_foreground(
        &self,
        session: &str,
        command: &str,
        spec: &crate::internal::tool_runtime::command_runner::CommandSpec,
        working_dir: &Path,
        envs: &HashMap<String, String>,
        timeout: std::time::Duration,
    ) -> Result<ForegroundOutcome, String> {
        let (id, process) = self.spawn_inner(session, command, spec, working_dir, envs, true)?;
        let mut guard = ForegroundGuard {
            registry: self,
            id: id.clone(),
            process: process.clone(),
            done: false,
        };
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if let Some(code) = *lock(&process.exit_code) {
                guard.done = true;
                lock(&self.processes).remove(&id);
                return Ok(ForegroundOutcome::Exited {
                    code,
                    output: full_output(&process),
                });
            }
            if !process.is_foreground() {
                guard.done = true;
                return Ok(ForegroundOutcome::Detached { id });
            }
            if tokio::time::Instant::now() >= deadline {
                guard.done = true;
                process.request_kill();
                for _ in 0..100 {
                    if lock(&process.exit_code).is_some() {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
                lock(&self.processes).remove(&id);
                return Ok(ForegroundOutcome::TimedOut {
                    output: full_output(&process),
                });
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }

    /// Move every foreground command of `session` to the background. Returns
    /// their ids (empty when nothing was running in the foreground).
    pub fn detach_foreground(&self, session: &str) -> Vec<String> {
        let mut ids: Vec<String> = lock(&self.processes)
            .iter()
            .filter(|(_, p)| p.session == session && lock(&p.exit_code).is_none())
            .filter(|(_, p)| p.foreground.swap(false, Ordering::SeqCst))
            .map(|(id, _)| id.clone())
            .collect();
        ids.sort();
        ids
    }

    /// Background processes of `session`, oldest first.
    pub fn jobs(&self, session: &str) -> Vec<BackgroundJob> {
        let mut jobs: Vec<BackgroundJob> = lock(&self.processes)
            .iter()
            .filter(|(_, p)| p.session == session && !p.is_foreground())
            .map(|(id, p)| BackgroundJob {
                id: id.clone(),
                command: p.command.clone(),
                started_at: p.started_at,
                exit_code: *lock(&p.exit_code),
            })
            .collect();
        jobs.sort_by(|a, b| a.started_at.cmp(&b.started_at).then(a.id.cmp(&b.id)));
        jobs
    }

    /// The last `max_bytes` of a background process's output, without
    /// moving the agent's read cursor.
    pub fn output_tail(&self, session: &str, id: &str, max_bytes: usize) -> Result<String, String> {
        let process = self.lookup(session, id)?;
        let output = lock(&process.output);
        let text = output.text.as_str();
        let start = if text.len() > max_bytes {
            let mut cut = text.len() - max_bytes;
            while !text.is_char_boundary(cut) {
                cut += 1;
            }
            cut
        } else {
            0
        };
        Ok(text[start..].to_string())
    }

    /// Stop a background process. Returns its status line.
    pub async fn kill(&self, session: &str, id: &str) -> Result<String, String> {
        let process = self.lookup(session, id)?;
        if lock(&process.exit_code).is_some() {
            return Ok(format!("{id} already finished; {}", status_line(&process)));
        }
        process.request_kill();
        for _ in 0..50 {
            if lock(&process.exit_code).is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        Ok(format!("Stopped {id}; {}", status_line(&process)))
    }

    fn spawn_inner(
        &self,
        session: &str,
        command: &str,
        spec: &crate::internal::tool_runtime::command_runner::CommandSpec,
        working_dir: &Path,
        envs: &HashMap<String, String>,
        foreground: bool,
    ) -> Result<(String, Arc<BackgroundProcess>), String> {
        let mut cmd =
            crate::internal::tool_runtime::command_runner::build_command(spec, Some(working_dir));
        for (k, v) in envs {
            cmd.env(k, v);
        }
        // A foreground command gets no stdin, like the plain foreground path
        // (a command that reads it sees end-of-input instead of hanging).
        let stdin = if foreground {
            std::process::Stdio::null()
        } else {
            std::process::Stdio::piped()
        };
        cmd.stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .stdin(stdin)
            .kill_on_drop(true);
        // Its own process group, so bash_kill stops the whole command
        // (`cd app && npm run dev` leaves node as a grandchild that holds the
        // output pipes), not only the shell.
        #[cfg(unix)]
        cmd.process_group(0);
        let mut child = cmd.spawn().map_err(|e| {
            if foreground {
                format!("Failed to execute command: {e}")
            } else {
                format!("Failed to start background command: {e}")
            }
        })?;
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

        let process = Arc::new(BackgroundProcess {
            session: session.to_string(),
            command: command.to_string(),
            started_at: chrono::Utc::now(),
            output,
            exit_code,
            kill_tx: Mutex::new(Some(kill_tx)),
            stdin: tokio::sync::Mutex::new(stdin),
            foreground: AtomicBool::new(foreground),
        });
        lock(&self.processes).insert(id.clone(), process.clone());
        Ok((id, process))
    }

    fn lookup(&self, session: &str, id: &str) -> Result<Arc<BackgroundProcess>, String> {
        let registry = lock(&self.processes);
        match registry.get(id) {
            Some(process) if process.session == session && !process.is_foreground() => {
                Ok(process.clone())
            }
            _ => {
                let known: Vec<_> = registry
                    .iter()
                    .filter(|(_, p)| p.session == session && !p.is_foreground())
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

/// Everything a process printed that is still buffered (all of it unless it
/// passed [`MAX_BUFFERED_BYTES`]).
fn full_output(process: &BackgroundProcess) -> String {
    let output = lock(&process.output);
    if output.base > 0 {
        format!(
            "(earlier output was dropped; only the most recent output is retained)\n{}",
            output.text
        )
    } else {
        output.text.clone()
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
                .filter(|(_, p)| p.session == session && !p.is_foreground())
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
        match self.0.kill(&session, id).await {
            Ok(status) => ToolResult::success(status),
            Err(msg) => ToolResult::error(msg),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn shell(command: &str) -> crate::internal::tool_runtime::command_runner::CommandSpec {
        crate::internal::tool_runtime::command_runner::shell_command(command)
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn foreground_run_returns_combined_output_and_exit_code() {
        let dir = tempfile::tempdir().unwrap();
        let registry = ProcessRegistry::default();
        let outcome = registry
            .run_foreground(
                "s",
                "echo out; echo err >&2; exit 3",
                &shell("echo out; echo err >&2; exit 3"),
                dir.path(),
                &HashMap::new(),
                std::time::Duration::from_secs(10),
            )
            .await
            .unwrap();
        let ForegroundOutcome::Exited { code, output } = outcome else {
            panic!("expected exit, got {outcome:?}");
        };
        assert_eq!(code, 3);
        assert!(output.contains("out") && output.contains("err"), "{output}");
        // A finished foreground command is not a background job.
        assert!(registry.jobs("s").is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn foreground_run_gets_no_stdin() {
        let dir = tempfile::tempdir().unwrap();
        let registry = ProcessRegistry::default();
        // `cat` with an open stdin would wait until the timeout.
        let outcome = registry
            .run_foreground(
                "s",
                "cat",
                &shell("cat; echo done"),
                dir.path(),
                &HashMap::new(),
                std::time::Duration::from_secs(10),
            )
            .await
            .unwrap();
        assert!(
            matches!(&outcome, ForegroundOutcome::Exited { code: 0, output } if output.contains("done")),
            "{outcome:?}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn foreground_run_times_out_and_stops_the_command() {
        let dir = tempfile::tempdir().unwrap();
        let registry = ProcessRegistry::default();
        let outcome = registry
            .run_foreground(
                "s",
                "sleep",
                &shell("echo before; sleep 30"),
                dir.path(),
                &HashMap::new(),
                std::time::Duration::from_millis(300),
            )
            .await
            .unwrap();
        assert!(
            matches!(&outcome, ForegroundOutcome::TimedOut { output } if output.contains("before")),
            "{outcome:?}"
        );
        assert!(registry.jobs("s").is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn detached_foreground_command_keeps_running_as_a_job() {
        let dir = tempfile::tempdir().unwrap();
        let registry = Arc::new(ProcessRegistry::default());
        let run = {
            let registry = registry.clone();
            let cwd = dir.path().to_path_buf();
            tokio::spawn(async move {
                registry
                    .run_foreground(
                        "s",
                        "slow",
                        &shell("echo started; sleep 30"),
                        &cwd,
                        &HashMap::new(),
                        std::time::Duration::from_secs(60),
                    )
                    .await
            })
        };
        // Wait until it runs, then detach it; another session sees nothing.
        let mut detached = Vec::new();
        for _ in 0..100 {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            assert!(registry.detach_foreground("other").is_empty());
            detached = registry.detach_foreground("s");
            if !detached.is_empty() {
                break;
            }
        }
        assert_eq!(detached.len(), 1);
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), run)
            .await
            .expect("the foreground call returns once detached")
            .unwrap()
            .unwrap();
        assert_eq!(
            outcome,
            ForegroundOutcome::Detached {
                id: detached[0].clone()
            }
        );
        let jobs = registry.jobs("s");
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].exit_code, None);
        for _ in 0..100 {
            if registry
                .output_tail("s", &jobs[0].id, 100)
                .unwrap()
                .contains("started")
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(registry
            .output_tail("s", &jobs[0].id, 100)
            .unwrap()
            .contains("started"));
        assert!(registry.output_tail("other", &jobs[0].id, 100).is_err());
        let status = registry.kill("s", &jobs[0].id).await.unwrap();
        assert!(status.starts_with("Stopped"), "{status}");
        assert_eq!(registry.jobs("s")[0].exit_code, Some(-9));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn dropping_a_foreground_run_stops_the_command() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("still-running");
        let registry = ProcessRegistry::default();
        let command = format!("sleep 1; touch {}", marker.display());
        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            registry.run_foreground(
                "s",
                &command,
                &shell(&command),
                dir.path(),
                &HashMap::new(),
                std::time::Duration::from_secs(30),
            ),
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        assert!(!marker.exists(), "the cancelled command kept running");
        assert!(registry.jobs("s").is_empty());
    }

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
