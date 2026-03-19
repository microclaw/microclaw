use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use agent_client_protocol::{
    self as acp, Agent as _, Client, ClientCapabilities, ClientSideConnection,
    FileSystemCapabilities, InitializeRequest, ProtocolVersion, RequestPermissionOutcome,
    SelectedPermissionOutcome,
};
use async_trait::async_trait;
use serde_json::json;
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

use crate::config::Config;
use crate::tools::{resolve_tool_working_dir, ToolAuthContext};
use microclaw_core::text::floor_char_boundary;
use microclaw_storage::db::Database;

const ACP_RUNTIME_PROVIDER: &str = "acp";
const ACP_AGENT_STDERR_LIMIT_BYTES: usize = 16 * 1024;
const ACP_TERMINAL_OUTPUT_LIMIT_BYTES: usize = 256 * 1024;
const ACP_CANCEL_POLL_MS: u64 = 350;

pub struct AcpSubagentTaskParams {
    pub config: Config,
    pub db: Arc<Database>,
    pub auth_context: ToolAuthContext,
    pub run_id: String,
    pub task: String,
    pub context: String,
    pub local_cancel: Arc<AtomicBool>,
}

#[derive(Default)]
struct RetainedText {
    text: String,
    truncated: bool,
}

#[derive(Default)]
struct TranscriptState {
    message_text: String,
    notes: Vec<String>,
}

struct TerminalSession {
    child: Mutex<tokio::process::Child>,
    output: Arc<Mutex<RetainedText>>,
    exit_status: Mutex<Option<acp::TerminalExitStatus>>,
}

impl TerminalSession {
    async fn output_response(&self) -> Result<acp::TerminalOutputResponse, acp::Error> {
        let exit_status = self.try_refresh_exit_status().await?;
        let output = self.output.lock().await;
        Ok(
            acp::TerminalOutputResponse::new(output.text.clone(), output.truncated)
                .exit_status(exit_status),
        )
    }

    async fn try_refresh_exit_status(&self) -> Result<Option<acp::TerminalExitStatus>, acp::Error> {
        if let Some(existing) = self.exit_status.lock().await.clone() {
            return Ok(Some(existing));
        }
        let maybe_status = {
            let mut child = self.child.lock().await;
            child.try_wait().map_err(internal_error)?
        };
        if let Some(status) = maybe_status {
            let mapped = map_exit_status(status);
            *self.exit_status.lock().await = Some(mapped.clone());
            Ok(Some(mapped))
        } else {
            Ok(None)
        }
    }

    async fn wait_for_exit(&self) -> Result<acp::WaitForTerminalExitResponse, acp::Error> {
        if let Some(existing) = self.exit_status.lock().await.clone() {
            return Ok(acp::WaitForTerminalExitResponse::new(existing));
        }
        let status = {
            let mut child = self.child.lock().await;
            child.wait().await.map_err(internal_error)?
        };
        let mapped = map_exit_status(status);
        *self.exit_status.lock().await = Some(mapped.clone());
        Ok(acp::WaitForTerminalExitResponse::new(mapped))
    }

    async fn kill(&self) -> Result<(), acp::Error> {
        if self.exit_status.lock().await.is_some() {
            return Ok(());
        }
        let status = {
            let mut child = self.child.lock().await;
            let _ = child.start_kill();
            child.wait().await.map_err(internal_error)?
        };
        *self.exit_status.lock().await = Some(map_exit_status(status));
        Ok(())
    }
}

#[derive(Clone)]
struct AcpSessionClient {
    working_dir: PathBuf,
    auto_approve: bool,
    transcript: Arc<Mutex<TranscriptState>>,
    terminals: Arc<Mutex<HashMap<String, Arc<TerminalSession>>>>,
}

impl AcpSessionClient {
    fn new(working_dir: PathBuf, auto_approve: bool) -> Self {
        Self {
            working_dir,
            auto_approve,
            transcript: Arc::new(Mutex::new(TranscriptState::default())),
            terminals: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn final_text(&self) -> String {
        let transcript = self.transcript.lock().await;
        if transcript.message_text.trim().is_empty() {
            transcript.notes.join("\n")
        } else if transcript.notes.is_empty() {
            transcript.message_text.clone()
        } else {
            format!(
                "{}\n\n{}",
                transcript.message_text,
                transcript.notes.join("\n")
            )
        }
    }

    async fn kill_all_terminals(&self) {
        let sessions = {
            let guard = self.terminals.lock().await;
            guard.values().cloned().collect::<Vec<_>>()
        };
        for session in sessions {
            let _ = session.kill().await;
        }
    }

    async fn append_note(&self, note: String) {
        if note.trim().is_empty() {
            return;
        }
        self.transcript.lock().await.notes.push(note);
    }
}

#[async_trait(?Send)]
impl Client for AcpSessionClient {
    async fn request_permission(
        &self,
        args: acp::RequestPermissionRequest,
    ) -> Result<acp::RequestPermissionResponse, acp::Error> {
        let title = args
            .tool_call
            .fields
            .title
            .clone()
            .unwrap_or_else(|| "ACP tool call".to_string());
        self.append_note(format!("[acp] permission requested: {title}"))
            .await;

        let preferred = if self.auto_approve {
            args.options
                .iter()
                .find(|opt| {
                    matches!(
                        opt.kind,
                        acp::PermissionOptionKind::AllowOnce
                            | acp::PermissionOptionKind::AllowAlways
                    )
                })
                .or_else(|| args.options.first())
        } else {
            args.options.iter().find(|opt| {
                matches!(
                    opt.kind,
                    acp::PermissionOptionKind::RejectOnce | acp::PermissionOptionKind::RejectAlways
                )
            })
        };

        let Some(selected) = preferred else {
            return Ok(acp::RequestPermissionResponse::new(
                RequestPermissionOutcome::Cancelled,
            ));
        };

        Ok(acp::RequestPermissionResponse::new(
            RequestPermissionOutcome::Selected(SelectedPermissionOutcome::new(
                selected.option_id.clone(),
            )),
        ))
    }

    async fn session_notification(&self, args: acp::SessionNotification) -> Result<(), acp::Error> {
        match args.update {
            acp::SessionUpdate::AgentMessageChunk(chunk) => {
                if let acp::ContentBlock::Text(text) = chunk.content {
                    self.transcript
                        .lock()
                        .await
                        .message_text
                        .push_str(&text.text);
                }
            }
            acp::SessionUpdate::ToolCall(tool_call) => {
                let title = if tool_call.title.trim().is_empty() {
                    format!("{:?}", tool_call.kind)
                } else {
                    tool_call.title
                };
                self.append_note(format!("[acp] tool call: {title}")).await;
            }
            acp::SessionUpdate::ToolCallUpdate(update) => {
                let title = update
                    .fields
                    .title
                    .clone()
                    .unwrap_or_else(|| update.tool_call_id.0.to_string());
                if let Some(status) = update.fields.status {
                    self.append_note(format!("[acp] tool update: {title} ({status:?})"))
                        .await;
                }
            }
            acp::SessionUpdate::Plan(plan) => {
                if !plan.entries.is_empty() {
                    let items = plan
                        .entries
                        .iter()
                        .map(|entry| entry.content.as_str())
                        .collect::<Vec<_>>()
                        .join(" | ");
                    self.append_note(format!("[acp] plan: {items}")).await;
                }
            }
            _ => {}
        }
        Ok(())
    }

    async fn write_text_file(
        &self,
        args: acp::WriteTextFileRequest,
    ) -> Result<acp::WriteTextFileResponse, acp::Error> {
        let path = resolve_client_path(&self.working_dir, &args.path)?;
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(internal_error)?;
        }
        tokio::fs::write(path, args.content)
            .await
            .map_err(internal_error)?;
        Ok(acp::WriteTextFileResponse::new())
    }

    async fn read_text_file(
        &self,
        args: acp::ReadTextFileRequest,
    ) -> Result<acp::ReadTextFileResponse, acp::Error> {
        let path = resolve_client_path(&self.working_dir, &args.path)?;
        let content = tokio::fs::read_to_string(path)
            .await
            .map_err(internal_error)?;
        let selected = slice_lines(&content, args.line, args.limit);
        Ok(acp::ReadTextFileResponse::new(selected))
    }

    async fn create_terminal(
        &self,
        args: acp::CreateTerminalRequest,
    ) -> Result<acp::CreateTerminalResponse, acp::Error> {
        let cwd = match args.cwd {
            Some(path) => resolve_client_path(&self.working_dir, &path)?,
            None => self.working_dir.clone(),
        };
        let terminal_id = format!("acp-term-{}", uuid::Uuid::new_v4());
        let output_limit = args
            .output_byte_limit
            .map(|value| value as usize)
            .unwrap_or(ACP_TERMINAL_OUTPUT_LIMIT_BYTES)
            .clamp(1024, ACP_TERMINAL_OUTPUT_LIMIT_BYTES);
        let mut cmd = tokio::process::Command::new(&args.command);
        cmd.args(&args.args)
            .current_dir(cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        for env in args.env {
            cmd.env(env.name, env.value);
        }
        let mut child = cmd.spawn().map_err(internal_error)?;
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let session = Arc::new(TerminalSession {
            child: Mutex::new(child),
            output: Arc::new(Mutex::new(RetainedText::default())),
            exit_status: Mutex::new(None),
        });

        if let Some(stdout) = stdout {
            tokio::spawn(read_pipe_into_output(
                stdout,
                session.output.clone(),
                output_limit,
            ));
        }
        if let Some(stderr) = stderr {
            tokio::spawn(read_pipe_into_output(
                stderr,
                session.output.clone(),
                output_limit,
            ));
        }

        self.terminals
            .lock()
            .await
            .insert(terminal_id.clone(), session);
        Ok(acp::CreateTerminalResponse::new(terminal_id))
    }

    async fn terminal_output(
        &self,
        args: acp::TerminalOutputRequest,
    ) -> Result<acp::TerminalOutputResponse, acp::Error> {
        let session = self
            .terminals
            .lock()
            .await
            .get(args.terminal_id.0.as_ref())
            .cloned()
            .ok_or_else(acp::Error::invalid_params)?;
        session.output_response().await
    }

    async fn release_terminal(
        &self,
        args: acp::ReleaseTerminalRequest,
    ) -> Result<acp::ReleaseTerminalResponse, acp::Error> {
        if let Some(session) = self
            .terminals
            .lock()
            .await
            .remove(args.terminal_id.0.as_ref())
        {
            let _ = session.kill().await;
        }
        Ok(acp::ReleaseTerminalResponse::new())
    }

    async fn wait_for_terminal_exit(
        &self,
        args: acp::WaitForTerminalExitRequest,
    ) -> Result<acp::WaitForTerminalExitResponse, acp::Error> {
        let session = self
            .terminals
            .lock()
            .await
            .get(args.terminal_id.0.as_ref())
            .cloned()
            .ok_or_else(acp::Error::invalid_params)?;
        session.wait_for_exit().await
    }

    async fn kill_terminal(
        &self,
        args: acp::KillTerminalRequest,
    ) -> Result<acp::KillTerminalResponse, acp::Error> {
        let session = self
            .terminals
            .lock()
            .await
            .get(args.terminal_id.0.as_ref())
            .cloned()
            .ok_or_else(acp::Error::invalid_params)?;
        session.kill().await?;
        Ok(acp::KillTerminalResponse::new())
    }
}

pub async fn run_acp_subagent_task(
    params: AcpSubagentTaskParams,
) -> Result<(String, String, i64, i64), String> {
    tokio::task::spawn_blocking(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("Failed creating ACP runtime: {e}"))?;
        let local = tokio::task::LocalSet::new();
        runtime.block_on(local.run_until(run_acp_subagent_task_inner(params)))
    })
    .await
    .map_err(|e| format!("ACP runtime join failed: {e}"))?
}

async fn run_acp_subagent_task_inner(
    params: AcpSubagentTaskParams,
) -> Result<(String, String, i64, i64), String> {
    let working_dir = resolve_session_working_dir(&params.config, &params.auth_context)
        .map_err(|e| format!("Failed resolving ACP working directory: {e}"))?;
    tokio::fs::create_dir_all(&working_dir)
        .await
        .map_err(|e| format!("Failed creating ACP working directory: {e}"))?;

    let command = params.config.subagents.acp.command.clone();
    if command.trim().is_empty() {
        return Err("ACP runtime is enabled but subagents.acp.command is empty".into());
    }

    let mut child = tokio::process::Command::new(&command);
    child
        .args(&params.config.subagents.acp.args)
        .current_dir(&working_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .env("MICROCLAW_SUBAGENT_RUN_ID", &params.run_id)
        .env(
            "MICROCLAW_SUBAGENT_CHAT_ID",
            params.auth_context.caller_chat_id.to_string(),
        )
        .env(
            "MICROCLAW_SUBAGENT_WORKDIR",
            working_dir.display().to_string(),
        );
    for (key, value) in &params.config.subagents.acp.env {
        child.env(key, value);
    }

    let mut child = child
        .spawn()
        .map_err(|e| format!("Failed spawning ACP agent command '{command}': {e}"))?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| "ACP agent stdin pipe unavailable".to_string())?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "ACP agent stdout pipe unavailable".to_string())?;
    let stderr = child.stderr.take();
    let stderr_capture = Arc::new(Mutex::new(RetainedText::default()));
    if let Some(stderr) = stderr {
        tokio::spawn(read_pipe_into_output(
            stderr,
            stderr_capture.clone(),
            ACP_AGENT_STDERR_LIMIT_BYTES,
        ));
    }

    let client = Arc::new(AcpSessionClient::new(
        working_dir.clone(),
        params.config.subagents.acp.auto_approve,
    ));
    let prompt_text = if params.context.is_empty() {
        params.task.clone()
    } else {
        format!("Context: {}\n\nTask: {}", params.context, params.task)
    };

    let db = params.db.clone();
    let run_id = params.run_id.clone();
    let local_cancel = params.local_cancel.clone();
    let (conn, handle_io) = ClientSideConnection::new(
        client.clone(),
        stdin.compat_write(),
        stdout.compat(),
        |fut| {
            tokio::task::spawn_local(fut);
        },
    );
    let io_handle = tokio::task::spawn_local(handle_io);

    conn.initialize(
        InitializeRequest::new(ProtocolVersion::V1)
            .client_info(
                acp::Implementation::new("microclaw-acp-client", env!("CARGO_PKG_VERSION"))
                    .title("MicroClaw ACP Client"),
            )
            .client_capabilities(
                ClientCapabilities::new()
                    .fs(FileSystemCapabilities::new()
                        .read_text_file(true)
                        .write_text_file(true))
                    .terminal(true),
            ),
    )
    .await
    .map_err(|e| format!("ACP initialize failed: {e}"))?;

    let session = conn
        .new_session(acp::NewSessionRequest::new(working_dir.clone()))
        .await
        .map_err(|e| format!("ACP new_session failed: {e}"))?;
    let session_id = session.session_id.clone();
    let prompt_future = conn.prompt(acp::PromptRequest::new(
        session_id.clone(),
        vec![prompt_text.into()],
    ));
    tokio::pin!(prompt_future);

    loop {
        tokio::select! {
            prompt_result = &mut prompt_future => {
                prompt_result.map_err(|e| format!("ACP prompt failed: {e}"))?;
                break;
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(ACP_CANCEL_POLL_MS)) => {
                if crate::tools::subagents::is_cancelled(db.clone(), &run_id, &local_cancel).await? {
                    let _ = conn.cancel(acp::CancelNotification::new(session_id.clone())).await;
                    client.kill_all_terminals().await;
                    let _ = terminate_child_process(&mut child).await;
                    io_handle.abort();
                    return Err("cancelled".to_string());
                }
            }
        }
    }

    client.kill_all_terminals().await;
    let _ = terminate_child_process(&mut child).await;
    io_handle.abort();

    let source = client.final_text().await;
    let stderr_text = stderr_capture.lock().await.text.clone();
    if source.trim().is_empty() && !stderr_text.trim().is_empty() {
        return Err(format!(
            "ACP agent produced no response. stderr:\n{stderr_text}"
        ));
    }
    let source = if source.trim().is_empty() {
        "(sub-agent produced no output)".to_string()
    } else {
        source
    };
    let (final_text, artifact_json) =
        crate::tools::subagents::normalize_subagent_artifact_payload(&source);
    Ok((final_text, artifact_json, 0, 0))
}

pub fn acp_runtime_model(config: &Config) -> String {
    if config.subagents.acp.command.trim().is_empty() {
        "acp".to_string()
    } else {
        Path::new(&config.subagents.acp.command)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("acp")
            .to_string()
    }
}

pub fn acp_runtime_provider() -> &'static str {
    ACP_RUNTIME_PROVIDER
}

fn resolve_session_working_dir(
    config: &Config,
    auth_context: &ToolAuthContext,
) -> Result<PathBuf, std::io::Error> {
    let input = json!({
        "__microclaw_auth": {
            "caller_channel": auth_context.caller_channel,
            "caller_chat_id": auth_context.caller_chat_id,
            "control_chat_ids": auth_context.control_chat_ids,
            "env_files": auth_context.env_files,
        }
    });
    let path = resolve_tool_working_dir(
        Path::new(&config.working_dir),
        config.working_dir_isolation,
        &input,
    );
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn resolve_client_path(root: &Path, requested: &Path) -> Result<PathBuf, acp::Error> {
    let raw_root = normalize_path(root);
    let root = std::fs::canonicalize(root).map_err(internal_error)?;
    let requested = normalize_path(requested);
    let candidate = if requested.is_absolute() {
        if let Ok(relative) = requested.strip_prefix(&root) {
            root.join(relative)
        } else if let Ok(relative) = requested.strip_prefix(&raw_root) {
            root.join(relative)
        } else {
            return Err(acp::Error::invalid_params());
        }
    } else {
        root.join(requested)
    };
    let resolved = std::fs::canonicalize(&candidate).unwrap_or_else(|_| normalize_path(&candidate));
    if !resolved.starts_with(&root) {
        return Err(acp::Error::invalid_params());
    }
    let path_str = resolved.to_string_lossy().to_string();
    if let Err(msg) = microclaw_tools::path_guard::check_path(&path_str) {
        let mut err = acp::Error::invalid_request();
        err.message = msg;
        return Err(err);
    }
    Ok(resolved)
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            std::path::Component::RootDir => normalized.push(Path::new("/")),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            std::path::Component::Normal(part) => normalized.push(part),
        }
    }
    normalized
}

fn slice_lines(content: &str, line: Option<u32>, limit: Option<u32>) -> String {
    let lines: Vec<&str> = content.lines().collect();
    let start = line.unwrap_or(1).saturating_sub(1) as usize;
    let max = limit.unwrap_or(lines.len() as u32).max(1) as usize;
    let end = (start + max).min(lines.len());
    lines[start.min(lines.len())..end].join("\n")
}

async fn read_pipe_into_output<R>(mut reader: R, output: Arc<Mutex<RetainedText>>, limit: usize)
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buf = [0_u8; 4096];
    loop {
        let read = match reader.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        let chunk = String::from_utf8_lossy(&buf[..read]).into_owned();
        let mut retained = output.lock().await;
        retained.text.push_str(&chunk);
        truncate_retained_text(&mut retained, limit);
    }
}

fn truncate_retained_text(output: &mut RetainedText, limit: usize) {
    if output.text.len() <= limit {
        return;
    }
    output.truncated = true;
    let overflow = output.text.len().saturating_sub(limit);
    let boundary = floor_char_boundary(&output.text, overflow);
    output.text.replace_range(..boundary, "");
}

fn map_exit_status(status: std::process::ExitStatus) -> acp::TerminalExitStatus {
    let mut mapped = acp::TerminalExitStatus::new();
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        mapped = mapped.signal(status.signal().map(|signal| signal.to_string()));
    }
    mapped.exit_code(status.code().map(|code| code as u32))
}

async fn terminate_child_process(child: &mut tokio::process::Child) -> Result<(), std::io::Error> {
    match child.try_wait()? {
        Some(_) => Ok(()),
        None => {
            let _ = child.start_kill();
            let _ = child.wait().await?;
            Ok(())
        }
    }
}

fn internal_error(err: impl std::fmt::Display) -> acp::Error {
    let mut error = acp::Error::internal_error();
    error.message = err.to_string();
    error
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_acp_client_read_write_stays_inside_workdir() {
        let root =
            std::env::temp_dir().join(format!("microclaw_acp_client_{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&root).await.unwrap();
        let client = AcpSessionClient::new(root.clone(), true);
        let session_id = acp::SessionId::new("test-session");

        client
            .write_text_file(acp::WriteTextFileRequest::new(
                session_id.clone(),
                root.join("notes/todo.txt"),
                "hello",
            ))
            .await
            .unwrap();
        let read = client
            .read_text_file(acp::ReadTextFileRequest::new(
                session_id.clone(),
                root.join("notes/todo.txt"),
            ))
            .await
            .unwrap();
        assert_eq!(read.content, "hello");

        let err = client
            .read_text_file(acp::ReadTextFileRequest::new(
                session_id,
                PathBuf::from("/etc/hosts"),
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code, acp::Error::invalid_params().code);
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn test_acp_client_terminal_lifecycle() {
        let root =
            std::env::temp_dir().join(format!("microclaw_acp_term_{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&root).await.unwrap();
        let client = AcpSessionClient::new(root.clone(), true);
        let session_id = acp::SessionId::new("test-session");

        let created = client
            .create_terminal(
                acp::CreateTerminalRequest::new(session_id.clone(), "/bin/sh")
                    .args(vec!["-c".into(), "printf 'hello'".into()]),
            )
            .await
            .unwrap();
        let waited = client
            .wait_for_terminal_exit(acp::WaitForTerminalExitRequest::new(
                session_id.clone(),
                created.terminal_id.clone(),
            ))
            .await
            .unwrap();
        assert_eq!(waited.exit_status.exit_code, Some(0));

        let output = client
            .terminal_output(acp::TerminalOutputRequest::new(
                session_id.clone(),
                created.terminal_id.clone(),
            ))
            .await
            .unwrap();
        assert!(output.output.contains("hello"));

        client
            .release_terminal(acp::ReleaseTerminalRequest::new(
                session_id,
                created.terminal_id,
            ))
            .await
            .unwrap();
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn test_permission_auto_approve_prefers_allow() {
        let client = AcpSessionClient::new(std::env::temp_dir(), true);
        let session_id = acp::SessionId::new("test-session");
        let response = client
            .request_permission(acp::RequestPermissionRequest::new(
                session_id,
                acp::ToolCallUpdate::new(
                    "tool-1",
                    acp::ToolCallUpdateFields::new().title("Run terminal".to_string()),
                ),
                vec![
                    acp::PermissionOption::new(
                        "reject",
                        "Reject",
                        acp::PermissionOptionKind::RejectOnce,
                    ),
                    acp::PermissionOption::new(
                        "allow",
                        "Allow",
                        acp::PermissionOptionKind::AllowOnce,
                    ),
                ],
            ))
            .await
            .unwrap();
        let RequestPermissionOutcome::Selected(selected) = response.outcome else {
            panic!("expected selected permission outcome");
        };
        assert_eq!(selected.option_id.0.as_ref(), "allow");
    }
}
