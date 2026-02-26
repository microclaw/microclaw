use async_trait::async_trait;
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;

use crate::config::WorkingDirIsolation;
use microclaw_core::llm_types::ToolDefinition;
use microclaw_core::text::floor_char_boundary;
use microclaw_tools::sandbox::{SandboxExecOptions, SandboxRouter};

use super::{schema_object, Tool, ToolResult};

pub struct BashTool {
    working_dir: PathBuf,
    working_dir_isolation: WorkingDirIsolation,
    default_timeout_secs: u64,
    sandbox_router: Option<Arc<SandboxRouter>>,
}

impl BashTool {
    pub fn new(working_dir: &str) -> Self {
        Self::new_with_isolation(working_dir, WorkingDirIsolation::Shared)
    }

    pub fn new_with_isolation(
        working_dir: &str,
        working_dir_isolation: WorkingDirIsolation,
    ) -> Self {
        Self {
            working_dir: PathBuf::from(working_dir),
            working_dir_isolation,
            default_timeout_secs: 120,
            sandbox_router: None,
        }
    }

    pub fn with_default_timeout_secs(mut self, timeout_secs: u64) -> Self {
        self.default_timeout_secs = timeout_secs;
        self
    }

    pub fn with_sandbox_router(mut self, router: Arc<SandboxRouter>) -> Self {
        self.sandbox_router = Some(router);
        self
    }
}

fn contains_explicit_tmp_absolute_path(command: &str) -> bool {
    let mut start = 0usize;
    while let Some(offset) = command[start..].find("/tmp/") {
        let idx = start + offset;
        let prev = if idx == 0 {
            None
        } else {
            command[..idx].chars().next_back()
        };
        if prev.is_none()
            || matches!(
                prev,
                Some(' ' | '\t' | '\n' | '\'' | '"' | '=' | '(' | ':' | ';' | '|')
            )
        {
            return true;
        }
        start = idx + 5;
    }
    false
}

#[async_trait]
impl Tool for BashTool {
    fn name(&self) -> &str {
        "bash"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "bash".into(),
            description: "Execute a bash command and return the output. IMPORTANT: You must CALL this tool (not write it as text) to run a command. Use for running shell commands, scripts, or system operations.".into(),
            input_schema: schema_object(
                json!({
                    "command": {
                        "type": "string",
                        "description": "The bash command to execute"
                    },
                    "timeout_secs": {
                        "type": "integer",
                        "description": "Timeout in seconds (defaults to configured tool timeout budget)"
                    }
                }),
                &["command"],
            ),
        }
    }

    async fn execute(&self, input: serde_json::Value) -> ToolResult {
        let command = match input.get("command").and_then(|v| v.as_str()) {
            Some(c) => c,
            None => return ToolResult::error("Missing 'command' parameter".into()),
        };

        let timeout_secs = input
            .get("timeout_secs")
            .and_then(|v| v.as_u64())
            .unwrap_or(self.default_timeout_secs);
        let working_dir =
            super::resolve_tool_working_dir(&self.working_dir, self.working_dir_isolation, &input)
                .join("tmp");
        if let Err(e) = tokio::fs::create_dir_all(&working_dir).await {
            return ToolResult::error(format!(
                "Failed to create working directory {}: {e}",
                working_dir.display()
            ));
        }

        if contains_explicit_tmp_absolute_path(command) {
            return ToolResult::error(format!(
                "Command contains absolute /tmp path, which is disallowed. Use paths under current chat working directory: {}",
                working_dir.display()
            ))
            .with_error_type("path_policy_blocked");
        }

        info!("Executing bash in {}: {}", working_dir.display(), command);

        let session_key = super::auth_context_from_input(&input)
            .map(|auth| format!("{}-{}", auth.caller_channel, auth.caller_chat_id))
            .unwrap_or_else(|| "shared".to_string());
        let exec_opts = SandboxExecOptions {
            timeout: std::time::Duration::from_secs(timeout_secs),
            working_dir: Some(working_dir.clone()),
        };
        let result = if let Some(router) = &self.sandbox_router {
            router.exec(&session_key, command, &exec_opts).await
        } else {
            microclaw_tools::sandbox::exec_host_command(command, &exec_opts).await
        };

        match result {
            Ok(output) => {
                let stdout = output.stdout;
                let stderr = output.stderr;
                let exit_code = output.exit_code;

                let mut result_text = String::new();
                if !stdout.is_empty() {
                    result_text.push_str(stdout.as_str());
                }
                if !stderr.is_empty() {
                    if !result_text.is_empty() {
                        result_text.push('\n');
                    }
                    result_text.push_str("STDERR:\n");
                    result_text.push_str(stderr.as_str());
                }
                if result_text.is_empty() {
                    result_text = format!("Command completed with exit code {exit_code}");
                }

                // Truncate very long output
                if result_text.len() > 30000 {
                    let cutoff = floor_char_boundary(&result_text, 30000);
                    result_text.truncate(cutoff);
                    result_text.push_str("\n... (output truncated)");
                }

                if exit_code == 0 {
                    ToolResult::success(result_text).with_status_code(exit_code)
                } else {
                    ToolResult::error(format!("Exit code {exit_code}\n{result_text}"))
                        .with_status_code(exit_code)
                        .with_error_type("process_exit")
                }
            }
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("timed out after") {
                    ToolResult::error(format!("Command timed out after {timeout_secs} seconds"))
                        .with_error_type("timeout")
                } else {
                    ToolResult::error(format!("Failed to execute command: {e}"))
                        .with_error_type("spawn_error")
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sleep_command(seconds: u64) -> String {
        if cfg!(target_os = "windows") {
            format!("Start-Sleep -Seconds {seconds}")
        } else {
            format!("sleep {seconds}")
        }
    }

    fn stderr_command() -> &'static str {
        if cfg!(target_os = "windows") {
            "[Console]::Error.WriteLine('err')"
        } else {
            "echo err >&2"
        }
    }

    fn write_marker_command(file_name: &str) -> String {
        if cfg!(target_os = "windows") {
            format!("New-Item -ItemType File -Path '{file_name}' -Force | Out-Null")
        } else {
            format!("touch '{file_name}'")
        }
    }

    #[test]
    fn test_contains_explicit_tmp_absolute_path_detection() {
        assert!(contains_explicit_tmp_absolute_path("ls /tmp/x"));
        assert!(contains_explicit_tmp_absolute_path("A=\"/tmp/x\"; echo $A"));
        assert!(!contains_explicit_tmp_absolute_path(
            "ls /Users/eevv/work/project/tmp/x"
        ));
    }

    #[tokio::test]
    async fn test_bash_echo() {
        let tool = BashTool::new(".");
        let result = tool.execute(json!({"command": "echo hello"})).await;
        assert!(!result.is_error);
        assert!(result.content.contains("hello"));
    }

    #[tokio::test]
    async fn test_bash_exit_code_nonzero() {
        let tool = BashTool::new(".");
        let result = tool.execute(json!({"command": "exit 1"})).await;
        assert!(result.is_error);
        assert!(result.content.contains("Exit code 1"));
    }

    #[tokio::test]
    async fn test_bash_stderr() {
        let tool = BashTool::new(".");
        let result = tool.execute(json!({"command": stderr_command()})).await;
        assert!(!result.is_error); // exit code is 0
        assert!(result.content.contains("STDERR"));
        assert!(result.content.contains("err"));
    }

    #[tokio::test]
    async fn test_bash_timeout() {
        let tool = BashTool::new(".");
        let result = tool
            .execute(json!({"command": sleep_command(10), "timeout_secs": 1}))
            .await;
        assert!(result.is_error);
        assert!(result.content.contains("timed out"));
    }

    #[tokio::test]
    async fn test_bash_blocks_tmp_absolute_path() {
        let tool = BashTool::new(".");
        let result = tool.execute(json!({"command": "ls /tmp/x"})).await;
        assert!(result.is_error);
        assert_eq!(result.error_type.as_deref(), Some("path_policy_blocked"));
        assert!(result.content.contains("current chat working directory"));
    }

    #[tokio::test]
    async fn test_bash_missing_command() {
        let tool = BashTool::new(".");
        let result = tool.execute(json!({})).await;
        assert!(result.is_error);
        assert!(result.content.contains("Missing 'command'"));
    }

    #[test]
    fn test_bash_tool_name_and_definition() {
        let tool = BashTool::new(".");
        assert_eq!(tool.name(), "bash");
        let def = tool.definition();
        assert_eq!(def.name, "bash");
        assert!(!def.description.is_empty());
        assert!(def.input_schema["properties"]["command"].is_object());
    }

    #[tokio::test]
    async fn test_bash_uses_working_dir() {
        let root = std::env::temp_dir().join(format!("microclaw_bash_{}", uuid::Uuid::new_v4()));
        let work = root.join("workspace");
        std::fs::create_dir_all(&work).unwrap();

        let tool = BashTool::new(work.to_str().unwrap());
        let marker = "cwd_marker.txt";
        let result = tool
            .execute(json!({"command": write_marker_command(marker)}))
            .await;
        assert!(!result.is_error);

        let expected_marker = work.join("shared").join("tmp").join(marker);
        assert!(expected_marker.exists());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn test_bash_chat_isolation_uses_chat_working_dir() {
        let root = std::env::temp_dir().join(format!("microclaw_bash_{}", uuid::Uuid::new_v4()));
        let work = root.join("workspace");
        std::fs::create_dir_all(&work).unwrap();

        let tool = BashTool::new_with_isolation(work.to_str().unwrap(), WorkingDirIsolation::Chat);
        let marker = "chat_marker.txt";
        let result = tool
            .execute(json!({
                "command": write_marker_command(marker),
                "__microclaw_auth": {
                    "caller_channel": "telegram",
                    "caller_chat_id": -100123,
                    "control_chat_ids": []
                }
            }))
            .await;
        assert!(!result.is_error);

        let expected_marker = work
            .join("chat")
            .join("telegram")
            .join("neg100123")
            .join("tmp")
            .join(marker);
        assert!(expected_marker.exists());

        let _ = std::fs::remove_dir_all(&root);
    }
}
