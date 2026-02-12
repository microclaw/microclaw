use async_trait::async_trait;
use serde_json::json;
use std::path::PathBuf;
use tracing::info;

use crate::claude::ToolDefinition;
use crate::config::WorkingDirIsolation;
use crate::tools::command_runner::{build_command, shell_command};

use super::{schema_object, Tool, ToolResult};

pub struct BashTool {
    working_dir: PathBuf,
    working_dir_isolation: WorkingDirIsolation,
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
        }
    }
}

#[async_trait]
impl Tool for BashTool {
    fn name(&self) -> &str {
        "bash"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "bash".into(),
            description: "Execute a bash command and return the output. Use for running shell commands, scripts, or system operations.".into(),
            input_schema: schema_object(
                json!({
                    "command": {
                        "type": "string",
                        "description": "The bash command to execute"
                    },
                    "timeout_secs": {
                        "type": "integer",
                        "description": "Timeout in seconds (default: 120)"
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
            .unwrap_or(120);
        let working_dir =
            super::resolve_tool_working_dir(&self.working_dir, self.working_dir_isolation, &input);
        if let Err(e) = tokio::fs::create_dir_all(&working_dir).await {
            return ToolResult::error(format!(
                "Failed to create working directory {}: {e}",
                working_dir.display()
            ));
        }

        info!("Executing bash: {}", command);

        let spec = shell_command(command);
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs),
            build_command(&spec, Some(&working_dir)).output(),
        )
        .await;

        match result {
            Ok(Ok(output)) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                let exit_code = output.status.code().unwrap_or(-1);

                let mut result_text = String::new();
                if !stdout.is_empty() {
                    result_text.push_str(&stdout);
                }
                if !stderr.is_empty() {
                    if !result_text.is_empty() {
                        result_text.push('\n');
                    }
                    result_text.push_str("STDERR:\n");
                    result_text.push_str(&stderr);
                }
                if result_text.is_empty() {
                    result_text = format!("Command completed with exit code {exit_code}");
                }

                // Truncate very long output
                if result_text.len() > 30000 {
                    result_text.truncate(30000);
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
            Ok(Err(e)) => ToolResult::error(format!("Failed to execute command: {e}"))
                .with_error_type("spawn_error"),
            Err(_) => ToolResult::error(format!("Command timed out after {timeout_secs} seconds"))
                .with_error_type("timeout"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn pwd_command() -> &'static str {
        if cfg!(target_os = "windows") {
            "(Get-Location).Path"
        } else {
            "pwd"
        }
    }

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

    fn normalize_path_for_assert(s: &str) -> String {
        let normalized = s.replace('\\', "/");
        if cfg!(target_os = "windows") {
            normalized.to_ascii_lowercase()
        } else {
            normalized
        }
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
        let result = tool.execute(json!({"command": pwd_command()})).await;
        assert!(!result.is_error);
        assert!(normalize_path_for_assert(&result.content)
            .contains(&normalize_path_for_assert(work.to_str().unwrap())));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn test_bash_chat_isolation_uses_chat_working_dir() {
        let root = std::env::temp_dir().join(format!("microclaw_bash_{}", uuid::Uuid::new_v4()));
        let work = root.join("workspace");
        std::fs::create_dir_all(&work).unwrap();

        let tool = BashTool::new_with_isolation(work.to_str().unwrap(), WorkingDirIsolation::Chat);
        let result = tool
            .execute(json!({
                "command": pwd_command(),
                "__microclaw_auth": {
                    "caller_channel": "telegram",
                    "caller_chat_id": -100123,
                    "control_chat_ids": []
                }
            }))
            .await;
        assert!(!result.is_error);
        let expected_chat_dir = work.join("chat").join("telegram").join("neg100123");
        assert!(
            normalize_path_for_assert(&result.content).contains(&normalize_path_for_assert(
                expected_chat_dir.to_str().unwrap()
            ))
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}
