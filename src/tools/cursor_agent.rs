use async_trait::async_trait;
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;

use crate::claude::ToolDefinition;
use crate::config::Config;
use crate::db::Database;

use super::{auth_context_from_input, schema_object, Tool, ToolResult};

const MAX_PROMPT_LEN: usize = 50_000;
const MAX_OUTPUT_LEN: usize = 30_000;
const PROMPT_PREVIEW_LEN: usize = 200;
const OUTPUT_PREVIEW_LEN: usize = 500;

pub struct CursorAgentTool {
    config: Config,
    db: Arc<Database>,
}

impl CursorAgentTool {
    pub fn new(config: &Config, db: Arc<Database>) -> Self {
        Self {
            config: config.clone(),
            db,
        }
    }
}

#[async_trait]
impl Tool for CursorAgentTool {
    fn name(&self) -> &str {
        "cursor_agent"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "cursor_agent".into(),
            description: "Run the Cursor CLI agent (cursor-agent) with a prompt. Use for research, code generation, or analysis that benefits from Cursor's native agent. Optional: timeout_secs, model override. Working directory is the shared tool workspace.".into(),
            input_schema: schema_object(
                json!({
                    "prompt": {
                        "type": "string",
                        "description": "The prompt to send to cursor-agent"
                    },
                    "timeout_secs": {
                        "type": "integer",
                        "description": "Timeout in seconds (default from config, typically 600)"
                    },
                    "model": {
                        "type": "string",
                        "description": "Override model for this run (e.g. gpt-5). Omit to use config default or Cursor auto"
                    }
                }),
                &["prompt"],
            ),
        }
    }

    async fn execute(&self, input: serde_json::Value) -> ToolResult {
        let prompt = match input.get("prompt").and_then(|v| v.as_str()) {
            Some(p) => p,
            None => return ToolResult::error("Missing 'prompt' parameter".into()),
        };

        if prompt.len() > MAX_PROMPT_LEN {
            return ToolResult::error(format!(
                "Prompt exceeds maximum length of {} characters",
                MAX_PROMPT_LEN
            ));
        }

        let auth = auth_context_from_input(&input);
        let started_at = chrono::Utc::now().to_rfc3339();
        let workdir_str_storage;
        let working_dir = super::resolve_tool_working_dir(PathBuf::from(self.config.working_dir()).as_path());
        if let Err(e) = tokio::fs::create_dir_all(&working_dir).await {
            return ToolResult::error(format!(
                "Failed to create working directory {}: {e}",
                working_dir.display()
            ));
        }
        workdir_str_storage = working_dir.to_string_lossy().to_string();
        if let Err(msg) = crate::tools::path_guard::check_path(&workdir_str_storage) {
            return ToolResult::error(msg);
        }

        let timeout_secs = input
            .get("timeout_secs")
            .and_then(|v| v.as_u64())
            .unwrap_or(self.config.cursor_agent_timeout_secs);
        let model_override = input.get("model").and_then(|v| v.as_str()).filter(|s| !s.is_empty());
        let model = model_override
            .unwrap_or_else(|| self.config.cursor_agent_model.as_str())
            .trim();

        let cli_path = self.config.cursor_agent_cli_path.trim();
        if cli_path.is_empty() {
            return ToolResult::error("cursor_agent_cli_path is not configured".into());
        }

        info!("Running cursor-agent (timeout {}s)", timeout_secs);

        let mut cmd = tokio::process::Command::new(cli_path);
        cmd.arg("-p").arg(prompt);
        if !model.is_empty() {
            cmd.arg("--model").arg(model);
        }
        cmd.arg("--output-format").arg("text");
        cmd.current_dir(&working_dir);

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs),
            cmd.output(),
        )
        .await;

        let finished_at = chrono::Utc::now().to_rfc3339();
        let prompt_preview: String = if prompt.len() <= PROMPT_PREVIEW_LEN {
            prompt.to_string()
        } else {
            format!("{}...", &prompt[..prompt.floor_char_boundary(PROMPT_PREVIEW_LEN)])
        };

        let (success, exit_code, result_content) = match &result {
            Ok(Ok(output)) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                let code = output.status.code().unwrap_or(-1);
                (code == 0, code, {
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
                        result_text = format!("Command completed with exit code {code}");
                    }
                    if result_text.len() > MAX_OUTPUT_LEN {
                        result_text.truncate(MAX_OUTPUT_LEN);
                        result_text.push_str("\n... (output truncated)");
                    }
                    result_text
                })
            }
            Ok(Err(_)) => (false, 1, "Failed to execute cursor-agent".to_string()),
            Err(_) => (
                false,
                -1,
                format!("Timed out after {} seconds", timeout_secs),
            ),
        };

        if let Some(ref a) = auth {
            let output_preview = if result_content.len() <= OUTPUT_PREVIEW_LEN {
                result_content.clone()
            } else {
                format!(
                    "{}...",
                    &result_content[..result_content.floor_char_boundary(OUTPUT_PREVIEW_LEN)]
                )
            };
            let db = self.db.clone();
            let chat_id = a.caller_chat_id;
            let channel = a.caller_channel.clone();
            let _ = crate::db::call_blocking(db, move |database| {
                database.insert_cursor_agent_run(
                    chat_id,
                    &channel,
                    &prompt_preview,
                    Some(&workdir_str_storage),
                    &started_at,
                    &finished_at,
                    success,
                    Some(exit_code),
                    Some(&output_preview),
                    None::<&str>,
                )
            })
            .await;
        }

        match result {
            Ok(Ok(output)) => {
                let exit_code = output.status.code().unwrap_or(-1);
                if exit_code == 0 {
                    ToolResult::success(result_content).with_status_code(exit_code)
                } else {
                    ToolResult::error(format!("Exit code {exit_code}\n{result_content}"))
                        .with_status_code(exit_code)
                        .with_error_type("process_exit")
                }
            }
            Ok(Err(e)) => ToolResult::error(format!("Failed to execute cursor-agent: {e}"))
                .with_error_type("spawn_error"),
            Err(_) => ToolResult::error(format!(
                "cursor-agent timed out after {} seconds",
                timeout_secs
            ))
            .with_error_type("timeout"),
        }
    }
}

// --- list_cursor_agent_runs ---

pub struct ListCursorAgentRunsTool {
    db: Arc<Database>,
}

impl ListCursorAgentRunsTool {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }
}

#[async_trait]
impl Tool for ListCursorAgentRunsTool {
    fn name(&self) -> &str {
        "list_cursor_agent_runs"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "list_cursor_agent_runs".into(),
            description: "List recent cursor-agent runs to monitor project status. By default returns runs for the current chat; use this to see last run outcome, success/failure, and output preview.".into(),
            input_schema: schema_object(
                json!({
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of runs to return (default: 10)"
                    },
                    "chat_id": {
                        "type": "integer",
                        "description": "Optional: list runs for this chat ID (control chats only). Omit to list runs for the current chat."
                    }
                }),
                &[],
            ),
        }
    }

    async fn execute(&self, input: serde_json::Value) -> ToolResult {
        let auth = auth_context_from_input(&input);
        let chat_id = input.get("chat_id").and_then(|v| v.as_i64()).or_else(|| {
            auth.as_ref().map(|a| a.caller_chat_id)
        });
        let limit = input
            .get("limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(10)
            .min(50) as usize;

        match crate::db::call_blocking(self.db.clone(), move |db| {
            db.get_cursor_agent_runs(chat_id, limit)
        })
        .await
        {
            Ok(runs) => {
                if runs.is_empty() {
                    return ToolResult::success("No cursor-agent runs found.".into());
                }
                let mut out = String::new();
                for r in &runs {
                    let status = if r.success { "ok" } else { "failed" };
                    let code = r
                        .exit_code
                        .map(|c| format!(" exit_code={}", c))
                        .unwrap_or_default();
                    let preview = r.prompt_preview.chars().take(60).collect::<String>();
                    let suffix = if r.prompt_preview.chars().count() > 60 { "..." } else { "" };
                    out.push_str(&format!(
                        "#{} {} {} {} | prompt: {}{}\n",
                        r.id, r.finished_at, status, code, preview, suffix
                    ));
                    if let Some(ref prev) = r.output_preview {
                        let first_line = prev.lines().next().unwrap_or("");
                        out.push_str(&format!("  -> {}\n", &first_line[..first_line.len().min(80)]));
                    }
                }
                ToolResult::success(out)
            }
            Err(e) => ToolResult::error(format!("Failed to list cursor-agent runs: {e}")),
        }
    }
}
