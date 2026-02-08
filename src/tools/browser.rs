use std::path::PathBuf;

use async_trait::async_trait;
use serde_json::json;
use tracing::info;

use crate::claude::ToolDefinition;

use super::{auth_context_from_input, schema_object, Tool, ToolResult};

/// Single-quote a string for safe shell embedding.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

pub struct BrowserTool {
    data_dir: PathBuf,
}

impl BrowserTool {
    pub fn new(data_dir: &str) -> Self {
        BrowserTool {
            data_dir: PathBuf::from(data_dir).join("groups"),
        }
    }

    fn profile_path(&self, chat_id: i64) -> PathBuf {
        self.data_dir.join(chat_id.to_string()).join("browser-profile")
    }
}

#[async_trait]
impl Tool for BrowserTool {
    fn name(&self) -> &str {
        "browser"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "browser".into(),
            description: "Headless browser automation via agent-browser CLI. Browser state (cookies, localStorage, login sessions) persists across calls and across conversations.\n\n\
                ## Basic workflow\n\
                1. `open <url>` — navigate to a URL\n\
                2. `snapshot -i` — get interactive elements with refs (@e1, @e2, ...)\n\
                3. `click @e1` / `fill @e2 \"text\"` — interact with elements\n\
                4. `get text @e3` — extract text content\n\
                5. Always run `snapshot -i` after navigation or interaction to see updated state\n\n\
                ## All available commands\n\
                **Navigation**: open, back, forward, reload, close\n\
                **Interaction**: click, dblclick, fill, type, press, hover, select, check, uncheck, upload, drag\n\
                **Scrolling**: scroll <dir> [px], scrollintoview <sel>\n\
                **Data extraction**: get text/html/value/attr/title/url/count/box <sel>\n\
                **State checks**: is visible/enabled/checked <sel>\n\
                **Snapshot**: snapshot (-i for interactive only, -c for compact)\n\
                **Screenshot/PDF**: screenshot [path] (--full for full page), pdf <path>\n\
                **JavaScript**: eval <js>\n\
                **Cookies**: cookies, cookies set <name> <val>, cookies clear\n\
                **Storage**: storage local [key], storage local set <k> <v>, storage local clear (same for session)\n\
                **Tabs**: tab, tab new [url], tab <n>, tab close [n]\n\
                **Frames**: frame <sel>, frame main\n\
                **Dialogs**: dialog accept [text], dialog dismiss\n\
                **Viewport**: set viewport <w> <h>, set device <name>, set media dark/light\n\
                **Network**: network route <url> [--abort|--body <json>], network requests\n\
                **Wait**: wait <sel|ms|--text|--url|--load|--fn>\n\
                **Auth state**: state save <path>, state load <path>\n\
                **Semantic find**: find role/text/label/placeholder <value> <action> [input]".into(),
            input_schema: schema_object(
                json!({
                    "command": {
                        "type": "string",
                        "description": "The agent-browser command to run (e.g. `open https://example.com`, `snapshot -i`, `fill @e2 \"hello\"`)"
                    },
                    "timeout_secs": {
                        "type": "integer",
                        "description": "Timeout in seconds (default: 30)"
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
            .unwrap_or(30);

        // Build --profile flag from auth context chat_id
        let profile_arg = auth_context_from_input(&input)
            .map(|auth| {
                let path = self.profile_path(auth.caller_chat_id);
                format!("--profile {}", shell_quote(&path.to_string_lossy()))
            })
            .unwrap_or_default();

        // Build full shell command so argument splitting is handled correctly
        let shell_cmd = if profile_arg.is_empty() {
            format!("agent-browser --session microclaw {command}")
        } else {
            format!("agent-browser --session microclaw {profile_arg} {command}")
        };

        info!("Executing browser: {}", shell_cmd);

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs),
            tokio::process::Command::new("bash")
                .arg("-c")
                .arg(&shell_cmd)
                .output(),
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
                    ToolResult::success(result_text)
                } else {
                    ToolResult::error(format!("Exit code {exit_code}\n{result_text}"))
                }
            }
            Ok(Err(e)) => ToolResult::error(format!("Failed to execute agent-browser: {e}")),
            Err(_) => ToolResult::error(format!(
                "Browser command timed out after {timeout_secs} seconds"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_browser_tool_name_and_definition() {
        let tool = BrowserTool::new("/tmp/test-data");
        assert_eq!(tool.name(), "browser");
        let def = tool.definition();
        assert_eq!(def.name, "browser");
        assert!(def.description.contains("agent-browser"));
        assert!(def.description.contains("cookies"));
        assert!(def.description.contains("eval"));
        assert!(def.description.contains("pdf"));
        assert!(def.input_schema["properties"]["command"].is_object());
        assert!(def.input_schema["properties"]["timeout_secs"].is_object());
    }

    #[test]
    fn test_browser_profile_path() {
        let tool = BrowserTool::new("/tmp/test-data");
        let path = tool.profile_path(12345);
        assert_eq!(path, PathBuf::from("/tmp/test-data/groups/12345/browser-profile"));
    }

    #[tokio::test]
    async fn test_browser_missing_command() {
        let tool = BrowserTool::new("/tmp/test-data");
        let result = tool.execute(json!({})).await;
        assert!(result.is_error);
        assert!(result.content.contains("Missing 'command'"));
    }
}
