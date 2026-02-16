use async_trait::async_trait;
use serde_json::json;
use tracing::info;

use super::{auth_context_from_input, schema_object, Tool, ToolRegistry, ToolResult};
use crate::claude::{ContentBlock, Message, MessageContent, ResponseContentBlock, ToolDefinition};
use crate::config::Config;

const MAX_SUB_AGENT_ITERATIONS: usize = 10;

pub struct SubAgentTool {
    config: Config,
}

impl SubAgentTool {
    pub fn new(config: &Config) -> Self {
        SubAgentTool {
            config: config.clone(),
        }
    }
}

#[async_trait]
impl Tool for SubAgentTool {
    fn name(&self) -> &str {
        "sub_agent"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "sub_agent".into(),
            description: "Delegate a self-contained sub-task to a parallel agent. The sub-agent has access to bash, file operations, glob, grep, web search, web fetch, and read_memory tools but cannot send messages, write memory, or manage scheduled tasks. Use this for independent research, file analysis, or coding tasks that don't need to interact with the user directly.".into(),
            input_schema: schema_object(
                json!({
                    "task": {
                        "type": "string",
                        "description": "A clear description of the task for the sub-agent to complete"
                    },
                    "context": {
                        "type": "string",
                        "description": "Optional additional context to provide to the sub-agent"
                    }
                }),
                &["task"],
            ),
        }
    }

    async fn execute(&self, input: serde_json::Value) -> ToolResult {
        let auth_context = auth_context_from_input(&input);
        let task = match input.get("task").and_then(|v| v.as_str()) {
            Some(t) => t,
            None => return ToolResult::error("Missing required parameter: task".into()),
        };

        let context = input.get("context").and_then(|v| v.as_str()).unwrap_or("");

        info!("Sub-agent starting task: {}", task);

        let llm = crate::llm::create_provider(&self.config);
        let tools = ToolRegistry::new_sub_agent(&self.config);
        let tool_defs = tools.definitions();

        let system_prompt = "You are a sub-agent assistant. Complete the given task thoroughly and return a clear, concise result. You have access to tools for file operations, search, web access, and browser automation (use the browser tool only, not bash). Focus on the task and provide actionable output.".to_string();

        let user_content = if context.is_empty() {
            task.to_string()
        } else {
            format!("Context: {context}\n\nTask: {task}")
        };

        let mut messages = vec![Message {
            role: "user".into(),
            content: MessageContent::Text(user_content),
        }];

        for iteration in 0..MAX_SUB_AGENT_ITERATIONS {
            let response = match llm
                .send_message(&system_prompt, messages.clone(), Some(tool_defs.clone()))
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    return ToolResult::error(format!("Sub-agent API error: {e}"));
                }
            };

            let stop_reason = response.stop_reason.as_deref().unwrap_or("end_turn");

            if stop_reason == "end_turn" || stop_reason == "max_tokens" {
                let text = response
                    .content
                    .iter()
                    .filter_map(|block| match block {
                        ResponseContentBlock::Text { text } => Some(text.as_str()),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
                    .join("");

                return ToolResult::success(if text.is_empty() {
                    "(sub-agent produced no output)".into()
                } else {
                    text
                });
            }

            if stop_reason == "tool_use" {
                let assistant_content: Vec<ContentBlock> = response
                    .content
                    .iter()
                    .map(|block| match block {
                        ResponseContentBlock::Text { text } => {
                            ContentBlock::Text { text: text.clone() }
                        }
                        ResponseContentBlock::ToolUse { id, name, input } => {
                            ContentBlock::ToolUse {
                                id: id.clone(),
                                name: name.clone(),
                                input: input.clone(),
                            }
                        }
                    })
                    .collect();

                messages.push(Message {
                    role: "assistant".into(),
                    content: MessageContent::Blocks(assistant_content),
                });

                let mut tool_results = Vec::new();
                for block in &response.content {
                    if let ResponseContentBlock::ToolUse { id, name, input } = block {
                        info!(
                            "Sub-agent executing tool: {} (iteration {})",
                            name,
                            iteration + 1
                        );
                        let result = if let Some(ref auth) = auth_context {
                            tools.execute_with_auth(name, input.clone(), auth).await
                        } else {
                            tools.execute(name, input.clone()).await
                        };
                        tool_results.push(ContentBlock::ToolResult {
                            tool_use_id: id.clone(),
                            content: result.content,
                            is_error: if result.is_error { Some(true) } else { None },
                        });
                    }
                }

                messages.push(Message {
                    role: "user".into(),
                    content: MessageContent::Blocks(tool_results),
                });

                continue;
            }

            // Unknown stop reason
            let text = response
                .content
                .iter()
                .filter_map(|block| match block {
                    ResponseContentBlock::Text { text } => Some(text.as_str()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("");
            return ToolResult::success(if text.is_empty() {
                "(sub-agent produced no output)".into()
            } else {
                text
            });
        }

        ToolResult::error(
            "Sub-agent reached maximum iterations without completing the task.".into(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> Config {
        Config {
            telegram_bot_token: "tok".into(),
            bot_username: "bot".into(),
            llm_provider: "anthropic".into(),
            api_key: "key".into(),
            model: "claude-test".into(),
            llm_base_url: None,
            max_tokens: 4096,
            max_tool_iterations: 100,
            max_history_messages: 50,
            max_document_size_mb: 100,
            workspace_dir: "/tmp".into(),
            openai_api_key: None,
            timezone: "UTC".into(),
            allowed_groups: vec![],
            control_chat_ids: vec![],
            max_session_messages: 40,
            compact_keep_recent: 20,
            whatsapp_access_token: None,
            whatsapp_phone_number_id: None,
            whatsapp_verify_token: None,
            whatsapp_webhook_port: 8080,
            discord_bot_token: None,
            discord_allowed_channels: vec![],
            show_thinking: false,
            web_enabled: false,
            web_host: "127.0.0.1".into(),
            web_port: 3900,
            web_auth_token: None,
            web_max_inflight_per_session: 2,
            web_max_requests_per_window: 8,
            web_rate_window_seconds: 10,
            web_run_history_limit: 512,
            web_session_idle_ttl_seconds: 300,
            browser_managed: false,
            browser_executable_path: None,
            browser_cdp_port_base: 9222,
            browser_idle_timeout_secs: None,
            browser_headless: false,
            agent_browser_path: None,
            cursor_agent_cli_path: "cursor-agent".into(),
            cursor_agent_model: String::new(),
            cursor_agent_timeout_secs: 600,
            social: None,
        }
    }

    #[test]
    fn test_sub_agent_tool_name_and_definition() {
        let tool = SubAgentTool::new(&test_config());
        assert_eq!(tool.name(), "sub_agent");
        let def = tool.definition();
        assert_eq!(def.name, "sub_agent");
        assert!(!def.description.is_empty());
        assert!(def.input_schema["properties"]["task"].is_object());
        assert!(def.input_schema["properties"]["context"].is_object());
        let required = def.input_schema["required"].as_array().unwrap();
        assert_eq!(required.len(), 1);
        assert_eq!(required[0], "task");
    }

    #[tokio::test]
    async fn test_sub_agent_missing_task() {
        let tool = SubAgentTool::new(&test_config());
        let result = tool.execute(json!({})).await;
        assert!(result.is_error);
        assert!(result.content.contains("Missing required parameter: task"));
    }

    #[test]
    fn test_sub_agent_restricted_registry_tool_count() {
        let config = test_config();
        let registry = ToolRegistry::new_sub_agent(&config);
        let defs = registry.definitions();
        assert_eq!(defs.len(), 12);
    }

    #[test]
    fn test_sub_agent_restricted_registry_excluded_tools() {
        let config = test_config();
        let registry = ToolRegistry::new_sub_agent(&config);
        let defs = registry.definitions();
        let names: Vec<&str> = defs.iter().map(|d| d.name.as_str()).collect();

        // Should include
        assert!(names.contains(&"bash"));
        assert!(names.contains(&"read_file"));
        assert!(names.contains(&"write_file"));
        assert!(names.contains(&"edit_file"));
        assert!(names.contains(&"glob"));
        assert!(names.contains(&"grep"));
        assert!(names.contains(&"web_search"));
        assert!(names.contains(&"web_fetch"));
        assert!(names.contains(&"read_memory"));
        assert!(names.contains(&"read_tiered_memory"));

        // Should NOT include
        assert!(!names.contains(&"sub_agent"));
        assert!(!names.contains(&"send_message"));
        assert!(!names.contains(&"write_memory"));
        assert!(!names.contains(&"write_tiered_memory"));
        assert!(!names.contains(&"schedule_task"));
        assert!(!names.contains(&"list_scheduled_tasks"));
        assert!(!names.contains(&"pause_scheduled_task"));
        assert!(!names.contains(&"resume_scheduled_task"));
        assert!(!names.contains(&"cancel_scheduled_task"));
        assert!(!names.contains(&"get_task_history"));
        assert!(!names.contains(&"export_chat"));
    }
}
