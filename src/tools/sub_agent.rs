use async_trait::async_trait;
use serde_json::json;
use std::sync::Arc;
use tracing::info;

use super::{auth_context_from_input, schema_object, Tool, ToolRegistry, ToolResult};
use crate::config::Config;
#[cfg(test)]
use crate::config::WorkingDirIsolation;
use microclaw_core::llm_types::{
    ContentBlock, Message, MessageContent, ResponseContentBlock, ToolDefinition,
};
use microclaw_storage::db::{call_blocking, Database};

const MAX_SUB_AGENT_ITERATIONS: usize = 10;

pub struct SubAgentTool {
    config: Config,
    db: Arc<Database>,
}

impl SubAgentTool {
    pub fn new(config: &Config, db: Arc<Database>) -> Self {
        SubAgentTool {
            config: config.clone(),
            db,
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
        let tools = ToolRegistry::new_sub_agent(&self.config, self.db.clone());
        let tool_defs = tools.definitions().to_vec();

        let system_prompt = "You are a sub-agent assistant. Complete the given task thoroughly and return a clear, concise result. You have access to tools for file operations, search, and web access. Focus on the task and provide actionable output.".to_string();

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

            if let Some(usage) = &response.usage {
                let chat_id = auth_context.as_ref().map(|a| a.caller_chat_id).unwrap_or(0);
                let caller_channel = auth_context
                    .as_ref()
                    .map(|a| a.caller_channel.clone())
                    .unwrap_or_else(|| "sub_agent".to_string());
                let provider = self.config.llm_provider.clone();
                let model = self.config.model.clone();
                let input_tokens = i64::from(usage.input_tokens);
                let output_tokens = i64::from(usage.output_tokens);
                let _ = call_blocking(self.db.clone(), move |db| {
                    db.log_llm_usage(
                        chat_id,
                        &caller_channel,
                        &provider,
                        &model,
                        input_tokens,
                        output_tokens,
                        "sub_agent",
                    )
                    .map(|_| ())
                })
                .await;
            }

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
                    .filter_map(|block| match block {
                        ResponseContentBlock::Text { text } => {
                            Some(ContentBlock::Text { text: text.clone() })
                        }
                        ResponseContentBlock::ToolUse { id, name, input } => {
                            Some(ContentBlock::ToolUse {
                                id: id.clone(),
                                name: name.clone(),
                                input: input.clone(),
                            })
                        }
                        ResponseContentBlock::Other => None,
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
    use microclaw_storage::db::Database;

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
            compaction_timeout_secs: 180,
            max_history_messages: 50,
            max_document_size_mb: 100,
            memory_token_budget: 1500,
            data_dir: "/tmp".into(),
            working_dir: "/tmp".into(),
            working_dir_isolation: WorkingDirIsolation::Shared,
            sandbox: crate::config::SandboxConfig::default(),
            openai_api_key: None,
            timezone: "UTC".into(),
            allowed_groups: vec![],
            control_chat_ids: vec![],
            max_session_messages: 40,
            compact_keep_recent: 20,
            discord_bot_token: None,
            discord_allowed_channels: vec![],
            discord_no_mention: false,
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
            model_prices: vec![],
            embedding_provider: None,
            embedding_api_key: None,
            embedding_base_url: None,
            embedding_model: None,
            embedding_dim: None,
            reflector_enabled: true,
            reflector_interval_mins: 15,
            soul_path: None,
            clawhub_registry: "https://clawhub.ai".into(),
            clawhub_token: None,
            clawhub_agent_tools_enabled: true,
            clawhub_skip_security_warnings: false,
            channels: std::collections::HashMap::new(),
        }
    }

    fn test_db() -> Arc<Database> {
        let dir =
            std::env::temp_dir().join(format!("microclaw_sub_agent_test_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        Arc::new(Database::new(dir.to_str().unwrap()).unwrap())
    }

    #[test]
    fn test_sub_agent_tool_name_and_definition() {
        let tool = SubAgentTool::new(&test_config(), test_db());
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
        let tool = SubAgentTool::new(&test_config(), test_db());
        let result = tool.execute(json!({})).await;
        assert!(result.is_error);
        assert!(result.content.contains("Missing required parameter: task"));
    }

    #[test]
    fn test_sub_agent_restricted_registry_tool_count() {
        let config = test_config();
        let registry = ToolRegistry::new_sub_agent(&config, test_db());
        let defs = registry.definitions();
        assert_eq!(defs.len(), 12);
    }

    #[test]
    fn test_sub_agent_restricted_registry_excluded_tools() {
        let config = test_config();
        let registry = ToolRegistry::new_sub_agent(&config, test_db());
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
        assert!(names.contains(&"structured_memory_search"));

        // Should NOT include
        assert!(!names.contains(&"sub_agent"));
        assert!(!names.contains(&"send_message"));
        assert!(!names.contains(&"write_memory"));
        assert!(!names.contains(&"schedule_task"));
        assert!(!names.contains(&"list_scheduled_tasks"));
        assert!(!names.contains(&"pause_scheduled_task"));
        assert!(!names.contains(&"resume_scheduled_task"));
        assert!(!names.contains(&"cancel_scheduled_task"));
        assert!(!names.contains(&"get_task_history"));
        assert!(!names.contains(&"export_chat"));
    }
}
