pub mod activate_skill;
pub mod bash;
pub mod browser;
pub mod edit_file;
pub mod export_chat;
pub mod glob;
pub mod grep;
pub mod mcp;
pub mod memory;
pub mod read_file;
pub mod schedule;
pub mod send_message;
pub mod structured_memory;
pub mod sub_agent;
pub mod sync_skills;
pub mod todo;
pub mod web_fetch;
pub mod web_search;
pub mod write_file;

use std::sync::{Arc, OnceLock};
use std::{path::PathBuf, time::Instant};

use crate::config::Config;
use microclaw_channels::channel_adapter::ChannelRegistry;
use microclaw_core::llm_types::ToolDefinition;
use microclaw_storage::db::Database;
pub use microclaw_tools::runtime::{
    auth_context_from_input, authorize_chat_access, resolve_tool_path, resolve_tool_working_dir,
    schema_object, tool_risk, Tool, ToolAuthContext, ToolResult, ToolRisk,
};
use microclaw_tools::runtime::{inject_auth_context, require_high_risk_approval};
use microclaw_tools::sandbox::SandboxRouter;

pub struct ToolRegistry {
    tools: Vec<Box<dyn Tool>>,
    cached_definitions: OnceLock<Vec<ToolDefinition>>,
}

impl ToolRegistry {
    pub fn new(config: &Config, channel_registry: Arc<ChannelRegistry>, db: Arc<Database>) -> Self {
        let working_dir = PathBuf::from(&config.working_dir);
        if let Err(e) = std::fs::create_dir_all(&working_dir) {
            tracing::warn!(
                "Failed to create working_dir '{}': {}",
                working_dir.display(),
                e
            );
        }
        let sandbox_router = Arc::new(SandboxRouter::new(config.sandbox.clone(), &working_dir));
        tracing::info!(
            mode = ?sandbox_router.mode(),
            backend = sandbox_router.backend_name(),
            "Sandbox initialized"
        );
        let skills_data_dir = config.skills_data_dir();
        let mut tools: Vec<Box<dyn Tool>> = vec![
            Box::new(bash::BashTool::new_with_isolation(
                &config.working_dir,
                config.working_dir_isolation,
            )),
            Box::new(browser::BrowserTool::new(&config.data_dir)),
            Box::new(read_file::ReadFileTool::new_with_isolation(
                &config.working_dir,
                config.working_dir_isolation,
            )),
            Box::new(write_file::WriteFileTool::new_with_isolation(
                &config.working_dir,
                config.working_dir_isolation,
            )),
            Box::new(edit_file::EditFileTool::new_with_isolation(
                &config.working_dir,
                config.working_dir_isolation,
            )),
            Box::new(glob::GlobTool::new_with_isolation(
                &config.working_dir,
                config.working_dir_isolation,
            )),
            Box::new(grep::GrepTool::new_with_isolation(
                &config.working_dir,
                config.working_dir_isolation,
            )),
            Box::new(memory::ReadMemoryTool::new(&config.data_dir)),
            Box::new(memory::WriteMemoryTool::new(&config.data_dir, db.clone())),
            Box::new(web_fetch::WebFetchTool),
            Box::new(web_search::WebSearchTool),
            Box::new(send_message::SendMessageTool::new(
                channel_registry.clone(),
                db.clone(),
                config.bot_username.clone(),
            )),
            Box::new(schedule::ScheduleTaskTool::new(
                channel_registry.clone(),
                db.clone(),
                config.timezone.clone(),
            )),
            Box::new(schedule::ListTasksTool::new(
                channel_registry.clone(),
                db.clone(),
            )),
            Box::new(schedule::PauseTaskTool::new(
                channel_registry.clone(),
                db.clone(),
            )),
            Box::new(schedule::ResumeTaskTool::new(
                channel_registry.clone(),
                db.clone(),
            )),
            Box::new(schedule::CancelTaskTool::new(
                channel_registry.clone(),
                db.clone(),
            )),
            Box::new(schedule::GetTaskHistoryTool::new(
                channel_registry.clone(),
                db.clone(),
            )),
            Box::new(export_chat::ExportChatTool::new(
                db.clone(),
                &config.data_dir,
            )),
            Box::new(sub_agent::SubAgentTool::new(config, db.clone())),
            Box::new(activate_skill::ActivateSkillTool::new(&skills_data_dir)),
            Box::new(sync_skills::SyncSkillsTool::new(&skills_data_dir)),
            Box::new(todo::TodoReadTool::new(&config.data_dir)),
            Box::new(todo::TodoWriteTool::new(&config.data_dir)),
            Box::new(structured_memory::StructuredMemorySearchTool::new(
                db.clone(),
            )),
            Box::new(structured_memory::StructuredMemoryDeleteTool::new(
                db.clone(),
            )),
            Box::new(structured_memory::StructuredMemoryUpdateTool::new(
                db.clone(),
            )),
        ];

        // Add ClawHub tools if enabled
        if config.clawhub_agent_tools_enabled {
            tools.push(Box::new(crate::clawhub::tools::ClawHubSearchTool::new(config)));
            tools.push(Box::new(crate::clawhub::tools::ClawHubInstallTool::new(config)));
        }

        ToolRegistry {
            tools,
            cached_definitions: OnceLock::new(),
        }
    }

    /// Create a restricted tool registry for sub-agents (no side-effect or recursive tools).
    pub fn new_sub_agent(config: &Config, db: Arc<Database>) -> Self {
        let working_dir = PathBuf::from(&config.working_dir);
        if let Err(e) = std::fs::create_dir_all(&working_dir) {
            tracing::warn!(
                "Failed to create working_dir '{}': {}",
                working_dir.display(),
                e
            );
        }
        let sandbox_router = Arc::new(SandboxRouter::new(config.sandbox.clone(), &working_dir));
        let skills_data_dir = config.skills_data_dir();
        let mut tools: Vec<Box<dyn Tool>> = vec![
            Box::new(bash::BashTool::new_with_isolation(
                &config.working_dir,
                config.working_dir_isolation,
            )),
            Box::new(browser::BrowserTool::new(&config.data_dir)),
            Box::new(read_file::ReadFileTool::new_with_isolation(
                &config.working_dir,
                config.working_dir_isolation,
            )),
            Box::new(write_file::WriteFileTool::new_with_isolation(
                &config.working_dir,
                config.working_dir_isolation,
            )),
            Box::new(edit_file::EditFileTool::new_with_isolation(
                &config.working_dir,
                config.working_dir_isolation,
            )),
            Box::new(glob::GlobTool::new_with_isolation(
                &config.working_dir,
                config.working_dir_isolation,
            )),
            Box::new(grep::GrepTool::new_with_isolation(
                &config.working_dir,
                config.working_dir_isolation,
            )),
            Box::new(memory::ReadMemoryTool::new(&config.data_dir)),
            Box::new(web_fetch::WebFetchTool),
            Box::new(web_search::WebSearchTool),
            Box::new(activate_skill::ActivateSkillTool::new(&skills_data_dir)),
            Box::new(structured_memory::StructuredMemorySearchTool::new(db)),
        ];
        ToolRegistry {
            tools,
            cached_definitions: OnceLock::new(),
        }
    }

    pub fn add_tool(&mut self, tool: Box<dyn Tool>) {
        // Invalidate cache when a new tool is added
        self.cached_definitions = OnceLock::new();
        self.tools.push(tool);
    }

    pub fn definitions(&self) -> &[ToolDefinition] {
        self.cached_definitions
            .get_or_init(|| self.tools.iter().map(|t| t.definition()).collect())
    }

    pub async fn execute(&self, name: &str, input: serde_json::Value) -> ToolResult {
        for tool in &self.tools {
            if tool.name() == name {
                let started = Instant::now();
                let mut result = tool.execute(input).await;
                result.duration_ms = Some(started.elapsed().as_millis());
                result.bytes = result.content.len();
                if result.is_error && result.error_type.is_none() {
                    result.error_type = Some("tool_error".to_string());
                }
                if result.status_code.is_none() {
                    result.status_code = Some(if result.is_error { 1 } else { 0 });
                }
                return result;
            }
        }
        ToolResult::error(format!("Unknown tool: {name}")).with_error_type("unknown_tool")
    }

    pub async fn execute_with_auth(
        &self,
        name: &str,
        input: serde_json::Value,
        auth: &ToolAuthContext,
    ) -> ToolResult {
        if let Some(blocked) = require_high_risk_approval(name, auth) {
            return blocked;
        }

        let input = inject_auth_context(input, auth);
        self.execute(name, input).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WorkingDirIsolation;
    use async_trait::async_trait;
    use serde_json::json;

    #[test]
    fn test_tool_result_success() {
        let r = ToolResult::success("ok".into());
        assert_eq!(r.content, "ok");
        assert!(!r.is_error);
    }

    #[test]
    fn test_tool_result_error() {
        let r = ToolResult::error("fail".into());
        assert_eq!(r.content, "fail");
        assert!(r.is_error);
    }

    #[test]
    fn test_schema_object() {
        let schema = schema_object(
            json!({
                "name": {"type": "string"},
                "age": {"type": "integer"}
            }),
            &["name"],
        );
        assert_eq!(schema["type"], "object");
        assert!(schema["properties"]["name"].is_object());
        assert!(schema["properties"]["age"].is_object());
        let required = schema["required"].as_array().unwrap();
        assert_eq!(required.len(), 1);
        assert_eq!(required[0], "name");
    }

    #[test]
    fn test_schema_object_empty_required() {
        let schema = schema_object(json!({}), &[]);
        let required = schema["required"].as_array().unwrap();
        assert!(required.is_empty());
    }

    #[test]
    fn test_auth_context_from_input() {
        let input = json!({
            "__microclaw_auth": {
                "caller_channel": "telegram",
                "caller_chat_id": 123,
                "control_chat_ids": [123, 999]
            }
        });
        let auth = auth_context_from_input(&input).unwrap();
        assert_eq!(auth.caller_channel, "telegram");
        assert_eq!(auth.caller_chat_id, 123);
        assert!(auth.is_control_chat());
        assert!(auth.can_access_chat(456));
    }

    #[test]
    fn test_authorize_chat_access_denied() {
        let input = json!({
            "__microclaw_auth": {
                "caller_channel": "telegram",
                "caller_chat_id": 100,
                "control_chat_ids": []
            }
        });
        let err = authorize_chat_access(&input, 200).unwrap_err();
        assert!(err.contains("Permission denied"));
    }

    #[test]
    fn test_resolve_tool_working_dir_shared() {
        let dir = resolve_tool_working_dir(
            std::path::Path::new("/tmp/work"),
            WorkingDirIsolation::Shared,
            &json!({
                "__microclaw_auth": {
                    "caller_channel": "telegram",
                    "caller_chat_id": 123,
                    "control_chat_ids": []
                }
            }),
        );
        assert_eq!(dir, std::path::PathBuf::from("/tmp/work/shared"));
    }

    #[test]
    fn test_resolve_tool_working_dir_chat() {
        let dir = resolve_tool_working_dir(
            std::path::Path::new("/tmp/work"),
            WorkingDirIsolation::Chat,
            &json!({
                "__microclaw_auth": {
                    "caller_channel": "discord",
                    "caller_chat_id": -100123,
                    "control_chat_ids": []
                }
            }),
        );
        assert_eq!(
            dir,
            std::path::PathBuf::from("/tmp/work/chat/discord/neg100123")
        );
    }

    struct DummyTool {
        tool_name: String,
    }

    #[async_trait]
    impl Tool for DummyTool {
        fn name(&self) -> &str {
            &self.tool_name
        }

        fn definition(&self) -> ToolDefinition {
            ToolDefinition {
                name: self.tool_name.clone(),
                description: "dummy".into(),
                input_schema: schema_object(json!({}), &[]),
            }
        }

        async fn execute(&self, _input: serde_json::Value) -> ToolResult {
            ToolResult::success("ok".into())
        }
    }

    #[test]
    fn test_tool_risk_levels() {
        assert_eq!(tool_risk("bash"), ToolRisk::High);
        assert_eq!(tool_risk("write_file"), ToolRisk::Medium);
        assert_eq!(tool_risk("pause_scheduled_task"), ToolRisk::Medium);
        assert_eq!(tool_risk("sync_skills"), ToolRisk::Medium);
        assert_eq!(tool_risk("read_file"), ToolRisk::Low);
    }

    #[tokio::test]
    async fn test_high_risk_tool_requires_second_approval_on_web() {
        let registry = ToolRegistry {
            cached_definitions: OnceLock::new(),
            tools: vec![Box::new(DummyTool {
                tool_name: "bash".into(),
            })],
        };
        let auth = ToolAuthContext {
            caller_channel: "web".into(),
            caller_chat_id: 1,
            control_chat_ids: vec![],
        };

        // First call: blocked with approval_required
        let first = registry.execute_with_auth("bash", json!({}), &auth).await;
        assert!(first.is_error);
        assert_eq!(first.error_type.as_deref(), Some("approval_required"));

        // Second call: auto-approved on retry (no token needed)
        let second = registry.execute_with_auth("bash", json!({}), &auth).await;
        assert!(!second.is_error);
        assert_eq!(second.content, "ok");
    }

    #[tokio::test]
    async fn test_high_risk_tool_requires_second_approval_on_control_chat() {
        let registry = ToolRegistry {
            cached_definitions: OnceLock::new(),
            tools: vec![Box::new(DummyTool {
                tool_name: "bash".into(),
            })],
        };
        let auth = ToolAuthContext {
            caller_channel: "telegram".into(),
            caller_chat_id: 123,
            control_chat_ids: vec![123],
        };

        let first = registry.execute_with_auth("bash", json!({}), &auth).await;
        assert!(first.is_error);
        assert_eq!(first.error_type.as_deref(), Some("approval_required"));
    }

    #[tokio::test]
    async fn test_medium_risk_tool_no_second_approval() {
        let registry = ToolRegistry {
            cached_definitions: OnceLock::new(),
            tools: vec![Box::new(DummyTool {
                tool_name: "write_file".into(),
            })],
        };
        let auth = ToolAuthContext {
            caller_channel: "web".into(),
            caller_chat_id: 1,
            control_chat_ids: vec![],
        };

        let result = registry
            .execute_with_auth("write_file", json!({}), &auth)
            .await;
        assert!(!result.is_error);
        assert_eq!(result.content, "ok");
    }
}
