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
pub mod time_math;
pub mod todo;
pub mod web_fetch;
pub mod web_search;
pub mod write_file;

use std::sync::{Arc, OnceLock};
use std::{path::PathBuf, time::Instant};

use crate::config::Config;
use crate::memory_backend::MemoryBackend;
use microclaw_channels::channel_adapter::ChannelRegistry;
use microclaw_core::llm_types::ToolDefinition;
use microclaw_storage::db::Database;
pub use microclaw_tools::runtime::{
    auth_context_from_input, authorize_chat_access, resolve_tool_path, resolve_tool_working_dir,
    schema_object, tool_execution_policy, tool_risk, validate_execution_policy, Tool,
    ToolAuthContext, ToolResult, ToolRisk,
};
use microclaw_tools::runtime::{inject_auth_context, require_high_risk_approval};
use microclaw_tools::sandbox::{ExtraMount, SandboxMode, SandboxRouter};

pub struct ToolRegistry {
    config: Config,
    tools: Vec<Box<dyn Tool>>,
    sandbox_mode: SandboxMode,
    sandbox_runtime_available: bool,
    cached_static_definitions: OnceLock<Vec<ToolDefinition>>,
}

impl ToolRegistry {
    fn should_inject_default_chat_id(tool_name: &str) -> bool {
        matches!(
            tool_name,
            "write_memory" | "read_memory" | "todo_read" | "todo_write"
        )
    }

    fn inject_default_chat_id_if_missing(
        tool_name: &str,
        input: serde_json::Value,
        auth: &ToolAuthContext,
    ) -> serde_json::Value {
        if !Self::should_inject_default_chat_id(tool_name) {
            return input;
        }
        let mut obj = match input {
            serde_json::Value::Object(map) => map,
            _ => serde_json::Map::new(),
        };
        let missing_chat_id = obj.get("chat_id").and_then(|v| v.as_i64()).is_none();
        if missing_chat_id {
            obj.insert(
                "chat_id".to_string(),
                serde_json::Value::Number(auth.caller_chat_id.into()),
            );
        }
        serde_json::Value::Object(obj)
    }

    pub fn new(
        config: &Config,
        channel_registry: Arc<ChannelRegistry>,
        db: Arc<Database>,
        memory_backend: Arc<MemoryBackend>,
    ) -> Self {
        let working_dir = PathBuf::from(&config.working_dir);
        if let Err(e) = std::fs::create_dir_all(&working_dir) {
            tracing::warn!(
                "Failed to create working_dir '{}': {}",
                working_dir.display(),
                e
            );
        }
        let skills_data_dir = config.skills_data_dir();
        let sandbox_router = Arc::new(SandboxRouter::new(
            config.sandbox.clone(),
            &working_dir,
            Self::build_extra_mounts(&working_dir, &skills_data_dir),
        ));
        tracing::info!(
            mode = ?sandbox_router.mode(),
            backend = sandbox_router.backend_name(),
            "Sandbox initialized"
        );
        let mut tools: Vec<Box<dyn Tool>> = vec![
            Box::new(
                bash::BashTool::new_with_isolation(
                    &config.working_dir,
                    config.working_dir_isolation,
                )
                .with_default_timeout_secs(config.tool_timeout_secs("bash", 120))
                .with_sandbox_router(sandbox_router.clone()),
            ),
            Box::new(
                browser::BrowserTool::new(&config.data_dir)
                    .with_default_timeout_secs(config.tool_timeout_secs("browser", 30)),
            ),
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
            Box::new(memory::ReadMemoryTool::new(&config.data_dir, db.clone())),
            Box::new(memory::WriteMemoryTool::new(
                &config.data_dir,
                db.clone(),
                memory_backend.clone(),
            )),
            Box::new(web_fetch::WebFetchTool::new(
                config.tool_timeout_secs("web_fetch", 15),
                config.web_fetch_validation,
                config.web_fetch_url_validation.clone(),
            )),
            Box::new(web_search::WebSearchTool::new(
                config.tool_timeout_secs("web_search", 15),
            )),
            Box::new(time_math::GetCurrentTimeTool::new(config.timezone.clone())),
            Box::new(time_math::CompareTimeTool::new(config.timezone.clone())),
            Box::new(time_math::CalculateTool::new()),
            Box::new(send_message::SendMessageTool::new(
                channel_registry.clone(),
                db.clone(),
                if config.bot_username.trim().is_empty() {
                    "bot".to_string()
                } else {
                    config.bot_username.clone()
                },
                config.bot_username_overrides(),
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
            Box::new(schedule::ListTaskDlqTool::new(
                channel_registry.clone(),
                db.clone(),
            )),
            Box::new(schedule::ReplayTaskDlqTool::new(
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
                memory_backend.clone(),
            )),
            Box::new(structured_memory::StructuredMemoryDeleteTool::new(
                db.clone(),
                memory_backend.clone(),
            )),
            Box::new(structured_memory::StructuredMemoryUpdateTool::new(
                db.clone(),
                memory_backend.clone(),
            )),
        ];

        // Add ClawHub tools if enabled
        if config.clawhub.agent_tools_enabled {
            tools.push(Box::new(crate::clawhub::tools::ClawHubSearchTool::new(
                config,
            )));
            tools.push(Box::new(crate::clawhub::tools::ClawHubInstallTool::new(
                config,
            )));
        }

        ToolRegistry {
            config: config.clone(),
            tools,
            sandbox_mode: sandbox_router.mode(),
            sandbox_runtime_available: sandbox_router.runtime_available(),
            cached_static_definitions: OnceLock::new(),
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
        let skills_data_dir = config.skills_data_dir();
        let sandbox_router = Arc::new(SandboxRouter::new(
            config.sandbox.clone(),
            &working_dir,
            Self::build_extra_mounts(&working_dir, &skills_data_dir),
        ));
        let memory_backend = Arc::new(MemoryBackend::local_only(db.clone()));
        let tools: Vec<Box<dyn Tool>> = vec![
            Box::new(
                bash::BashTool::new_with_isolation(
                    &config.working_dir,
                    config.working_dir_isolation,
                )
                .with_default_timeout_secs(config.tool_timeout_secs("bash", 120))
                .with_sandbox_router(sandbox_router.clone()),
            ),
            Box::new(
                browser::BrowserTool::new(&config.data_dir)
                    .with_default_timeout_secs(config.tool_timeout_secs("browser", 30)),
            ),
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
            Box::new(memory::ReadMemoryTool::new(&config.data_dir, db.clone())),
            Box::new(web_fetch::WebFetchTool::new(
                config.tool_timeout_secs("web_fetch", 15),
                config.web_fetch_validation,
                config.web_fetch_url_validation.clone(),
            )),
            Box::new(web_search::WebSearchTool::new(
                config.tool_timeout_secs("web_search", 15),
            )),
            Box::new(time_math::GetCurrentTimeTool::new(config.timezone.clone())),
            Box::new(time_math::CompareTimeTool::new(config.timezone.clone())),
            Box::new(time_math::CalculateTool::new()),
            Box::new(activate_skill::ActivateSkillTool::new(&skills_data_dir)),
            Box::new(structured_memory::StructuredMemorySearchTool::new(
                db,
                memory_backend,
            )),
        ];
        ToolRegistry {
            config: config.clone(),
            tools,
            sandbox_mode: sandbox_router.mode(),
            sandbox_runtime_available: sandbox_router.runtime_available(),
            cached_static_definitions: OnceLock::new(),
        }
    }

    fn build_extra_mounts(working_dir: &PathBuf, skills_data_dir: &str) -> Vec<ExtraMount> {
        let skills_path = PathBuf::from(skills_data_dir);
        let canonical_skills = std::fs::canonicalize(&skills_path).unwrap_or(skills_path.clone());
        let canonical_working =
            std::fs::canonicalize(working_dir).unwrap_or_else(|_| working_dir.clone());
        let mut mounts = Vec::new();
        if canonical_skills.exists() && canonical_skills != canonical_working {
            mounts.push(ExtraMount {
                host_path: canonical_skills,
                read_only: true,
            });
        }
        mounts
    }

    pub fn add_tool(&mut self, tool: Box<dyn Tool>) {
        // Invalidate cache when a new tool is added
        self.cached_static_definitions = OnceLock::new();
        self.tools.push(tool);
    }

    pub fn definitions(&self) -> Vec<ToolDefinition> {
        let static_defs = self
            .cached_static_definitions
            .get_or_init(|| self.tools.iter().map(|t| t.definition()).collect())
            .clone();
        let mut out = static_defs;
        let mut existing: std::collections::HashSet<String> =
            out.iter().map(|d| d.name.to_ascii_lowercase()).collect();
        for plugin_def in crate::plugins::dynamic_plugin_tool_definitions(&self.config) {
            let normalized = plugin_def.name.to_ascii_lowercase();
            if existing.insert(normalized) {
                out.push(plugin_def);
            }
        }
        out
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
        if let Err(msg) =
            validate_execution_policy(name, self.sandbox_mode, self.sandbox_runtime_available)
        {
            return ToolResult::error(msg).with_error_type("execution_policy_blocked");
        }
        if let Some(blocked) = require_high_risk_approval(name, auth, &input) {
            return blocked;
        }

        tracing::debug!(
            tool = name,
            risk = tool_risk(name).as_str(),
            execution_policy = tool_execution_policy(name).as_str(),
            sandbox_mode = ?self.sandbox_mode,
            sandbox_runtime_available = self.sandbox_runtime_available,
            "tool execution policy evaluated"
        );
        let input = Self::inject_default_chat_id_if_missing(name, input, auth);
        let input = inject_auth_context(input, auth);
        let result = self.execute(name, input.clone()).await;
        if result.error_type.as_deref() == Some("unknown_tool") {
            if let Some(dynamic) =
                crate::plugins::execute_dynamic_plugin_tool(&self.config, name, input).await
            {
                return dynamic;
            }
        }
        result
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

    struct CaptureInputTool {
        tool_name: String,
    }

    #[async_trait]
    impl Tool for CaptureInputTool {
        fn name(&self) -> &str {
            &self.tool_name
        }

        fn definition(&self) -> ToolDefinition {
            ToolDefinition {
                name: self.tool_name.clone(),
                description: "capture".into(),
                input_schema: schema_object(json!({}), &[]),
            }
        }

        async fn execute(&self, input: serde_json::Value) -> ToolResult {
            ToolResult::success(input.to_string())
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
    async fn test_high_risk_tool_requires_explicit_approval_on_web() {
        let registry = ToolRegistry {
            config: crate::config::Config::test_defaults(),
            sandbox_mode: SandboxMode::Off,
            sandbox_runtime_available: false,
            cached_static_definitions: OnceLock::new(),
            tools: vec![Box::new(DummyTool {
                tool_name: "bash".into(),
            })],
        };
        let auth = ToolAuthContext {
            caller_channel: "web".into(),
            caller_chat_id: 1,
            control_chat_ids: vec![],
        };

        let first = registry.execute_with_auth("bash", json!({}), &auth).await;
        assert!(first.is_error);
        assert_eq!(first.error_type.as_deref(), Some("approval_required"));

        let second = registry.execute_with_auth("bash", json!({}), &auth).await;
        assert!(second.is_error);
        assert_eq!(second.error_type.as_deref(), Some("approval_required"));

        let approved = registry
            .execute_with_auth(
                "bash",
                json!({"__microclaw_high_risk_approved": true}),
                &auth,
            )
            .await;
        assert!(!approved.is_error);
        assert_eq!(approved.content, "ok");
    }

    #[tokio::test]
    async fn test_high_risk_tool_requires_explicit_approval_on_control_chat() {
        let registry = ToolRegistry {
            config: crate::config::Config::test_defaults(),
            sandbox_mode: SandboxMode::Off,
            sandbox_runtime_available: false,
            cached_static_definitions: OnceLock::new(),
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

        let approved = registry
            .execute_with_auth(
                "bash",
                json!({"__microclaw_high_risk_approved": true}),
                &auth,
            )
            .await;
        assert!(!approved.is_error);
        assert_eq!(approved.content, "ok");
    }

    #[tokio::test]
    async fn test_medium_risk_tool_no_second_approval() {
        let registry = ToolRegistry {
            config: crate::config::Config::test_defaults(),
            sandbox_mode: SandboxMode::Off,
            sandbox_runtime_available: false,
            cached_static_definitions: OnceLock::new(),
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

    #[tokio::test]
    async fn test_dynamic_plugin_tool_executes_without_restart() {
        let root = std::env::temp_dir().join(format!("microclaw_plugin_{}", uuid::Uuid::new_v4()));
        let plugins_dir = root.join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();
        let manifest = plugins_dir.join("demo.yaml");
        std::fs::write(
            &manifest,
            r#"
name: demo
enabled: true
tools:
  - name: plugin_runtime_echo
    description: runtime echo
    input_schema:
      type: object
      properties: {}
      required: []
    run:
      command: "printf plugin-ok"
      timeout_secs: 5
"#,
        )
        .unwrap();

        let mut config = crate::config::Config::test_defaults();
        config.working_dir = root.join("work").to_string_lossy().to_string();
        config.plugins.enabled = true;
        config.plugins.dir = Some(plugins_dir.to_string_lossy().to_string());

        let registry = ToolRegistry {
            config,
            tools: vec![],
            sandbox_mode: SandboxMode::Off,
            sandbox_runtime_available: false,
            cached_static_definitions: OnceLock::new(),
        };
        let auth = ToolAuthContext {
            caller_channel: "web".into(),
            caller_chat_id: 7,
            control_chat_ids: vec![],
        };

        let defs = registry.definitions();
        assert!(defs.iter().any(|d| d.name == "plugin_runtime_echo"));

        let result = registry
            .execute_with_auth("plugin_runtime_echo", json!({}), &auth)
            .await;
        assert!(!result.is_error, "{}", result.content);
        assert!(result.content.contains("plugin-ok"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn test_injects_default_chat_id_for_memory_tools() {
        let registry = ToolRegistry {
            config: crate::config::Config::test_defaults(),
            sandbox_mode: SandboxMode::Off,
            sandbox_runtime_available: false,
            cached_static_definitions: OnceLock::new(),
            tools: vec![Box::new(CaptureInputTool {
                tool_name: "write_memory".into(),
            })],
        };
        let auth = ToolAuthContext {
            caller_channel: "feishu".into(),
            caller_chat_id: 8009499081,
            control_chat_ids: vec![],
        };

        let result = registry
            .execute_with_auth(
                "write_memory",
                json!({"scope":"chat","content":"hello"}),
                &auth,
            )
            .await;
        assert!(!result.is_error);
        let payload: serde_json::Value = serde_json::from_str(&result.content).unwrap();
        assert_eq!(payload["chat_id"].as_i64(), Some(8009499081));
    }

    #[tokio::test]
    async fn test_does_not_override_existing_chat_id() {
        let registry = ToolRegistry {
            config: crate::config::Config::test_defaults(),
            sandbox_mode: SandboxMode::Off,
            sandbox_runtime_available: false,
            cached_static_definitions: OnceLock::new(),
            tools: vec![Box::new(CaptureInputTool {
                tool_name: "write_memory".into(),
            })],
        };
        let auth = ToolAuthContext {
            caller_channel: "feishu".into(),
            caller_chat_id: 8009499081,
            control_chat_ids: vec![],
        };

        let result = registry
            .execute_with_auth(
                "write_memory",
                json!({"scope":"chat","chat_id":42,"content":"hello"}),
                &auth,
            )
            .await;
        assert!(!result.is_error);
        let payload: serde_json::Value = serde_json::from_str(&result.content).unwrap();
        assert_eq!(payload["chat_id"].as_i64(), Some(42));
    }
}
