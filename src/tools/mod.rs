pub mod activate_skill;
pub mod bash;
pub mod browser;
pub mod command_runner;
pub mod edit_file;
pub mod export_chat;
pub mod glob;
pub mod grep;
pub mod mcp;
pub mod memory;
pub mod path_guard;
pub mod read_file;
pub mod schedule;
pub mod send_message;
pub mod structured_memory;
pub mod sub_agent;
pub mod sync_skills;
pub mod todo;
pub mod web_fetch;
pub mod web_html;
pub mod web_search;
pub mod write_file;

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::{path::Path, path::PathBuf, time::Instant};

use crate::channel_adapter::ChannelRegistry;
use crate::config::{Config, WorkingDirIsolation};
use crate::db::Database;
use crate::llm_types::ToolDefinition;
use async_trait::async_trait;
use serde_json::json;

pub struct ToolResult {
    pub content: String,
    pub is_error: bool,
    pub status_code: Option<i32>,
    pub bytes: usize,
    pub duration_ms: Option<u128>,
    pub error_type: Option<String>,
}

impl ToolResult {
    pub fn success(content: String) -> Self {
        let bytes = content.len();
        ToolResult {
            content,
            is_error: false,
            status_code: Some(0),
            bytes,
            duration_ms: None,
            error_type: None,
        }
    }

    pub fn error(content: String) -> Self {
        let bytes = content.len();
        ToolResult {
            content,
            is_error: true,
            status_code: Some(1),
            bytes,
            duration_ms: None,
            error_type: Some("tool_error".to_string()),
        }
    }

    pub fn with_status_code(mut self, status_code: i32) -> Self {
        self.status_code = Some(status_code);
        self
    }

    pub fn with_error_type(mut self, error_type: impl Into<String>) -> Self {
        self.error_type = Some(error_type.into());
        self
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToolRisk {
    Low,
    Medium,
    High,
}

impl ToolRisk {
    pub fn as_str(&self) -> &'static str {
        match self {
            ToolRisk::Low => "low",
            ToolRisk::Medium => "medium",
            ToolRisk::High => "high",
        }
    }
}

pub fn tool_risk(name: &str) -> ToolRisk {
    match name {
        "bash" => ToolRisk::High,
        "write_file"
        | "edit_file"
        | "write_memory"
        | "send_message"
        | "sync_skills"
        | "schedule_task"
        | "pause_scheduled_task"
        | "resume_scheduled_task"
        | "cancel_scheduled_task"
        | "structured_memory_delete"
        | "structured_memory_update" => ToolRisk::Medium,
        _ => ToolRisk::Low,
    }
}

fn approval_key(auth: &ToolAuthContext, tool_name: &str) -> String {
    format!(
        "{}:{}:{}",
        auth.caller_channel, auth.caller_chat_id, tool_name
    )
}

fn pending_approvals() -> &'static std::sync::Mutex<HashMap<String, Instant>> {
    static PENDING: OnceLock<std::sync::Mutex<HashMap<String, Instant>>> = OnceLock::new();
    PENDING.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

fn requires_high_risk_approval(name: &str, auth: &ToolAuthContext) -> bool {
    tool_risk(name) == ToolRisk::High && (auth.caller_channel == "web" || auth.is_control_chat())
}

#[derive(Clone, Debug)]
pub struct ToolAuthContext {
    pub caller_channel: String,
    pub caller_chat_id: i64,
    pub control_chat_ids: Vec<i64>,
}

impl ToolAuthContext {
    pub fn is_control_chat(&self) -> bool {
        self.control_chat_ids.contains(&self.caller_chat_id)
    }

    pub fn can_access_chat(&self, target_chat_id: i64) -> bool {
        self.is_control_chat() || self.caller_chat_id == target_chat_id
    }
}

const AUTH_CONTEXT_KEY: &str = "__microclaw_auth";

pub fn auth_context_from_input(input: &serde_json::Value) -> Option<ToolAuthContext> {
    let ctx = input.get(AUTH_CONTEXT_KEY)?;
    let caller_channel = ctx
        .get("caller_channel")
        .and_then(|v| v.as_str())
        .unwrap_or("telegram")
        .to_string();
    let caller_chat_id = ctx.get("caller_chat_id")?.as_i64()?;
    let control_chat_ids = ctx
        .get("control_chat_ids")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|x| x.as_i64()).collect())
        .unwrap_or_default();
    Some(ToolAuthContext {
        caller_channel,
        caller_chat_id,
        control_chat_ids,
    })
}

pub fn authorize_chat_access(input: &serde_json::Value, target_chat_id: i64) -> Result<(), String> {
    if let Some(auth) = auth_context_from_input(input) {
        if !auth.can_access_chat(target_chat_id) {
            return Err(format!(
                "Permission denied: chat {} cannot operate on chat {}",
                auth.caller_chat_id, target_chat_id
            ));
        }
    }
    Ok(())
}

fn inject_auth_context(input: serde_json::Value, auth: &ToolAuthContext) -> serde_json::Value {
    let mut obj = match input {
        serde_json::Value::Object(map) => map,
        _ => serde_json::Map::new(),
    };
    obj.insert(
        AUTH_CONTEXT_KEY.to_string(),
        json!({
            "caller_channel": auth.caller_channel,
            "caller_chat_id": auth.caller_chat_id,
            "control_chat_ids": auth.control_chat_ids,
        }),
    );
    serde_json::Value::Object(obj)
}

#[async_trait]
pub trait Tool: Send + Sync {
    fn name(&self) -> &str;
    fn definition(&self) -> ToolDefinition;
    async fn execute(&self, input: serde_json::Value) -> ToolResult;
}

pub struct ToolRegistry {
    tools: Vec<Box<dyn Tool>>,
    cached_definitions: OnceLock<Vec<ToolDefinition>>,
}

pub fn resolve_tool_path(working_dir: &Path, path: &str) -> PathBuf {
    let candidate = PathBuf::from(path);
    if candidate.is_absolute() {
        candidate
    } else {
        working_dir.join(candidate)
    }
}

fn sanitize_channel_segment(channel: &str) -> String {
    let mut out = String::with_capacity(channel.len());
    for c in channel.chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
            out.push(c.to_ascii_lowercase());
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "unknown".to_string()
    } else {
        out
    }
}

fn chat_working_dir(base_working_dir: &Path, channel: &str, chat_id: i64) -> PathBuf {
    let chat_segment = if chat_id < 0 {
        format!("neg{}", chat_id.unsigned_abs())
    } else {
        chat_id.to_string()
    };
    base_working_dir
        .join("chat")
        .join(sanitize_channel_segment(channel))
        .join(chat_segment)
}

pub fn resolve_tool_working_dir(
    base_working_dir: &Path,
    isolation: WorkingDirIsolation,
    input: &serde_json::Value,
) -> PathBuf {
    let resolved = match isolation {
        WorkingDirIsolation::Shared => base_working_dir.join("shared"),
        WorkingDirIsolation::Chat => auth_context_from_input(input)
            .map(|auth| {
                chat_working_dir(base_working_dir, &auth.caller_channel, auth.caller_chat_id)
            })
            .unwrap_or_else(|| base_working_dir.join("shared")),
    };
    let _ = std::fs::create_dir_all(&resolved);
    resolved
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
        let skills_data_dir = config.skills_data_dir();
        let tools: Vec<Box<dyn Tool>> = vec![
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
        let skills_data_dir = config.skills_data_dir();
        let tools: Vec<Box<dyn Tool>> = vec![
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
        if requires_high_risk_approval(name, auth) {
            let key = approval_key(auth, name);
            let mut pending = pending_approvals()
                .lock()
                .unwrap_or_else(|e| e.into_inner());

            if let Some(&created_at) = pending.get(&key) {
                if created_at.elapsed().as_secs() < 120 {
                    // Already warned within 2 minutes — auto-approve on retry
                    tracing::warn!(
                        tool = name,
                        channel = auth.caller_channel.as_str(),
                        chat_id = auth.caller_chat_id,
                        elapsed_secs = created_at.elapsed().as_secs(),
                        "Auto-approved high-risk tool on retry"
                    );
                    pending.remove(&key);
                } else {
                    // Expired — re-issue warning
                    pending.insert(key, Instant::now());
                    return ToolResult::error(format!(
                        "Approval expired for high-risk tool '{name}' (risk: {}). Re-run the same tool call to confirm.",
                        tool_risk(name).as_str(),
                    ))
                    .with_error_type("approval_required");
                }
            } else {
                // First call — store pending and warn
                pending.insert(key, Instant::now());
                return ToolResult::error(format!(
                    "Approval required for high-risk tool '{name}' (risk: {}). Re-run the same tool call to confirm.",
                    tool_risk(name).as_str(),
                ))
                .with_error_type("approval_required");
            }
        }

        let input = inject_auth_context(input, auth);
        self.execute(name, input).await
    }
}

/// Helper to build a JSON Schema object with required properties.
pub fn schema_object(properties: serde_json::Value, required: &[&str]) -> serde_json::Value {
    json!({
        "type": "object",
        "properties": properties,
        "required": required,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WorkingDirIsolation;

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
