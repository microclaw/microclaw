pub mod activate_skill;
pub mod bash;
pub mod browser;
pub mod command_runner;
pub mod cursor_agent;
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
pub mod social_feed;
pub mod sub_agent;
pub mod sync_skills;
pub mod tiered_memory;
pub mod web_fetch;
pub mod web_html;
pub mod web_search;
pub mod write_file;

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::{path::Path, path::PathBuf, time::Instant};

use async_trait::async_trait;
use serde_json::json;
use teloxide::prelude::*;

use crate::claude::ToolDefinition;
use crate::config::Config;
use crate::db::Database;

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
        "bash" | "cursor_agent" => ToolRisk::High,
        "write_file"
        | "edit_file"
        | "write_memory"
        | "write_tiered_memory"
        | "send_message"
        | "sync_skills"
        | "schedule_task"
        | "pause_scheduled_task"
        | "resume_scheduled_task"
        | "cancel_scheduled_task" => ToolRisk::Medium,
        _ => ToolRisk::Low,
    }
}

const APPROVAL_CONTEXT_KEY: &str = "__microclaw_approval";

fn approval_token_from_input(input: &serde_json::Value) -> Option<String> {
    input
        .get(APPROVAL_CONTEXT_KEY)
        .and_then(|v| v.get("token"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn issue_approval_token() -> String {
    uuid::Uuid::new_v4()
        .simple()
        .to_string()
        .chars()
        .take(8)
        .collect()
}

fn approval_key(auth: &ToolAuthContext, tool_name: &str) -> String {
    format!(
        "{}:{}:{}",
        auth.caller_channel, auth.caller_chat_id, tool_name
    )
}

fn pending_approvals() -> &'static std::sync::Mutex<HashMap<String, String>> {
    static PENDING: OnceLock<std::sync::Mutex<HashMap<String, String>>> = OnceLock::new();
    PENDING.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

fn requires_high_risk_approval(name: &str, auth: &ToolAuthContext) -> bool {
    tool_risk(name) == ToolRisk::High && (auth.caller_channel == "web" || auth.is_control_chat())
}

#[derive(Clone, Debug)]
pub struct ToolAuthContext {
    pub caller_channel: String,
    pub caller_chat_id: i64,
    pub caller_persona_id: i64,
    pub control_chat_ids: Vec<i64>,
}

impl ToolAuthContext {
    pub fn is_control_chat(&self) -> bool {
        self.control_chat_ids.contains(&self.caller_chat_id)
    }

    pub fn can_access_chat(&self, target_chat_id: i64) -> bool {
        self.is_control_chat() || self.caller_chat_id == target_chat_id
    }

    /// True if the caller can access the given (chat_id, persona_id) for memory/tiered operations.
    pub fn can_access_chat_persona(&self, target_chat_id: i64, target_persona_id: i64) -> bool {
        self.is_control_chat()
            || (self.caller_chat_id == target_chat_id && self.caller_persona_id == target_persona_id)
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
    let caller_persona_id = ctx
        .get("caller_persona_id")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let control_chat_ids = ctx
        .get("control_chat_ids")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|x| x.as_i64()).collect())
        .unwrap_or_default();
    Some(ToolAuthContext {
        caller_channel,
        caller_chat_id,
        caller_persona_id,
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

/// Authorize access to (chat_id, persona_id) for tiered memory. Fails if auth is missing or cannot access that pair.
pub fn authorize_chat_persona_access(
    input: &serde_json::Value,
    target_chat_id: i64,
    target_persona_id: i64,
) -> Result<(), String> {
    let auth = auth_context_from_input(input)
        .ok_or_else(|| "Permission denied: no auth context".to_string())?;
    if !auth.can_access_chat_persona(target_chat_id, target_persona_id) {
        return Err(format!(
            "Permission denied: cannot access memory for chat {} persona {}",
            target_chat_id, target_persona_id
        ));
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
            "caller_persona_id": auth.caller_persona_id,
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
}

pub fn resolve_tool_path(working_dir: &Path, path: &str) -> PathBuf {
    let candidate = PathBuf::from(path);
    if candidate.is_absolute() {
        candidate
    } else {
        working_dir.join(candidate)
    }
}

/// Resolve the tool working directory. Always uses the shared workspace (base/shared).
pub fn resolve_tool_working_dir(base_working_dir: &Path) -> PathBuf {
    let resolved = base_working_dir.join("shared");
    let _ = std::fs::create_dir_all(&resolved);
    resolved
}

impl ToolRegistry {
    pub fn new(config: &Config, bot: Bot, db: Arc<Database>) -> Self {
        let working_dir = PathBuf::from(config.working_dir());
        if let Err(e) = std::fs::create_dir_all(&working_dir) {
            tracing::warn!(
                "Failed to create working_dir '{}': {}",
                working_dir.display(),
                e
            );
        }
        let skills_data_dir = config.skills_data_dir();
        let tools: Vec<Box<dyn Tool>> = vec![
            Box::new(bash::BashTool::new(config.working_dir())),
            Box::new(browser::BrowserTool::new(
                &config.runtime_data_dir(),
                config.agent_browser_path.clone(),
            )),
            Box::new(read_file::ReadFileTool::new(config.working_dir())),
            Box::new(write_file::WriteFileTool::new(config.working_dir())),
            Box::new(edit_file::EditFileTool::new(config.working_dir())),
            Box::new(glob::GlobTool::new(config.working_dir())),
            Box::new(grep::GrepTool::new(config.working_dir())),
            Box::new(memory::ReadMemoryTool::new(&config.runtime_data_dir(), config.working_dir())),
            Box::new(memory::WriteMemoryTool::new(&config.runtime_data_dir(), config.working_dir())),
            Box::new(web_fetch::WebFetchTool),
            Box::new(web_search::WebSearchTool),
            Box::new(send_message::SendMessageTool::new_with_config(
                bot,
                db.clone(),
                config.bot_username.clone(),
                config.clone(),
            )),
            Box::new(schedule::ScheduleTaskTool::new(
                db.clone(),
                config.timezone.clone(),
            )),
            Box::new(schedule::ListTasksTool::new(db.clone())),
            Box::new(schedule::PauseTaskTool::new(db.clone())),
            Box::new(schedule::ResumeTaskTool::new(db.clone())),
            Box::new(schedule::CancelTaskTool::new(db.clone())),
            Box::new(schedule::GetTaskHistoryTool::new(db.clone())),
            Box::new(export_chat::ExportChatTool::new(db.clone(), &config.runtime_data_dir())),
            Box::new(sub_agent::SubAgentTool::new(config)),
            Box::new(cursor_agent::CursorAgentTool::new(config, db.clone())),
            Box::new(cursor_agent::ListCursorAgentRunsTool::new(db.clone())),
            Box::new(activate_skill::ActivateSkillTool::new(&skills_data_dir)),
            Box::new(sync_skills::SyncSkillsTool::new(&skills_data_dir)),
            Box::new(tiered_memory::ReadTieredMemoryTool::new(&config.runtime_data_dir())),
            Box::new(tiered_memory::WriteTieredMemoryTool::new(&config.runtime_data_dir())),
        ];

        let mut tools: Vec<Box<dyn Tool>> = tools;
        let mut social_added = Vec::new();
        if let Some(ref social) = config.social {
            if social.is_platform_enabled("tiktok") {
                tools.push(Box::new(social_feed::FetchTiktokFeedTool::new(config, db.clone())));
                social_added.push("fetch_tiktok_feed");
            }
            if social.is_platform_enabled("instagram") {
                tools.push(Box::new(social_feed::FetchInstagramFeedTool::new(config, db.clone())));
                social_added.push("fetch_instagram_feed");
            }
            if social.is_platform_enabled("linkedin") {
                tools.push(Box::new(social_feed::FetchLinkedinFeedTool::new(config, db)));
                social_added.push("fetch_linkedin_feed");
            }
        }
        if !social_added.is_empty() {
            tracing::info!("Social feed tools registered: {}", social_added.join(", "));
        }
        ToolRegistry { tools }
    }

    /// Create a restricted tool registry for sub-agents (no side-effect or recursive tools).
    pub fn new_sub_agent(config: &Config) -> Self {
        let working_dir = PathBuf::from(config.working_dir());
        if let Err(e) = std::fs::create_dir_all(&working_dir) {
            tracing::warn!(
                "Failed to create working_dir '{}': {}",
                working_dir.display(),
                e
            );
        }
        let skills_data_dir = config.skills_data_dir();
        let tools: Vec<Box<dyn Tool>> = vec![
            Box::new(bash::BashTool::new(config.working_dir())),
            Box::new(browser::BrowserTool::new(
                &config.runtime_data_dir(),
                config.agent_browser_path.clone(),
            )),
            Box::new(read_file::ReadFileTool::new(config.working_dir())),
            Box::new(write_file::WriteFileTool::new(config.working_dir())),
            Box::new(edit_file::EditFileTool::new(config.working_dir())),
            Box::new(glob::GlobTool::new(config.working_dir())),
            Box::new(grep::GrepTool::new(config.working_dir())),
            Box::new(memory::ReadMemoryTool::new(&config.runtime_data_dir(), config.working_dir())),
            Box::new(tiered_memory::ReadTieredMemoryTool::new(&config.runtime_data_dir())),
            Box::new(web_fetch::WebFetchTool),
            Box::new(web_search::WebSearchTool),
            Box::new(activate_skill::ActivateSkillTool::new(&skills_data_dir)),
        ];
        ToolRegistry { tools }
    }

    pub fn add_tool(&mut self, tool: Box<dyn Tool>) {
        self.tools.push(tool);
    }

    pub fn definitions(&self) -> Vec<ToolDefinition> {
        self.tools.iter().map(|t| t.definition()).collect()
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
            let provided = approval_token_from_input(&input);
            let key = approval_key(auth, name);
            let mut pending = pending_approvals()
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            match provided {
                Some(token) => {
                    let valid = pending.get(&key).map(|t| t == &token).unwrap_or(false);
                    if valid {
                        pending.remove(&key);
                    } else {
                        let replacement = issue_approval_token();
                        pending.insert(key, replacement.clone());
                        return ToolResult::error(format!(
                            "Approval token invalid or expired for high-risk tool '{name}' (risk: {}). Re-run with __microclaw_approval.token=\"{}\".",
                            tool_risk(name).as_str(),
                            replacement
                        ))
                        .with_error_type("approval_required");
                    }
                }
                None => {
                    let token = issue_approval_token();
                    pending.insert(key, token.clone());
                    return ToolResult::error(format!(
                        "Approval required for high-risk tool '{name}' (risk: {}). Re-run the same tool with __microclaw_approval.token=\"{}\" to confirm.",
                        tool_risk(name).as_str(),
                        token
                    ))
                    .with_error_type("approval_required");
                }
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
        let dir = resolve_tool_working_dir(std::path::Path::new("/tmp/work"));
        assert_eq!(dir, std::path::PathBuf::from("/tmp/work/shared"));
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

    fn extract_token(msg: &str) -> String {
        let marker = "__microclaw_approval.token=\"";
        let start = msg.find(marker).unwrap() + marker.len();
        let rest = &msg[start..];
        rest.split('"').next().unwrap().to_string()
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
            tools: vec![Box::new(DummyTool {
                tool_name: "bash".into(),
            })],
        };
        let auth = ToolAuthContext {
            caller_channel: "web".into(),
            caller_chat_id: 1,
            caller_persona_id: 0,
            control_chat_ids: vec![],
        };

        let first = registry.execute_with_auth("bash", json!({}), &auth).await;
        assert!(first.is_error);
        assert_eq!(first.error_type.as_deref(), Some("approval_required"));
        let token = extract_token(&first.content);

        let second = registry
            .execute_with_auth(
                "bash",
                json!({"__microclaw_approval": {"token": token}}),
                &auth,
            )
            .await;
        assert!(!second.is_error);
        assert_eq!(second.content, "ok");
    }

    #[tokio::test]
    async fn test_high_risk_tool_requires_second_approval_on_control_chat() {
        let registry = ToolRegistry {
            tools: vec![Box::new(DummyTool {
                tool_name: "bash".into(),
            })],
        };
        let auth = ToolAuthContext {
            caller_channel: "telegram".into(),
            caller_chat_id: 123,
            caller_persona_id: 1,
            control_chat_ids: vec![123],
        };

        let first = registry.execute_with_auth("bash", json!({}), &auth).await;
        assert!(first.is_error);
        assert_eq!(first.error_type.as_deref(), Some("approval_required"));
    }

    #[tokio::test]
    async fn test_medium_risk_tool_no_second_approval() {
        let registry = ToolRegistry {
            tools: vec![Box::new(DummyTool {
                tool_name: "write_file".into(),
            })],
        };
        let auth = ToolAuthContext {
            caller_channel: "web".into(),
            caller_chat_id: 1,
            caller_persona_id: 0,
            control_chat_ids: vec![],
        };

        let result = registry
            .execute_with_auth("write_file", json!({}), &auth)
            .await;
        assert!(!result.is_error);
        assert_eq!(result.content, "ok");
    }
}
