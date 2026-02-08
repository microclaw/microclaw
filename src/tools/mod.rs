pub mod activate_skill;
pub mod bash;
pub mod browser;
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
pub mod sub_agent;
pub mod todo;
pub mod web_fetch;
pub mod web_search;
pub mod write_file;

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::json;
use teloxide::prelude::*;

use crate::claude::ToolDefinition;
use crate::config::Config;
use crate::db::Database;

pub struct ToolResult {
    pub content: String,
    pub is_error: bool,
}

impl ToolResult {
    pub fn success(content: String) -> Self {
        ToolResult {
            content,
            is_error: false,
        }
    }

    pub fn error(content: String) -> Self {
        ToolResult {
            content,
            is_error: true,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ToolAuthContext {
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
    let caller_chat_id = ctx.get("caller_chat_id")?.as_i64()?;
    let control_chat_ids = ctx
        .get("control_chat_ids")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|x| x.as_i64()).collect())
        .unwrap_or_default();
    Some(ToolAuthContext {
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
}

impl ToolRegistry {
    pub fn new(config: &Config, bot: Bot, db: Arc<Database>) -> Self {
        let skills_data_dir = config.skills_data_dir();
        let tools: Vec<Box<dyn Tool>> = vec![
            Box::new(bash::BashTool),
            Box::new(browser::BrowserTool::new(&config.data_dir)),
            Box::new(read_file::ReadFileTool),
            Box::new(write_file::WriteFileTool),
            Box::new(edit_file::EditFileTool),
            Box::new(glob::GlobTool),
            Box::new(grep::GrepTool),
            Box::new(memory::ReadMemoryTool::new(&config.data_dir)),
            Box::new(memory::WriteMemoryTool::new(&config.data_dir)),
            Box::new(web_fetch::WebFetchTool),
            Box::new(web_search::WebSearchTool),
            Box::new(send_message::SendMessageTool::new(bot)),
            Box::new(schedule::ScheduleTaskTool::new(
                db.clone(),
                config.timezone.clone(),
            )),
            Box::new(schedule::ListTasksTool::new(db.clone())),
            Box::new(schedule::PauseTaskTool::new(db.clone())),
            Box::new(schedule::ResumeTaskTool::new(db.clone())),
            Box::new(schedule::CancelTaskTool::new(db.clone())),
            Box::new(schedule::GetTaskHistoryTool::new(db.clone())),
            Box::new(export_chat::ExportChatTool::new(db, &config.data_dir)),
            Box::new(sub_agent::SubAgentTool::new(config)),
            Box::new(activate_skill::ActivateSkillTool::new(&skills_data_dir)),
            Box::new(todo::TodoReadTool::new(&config.data_dir)),
            Box::new(todo::TodoWriteTool::new(&config.data_dir)),
        ];
        ToolRegistry { tools }
    }

    /// Create a restricted tool registry for sub-agents (no side-effect or recursive tools).
    pub fn new_sub_agent(config: &Config) -> Self {
        let skills_data_dir = config.skills_data_dir();
        let tools: Vec<Box<dyn Tool>> = vec![
            Box::new(bash::BashTool),
            Box::new(browser::BrowserTool::new(&config.data_dir)),
            Box::new(read_file::ReadFileTool),
            Box::new(write_file::WriteFileTool),
            Box::new(edit_file::EditFileTool),
            Box::new(glob::GlobTool),
            Box::new(grep::GrepTool),
            Box::new(memory::ReadMemoryTool::new(&config.data_dir)),
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
                return tool.execute(input).await;
            }
        }
        ToolResult::error(format!("Unknown tool: {name}"))
    }

    pub async fn execute_with_auth(
        &self,
        name: &str,
        input: serde_json::Value,
        auth: &ToolAuthContext,
    ) -> ToolResult {
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
                "caller_chat_id": 123,
                "control_chat_ids": [123, 999]
            }
        });
        let auth = auth_context_from_input(&input).unwrap();
        assert_eq!(auth.caller_chat_id, 123);
        assert!(auth.is_control_chat());
        assert!(auth.can_access_chat(456));
    }

    #[test]
    fn test_authorize_chat_access_denied() {
        let input = json!({
            "__microclaw_auth": {
                "caller_chat_id": 100,
                "control_chat_ids": []
            }
        });
        let err = authorize_chat_access(&input, 200).unwrap_err();
        assert!(err.contains("Permission denied"));
    }
}
