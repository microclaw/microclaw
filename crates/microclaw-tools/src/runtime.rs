use std::path::{Path, PathBuf};

use async_trait::async_trait;
use microclaw_core::llm_types::ToolDefinition;
use serde_json::json;

use crate::sandbox::SandboxMode;
use crate::types::WorkingDirIsolation;

pub struct ToolResult {
    pub content: String,
    pub is_error: bool,
    pub status_code: Option<i32>,
    pub bytes: usize,
    pub duration_ms: Option<u128>,
    pub error_type: Option<String>,
    pub metadata: Option<serde_json::Value>,
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
            metadata: None,
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
            metadata: None,
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

    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = Some(metadata);
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToolExecutionPolicy {
    HostOnly,
    SandboxOnly,
    Dual,
}

impl ToolExecutionPolicy {
    pub fn as_str(&self) -> &'static str {
        match self {
            ToolExecutionPolicy::HostOnly => "host-only",
            ToolExecutionPolicy::SandboxOnly => "sandbox-only",
            ToolExecutionPolicy::Dual => "dual",
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
        | "replay_scheduled_task_dlq"
        | "structured_memory_delete"
        | "structured_memory_update" => ToolRisk::Medium,
        _ => ToolRisk::Low,
    }
}

pub fn tool_execution_policy(name: &str) -> ToolExecutionPolicy {
    match name {
        "bash" => ToolExecutionPolicy::Dual,
        "write_file" | "edit_file" => ToolExecutionPolicy::HostOnly,
        _ => ToolExecutionPolicy::HostOnly,
    }
}

pub fn validate_execution_policy(
    name: &str,
    sandbox_mode: SandboxMode,
    sandbox_runtime_available: bool,
) -> Result<(), String> {
    let policy = tool_execution_policy(name);
    match policy {
        ToolExecutionPolicy::HostOnly => Ok(()),
        ToolExecutionPolicy::SandboxOnly => {
            if sandbox_mode == SandboxMode::All && sandbox_runtime_available {
                Ok(())
            } else {
                Err(format!(
                    "Tool '{name}' requires sandbox runtime (policy: {}). Enable sandbox and ensure docker runtime is available.",
                    policy.as_str()
                ))
            }
        }
        ToolExecutionPolicy::Dual => {
            if sandbox_mode == SandboxMode::All && !sandbox_runtime_available {
                // Allowed by current fallback behavior, but explicit for observability.
                tracing::warn!(
                    tool = name,
                    policy = policy.as_str(),
                    "sandbox configured but runtime unavailable; falling back to host execution"
                );
            }
            Ok(())
        }
    }
}

#[derive(Clone, Debug)]
pub struct ToolAuthContext {
    pub caller_channel: String,
    pub caller_chat_id: i64,
    pub control_chat_ids: Vec<i64>,
    pub env_files: Vec<String>,
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
    let env_files = ctx
        .get("env_files")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    Some(ToolAuthContext {
        caller_channel,
        caller_chat_id,
        control_chat_ids,
        env_files,
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

pub fn inject_auth_context(input: serde_json::Value, auth: &ToolAuthContext) -> serde_json::Value {
    let mut obj = match input {
        serde_json::Value::Object(map) => map,
        _ => serde_json::Map::new(),
    };
    let mut auth_val = json!({
        "caller_channel": auth.caller_channel,
        "caller_chat_id": auth.caller_chat_id,
        "control_chat_ids": auth.control_chat_ids,
    });
    if !auth.env_files.is_empty() {
        auth_val["env_files"] = json!(auth.env_files);
    }
    obj.insert(AUTH_CONTEXT_KEY.to_string(), auth_val);
    serde_json::Value::Object(obj)
}

#[async_trait]
pub trait Tool: Send + Sync {
    fn name(&self) -> &str;
    fn definition(&self) -> ToolDefinition;
    async fn execute(&self, input: serde_json::Value) -> ToolResult;
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

fn requires_high_risk_approval(name: &str, auth: &ToolAuthContext) -> bool {
    tool_risk(name) == ToolRisk::High && (auth.caller_channel == "web" || auth.is_control_chat())
}

const HIGH_RISK_APPROVED_KEY: &str = "__microclaw_high_risk_approved";

pub fn require_high_risk_approval(
    name: &str,
    auth: &ToolAuthContext,
    input: &serde_json::Value,
) -> Option<ToolResult> {
    if !requires_high_risk_approval(name, auth) {
        return None;
    }

    let approved = input
        .get(HIGH_RISK_APPROVED_KEY)
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if approved {
        tracing::warn!(
            tool = name,
            channel = auth.caller_channel.as_str(),
            chat_id = auth.caller_chat_id,
            "Executing high-risk tool with explicit approval marker"
        );
        None
    } else {
        Some(
            ToolResult::error(format!(
                "Approval required for high-risk tool '{name}' (risk: {}). Add `{HIGH_RISK_APPROVED_KEY}: true` only after explicit operator approval.",
                tool_risk(name).as_str(),
            ))
            .with_error_type("approval_required"),
        )
    }
}

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
    fn test_tool_execution_policy_levels() {
        assert_eq!(tool_execution_policy("bash"), ToolExecutionPolicy::Dual);
        assert_eq!(
            tool_execution_policy("write_file"),
            ToolExecutionPolicy::HostOnly
        );
        assert_eq!(
            tool_execution_policy("read_file"),
            ToolExecutionPolicy::HostOnly
        );
    }

    #[test]
    fn test_validate_execution_policy_dual_allows_fallback() {
        let ok = validate_execution_policy("bash", SandboxMode::All, false);
        assert!(ok.is_ok());
    }
}
