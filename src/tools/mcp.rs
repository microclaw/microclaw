use std::sync::Arc;

use async_trait::async_trait;

use crate::mcp::{McpServer, McpToolInfo};
use microclaw_core::llm_types::ToolDefinition;

use super::{Tool, ToolResult};

pub struct McpTool {
    server: Arc<McpServer>,
    tool_info: McpToolInfo,
    qualified_name: String,
}

impl McpTool {
    pub fn new(server: Arc<McpServer>, tool_info: McpToolInfo) -> Self {
        // Namespaced name: mcp_{server}_{tool} to avoid conflicts with built-in tools
        let qualified_name = format!("mcp_{}_{}", tool_info.server_name, tool_info.name);
        // Sanitize: tool names must match [a-zA-Z0-9_-]{1,64}
        let qualified_name: String = qualified_name
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '_' || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .take(64)
            .collect();

        McpTool {
            server,
            tool_info,
            qualified_name,
        }
    }

    fn classify_mcp_error_type(err: &str) -> &'static str {
        let lower = err.to_ascii_lowercase();
        if lower.contains("rate-limited") {
            "mcp_rate_limited"
        } else if lower.contains("busy; exceeded queue wait") {
            "mcp_bulkhead_rejected"
        } else if lower.contains("circuit open") {
            "mcp_circuit_open"
        } else {
            "mcp_error"
        }
    }

    fn sanitize_input_for_mcp(input: serde_json::Value) -> serde_json::Value {
        let mut map = input.as_object().cloned().unwrap_or_default();
        map.retain(|k, _| !k.starts_with("__microclaw_"));
        serde_json::Value::Object(map)
    }
}

#[async_trait]
impl Tool for McpTool {
    fn name(&self) -> &str {
        &self.qualified_name
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: self.qualified_name.clone(),
            description: format!(
                "[MCP:{}] {}",
                self.tool_info.server_name, self.tool_info.description
            ),
            input_schema: self.tool_info.input_schema.clone(),
        }
    }

    async fn execute(&self, input: serde_json::Value) -> ToolResult {
        let sanitized_input = Self::sanitize_input_for_mcp(input);
        match self
            .server
            .call_tool(&self.tool_info.name, sanitized_input)
            .await
        {
            Ok(output) => ToolResult::success(output),
            Err(e) => ToolResult::error(format!("MCP tool error: {e}"))
                .with_error_type(Self::classify_mcp_error_type(&e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::McpTool;
    use serde_json::json;

    #[test]
    fn test_classify_mcp_error_type() {
        assert_eq!(
            McpTool::classify_mcp_error_type("rate-limited; retry in 3s"),
            "mcp_rate_limited"
        );
        assert_eq!(
            McpTool::classify_mcp_error_type("busy; exceeded queue wait of 200ms"),
            "mcp_bulkhead_rejected"
        );
        assert_eq!(
            McpTool::classify_mcp_error_type("circuit open; retry in 10s"),
            "mcp_circuit_open"
        );
        assert_eq!(
            McpTool::classify_mcp_error_type("transport disconnected"),
            "mcp_error"
        );
    }

    #[test]
    fn test_sanitize_input_for_mcp_strips_internal_keys() {
        let input = json!({
            "query": "status",
            "__microclaw_auth": {"caller_chat_id": 1},
            "__microclaw_async": true,
            "__microclaw_other": "x"
        });
        let out = McpTool::sanitize_input_for_mcp(input);
        assert_eq!(out, json!({"query": "status"}));
    }
}
