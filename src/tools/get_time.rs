use async_trait::async_trait;
use chrono::Utc;
use serde_json::json;

use super::{schema_object, Tool, ToolResult};
use microclaw_core::llm_types::ToolDefinition;

pub struct GetTimeTool {
    default_timezone: String,
}

impl GetTimeTool {
    pub fn new(default_timezone: String) -> Self {
        GetTimeTool { default_timezone }
    }
}

#[async_trait]
impl Tool for GetTimeTool {
    fn name(&self) -> &str {
        "get_time"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "get_time".into(),
            description: "Get the current time in a specified timezone. Returns the local time, UTC time, and Unix timestamp. Use this instead of running shell commands like `date` to get accurate time information.".into(),
            input_schema: schema_object(
                json!({
                    "timezone": {
                        "type": "string",
                        "description": "IANA timezone name (e.g. 'Asia/Shanghai', 'US/Eastern', 'Europe/London'). Defaults to the server configured timezone if omitted."
                    }
                }),
                &[],
            ),
        }
    }

    async fn execute(&self, input: serde_json::Value) -> ToolResult {
        let tz_name = input
            .get("timezone")
            .and_then(|v| v.as_str())
            .unwrap_or(&self.default_timezone);

        let tz: chrono_tz::Tz = match tz_name.parse() {
            Ok(t) => t,
            Err(_) => return ToolResult::error(format!("Invalid timezone: {tz_name}")),
        };

        let now_utc = Utc::now();
        let now_local = now_utc.with_timezone(&tz);
        let timestamp = now_utc.timestamp();

        let result = format!(
            "Timezone: {tz_name}\nLocal time: {}\nUTC time: {}\nUnix timestamp: {timestamp}",
            now_local.format("%Y-%m-%d %H:%M:%S %Z"),
            now_utc.format("%Y-%m-%d %H:%M:%S UTC"),
        );

        ToolResult::success(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_get_time_default_timezone() {
        let tool = GetTimeTool::new("UTC".into());
        let result = tool.execute(json!({})).await;
        assert!(!result.is_error, "Error: {}", result.content);
        assert!(result.content.contains("Timezone: UTC"));
        assert!(result.content.contains("Unix timestamp:"));
    }

    #[tokio::test]
    async fn test_get_time_with_timezone() {
        let tool = GetTimeTool::new("UTC".into());
        let result = tool.execute(json!({"timezone": "Asia/Shanghai"})).await;
        assert!(!result.is_error, "Error: {}", result.content);
        assert!(result.content.contains("Timezone: Asia/Shanghai"));
        assert!(result.content.contains("Unix timestamp:"));
    }

    #[tokio::test]
    async fn test_get_time_invalid_timezone() {
        let tool = GetTimeTool::new("UTC".into());
        let result = tool.execute(json!({"timezone": "Not/A/Zone"})).await;
        assert!(result.is_error);
        assert!(result.content.contains("Invalid timezone"));
    }

    #[tokio::test]
    async fn test_get_time_uses_configured_default() {
        let tool = GetTimeTool::new("Asia/Tokyo".into());
        let result = tool.execute(json!({})).await;
        assert!(!result.is_error, "Error: {}", result.content);
        assert!(result.content.contains("Timezone: Asia/Tokyo"));
    }
}
