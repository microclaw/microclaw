use async_trait::async_trait;
use serde_json::json;
use std::path::PathBuf;
use tracing::info;

use crate::config::WorkingDirIsolation;
use crate::llm_types::ToolDefinition;

use super::{schema_object, Tool, ToolResult};

pub struct WriteFileTool {
    working_dir: PathBuf,
    working_dir_isolation: WorkingDirIsolation,
}

impl WriteFileTool {
    pub fn new(working_dir: &str) -> Self {
        Self::new_with_isolation(working_dir, WorkingDirIsolation::Shared)
    }

    pub fn new_with_isolation(
        working_dir: &str,
        working_dir_isolation: WorkingDirIsolation,
    ) -> Self {
        Self {
            working_dir: PathBuf::from(working_dir),
            working_dir_isolation,
        }
    }
}

#[async_trait]
impl Tool for WriteFileTool {
    fn name(&self) -> &str {
        "write_file"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "write_file".into(),
            description: "Write content to a file. Creates the file and any parent directories if they don't exist. Overwrites existing content.".into(),
            input_schema: schema_object(
                json!({
                    "path": {
                        "type": "string",
                        "description": "The file path to write to"
                    },
                    "content": {
                        "type": "string",
                        "description": "The content to write"
                    }
                }),
                &["path", "content"],
            ),
        }
    }

    async fn execute(&self, input: serde_json::Value) -> ToolResult {
        let path = match input.get("path").and_then(|v| v.as_str()) {
            Some(p) => p,
            None => return ToolResult::error("Missing 'path' parameter".into()),
        };
        let working_dir =
            super::resolve_tool_working_dir(&self.working_dir, self.working_dir_isolation, &input);
        let resolved_path = super::resolve_tool_path(&working_dir, path);
        let resolved_path_str = resolved_path.to_string_lossy().to_string();

        if let Err(msg) = crate::tools::path_guard::check_path(&resolved_path_str) {
            return ToolResult::error(msg);
        }

        // Guard: SKILL.md files must go in the correct skills directory, not runtime/skills/ or elsewhere.
        if resolved_path.file_name().and_then(|f| f.to_str()) == Some("SKILL.md") {
            let skills_marker = std::path::Path::new("microclaw.data").join("skills");
            let runtime_skills = std::path::Path::new("microclaw.data")
                .join("runtime")
                .join("skills");
            let path_str = resolved_path.to_string_lossy();
            let in_correct_dir = path_str.contains(&skills_marker.to_string_lossy().to_string());
            let in_runtime_dir = path_str.contains(&runtime_skills.to_string_lossy().to_string());
            if in_runtime_dir || !in_correct_dir {
                return ToolResult::error(format!(
                    "Wrong directory for skills! SKILL.md files MUST be written to microclaw.data/skills/<skill-name>/SKILL.md — \
                    NOT runtime/skills/ or any other location. Use the `sync_skills` tool instead, which handles this automatically. \
                    Attempted path: {}",
                    resolved_path.display()
                ));
            }
        }

        let content = match input.get("content").and_then(|v| v.as_str()) {
            Some(c) => c,
            None => return ToolResult::error("Missing 'content' parameter".into()),
        };

        info!("Writing file: {}", resolved_path.display());

        if let Some(parent) = resolved_path.parent() {
            if let Err(e) = tokio::fs::create_dir_all(parent).await {
                return ToolResult::error(format!("Failed to create directories: {e}"));
            }
        }

        match tokio::fs::write(&resolved_path, content).await {
            Ok(()) => {
                ToolResult::success(format!("Successfully wrote to {}", resolved_path.display()))
            }
            Err(e) => ToolResult::error(format!("Failed to write file: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_write_file_success() {
        let dir = std::env::temp_dir().join(format!("microclaw_wf_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("out.txt");

        let tool = WriteFileTool::new(".");
        let result = tool
            .execute(json!({"path": file.to_str().unwrap(), "content": "hello world"}))
            .await;
        assert!(!result.is_error);
        assert!(result.content.contains("Successfully wrote"));

        let content = std::fs::read_to_string(&file).unwrap();
        assert_eq!(content, "hello world");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_write_file_creates_parent_dirs() {
        let dir = std::env::temp_dir().join(format!("microclaw_wf2_{}", uuid::Uuid::new_v4()));
        let file = dir.join("sub").join("dir").join("file.txt");

        let tool = WriteFileTool::new(".");
        let result = tool
            .execute(json!({"path": file.to_str().unwrap(), "content": "nested"}))
            .await;
        assert!(!result.is_error);
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "nested");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_write_file_missing_params() {
        let tool = WriteFileTool::new(".");

        let result = tool.execute(json!({"content": "hello"})).await;
        assert!(result.is_error);
        assert!(result.content.contains("Missing 'path'"));

        let result = tool.execute(json!({"path": "/tmp/x"})).await;
        assert!(result.is_error);
        assert!(result.content.contains("Missing 'content'"));
    }

    #[tokio::test]
    async fn test_write_file_resolves_relative_to_working_dir() {
        let root = std::env::temp_dir().join(format!("microclaw_wf3_{}", uuid::Uuid::new_v4()));
        let work = root.join("workspace");
        std::fs::create_dir_all(&work).unwrap();

        let tool = WriteFileTool::new(work.to_str().unwrap());
        let result = tool
            .execute(json!({"path": "nested/out.txt", "content": "ok"}))
            .await;
        assert!(!result.is_error);
        assert_eq!(
            std::fs::read_to_string(work.join("shared/nested/out.txt")).unwrap(),
            "ok"
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}
