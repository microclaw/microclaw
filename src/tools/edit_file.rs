use async_trait::async_trait;
use serde_json::json;
use std::path::PathBuf;
use tracing::info;

use crate::config::WorkingDirIsolation;
use microclaw_core::llm_types::ToolDefinition;

use super::{schema_object, Tool, ToolResult};

pub struct EditFileTool {
    working_dir: PathBuf,
    working_dir_isolation: WorkingDirIsolation,
}

impl EditFileTool {
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
impl Tool for EditFileTool {
    fn name(&self) -> &str {
        "edit_file"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "edit_file".into(),
            description: "Edit a file by replacing a string match with new content. The match must be unique. The tool first tries an exact match; if that fails it falls back to whitespace/indentation-flexible, escape-normalized, smart-quote-aware, and block-anchor matching, and tells you which strategy succeeded. Prefer paths relative to the current chat working directory; do not invent machine-specific absolute paths unless the user or a tool already provided them.".into(),
            input_schema: schema_object(
                json!({
                    "path": {
                        "type": "string",
                        "description": "The file path to edit, usually relative to the current chat working directory"
                    },
                    "old_string": {
                        "type": "string",
                        "description": "The exact string to find and replace (must be unique in the file)"
                    },
                    "new_string": {
                        "type": "string",
                        "description": "The string to replace with"
                    }
                }),
                &["path", "old_string", "new_string"],
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

        if let Err(msg) = microclaw_tools::path_guard::check_path(&resolved_path_str) {
            return ToolResult::error(msg);
        }

        let old_string = match input.get("old_string").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return ToolResult::error("Missing 'old_string' parameter".into()),
        };
        let new_string = match input.get("new_string").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return ToolResult::error("Missing 'new_string' parameter".into()),
        };

        info!("Editing file: {}", resolved_path.display());

        let content = match tokio::fs::read_to_string(&resolved_path).await {
            Ok(c) => c,
            Err(e) => return ToolResult::error(format!("Failed to read file: {e}")),
        };

        let fm = match super::fuzzy_match::fuzzy_find_and_replace(&content, old_string, new_string)
        {
            Ok(fm) => fm,
            Err(msg) => return ToolResult::error(msg),
        };

        match tokio::fs::write(&resolved_path, &fm.new_content).await {
            Ok(()) => {
                let suffix = if fm.strategy == "exact" {
                    String::new()
                } else {
                    format!(" (matched via `{}` strategy — re-read the file if you want to confirm the byte-exact form)", fm.strategy)
                };
                ToolResult::success(format!(
                    "Successfully edited {}{}",
                    resolved_path.display(),
                    suffix
                ))
            }
            Err(e) => ToolResult::error(format!("Failed to write file: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_edit_file_definition_prefers_relative_paths() {
        let tool = EditFileTool::new(".");
        let def = tool.definition();
        assert!(def
            .description
            .contains("Prefer paths relative to the current chat working directory"));
        assert_eq!(
            def.input_schema["properties"]["path"]["description"].as_str(),
            Some("The file path to edit, usually relative to the current chat working directory")
        );
    }

    fn setup_file(content: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("microclaw_ef_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("edit_me.txt");
        std::fs::write(&file, content).unwrap();
        (dir, file)
    }

    #[tokio::test]
    async fn test_edit_file_success() {
        let (dir, file) = setup_file("hello world");
        let tool = EditFileTool::new(".");
        let result = tool
            .execute(json!({
                "path": file.to_str().unwrap(),
                "old_string": "world",
                "new_string": "rust"
            }))
            .await;
        assert!(!result.is_error);
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "hello rust");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_edit_file_not_found() {
        let tool = EditFileTool::new(".");
        let result = tool
            .execute(json!({
                "path": "/nonexistent/file.txt",
                "old_string": "a",
                "new_string": "b"
            }))
            .await;
        assert!(result.is_error);
        assert!(result.content.contains("Failed to read file"));
    }

    #[tokio::test]
    async fn test_edit_file_old_string_not_found() {
        let (dir, file) = setup_file("hello world");
        let tool = EditFileTool::new(".");
        let result = tool
            .execute(json!({
                "path": file.to_str().unwrap(),
                "old_string": "completely different content xyz",
                "new_string": "abc"
            }))
            .await;
        assert!(result.is_error);
        assert!(result.content.contains("Could not find a match"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_edit_file_multiple_matches() {
        let (dir, file) = setup_file("aaa bbb aaa");
        let tool = EditFileTool::new(".");
        let result = tool
            .execute(json!({
                "path": file.to_str().unwrap(),
                "old_string": "aaa",
                "new_string": "ccc"
            }))
            .await;
        assert!(result.is_error);
        assert!(result.content.contains("2 matches"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_edit_file_fuzzy_indentation() {
        // File has 4-space indent; LLM provided 0-space indent.
        let (dir, file) = setup_file("    let x = 1;\n    let y = 2;\n");
        let tool = EditFileTool::new(".");
        let result = tool
            .execute(json!({
                "path": file.to_str().unwrap(),
                "old_string": "let x = 1;\nlet y = 2;",
                "new_string": "let x = 1;\nlet y = 99;"
            }))
            .await;
        assert!(!result.is_error, "got error: {}", result.content);
        // Either line_trimmed or indentation_flexible can win; both fix the issue.
        assert!(
            result.content.contains("line_trimmed")
                || result.content.contains("indentation_flexible"),
            "expected fuzzy strategy hint, got: {}",
            result.content
        );
        let after = std::fs::read_to_string(&file).unwrap();
        assert!(after.contains("let y = 99"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_edit_file_missing_params() {
        let tool = EditFileTool::new(".");
        let result = tool.execute(json!({})).await;
        assert!(result.is_error);
        assert!(result.content.contains("Missing 'path'"));

        let result = tool.execute(json!({"path": "/tmp/x"})).await;
        assert!(result.is_error);
        assert!(result.content.contains("Missing 'old_string'"));
    }

    #[tokio::test]
    async fn test_edit_file_resolves_relative_to_working_dir() {
        let root = std::env::temp_dir().join(format!("microclaw_ef2_{}", uuid::Uuid::new_v4()));
        let work = root.join("workspace");
        let shared = work.join("shared");
        std::fs::create_dir_all(&shared).unwrap();
        let file = shared.join("edit_me.txt");
        std::fs::write(&file, "aaa bbb").unwrap();

        let tool = EditFileTool::new(work.to_str().unwrap());
        let result = tool
            .execute(json!({
                "path": "edit_me.txt",
                "old_string": "bbb",
                "new_string": "ccc"
            }))
            .await;
        assert!(!result.is_error);
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "aaa ccc");

        let _ = std::fs::remove_dir_all(&root);
    }
}
