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
    diff_max_lines: usize,
    governance_guard: crate::internal::tool_runtime::path_guard::GovernanceGuard,
    file_state: std::sync::Arc<super::file_state::FileStateTable>,
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
            diff_max_lines: microclaw_core::diff::DEFAULT_DIFF_MAX_LINES,
            governance_guard: Default::default(),
            file_state: Default::default(),
        }
    }

    /// Share the stale-read table with the other file tools of a registry.
    pub fn with_file_state(
        mut self,
        file_state: std::sync::Arc<super::file_state::FileStateTable>,
    ) -> Self {
        self.file_state = file_state;
        self
    }

    pub fn with_diff_max_lines(mut self, max_lines: usize) -> Self {
        self.diff_max_lines = max_lines;
        self
    }

    pub fn with_governance_guard(
        mut self,
        guard: crate::internal::tool_runtime::path_guard::GovernanceGuard,
    ) -> Self {
        self.governance_guard = guard;
        self
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
            description: "Edit a file by replacing a string match with new content. The match must be unique unless replace_all is set. The tool first tries an exact match; if that fails it falls back to whitespace/indentation-flexible, escape-normalized, smart-quote-aware, and block-anchor matching, and tells you which strategy succeeded. To make several changes to one file in a single call, pass `edits` (applied in order, all or nothing) instead of old_string/new_string. Edits are refused when the file changed on disk after you last read it; re-read it first. Prefer paths relative to the current chat working directory; do not invent machine-specific absolute paths unless the user or a tool already provided them.".into(),
            input_schema: schema_object(
                json!({
                    "path": {
                        "type": "string",
                        "description": "The file path to edit, usually relative to the current chat working directory"
                    },
                    "old_string": {
                        "type": "string",
                        "description": "The exact string to find and replace (must be unique in the file unless replace_all is true)"
                    },
                    "new_string": {
                        "type": "string",
                        "description": "The string to replace with"
                    },
                    "replace_all": {
                        "type": "boolean",
                        "description": "Replace every exact occurrence of old_string instead of requiring a unique match (default: false)"
                    },
                    "edits": {
                        "type": "array",
                        "description": "Several replacements applied in order to the same file; all must succeed or the file is left unchanged",
                        "items": {
                            "type": "object",
                            "properties": {
                                "old_string": {"type": "string"},
                                "new_string": {"type": "string"},
                                "replace_all": {"type": "boolean"}
                            },
                            "required": ["old_string", "new_string"]
                        }
                    }
                }),
                &["path"],
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

        if let Err(msg) = crate::internal::tool_runtime::path_guard::check_path(&resolved_path_str)
        {
            return ToolResult::error(msg);
        }
        if let Err(msg) = self.governance_guard.check_write(&resolved_path) {
            return ToolResult::error(msg);
        }

        let edits = match parse_edits(&input) {
            Ok(edits) => edits,
            Err(msg) => return ToolResult::error(msg),
        };

        info!("Editing file: {}", resolved_path.display());

        let content = match tokio::fs::read_to_string(&resolved_path).await {
            Ok(c) => c,
            Err(e) => return ToolResult::error(format!("Failed to read file: {e}")),
        };
        if let Err(msg) = self
            .file_state
            .check_fresh(&resolved_path, content.as_bytes())
        {
            return ToolResult::error(msg).with_error_type("stale_read");
        }

        let multi = edits.len() > 1;
        let mut new_content = content.clone();
        let mut notes = Vec::new();
        for (index, edit) in edits.iter().enumerate() {
            let label = if multi {
                format!("edit {}: ", index + 1)
            } else {
                String::new()
            };
            match apply_edit(&new_content, edit) {
                Ok((updated, note)) => {
                    new_content = updated;
                    if let Some(note) = note {
                        notes.push(format!("{label}{note}"));
                    }
                }
                Err(msg) => {
                    let unchanged = if multi { " No edits were applied." } else { "" };
                    return ToolResult::error(format!("{label}{msg}{unchanged}"));
                }
            }
        }

        match tokio::fs::write(&resolved_path, &new_content).await {
            Ok(()) => {
                self.file_state
                    .record(&resolved_path, new_content.as_bytes());
                let suffix = if notes.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", notes.join("; "))
                };
                let count = if multi {
                    format!(" with {} edits", edits.len())
                } else {
                    String::new()
                };
                let diff =
                    microclaw_core::diff::unified_diff(&content, &new_content, self.diff_max_lines);
                let mut result = ToolResult::success(match &diff {
                    Some(d) => format!(
                        "Successfully edited {}{} ({}){}",
                        resolved_path.display(),
                        count,
                        d.stats(),
                        suffix
                    ),
                    None => format!(
                        "Successfully edited {}{}{}",
                        resolved_path.display(),
                        count,
                        suffix
                    ),
                });
                if let Some(d) = diff {
                    result =
                        result.with_metadata(microclaw_core::diff::file_diff_metadata(path, &d));
                }
                result
            }
            Err(e) => ToolResult::error(format!("Failed to write file: {e}")),
        }
    }
}

struct Edit {
    old_string: String,
    new_string: String,
    replace_all: bool,
}

fn parse_edit(value: &serde_json::Value, context: &str) -> Result<Edit, String> {
    let old_string = value
        .get("old_string")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("Missing 'old_string' parameter{context}"))?;
    let new_string = value
        .get("new_string")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("Missing 'new_string' parameter{context}"))?;
    Ok(Edit {
        old_string: old_string.to_string(),
        new_string: new_string.to_string(),
        replace_all: value
            .get("replace_all")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
    })
}

fn parse_edits(input: &serde_json::Value) -> Result<Vec<Edit>, String> {
    match input.get("edits") {
        Some(serde_json::Value::Array(items)) => {
            if input.get("old_string").is_some() {
                return Err("Pass either 'edits' or 'old_string'/'new_string', not both".into());
            }
            if items.is_empty() {
                return Err("'edits' must contain at least one edit".into());
            }
            items
                .iter()
                .enumerate()
                .map(|(i, item)| parse_edit(item, &format!(" in edits[{i}]")))
                .collect()
        }
        Some(_) => Err("'edits' must be an array of {old_string, new_string} objects".into()),
        None => parse_edit(input, " (or provide 'edits')").map(|edit| vec![edit]),
    }
}

/// Apply one edit, returning the new content and an optional note about how
/// the match was made.
fn apply_edit(content: &str, edit: &Edit) -> Result<(String, Option<String>), String> {
    if edit.replace_all {
        if edit.old_string.is_empty() {
            return Err("old_string cannot be empty".into());
        }
        if edit.old_string == edit.new_string {
            return Err("old_string and new_string are identical".into());
        }
        let count = content.matches(edit.old_string.as_str()).count();
        if count == 0 {
            return Err(
                "Could not find a match for old_string (replace_all requires an exact match)"
                    .into(),
            );
        }
        let note = format!(
            "replaced {count} occurrence{}",
            if count == 1 { "" } else { "s" }
        );
        return Ok((
            content.replace(edit.old_string.as_str(), &edit.new_string),
            Some(note),
        ));
    }
    let fm =
        super::fuzzy_match::fuzzy_find_and_replace(content, &edit.old_string, &edit.new_string)?;
    let note = (fm.strategy != "exact").then(|| {
        format!(
            "matched via `{}` strategy — re-read the file if you want to confirm the byte-exact form",
            fm.strategy
        )
    });
    Ok((fm.new_content, note))
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

    #[tokio::test]
    async fn test_edit_file_replace_all() {
        let (dir, file) = setup_file("aaa bbb aaa");
        let tool = EditFileTool::new(".");
        let result = tool
            .execute(json!({
                "path": file.to_str().unwrap(),
                "old_string": "aaa",
                "new_string": "ccc",
                "replace_all": true
            }))
            .await;
        assert!(!result.is_error, "{}", result.content);
        assert!(result.content.contains("replaced 2 occurrences"));
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "ccc bbb ccc");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_edit_file_multi_edit_is_all_or_nothing() {
        let (dir, file) = setup_file("one two three");
        let tool = EditFileTool::new(".");
        let failed = tool
            .execute(json!({
                "path": file.to_str().unwrap(),
                "edits": [
                    {"old_string": "one", "new_string": "1"},
                    {"old_string": "missing words here", "new_string": "x"}
                ]
            }))
            .await;
        assert!(failed.is_error);
        assert!(failed.content.contains("edit 2"));
        assert!(failed.content.contains("No edits were applied"));
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "one two three");

        let ok = tool
            .execute(json!({
                "path": file.to_str().unwrap(),
                "edits": [
                    {"old_string": "one", "new_string": "1"},
                    {"old_string": "three", "new_string": "3"}
                ]
            }))
            .await;
        assert!(!ok.is_error, "{}", ok.content);
        assert!(ok.content.contains("with 2 edits"));
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "1 two 3");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_edit_file_refuses_stale_read() {
        let (dir, file) = setup_file("original");
        let table = std::sync::Arc::new(super::super::file_state::FileStateTable::default());
        let read = super::super::read_file::ReadFileTool::new(".").with_file_state(table.clone());
        let _ = read.execute(json!({"path": file.to_str().unwrap()})).await;
        std::fs::write(&file, "changed by the user").unwrap();

        let tool = EditFileTool::new(".").with_file_state(table);
        let result = tool
            .execute(json!({
                "path": file.to_str().unwrap(),
                "old_string": "changed",
                "new_string": "edited"
            }))
            .await;
        assert!(result.is_error);
        assert_eq!(result.error_type.as_deref(), Some("stale_read"));
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            "changed by the user"
        );

        let _ = read.execute(json!({"path": file.to_str().unwrap()})).await;
        let retry = tool
            .execute(json!({
                "path": file.to_str().unwrap(),
                "old_string": "changed",
                "new_string": "edited"
            }))
            .await;
        assert!(!retry.is_error, "{}", retry.content);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
