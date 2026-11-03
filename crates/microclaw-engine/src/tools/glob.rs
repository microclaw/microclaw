use async_trait::async_trait;
use serde_json::json;
use std::path::{Path, PathBuf};
use tracing::info;

use crate::config::WorkingDirIsolation;
use microclaw_core::llm_types::ToolDefinition;

use super::{schema_object, Tool, ToolResult};

pub struct GlobTool {
    working_dir: PathBuf,
    working_dir_isolation: WorkingDirIsolation,
}

impl GlobTool {
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
impl Tool for GlobTool {
    fn name(&self) -> &str {
        "glob"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "glob".into(),
            description: "Find files matching a glob pattern. Returns matching file paths. Relative patterns respect .gitignore/.ignore files and skip hidden, node_modules and target directories; set include_ignored (or target a hidden/ignored path explicitly) to match everything.".into(),
            input_schema: schema_object(
                json!({
                    "pattern": {
                        "type": "string",
                        "description": "The glob pattern to match (e.g., '**/*.rs', 'src/**/*.ts')"
                    },
                    "path": {
                        "type": "string",
                        "description": "Base directory to search from (default: current directory)"
                    },
                    "include_ignored": {
                        "type": "boolean",
                        "description": "Also match hidden files and files excluded by .gitignore/.ignore (default: false)"
                    }
                }),
                &["pattern"],
            ),
        }
    }

    async fn execute(&self, input: serde_json::Value) -> ToolResult {
        let pattern = match input.get("pattern").and_then(|v| v.as_str()) {
            Some(p) => p,
            None => return ToolResult::error("Missing 'pattern' parameter".into()),
        };
        let base = input.get("path").and_then(|v| v.as_str()).unwrap_or(".");
        let working_dir =
            super::resolve_tool_working_dir(&self.working_dir, self.working_dir_isolation, &input);
        let resolved_base = super::resolve_tool_path(&working_dir, base);
        let resolved_base_str = resolved_base.to_string_lossy().to_string();

        if let Err(msg) = crate::internal::tool_runtime::path_guard::check_path(&resolved_base_str)
        {
            return ToolResult::error(msg);
        }

        info!("Glob: {} in {}", pattern, resolved_base.display());

        let include_ignored = input
            .get("include_ignored")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let mut matches = if include_ignored || pattern.starts_with('/') {
            None
        } else {
            match workspace_matches(&resolved_base, pattern) {
                Ok(found) => Some(found),
                Err(e) => return ToolResult::error(format!("Invalid glob pattern: {e}")),
            }
        };
        // Nothing visible matched: fall back to a literal filesystem glob so
        // explicitly targeted hidden or ignored paths (".github/**", "dist/*")
        // keep working.
        if matches.as_ref().is_none_or(|found| found.is_empty()) {
            matches = match literal_matches(&resolved_base, pattern) {
                Ok(found) => Some(found),
                Err(e) => return ToolResult::error(format!("Invalid glob pattern: {e}")),
            };
        }
        let mut matches =
            crate::internal::tool_runtime::path_guard::filter_paths(matches.unwrap_or_default());
        matches.sort();
        matches.dedup();

        if matches.is_empty() {
            ToolResult::success("No files found matching pattern.".into())
        } else {
            let count = matches.len();
            if count > 500 {
                matches.truncate(500);
                matches.push(format!("... and {} more files", count - 500));
            }
            ToolResult::success(matches.join("\n"))
        }
    }
}

fn workspace_matches(base: &Path, pattern: &str) -> Result<Vec<String>, glob::PatternError> {
    let compiled = glob::Pattern::new(pattern)?;
    let options = glob::MatchOptions {
        case_sensitive: true,
        require_literal_separator: true,
        require_literal_leading_dot: false,
    };
    let walk_options = super::workspace_walk::WalkOptions {
        include_ignored: false,
        include_dirs: true,
    };
    Ok(super::workspace_walk::walk(base, walk_options)
        .into_iter()
        .filter(|path| {
            path.strip_prefix(base)
                .map(|relative| compiled.matches_path_with(relative, options))
                .unwrap_or(false)
        })
        .map(|path| path.display().to_string())
        .collect())
}

fn literal_matches(base: &Path, pattern: &str) -> Result<Vec<String>, glob::PatternError> {
    let full_pattern = if pattern.starts_with('/') {
        pattern.to_string()
    } else {
        format!("{}/{}", base.display(), pattern)
    };
    Ok(glob::glob(&full_pattern)?
        .filter_map(|p| p.ok())
        .map(|p| p.display().to_string())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_glob_finds_files() {
        let dir = std::env::temp_dir().join(format!("microclaw_glob_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), "").unwrap();
        std::fs::write(dir.join("b.txt"), "").unwrap();
        std::fs::write(dir.join("c.rs"), "").unwrap();

        let tool = GlobTool::new(".");
        let result = tool
            .execute(json!({"pattern": "*.txt", "path": dir.to_str().unwrap()}))
            .await;
        assert!(!result.is_error);
        assert!(result.content.contains("a.txt"));
        assert!(result.content.contains("b.txt"));
        assert!(!result.content.contains("c.rs"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_glob_no_matches() {
        let dir = std::env::temp_dir().join(format!("microclaw_glob2_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();

        let tool = GlobTool::new(".");
        let result = tool
            .execute(json!({"pattern": "*.xyz", "path": dir.to_str().unwrap()}))
            .await;
        assert!(!result.is_error);
        assert!(result.content.contains("No files found"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_glob_missing_pattern() {
        let tool = GlobTool::new(".");
        let result = tool.execute(json!({})).await;
        assert!(result.is_error);
        assert!(result.content.contains("Missing 'pattern'"));
    }

    #[tokio::test]
    async fn test_glob_defaults_to_working_dir() {
        let root = std::env::temp_dir().join(format!("microclaw_glob3_{}", uuid::Uuid::new_v4()));
        let work = root.join("workspace");
        let shared = work.join("shared");
        std::fs::create_dir_all(&shared).unwrap();
        std::fs::write(shared.join("x.txt"), "").unwrap();

        let tool = GlobTool::new(work.to_str().unwrap());
        let result = tool.execute(json!({"pattern":"*.txt"})).await;
        assert!(!result.is_error);
        assert!(result.content.contains("x.txt"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn test_glob_respects_gitignore_with_literal_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join(".gitignore"), "dist/\n").unwrap();
        std::fs::create_dir_all(root.join("dist")).unwrap();
        std::fs::create_dir_all(root.join("src/nested")).unwrap();
        std::fs::write(root.join("dist/app.js"), "").unwrap();
        std::fs::write(root.join("src/main.js"), "").unwrap();
        std::fs::write(root.join("src/nested/util.js"), "").unwrap();

        let tool = GlobTool::new(".");
        let result = tool
            .execute(json!({"pattern": "**/*.js", "path": root.to_str().unwrap()}))
            .await;
        assert!(result.content.contains("main.js"));
        assert!(result.content.contains("util.js"));
        assert!(!result.content.contains("app.js"));

        let top_level = tool
            .execute(json!({"pattern": "*.js", "path": root.join("src").to_str().unwrap()}))
            .await;
        assert!(top_level.content.contains("main.js"));
        assert!(!top_level.content.contains("util.js"));

        let explicit = tool
            .execute(json!({"pattern": "dist/*.js", "path": root.to_str().unwrap()}))
            .await;
        assert!(explicit.content.contains("app.js"));
    }
}
