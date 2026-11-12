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

        let pattern = pattern.to_string();
        let search = tokio::task::spawn_blocking(move || {
            find_matches(&resolved_base, &pattern, include_ignored)
        })
        .await;
        let (mut matches, truncated) = match search {
            Ok(Ok(found)) => found,
            Ok(Err(e)) => return ToolResult::error(format!("Invalid glob pattern: {e}")),
            Err(e) => return ToolResult::error(format!("Glob search failed: {e}")),
        };
        matches.sort();
        matches.dedup();
        let stopped = truncated.then(|| {
            format!(
                "Search stopped after visiting {MAX_LITERAL_ENTRIES} entries; narrow `path` or the pattern."
            )
        });

        if matches.is_empty() {
            let mut text = "No files found matching pattern.".to_string();
            if let Some(note) = stopped {
                text.push(' ');
                text.push_str(&note);
            }
            ToolResult::success(text)
        } else {
            let count = matches.len();
            if count > 500 {
                matches.truncate(500);
                matches.push(format!("... and {} more files", count - 500));
            }
            if let Some(note) = stopped {
                matches.push(note);
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

/// Visible matches first; when nothing visible matches, a literal walk so
/// explicitly targeted hidden or ignored paths (".github/**", "dist/*") and
/// absolute patterns keep working. Returns the path-guard filtered matches
/// and whether the literal walk stopped early.
fn find_matches(
    base: &Path,
    pattern: &str,
    include_ignored: bool,
) -> Result<(Vec<String>, bool), glob::PatternError> {
    if !include_ignored && !pattern.starts_with('/') {
        let found = workspace_matches(base, pattern)?;
        if !found.is_empty() {
            return Ok((
                crate::internal::tool_runtime::path_guard::filter_paths(found),
                false,
            ));
        }
    }
    let (found, truncated) = literal_matches(base, pattern, MAX_LITERAL_ENTRIES)?;
    Ok((
        crate::internal::tool_runtime::path_guard::filter_paths(found),
        truncated,
    ))
}

/// Upper bound on entries (files and directories) one literal walk visits,
/// so a broad pattern over a large tree (`**/x` from a home directory)
/// answers in about a second instead of scanning the disk.
const MAX_LITERAL_ENTRIES: usize = 50_000;

fn has_glob_meta(component: &str) -> bool {
    component.contains(['*', '?', '['])
}

/// Walk from the literal prefix of `pattern` (everything before the first
/// component with a wildcard) and match full paths. Hidden and ignored
/// entries are included; the walk stops after `limit` visited entries.
fn literal_matches(
    base: &Path,
    pattern: &str,
    limit: usize,
) -> Result<(Vec<String>, bool), glob::PatternError> {
    let (mut root, rest) = if pattern.starts_with('/') {
        (PathBuf::from("/"), pattern.trim_start_matches('/'))
    } else {
        (base.to_path_buf(), pattern.trim_start_matches("./"))
    };
    let mut wild: Vec<&str> = Vec::new();
    for component in rest.split('/').filter(|c| !c.is_empty() && *c != ".") {
        if wild.is_empty() && !has_glob_meta(component) {
            root.push(component);
        } else {
            wild.push(component);
        }
    }
    if wild.is_empty() {
        // No wildcard at all: the pattern names one path.
        return Ok((
            if root.exists() {
                vec![root.display().to_string()]
            } else {
                Vec::new()
            },
            false,
        ));
    }
    let compiled = glob::Pattern::new(&format!(
        "{}/{}",
        glob::Pattern::escape(&root.to_string_lossy()).trim_end_matches('/'),
        wild.join("/")
    ))?;
    let options = glob::MatchOptions {
        case_sensitive: true,
        require_literal_separator: true,
        require_literal_leading_dot: false,
    };
    let mut builder = ignore::WalkBuilder::new(&root);
    builder.standard_filters(false).follow_links(false);
    if !wild.contains(&"**") {
        builder.max_depth(Some(wild.len()));
    }
    let mut out = Vec::new();
    let mut visited = 0usize;
    for entry in builder.build().flatten() {
        if entry.depth() == 0 {
            continue;
        }
        visited += 1;
        if visited > limit {
            return Ok((out, true));
        }
        if compiled.matches_path_with(entry.path(), options) {
            out.push(entry.path().display().to_string());
        }
    }
    Ok((out, false))
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

    #[tokio::test]
    async fn literal_fallback_finds_hidden_and_absolute_paths() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join(".github/workflows")).unwrap();
        std::fs::write(root.join(".github/workflows/ci.yml"), "").unwrap();
        std::fs::write(root.join("README.md"), "").unwrap();

        let tool = GlobTool::new(".");
        let hidden = tool
            .execute(json!({"pattern": ".github/workflows/*.yml", "path": root.to_str().unwrap()}))
            .await;
        assert!(hidden.content.contains("ci.yml"), "{}", hidden.content);

        let absolute = format!("{}/**/*.yml", root.display());
        let found = tool.execute(json!({"pattern": absolute})).await;
        assert!(found.content.contains("ci.yml"), "{}", found.content);
        assert!(!found.content.contains("README.md"));

        let exact = tool
            .execute(json!({"pattern": "README.md", "path": root.to_str().unwrap(), "include_ignored": true}))
            .await;
        assert!(exact.content.contains("README.md"), "{}", exact.content);
    }

    #[test]
    fn literal_walk_stops_after_the_entry_limit() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..30 {
            std::fs::create_dir_all(dir.path().join(format!("d{i}/inner"))).unwrap();
        }
        let (found, truncated) = literal_matches(dir.path(), "**/missing*", 20).unwrap();
        assert!(found.is_empty());
        assert!(truncated);
        let (_, truncated) = literal_matches(dir.path(), "**/missing*", 1_000).unwrap();
        assert!(!truncated);
    }
}
