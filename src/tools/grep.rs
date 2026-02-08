use async_trait::async_trait;
use serde_json::json;
use tracing::info;

use crate::claude::ToolDefinition;

use super::{schema_object, Tool, ToolResult};

pub struct GrepTool;

#[async_trait]
impl Tool for GrepTool {
    fn name(&self) -> &str {
        "grep"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "grep".into(),
            description: "Search file contents using a regex pattern. Returns matching lines with file paths and line numbers.".into(),
            input_schema: schema_object(
                json!({
                    "pattern": {
                        "type": "string",
                        "description": "Regex pattern to search for"
                    },
                    "path": {
                        "type": "string",
                        "description": "File or directory to search in (default: current directory)"
                    },
                    "glob": {
                        "type": "string",
                        "description": "Glob pattern to filter files (e.g., '*.rs')"
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
        let path = input.get("path").and_then(|v| v.as_str()).unwrap_or(".");
        let file_glob = input.get("glob").and_then(|v| v.as_str());

        info!("Grep: {} in {}", pattern, path);

        let re = match regex::Regex::new(pattern) {
            Ok(r) => r,
            Err(e) => return ToolResult::error(format!("Invalid regex: {e}")),
        };

        let mut results = Vec::new();
        let mut file_count = 0;

        if let Err(e) = grep_recursive(path, file_glob, &re, &mut results, &mut file_count) {
            return ToolResult::error(format!("Search error: {e}"));
        }

        if results.is_empty() {
            ToolResult::success("No matches found.".into())
        } else {
            if results.len() > 500 {
                results.truncate(500);
                results.push("... (results truncated)".into());
            }
            ToolResult::success(results.join("\n"))
        }
    }
}

fn grep_recursive(
    path: &str,
    file_glob: Option<&str>,
    re: &regex::Regex,
    results: &mut Vec<String>,
    file_count: &mut usize,
) -> std::io::Result<()> {
    let metadata = std::fs::metadata(path)?;

    if metadata.is_file() {
        grep_file(path, re, results)?;
    } else if metadata.is_dir() {
        let glob_pattern = file_glob.and_then(|g| glob::Pattern::new(g).ok());

        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let entry_path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();

            // Skip hidden directories and common non-code dirs
            if name.starts_with('.') || name == "node_modules" || name == "target" {
                continue;
            }

            if entry_path.is_dir() {
                grep_recursive(
                    &entry_path.display().to_string(),
                    file_glob,
                    re,
                    results,
                    file_count,
                )?;
            } else if entry_path.is_file() {
                if crate::tools::path_guard::is_blocked(&entry_path) {
                    continue;
                }
                if let Some(ref pat) = glob_pattern {
                    if !pat.matches(&name) {
                        continue;
                    }
                }
                *file_count += 1;
                if *file_count > 10000 {
                    return Ok(());
                }
                grep_file(&entry_path.display().to_string(), re, results)?;
            }
        }
    }
    Ok(())
}

fn grep_file(path: &str, re: &regex::Regex, results: &mut Vec<String>) -> std::io::Result<()> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Ok(()), // Skip binary / unreadable files
    };

    for (line_num, line) in content.lines().enumerate() {
        if re.is_match(line) {
            results.push(format!("{}:{}: {}", path, line_num + 1, line));
            if results.len() >= 500 {
                return Ok(());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn setup_grep_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("microclaw_grep_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("hello.rs"),
            "fn main() {\n    println!(\"hello\");\n}\n",
        )
        .unwrap();
        std::fs::write(dir.join("world.txt"), "hello world\ngoodbye world\n").unwrap();
        dir
    }

    #[tokio::test]
    async fn test_grep_finds_matches() {
        let dir = setup_grep_dir();
        let tool = GrepTool;
        let result = tool
            .execute(json!({"pattern": "hello", "path": dir.to_str().unwrap()}))
            .await;
        assert!(!result.is_error);
        assert!(result.content.contains("hello"));
        // Should have file:line format
        assert!(result.content.contains(":"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_grep_no_matches() {
        let dir = setup_grep_dir();
        let tool = GrepTool;
        let result = tool
            .execute(json!({"pattern": "zzzzzzz", "path": dir.to_str().unwrap()}))
            .await;
        assert!(!result.is_error);
        assert!(result.content.contains("No matches"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_grep_with_file_glob() {
        let dir = setup_grep_dir();
        let tool = GrepTool;
        // Only search .txt files
        let result = tool
            .execute(json!({
                "pattern": "hello",
                "path": dir.to_str().unwrap(),
                "glob": "*.txt"
            }))
            .await;
        assert!(!result.is_error);
        assert!(result.content.contains("world.txt"));
        // Should NOT match the .rs file
        assert!(!result.content.contains("hello.rs"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_grep_invalid_regex() {
        let tool = GrepTool;
        let result = tool
            .execute(json!({"pattern": "[invalid", "path": "."}))
            .await;
        assert!(result.is_error);
        assert!(result.content.contains("Invalid regex"));
    }

    #[tokio::test]
    async fn test_grep_missing_pattern() {
        let tool = GrepTool;
        let result = tool.execute(json!({})).await;
        assert!(result.is_error);
        assert!(result.content.contains("Missing 'pattern'"));
    }

    #[test]
    fn test_grep_file_function() {
        let dir = std::env::temp_dir().join(format!("microclaw_gf_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("test.txt");
        std::fs::write(&file, "foo bar\nbaz qux\nfoo again\n").unwrap();

        let re = regex::Regex::new("foo").unwrap();
        let mut results = Vec::new();
        grep_file(file.to_str().unwrap(), &re, &mut results).unwrap();
        assert_eq!(results.len(), 2);
        assert!(results[0].contains(":1:"));
        assert!(results[1].contains(":3:"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_grep_recursive_skips_hidden_dirs() {
        let dir = std::env::temp_dir().join(format!("microclaw_gr_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(dir.join(".hidden")).unwrap();
        std::fs::write(dir.join(".hidden").join("secret.txt"), "match_me").unwrap();
        std::fs::write(dir.join("visible.txt"), "match_me").unwrap();

        let re = regex::Regex::new("match_me").unwrap();
        let mut results = Vec::new();
        let mut count = 0;
        grep_recursive(dir.to_str().unwrap(), None, &re, &mut results, &mut count).unwrap();

        // Should only find in visible.txt
        assert_eq!(results.len(), 1);
        assert!(results[0].contains("visible.txt"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
