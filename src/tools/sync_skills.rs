use async_trait::async_trait;
use chrono::Utc;
use serde_json::json;

use crate::claude::ToolDefinition;

use super::{schema_object, Tool, ToolResult};

pub struct SyncSkillsTool {
    skills_dir: std::path::PathBuf,
}

impl SyncSkillsTool {
    pub fn new(skills_dir: &str) -> Self {
        Self {
            skills_dir: std::path::PathBuf::from(skills_dir),
        }
    }

    async fn fetch_skill_content(
        source_repo: &str,
        skill_name: &str,
        git_ref: &str,
    ) -> Result<String, String> {
        let candidates = [
            format!(
                "https://raw.githubusercontent.com/{}/{}/skills/{}/SKILL.md",
                source_repo, git_ref, skill_name
            ),
            format!(
                "https://raw.githubusercontent.com/{}/{}/{}/SKILL.md",
                source_repo, git_ref, skill_name
            ),
            format!(
                "https://raw.githubusercontent.com/{}/{}/{}.md",
                source_repo, git_ref, skill_name
            ),
        ];

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .build()
            .map_err(|e| e.to_string())?;

        let mut errors = Vec::new();
        for url in candidates {
            match client
                .get(&url)
                .header("User-Agent", "MicroClaw/1.0")
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    let text = resp.text().await.map_err(|e| e.to_string())?;
                    if !text.trim().is_empty() {
                        return Ok(text);
                    }
                }
                Ok(resp) => errors.push(format!("{} -> HTTP {}", url, resp.status())),
                Err(e) => errors.push(format!("{} -> {}", url, e)),
            }
        }

        Err(format!(
            "Failed to fetch skill '{skill_name}' from {source_repo}@{git_ref}. Tried URLs:\n{}",
            errors.join("\n")
        ))
    }

    fn split_frontmatter(content: &str) -> (Option<serde_yaml::Value>, String) {
        let trimmed = content.trim_start_matches('\u{feff}');
        if !trimmed.starts_with("---\n") && !trimmed.starts_with("---\r\n") {
            return (None, trimmed.to_string());
        }

        let mut lines = trimmed.lines();
        let _ = lines.next(); // opening ---
        let mut yaml_block = String::new();
        let mut consumed = 0usize;
        for line in lines {
            consumed += line.len() + 1;
            if line.trim() == "---" || line.trim() == "..." {
                break;
            }
            yaml_block.push_str(line);
            yaml_block.push('\n');
        }

        let header_len = if let Some(idx) = trimmed.find("\n---\n") {
            idx + 5
        } else if let Some(idx) = trimmed.find("\n...\n") {
            idx + 5
        } else {
            4 + consumed
        };

        let body = trimmed
            .get(header_len..)
            .unwrap_or_default()
            .trim()
            .to_string();

        if yaml_block.trim().is_empty() {
            (None, body)
        } else {
            (
                serde_yaml::from_str::<serde_yaml::Value>(&yaml_block).ok(),
                body,
            )
        }
    }

    fn str_seq(value: Option<&serde_yaml::Value>) -> Vec<String> {
        match value {
            Some(serde_yaml::Value::Sequence(items)) => items
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.trim().to_string()))
                .filter(|s| !s.is_empty())
                .collect(),
            _ => Vec::new(),
        }
    }

    fn normalize_skill_markdown(
        raw: &str,
        source_repo: &str,
        git_ref: &str,
        skill_name: &str,
        target_name: &str,
    ) -> String {
        let (fm, body) = Self::split_frontmatter(raw);
        let fm = fm.unwrap_or(serde_yaml::Value::Null);

        let get = |k: &str| fm.get(k).and_then(|v| v.as_str()).unwrap_or("");

        let description = if !get("description").trim().is_empty() {
            get("description").trim().to_string()
        } else {
            format!("Synced from {source_repo} skill '{skill_name}' and adapted for MicroClaw.")
        };

        let mut platforms = Self::str_seq(fm.get("platforms"));
        if platforms.is_empty() {
            platforms = Self::str_seq(fm.get("compatibility").and_then(|c| c.get("os")));
        }

        let mut deps = Self::str_seq(fm.get("deps"));
        if deps.is_empty() {
            deps = Self::str_seq(fm.get("compatibility").and_then(|c| c.get("deps")));
        }

        let mut frontmatter = vec![
            "---".to_string(),
            format!("name: {}", target_name),
            format!("description: {}", description),
            format!("source: remote:{}", source_repo),
            format!("version: {}", git_ref),
            format!("updated_at: {}", Utc::now().to_rfc3339()),
            "license: Proprietary. LICENSE.txt has complete terms".to_string(),
        ];

        if !platforms.is_empty() {
            frontmatter.push("platforms:".to_string());
            for p in platforms {
                frontmatter.push(format!("  - {}", p));
            }
        }
        if !deps.is_empty() {
            frontmatter.push("deps:".to_string());
            for d in deps {
                frontmatter.push(format!("  - {}", d));
            }
        }

        frontmatter.push("---".to_string());
        frontmatter.push(String::new());
        if body.is_empty() {
            frontmatter.push(format!(
                "# {}\n\nSynced from `{}` (`{}`).",
                target_name, source_repo, git_ref
            ));
        } else {
            frontmatter.push(body);
        }

        frontmatter.join("\n")
    }
}

#[async_trait]
impl Tool for SyncSkillsTool {
    fn name(&self) -> &str {
        "sync_skills"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "sync_skills".into(),
            description: "Sync a skill from an external repository (default: vercel-labs/skills) into the local skills directory and normalize frontmatter (source/version/updated_at/platforms/deps).".into(),
            input_schema: schema_object(
                json!({
                    "skill_name": {
                        "type": "string",
                        "description": "Upstream skill name/path to sync"
                    },
                    "target_name": {
                        "type": "string",
                        "description": "Optional local skill directory/name (defaults to skill_name)"
                    },
                    "source_repo": {
                        "type": "string",
                        "description": "GitHub repo in owner/name format (default: vercel-labs/skills)"
                    },
                    "git_ref": {
                        "type": "string",
                        "description": "Branch/tag/commit (default: main)"
                    }
                }),
                &["skill_name"],
            ),
        }
    }

    async fn execute(&self, input: serde_json::Value) -> ToolResult {
        let skill_name = match input.get("skill_name").and_then(|v| v.as_str()) {
            Some(v) if !v.trim().is_empty() => v.trim(),
            _ => return ToolResult::error("Missing required parameter: skill_name".into()),
        };

        let source_repo = input
            .get("source_repo")
            .and_then(|v| v.as_str())
            .filter(|v| !v.trim().is_empty())
            .unwrap_or("vercel-labs/skills")
            .trim();

        let git_ref = input
            .get("git_ref")
            .and_then(|v| v.as_str())
            .filter(|v| !v.trim().is_empty())
            .unwrap_or("main")
            .trim();

        let target_name = input
            .get("target_name")
            .and_then(|v| v.as_str())
            .filter(|v| !v.trim().is_empty())
            .unwrap_or(skill_name)
            .trim();

        let raw = match Self::fetch_skill_content(source_repo, skill_name, git_ref).await {
            Ok(v) => v,
            Err(e) => return ToolResult::error(e).with_error_type("sync_fetch_failed"),
        };

        let normalized =
            Self::normalize_skill_markdown(&raw, source_repo, git_ref, skill_name, target_name);

        let out_dir = self.skills_dir.join(target_name);
        if let Err(e) = std::fs::create_dir_all(&out_dir) {
            return ToolResult::error(format!("Failed to create skill directory: {e}"))
                .with_error_type("sync_write_failed");
        }

        let out_file = out_dir.join("SKILL.md");
        if let Err(e) = std::fs::write(&out_file, normalized) {
            return ToolResult::error(format!("Failed to write SKILL.md: {e}"))
                .with_error_type("sync_write_failed");
        }

        ToolResult::success(format!(
            "Skill synced: {} -> {}\nSource: {}@{}\nPath: {}",
            skill_name,
            target_name,
            source_repo,
            git_ref,
            out_file.display()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_sync_skills_definition() {
        let tool = SyncSkillsTool::new("/tmp/skills");
        assert_eq!(tool.name(), "sync_skills");
        let def = tool.definition();
        assert_eq!(def.name, "sync_skills");
        assert!(def.input_schema["properties"]["skill_name"].is_object());
    }

    #[tokio::test]
    async fn test_sync_skills_missing_name() {
        let tool = SyncSkillsTool::new("/tmp/skills");
        let result = tool.execute(json!({})).await;
        assert!(result.is_error);
        assert!(result.content.contains("skill_name"));
    }

    #[test]
    fn test_normalize_skill_markdown_adds_source_fields() {
        let raw = "# Demo\n\nBody";
        let out = SyncSkillsTool::normalize_skill_markdown(
            raw,
            "vercel-labs/skills",
            "main",
            "demo",
            "demo",
        );
        assert!(out.contains("source: remote:vercel-labs/skills"));
        assert!(out.contains("version: main"));
        assert!(out.contains("updated_at:"));
    }
}
