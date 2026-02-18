use async_trait::async_trait;
use chrono::Utc;
use serde_json::json;

use crate::llm_types::ToolDefinition;

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

    /// Parse a skill reference that may contain a full GitHub URL or owner/repo/skill path.
    /// Returns (source_repo, skill_name, git_ref_override).
    fn parse_skill_reference(raw: &str) -> Option<(String, String, Option<String>)> {
        let raw = raw.trim();

        // Handle full GitHub URLs:
        // https://github.com/owner/repo/tree/branch/skills/skill-name
        // https://github.com/owner/repo/tree/branch/skill-name
        if let Some(rest) = raw
            .strip_prefix("https://github.com/")
            .or_else(|| raw.strip_prefix("http://github.com/"))
        {
            let parts: Vec<&str> = rest.splitn(5, '/').collect();
            if parts.len() >= 4 && parts[2] == "tree" {
                let repo = format!("{}/{}", parts[0], parts[1]);
                let branch = parts[3].to_string();
                let skill_path = parts.get(4).unwrap_or(&"").to_string();
                // Strip leading "skills/" prefix if present
                let skill = skill_path
                    .strip_prefix("skills/")
                    .unwrap_or(&skill_path)
                    .trim_end_matches('/')
                    .to_string();
                if !skill.is_empty() {
                    return Some((repo, skill, Some(branch)));
                }
            }
        }

        // Handle raw.githubusercontent.com URLs
        if let Some(rest) = raw.strip_prefix("https://raw.githubusercontent.com/") {
            let parts: Vec<&str> = rest.splitn(4, '/').collect();
            if parts.len() >= 4 {
                let repo = format!("{}/{}", parts[0], parts[1]);
                let branch = parts[2].to_string();
                let skill_path = parts[3]
                    .strip_prefix("skills/")
                    .unwrap_or(parts[3])
                    .trim_end_matches("/SKILL.md")
                    .trim_end_matches(".md")
                    .to_string();
                if !skill_path.is_empty() {
                    return Some((repo, skill_path, Some(branch)));
                }
            }
        }

        // Handle owner/repo/skill patterns (3+ segments with no source_repo override):
        // "omer-metin/skills-for-antigravity/viral-hooks" -> repo=omer-metin/skills-for-antigravity, skill=viral-hooks
        let segments: Vec<&str> = raw.split('/').collect();
        if segments.len() >= 3 {
            let repo = format!("{}/{}", segments[0], segments[1]);
            let skill = segments[2..].join("/");
            return Some((repo, skill, None));
        }

        None
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
            description: "Sync a skill from a GitHub repository into local microclaw.data/skills. Accepts: skill name, owner/repo/skill path, or full GitHub URL. Auto-detects the source repo from the path — no need to set source_repo separately for most skills.".into(),
            input_schema: schema_object(
                json!({
                    "skill_name": {
                        "type": "string",
                        "description": "Skill name, owner/repo/skill path, or full GitHub URL"
                    },
                    "target_name": {
                        "type": "string",
                        "description": "Optional local skill directory/name (defaults to last segment of skill_name)"
                    },
                    "source_repo": {
                        "type": "string",
                        "description": "GitHub repo in owner/name format (auto-detected from skill_name if not provided)"
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
        let raw_skill_name = match input.get("skill_name").and_then(|v| v.as_str()) {
            Some(v) if !v.trim().is_empty() => v.trim(),
            _ => return ToolResult::error("Missing required parameter: skill_name".into()),
        };

        let explicit_repo = input
            .get("source_repo")
            .and_then(|v| v.as_str())
            .filter(|v| !v.trim().is_empty());

        let explicit_ref = input
            .get("git_ref")
            .and_then(|v| v.as_str())
            .filter(|v| !v.trim().is_empty());

        // Auto-detect repo from skill_name if no explicit source_repo was given
        let (source_repo, skill_name, git_ref) = if let Some(repo) = explicit_repo {
            (
                repo.trim().to_string(),
                raw_skill_name.to_string(),
                explicit_ref.unwrap_or("main").to_string(),
            )
        } else if let Some((repo, skill, ref_override)) =
            Self::parse_skill_reference(raw_skill_name)
        {
            let git_ref = explicit_ref
                .map(|s| s.to_string())
                .or(ref_override)
                .unwrap_or_else(|| "main".to_string());
            (repo, skill, git_ref)
        } else {
            (
                "vercel-labs/skills".to_string(),
                raw_skill_name.to_string(),
                explicit_ref.unwrap_or("main").to_string(),
            )
        };

        let target_name = input
            .get("target_name")
            .and_then(|v| v.as_str())
            .filter(|v| !v.trim().is_empty())
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| {
                // Use just the last segment as the target name
                skill_name
                    .rsplit('/')
                    .next()
                    .unwrap_or(&skill_name)
                    .to_string()
            });

        let raw = match Self::fetch_skill_content(&source_repo, &skill_name, &git_ref).await {
            Ok(v) => v,
            Err(e) => return ToolResult::error(e).with_error_type("sync_fetch_failed"),
        };

        let normalized =
            Self::normalize_skill_markdown(&raw, &source_repo, &git_ref, &skill_name, &target_name);

        let out_dir = self.skills_dir.join(&target_name);
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
    fn test_parse_skill_reference_github_url() {
        let result = SyncSkillsTool::parse_skill_reference(
            "https://github.com/omer-metin/skills-for-antigravity/tree/main/skills/viral-hooks",
        );
        let (repo, skill, git_ref) = result.unwrap();
        assert_eq!(repo, "omer-metin/skills-for-antigravity");
        assert_eq!(skill, "viral-hooks");
        assert_eq!(git_ref.unwrap(), "main");
    }

    #[test]
    fn test_parse_skill_reference_owner_repo_skill() {
        let result =
            SyncSkillsTool::parse_skill_reference("omer-metin/skills-for-antigravity/viral-hooks");
        let (repo, skill, git_ref) = result.unwrap();
        assert_eq!(repo, "omer-metin/skills-for-antigravity");
        assert_eq!(skill, "viral-hooks");
        assert!(git_ref.is_none());
    }

    #[test]
    fn test_parse_skill_reference_simple_name() {
        // Two segments or less should return None (use default repo)
        assert!(SyncSkillsTool::parse_skill_reference("viral-hooks").is_none());
        assert!(SyncSkillsTool::parse_skill_reference("find-skills").is_none());
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
