use async_trait::async_trait;
use serde_json::json;
use tracing::info;

use crate::skills::SkillManager;
use microclaw_core::llm_types::ToolDefinition;

use super::{schema_object, Tool, ToolResult};

pub struct ActivateSkillTool {
    skill_manager: SkillManager,
}

impl ActivateSkillTool {
    pub fn new(skills_dir: &str) -> Self {
        ActivateSkillTool {
            skill_manager: SkillManager::from_skills_dir(skills_dir),
        }
    }
}

#[async_trait]
impl Tool for ActivateSkillTool {
    fn name(&self) -> &str {
        "activate_skill"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "activate_skill".into(),
            description: "Activate an agent skill to load its full instructions. IMPORTANT: You must CALL this tool (not write it as text) to activate a skill. Use this when you see a relevant skill in the available skills list and need its detailed instructions to complete a task. Skills are filtered by platform/dependencies before they are listed.".into(),
            input_schema: schema_object(
                json!({
                    "skill_name": {
                        "type": "string",
                        "description": "The name of the skill to activate"
                    }
                }),
                &["skill_name"],
            ),
        }
    }

    async fn execute(&self, input: serde_json::Value) -> ToolResult {
        let skill_name = match input.get("skill_name").and_then(|v| v.as_str()) {
            Some(n) => n,
            None => return ToolResult::error("Missing required parameter: skill_name".into()),
        };

        info!("Activating skill: {}", skill_name);

        match self.skill_manager.load_skill_checked(skill_name) {
            Ok((meta, body)) => {
                let mut result = format!("# Skill: {}\n\n", meta.name);
                result.push_str(&format!("Description: {}\n", meta.description));
                result.push_str(&format!("Skill directory: {}\n", meta.dir_path.display()));
                result.push_str(&format!("Source: {}\n", meta.source));
                if let Some(version) = &meta.version {
                    result.push_str(&format!("Version: {}\n", version));
                }
                if let Some(updated_at) = &meta.updated_at {
                    result.push_str(&format!("Updated at: {}\n", updated_at));
                }
                if !meta.platforms.is_empty() {
                    result.push_str(&format!("Platforms: {}\n", meta.platforms.join(", ")));
                }
                if !meta.deps.is_empty() {
                    result.push_str(&format!("Dependencies: {}\n", meta.deps.join(", ")));
                }
                result.push_str("\n## Instructions\n\n");
                result.push_str(&body);
                let mut tool_result = ToolResult::success(result);
                if let Some(env_file_name) = &meta.env_file {
                    let env_path = meta.dir_path.join(env_file_name);
                    if env_path.exists() {
                        tool_result = tool_result.with_metadata(json!({
                            "skill_env_file": env_path.to_string_lossy(),
                        }));
                    }
                }
                tool_result
            }
            Err(e) => ToolResult::error(format!(
                "{}\nHint: Run `/skills` to list available skills, or `microclaw skill available --all` for unavailable-skill diagnostics.",
                e
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::path::PathBuf;

    fn test_dir() -> PathBuf {
        std::env::temp_dir().join(format!(
            "microclaw_activate_skill_test_{}",
            uuid::Uuid::new_v4()
        ))
    }

    fn create_skill(base_dir: &std::path::Path, name: &str, desc: &str, body: &str) {
        let skill_dir = base_dir.join(name);
        std::fs::create_dir_all(&skill_dir).unwrap();
        let content = format!("---\nname: {name}\ndescription: {desc}\n---\n{body}\n");
        std::fs::write(skill_dir.join("SKILL.md"), content).unwrap();
    }

    fn cleanup(dir: &std::path::Path) {
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn test_activate_skill_tool_name_and_definition() {
        let dir = test_dir();
        let tool = ActivateSkillTool::new(dir.to_str().unwrap());
        assert_eq!(tool.name(), "activate_skill");
        let def = tool.definition();
        assert_eq!(def.name, "activate_skill");
        assert!(!def.description.is_empty());
        assert!(def.input_schema["properties"]["skill_name"].is_object());
        let required = def.input_schema["required"].as_array().unwrap();
        assert_eq!(required.len(), 1);
        assert_eq!(required[0], "skill_name");
        cleanup(&dir);
    }

    #[tokio::test]
    async fn test_activate_skill_found() {
        let dir = test_dir();
        create_skill(
            &dir,
            "pdf",
            "Convert to PDF",
            "Use pdflatex to convert documents.",
        );

        let tool = ActivateSkillTool::new(dir.to_str().unwrap());
        let result = tool.execute(json!({"skill_name": "pdf"})).await;
        assert!(!result.is_error);
        assert!(result.content.contains("# Skill: pdf"));
        assert!(result.content.contains("Convert to PDF"));
        assert!(result
            .content
            .contains("Use pdflatex to convert documents."));
        assert!(result.content.contains("Skill directory:"));
        cleanup(&dir);
    }

    #[tokio::test]
    async fn test_activate_skill_not_found() {
        let dir = test_dir();
        create_skill(&dir, "pdf", "Convert to PDF", "Instructions");

        let tool = ActivateSkillTool::new(dir.to_str().unwrap());
        let result = tool.execute(json!({"skill_name": "nonexistent"})).await;
        assert!(result.is_error);
        assert!(result.content.contains("not found"));
        assert!(result.content.contains("pdf"));
        cleanup(&dir);
    }

    #[tokio::test]
    async fn test_activate_skill_not_found_no_skills() {
        let dir = test_dir();
        let tool = ActivateSkillTool::new(dir.to_str().unwrap());
        let result = tool.execute(json!({"skill_name": "anything"})).await;
        assert!(result.is_error);
        assert!(result.content.contains("No skills are currently available"));
        cleanup(&dir);
    }

    #[tokio::test]
    async fn test_activate_skill_missing_param() {
        let dir = test_dir();
        let tool = ActivateSkillTool::new(dir.to_str().unwrap());
        let result = tool.execute(json!({})).await;
        assert!(result.is_error);
        assert!(result.content.contains("Missing required parameter"));
        cleanup(&dir);
    }
}
