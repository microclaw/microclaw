use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct SkillMetadata {
    pub name: String,
    pub description: String,
    pub dir_path: PathBuf,
    pub platforms: Vec<String>,
    pub deps: Vec<String>,
    pub source: String,
    pub version: Option<String>,
    pub updated_at: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct SkillFrontmatter {
    name: Option<String>,
    #[serde(default)]
    description: String,
    #[serde(default)]
    platforms: Vec<String>,
    #[serde(default)]
    deps: Vec<String>,
    #[serde(default)]
    compatibility: SkillCompatibility,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    updated_at: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct SkillCompatibility {
    #[serde(default)]
    os: Vec<String>,
    #[serde(default)]
    deps: Vec<String>,
}

pub struct SkillManager {
    skills_dir: PathBuf,
}

impl SkillManager {
    pub fn from_skills_dir(skills_dir: &str) -> Self {
        SkillManager {
            skills_dir: PathBuf::from(skills_dir),
        }
    }

    #[allow(dead_code)]
    pub fn new(data_dir: &str) -> Self {
        let skills_dir = PathBuf::from(data_dir).join("skills");
        SkillManager { skills_dir }
    }

    /// Discover all skills that are available on the current platform and satisfy dependency checks.
    pub fn discover_skills(&self) -> Vec<SkillMetadata> {
        self.discover_skills_internal(false)
    }

    fn discover_skills_internal(&self, include_unavailable: bool) -> Vec<SkillMetadata> {
        let mut skills = Vec::new();
        let entries = match std::fs::read_dir(&self.skills_dir) {
            Ok(e) => e,
            Err(_) => return skills,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let skill_md = path.join("SKILL.md");
            if !skill_md.exists() {
                continue;
            }
            if let Ok(content) = std::fs::read_to_string(&skill_md) {
                if let Some((meta, _body)) = parse_skill_md(&content, &path) {
                    if include_unavailable || self.skill_is_available(&meta).is_ok() {
                        skills.push(meta);
                    }
                }
            }
        }

        skills.sort_by(|a, b| a.name.cmp(&b.name));
        skills
    }

    /// Load a skill by name if it is available on the current platform.
    pub fn load_skill(&self, name: &str) -> Option<(SkillMetadata, String)> {
        self.load_skill_checked(name).ok()
    }

    /// Load a skill with availability diagnostics.
    pub fn load_skill_checked(&self, name: &str) -> Result<(SkillMetadata, String), String> {
        let all_skills = self.discover_skills_internal(true);

        for skill in all_skills {
            if skill.name != name {
                continue;
            }

            self.skill_is_available(&skill)?;

            let skill_md = skill.dir_path.join("SKILL.md");
            if let Ok(content) = std::fs::read_to_string(&skill_md) {
                if let Some((meta, body)) = parse_skill_md(&content, &skill.dir_path) {
                    return Ok((meta, body));
                }
            }
            return Err(format!("Skill '{name}' exists but could not be loaded."));
        }

        let available = self.discover_skills();
        if available.is_empty() {
            Err(format!(
                "Skill '{name}' not found. No skills are currently available."
            ))
        } else {
            let names: Vec<&str> = available.iter().map(|s| s.name.as_str()).collect();
            Err(format!(
                "Skill '{name}' not found. Available skills: {}",
                names.join(", ")
            ))
        }
    }

    fn skill_is_available(&self, skill: &SkillMetadata) -> Result<(), String> {
        if !platform_allowed(&skill.platforms) {
            return Err(format!(
                "Skill '{}' is not available on this platform (current: {}, supported: {}).",
                skill.name,
                current_platform(),
                skill.platforms.join(", ")
            ));
        }

        let missing = missing_deps(&skill.deps);
        if !missing.is_empty() {
            return Err(format!(
                "Skill '{}' is missing required dependencies: {}",
                skill.name,
                missing.join(", ")
            ));
        }

        Ok(())
    }

    /// Build a compact skills catalog for the system prompt.
    /// Returns empty string if no skills are available.
    pub fn build_skills_catalog(&self) -> String {
        let skills = self.discover_skills();
        if skills.is_empty() {
            return String::new();
        }
        let mut catalog = String::from("<available_skills>\n");
        for skill in &skills {
            catalog.push_str(&format!("- {}: {}\n", skill.name, skill.description));
        }
        catalog.push_str("</available_skills>");
        catalog
    }

    /// Build a user-facing formatted list of available skills.
    pub fn list_skills_formatted(&self) -> String {
        let skills = self.discover_skills();
        if skills.is_empty() {
            return "No skills available on this platform/runtime.".into();
        }
        let mut output = format!("Available skills ({}):\n\n", skills.len());
        for skill in &skills {
            output.push_str(&format!(
                "• {} — {} [{}]\n",
                skill.name, skill.description, skill.source
            ));
        }
        output
    }

    #[allow(dead_code)]
    pub fn skills_dir(&self) -> &PathBuf {
        &self.skills_dir
    }
}

fn current_platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "unknown"
    }
}

fn normalize_platform(value: &str) -> String {
    let v = value.trim().to_ascii_lowercase();
    match v.as_str() {
        "macos" | "osx" => "darwin".to_string(),
        _ => v,
    }
}

fn platform_allowed(platforms: &[String]) -> bool {
    if platforms.is_empty() {
        return true;
    }

    let current = current_platform();
    platforms.iter().any(|p| {
        let p = normalize_platform(p);
        p == "all" || p == "*" || p == current
    })
}

fn command_exists(command: &str) -> bool {
    if command.trim().is_empty() {
        return true;
    }

    let path_var = std::env::var_os("PATH").unwrap_or_default();
    let paths = std::env::split_paths(&path_var);

    #[cfg(target_os = "windows")]
    let candidates: Vec<String> = {
        let exts = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into());
        let ext_list: Vec<String> = exts
            .split(';')
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        let lower = command.to_ascii_lowercase();
        if ext_list.iter().any(|ext| lower.ends_with(ext)) {
            vec![command.to_string()]
        } else {
            let mut c = vec![command.to_string()];
            for ext in ext_list {
                c.push(format!("{command}{ext}"));
            }
            c
        }
    };

    #[cfg(not(target_os = "windows"))]
    let candidates: Vec<String> = vec![command.to_string()];

    for base in paths {
        for candidate in &candidates {
            let full = base.join(candidate);
            if full.is_file() {
                return true;
            }
        }
    }

    false
}

fn missing_deps(deps: &[String]) -> Vec<String> {
    deps.iter()
        .filter(|dep| !command_exists(dep))
        .cloned()
        .collect()
}

/// Attempt to convert single-line frontmatter (`--- name: x description: y --- body`)
/// into standard multi-line YAML format for parsing.
fn normalize_single_line_frontmatter(content: &str) -> Option<String> {
    if !content.starts_with("--- ") {
        return None;
    }
    let after_open = &content[4..]; // skip "--- "
    let close_idx = after_open.find(" ---")?;
    let yaml_part = after_open[..close_idx].trim();
    if yaml_part.is_empty() {
        return None;
    }
    let body = after_open[close_idx + 4..].trim_start();

    // Insert newlines before known frontmatter keys so serde_yaml can parse them
    let known_keys: &[&str] = &[
        "name:",
        "description:",
        "license:",
        "platforms:",
        "deps:",
        "compatibility:",
        "source:",
        "version:",
        "updated_at:",
    ];
    let mut yaml = yaml_part.to_string();
    for key in known_keys {
        yaml = yaml.replacen(&format!(" {key}"), &format!("\n{key}"), 1);
    }

    Some(format!("---\n{yaml}\n---\n{body}"))
}

/// Parse a SKILL.md file, extracting frontmatter via YAML and body.
/// Returns None if the file lacks valid frontmatter with a name field.
fn parse_skill_md(content: &str, dir_path: &std::path::Path) -> Option<(SkillMetadata, String)> {
    let trimmed = content.trim_start_matches('\u{feff}');

    // Try normalizing single-line frontmatter if standard format not found
    let normalized;
    let input = if !trimmed.starts_with("---\n") && !trimmed.starts_with("---\r\n") {
        normalized = normalize_single_line_frontmatter(trimmed)?;
        &normalized
    } else {
        trimmed
    };

    let mut lines = input.lines();
    let _ = lines.next()?; // opening ---

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

    if yaml_block.trim().is_empty() {
        return None;
    }

    let fm: SkillFrontmatter = serde_yaml::from_str(&yaml_block).ok()?;
    let name = fm.name?.trim().to_string();
    if name.is_empty() {
        return None;
    }

    let mut platforms: Vec<String> = fm
        .platforms
        .into_iter()
        .chain(fm.compatibility.os)
        .map(|p| normalize_platform(&p))
        .filter(|p| !p.is_empty())
        .collect();
    platforms.sort();
    platforms.dedup();

    let mut deps: Vec<String> = fm
        .deps
        .into_iter()
        .chain(fm.compatibility.deps)
        .map(|d| d.trim().to_string())
        .filter(|d| !d.is_empty())
        .collect();
    deps.sort();
    deps.dedup();

    let header_len = if let Some(idx) = input.find("\n---\n") {
        idx + 5
    } else if let Some(idx) = input.find("\n...\n") {
        idx + 5
    } else {
        // fallback to consumed length from line-by-line scan
        4 + consumed
    };

    let body = input
        .get(header_len..)
        .unwrap_or_default()
        .trim()
        .to_string();

    Some((
        SkillMetadata {
            name,
            description: fm.description,
            dir_path: dir_path.to_path_buf(),
            platforms,
            deps,
            source: fm
                .source
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "local".to_string()),
            version: fm
                .version
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            updated_at: fm
                .updated_at
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
        },
        body,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_skill_md_valid() {
        let content = r#"---
name: pdf
description: Convert documents to PDF
platforms: [linux, darwin]
deps: [pandoc]
---
Use this skill to convert documents.
"#;
        let dir = PathBuf::from("/tmp/skills/pdf");
        let result = parse_skill_md(content, &dir);
        assert!(result.is_some());
        let (meta, body) = result.unwrap();
        assert_eq!(meta.name, "pdf");
        assert_eq!(meta.description, "Convert documents to PDF");
        assert_eq!(meta.platforms, vec!["darwin", "linux"]);
        assert_eq!(meta.deps, vec!["pandoc"]);
        assert_eq!(meta.source, "local");
        assert!(body.contains("Use this skill"));
    }

    #[test]
    fn test_parse_skill_md_compatibility_os() {
        let content = r#"---
name: apple-notes
description: Apple Notes
compatibility:
  os:
    - darwin
  deps:
    - memo
---
Instructions.
"#;
        let dir = PathBuf::from("/tmp/skills/apple-notes");
        let (meta, _) = parse_skill_md(content, &dir).unwrap();
        assert_eq!(meta.platforms, vec!["darwin"]);
        assert_eq!(meta.deps, vec!["memo"]);
    }

    #[test]
    fn test_parse_skill_md_no_frontmatter() {
        let content = "Just some markdown without frontmatter.";
        let dir = PathBuf::from("/tmp/skills/test");
        assert!(parse_skill_md(content, &dir).is_none());
    }

    #[test]
    fn test_parse_skill_md_single_line_frontmatter() {
        let content = "--- name: frontend-design description: Create distinctive UIs license: Complete terms in LICENSE.txt --- This skill guides creation of distinctive interfaces.";
        let dir = PathBuf::from("/tmp/skills/frontend-design");
        let result = parse_skill_md(content, &dir);
        assert!(result.is_some(), "single-line frontmatter should parse");
        let (meta, body) = result.unwrap();
        assert_eq!(meta.name, "frontend-design");
        assert!(meta.description.starts_with("Create distinctive"));
        assert!(body.contains("This skill guides"));
    }

    #[test]
    fn test_normalize_single_line_frontmatter() {
        let content = "--- name: test description: A test skill --- Body here";
        let result = normalize_single_line_frontmatter(content);
        assert!(result.is_some());
        let norm = result.unwrap();
        assert!(norm.starts_with("---\n"));
        assert!(norm.contains("\nname: test"));
        assert!(norm.contains("\ndescription: A test skill"));
        assert!(norm.contains("---\nBody here"));
    }

    #[test]
    fn test_platform_allowed_empty_means_all() {
        assert!(platform_allowed(&[]));
    }

    #[test]
    fn test_build_skills_catalog_empty() {
        let dir =
            std::env::temp_dir().join(format!("microclaw_skills_test_{}", uuid::Uuid::new_v4()));
        let sm = SkillManager::new(dir.to_str().unwrap());
        let catalog = sm.build_skills_catalog();
        assert!(catalog.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
