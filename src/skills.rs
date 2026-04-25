use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

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
    pub env_file: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SkillAvailability {
    pub meta: SkillMetadata,
    pub available: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[allow(dead_code)]
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
    #[serde(default)]
    env_file: Option<String>,
    #[serde(default)]
    metadata: SkillFrontmatterMetadata,
}

#[derive(Debug, Deserialize, Default)]
#[allow(dead_code)]
struct SkillFrontmatterMetadata {
    #[serde(default)]
    pub openclaw: Option<OpenClaw>,
    #[serde(default)]
    pub clawdbot: Option<OpenClaw>, // alias
}

#[derive(Debug, Deserialize, Default)]
#[allow(dead_code)]
struct OpenClaw {
    #[serde(default)]
    pub requires: Option<Requires>,
    #[serde(default)]
    pub os: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
#[allow(dead_code)]
struct Requires {
    #[serde(default)]
    pub bins: Vec<String>,
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default, rename = "anyBins")]
    pub any_bins: Vec<String>,
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
    state_file: Option<PathBuf>,
}

const MAX_SKILLS_CATALOG_ITEMS: usize = 40;
const MAX_SKILL_DESCRIPTION_CHARS: usize = 120;
const COMPACT_SKILLS_MODE_THRESHOLD: usize = 20;
const SKILLS_STATE_FILENAME: &str = "skills_state.json";

/// Per-skill body cap when a hot match's full SKILL.md is inlined into
/// the system prompt. Keeps the prompt-cost predictable as the skill
/// library grows; the agent can still call `activate_skill` to read the
/// full body if it needs more.
const MAX_INLINED_SKILL_BODY_CHARS: usize = 1500;

impl SkillManager {
    pub fn from_skills_dir(skills_dir: &str) -> Self {
        SkillManager {
            skills_dir: PathBuf::from(skills_dir),
            state_file: None,
        }
    }

    pub fn from_skills_and_runtime(skills_dir: &str, runtime_dir: &str) -> Self {
        SkillManager {
            skills_dir: PathBuf::from(skills_dir),
            state_file: Some(PathBuf::from(runtime_dir).join(SKILLS_STATE_FILENAME)),
        }
    }

    #[allow(dead_code)]
    pub fn new(data_dir: &str) -> Self {
        let skills_dir = PathBuf::from(data_dir).join("skills");
        SkillManager {
            skills_dir,
            state_file: None,
        }
    }

    /// Discover all skills that are available on the current platform and satisfy dependency checks.
    pub fn discover_skills(&self) -> Vec<SkillMetadata> {
        self.discover_skills_internal(false)
    }

    /// Discover skills with availability diagnostics.
    pub fn discover_skills_with_status(&self, include_unavailable: bool) -> Vec<SkillAvailability> {
        let mut statuses = self.discover_skill_statuses();
        if !include_unavailable {
            statuses.retain(|s| s.available);
        }
        statuses
    }

    /// Reload skills from disk (live reload)
    pub fn reload(&self) -> Vec<SkillMetadata> {
        self.discover_skills()
    }

    fn discover_skills_internal(&self, include_unavailable: bool) -> Vec<SkillMetadata> {
        self.discover_skills_with_status(include_unavailable)
            .into_iter()
            .map(|s| s.meta)
            .collect()
    }

    fn discover_skill_statuses(&self) -> Vec<SkillAvailability> {
        let mut statuses = Vec::new();
        let state = self.read_state_file();
        let entries = match std::fs::read_dir(&self.skills_dir) {
            Ok(e) => e,
            Err(_) => return statuses,
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
                    if matches!(state.get(&meta.name), Some(false)) {
                        statuses.push(SkillAvailability {
                            meta,
                            available: false,
                            reason: Some("Skill is disabled for this runtime.".to_string()),
                        });
                        continue;
                    }
                    match self.skill_is_available(&meta) {
                        Ok(()) => statuses.push(SkillAvailability {
                            meta,
                            available: true,
                            reason: None,
                        }),
                        Err(reason) => statuses.push(SkillAvailability {
                            meta,
                            available: false,
                            reason: Some(reason),
                        }),
                    };
                }
            }
        }

        statuses.sort_by(|a, b| a.meta.name.cmp(&b.meta.name));
        statuses
    }

    pub fn has_skill(&self, name: &str) -> bool {
        self.discover_skill_statuses()
            .iter()
            .any(|skill| skill.meta.name == name)
    }

    pub fn set_enabled(&self, name: &str, enabled: bool) -> Result<(), String> {
        if !self.has_skill(name) {
            return Err(format!("Skill not found: {name}"));
        }
        let mut state = self.read_state_file();
        if enabled {
            state.remove(name);
        } else {
            state.insert(name.to_string(), false);
        }
        self.write_state_file(&state)
    }

    /// Load a skill by name if it is available on the current platform.
    pub fn load_skill(&self, name: &str) -> Option<(SkillMetadata, String)> {
        self.load_skill_checked(name).ok()
    }

    /// Load a skill with availability diagnostics.
    pub fn load_skill_checked(&self, name: &str) -> Result<(SkillMetadata, String), String> {
        let all_skills = self.discover_skills_with_status(true);

        for skill in all_skills {
            if skill.meta.name != name {
                continue;
            }
            if !skill.available {
                let reason = skill
                    .reason
                    .unwrap_or_else(|| "unknown availability failure".to_string());
                return Err(format!(
                    "Skill '{name}' is currently unavailable: {reason}\nRun `microclaw skill available --all` for full diagnostics."
                ));
            }
            let skill_md = skill.meta.dir_path.join("SKILL.md");
            if let Ok(content) = std::fs::read_to_string(&skill_md) {
                if let Some((meta, body)) = parse_skill_md(&content, &skill.meta.dir_path) {
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
        let mut skills = self.discover_skills();
        if skills.is_empty() {
            return String::new();
        }

        // Keep prompt injection stable across runs and bounded for token budget.
        skills.sort_by_key(|s| s.name.to_ascii_lowercase());

        let total_count = skills.len();
        let omitted = total_count.saturating_sub(MAX_SKILLS_CATALOG_ITEMS);
        let visible = skills
            .into_iter()
            .take(MAX_SKILLS_CATALOG_ITEMS)
            .collect::<Vec<_>>();
        let compact_mode = total_count > COMPACT_SKILLS_MODE_THRESHOLD || omitted > 0;

        let mut catalog = String::from("<available_skills>\n");
        for skill in &visible {
            if compact_mode {
                catalog.push_str(&format!("- {}\n", skill.name));
            } else {
                let desc = truncate_chars(&skill.description, MAX_SKILL_DESCRIPTION_CHARS);
                catalog.push_str(&format!("- {}: {}\n", skill.name, desc));
            }
        }
        if compact_mode {
            catalog.push_str("- (compact mode: use activate_skill to load full instructions)\n");
        }
        if omitted > 0 {
            catalog.push_str(&format!(
                "- ... ({} additional skills omitted for prompt budget)\n",
                omitted
            ));
        }
        catalog.push_str("</available_skills>");
        catalog
    }

    /// Build a query-aware skills catalog: inline the full body of the
    /// top-`top_k` skills whose descriptions overlap the query, and fall
    /// back to a compact `name: description` listing for the rest.
    ///
    /// Tradeoff vs `build_skills_catalog`: spending a bigger token slice
    /// on the most-relevant skills (so the agent has the procedural
    /// knowledge inline and doesn't need an extra `activate_skill`
    /// round-trip) while keeping the long tail cheap.
    ///
    /// `top_k = 0` falls back to [`build_skills_catalog`] verbatim. An
    /// empty `query` also falls back — without a query the relevance
    /// score is meaningless.
    pub fn build_skills_catalog_for_query(&self, query: &str, top_k: usize) -> String {
        if top_k == 0 || query.trim().is_empty() {
            return self.build_skills_catalog();
        }
        let mut skills = self.discover_skills();
        if skills.is_empty() {
            return String::new();
        }

        let query_tokens = crate::memory_service::tokenize_for_relevance(query);
        // Score by description-token overlap. Name is also factored in so
        // a query like "tokyo-deploy" matches a skill literally named
        // `tokyo-deploy`.
        let mut scored: Vec<(usize, SkillMetadata)> = skills
            .drain(..)
            .map(|s| {
                let blob = format!("{} {}", s.name, s.description);
                let blob_tokens = crate::memory_service::tokenize_for_relevance(&blob);
                let score = blob_tokens
                    .iter()
                    .filter(|t| query_tokens.contains(*t))
                    .count();
                (score, s)
            })
            .collect();
        // Higher score first; tie-break by name for stability.
        scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.name.cmp(&b.1.name)));

        // Hot bucket: top_k entries with score > 0.
        let mut hot: Vec<SkillMetadata> = Vec::new();
        let mut cold: Vec<SkillMetadata> = Vec::new();
        for (score, meta) in scored {
            if score > 0 && hot.len() < top_k {
                hot.push(meta);
            } else {
                cold.push(meta);
            }
        }
        if hot.is_empty() {
            // No relevant matches — degenerate to the plain catalog.
            return self.build_skills_catalog();
        }

        let mut out = String::from("<available_skills>\n");
        out.push_str("<!-- Hot matches: full body inlined for the most relevant skills. -->\n");
        for meta in &hot {
            out.push_str(&format!("## {}\n", meta.name));
            out.push_str(&format!("Description: {}\n", meta.description));
            if let Some(version) = &meta.version {
                out.push_str(&format!("Version: {}\n", version));
            }
            let skill_md = meta.dir_path.join("SKILL.md");
            if let Ok(content) = std::fs::read_to_string(&skill_md) {
                let body = strip_frontmatter(&content);
                let body = truncate_chars(body, MAX_INLINED_SKILL_BODY_CHARS);
                out.push_str("Instructions:\n");
                out.push_str(&body);
                if !body.ends_with('\n') {
                    out.push('\n');
                }
            }
            out.push('\n');
        }
        if !cold.is_empty() {
            out.push_str("<!-- Other available skills (call activate_skill to load full body): -->\n");
            cold.sort_by_key(|s| s.name.to_ascii_lowercase());
            let total_cold = cold.len();
            let omitted = total_cold.saturating_sub(MAX_SKILLS_CATALOG_ITEMS);
            for skill in cold.into_iter().take(MAX_SKILLS_CATALOG_ITEMS) {
                let desc = truncate_chars(&skill.description, MAX_SKILL_DESCRIPTION_CHARS);
                out.push_str(&format!("- {}: {}\n", skill.name, desc));
            }
            if omitted > 0 {
                out.push_str(&format!(
                    "- ... ({omitted} additional skills omitted for prompt budget)\n"
                ));
            }
        }
        out.push_str("</available_skills>");
        out
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

    /// Build a user-facing list, optionally including unavailable skills and reasons.
    pub fn list_skills_formatted_all(&self) -> String {
        let statuses = self.discover_skills_with_status(true);
        if statuses.is_empty() {
            return "No skills found in skills directory.".into();
        }
        let available: Vec<&SkillAvailability> = statuses.iter().filter(|s| s.available).collect();
        let unavailable: Vec<&SkillAvailability> =
            statuses.iter().filter(|s| !s.available).collect();
        let mut output = String::new();
        output.push_str(&format!("Available skills ({}):\n\n", available.len()));
        for skill in available {
            output.push_str(&format!(
                "• {} — {} [{}]\n",
                skill.meta.name, skill.meta.description, skill.meta.source
            ));
        }
        output.push('\n');
        output.push_str(&format!("Unavailable skills ({}):\n\n", unavailable.len()));
        for skill in unavailable {
            output.push_str(&format!(
                "• {} — {}\n",
                skill.meta.name,
                skill
                    .reason
                    .as_deref()
                    .unwrap_or("unavailable for unknown reason")
            ));
        }
        output
    }

    #[allow(dead_code)]
    pub fn skills_dir(&self) -> &PathBuf {
        &self.skills_dir
    }

    pub fn state_file_path(&self) -> Option<&Path> {
        self.state_file.as_deref()
    }

    fn read_state_file(&self) -> HashMap<String, bool> {
        let Some(path) = self.state_file.as_ref() else {
            return HashMap::new();
        };
        if !path.exists() {
            return HashMap::new();
        }
        match std::fs::read_to_string(path) {
            Ok(raw) => serde_json::from_str::<HashMap<String, bool>>(&raw).unwrap_or_default(),
            Err(_) => HashMap::new(),
        }
    }

    fn write_state_file(&self, state: &HashMap<String, bool>) -> Result<(), String> {
        let Some(path) = self.state_file.as_ref() else {
            return Err("Skill state is not configured for this runtime.".to_string());
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let body = serde_json::to_string_pretty(state).map_err(|e| e.to_string())?;
        std::fs::write(path, body).map_err(|e| e.to_string())
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

/// Return the SKILL.md body with its YAML frontmatter (`---\n…\n---\n`)
/// removed. If no frontmatter is present, the input is returned as-is.
fn strip_frontmatter(content: &str) -> &str {
    let trimmed = content.trim_start_matches('\u{feff}');
    if !trimmed.starts_with("---\n") {
        return trimmed;
    }
    match trimmed[4..].find("\n---\n") {
        Some(end) => trimmed[4 + end + 5..].trim_start_matches('\n'),
        None => trimmed,
    }
}

fn truncate_chars(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    let truncated: String = s.chars().take(max_chars).collect();
    format!("{truncated}...")
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
            env_file: fm
                .env_file
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

    #[test]
    fn test_build_skills_catalog_sorted_and_truncated() {
        let dir = std::env::temp_dir().join(format!(
            "microclaw_skills_catalog_sorted_{}",
            uuid::Uuid::new_v4()
        ));
        let long_desc = "z".repeat(MAX_SKILL_DESCRIPTION_CHARS + 32);
        let zeta = dir.join("zeta");
        let alpha = dir.join("alpha");
        std::fs::create_dir_all(&zeta).unwrap();
        std::fs::create_dir_all(&alpha).unwrap();
        std::fs::write(
            zeta.join("SKILL.md"),
            format!("---\nname: zeta\ndescription: {long_desc}\n---\nok\n"),
        )
        .unwrap();
        std::fs::write(
            alpha.join("SKILL.md"),
            r#"---
name: alpha
description: alpha skill
---
ok
"#,
        )
        .unwrap();

        let sm = SkillManager::from_skills_dir(dir.to_str().unwrap());
        let catalog = sm.build_skills_catalog();
        let alpha_pos = catalog.find("- alpha: alpha skill").unwrap();
        let zeta_pos = catalog.find("- zeta: ").unwrap();
        assert!(alpha_pos < zeta_pos);
        assert!(catalog.contains("..."));
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn write_skill(root: &std::path::Path, name: &str, description: &str, body: &str) {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        let content = format!(
            "---\nname: {name}\ndescription: {description}\nsource: agent-created\n---\n{body}\n"
        );
        std::fs::write(dir.join("SKILL.md"), content).unwrap();
    }

    #[test]
    fn build_skills_catalog_for_query_falls_back_when_top_k_zero() {
        let dir = std::env::temp_dir().join(format!(
            "mc_skills_query_top_k_zero_{}",
            uuid::Uuid::new_v4()
        ));
        write_skill(&dir, "alpha", "alpha skill", "ok");
        let sm = SkillManager::from_skills_dir(dir.to_str().unwrap());
        let plain = sm.build_skills_catalog();
        let queried = sm.build_skills_catalog_for_query("alpha", 0);
        assert_eq!(plain, queried);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn build_skills_catalog_for_query_inlines_relevant_skill_body() {
        let dir = std::env::temp_dir().join(format!(
            "mc_skills_query_inline_{}",
            uuid::Uuid::new_v4()
        ));
        write_skill(&dir, "deploy-helper", "kubernetes rolling deploy", "Step 1: kubectl apply\nStep 2: verify");
        write_skill(&dir, "irrelevant", "make tea", "boil water");
        let sm = SkillManager::from_skills_dir(dir.to_str().unwrap());
        let out = sm.build_skills_catalog_for_query("how do i do a kubernetes deploy?", 3);
        assert!(out.contains("## deploy-helper"), "got: {out}");
        assert!(out.contains("Step 1: kubectl apply"), "body not inlined: {out}");
        // Irrelevant skill ends up in the cold list with just name+desc.
        assert!(out.contains("- irrelevant: make tea"), "got: {out}");
        assert!(!out.contains("boil water"), "irrelevant body leaked: {out}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn build_skills_catalog_for_query_falls_back_when_no_match() {
        let dir = std::env::temp_dir().join(format!(
            "mc_skills_query_nomatch_{}",
            uuid::Uuid::new_v4()
        ));
        write_skill(&dir, "alpha", "alpha skill", "ok");
        write_skill(&dir, "beta", "beta skill", "ok");
        let sm = SkillManager::from_skills_dir(dir.to_str().unwrap());
        // Query has no overlap with any skill description.
        let out = sm.build_skills_catalog_for_query("xyz unrelated", 3);
        // No "## name" inlined-body sections.
        assert!(!out.contains("## alpha"));
        assert!(!out.contains("## beta"));
        // Plain catalog still lists both.
        assert!(out.contains("- alpha: alpha skill"));
        assert!(out.contains("- beta: beta skill"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn build_skills_catalog_for_query_caps_inlined_body() {
        let dir = std::env::temp_dir().join(format!(
            "mc_skills_query_cap_{}",
            uuid::Uuid::new_v4()
        ));
        let big_body = "x".repeat(MAX_INLINED_SKILL_BODY_CHARS + 500);
        write_skill(&dir, "matchme", "matchme description", &big_body);
        let sm = SkillManager::from_skills_dir(dir.to_str().unwrap());
        let out = sm.build_skills_catalog_for_query("matchme description", 3);
        assert!(out.contains("## matchme"));
        // Body got truncated with the "..." sentinel from truncate_chars.
        assert!(out.contains("..."), "expected truncation marker: {out}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn build_skills_catalog_for_query_respects_top_k_bucket() {
        let dir = std::env::temp_dir().join(format!(
            "mc_skills_query_top_k_{}",
            uuid::Uuid::new_v4()
        ));
        // Five skills all matching "deploy"; top_k=2 should inline 2 hot
        // bodies, others go to the cold list.
        for n in 0..5 {
            let name = format!("deploy-{n}");
            write_skill(&dir, &name, "deploy stuff", &format!("body {n}"));
        }
        let sm = SkillManager::from_skills_dir(dir.to_str().unwrap());
        let out = sm.build_skills_catalog_for_query("deploy", 2);
        let inlined = out.matches("## deploy-").count();
        assert_eq!(inlined, 2, "expected 2 inlined hot matches; got: {out}");
        // Remaining 3 should be in the cold list with name+description.
        let cold = out.matches("- deploy-").count();
        assert_eq!(cold, 3, "expected 3 cold entries; got: {out}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn strip_frontmatter_removes_yaml_block() {
        let body = "---\nname: x\ndescription: y\n---\nthe body\n";
        assert_eq!(strip_frontmatter(body), "the body\n");
    }

    #[test]
    fn strip_frontmatter_returns_input_when_no_frontmatter() {
        let body = "no frontmatter here\n";
        assert_eq!(strip_frontmatter(body), body);
    }

    #[test]
    fn test_build_skills_catalog_applies_item_cap() {
        let dir = std::env::temp_dir().join(format!(
            "microclaw_skills_catalog_cap_{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        for idx in 0..=MAX_SKILLS_CATALOG_ITEMS {
            let name = format!("skill-{idx:02}");
            let skill_dir = dir.join(&name);
            std::fs::create_dir_all(&skill_dir).unwrap();
            std::fs::write(
                skill_dir.join("SKILL.md"),
                format!("---\nname: {name}\ndescription: test skill {idx}\n---\nbody\n"),
            )
            .unwrap();
        }
        let sm = SkillManager::from_skills_dir(dir.to_str().unwrap());
        let catalog = sm.build_skills_catalog();
        assert!(catalog.contains("additional skills omitted for prompt budget"));
        let rendered_items = catalog
            .lines()
            .filter(|line| line.starts_with("- skill-"))
            .count();
        assert_eq!(rendered_items, MAX_SKILLS_CATALOG_ITEMS);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_build_skills_catalog_enters_compact_mode_when_many_skills() {
        let dir = std::env::temp_dir().join(format!(
            "microclaw_skills_catalog_compact_mode_{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        for idx in 0..=COMPACT_SKILLS_MODE_THRESHOLD {
            let name = format!("compact-skill-{idx:02}");
            let skill_dir = dir.join(&name);
            std::fs::create_dir_all(&skill_dir).unwrap();
            std::fs::write(
                skill_dir.join("SKILL.md"),
                format!(
                    "---\nname: {name}\ndescription: this description should not appear in compact mode\n---\nbody\n"
                ),
            )
            .unwrap();
        }

        let sm = SkillManager::from_skills_dir(dir.to_str().unwrap());
        let catalog = sm.build_skills_catalog();
        assert!(catalog.contains("compact mode: use activate_skill"));
        assert!(!catalog.contains(": this description should not appear"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_list_skills_formatted_all_includes_unavailable_reasons() {
        let dir = std::env::temp_dir().join(format!(
            "microclaw_skills_all_test_{}",
            uuid::Uuid::new_v4()
        ));
        let available = dir.join("available");
        std::fs::create_dir_all(&available).unwrap();
        std::fs::write(
            available.join("SKILL.md"),
            r#"---
name: available
description: Available skill
---
ok
"#,
        )
        .unwrap();

        let unavailable = dir.join("unavailable");
        std::fs::create_dir_all(&unavailable).unwrap();
        std::fs::write(
            unavailable.join("SKILL.md"),
            r#"---
name: unavailable
description: Missing dependency
deps: [definitely_missing_dep_123456]
---
nope
"#,
        )
        .unwrap();

        let sm = SkillManager::from_skills_dir(dir.to_str().unwrap());
        let text = sm.list_skills_formatted_all();
        assert!(text.contains("Available skills (1)"));
        assert!(text.contains("available"));
        assert!(text.contains("Unavailable skills (1)"));
        assert!(text.contains("definitely_missing_dep_123456"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_skill_checked_unavailable_has_diagnostic_hint() {
        let dir = std::env::temp_dir().join(format!(
            "microclaw_skills_unavailable_test_{}",
            uuid::Uuid::new_v4()
        ));
        let unavailable = dir.join("bad");
        std::fs::create_dir_all(&unavailable).unwrap();
        std::fs::write(
            unavailable.join("SKILL.md"),
            r#"---
name: bad
description: Missing dependency
deps: [definitely_missing_dep_654321]
---
nope
"#,
        )
        .unwrap();
        let sm = SkillManager::from_skills_dir(dir.to_str().unwrap());
        let err = sm.load_skill_checked("bad").unwrap_err();
        assert!(err.contains("currently unavailable"));
        assert!(err.contains("available --all"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_parse_skill_md_with_env_file() {
        let content = r#"---
name: outline
description: Manage Outline wiki
env_file: .env
---
Use this skill to interact with Outline.
"#;
        let dir = PathBuf::from("/tmp/skills/outline");
        let result = parse_skill_md(content, &dir);
        assert!(result.is_some());
        let (meta, _body) = result.unwrap();
        assert_eq!(meta.env_file.as_deref(), Some(".env"));
    }

    #[test]
    fn test_disable_skill_is_runtime_scoped() {
        let base_dir = std::env::temp_dir().join(format!(
            "microclaw_skills_runtime_scoped_{}",
            uuid::Uuid::new_v4()
        ));
        let runtime_a = base_dir.join("runtime-a");
        let runtime_b = base_dir.join("runtime-b");
        let skills_dir = base_dir.join("skills");
        let skill_dir = skills_dir.join("pdf");
        std::fs::create_dir_all(&skill_dir).unwrap();
        std::fs::write(
            skill_dir.join("SKILL.md"),
            r#"---
name: pdf
description: Convert to PDF
---
Use this skill.
"#,
        )
        .unwrap();

        let manager_a = SkillManager::from_skills_and_runtime(
            skills_dir.to_str().unwrap(),
            runtime_a.to_str().unwrap(),
        );
        let manager_b = SkillManager::from_skills_and_runtime(
            skills_dir.to_str().unwrap(),
            runtime_b.to_str().unwrap(),
        );

        manager_a.set_enabled("pdf", false).unwrap();

        let status_a = manager_a.discover_skills_with_status(true);
        let status_b = manager_b.discover_skills_with_status(true);

        assert!(!status_a[0].available);
        assert!(status_a[0]
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("disabled"));
        assert!(status_b[0].available);
        assert!(skill_dir.join("SKILL.md").exists());
        let _ = std::fs::remove_dir_all(&base_dir);
    }

    #[test]
    fn test_set_enabled_missing_skill_returns_error() {
        let base_dir = std::env::temp_dir().join(format!(
            "microclaw_skills_enable_missing_{}",
            uuid::Uuid::new_v4()
        ));
        let runtime = base_dir.join("runtime");
        let skills_dir = base_dir.join("skills");
        std::fs::create_dir_all(&skills_dir).unwrap();
        let manager = SkillManager::from_skills_and_runtime(
            skills_dir.to_str().unwrap(),
            runtime.to_str().unwrap(),
        );
        let err = manager.set_enabled("missing", false).unwrap_err();
        assert!(err.contains("Skill not found"));
        let _ = std::fs::remove_dir_all(&base_dir);
    }
}
