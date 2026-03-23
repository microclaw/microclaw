use include_dir::{include_dir, Dir, DirEntry, File};
use serde::Deserialize;
use std::path::Path;

static BUILTIN_SKILLS_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/../../skills/built-in");

pub fn ensure_builtin_skills(skills_root: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(skills_root)?;
    copy_compatible_skills(&BUILTIN_SKILLS_DIR, skills_root)
}

fn copy_compatible_skills(embedded: &Dir<'_>, destination: &Path) -> std::io::Result<()> {
    for entry in embedded.entries() {
        let DirEntry::Dir(skill_dir) = entry else {
            continue;
        };
        let Some(skill_name) = skill_dir.path().file_name() else {
            continue;
        };
        let skill_name_str = skill_name.to_string_lossy();
        tracing::debug!("Found built-in skill: {}", skill_name_str);

        let Some(skill_md) = get_file_with_relative_dir(skill_dir, "SKILL.md") else {
            tracing::debug!("Skipping {} - missing SKILL.md", skill_name_str);
            continue;
        };
        let content = String::from_utf8_lossy(skill_md.contents());
        if let Some(reason) = skill_skip_reason(&content) {
            tracing::debug!(
                "Skipping built-in skill '{}' on this host: {}",
                skill_name_str,
                reason
            );
            continue;
        }
        let next_dest = destination.join(skill_name);
        if !next_dest.exists() {
            tracing::debug!(
                "Installing skill {} to {}",
                skill_name_str,
                next_dest.display()
            );
            std::fs::create_dir_all(&next_dest)?;
            copy_missing_entries(skill_dir, &next_dest)?;
        } else {
            tracing::debug!(
                "Skill {} already exists at {}",
                skill_name_str,
                next_dest.display()
            );
            // still copy missing files inside
            copy_missing_entries(skill_dir, &next_dest)?;
        }
    }
    Ok(())
}

fn get_file_with_relative_dir<'a>(dir: &'a Dir<'a>, relative_path: &str) -> Option<&'a File<'a>> {
    let full_path = dir.path().join(relative_path);
    dir.get_file(full_path)
}

fn copy_missing_entries(embedded: &Dir<'_>, destination: &Path) -> std::io::Result<()> {
    for entry in embedded.entries() {
        match entry {
            DirEntry::Dir(dir) => {
                let Some(name) = dir.path().file_name() else {
                    continue;
                };
                let next_dest = destination.join(name);
                if !next_dest.exists() {
                    std::fs::create_dir_all(&next_dest)?;
                }
                copy_missing_entries(dir, &next_dest)?;
            }
            DirEntry::File(file) => {
                let Some(name) = file.path().file_name() else {
                    continue;
                };
                let out_path = destination.join(name);
                if !out_path.exists() {
                    tracing::debug!("Writing file: {}", out_path.display());
                    std::fs::write(out_path, file.contents())?;
                }
            }
        }
    }
    Ok(())
}

#[derive(Debug, Deserialize, Default)]
struct SkillFrontmatter {
    #[serde(default)]
    platforms: Vec<String>,
    #[serde(default)]
    deps: Vec<String>,
    #[serde(default)]
    compatibility: SkillCompatibility,
    #[serde(default)]
    metadata: SkillFrontmatterMetadata,
}

#[derive(Debug, Deserialize, Default)]
struct SkillCompatibility {
    #[serde(default)]
    os: Vec<String>,
    #[serde(default)]
    deps: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
struct SkillFrontmatterMetadata {
    #[serde(default)]
    openclaw: Option<OpenClawMetadata>,
    #[serde(default)]
    clawdbot: Option<OpenClawMetadata>,
}

#[derive(Debug, Deserialize, Default)]
struct OpenClawMetadata {
    #[serde(default)]
    os: Vec<String>,
    #[serde(default)]
    requires: Option<RequiresMetadata>,
}

#[derive(Debug, Deserialize, Default)]
struct RequiresMetadata {
    #[serde(default)]
    bins: Vec<String>,
}

fn parse_frontmatter(content: &str) -> Option<SkillFrontmatter> {
    let trimmed = content.trim_start_matches('\u{feff}');
    let rest = trimmed.strip_prefix("---\n")?;
    let end_idx = rest.find("\n---\n").or_else(|| rest.find("\n...\n"))?;
    let yaml = &rest[..end_idx];
    serde_yaml::from_str(yaml).ok()
}

fn skill_skip_reason(content: &str) -> Option<String> {
    let fm = parse_frontmatter(content)?;
    let mut supported = fm.platforms;
    supported.extend(fm.compatibility.os);
    if let Some(meta) = fm
        .metadata
        .openclaw
        .as_ref()
        .or(fm.metadata.clawdbot.as_ref())
    {
        supported.extend(meta.os.iter().cloned());
    }
    supported.sort();
    supported.dedup();
    if !platform_allowed(&supported) {
        return Some(format!(
            "unsupported platform (current: {}, supported: {})",
            current_platform(),
            supported.join(", ")
        ));
    }

    let mut deps = fm.deps;
    deps.extend(fm.compatibility.deps);
    if let Some(meta) = fm
        .metadata
        .openclaw
        .as_ref()
        .or(fm.metadata.clawdbot.as_ref())
    {
        if let Some(requires) = &meta.requires {
            deps.extend(requires.bins.iter().cloned());
        }
    }
    deps.sort();
    deps.dedup();
    let missing: Vec<String> = deps.into_iter().filter(|d| !command_exists(d)).collect();
    if !missing.is_empty() {
        return Some(format!("missing dependencies: {}", missing.join(", ")));
    }
    None
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

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "microclaw_builtin_skills_test_{}",
            uuid::Uuid::new_v4()
        ))
    }

    fn cleanup(path: &Path) {
        let _ = std::fs::remove_dir_all(path);
    }

    #[test]
    fn test_ensure_builtin_skills_writes_missing_files() {
        let root = temp_root();
        let skills_root = root.join("skills");
        ensure_builtin_skills(&skills_root).unwrap();
        let sample = skills_root.join("pdf").join("SKILL.md");
        assert!(sample.exists());
        let content = std::fs::read_to_string(sample).unwrap();
        assert!(!content.trim().is_empty());
        cleanup(&root);
    }

    #[test]
    fn test_ensure_builtin_skills_does_not_overwrite_existing_file() {
        let root = temp_root();
        let skills_root = root.join("skills");
        let custom_pdf = skills_root.join("pdf");
        std::fs::create_dir_all(&custom_pdf).unwrap();
        let custom_file = custom_pdf.join("SKILL.md");
        std::fs::write(&custom_file, "custom-content").unwrap();

        ensure_builtin_skills(&skills_root).unwrap();
        let content = std::fs::read_to_string(custom_file).unwrap();
        assert_eq!(content, "custom-content");
        cleanup(&root);
    }

    #[test]
    fn test_get_file_with_relative_dir_handles_include_dir_subdirs() {
        let pdf_dir = BUILTIN_SKILLS_DIR.get_dir("pdf").unwrap();
        assert!(pdf_dir.get_file("SKILL.md").is_none());
        assert!(get_file_with_relative_dir(pdf_dir, "SKILL.md").is_some());
    }

    #[test]
    fn test_ensure_builtin_skills_includes_new_macos_and_weather_skills() {
        let root = temp_root();
        let skills_root = root.join("skills");
        ensure_builtin_skills(&skills_root).unwrap();

        for skill in ["pdf", "docx", "xlsx", "pptx", "skill-creator"] {
            let skill_file = skills_root.join(skill).join("SKILL.md");
            assert!(skill_file.exists(), "missing built-in skill: {skill}");
            let content = std::fs::read_to_string(skill_file).unwrap();
            assert!(!content.trim().is_empty(), "empty skill file: {skill}");
        }
        #[cfg(not(target_os = "macos"))]
        {
            assert!(!skills_root.join("apple-notes").exists());
            assert!(!skills_root.join("apple-reminders").exists());
            assert!(!skills_root.join("apple-calendar").exists());
        }
        #[cfg(target_os = "macos")]
        {
            if command_exists("memo") {
                assert!(skills_root.join("apple-notes").exists());
            } else {
                assert!(!skills_root.join("apple-notes").exists());
            }
            if command_exists("remindctl") {
                assert!(skills_root.join("apple-reminders").exists());
            } else {
                assert!(!skills_root.join("apple-reminders").exists());
            }
            if command_exists("icalBuddy") {
                assert!(skills_root.join("apple-calendar").exists());
            } else {
                assert!(!skills_root.join("apple-calendar").exists());
            }
        }
        if command_exists("curl") {
            assert!(skills_root.join("find-skills").exists());
            assert!(skills_root.join("weather").exists());
        }

        cleanup(&root);
    }

    #[test]
    fn test_skill_skip_reason_parses_compatibility() {
        let content = r#"---
name: x
description: x
compatibility:
  os: [darwin]
  deps: [curl]
---
body
"#;
        let reason = skill_skip_reason(content);
        if cfg!(target_os = "macos") && command_exists("curl") {
            assert!(reason.is_none());
        } else {
            assert!(reason.is_some());
        }
    }

    #[test]
    fn test_skill_skip_reason_parses_metadata_requires() {
        let content = r#"---
name: x
description: x
metadata:
  clawdbot:
    os: [darwin]
    requires:
      bins: [curl]
---
body
"#;
        let reason = skill_skip_reason(content);
        if cfg!(target_os = "macos") && command_exists("curl") {
            assert!(reason.is_none());
        } else {
            assert!(reason.is_some());
        }
    }
}
