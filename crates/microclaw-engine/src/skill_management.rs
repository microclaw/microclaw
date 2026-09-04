//! Shared Skill package lifecycle used by SDK and product UIs.

use std::fs;
use std::path::{Path, PathBuf};

use crate::clawhub::install::InstallOptions;
use crate::clawhub::service::{ClawHubGateway, RegistryClawHubGateway};
use crate::config::Config;
use crate::skills::{validate_agentskills_name, SkillManager};
use crate::tools::{sync_skills::SyncSkillsTool, Tool};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillInstallOutcome {
    pub message: String,
    pub warnings: Vec<String>,
}

/// Install or update a Skill from a local directory, GitHub reference, or ClawHub slug.
pub async fn install_skill(
    config: &Config,
    manager: &SkillManager,
    reference: &str,
) -> Result<SkillInstallOutcome, String> {
    let reference = reference.trim();
    if reference.is_empty() {
        return Err("skill source is required".into());
    }
    let skills_dir = PathBuf::from(config.skills_data_dir());
    fs::create_dir_all(&skills_dir).map_err(|error| error.to_string())?;

    let outcome = if Path::new(reference).is_dir() {
        SkillInstallOutcome {
            message: import_local_skill(Path::new(reference), &skills_dir)?,
            warnings: Vec::new(),
        }
    } else if reference.contains("github.com/") || reference.split('/').count() >= 3 {
        let result = SyncSkillsTool::new(&config.skills_data_dir())
            .execute(serde_json::json!({"skill_name": reference}))
            .await;
        if result.is_error {
            return Err(result.content);
        }
        SkillInstallOutcome {
            message: result.content,
            warnings: Vec::new(),
        }
    } else {
        let result = RegistryClawHubGateway::from_config(config)
            .install(
                reference,
                None,
                &skills_dir,
                &config.clawhub_lockfile_path(),
                &InstallOptions {
                    force: true,
                    skip_gates: false,
                    skip_security: false,
                },
            )
            .await
            .map_err(|error| error.to_string())?;
        if !result.success {
            return Err(result.message);
        }
        SkillInstallOutcome {
            message: result.message,
            warnings: result.warnings,
        }
    };
    manager.reload();
    Ok(outcome)
}

/// Recoverably remove an unmanaged Skill by moving it under `.archived/`.
pub fn archive_skill(manager: &SkillManager, name: &str) -> Result<PathBuf, String> {
    validate_agentskills_name(name)?;
    if !manager.has_skill(name) {
        return Err(format!("Skill not found: {name}"));
    }
    let source = manager.skills_dir().join(name);
    let archive_root = manager.skills_dir().join(".archived");
    fs::create_dir_all(&archive_root).map_err(|error| error.to_string())?;
    let suffix = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
    let target = archive_root.join(format!("{name}-{suffix}"));
    fs::rename(&source, &target).map_err(|error| error.to_string())?;
    manager.reload();
    Ok(target)
}

fn import_local_skill(source: &Path, skills_dir: &Path) -> Result<String, String> {
    let name = source
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "invalid local Skill directory name".to_string())?;
    validate_agentskills_name(name)?;
    if !source.join("SKILL.md").is_file() {
        return Err("local Skill directory must contain SKILL.md".into());
    }
    let staging = skills_dir.join(format!(".{name}.sdk-import"));
    let backup = skills_dir.join(format!(".{name}.sdk-backup"));
    let _ = fs::remove_dir_all(&staging);
    let _ = fs::remove_dir_all(&backup);
    copy_skill_tree(source, &staging)?;
    if let Err(error) = scan_skill_tree(&staging) {
        let _ = fs::remove_dir_all(&staging);
        return Err(error);
    }
    let target = skills_dir.join(name);
    if target.exists() {
        fs::rename(&target, &backup).map_err(|error| error.to_string())?;
    }
    if let Err(error) = fs::rename(&staging, &target) {
        if backup.exists() {
            let _ = fs::rename(&backup, &target);
        }
        return Err(error.to_string());
    }
    let _ = fs::remove_dir_all(&backup);
    Ok(format!(
        "Imported local Skill {name} from {}",
        source.display()
    ))
}

fn copy_skill_tree(source: &Path, target: &Path) -> Result<(), String> {
    fs::create_dir_all(target).map_err(|error| error.to_string())?;
    for entry in fs::read_dir(source).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let file_type = entry.file_type().map_err(|error| error.to_string())?;
        if file_type.is_symlink() {
            return Err(format!(
                "local Skill contains unsupported symlink: {}",
                entry.path().display()
            ));
        }
        let destination = target.join(entry.file_name());
        if file_type.is_dir() {
            copy_skill_tree(&entry.path(), &destination)?;
        } else if file_type.is_file() {
            fs::copy(entry.path(), destination).map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}

fn scan_skill_tree(root: &Path) -> Result<(), String> {
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).map_err(|error| error.to_string())? {
            let entry = entry.map_err(|error| error.to_string())?;
            let path = entry.path();
            let kind = entry.file_type().map_err(|error| error.to_string())?;
            if kind.is_dir() {
                pending.push(path);
            } else if kind.is_file() {
                let Ok(content) = fs::read_to_string(&path) else {
                    continue;
                };
                if let Err(reason) = microclaw_core::injection_scan::scan_for_injection(&content) {
                    return Err(format!(
                        "refusing local Skill import: {} was flagged by the security scan ({reason})",
                        path.strip_prefix(root).unwrap_or(&path).display()
                    ));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_import_is_staged_scanned_and_archived_recoverably() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("review-skill");
        let skills = directory.path().join("skills");
        let runtime = directory.path().join("runtime");
        fs::create_dir_all(&source).unwrap();
        fs::write(
            source.join("SKILL.md"),
            "---\nname: review-skill\ndescription: review code\n---\nReview carefully.\n",
        )
        .unwrap();
        let mut config = Config::test_defaults();
        config.skills_dir = Some(skills.display().to_string());
        config.data_dir = runtime.display().to_string();
        let manager = SkillManager::from_skills_and_runtime(
            &config.skills_data_dir(),
            &config.runtime_data_dir(),
        );
        let outcome = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(install_skill(&config, &manager, source.to_str().unwrap()))
            .unwrap();
        assert!(outcome.message.contains("review-skill"));
        assert!(manager.has_skill("review-skill"));
        let archived = archive_skill(&manager, "review-skill").unwrap();
        assert!(archived.join("SKILL.md").is_file());
        assert!(!manager.has_skill("review-skill"));
    }
}
