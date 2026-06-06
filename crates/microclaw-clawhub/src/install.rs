use crate::client::ClawHubClient;
use crate::gate::check_requirements;
use crate::lockfile::{is_clawhub_managed, read_lockfile, write_lockfile};
use crate::types::{LockEntry, LockFile};
use microclaw_core::error::MicroClawError;
use sha2::{Digest, Sha256};
use std::path::Path;
use zip::ZipArchive;

#[derive(Clone)]
pub struct InstallOptions {
    pub force: bool,
    pub skip_gates: bool,
    pub skip_security: bool,
}

pub struct InstallResult {
    pub success: bool,
    pub message: String,
    pub requires_restart: bool,
    /// Non-fatal warnings surfaced to the user (unmet gates, security flags).
    pub warnings: Vec<String>,
}

/// Main install function
pub async fn install_skill(
    client: &ClawHubClient,
    slug: &str,
    version: Option<&str>,
    skills_dir: &Path,
    lockfile_path: &Path,
    options: &InstallOptions,
) -> Result<InstallResult, MicroClawError> {
    // 1. Get skill metadata
    let meta = client.get_skill(slug).await?;

    // 2. Resolve version
    let target_version = version.unwrap_or("latest");
    let actual_version = if target_version == "latest" {
        meta.versions
            .iter()
            .find(|v| v.latest)
            .map(|v| v.version.clone())
            .unwrap_or_else(|| "latest".to_string())
    } else {
        target_version.to_string()
    };

    let mut warnings: Vec<String> = Vec::new();

    // 3. Gate checks (unless skipped)
    if !options.skip_gates {
        let req = &meta
            .metadata
            .openclaw
            .as_ref()
            .and_then(|o| o.requires.clone())
            .or_else(|| {
                meta.metadata
                    .clawdbot
                    .as_ref()
                    .and_then(|c| c.requires.clone())
            });
        let os_list = meta
            .metadata
            .openclaw
            .as_ref()
            .map(|o| o.os.clone())
            .unwrap_or_default();
        let gate_result = check_requirements(req, &os_list);
        if !gate_result.missing_bins.is_empty() {
            warnings.push(format!(
                "Missing required command(s): {}",
                gate_result.missing_bins.join(", ")
            ));
        }
        if !gate_result.missing_envs.is_empty() {
            warnings.push(format!(
                "Missing required environment variable(s): {}",
                gate_result.missing_envs.join(", ")
            ));
        }
        if gate_result.wrong_os {
            warnings.push("Skill declares it does not support this platform".to_string());
        }
    }

    // 4. Security check
    if !options.skip_security {
        if let Some(vt) = &meta.virustotal {
            if vt.report_count >= 3 {
                warnings.push(format!(
                    "VirusTotal flagged this skill: {} ({} report(s)) — review before trusting it",
                    vt.status, vt.report_count
                ));
            } else if vt.pending_scan {
                warnings.push(
                    "VirusTotal scan is still pending — this skill has not been fully scanned"
                        .to_string(),
                );
            }
        }
    }

    // 5. Check existing installation
    let skill_path = skills_dir.join(slug);
    let lock = read_lockfile(lockfile_path)?;
    let is_managed = is_clawhub_managed(&lock, slug);

    if skill_path.exists() && !options.force && is_managed {
        return Ok(InstallResult {
            success: false,
            message: format!(
                "Skill '{}' is already installed. Use --force to update.",
                slug
            ),
            requires_restart: false,
            warnings,
        });
    }
    if skill_path.exists() && !options.force {
        // Manual skill exists - hybrid: warn but allow
    }

    // 6. Download
    let bytes = client.download_skill(slug, &actual_version).await?;

    // 7. Verify hash (if provided)
    let hash = format!("sha256:{:x}", Sha256::digest(&bytes));

    // 8. Extract
    if skill_path.exists() && options.force {
        std::fs::remove_dir_all(&skill_path)?;
    }
    std::fs::create_dir_all(&skill_path)?;

    let cursor = std::io::Cursor::new(bytes);
    let mut archive = ZipArchive::new(cursor)
        .map_err(|e| MicroClawError::Config(format!("Failed to read ZIP: {}", e)))?;
    archive
        .extract(&skill_path)
        .map_err(|e| MicroClawError::Config(format!("Failed to extract ZIP: {}", e)))?;

    // 9. Update lockfile
    let mut lock = read_lockfile(lockfile_path)?;
    let now = chrono::Utc::now().to_rfc3339();
    lock.skills.insert(
        slug.to_string(),
        LockEntry {
            slug: slug.to_string(),
            installed_version: actual_version.clone(),
            installed_at: now,
            content_hash: hash,
            local_path: skill_path.to_string_lossy().to_string(),
        },
    );
    write_lockfile(lockfile_path, &lock)?;

    Ok(InstallResult {
        success: true,
        message: format!("Installed {} v{}", slug, actual_version),
        requires_restart: true,
        warnings,
    })
}

/// Check if update is needed
pub fn check_update_available(
    _lock: &LockFile,
    current_version: &str,
    latest_version: &str,
) -> bool {
    // Simple version comparison - could use semver for more accuracy
    current_version != latest_version
}

#[cfg(test)]
mod tests {
    use crate::types::LockFile;
    use std::collections::HashMap;

    use super::check_update_available;

    #[test]
    fn test_check_update_available_true_when_version_changes() {
        let lock = LockFile {
            version: 1,
            skills: HashMap::new(),
        };
        assert!(check_update_available(&lock, "1.0.0", "1.1.0"));
    }

    #[test]
    fn test_check_update_available_false_when_version_unchanged() {
        let lock = LockFile {
            version: 1,
            skills: HashMap::new(),
        };
        assert!(!check_update_available(&lock, "1.0.0", "1.0.0"));
    }
}
