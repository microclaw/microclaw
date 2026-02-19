use crate::clawhub::types::{LockEntry, LockFile};
use crate::error::MicroClawError;
use std::collections::HashMap;
use std::path::Path;

/// Read lockfile from disk
pub fn read_lockfile(path: &Path) -> Result<LockFile, MicroClawError> {
    if !path.exists() {
        return Ok(LockFile {
            version: 1,
            skills: HashMap::new(),
        });
    }
    let content = std::fs::read_to_string(path)
        .map_err(|e| MicroClawError::Config(format!("Failed to read lockfile: {}", e)))?;
    let lock: LockFile = serde_json::from_str(&content)
        .map_err(|e| MicroClawError::Config(format!("Failed to parse lockfile: {}", e)))?;
    Ok(lock)
}

/// Write lockfile to disk
pub fn write_lockfile(path: &Path, lock: &LockFile) -> Result<(), MicroClawError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| MicroClawError::Config(format!("Failed to create lockfile dir: {}", e)))?;
    }
    let content = serde_json::to_string_pretty(lock)
        .map_err(|e| MicroClawError::Config(format!("Failed to serialize lockfile: {}", e)))?;
    std::fs::write(path, content)
        .map_err(|e| MicroClawError::Config(format!("Failed to write lockfile: {}", e)))?;
    Ok(())
}

/// Check if a skill is managed by ClawHub (in lockfile)
pub fn is_clawhub_managed(lock: &LockFile, slug: &str) -> bool {
    lock.skills.contains_key(slug)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lockfile_missing_returns_empty() {
        let temp_path = std::env::temp_dir().join(format!("nonexistent_{}", uuid::Uuid::new_v4()));
        let lock = read_lockfile(&temp_path).unwrap();
        assert_eq!(lock.version, 1);
        assert!(lock.skills.is_empty());
    }

    #[test]
    fn test_lockfile_roundtrip() {
        let temp_dir = std::env::temp_dir().join(format!("clawhub_test_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let lock_path = temp_dir.join("clawhub.lock.json");

        let mut lock = LockFile {
            version: 1,
            skills: HashMap::new(),
        };
        lock.skills.insert(
            "test-skill".into(),
            LockEntry {
                slug: "test-skill".into(),
                installed_version: "1.0.0".into(),
                installed_at: "2026-02-18T00:00:00Z".into(),
                content_hash: "sha256:abc".into(),
                local_path: "/tmp/test".into(),
            },
        );

        write_lockfile(&lock_path, &lock).unwrap();
        let read = read_lockfile(&lock_path).unwrap();
        assert_eq!(
            read.skills
                .get("test-skill")
                .unwrap()
                .installed_version,
            "1.0.0"
        );

        std::fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_is_clawhub_managed() {
        let mut lock = LockFile {
            version: 1,
            skills: HashMap::new(),
        };
        lock.skills.insert(
            "my-skill".into(),
            LockEntry {
                slug: "my-skill".into(),
                installed_version: "1.0.0".into(),
                installed_at: "2026-02-18T00:00:00Z".into(),
                content_hash: "sha256:abc".into(),
                local_path: "/tmp/test".into(),
            },
        );

        assert!(is_clawhub_managed(&lock, "my-skill"));
        assert!(!is_clawhub_managed(&lock, "other-skill"));
    }
}
