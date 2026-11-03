//! Per-user project trust decisions.
//!
//! A project's `.microclaw/project.yaml` is only honoured, and its checks only
//! run automatically, after the user trusted that project. A decision covers
//! the exact project-file content it was made for: if the file changes later
//! (for example after a `git pull`), the project is treated as undecided
//! again. Decisions are stored in the Code home, never in the repository.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TrustEntry {
    trusted: bool,
    decided_at: String,
    /// SHA-256 of `.microclaw/project.yaml` when the decision was made.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    config_sha256: Option<String>,
}

/// The user's standing decision for a project root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustDecision {
    /// Never asked.
    Undecided,
    Trusted,
    Distrusted,
    /// Trusted before, but the project file changed since.
    ConfigChanged,
}

/// Trust decisions keyed by canonical project root.
#[derive(Debug, Clone)]
pub struct TrustStore {
    path: PathBuf,
    entries: BTreeMap<String, TrustEntry>,
}

impl TrustStore {
    /// Default location inside the Code home.
    pub fn default_path() -> PathBuf {
        crate::home::code_home().join("trusted-projects.json")
    }

    pub fn load(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let entries = std::fs::read_to_string(&path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default();
        Self { path, entries }
    }

    fn key(root: &Path) -> String {
        std::fs::canonicalize(root)
            .unwrap_or_else(|_| root.to_path_buf())
            .to_string_lossy()
            .into_owned()
    }

    /// The decision for `root`, given the current project-file hash.
    pub fn decision(&self, root: &Path, config_sha256: Option<&str>) -> TrustDecision {
        match self.entries.get(&Self::key(root)) {
            None => TrustDecision::Undecided,
            Some(entry) if !entry.trusted => TrustDecision::Distrusted,
            Some(entry) if entry.config_sha256.as_deref() != config_sha256 => {
                TrustDecision::ConfigChanged
            }
            Some(_) => TrustDecision::Trusted,
        }
    }

    pub fn is_trusted(&self, root: &Path, config_sha256: Option<&str>) -> bool {
        self.decision(root, config_sha256) == TrustDecision::Trusted
    }

    pub fn set(
        &mut self,
        root: &Path,
        trusted: bool,
        config_sha256: Option<&str>,
    ) -> std::io::Result<()> {
        self.entries.insert(
            Self::key(root),
            TrustEntry {
                trusted,
                decided_at: chrono::Utc::now().to_rfc3339(),
                config_sha256: config_sha256.map(str::to_string),
            },
        );
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let text = serde_json::to_string_pretty(&self.entries).map_err(std::io::Error::other)?;
        std::fs::write(&self.path, text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decisions_persist_and_follow_the_project_file() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let path = dir.path().join("trust.json");
        let mut store = TrustStore::load(&path);
        assert_eq!(store.decision(&repo, None), TrustDecision::Undecided);

        store.set(&repo, true, Some("aaa")).unwrap();
        let reloaded = TrustStore::load(&path);
        assert_eq!(
            reloaded.decision(&repo, Some("aaa")),
            TrustDecision::Trusted
        );
        assert!(reloaded.is_trusted(&repo, Some("aaa")));
        assert_eq!(
            reloaded.decision(&repo, Some("bbb")),
            TrustDecision::ConfigChanged
        );
        assert!(!reloaded.is_trusted(&repo, Some("bbb")));

        let mut store = reloaded;
        store.set(&repo, false, Some("bbb")).unwrap();
        assert_eq!(
            store.decision(&repo, Some("bbb")),
            TrustDecision::Distrusted
        );
        assert_eq!(store.decision(dir.path(), None), TrustDecision::Undecided);
    }
}
