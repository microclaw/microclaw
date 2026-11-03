//! Per-user project trust decisions, shared by the desktop app and `mcdesk`.
//!
//! A project's `.microclaw/project.yaml` is only honoured, and its checks only
//! run automatically, after the user trusted that project root. Decisions are
//! stored outside the repository in the MicroClaw Desktop data directory.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TrustEntry {
    trusted: bool,
    decided_at: String,
}

/// Trust decisions keyed by canonical project root.
#[derive(Debug, Clone)]
pub struct TrustStore {
    path: PathBuf,
    entries: BTreeMap<String, TrustEntry>,
}

impl TrustStore {
    /// Default location inside the MicroClaw Desktop data directory.
    pub fn default_path() -> PathBuf {
        crate::desktop_data_root().join("trusted-projects.json")
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

    /// `Some(decision)` once the user decided; `None` if never asked.
    pub fn decision(&self, root: &Path) -> Option<bool> {
        self.entries
            .get(&Self::key(root))
            .map(|entry| entry.trusted)
    }

    pub fn is_trusted(&self, root: &Path) -> bool {
        self.decision(root).unwrap_or(false)
    }

    pub fn set(&mut self, root: &Path, trusted: bool) -> std::io::Result<()> {
        self.entries.insert(
            Self::key(root),
            TrustEntry {
                trusted,
                decided_at: chrono::Utc::now().to_rfc3339(),
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
    fn decisions_persist_per_root() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let path = dir.path().join("trust.json");
        let mut store = TrustStore::load(&path);
        assert_eq!(store.decision(&repo), None);
        assert!(!store.is_trusted(&repo));
        store.set(&repo, true).unwrap();
        let reloaded = TrustStore::load(&path);
        assert_eq!(reloaded.decision(&repo), Some(true));
        assert!(!reloaded.is_trusted(dir.path()));
    }
}
