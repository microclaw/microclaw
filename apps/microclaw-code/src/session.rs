//! Per-project session naming and the "continue last session" index.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// Stable short id for a project root.
pub fn project_id(root: &Path) -> String {
    let digest = Sha256::digest(root.to_string_lossy().as_bytes());
    digest.iter().take(6).map(|b| format!("{b:02x}")).collect()
}

/// A fresh session name for a project.
pub fn new_session_name(root: &Path) -> String {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!("code-{}-{stamp:x}", project_id(root))
}

/// Remembers the most recent session per project so `--continue` can resume it.
pub struct SessionIndex {
    path: Option<PathBuf>,
    entries: BTreeMap<String, String>,
}

impl SessionIndex {
    pub fn default_path() -> Option<PathBuf> {
        if let Some(dir) = std::env::var_os("MICROCLAW_CODE_HOME") {
            return Some(PathBuf::from(dir).join("sessions.json"));
        }
        dirs::home_dir().map(|home| home.join(".microclaw").join("code").join("sessions.json"))
    }

    pub fn load(path: Option<PathBuf>) -> Self {
        let entries = path
            .as_ref()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default();
        Self { path, entries }
    }

    pub fn last(&self, root: &Path) -> Option<&str> {
        self.entries
            .get(&root.to_string_lossy().to_string())
            .map(String::as_str)
    }

    pub fn remember(&mut self, root: &Path, session: &str) {
        self.entries
            .insert(root.to_string_lossy().to_string(), session.to_string());
        let Some(path) = &self.path else {
            return;
        };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(text) = serde_json::to_string_pretty(&self.entries) {
            let _ = std::fs::write(path, text);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_project_scoped() {
        let a = new_session_name(Path::new("/repo/a"));
        let b = new_session_name(Path::new("/repo/b"));
        assert!(a.starts_with("code-"));
        assert_ne!(a[..17], b[..17]);
        assert_eq!(project_id(Path::new("/repo/a")).len(), 12);
    }

    #[test]
    fn index_persists_last_session() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.json");
        let mut index = SessionIndex::load(Some(path.clone()));
        index.remember(Path::new("/repo"), "code-1");
        let reloaded = SessionIndex::load(Some(path));
        assert_eq!(reloaded.last(Path::new("/repo")), Some("code-1"));
        assert_eq!(reloaded.last(Path::new("/other")), None);
    }
}
