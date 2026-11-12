//! The app's own state (recently opened projects) in
//! `~/.mccode/desktop/state.json`, next to everything else Code keeps.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Projects remembered in the sidebar.
const MAX_RECENT: usize = 20;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopState {
    /// Most recent first.
    #[serde(default)]
    pub recent_projects: Vec<PathBuf>,
}

impl DesktopState {
    pub fn default_path() -> PathBuf {
        microclaw_code_core::home::code_home()
            .join("desktop")
            .join("state.json")
    }

    pub fn load(path: &Path) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let temporary = path.with_extension("json.tmp");
        std::fs::write(&temporary, serde_json::to_string_pretty(self)?)?;
        std::fs::rename(&temporary, path)
    }

    /// Move `root` to the top of the recent list.
    pub fn opened(&mut self, root: &Path) {
        self.recent_projects.retain(|p| p != root);
        self.recent_projects.insert(0, root.to_path_buf());
        self.recent_projects.truncate(MAX_RECENT);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recent_projects_are_ordered_unique_and_saved() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("desktop/state.json");
        let mut state = DesktopState::load(&path);
        state.opened(Path::new("/a"));
        state.opened(Path::new("/b"));
        state.opened(Path::new("/a"));
        state.save(&path).unwrap();
        let loaded = DesktopState::load(&path);
        assert_eq!(
            loaded.recent_projects,
            vec![PathBuf::from("/a"), PathBuf::from("/b")]
        );
    }
}
