//! Session index for MicroClaw Code.
//!
//! The conversation itself (messages, tool calls, results) lives in the Agent
//! Engine's SQLite store under the session name; this index only records which
//! sessions belong to which project, with a title and timestamps, so `mccode`
//! can list and resume them. It is metadata, not a second transcript.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Sessions kept per project; older ones drop out of the index (their
/// history stays in the engine store).
const MAX_SESSIONS_PER_PROJECT: usize = 50;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRecord {
    pub id: String,
    pub project: String,
    pub title: String,
    pub created_at: String,
    pub updated_at: String,
    pub turns: u32,
}

/// Stable short id for a project root.
pub fn project_id(root: &Path) -> String {
    Sha256::digest(root.to_string_lossy().as_bytes())
        .iter()
        .take(6)
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[derive(Debug, Clone)]
pub struct SessionIndex {
    path: PathBuf,
    records: Vec<SessionRecord>,
}

impl SessionIndex {
    pub fn default_path() -> PathBuf {
        crate::home::code_home().join("sessions.json")
    }

    pub fn load(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let records = std::fs::read_to_string(&path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default();
        Self { path, records }
    }

    fn save(&self) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let text = serde_json::to_string_pretty(&self.records).map_err(std::io::Error::other)?;
        let temporary = self.path.with_extension("json.tmp");
        std::fs::write(&temporary, text)?;
        std::fs::rename(&temporary, &self.path)
    }

    /// Start a new session for `root`.
    pub fn create(&mut self, root: &Path) -> std::io::Result<SessionRecord> {
        let now = chrono::Utc::now();
        let record = SessionRecord {
            id: format!("code-{}-{:x}", project_id(root), now.timestamp_millis()),
            project: root.to_string_lossy().into_owned(),
            title: String::new(),
            created_at: now.to_rfc3339(),
            updated_at: now.to_rfc3339(),
            turns: 0,
        };
        self.records.push(record.clone());
        self.save()?;
        Ok(record)
    }

    /// Record a finished turn; the first prompt becomes the title.
    pub fn touch(&mut self, id: &str, prompt: &str) -> std::io::Result<()> {
        let Some(record) = self.records.iter_mut().find(|r| r.id == id) else {
            return Ok(());
        };
        if record.title.is_empty() {
            let title: String = prompt.split_whitespace().collect::<Vec<_>>().join(" ");
            record.title = title.chars().take(80).collect();
        }
        record.turns += 1;
        record.updated_at = chrono::Utc::now().to_rfc3339();
        let project = record.project.clone();
        let mut mine: Vec<_> = self
            .records
            .iter()
            .filter(|r| r.project == project)
            .map(|r| (r.updated_at.clone(), r.id.clone()))
            .collect();
        if mine.len() > MAX_SESSIONS_PER_PROJECT {
            mine.sort();
            let drop: Vec<_> = mine[..mine.len() - MAX_SESSIONS_PER_PROJECT]
                .iter()
                .map(|(_, id)| id.clone())
                .collect();
            self.records.retain(|r| !drop.contains(&r.id));
        }
        self.save()
    }

    /// Sessions of `root`, most recent first.
    pub fn for_project(&self, root: &Path) -> Vec<SessionRecord> {
        let root = root.to_string_lossy();
        let mut records: Vec<_> = self
            .records
            .iter()
            .filter(|r| r.project == root)
            .cloned()
            .collect();
        records.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
        records
    }

    /// Every session of every project, most recent first.
    pub fn all(&self) -> Vec<SessionRecord> {
        let mut records = self.records.clone();
        records.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
        records
    }

    pub fn get(&self, id: &str) -> Option<&SessionRecord> {
        self.records.iter().find(|r| r.id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sessions_are_scoped_titled_and_ordered() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.json");
        let mut index = SessionIndex::load(&path);
        let a = index.create(Path::new("/repo/a")).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let b = index.create(Path::new("/repo/a")).unwrap();
        index.create(Path::new("/repo/other")).unwrap();
        index.touch(&a.id, "  fix   the parser bug ").unwrap();
        index.touch(&a.id, "second prompt").unwrap();

        let reloaded = SessionIndex::load(&path);
        let listed = reloaded.for_project(Path::new("/repo/a"));
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].id, a.id, "most recently used first");
        assert_eq!(listed[0].title, "fix the parser bug");
        assert_eq!(listed[0].turns, 2);
        assert_eq!(listed[1].id, b.id);
        assert!(a.id.starts_with("code-"));

        let everything = reloaded.all();
        assert_eq!(everything.len(), 3, "all() spans every project");
        assert_eq!(everything[0].id, a.id, "most recently used first");
        assert!(everything.iter().any(|r| r.project == "/repo/other"));
    }
}
