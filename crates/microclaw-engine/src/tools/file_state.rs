//! Stale-read guard shared by `read_file`, `edit_file` and `write_file`.
//!
//! The tools of one registry share a [`FileStateTable`] that remembers a
//! content fingerprint for every file the agent read or wrote. Before
//! overwriting a file it has seen, a tool compares the current on-disk content
//! with that fingerprint; a mismatch means someone else (the user's editor, a
//! formatter, another process) changed the file after the agent looked at it,
//! and the write is refused so those changes are not silently clobbered.
//! Files the agent never read are not tracked and are unaffected.
//!
//! The table belongs to a `ToolRegistry` rather than the process, so separate
//! runtimes (and tests) never observe each other's reads.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use sha2::{Digest, Sha256};

/// Bound on tracked files; the table is cleared when it grows past this.
const MAX_TRACKED_FILES: usize = 4096;

type Fingerprint = [u8; 32];

/// Content fingerprints of files read or written through one tool registry.
#[derive(Debug, Default)]
pub struct FileStateTable {
    entries: Mutex<HashMap<PathBuf, Fingerprint>>,
}

fn key(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn fingerprint(content: &[u8]) -> Fingerprint {
    Sha256::digest(content).into()
}

impl FileStateTable {
    /// Remember the content the agent has just read or written.
    pub fn record(&self, path: &Path, content: &[u8]) {
        let key = key(path);
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if entries.len() >= MAX_TRACKED_FILES && !entries.contains_key(&key) {
            entries.clear();
        }
        entries.insert(key, fingerprint(content));
    }

    /// Return an error message when `current` differs from the content the
    /// agent last read or wrote at `path`.
    pub fn check_fresh(&self, path: &Path, current: &[u8]) -> Result<(), String> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        match entries.get(&key(path)) {
            Some(known) if *known != fingerprint(current) => Err(format!(
                "{} was modified on disk after you last read it (by the user, an editor, or another process). Read the file again before editing so those changes are not overwritten.",
                path.display()
            )),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn untracked_files_are_always_fresh() {
        let table = FileStateTable::default();
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a.txt");
        std::fs::write(&file, "one").unwrap();
        assert!(table.check_fresh(&file, b"anything").is_ok());
    }

    #[test]
    fn external_change_after_read_is_detected() {
        let table = FileStateTable::default();
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a.txt");
        std::fs::write(&file, "one").unwrap();
        table.record(&file, b"one");
        assert!(table.check_fresh(&file, b"one").is_ok());
        let err = table.check_fresh(&file, b"two").unwrap_err();
        assert!(err.contains("modified on disk"));
    }

    #[test]
    fn tables_are_independent() {
        let a = FileStateTable::default();
        let b = FileStateTable::default();
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a.txt");
        a.record(&file, b"one");
        assert!(b.check_fresh(&file, b"two").is_ok());
    }
}
