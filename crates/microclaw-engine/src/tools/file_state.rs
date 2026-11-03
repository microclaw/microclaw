//! Stale-read guard shared by `read_file`, `edit_file` and `write_file`.
//!
//! The tools remember a content fingerprint for every file the agent read or
//! wrote. Before overwriting a file it has seen, a tool compares the current
//! on-disk content with that fingerprint; a mismatch means someone else (the
//! user's editor, a formatter, another process) changed the file after the
//! agent looked at it, and the write is refused so those changes are not
//! silently clobbered. Files the agent never read are not tracked and are
//! unaffected.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use sha2::{Digest, Sha256};

/// Bound on tracked files; the table is cleared when it grows past this.
const MAX_TRACKED_FILES: usize = 4096;

type Fingerprint = [u8; 32];

fn table() -> &'static Mutex<HashMap<PathBuf, Fingerprint>> {
    static TABLE: OnceLock<Mutex<HashMap<PathBuf, Fingerprint>>> = OnceLock::new();
    TABLE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn key(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn fingerprint(content: &[u8]) -> Fingerprint {
    Sha256::digest(content).into()
}

/// Remember the content the agent has just read or written.
pub fn record(path: &Path, content: &[u8]) {
    let key = key(path);
    let mut table = table().lock().unwrap_or_else(|e| e.into_inner());
    if table.len() >= MAX_TRACKED_FILES && !table.contains_key(&key) {
        table.clear();
    }
    table.insert(key, fingerprint(content));
}

/// Return an error message when `current` differs from the content the agent
/// last read or wrote at `path`.
pub fn check_fresh(path: &Path, current: &[u8]) -> Result<(), String> {
    let table = table().lock().unwrap_or_else(|e| e.into_inner());
    match table.get(&key(path)) {
        Some(known) if *known != fingerprint(current) => Err(format!(
            "{} was modified on disk after you last read it (by the user, an editor, or another process). Read the file again before editing so those changes are not overwritten.",
            path.display()
        )),
        _ => Ok(()),
    }
}

/// Forget a path, e.g. after it was deleted.
#[cfg(test)]
pub fn forget(path: &Path) {
    let mut table = table().lock().unwrap_or_else(|e| e.into_inner());
    table.remove(&key(path));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn untracked_files_are_always_fresh() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a.txt");
        std::fs::write(&file, "one").unwrap();
        assert!(check_fresh(&file, b"anything").is_ok());
    }

    #[test]
    fn external_change_after_read_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a.txt");
        std::fs::write(&file, "one").unwrap();
        record(&file, b"one");
        assert!(check_fresh(&file, b"one").is_ok());
        let err = check_fresh(&file, b"two").unwrap_err();
        assert!(err.contains("modified on disk"));
        forget(&file);
        assert!(check_fresh(&file, b"two").is_ok());
    }
}
