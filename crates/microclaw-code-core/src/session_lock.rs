//! One front end drives a session at a time.
//!
//! The TUI, `-p` and the desktop app all share `~/.mccode`, so the same
//! session can be opened twice; two drivers would interleave turns and
//! overwrite each other's history. Whoever drives a session holds
//! `~/.mccode/sessions/<id>.lock` (pid, front end, start time and a random
//! token). A lock whose process is gone is stale and is replaced silently; a
//! live one is replaced only on an explicit take-over, after which the
//! previous holder sees [`SessionLock::check`] fail and stops driving.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Who holds a session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockInfo {
    pub pid: u32,
    /// `tui`, `print`, `desktop`, …
    pub front_end: String,
    pub since: String,
    pub token: String,
}

impl LockInfo {
    /// One line for the user: "the desktop app (pid 123) since 10:42".
    pub fn describe(&self) -> String {
        let who = match self.front_end.as_str() {
            "desktop" => "the MicroClaw Code app".to_string(),
            "tui" => "mccode".to_string(),
            "print" => "mccode -p".to_string(),
            other => other.to_string(),
        };
        let since = chrono::DateTime::parse_from_rfc3339(&self.since)
            .map(|t| {
                t.with_timezone(&chrono::Local)
                    .format("%Y-%m-%d %H:%M")
                    .to_string()
            })
            .unwrap_or_else(|_| self.since.clone());
        format!("{who} (pid {}) since {since}", self.pid)
    }
}

/// What holds a session right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockState {
    Free,
    Held(LockInfo),
    /// The holder's process is gone.
    Stale(LockInfo),
}

/// The lock file of session `id` under `home` (`~/.mccode`).
pub fn lock_path(home: &Path, id: &str) -> PathBuf {
    let safe: String = id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    home.join("sessions").join(format!("{safe}.lock"))
}

fn read(path: &Path) -> Option<LockInfo> {
    serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

/// Whether process `pid` still runs.
pub fn process_alive(pid: u32) -> bool {
    if pid == std::process::id() {
        return true;
    }
    #[cfg(unix)]
    {
        // `kill -0` probes without signalling; it fails for a missing pid
        // (and for one we may not signal, which then counts as alive below).
        match std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .output()
        {
            Ok(out) if out.status.success() => true,
            Ok(out) => String::from_utf8_lossy(&out.stderr)
                .to_ascii_lowercase()
                .contains("not permitted"),
            Err(_) => true,
        }
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Who holds session `id` under `home`.
pub fn inspect(home: &Path, id: &str) -> LockState {
    match read(&lock_path(home, id)) {
        None => LockState::Free,
        Some(info) if process_alive(info.pid) => LockState::Held(info),
        Some(info) => LockState::Stale(info),
    }
}

/// A held session lock; released when dropped (unless taken over since).
#[derive(Debug)]
pub struct SessionLock {
    path: PathBuf,
    session_id: String,
    info: LockInfo,
}

fn new_token() -> String {
    use sha2::{Digest, Sha256};
    let seed = format!(
        "{}-{}-{:?}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default(),
        std::thread::current().id()
    );
    Sha256::digest(seed.as_bytes())
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect()
}

impl SessionLock {
    /// Take the lock of session `id` for `front_end`. A live holder is
    /// returned as the error unless `take_over`; a stale one is replaced.
    pub fn acquire(
        home: &Path,
        id: &str,
        front_end: &str,
        take_over: bool,
    ) -> Result<Self, LockError> {
        let path = lock_path(home, id);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(LockError::Io)?;
        }
        let info = LockInfo {
            pid: std::process::id(),
            front_end: front_end.to_string(),
            since: chrono::Utc::now().to_rfc3339(),
            token: new_token(),
        };
        let text = serde_json::to_string(&info).map_err(|e| LockError::Io(e.into()))?;
        // Fast path: nobody holds it.
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                use std::io::Write;
                file.write_all(text.as_bytes()).map_err(LockError::Io)?;
                return Ok(Self {
                    path,
                    session_id: id.to_string(),
                    info,
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(LockError::Io(e)),
        }
        if let Some(holder) = read(&path)
            && process_alive(holder.pid)
            && !take_over
        {
            return Err(LockError::Held(holder));
        }
        let temporary = path.with_extension(format!("lock.{}", info.token));
        std::fs::write(&temporary, text).map_err(LockError::Io)?;
        std::fs::rename(&temporary, &path).map_err(LockError::Io)?;
        Ok(Self {
            path,
            session_id: id.to_string(),
            info,
        })
    }

    /// The session this lock is for.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn info(&self) -> &LockInfo {
        &self.info
    }

    /// `Err` with the new holder when another front end took the session
    /// over; a removed lock file is quietly recreated.
    pub fn check(&self) -> Result<(), LockInfo> {
        match read(&self.path) {
            Some(holder) if holder.token == self.info.token => Ok(()),
            Some(holder) if process_alive(holder.pid) => Err(holder),
            _ => {
                if let Ok(text) = serde_json::to_string(&self.info) {
                    let _ = std::fs::write(&self.path, text);
                }
                Ok(())
            }
        }
    }
}

impl Drop for SessionLock {
    fn drop(&mut self) {
        if read(&self.path).is_some_and(|h| h.token == self.info.token) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[derive(Debug)]
pub enum LockError {
    /// Another live front end drives the session.
    Held(LockInfo),
    Io(std::io::Error),
}

impl std::fmt::Display for LockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Held(holder) => write!(f, "this session is open in {}", holder.describe()),
            Self::Io(e) => write!(f, "could not lock the session: {e}"),
        }
    }
}

impl std::error::Error for LockError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn dead_pid() -> u32 {
        // A process that has exited and been reaped.
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        pid
    }

    #[test]
    fn second_holder_is_refused_until_released() {
        let home = tempfile::tempdir().unwrap();
        let first = SessionLock::acquire(home.path(), "code-a", "tui", false).unwrap();
        match SessionLock::acquire(home.path(), "code-a", "desktop", false) {
            Err(LockError::Held(holder)) => {
                assert_eq!(holder.front_end, "tui");
                assert_eq!(holder.pid, std::process::id());
            }
            other => panic!("expected Held, got {other:?}"),
        }
        assert!(matches!(inspect(home.path(), "code-a"), LockState::Held(_)));
        drop(first);
        assert_eq!(inspect(home.path(), "code-a"), LockState::Free);
        SessionLock::acquire(home.path(), "code-a", "desktop", false).unwrap();
    }

    #[test]
    fn take_over_hands_the_session_to_the_new_front_end() {
        let home = tempfile::tempdir().unwrap();
        let old = SessionLock::acquire(home.path(), "code-b", "tui", false).unwrap();
        assert!(old.check().is_ok());
        let new = SessionLock::acquire(home.path(), "code-b", "desktop", true).unwrap();
        let holder = old.check().unwrap_err();
        assert_eq!(holder.front_end, "desktop");
        // The old holder going away leaves the new lock in place.
        drop(old);
        assert!(new.check().is_ok());
        assert!(
            matches!(inspect(home.path(), "code-b"), LockState::Held(h) if h.front_end == "desktop")
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_lock_left_by_a_dead_process_is_stale_and_replaced() {
        let home = tempfile::tempdir().unwrap();
        let path = lock_path(home.path(), "code-c");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let info = LockInfo {
            pid: dead_pid(),
            front_end: "tui".into(),
            since: chrono::Utc::now().to_rfc3339(),
            token: "old".into(),
        };
        std::fs::write(&path, serde_json::to_string(&info).unwrap()).unwrap();
        assert!(matches!(
            inspect(home.path(), "code-c"),
            LockState::Stale(_)
        ));
        let lock = SessionLock::acquire(home.path(), "code-c", "desktop", false).unwrap();
        assert_eq!(lock.info().front_end, "desktop");
    }

    #[test]
    fn ids_cannot_escape_the_sessions_directory() {
        let path = lock_path(Path::new("/h"), "../../etc/passwd");
        assert!(path.starts_with("/h/sessions"));
        assert_eq!(path.file_name().unwrap(), ".._.._etc_passwd.lock");
    }
}
