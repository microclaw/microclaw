use crate::session::{WorkCommand, WorkSessionSnapshot, WorkStatus};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Resolve the safe workspace used when Work opens. An available selected
/// project wins; otherwise Work creates and returns its private Work Home.
pub fn startup_workspace(current: &str, work_home: &Path) -> io::Result<(PathBuf, bool)> {
    if !current.is_empty() && Path::new(current).is_dir() {
        return Ok((PathBuf::from(current), false));
    }
    fs::create_dir_all(work_home)?;
    Ok((work_home.to_path_buf(), true))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkSessionSummary {
    pub session_id: String,
    pub task: String,
    pub workspace: String,
    pub status: WorkStatus,
    #[serde(default)]
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    #[serde(default)]
    pub pinned: bool,
}

impl WorkSessionSummary {
    pub fn matches_query(&self, query: &str) -> bool {
        let query = query.trim().to_lowercase();
        query.is_empty()
            || self.task.to_lowercase().contains(&query)
            || self.workspace.to_lowercase().contains(&query)
    }
}

impl From<&WorkSessionSnapshot> for WorkSessionSummary {
    fn from(snapshot: &WorkSessionSnapshot) -> Self {
        Self {
            session_id: snapshot.session_id.clone(),
            task: if snapshot.title.trim().is_empty() {
                snapshot.task.clone()
            } else {
                snapshot.title.clone()
            },
            workspace: snapshot.workspace.clone(),
            status: snapshot.status,
            created_at_ms: snapshot.created_at_ms,
            updated_at_ms: snapshot.updated_at_ms,
            pinned: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct WorkSessionIndex {
    schema_version: u32,
    active_session_id: Option<String>,
    sessions: Vec<WorkSessionSummary>,
}

impl Default for WorkSessionIndex {
    fn default() -> Self {
        Self {
            schema_version: Self::SCHEMA_VERSION,
            active_session_id: None,
            sessions: Vec::new(),
        }
    }
}

impl WorkSessionIndex {
    const SCHEMA_VERSION: u32 = 1;
}

#[derive(Debug, Clone)]
pub struct WorkSessionStore {
    root: PathBuf,
}

#[derive(Debug)]
pub struct WorkSessionLoad {
    pub snapshot: WorkSessionSnapshot,
    pub recovery_message: Option<String>,
}

impl WorkSessionStore {
    pub const MAX_SESSIONS: usize = 100;

    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn load_active_or_create(&self) -> io::Result<WorkSessionSnapshot> {
        Ok(self.load_active_or_recover()?.snapshot)
    }

    pub fn load_active_or_recover(&self) -> io::Result<WorkSessionLoad> {
        let (mut index, mut recovery_message) = match self.load_index() {
            Ok(index) => (index, None),
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                let backup = quarantine_file(&self.index_path())?;
                let rebuilt = self.rebuild_index()?;
                self.save_index(&rebuilt)?;
                (
                    rebuilt,
                    Some(format!(
                        "Recovered a damaged conversation index. The original was preserved at {}.",
                        backup.display()
                    )),
                )
            }
            Err(error) => return Err(error),
        };
        if let Some(session_id) = index.active_session_id {
            match self.load(&session_id) {
                Ok(mut snapshot) => {
                    if matches!(snapshot.status, WorkStatus::Running | WorkStatus::Verifying) {
                        snapshot
                            .apply(WorkCommand::MarkInterrupted)
                            .map_err(io::Error::other)?;
                        self.save(&snapshot)?;
                    }
                    return Ok(WorkSessionLoad {
                        snapshot,
                        recovery_message,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                    let backup = quarantine_file(&self.session_path(&session_id))?;
                    index = self.rebuild_index()?;
                    self.save_index(&index)?;
                    recovery_message = Some(format!(
                        "Recovered from a damaged conversation. The original was preserved at {}.",
                        backup.display()
                    ));
                    if let Some(next_id) = index.active_session_id.as_deref() {
                        let snapshot = self.open(next_id)?;
                        return Ok(WorkSessionLoad {
                            snapshot,
                            recovery_message,
                        });
                    }
                }
                Err(error) => return Err(error),
            }
        }

        let snapshot = WorkSessionSnapshot::new("");
        self.save(&snapshot)?;
        Ok(WorkSessionLoad {
            snapshot,
            recovery_message,
        })
    }

    pub fn create(&self, workspace: impl Into<String>) -> io::Result<WorkSessionSnapshot> {
        let snapshot = WorkSessionSnapshot::new(workspace);
        self.save(&snapshot)?;
        Ok(snapshot)
    }

    pub fn load(&self, session_id: &str) -> io::Result<WorkSessionSnapshot> {
        validate_session_id(session_id)?;
        WorkSessionSnapshot::load(self.session_path(session_id))
    }

    pub fn open(&self, session_id: &str) -> io::Result<WorkSessionSnapshot> {
        let mut snapshot = self.load(session_id)?;
        if matches!(snapshot.status, WorkStatus::Running | WorkStatus::Verifying) {
            snapshot
                .apply(WorkCommand::MarkInterrupted)
                .map_err(io::Error::other)?;
        }
        snapshot.touch();
        self.save(&snapshot)?;
        Ok(snapshot)
    }

    pub fn save(&self, snapshot: &WorkSessionSnapshot) -> io::Result<()> {
        validate_session_id(&snapshot.session_id)?;
        fs::create_dir_all(self.sessions_dir())?;
        snapshot.save(self.session_path(&snapshot.session_id))?;

        let mut index = self.load_index()?;
        let pinned = index
            .sessions
            .iter()
            .find(|entry| entry.session_id == snapshot.session_id)
            .is_some_and(|entry| entry.pinned);
        index
            .sessions
            .retain(|entry| entry.session_id != snapshot.session_id);
        let mut summary = WorkSessionSummary::from(snapshot);
        summary.pinned = pinned;
        index.sessions.push(summary);
        sort_session_summaries(&mut index.sessions);
        index.sessions.truncate(Self::MAX_SESSIONS);
        index.active_session_id = Some(snapshot.session_id.clone());
        self.save_index(&index)
    }

    pub fn list(&self) -> io::Result<Vec<WorkSessionSummary>> {
        Ok(self.load_index()?.sessions)
    }

    pub fn set_pinned(&self, session_id: &str, pinned: bool) -> io::Result<()> {
        validate_session_id(session_id)?;
        let mut index = self.load_index()?;
        let entry = index
            .sessions
            .iter_mut()
            .find(|entry| entry.session_id == session_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Work session not found"))?;
        entry.pinned = pinned;
        sort_session_summaries(&mut index.sessions);
        self.save_index(&index)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn load_index(&self) -> io::Result<WorkSessionIndex> {
        let path = self.index_path();
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(WorkSessionIndex::default());
            }
            Err(error) => return Err(error),
        };
        let mut index: WorkSessionIndex = serde_json::from_slice(&bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if index.schema_version != WorkSessionIndex::SCHEMA_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unsupported work session index schema {}, expected {}",
                    index.schema_version,
                    WorkSessionIndex::SCHEMA_VERSION
                ),
            ));
        }
        for entry in &mut index.sessions {
            if entry.created_at_ms == 0
                && let Ok(snapshot) = self.load(&entry.session_id)
            {
                entry.created_at_ms = snapshot.created_at_ms;
            }
        }
        sort_session_summaries(&mut index.sessions);
        Ok(index)
    }

    fn save_index(&self, index: &WorkSessionIndex) -> io::Result<()> {
        fs::create_dir_all(&self.root)?;
        let bytes = serde_json::to_vec_pretty(index).map_err(io::Error::other)?;
        atomic_write(&self.index_path(), &bytes)
    }

    fn rebuild_index(&self) -> io::Result<WorkSessionIndex> {
        let mut sessions = Vec::new();
        let entries = match fs::read_dir(self.sessions_dir()) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(WorkSessionIndex::default());
            }
            Err(error) => return Err(error),
        };
        for entry in entries {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            if let Ok(snapshot) = WorkSessionSnapshot::load(&path) {
                let matching_file = path.file_stem().and_then(|value| value.to_str())
                    == Some(snapshot.session_id.as_str());
                if matching_file && validate_session_id(&snapshot.session_id).is_ok() {
                    sessions.push(WorkSessionSummary::from(&snapshot));
                }
            }
        }
        sort_session_summaries(&mut sessions);
        sessions.truncate(Self::MAX_SESSIONS);
        Ok(WorkSessionIndex {
            schema_version: WorkSessionIndex::SCHEMA_VERSION,
            active_session_id: sessions.first().map(|entry| entry.session_id.clone()),
            sessions,
        })
    }

    fn sessions_dir(&self) -> PathBuf {
        self.root.join("sessions")
    }

    fn session_path(&self, session_id: &str) -> PathBuf {
        self.sessions_dir().join(format!("{session_id}.json"))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }
}

fn validate_session_id(session_id: &str) -> io::Result<()> {
    if session_id.is_empty()
        || !session_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Work session id",
        ));
    }
    Ok(())
}

fn sort_session_summaries(sessions: &mut [WorkSessionSummary]) {
    sessions.sort_by(|a, b| {
        b.pinned
            .cmp(&a.pinned)
            .then_with(|| b.created_at_ms.cmp(&a.created_at_ms))
            .then_with(|| b.session_id.cmp(&a.session_id))
    });
}

fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, bytes)?;
    fs::rename(temporary, path)
}

fn quarantine_file(path: &Path) -> io::Result<PathBuf> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("data");
    for attempt in 0..100_u8 {
        let backup = path.with_file_name(format!("{file_name}.corrupt-{timestamp}-{attempt}"));
        if !backup.exists() {
            fs::rename(path, &backup)?;
            return Ok(backup);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a recovery backup path",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_workspace_provisions_work_home_for_first_chat() {
        let directory = tempfile::tempdir().unwrap();
        let work_home = directory.path().join("work-home");

        let (workspace, used_fallback) = startup_workspace("", &work_home).unwrap();

        assert!(used_fallback);
        assert_eq!(workspace, work_home);
        assert!(workspace.is_dir());
    }

    #[test]
    fn startup_workspace_keeps_an_available_project() {
        let directory = tempfile::tempdir().unwrap();
        let project = directory.path().join("project");
        let work_home = directory.path().join("work-home");
        fs::create_dir(&project).unwrap();

        let (workspace, used_fallback) =
            startup_workspace(project.to_str().unwrap(), &work_home).unwrap();

        assert!(!used_fallback);
        assert_eq!(workspace, project);
        assert!(!work_home.exists());
    }

    #[test]
    fn startup_workspace_replaces_an_unavailable_project() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing-project");
        let work_home = directory.path().join("work-home");

        let (workspace, used_fallback) =
            startup_workspace(missing.to_str().unwrap(), &work_home).unwrap();

        assert!(used_fallback);
        assert_eq!(workspace, work_home);
        assert!(workspace.is_dir());
    }

    #[test]
    fn creates_lists_and_reopens_distinct_sessions() {
        let directory = tempfile::tempdir().unwrap();
        let store = WorkSessionStore::new(directory.path());
        let mut first = store.create("").unwrap();
        first.task = "first task".into();
        first.created_at_ms = 10;
        first.updated_at_ms = 100;
        store.save(&first).unwrap();
        let mut second = store.create("").unwrap();
        second.task = "second task".into();
        second.created_at_ms = 20;
        second.updated_at_ms = 20;
        store.save(&second).unwrap();

        let summaries = store.list().unwrap();
        assert_eq!(summaries.len(), 2);
        assert_eq!(summaries[0].task, "second task");
        assert_eq!(store.load(&first.session_id).unwrap().task, "first task");
        assert_eq!(
            store.load_active_or_create().unwrap().session_id,
            second.session_id
        );

        store.open(&first.session_id).unwrap();
        assert_eq!(store.list().unwrap()[0].session_id, second.session_id);
        store.set_pinned(&first.session_id, true).unwrap();
        assert_eq!(store.list().unwrap()[0].session_id, first.session_id);
        store.set_pinned(&first.session_id, false).unwrap();
        assert_eq!(store.list().unwrap()[0].session_id, second.session_id);
    }

    #[test]
    fn recovers_active_execution_as_interrupted() {
        let directory = tempfile::tempdir().unwrap();
        let store = WorkSessionStore::new(directory.path());
        let mut snapshot = store.create("").unwrap();
        snapshot
            .apply(WorkCommand::StartTask {
                task: "running task".into(),
            })
            .unwrap();
        store.save(&snapshot).unwrap();

        let mut recovered = store.load_active_or_create().unwrap();
        assert_eq!(recovered.status, WorkStatus::Interrupted);
        assert!(recovered.composer_draft.is_empty());
        recovered.apply(WorkCommand::RetryTask).unwrap();
        assert_eq!(recovered.status, WorkStatus::Running);
        assert_eq!(recovered.task, "running task");
        assert_eq!(store.list().unwrap()[0].status, WorkStatus::Interrupted);
    }

    #[test]
    fn rejects_session_id_path_traversal() {
        let directory = tempfile::tempdir().unwrap();
        let store = WorkSessionStore::new(directory.path());
        let error = store.load("../../outside").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn recent_index_is_bounded() {
        let directory = tempfile::tempdir().unwrap();
        let store = WorkSessionStore::new(directory.path());
        for index in 0..(WorkSessionStore::MAX_SESSIONS + 5) {
            let mut snapshot = store.create("").unwrap();
            snapshot.task = format!("task {index}");
            snapshot.updated_at_ms = index as u64;
            store.save(&snapshot).unwrap();
        }

        let summaries = store.list().unwrap();
        assert_eq!(summaries.len(), WorkSessionStore::MAX_SESSIONS);
        assert_eq!(summaries[0].task, "task 104");
    }

    #[test]
    fn summary_search_matches_title_and_workspace_case_insensitively() {
        let summary = WorkSessionSummary {
            session_id: "session-1".into(),
            task: "Refine Native Settings".into(),
            workspace: "/tmp/MicroClaw".into(),
            status: WorkStatus::Completed,
            created_at_ms: 1,
            updated_at_ms: 1,
            pinned: false,
        };

        assert!(summary.matches_query("native"));
        assert!(summary.matches_query(" MICROCLAW "));
        assert!(summary.matches_query(""));
        assert!(!summary.matches_query("server migration"));
    }

    #[test]
    fn damaged_index_is_preserved_and_rebuilt_from_sessions() {
        let directory = tempfile::tempdir().unwrap();
        let store = WorkSessionStore::new(directory.path());
        let mut session = store.create("/tmp/project").unwrap();
        session.task = "recover me".into();
        session.updated_at_ms = 42;
        store.save(&session).unwrap();
        fs::write(store.index_path(), b"not json").unwrap();

        let loaded = store.load_active_or_recover().unwrap();

        assert_eq!(loaded.snapshot.session_id, session.session_id);
        assert!(loaded.recovery_message.unwrap().contains("index"));
        assert!(fs::read_dir(directory.path()).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("index.json.corrupt-")
        }));
    }

    #[test]
    fn damaged_active_session_is_preserved_and_falls_back_to_valid_history() {
        let directory = tempfile::tempdir().unwrap();
        let store = WorkSessionStore::new(directory.path());
        let mut older = store.create("/tmp/project").unwrap();
        older.task = "valid conversation".into();
        older.updated_at_ms = 10;
        store.save(&older).unwrap();
        let mut active = store.create("/tmp/project").unwrap();
        active.task = "damaged conversation".into();
        active.updated_at_ms = 20;
        store.save(&active).unwrap();
        fs::write(store.session_path(&active.session_id), b"not json").unwrap();

        let loaded = store.load_active_or_recover().unwrap();

        assert_eq!(loaded.snapshot.session_id, older.session_id);
        assert!(loaded.recovery_message.unwrap().contains("conversation"));
        assert!(fs::read_dir(store.sessions_dir()).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(&format!("{}.json.corrupt-", active.session_id))
        }));
    }
}
