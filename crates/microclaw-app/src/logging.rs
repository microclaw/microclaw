use anyhow::{Context, Result};
use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tracing_subscriber::fmt::writer::MakeWriter;

pub const LOG_FILE_PREFIX: &str = "microclaw-";
pub const LOG_FILE_SUFFIX: &str = ".log";
pub const LOG_RETENTION_DAYS: i64 = 30;

pub fn init_logging(runtime_data_dir: &str) -> Result<()> {
    let log_dir = PathBuf::from(runtime_data_dir).join("logs");
    fs::create_dir_all(&log_dir)
        .with_context(|| format!("Failed to create log directory: {}", log_dir.display()))?;
    cleanup_old_logs(&log_dir, Utc::now(), LOG_RETENTION_DAYS)?;

    let writer = HourlyLogWriter::new(log_dir, LOG_RETENTION_DAYS)?;
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .with_ansi(false)
        .with_writer(writer)
        .init();

    Ok(())
}

pub fn init_console_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();
}

#[derive(Debug)]
struct HourlyState {
    current_hour_key: String,
    file: File,
}

#[derive(Clone, Debug)]
struct HourlyLogWriter {
    log_dir: PathBuf,
    retention_days: i64,
    state: Arc<Mutex<HourlyState>>,
}

impl HourlyLogWriter {
    fn new(log_dir: PathBuf, retention_days: i64) -> Result<Self> {
        let now = Utc::now();
        let hour_key = hour_key(now);
        let file = open_log_file(&log_dir, &hour_key)?;
        let state = HourlyState {
            current_hour_key: hour_key,
            file,
        };
        Ok(Self {
            log_dir,
            retention_days,
            state: Arc::new(Mutex::new(state)),
        })
    }
}

impl<'a> MakeWriter<'a> for HourlyLogWriter {
    type Writer = HourlyLogGuard;

    fn make_writer(&'a self) -> Self::Writer {
        HourlyLogGuard {
            log_dir: self.log_dir.clone(),
            retention_days: self.retention_days,
            state: self.state.clone(),
        }
    }
}

struct HourlyLogGuard {
    log_dir: PathBuf,
    retention_days: i64,
    state: Arc<Mutex<HourlyState>>,
}

impl Write for HourlyLogGuard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let now = Utc::now();
        let now_key = hour_key(now);
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("failed to lock log writer"))?;

        if state.current_hour_key != now_key {
            state.file.flush()?;
            state.file = open_log_file(&self.log_dir, &now_key)?;
            state.current_hour_key = now_key;
            let _ = cleanup_old_logs(&self.log_dir, now, self.retention_days);
        }

        state.file.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("failed to lock log writer"))?;
        state.file.flush()
    }
}

fn hour_key(now: DateTime<Utc>) -> String {
    now.format("%Y-%m-%d-%H").to_string()
}

fn log_file_path(log_dir: &Path, hour: &str) -> PathBuf {
    log_dir.join(format!("{LOG_FILE_PREFIX}{hour}{LOG_FILE_SUFFIX}"))
}

fn open_log_file(log_dir: &Path, hour: &str) -> io::Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file_path(log_dir, hour))
}

pub fn cleanup_old_logs(log_dir: &Path, now: DateTime<Utc>, retention_days: i64) -> Result<()> {
    let cutoff = now - Duration::days(retention_days);
    let entries = match fs::read_dir(log_dir) {
        Ok(v) => v,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("Failed to read {}", log_dir.display())),
    };

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(file_name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        let Some(log_time) = parse_log_filename_time(file_name) else {
            continue;
        };
        if log_time < cutoff {
            let _ = fs::remove_file(&path);
        }
    }
    Ok(())
}

fn parse_log_filename_time(file_name: &str) -> Option<DateTime<Utc>> {
    if !(file_name.starts_with(LOG_FILE_PREFIX) && file_name.ends_with(LOG_FILE_SUFFIX)) {
        return None;
    }
    let body = &file_name[LOG_FILE_PREFIX.len()..file_name.len() - LOG_FILE_SUFFIX.len()];
    let naive =
        NaiveDateTime::parse_from_str(&format!("{body}:00:00"), "%Y-%m-%d-%H:%M:%S").ok()?;
    Some(DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc))
}

pub fn list_log_files_sorted(log_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let entries = match fs::read_dir(log_dir) {
        Ok(v) => v,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(files),
        Err(e) => return Err(e).with_context(|| format!("Failed to read {}", log_dir.display())),
    };
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|v| v.to_str()) else {
            continue;
        };
        if parse_log_filename_time(name).is_some() {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

pub fn read_last_lines_from_logs(log_dir: &Path, max_lines: usize) -> Result<Vec<String>> {
    let mut queue: VecDeque<String> = VecDeque::new();
    for file in list_log_files_sorted(log_dir)? {
        let content = fs::read_to_string(&file)
            .with_context(|| format!("Failed to read {}", file.display()))?;
        for line in content.lines() {
            queue.push_back(line.to_string());
            if queue.len() > max_lines {
                queue.pop_front();
            }
        }
    }
    Ok(queue.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn test_dir() -> PathBuf {
        std::env::temp_dir().join(format!("microclaw_logging_test_{}", Uuid::new_v4()))
    }

    #[test]
    fn test_parse_log_filename_time() {
        assert!(parse_log_filename_time("microclaw-2026-02-08-10.log").is_some());
        assert!(parse_log_filename_time("microclaw-2026-02-08.log").is_none());
        assert!(parse_log_filename_time("other-2026-02-08-10.log").is_none());
    }

    #[test]
    fn test_cleanup_old_logs_keeps_recent_removes_old() {
        let dir = test_dir();
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("microclaw-2025-01-01-00.log"), "old").unwrap();
        fs::write(dir.join("microclaw-2026-02-08-10.log"), "new").unwrap();

        let now = DateTime::parse_from_rfc3339("2026-02-08T11:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        cleanup_old_logs(&dir, now, 30).unwrap();

        assert!(!dir.join("microclaw-2025-01-01-00.log").exists());
        assert!(dir.join("microclaw-2026-02-08-10.log").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_read_last_lines_from_logs() {
        let dir = test_dir();
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("microclaw-2026-02-08-09.log"), "a\nb\n").unwrap();
        fs::write(dir.join("microclaw-2026-02-08-10.log"), "c\nd\n").unwrap();

        let lines = read_last_lines_from_logs(&dir, 3).unwrap();
        assert_eq!(lines, vec!["b", "c", "d"]);
        let _ = fs::remove_dir_all(&dir);
    }
}
