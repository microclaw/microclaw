//! Lazily inject subdirectory `AGENTS.md` / `CLAUDE.md` / `.cursorrules`
//! context when the agent starts working in a new area of the codebase.
//!
//! At session start, microclaw loads the project-root context once into the
//! system prompt. But the model only sees subdirectory-specific guidance if
//! the user mentioned it. This tracker watches tool calls (`read_file`,
//! `edit_file`, `glob`, `grep`, `bash`'s `cwd` etc.), notices when the agent
//! reaches into a new directory, and appends that subtree's nearest hint file
//! to the tool result.
//!
//! Hermes reference: `agent/subdirectory_hints.py:SubdirectoryHintTracker`.
//! Inspired upstream by Block/goose.
//!
//! The tracker remembers which directories it has already emitted for, so a
//! single hint file is only injected once per chat turn. The tracker is
//! constructed per agent loop.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

const HINT_FILENAMES: &[&str] = &[
    "AGENTS.md",
    "agents.md",
    "CLAUDE.md",
    "claude.md",
    ".cursorrules",
];

/// Tool argument keys that typically carry a filesystem path.
const PATH_ARG_KEYS: &[&str] = &["path", "file_path", "workdir", "cwd"];

/// Tools whose primary argument is a shell command — we extract path-shaped
/// tokens from it.
const COMMAND_TOOLS: &[&str] = &["bash"];

const MAX_HINT_CHARS: usize = 8_000;
const MAX_ANCESTOR_WALK: usize = 5;

pub struct SubdirectoryHintTracker {
    working_dir: PathBuf,
    loaded_dirs: HashSet<PathBuf>,
}

impl SubdirectoryHintTracker {
    pub fn new(working_dir: PathBuf) -> Self {
        let working_dir = working_dir.canonicalize().unwrap_or(working_dir);
        let mut loaded_dirs = HashSet::new();
        // The root is loaded as part of the system prompt — don't re-inject it.
        loaded_dirs.insert(working_dir.clone());
        Self {
            working_dir,
            loaded_dirs,
        }
    }

    /// Called after a tool executes. Returns formatted hint text to append
    /// to the tool's result content, or `None` if no new hint applies.
    pub fn check_tool_call(&mut self, tool_name: &str, args: &serde_json::Value) -> Option<String> {
        let dirs = self.extract_directories(tool_name, args);
        if dirs.is_empty() {
            return None;
        }
        let mut found = Vec::new();
        for d in dirs {
            if let Some(hint) = self.load_hints_for_directory(&d) {
                found.push(hint);
            }
        }
        if found.is_empty() {
            None
        } else {
            Some(format!("\n\n{}", found.join("\n\n")))
        }
    }

    fn extract_directories(&self, tool_name: &str, args: &serde_json::Value) -> Vec<PathBuf> {
        let mut candidates: HashSet<PathBuf> = HashSet::new();
        let obj = match args.as_object() {
            Some(o) => o,
            None => return Vec::new(),
        };
        for key in PATH_ARG_KEYS {
            if let Some(s) = obj.get(*key).and_then(|v| v.as_str()) {
                self.add_path_candidate(s, &mut candidates);
            }
        }
        if COMMAND_TOOLS.contains(&tool_name) {
            if let Some(cmd) = obj.get("command").and_then(|v| v.as_str()) {
                self.extract_paths_from_command(cmd, &mut candidates);
            }
        }
        candidates.into_iter().collect()
    }

    fn add_path_candidate(&self, raw: &str, candidates: &mut HashSet<PathBuf>) {
        if raw.trim().is_empty() {
            return;
        }
        let raw = raw.trim();
        // Skip URLs and repository specs.
        if raw.starts_with("http://") || raw.starts_with("https://") || raw.starts_with("git@") {
            return;
        }
        let mut p = PathBuf::from(raw);
        if !p.is_absolute() {
            p = self.working_dir.join(p);
        }
        let resolved = p.canonicalize().unwrap_or(p);
        // Use parent if it points at a file (or looks like one).
        let mut current = if resolved.is_file() || resolved.extension().is_some() {
            resolved
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or(resolved)
        } else {
            resolved
        };
        for _ in 0..MAX_ANCESTOR_WALK {
            if self.loaded_dirs.contains(&current) {
                break;
            }
            if current.is_dir() {
                candidates.insert(current.clone());
            }
            let parent = current.parent().map(|p| p.to_path_buf());
            match parent {
                Some(p) if p != current => current = p,
                _ => break,
            }
        }
    }

    fn extract_paths_from_command(&self, cmd: &str, candidates: &mut HashSet<PathBuf>) {
        for token in cmd.split_whitespace() {
            if token.starts_with('-') {
                continue;
            }
            if !token.contains('/') && !token.contains('.') {
                continue;
            }
            self.add_path_candidate(token, candidates);
        }
    }

    fn load_hints_for_directory(&mut self, directory: &Path) -> Option<String> {
        // Mark loaded BEFORE attempting the read so a missing-file directory
        // isn't re-walked next call.
        self.loaded_dirs.insert(directory.to_path_buf());
        for filename in HINT_FILENAMES {
            let hint_path = directory.join(filename);
            if !hint_path.is_file() {
                continue;
            }
            let content = match std::fs::read_to_string(&hint_path) {
                Ok(s) => s.trim().to_string(),
                Err(_) => continue,
            };
            if content.is_empty() {
                continue;
            }
            let total_chars = content.chars().count();
            let truncated = if total_chars > MAX_HINT_CHARS {
                let prefix: String = content.chars().take(MAX_HINT_CHARS).collect();
                format!(
                    "{}\n\n[...truncated {}: {} chars total]",
                    prefix, filename, total_chars
                )
            } else {
                content
            };
            let display = hint_path
                .strip_prefix(&self.working_dir)
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|_| hint_path.to_string_lossy().into_owned());
            return Some(format!(
                "[Subdirectory context discovered: {display}]\n{truncated}"
            ));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tmp_root() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("microclaw_subhint_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.canonicalize().unwrap()
    }

    #[test]
    fn loads_subdir_agents_md_on_first_touch() {
        let root = tmp_root();
        let sub = root.join("backend");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("AGENTS.md"), "# Backend conventions\nUse async.").unwrap();
        std::fs::write(sub.join("main.py"), "print('hi')").unwrap();

        let mut tracker = SubdirectoryHintTracker::new(root.clone());
        let hint = tracker
            .check_tool_call("read_file", &json!({"path": "backend/main.py"}))
            .expect("should emit a hint");
        assert!(hint.contains("Backend conventions"));
        assert!(hint.contains("AGENTS.md") || hint.contains("backend"));

        // Second touch in same dir → no duplicate hint.
        let again = tracker.check_tool_call("read_file", &json!({"path": "backend/main.py"}));
        assert!(again.is_none());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn ignores_root_directory() {
        let root = tmp_root();
        std::fs::write(root.join("AGENTS.md"), "root context").unwrap();
        std::fs::write(root.join("a.txt"), "data").unwrap();
        let mut tracker = SubdirectoryHintTracker::new(root.clone());
        let hint = tracker.check_tool_call("read_file", &json!({"path": "a.txt"}));
        assert!(
            hint.is_none(),
            "root context should be loaded by system prompt, not hint"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn walks_ancestors_until_hint_found() {
        let root = tmp_root();
        let deep = root.join("a/b/c");
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(root.join("a/AGENTS.md"), "ancestor hint").unwrap();
        std::fs::write(deep.join("file.txt"), "hi").unwrap();

        let mut tracker = SubdirectoryHintTracker::new(root.clone());
        let hint = tracker
            .check_tool_call("read_file", &json!({"path": "a/b/c/file.txt"}))
            .expect("should walk up to a/AGENTS.md");
        assert!(hint.contains("ancestor hint"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn extracts_paths_from_bash_command() {
        let root = tmp_root();
        let sub = root.join("frontend");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("CLAUDE.md"), "frontend rules").unwrap();
        std::fs::write(sub.join("page.tsx"), "x").unwrap();

        let mut tracker = SubdirectoryHintTracker::new(root.clone());
        let hint = tracker
            .check_tool_call("bash", &json!({"command": "cat frontend/page.tsx"}))
            .expect("should pull frontend hint from bash command");
        assert!(hint.contains("frontend rules"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn truncates_oversized_hint() {
        let root = tmp_root();
        let sub = root.join("big");
        std::fs::create_dir_all(&sub).unwrap();
        let huge = "x".repeat(MAX_HINT_CHARS + 5_000);
        std::fs::write(sub.join("AGENTS.md"), &huge).unwrap();
        std::fs::write(sub.join("file"), "y").unwrap();

        let mut tracker = SubdirectoryHintTracker::new(root.clone());
        let hint = tracker
            .check_tool_call("read_file", &json!({"path": "big/file"}))
            .unwrap();
        assert!(hint.contains("[...truncated"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn no_path_arg_returns_none() {
        let root = tmp_root();
        let mut tracker = SubdirectoryHintTracker::new(root.clone());
        let hint = tracker.check_tool_call("web_search", &json!({"query": "rust"}));
        assert!(hint.is_none());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn url_paths_are_skipped() {
        let root = tmp_root();
        let mut tracker = SubdirectoryHintTracker::new(root.clone());
        let hint = tracker.check_tool_call(
            "web_fetch",
            &json!({"url": "https://example.com/some/path"}),
        );
        assert!(hint.is_none());
        let _ = std::fs::remove_dir_all(&root);
    }
}
