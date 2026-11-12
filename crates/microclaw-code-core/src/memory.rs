//! Project memory: what the agent keeps between sessions of one repository.
//!
//! There are two files:
//!
//! - the **shared** memory `.microclaw/memory.md`, inside the repository and
//!   meant to be committed: facts about the code every contributor benefits
//!   from (how to build and test it, slow tests, conventions, pitfalls);
//! - the **private** memory `~/.mccode/projects/<repo>-<hash>/memory.md`,
//!   outside the repository: this user's preferences and this machine's
//!   setup ("I use nextest", "Docker is not installed here").
//!
//! Both are loaded into the system prompt of trusted projects, which is
//! rebuilt for every turn, so they survive compaction. The private file is
//! keyed by the main repository root, so `--worktree` tasks share it.

use std::path::{Path, PathBuf};

/// The shared memory file, relative to the repository root.
pub const SHARED_FILE: &str = ".microclaw/memory.md";
/// File name of the private memory inside its project directory.
pub const PRIVATE_FILE: &str = "memory.md";
/// Cap on each memory file's text in the system prompt.
pub const MAX_PROMPT_BYTES: usize = 8 * 1024;

/// Short stable key for a repository: `<dir name>-<8 hex of SHA-256(path)>`.
pub fn project_key(root: &Path) -> String {
    use sha2::{Digest, Sha256};
    let name: String = root
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("repo")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let hash = Sha256::digest(root.to_string_lossy().as_bytes());
    let short: String = hash.iter().take(4).map(|b| format!("{b:02x}")).collect();
    format!("{name}-{short}")
}

/// The main repository of `root`: for a linked git worktree, the checkout
/// that owns it; otherwise `root` itself.
pub fn main_repo_root(root: &Path) -> PathBuf {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--path-format=absolute", "--git-common-dir"])
        .current_dir(root)
        .stderr(std::process::Stdio::null())
        .output();
    if let Ok(output) = output
        && output.status.success()
    {
        let common = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
        if common.file_name().is_some_and(|n| n == ".git")
            && let Some(parent) = common.parent()
        {
            return std::fs::canonicalize(parent).unwrap_or_else(|_| parent.to_path_buf());
        }
    }
    root.to_path_buf()
}

/// Private memory of the repository at `root` under `code_home`.
pub fn private_memory_path_in(code_home: &Path, root: &Path) -> PathBuf {
    code_home
        .join("projects")
        .join(project_key(&main_repo_root(root)))
        .join(PRIVATE_FILE)
}

/// Private memory of the repository at `root` (in the Code home).
pub fn private_memory_path(root: &Path) -> PathBuf {
    private_memory_path_in(&crate::home::code_home(), root)
}

fn truncate_to_bytes(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_string();
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n…(truncated)", &text[..end])
}

fn read_trimmed(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let text = text.trim();
    (!text.is_empty()).then(|| truncate_to_bytes(text, MAX_PROMPT_BYTES))
}

/// The `# Project memory` section of the system prompt.
pub fn prompt_section(root: &Path, private: &Path) -> String {
    let mut out = String::from("\n# Project memory\n\n");
    out.push_str(&format!(
        "You keep two memory files for this repository. Shared memory `{SHARED_FILE}` is in the repository and is committed for every contributor: write only facts about the code there. Private memory `{}` is outside the repository and belongs to this user alone: write their personal preferences and facts about this machine there.\n\n",
        private.display()
    ));
    match read_trimmed(&root.join(SHARED_FILE)) {
        Some(text) => out.push_str(&format!("From `{SHARED_FILE}` (shared):\n\n{text}\n\n")),
        None => out.push_str(&format!("There is no `{SHARED_FILE}` yet.\n\n")),
    }
    match read_trimmed(private) {
        Some(text) => out.push_str(&format!("From the private memory:\n\n{text}\n\n")),
        None => out.push_str("The private memory is empty.\n\n"),
    }
    out.push_str(&format!(
        "When you learn something durable that a future session would otherwise rediscover, add one short bullet with the file tools:\n\
- to `{SHARED_FILE}`: how to build or test the repository, slow or flaky tests, a non-obvious convention, a pitfall and its fix;\n\
- to the private memory (absolute path above): how this user likes to work (tools, style, what to avoid) and this machine's setup (installed tools, local services, paths).\n\
When the user states a preference (\"I use nextest\", \"don't run the e2e suite\"), it goes to the private memory, never to the shared file. Keep each file under 60 bullets; update or remove stale ones. Never store secrets in either.\n"
    ));
    out
}

/// One memory imported from another agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedMemory {
    /// Bullet text (one line).
    pub text: String,
    /// Where it came from.
    pub origin: String,
}

/// Claude Code's directory name for a project path: every character other
/// than an ASCII letter or digit becomes `-`.
pub fn claude_project_dir_name(root: &Path) -> String {
    root.to_string_lossy()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

fn one_line(text: &str, max_chars: usize) -> String {
    let joined = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if joined.chars().count() <= max_chars {
        joined
    } else {
        let cut: String = joined.chars().take(max_chars).collect();
        format!("{cut}…")
    }
}

/// Split a Markdown file with optional YAML front matter into
/// (`description`, body).
fn front_matter(text: &str) -> (Option<String>, &str) {
    let Some(rest) = text
        .strip_prefix("---\n")
        .or_else(|| text.strip_prefix("---\r\n"))
    else {
        return (None, text);
    };
    let Some(end) = rest.find("\n---") else {
        return (None, text);
    };
    let header = &rest[..end];
    let body = rest[end + 4..].trim_start_matches(['\r', '\n']);
    let description = header.lines().find_map(|line| {
        line.trim()
            .strip_prefix("description:")
            .map(|d| d.trim().trim_matches(['"', '\'']).to_string())
            .filter(|d| !d.is_empty())
    });
    (description, body)
}

/// Claude Code auto memory of the project at `root`
/// (`~/.claude/projects/<path>/memory/*.md`): one bullet per memory file;
/// the `MEMORY.md` index is used only when there are no topic files.
pub fn claude_memories(home: &Path, root: &Path) -> (Vec<ImportedMemory>, Vec<PathBuf>) {
    let dir = home
        .join(".claude/projects")
        .join(claude_project_dir_name(root))
        .join("memory");
    let mut read = Vec::new();
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return (out, read);
    };
    let mut paths: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.extension().is_some_and(|e| e == "md"))
        .collect();
    paths.sort();
    let index = dir.join("MEMORY.md");
    let topics: Vec<&PathBuf> = paths.iter().filter(|p| **p != index).collect();
    for path in &topics {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        read.push((*path).clone());
        let (description, body) = front_matter(&text);
        let body = one_line(body, 400);
        let line = match description {
            Some(d) if !body.is_empty() => format!("{d}: {body}"),
            Some(d) => d,
            None => body,
        };
        if !line.trim().is_empty() {
            out.push(ImportedMemory {
                text: line,
                origin: path.display().to_string(),
            });
        }
    }
    if topics.is_empty()
        && let Ok(text) = std::fs::read_to_string(&index)
    {
        read.push(index.clone());
        for line in text.lines() {
            let line = line.trim().trim_start_matches(['-', '*']).trim();
            if !line.is_empty() && !line.starts_with('#') {
                out.push(ImportedMemory {
                    text: one_line(line, 400),
                    origin: index.display().to_string(),
                });
            }
        }
    }
    (out, read)
}

/// Codex memories (`~/.codex/memories_v2/*.md`, or `~/.codex/memories/*.md`
/// for older profiles). Codex keeps them per machine, not per project, so
/// only list items are taken, one bullet each.
pub fn codex_memories(home: &Path) -> (Vec<ImportedMemory>, Vec<PathBuf>) {
    let mut read = Vec::new();
    let mut out = Vec::new();
    for dir in ["memories_v2", "memories"] {
        let Ok(entries) = std::fs::read_dir(home.join(".codex").join(dir)) else {
            continue;
        };
        let mut paths: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_file() && p.extension().is_some_and(|e| e == "md"))
            .collect();
        paths.sort();
        for path in paths {
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            read.push(path.clone());
            for line in text.lines() {
                let trimmed = line.trim_start();
                let Some(item) = trimmed
                    .strip_prefix("- ")
                    .or_else(|| trimmed.strip_prefix("* "))
                else {
                    continue;
                };
                let item = one_line(item, 400);
                if !item.is_empty() {
                    out.push(ImportedMemory {
                        text: item,
                        origin: path.display().to_string(),
                    });
                }
            }
        }
        if !read.is_empty() {
            break;
        }
    }
    (out, read)
}

/// Append `memories` to the private memory file at `path` as bullets,
/// skipping ones already there. Returns how many were added.
pub fn append_bullets(path: &Path, memories: &[ImportedMemory]) -> std::io::Result<usize> {
    let existing = std::fs::read_to_string(path).unwrap_or_default();
    let mut text = existing.clone();
    let mut added = 0;
    for memory in memories {
        let bullet = format!("- {}", memory.text);
        if existing.lines().any(|l| l.trim() == bullet) || text.lines().any(|l| l == bullet) {
            continue;
        }
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(&bullet);
        text.push('\n');
        added += 1;
    }
    if added > 0 {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, text)?;
    }
    Ok(added)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_memory_lives_outside_the_repository() {
        let home = tempfile::tempdir().unwrap();
        let repo = tempfile::tempdir().unwrap();
        let path = private_memory_path_in(home.path(), repo.path());
        assert!(path.starts_with(home.path().join("projects")));
        assert!(!path.starts_with(repo.path()));
        assert_eq!(path.file_name().unwrap(), PRIVATE_FILE);
        // Stable for the same repository.
        assert_eq!(path, private_memory_path_in(home.path(), repo.path()));
    }

    #[test]
    fn worktrees_share_the_main_repository_memory() {
        let repo = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(repo.path()).unwrap();
        let git = |args: &[&str]| {
            std::process::Command::new("git")
                .args(args)
                .current_dir(&root)
                .output()
                .unwrap()
        };
        if !git(&["init", "-q"]).status.success() {
            return; // no git here
        }
        git(&[
            "-c",
            "user.email=t@t",
            "-c",
            "user.name=t",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "i",
        ]);
        let wt = root.join("wt");
        git(&["worktree", "add", "-q", wt.to_str().unwrap()]);
        assert_eq!(main_repo_root(&wt), root);
        assert_eq!(main_repo_root(&root), root);
    }

    #[test]
    fn prompt_names_both_files_and_their_roles() {
        let repo = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(repo.path().join(".microclaw")).unwrap();
        std::fs::write(repo.path().join(SHARED_FILE), "- run `make db` first").unwrap();
        let private = repo.path().join("private.md");
        std::fs::write(&private, "- user prefers cargo nextest").unwrap();
        let text = prompt_section(repo.path(), &private);
        assert!(text.contains("run `make db` first"));
        assert!(text.contains("user prefers cargo nextest"));
        assert!(text.contains(&private.display().to_string()));
        assert!(text.contains("never to the shared file"));
        std::fs::remove_file(&private).unwrap();
        assert!(prompt_section(repo.path(), &private).contains("The private memory is empty."));
    }

    #[test]
    fn imports_claude_auto_memory() {
        let home = tempfile::tempdir().unwrap();
        let root = Path::new("/Users/me/src/my.app");
        let dir = home
            .path()
            .join(".claude/projects/-Users-me-src-my-app/memory");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("MEMORY.md"), "- [Tests](tests.md) — nextest\n").unwrap();
        std::fs::write(
            dir.join("tests.md"),
            "---\nname: tests\ndescription: Uses cargo nextest\nmetadata:\n  type: feedback\n---\n\nRun `cargo nextest run`,\nnot cargo test.\n",
        )
        .unwrap();
        let (memories, read) = claude_memories(home.path(), root);
        assert_eq!(read.len(), 1);
        assert_eq!(
            memories[0].text,
            "Uses cargo nextest: Run `cargo nextest run`, not cargo test."
        );
    }

    #[test]
    fn imports_codex_memory_items_and_dedups() {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join(".codex/memories_v2");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("summary.md"),
            "# Memories\n\nSome prose.\n- Prefers small commits\n* Uses pnpm\n",
        )
        .unwrap();
        let (memories, _) = codex_memories(home.path());
        let texts: Vec<&str> = memories.iter().map(|m| m.text.as_str()).collect();
        assert_eq!(texts, ["Prefers small commits", "Uses pnpm"]);
        let target = home.path().join("p/memory.md");
        assert_eq!(append_bullets(&target, &memories).unwrap(), 2);
        assert_eq!(append_bullets(&target, &memories).unwrap(), 0);
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "- Prefers small commits\n- Uses pnpm\n"
        );
    }
}
