//! Git helpers: a working-tree fingerprint used to decide whether a turn
//! changed anything (including edits made through `bash`, not only the file
//! tools).

use std::path::Path;
use std::process::Command;

use sha2::{Digest, Sha256};

fn git(root: &Path, args: &[&str]) -> Option<Vec<u8>> {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    output.status.success().then_some(output.stdout)
}

/// Untracked files above this size are fingerprinted by metadata.
const FINGERPRINT_READ_LIMIT: u64 = 1024 * 1024;

/// Untracked paths listed by name in a review; the rest are counted per
/// top-level directory.
const REVIEW_UNTRACKED_LISTED: usize = 100;

/// Fingerprint of the working tree relative to `HEAD` (tracked changes and
/// untracked files). `None` outside a git repository.
pub fn worktree_fingerprint(root: &Path) -> Option<String> {
    let status = git(
        root,
        &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    )?;
    let diff = git(root, &["diff", "--no-ext-diff", "--binary", "HEAD"]).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(&status);
    hasher.update([0u8]);
    hasher.update(&diff);
    // Untracked files are listed by name only; hash their contents too so a
    // second edit to a new file is still noticed.
    // Large files (build output in a repository without a .gitignore) are
    // fingerprinted by size and modification time instead of being read on
    // every turn.
    for entry in status.split(|b| *b == 0) {
        let Some(path) = entry.strip_prefix(b"?? ") else {
            continue;
        };
        let full = root.join(String::from_utf8_lossy(path).as_ref());
        let Ok(meta) = std::fs::metadata(&full) else {
            continue;
        };
        if meta.len() > FINGERPRINT_READ_LIMIT {
            hasher.update(meta.len().to_le_bytes());
            if let Ok(modified) = meta.modified()
                && let Ok(since) = modified.duration_since(std::time::UNIX_EPOCH)
            {
                hasher.update(since.as_nanos().to_le_bytes());
            }
        } else if let Ok(bytes) = std::fs::read(&full) {
            hasher.update(&bytes);
        }
    }
    Some(
        hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    )
}

/// The uncommitted changes for a review: `git diff HEAD` (or the plain
/// diff before the first commit) plus the untracked files, capped at
/// `limit` bytes. `None` outside git or when nothing changed.
pub fn review_diff(root: &Path, limit: usize) -> Option<String> {
    let diff = git(root, &["diff", "--no-ext-diff", "HEAD"])
        .or_else(|| git(root, &["diff", "--no-ext-diff"]))?;
    let untracked = git(root, &["ls-files", "--others", "--exclude-standard"]).unwrap_or_default();
    let diff = String::from_utf8_lossy(&diff);
    let untracked = String::from_utf8_lossy(&untracked);
    if diff.trim().is_empty() && untracked.trim().is_empty() {
        return None;
    }
    let mut out = String::new();
    if !diff.trim().is_empty() {
        out.push_str(&diff);
    }
    if !untracked.trim().is_empty() {
        out.push_str("\nUntracked files (read them to review their content):\n");
        let paths: Vec<&str> = untracked.lines().collect();
        for path in paths.iter().take(REVIEW_UNTRACKED_LISTED) {
            out.push_str(&format!("  {path}\n"));
        }
        if paths.len() > REVIEW_UNTRACKED_LISTED {
            let mut by_dir: std::collections::BTreeMap<&str, usize> = Default::default();
            for path in &paths[REVIEW_UNTRACKED_LISTED..] {
                let top = path.split('/').next().unwrap_or(path);
                *by_dir.entry(top).or_default() += 1;
            }
            let summary = by_dir
                .iter()
                .map(|(dir, count)| format!("{dir} ({count})"))
                .collect::<Vec<_>>()
                .join(", ");
            out.push_str(&format!(
                "  … and {} more: {summary}\n",
                paths.len() - REVIEW_UNTRACKED_LISTED
            ));
        }
    }
    if out.len() > limit {
        let mut end = limit;
        while !out.is_char_boundary(end) {
            end -= 1;
        }
        out.truncate(end);
        out.push_str("\n… (diff truncated; read the files for the rest)\n");
    }
    Some(out)
}

/// Current branch name, if any.
pub fn branch(root: &Path) -> Option<String> {
    git(root, &["rev-parse", "--abbrev-ref", "HEAD"])
        .map(|out| String::from_utf8_lossy(&out).trim().to_string())
        .filter(|b| !b.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let run = |args: &[&str]| {
            assert!(
                Command::new("git")
                    .args(args)
                    .current_dir(dir.path())
                    .output()
                    .unwrap()
                    .status
                    .success()
            );
        };
        run(&["init", "-q"]);
        std::fs::write(dir.path().join("a.txt"), "1").unwrap();
        run(&["add", "-A"]);
        run(&[
            "-c",
            "user.email=t@t",
            "-c",
            "user.name=t",
            "commit",
            "-qm",
            "init",
        ]);
        dir
    }

    #[test]
    fn fingerprint_changes_with_tracked_and_untracked_edits() {
        let dir = init_repo();
        let clean = worktree_fingerprint(dir.path()).unwrap();
        assert_eq!(worktree_fingerprint(dir.path()).unwrap(), clean);

        std::fs::write(dir.path().join("a.txt"), "2").unwrap();
        let tracked = worktree_fingerprint(dir.path()).unwrap();
        assert_ne!(tracked, clean);

        std::fs::write(dir.path().join("new.txt"), "x").unwrap();
        let untracked = worktree_fingerprint(dir.path()).unwrap();
        assert_ne!(untracked, tracked);
        std::fs::write(dir.path().join("new.txt"), "y").unwrap();
        assert_ne!(worktree_fingerprint(dir.path()).unwrap(), untracked);
        assert!(branch(dir.path()).is_some());
    }

    #[test]
    fn review_diff_summarizes_long_untracked_lists() {
        let dir = init_repo();
        std::fs::create_dir_all(dir.path().join("target/debug")).unwrap();
        for i in 0..(REVIEW_UNTRACKED_LISTED + 30) {
            std::fs::write(dir.path().join(format!("target/debug/f{i:03}")), "x").unwrap();
        }
        let diff = review_diff(dir.path(), 1_000_000).unwrap();
        let listed = diff.lines().filter(|l| l.starts_with("  target/")).count();
        assert_eq!(listed, REVIEW_UNTRACKED_LISTED, "{diff}");
        assert!(diff.contains("… and 30 more: target (30)"), "{diff}");
    }

    #[test]
    fn fingerprint_notices_changes_to_large_untracked_files() {
        let dir = init_repo();
        let big = dir.path().join("big.bin");
        std::fs::write(&big, vec![0u8; (FINGERPRINT_READ_LIMIT + 1) as usize]).unwrap();
        let first = worktree_fingerprint(dir.path()).unwrap();
        std::fs::write(&big, vec![1u8; (FINGERPRINT_READ_LIMIT + 2) as usize]).unwrap();
        assert_ne!(worktree_fingerprint(dir.path()).unwrap(), first);
    }

    #[test]
    fn review_diff_lists_changes_and_untracked_files() {
        let dir = init_repo();
        assert_eq!(review_diff(dir.path(), 10_000), None);
        std::fs::write(dir.path().join("a.txt"), "2").unwrap();
        std::fs::write(dir.path().join("new.txt"), "x").unwrap();
        let diff = review_diff(dir.path(), 10_000).unwrap();
        assert!(diff.contains("-1"), "{diff}");
        assert!(diff.contains("+2"));
        assert!(diff.contains("new.txt"));
        assert!(review_diff(dir.path(), 10).unwrap().contains("truncated"));
    }

    #[test]
    fn outside_git_there_is_no_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(worktree_fingerprint(dir.path()), None);
    }
}
