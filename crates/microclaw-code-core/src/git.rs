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
    for entry in status.split(|b| *b == 0) {
        if let Some(path) = entry.strip_prefix(b"?? ")
            && let Ok(bytes) = std::fs::read(root.join(String::from_utf8_lossy(path).as_ref()))
        {
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
        for path in untracked.lines() {
            out.push_str(&format!("  {path}\n"));
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
