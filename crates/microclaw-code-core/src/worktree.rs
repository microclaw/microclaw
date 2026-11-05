//! Isolated task workspaces (`mccode --worktree`) and pull-request diffs.
//!
//! A task can run in its own git worktree on a new branch `mccode/<name>`, so
//! several tasks run in parallel without touching the main checkout; the
//! result is a branch to review and merge.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Worktrees live under the Code home, one directory per repository.
pub fn worktrees_dir(repo_root: &Path) -> PathBuf {
    use sha2::{Digest, Sha256};
    let name = repo_root
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("repo");
    let hash = Sha256::digest(repo_root.to_string_lossy().as_bytes());
    let short: String = hash.iter().take(4).map(|b| format!("{b:02x}")).collect();
    crate::home::code_home()
        .join("worktrees")
        .join(format!("{name}-{short}"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Worktree {
    pub name: String,
    pub path: PathBuf,
    pub branch: String,
}

fn git(dir: &Path, args: &[&str]) -> anyhow::Result<String> {
    let output = Command::new("git").args(args).current_dir(dir).output()?;
    if !output.status.success() {
        anyhow::bail!(
            "git {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 60
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        && !name.starts_with('.')
}

/// A name for an unnamed task: `task-<unix seconds>`.
pub fn default_name() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("task-{secs}")
}

/// Create worktree `name` of the repository at `repo_root` on a new branch
/// `mccode/<name>` from the current HEAD.
pub fn create(repo_root: &Path, name: &str) -> anyhow::Result<Worktree> {
    create_in(&worktrees_dir(repo_root), repo_root, name)
}

fn create_in(base: &Path, repo_root: &Path, name: &str) -> anyhow::Result<Worktree> {
    if !valid_name(name) {
        anyhow::bail!("invalid worktree name `{name}` (letters, digits, - _ . only)");
    }
    let path = base.join(name);
    if path.exists() {
        anyhow::bail!("worktree `{name}` already exists at {}", path.display());
    }
    std::fs::create_dir_all(path.parent().unwrap_or(&path))?;
    let branch = format!("mccode/{name}");
    git(
        repo_root,
        &[
            "worktree",
            "add",
            "-b",
            &branch,
            &path.to_string_lossy(),
            "HEAD",
        ],
    )?;
    Ok(Worktree {
        name: name.to_string(),
        path,
        branch,
    })
}

/// Worktrees created by MicroClaw Code for this repository.
pub fn list(repo_root: &Path) -> anyhow::Result<Vec<Worktree>> {
    list_in(&worktrees_dir(repo_root), repo_root)
}

fn list_in(base: &Path, repo_root: &Path) -> anyhow::Result<Vec<Worktree>> {
    // git prints resolved paths (macOS: /private/var/… for /var/…).
    let base = std::fs::canonicalize(base).unwrap_or_else(|_| base.to_path_buf());
    let porcelain = git(repo_root, &["worktree", "list", "--porcelain"])?;
    let mut out = Vec::new();
    let mut path: Option<PathBuf> = None;
    for line in porcelain.lines() {
        if let Some(p) = line.strip_prefix("worktree ") {
            path = Some(PathBuf::from(p));
        } else if let Some(b) = line.strip_prefix("branch refs/heads/")
            && let Some(p) = path
                .take()
                .map(|p| std::fs::canonicalize(&p).unwrap_or(p))
                .filter(|p| p.starts_with(&base))
        {
            let name = p
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            out.push(Worktree {
                name,
                path: p,
                branch: b.to_string(),
            });
        }
    }
    Ok(out)
}

/// Remove worktree `name` (refuses when it has uncommitted changes) and its
/// branch when that is merged.
pub fn remove(repo_root: &Path, name: &str) -> anyhow::Result<()> {
    remove_in(&worktrees_dir(repo_root), repo_root, name)
}

fn remove_in(base: &Path, repo_root: &Path, name: &str) -> anyhow::Result<()> {
    let tree = list_in(base, repo_root)?
        .into_iter()
        .find(|t| t.name == name)
        .ok_or_else(|| anyhow::anyhow!("no MicroClaw Code worktree named `{name}`"))?;
    git(
        repo_root,
        &["worktree", "remove", &tree.path.to_string_lossy()],
    )?;
    // `-d` keeps an unmerged branch (and fails quietly here).
    let _ = git(repo_root, &["branch", "-d", &tree.branch]);
    Ok(())
}

/// One line describing what a finished worktree task produced.
pub fn summary(tree: &Worktree, repo_root: &Path) -> String {
    let stat = git(&tree.path, &["diff", "--shortstat", "HEAD"]).unwrap_or_default();
    let commits = git(
        repo_root,
        &["rev-list", "--count", &format!("HEAD..{}", tree.branch)],
    )
    .unwrap_or_else(|_| "0".into());
    let path = tree.path.display();
    let mut next = vec![format!("review with `git -C {path} diff HEAD`")];
    if !stat.is_empty() {
        // The agent leaves its edits uncommitted; merging the branch alone
        // would bring nothing over.
        next.push(format!(
            "commit them there with `git -C {path} add -A && git -C {path} commit -m \"…\"`, then merge with `git merge {}`",
            tree.branch
        ));
    } else if commits != "0" {
        next.push(format!("merge with `git merge {}`", tree.branch));
    }
    next.push(format!(
        "remove with `mccode worktree remove {}`",
        tree.name
    ));
    format!(
        "worktree {path} (branch {}): {commits} new commit(s){}; {}",
        tree.branch,
        if stat.is_empty() {
            String::new()
        } else {
            format!(", uncommitted: {stat}")
        },
        next.join(", ")
    )
}

/// The diff of pull request `number`: `gh pr diff` when the GitHub CLI is
/// available, otherwise the PR head fetched from `origin` compared with the
/// merge base of the default branch.
pub fn pull_request_diff(repo_root: &Path, number: u64) -> anyhow::Result<String> {
    let number_text = number.to_string();
    if let Ok(diff) = git_free_gh(repo_root, &["pr", "diff", &number_text])
        && !diff.trim().is_empty()
    {
        return Ok(diff);
    }
    let local = format!("refs/mccode/pr-{number}");
    git(
        repo_root,
        &[
            "fetch",
            "--quiet",
            "origin",
            &format!("+refs/pull/{number}/head:{local}"),
        ],
    )?;
    let base = git(
        repo_root,
        &["symbolic-ref", "--short", "refs/remotes/origin/HEAD"],
    )
    .unwrap_or_else(|_| "origin/main".into());
    git(repo_root, &["diff", &format!("{base}...{local}")])
}

fn git_free_gh(dir: &Path, args: &[&str]) -> anyhow::Result<String> {
    let output = Command::new("gh").args(args).current_dir(dir).output()?;
    if !output.status.success() {
        anyhow::bail!("gh failed");
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for args in [
            vec!["init", "-q", "-b", "main"],
            vec!["config", "user.email", "t@example.com"],
            vec!["config", "user.name", "t"],
        ] {
            git(dir.path(), &args).unwrap();
        }
        std::fs::write(dir.path().join("a.txt"), "one\n").unwrap();
        git(dir.path(), &["add", "."]).unwrap();
        git(dir.path(), &["commit", "-q", "-m", "init"]).unwrap();
        dir
    }

    #[test]
    fn names_are_validated() {
        assert!(valid_name("fix-parser_2"));
        assert!(!valid_name("../x"));
        assert!(!valid_name(".hidden"));
        assert!(!valid_name("a b"));
        assert!(default_name().starts_with("task-"));
    }

    #[test]
    fn creates_lists_and_removes_worktrees() {
        let home = tempfile::tempdir().unwrap();
        let base = home.path().join("wt");
        let repo = repo();
        let tree = create_in(&base, repo.path(), "t1").unwrap();
        assert!(tree.path.join("a.txt").is_file());
        assert_eq!(tree.branch, "mccode/t1");
        assert!(create_in(&base, repo.path(), "t1").is_err());
        let listed = list_in(&base, repo.path()).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "t1");
        let clean = summary(&tree, repo.path());
        assert!(clean.contains("mccode/t1"), "{clean}");
        assert!(
            !clean.contains("git merge"),
            "nothing to merge yet: {clean}"
        );
        std::fs::write(tree.path.join("a.txt"), "two\n").unwrap();
        let edited = summary(&tree, repo.path());
        assert!(edited.contains("uncommitted"), "{edited}");
        assert!(edited.contains("commit -m"), "{edited}");
        git(&tree.path, &["checkout", "--", "a.txt"]).unwrap();
        remove_in(&base, repo.path(), "t1").unwrap();
        assert!(list_in(&base, repo.path()).unwrap().is_empty());
        assert!(remove_in(&base, repo.path(), "t1").is_err());
    }
}
