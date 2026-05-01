//! Filesystem checkpoints via shadow git repos.
//!
//! Once per agent turn we run `git add -A && git commit` against a shadow
//! repo whose `GIT_DIR` lives outside the user's working tree (under the
//! configured data dir). Tools never see this — it's transparent
//! infrastructure. Users can `/rewind` to any prior checkpoint.
//!
//! Hermes reference: `tools/checkpoint_manager.py`. This is a focused port:
//! we cover init, snapshot, list, restore. We do NOT expose per-file restore
//! or per-checkpoint diff yet.
//!
//! Isolation: env vars redirect git to the shadow `GIT_DIR` and keep it from
//! reading the user's `~/.gitconfig` (no signing prompts, no hooks, no
//! credential helpers).

use std::path::{Path, PathBuf};
use std::process::Stdio;

use sha2::{Digest, Sha256};
use tokio::process::Command;

const DEFAULT_EXCLUDES: &[&str] = &[
    "node_modules/",
    "dist/",
    "build/",
    ".env",
    ".env.*",
    ".env.local",
    ".env.*.local",
    "__pycache__/",
    "*.pyc",
    "*.pyo",
    ".DS_Store",
    "*.log",
    ".cache/",
    ".next/",
    ".nuxt/",
    "coverage/",
    ".pytest_cache/",
    ".venv/",
    "venv/",
    ".git/",
    "target/",
];

const GIT_TIMEOUT_SECS: u64 = 30;

#[derive(Debug, Clone)]
pub struct Checkpoint {
    pub commit: String,
    pub label: String,
    pub timestamp: String,
}

/// Path to the shadow repo for a given working dir, anchored under the data
/// dir's `checkpoints` subfolder. Per-(checkpoints_root, working_dir) so two
/// different chats with separate working dirs get separate shadow repos.
pub fn shadow_repo_path(checkpoints_root: &Path, working_dir: &Path) -> PathBuf {
    let canonical = working_dir
        .canonicalize()
        .unwrap_or_else(|_| working_dir.to_path_buf());
    let mut hasher = Sha256::new();
    hasher.update(canonical.to_string_lossy().as_bytes());
    let h = hasher.finalize();
    let dir_hash = format!("{:x}", h)[..16].to_string();
    checkpoints_root.join(dir_hash)
}

/// Initialise the shadow repo if not already present. Idempotent.
pub async fn ensure_shadow_repo(shadow_repo: &Path, working_dir: &Path) -> Result<(), String> {
    if shadow_repo.join("HEAD").exists() {
        return Ok(());
    }
    if !working_dir.exists() {
        return Err(format!(
            "working directory does not exist: {}",
            working_dir.display()
        ));
    }
    tokio::fs::create_dir_all(shadow_repo)
        .await
        .map_err(|e| format!("create shadow dir: {e}"))?;

    run_git(&["init", "--quiet"], shadow_repo, working_dir).await?;
    run_git(
        &["config", "user.email", "microclaw@local"],
        shadow_repo,
        working_dir,
    )
    .await?;
    run_git(
        &["config", "user.name", "MicroClaw Checkpoint"],
        shadow_repo,
        working_dir,
    )
    .await?;
    run_git(
        &["config", "commit.gpgsign", "false"],
        shadow_repo,
        working_dir,
    )
    .await?;
    run_git(
        &["config", "tag.gpgSign", "false"],
        shadow_repo,
        working_dir,
    )
    .await?;

    let info_dir = shadow_repo.join("info");
    tokio::fs::create_dir_all(&info_dir)
        .await
        .map_err(|e| format!("create info dir: {e}"))?;
    let exclude_body = DEFAULT_EXCLUDES.join("\n") + "\n";
    tokio::fs::write(info_dir.join("exclude"), exclude_body)
        .await
        .map_err(|e| format!("write info/exclude: {e}"))?;

    let workdir_marker = shadow_repo.join("MICROCLAW_WORKDIR");
    let _ = tokio::fs::write(&workdir_marker, format!("{}\n", working_dir.display())).await;
    Ok(())
}

/// Stage everything and commit. Returns the new commit hash, or None if
/// there were no changes to snapshot.
pub async fn snapshot(
    shadow_repo: &Path,
    working_dir: &Path,
    label: &str,
) -> Result<Option<String>, String> {
    ensure_shadow_repo(shadow_repo, working_dir).await?;
    run_git(&["add", "-A"], shadow_repo, working_dir).await?;

    // `git diff --cached --quiet` returns 0 if no diff, 1 if diff exists.
    let exit =
        run_git_status_only(&["diff", "--cached", "--quiet"], shadow_repo, working_dir).await?;
    if exit == 0 {
        return Ok(None);
    }

    run_git(
        &["commit", "--quiet", "--allow-empty-message", "-m", label],
        shadow_repo,
        working_dir,
    )
    .await?;
    let (_ok, stdout, _stderr) =
        capture_git(&["rev-parse", "HEAD"], shadow_repo, working_dir).await?;
    Ok(Some(stdout.trim().to_string()))
}

/// List the most recent checkpoints (newest first), capped at `limit`.
pub async fn list(
    shadow_repo: &Path,
    working_dir: &Path,
    limit: usize,
) -> Result<Vec<Checkpoint>, String> {
    if !shadow_repo.join("HEAD").exists() {
        return Ok(Vec::new());
    }
    let limit_str = limit.to_string();
    let format = "%h\x1f%s\x1f%cI";
    let (ok, stdout, stderr) = capture_git(
        &[
            "log",
            "-n",
            &limit_str,
            &format!("--pretty=format:{format}"),
        ],
        shadow_repo,
        working_dir,
    )
    .await?;
    if !ok {
        if stderr.contains("does not have any commits") {
            return Ok(Vec::new());
        }
        return Err(format!("git log failed: {stderr}"));
    }
    let mut out = Vec::new();
    for line in stdout.lines() {
        let mut parts = line.splitn(3, '\x1f');
        let commit = parts.next().unwrap_or("").to_string();
        let label = parts.next().unwrap_or("").to_string();
        let timestamp = parts.next().unwrap_or("").to_string();
        if !commit.is_empty() {
            out.push(Checkpoint {
                commit,
                label,
                timestamp,
            });
        }
    }
    Ok(out)
}

/// Restore the working directory to the state at `commit_hash`. Validates
/// the hash is a hex string to avoid argument injection.
pub async fn restore(
    shadow_repo: &Path,
    working_dir: &Path,
    commit_hash: &str,
) -> Result<(), String> {
    if commit_hash.is_empty() || commit_hash.starts_with('-') {
        return Err(format!("invalid commit hash: {commit_hash:?}"));
    }
    if !commit_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "invalid commit hash (must be 4–64 hex chars): {commit_hash:?}"
        ));
    }
    if commit_hash.len() < 4 || commit_hash.len() > 64 {
        return Err(format!(
            "invalid commit hash (must be 4–64 hex chars): {commit_hash:?}"
        ));
    }
    if !shadow_repo.join("HEAD").exists() {
        return Err("no checkpoint repo exists for this chat".into());
    }
    // `git checkout <hash> -- :/` overlays every tracked file in the working
    // tree from the commit, leaving HEAD where it is so subsequent snapshots
    // are still children of the active branch.
    run_git(
        &["checkout", commit_hash, "--", ":/"],
        shadow_repo,
        working_dir,
    )
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

fn build_command(args: &[&str], shadow_repo: &Path, working_dir: &Path) -> Command {
    let mut cmd = Command::new("git");
    cmd.args(args)
        .current_dir(working_dir)
        .env("GIT_DIR", shadow_repo)
        .env("GIT_WORK_TREE", working_dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_NAMESPACE")
        .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

async fn run_git(args: &[&str], shadow_repo: &Path, working_dir: &Path) -> Result<(), String> {
    let mut cmd = build_command(args, shadow_repo, working_dir);
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(GIT_TIMEOUT_SECS),
        cmd.output(),
    )
    .await
    .map_err(|_| format!("git timed out: {args:?}"))?
    .map_err(|e| format!("git spawn failed: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

async fn run_git_status_only(
    args: &[&str],
    shadow_repo: &Path,
    working_dir: &Path,
) -> Result<i32, String> {
    let mut cmd = build_command(args, shadow_repo, working_dir);
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(GIT_TIMEOUT_SECS),
        cmd.output(),
    )
    .await
    .map_err(|_| format!("git timed out: {args:?}"))?
    .map_err(|e| format!("git spawn failed: {e}"))?;
    Ok(output.status.code().unwrap_or(-1))
}

async fn capture_git(
    args: &[&str],
    shadow_repo: &Path,
    working_dir: &Path,
) -> Result<(bool, String, String), String> {
    let mut cmd = build_command(args, shadow_repo, working_dir);
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(GIT_TIMEOUT_SECS),
        cmd.output(),
    )
    .await
    .map_err(|_| format!("git timed out: {args:?}"))?
    .map_err(|e| format!("git spawn failed: {e}"))?;
    Ok((
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("microclaw_ckpt_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    async fn git_available() -> bool {
        Command::new("git").arg("--version").output().await.is_ok()
    }

    #[tokio::test]
    async fn snapshot_then_list_then_restore_round_trip() {
        if !git_available().await {
            eprintln!("skipping: git not installed");
            return;
        }
        let workdir = tmp_dir();
        let shadow = tmp_dir().join("shadow");

        // Round 1
        std::fs::write(workdir.join("a.txt"), "v1").unwrap();
        let c1 = snapshot(&shadow, &workdir, "round 1").await.unwrap();
        assert!(c1.is_some(), "first snapshot should make a commit");

        // Round 2
        std::fs::write(workdir.join("a.txt"), "v2").unwrap();
        let c2 = snapshot(&shadow, &workdir, "round 2").await.unwrap();
        assert!(c2.is_some());
        let c2_hash = c2.unwrap();

        // No-op snapshot returns None.
        let c3 = snapshot(&shadow, &workdir, "round 3 noop").await.unwrap();
        assert!(c3.is_none(), "no changes -> no commit");

        // List shows both.
        let entries = list(&shadow, &workdir, 10).await.unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries[0].label.contains("round 2"));
        assert!(entries[1].label.contains("round 1"));

        // Restore round 1.
        let c1_hash = c1.unwrap();
        restore(&shadow, &workdir, &c1_hash).await.unwrap();
        assert_eq!(
            std::fs::read_to_string(workdir.join("a.txt")).unwrap(),
            "v1"
        );

        // Restore round 2.
        restore(&shadow, &workdir, &c2_hash).await.unwrap();
        assert_eq!(
            std::fs::read_to_string(workdir.join("a.txt")).unwrap(),
            "v2"
        );

        // Cleanup.
        let _ = std::fs::remove_dir_all(&workdir);
        let _ = std::fs::remove_dir_all(shadow.parent().unwrap());
    }

    #[tokio::test]
    async fn restore_rejects_invalid_hash() {
        if !git_available().await {
            return;
        }
        let workdir = tmp_dir();
        let shadow = tmp_dir().join("shadow");
        std::fs::write(workdir.join("a.txt"), "v1").unwrap();
        snapshot(&shadow, &workdir, "init").await.unwrap();

        // Argument-injection guard: hash starting with '-'.
        let err = restore(&shadow, &workdir, "--patch").await.unwrap_err();
        assert!(err.contains("invalid commit hash"));
        // Non-hex.
        let err = restore(&shadow, &workdir, "ZZZZ").await.unwrap_err();
        assert!(err.contains("invalid commit hash"));
        // Too short.
        let err = restore(&shadow, &workdir, "abc").await.unwrap_err();
        assert!(err.contains("invalid commit hash"));

        let _ = std::fs::remove_dir_all(&workdir);
        let _ = std::fs::remove_dir_all(shadow.parent().unwrap());
    }

    #[test]
    fn shadow_repo_path_is_deterministic() {
        let root = PathBuf::from("/tmp/data/checkpoints");
        let wd = std::env::temp_dir(); // exists
        let p1 = shadow_repo_path(&root, &wd);
        let p2 = shadow_repo_path(&root, &wd);
        assert_eq!(p1, p2);
        assert_eq!(p1.parent(), Some(root.as_path()));
        assert_eq!(p1.file_name().unwrap().len(), 16);
    }

    #[tokio::test]
    async fn list_returns_empty_for_uninitialised_repo() {
        let shadow = tmp_dir().join("never_initialised");
        let workdir = tmp_dir();
        let entries = list(&shadow, &workdir, 5).await.unwrap();
        assert!(entries.is_empty());
        let _ = std::fs::remove_dir_all(&workdir);
    }
}
