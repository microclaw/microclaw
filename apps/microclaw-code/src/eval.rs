//! `mccode eval`: measure MicroClaw Code on coding tasks.
//!
//! A case is a directory with `case.yaml` and a `repo/` snapshot:
//!
//! ```yaml
//! prompt: Fix the failing test in parser.rs
//! check: cargo test parser      # passes when it exits 0 after the run
//! setup: npm ci                 # optional, run before the agent
//! mode: auto                    # optional (default auto)
//! timeout_secs: 900             # optional, for the check
//! ```
//!
//! Each case runs in a fresh temporary git repository (trusted, sandboxed
//! like a normal session), then the check decides pass/fail. `mccode eval
//! replay` turns bug-fix commits of a repository into cases: the parent
//! commit is the snapshot and the commit message is the prompt.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use microclaw_code_core::driver::{CodeSession, SandboxInfo, SessionSettings};
use microclaw_code_core::project::{Check, Mode, Project};
use microclaw_code_core::verify;
use microclaw_sdk::{MicroClaw, ShellSandbox};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

#[derive(Debug, Clone, Deserialize)]
pub struct CaseSpec {
    pub prompt: String,
    pub check: String,
    #[serde(default)]
    pub setup: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
    /// Further turns sent after `prompt`, in the same session (long-session
    /// and cross-compaction cases).
    #[serde(default)]
    pub followups: Vec<String>,
    /// Pretend the model's context window is this many tokens, so a case can
    /// exercise automatic compaction without huge inputs.
    #[serde(default)]
    pub context_window: Option<usize>,
    /// The case fails unless at least this many compactions happened (for
    /// cases that test recall across a compaction).
    #[serde(default)]
    pub min_compactions: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct CaseResult {
    pub case: String,
    pub passed: bool,
    pub status: String,
    pub seconds: f64,
    pub changed_files: Vec<String>,
    pub requests: i64,
    pub input_tokens: i64,
    pub output_tokens: i64,
    /// Automatic or forced compactions during the case.
    pub compactions: usize,
    pub check_tail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub struct EvalOptions {
    pub config_path: PathBuf,
    pub sandbox: ShellSandbox,
    pub sandbox_info: Option<SandboxInfo>,
    pub max_fix_rounds: Option<u32>,
    pub keep: bool,
    pub filter: Option<String>,
}

/// Case directories under `dir` (those with a `case.yaml`), sorted.
pub fn discover_cases(dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
    if dir.join("case.yaml").is_file() {
        return Ok(vec![dir.to_path_buf()]);
    }
    let mut cases: Vec<PathBuf> = std::fs::read_dir(dir)?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.join("case.yaml").is_file())
        .collect();
    cases.sort();
    Ok(cases)
}

fn copy_dir(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

fn git(dir: &Path, args: &[&str]) -> anyhow::Result<()> {
    let status = std::process::Command::new("git")
        .args(args)
        .current_dir(dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
    if !status.success() {
        anyhow::bail!("git {} failed", args.join(" "));
    }
    Ok(())
}

/// Copy a case's snapshot into a fresh git repository.
pub fn prepare_workspace(case_dir: &Path, work: &Path) -> anyhow::Result<()> {
    let repo = case_dir.join("repo");
    if repo.is_dir() {
        copy_dir(&repo, work)?;
    } else {
        std::fs::create_dir_all(work)?;
    }
    git(work, &["init", "-q"])?;
    git(work, &["add", "-A"])?;
    git(
        work,
        &[
            "-c",
            "user.email=eval@microclaw.local",
            "-c",
            "user.name=mccode eval",
            "commit",
            "-qm",
            "eval baseline",
            "--allow-empty",
        ],
    )?;
    Ok(())
}

async fn run_case(options: &EvalOptions, case_dir: &Path) -> CaseResult {
    let name = case_dir
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let started = Instant::now();
    let mut result = CaseResult {
        case: name.clone(),
        passed: false,
        status: "error".into(),
        seconds: 0.0,
        changed_files: Vec::new(),
        requests: 0,
        input_tokens: 0,
        output_tokens: 0,
        compactions: 0,
        check_tail: String::new(),
        error: None,
    };
    let outcome: anyhow::Result<()> = async {
        let spec: CaseSpec =
            serde_yaml::from_str(&std::fs::read_to_string(case_dir.join("case.yaml"))?)?;
        let work =
            std::env::temp_dir().join(format!("mccode-eval-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&work);
        prepare_workspace(case_dir, &work)?;
        let project = Project::discover(&work, |_, _| true)?;
        let timeout = spec.timeout_secs.unwrap_or(900);
        if let Some(setup) = &spec.setup {
            let check = Check {
                name: "setup".into(),
                run: setup.clone(),
                auto: false,
                timeout_secs: Some(timeout),
            };
            let outcome = verify::run_check(&project.root, &check).await;
            if !outcome.success {
                anyhow::bail!("setup failed: {}", verify::tail(&outcome.output, 500));
            }
            git(&work, &["add", "-A"])?;
            git(
                &work,
                &[
                    "-c",
                    "user.email=eval@microclaw.local",
                    "-c",
                    "user.name=mccode eval",
                    "commit",
                    "-qm",
                    "setup",
                    "--allow-empty",
                ],
            )?;
        }
        let mode = match spec.mode.as_deref() {
            Some(raw) => Mode::parse(raw).ok_or_else(|| anyhow::anyhow!("unknown mode {raw}"))?,
            None => Mode::Auto,
        };
        let engine = MicroClaw::builder(&options.config_path)
            .caller_channel(microclaw_code_core::driver::CALLER_CHANNEL)
            .workspace(&project.root)
            .data_dir(microclaw_code_core::home::data_dir())
            .max_concurrent_runs(1)
            .shell_sandbox(options.sandbox.clone())
            .compact_instructions(project.config.compact_instructions.clone())
            .context_window(spec.context_window)
            .context_tools(project.config.context_tools == Some(true))
            .project_agents_dir(project.agents_dir())
            .build()
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let session_id = format!("eval-{name}-{}", chrono_stamp());
        let settings = SessionSettings {
            max_session_tokens: project.config.max_session_tokens,
            mode,
            verify: true,
            max_fix_rounds: options
                .max_fix_rounds
                .unwrap_or_else(|| project.max_fix_rounds()),
            interactive: false,
            sandbox: options.sandbox_info.clone(),
        };
        let mut session = CodeSession::new(engine, project, session_id, settings);
        let (updates_tx, mut updates_rx) = mpsc::unbounded_channel();
        let compactions = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = compactions.clone();
        let counting = tokio::spawn(async move {
            while let Some(update) = updates_rx.recv().await {
                if let microclaw_code_core::driver::Update::Runtime(envelope) = update
                    && matches!(
                        envelope.event,
                        microclaw_sdk::RuntimeEvent::ContextCompacted { .. }
                    )
                {
                    counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
        });
        let (_controls_tx, mut controls_rx) = mpsc::unbounded_channel();
        let mut report = session
            .turn(&spec.prompt, &updates_tx, &mut controls_rx)
            .await?;
        for followup in &spec.followups {
            if report.approval_pending.is_some() || report.failed {
                break;
            }
            let next = session
                .turn(followup, &updates_tx, &mut controls_rx)
                .await?;
            let mut changed = report.changed_files.clone();
            for file in &next.changed_files {
                if !changed.contains(file) {
                    changed.push(file.clone());
                }
            }
            report = next;
            report.changed_files = changed;
        }
        drop(updates_tx);
        // Wait until every queued update has been counted (bounded, in case
        // a background task still holds a sender).
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), counting).await;
        result.compactions = compactions.load(std::sync::atomic::Ordering::Relaxed);
        result.status = report.status.clone();
        result.changed_files = report.changed_files.clone();
        if let Ok(usage) = session.usage().await {
            result.requests = usage.requests;
            result.input_tokens = usage.input_tokens;
            result.output_tokens = usage.output_tokens;
        }
        let check = Check {
            name: "eval".into(),
            run: spec.check.clone(),
            auto: false,
            timeout_secs: Some(timeout),
        };
        let outcome = verify::run_check(&session.project.root, &check).await;
        result.passed = outcome.success;
        result.check_tail = verify::tail(outcome.output.trim_end(), 400).to_string();
        if result.compactions < spec.min_compactions {
            result.passed = false;
            result.check_tail = format!(
                "expected at least {} compaction(s), got {}; {}",
                spec.min_compactions, result.compactions, result.check_tail
            );
        }
        if report.approval_pending.is_some() {
            result.status = "approval_pending".into();
        }
        if !options.keep {
            let _ = std::fs::remove_dir_all(&work);
        }
        Ok(())
    }
    .await;
    if let Err(e) = outcome {
        result.error = Some(format!("{e:#}"));
    }
    result.seconds = started.elapsed().as_secs_f64();
    result
}

fn chrono_stamp() -> String {
    format!(
        "{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_millis()
    )
}

/// Run every case under `dir`; returns the results.
pub async fn run(options: &EvalOptions, dir: &Path, json: bool) -> anyhow::Result<Vec<CaseResult>> {
    let mut cases = discover_cases(dir)?;
    if let Some(filter) = &options.filter {
        cases.retain(|c| c.to_string_lossy().contains(filter.as_str()));
    }
    if cases.is_empty() {
        anyhow::bail!(
            "no cases (directories with case.yaml) under {}",
            dir.display()
        );
    }
    let mut results = Vec::new();
    for case in &cases {
        let result = run_case(options, case).await;
        if json {
            println!("{}", serde_json::to_string(&result)?);
        } else {
            println!(
                "{} {:<32} {:>6.1}s  {:>3} req  {:>7} tok  {:>2} cmp  {}",
                if result.passed { "PASS" } else { "FAIL" },
                result.case,
                result.seconds,
                result.requests,
                result.input_tokens + result.output_tokens,
                result.compactions,
                result
                    .error
                    .clone()
                    .unwrap_or_else(|| result.status.clone())
            );
        }
        results.push(result);
    }
    let passed = results.iter().filter(|r| r.passed).count();
    if json {
        println!(
            "{}",
            serde_json::json!({"type": "summary", "passed": passed, "total": results.len()})
        );
    } else {
        println!("\n{passed}/{} passed", results.len());
    }
    Ok(results)
}

/// Write one case per bug-fix commit in `range` of `repo` into `out`.
pub fn replay(
    repo: &Path,
    range: &str,
    out: &Path,
    check: &str,
    all: bool,
) -> anyhow::Result<usize> {
    let log = std::process::Command::new("git")
        .args(["log", "--format=%H%x1f%P%x1f%s%x1f%b%x1e", range])
        .current_dir(repo)
        .output()?;
    if !log.status.success() {
        anyhow::bail!(
            "git log {range} failed: {}",
            String::from_utf8_lossy(&log.stderr).trim()
        );
    }
    let text = String::from_utf8_lossy(&log.stdout).to_string();
    let mut written = 0;
    for record in text.split('\u{1e}') {
        let fields: Vec<&str> = record.trim_matches('\n').split('\u{1f}').collect();
        let [hash, parents, subject, body] = fields[..] else {
            continue;
        };
        let parent = parents.split_whitespace().next();
        let Some(parent) = parent else { continue };
        if parents.split_whitespace().count() > 1 {
            continue; // merges
        }
        let lower = subject.to_ascii_lowercase();
        if !all
            && !["fix", "bug", "repair", "correct"]
                .iter()
                .any(|w| lower.contains(w))
        {
            continue;
        }
        let short = &hash[..hash.len().min(10)];
        let case = out.join(format!("replay-{short}"));
        let snapshot = case.join("repo");
        std::fs::create_dir_all(&snapshot)?;
        let archive = std::process::Command::new("git")
            .args(["archive", "--format=tar", parent])
            .current_dir(repo)
            .output()?;
        if !archive.status.success() {
            continue;
        }
        let mut untar = std::process::Command::new("tar")
            .args(["-xf", "-", "-C"])
            .arg(&snapshot)
            .stdin(std::process::Stdio::piped())
            .spawn()?;
        {
            use std::io::Write;
            untar
                .stdin
                .take()
                .expect("piped stdin")
                .write_all(&archive.stdout)?;
        }
        if !untar.wait()?.success() {
            continue;
        }
        // Drop commit trailers (Co-Authored-By, Signed-off-by, …).
        let body: String = body
            .lines()
            .filter(|line| {
                let trimmed = line.trim();
                !trimmed.split_once(':').is_some_and(|(key, _)| {
                    !key.is_empty()
                        && !key.contains(' ')
                        && key.contains('-')
                        && key.chars().next().is_some_and(char::is_uppercase)
                })
            })
            .collect::<Vec<_>>()
            .join("\n");
        let body = body.as_str();
        let prompt = if body.trim().is_empty() {
            subject.trim().to_string()
        } else {
            format!("{}\n\n{}", subject.trim(), body.trim())
        };
        let yaml = format!(
            "# Replayed from {hash}\nprompt: {}\ncheck: {}\n",
            serde_json::to_string(&prompt)?,
            serde_json::to_string(check)?
        );
        std::fs::write(case.join("case.yaml"), yaml)?;
        written += 1;
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_git(dir: &Path, args: &[&str]) {
        assert!(
            std::process::Command::new("git")
                .args(args)
                .current_dir(dir)
                .output()
                .unwrap()
                .status
                .success(),
            "git {args:?}"
        );
    }

    #[test]
    fn replay_turns_fix_commits_into_cases() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        run_git(&repo, &["init", "-q"]);
        let commit = |msg: &str| {
            run_git(&repo, &["add", "-A"]);
            run_git(
                &repo,
                &[
                    "-c",
                    "user.email=a@b",
                    "-c",
                    "user.name=t",
                    "commit",
                    "-qm",
                    msg,
                ],
            );
        };
        std::fs::write(repo.join("a.txt"), "buggy\n").unwrap();
        commit("initial");
        std::fs::write(repo.join("a.txt"), "fixed\n").unwrap();
        commit("Fix the greeting\n\nCo-Authored-By: Someone <a@b>");
        std::fs::write(repo.join("b.txt"), "x\n").unwrap();
        commit("Add docs");
        let out = dir.path().join("cases");
        let written = replay(&repo, "HEAD~2..HEAD", &out, "grep -q fixed a.txt", false).unwrap();
        assert_eq!(written, 1);
        let cases = discover_cases(&out).unwrap();
        assert_eq!(cases.len(), 1);
        let spec: CaseSpec =
            serde_yaml::from_str(&std::fs::read_to_string(cases[0].join("case.yaml")).unwrap())
                .unwrap();
        assert_eq!(spec.prompt, "Fix the greeting");
        assert_eq!(spec.check, "grep -q fixed a.txt");
        assert_eq!(
            std::fs::read_to_string(cases[0].join("repo/a.txt")).unwrap(),
            "buggy\n"
        );
        let work = dir.path().join("work");
        prepare_workspace(&cases[0], &work).unwrap();
        assert!(work.join(".git").is_dir());
    }
}
