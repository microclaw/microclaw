//! Run project checks and turn failures into a fix-up prompt.

use std::path::Path;
use std::time::{Duration, Instant};

use crate::project::Check;

/// Default per-check timeout.
const DEFAULT_TIMEOUT_SECS: u64 = 600;
/// Output tail handed back to the agent on failure.
const FAILURE_TAIL_CHARS: usize = 6_000;

#[derive(Debug, Clone)]
pub struct CheckOutcome {
    pub check: Check,
    pub success: bool,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub duration: Duration,
    pub output: String,
}

impl CheckOutcome {
    pub fn status_label(&self) -> String {
        if self.timed_out {
            "timed out".into()
        } else if self.success {
            "passed".into()
        } else {
            match self.exit_code {
                Some(code) => format!("failed (exit {code})"),
                None => "failed".into(),
            }
        }
    }
}

fn shell(command: &str) -> tokio::process::Command {
    if cfg!(windows) {
        let mut cmd = tokio::process::Command::new("cmd");
        cmd.args(["/C", command]);
        cmd
    } else {
        let mut cmd = tokio::process::Command::new("sh");
        cmd.args(["-c", command]);
        cmd
    }
}

/// Run one check in `root`, capturing combined output.
pub async fn run_check(root: &Path, check: &Check) -> CheckOutcome {
    let started = Instant::now();
    let timeout = Duration::from_secs(check.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS));
    let mut cmd = shell(&check.run);
    cmd.current_dir(root)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    let outcome = match cmd.spawn() {
        Ok(child) => tokio::time::timeout(timeout, child.wait_with_output()).await,
        Err(e) => {
            return CheckOutcome {
                check: check.clone(),
                success: false,
                exit_code: None,
                timed_out: false,
                duration: started.elapsed(),
                output: format!("could not start `{}`: {e}", check.run),
            };
        }
    };
    match outcome {
        Ok(Ok(output)) => {
            let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.trim().is_empty() {
                if !text.is_empty() && !text.ends_with('\n') {
                    text.push('\n');
                }
                text.push_str(&stderr);
            }
            CheckOutcome {
                check: check.clone(),
                success: output.status.success(),
                exit_code: output.status.code(),
                timed_out: false,
                duration: started.elapsed(),
                output: text,
            }
        }
        Ok(Err(e)) => CheckOutcome {
            check: check.clone(),
            success: false,
            exit_code: None,
            timed_out: false,
            duration: started.elapsed(),
            output: format!("failed to run `{}`: {e}", check.run),
        },
        Err(_) => CheckOutcome {
            check: check.clone(),
            success: false,
            exit_code: None,
            timed_out: true,
            duration: started.elapsed(),
            output: format!("`{}` timed out after {}s", check.run, timeout.as_secs()),
        },
    }
}

/// Last `max` characters of `text`, on a char boundary.
pub fn tail(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut start = text.len() - max;
    while !text.is_char_boundary(start) {
        start += 1;
    }
    &text[start..]
}

/// Prompt handed back to the agent when a check fails.
pub fn fix_prompt(outcome: &CheckOutcome, round: u32, max_rounds: u32) -> String {
    let output = tail(outcome.output.trim_end(), FAILURE_TAIL_CHARS);
    format!(
        "[MicroClaw Desktop verification, round {round}/{max_rounds}] The project check `{name}` (`{run}`) {status} after your changes.\n\
         Output (last {limit} characters):\n```\n{output}\n```\n\
         Fix the cause and stop when the change is complete. Do not delete, skip or weaken tests or checks to make them pass; if the failure is unrelated to your change, say so instead of changing unrelated code.",
        name = outcome.check.name,
        run = outcome.check.run,
        status = outcome.status_label(),
        limit = FAILURE_TAIL_CHARS,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(run: &str) -> Check {
        Check {
            name: "t".into(),
            run: run.into(),
            auto: true,
            timeout_secs: Some(5),
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn reports_success_and_failure() {
        let dir = tempfile::tempdir().unwrap();
        let ok = run_check(dir.path(), &check("echo fine")).await;
        assert!(ok.success);
        assert!(ok.output.contains("fine"));

        let bad = run_check(dir.path(), &check("echo broken >&2; exit 3")).await;
        assert!(!bad.success);
        assert_eq!(bad.exit_code, Some(3));
        assert!(bad.output.contains("broken"));
        let prompt = fix_prompt(&bad, 1, 2);
        assert!(prompt.contains("failed (exit 3)"));
        assert!(prompt.contains("Do not delete, skip or weaken tests"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn times_out() {
        let dir = tempfile::tempdir().unwrap();
        let mut slow = check("sleep 5");
        slow.timeout_secs = Some(1);
        let outcome = run_check(dir.path(), &slow).await;
        assert!(outcome.timed_out);
        assert_eq!(outcome.status_label(), "timed out");
    }

    #[test]
    fn tail_respects_char_boundaries() {
        assert_eq!(tail("héllo", 3), "llo");
        assert_eq!(tail("ab", 10), "ab");
        assert_eq!(tail("aé", 1), "");
    }
}
