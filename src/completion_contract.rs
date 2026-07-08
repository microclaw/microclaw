//! Completion contracts: evidence-based verification that a sub-agent's task
//! is actually done, instead of trusting its self-report.
//!
//! A contract is a small list of machine-checkable exit criteria declared at
//! spawn time (`exit_criteria` on `sessions_spawn`). When the sub-agent
//! finishes, the runtime executes every criterion and annotates the result
//! with per-criterion evidence — "done" then means *verified done* (v0.4.0
//! item C+E in `docs/roadmap/competitive-intel-update-2026-07.md`).
//!
//! Safety model:
//! - File criteria only accept RELATIVE paths and resolve inside the chat's
//!   working directory — a contract cannot be used to probe `~/.ssh` or other
//!   host paths, and evidence excerpts are capped.
//! - Command criteria run through the sub-agent's own `bash` tool via
//!   [`CommandRunner`], so the sandbox router, dangerous-pattern checks, and
//!   `tool_policy` all apply exactly as if the agent had run the command.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Hard cap on criteria per contract — a contract is a checklist, not a test
/// suite; anything larger belongs in an actual test the agent runs itself.
pub const MAX_CRITERIA: usize = 8;

/// Cap on evidence excerpts embedded in the verification report.
const MAX_EVIDENCE_CHARS: usize = 300;

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExitCriterion {
    /// A file exists (relative to the chat working dir).
    FileExists { path: String },
    /// A file exists and contains `needle` (substring match).
    FileContains { path: String, needle: String },
    /// A file exists and is at least `min_bytes` long.
    FileMinBytes { path: String, min_bytes: u64 },
    /// The sub-agent's final result text contains `needle`.
    ResultContains { needle: String },
    /// A shell command succeeds (exit 0), optionally also requiring its
    /// output to contain `expect_contains`. Runs through the sub-agent's
    /// bash tool — sandbox and policy guards apply.
    Command {
        run: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expect_contains: Option<String>,
    },
}

impl ExitCriterion {
    /// One-line human-readable form used in prompts and reports.
    pub fn describe(&self) -> String {
        match self {
            ExitCriterion::FileExists { path } => format!("file `{path}` exists"),
            ExitCriterion::FileContains { path, needle } => {
                format!("file `{path}` contains {needle:?}")
            }
            ExitCriterion::FileMinBytes { path, min_bytes } => {
                format!("file `{path}` is at least {min_bytes} bytes")
            }
            ExitCriterion::ResultContains { needle } => {
                format!("result text contains {needle:?}")
            }
            ExitCriterion::Command {
                run,
                expect_contains,
            } => match expect_contains {
                Some(needle) => format!("command `{run}` succeeds and prints {needle:?}"),
                None => format!("command `{run}` succeeds"),
            },
        }
    }
}

/// Outcome of checking one criterion.
#[derive(Debug, Clone)]
pub struct CriterionOutcome {
    pub description: String,
    pub passed: bool,
    pub evidence: String,
}

/// Executes `Command` criteria. Production wires this to the sub-agent's
/// bash tool; tests use a stub.
#[async_trait]
pub trait CommandRunner: Send + Sync {
    /// Returns (success, output-or-error-text).
    async fn run(&self, command: &str) -> (bool, String);
}

/// Parse the `exit_criteria` tool-input value. `None` when absent/null;
/// errors on malformed entries so bad contracts fail loudly at spawn time
/// instead of silently verifying nothing.
pub fn parse_exit_criteria(value: Option<&serde_json::Value>) -> Result<Vec<ExitCriterion>, String> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    if value.is_null() {
        return Ok(Vec::new());
    }
    let arr = value
        .as_array()
        .ok_or_else(|| "exit_criteria must be an array".to_string())?;
    if arr.len() > MAX_CRITERIA {
        return Err(format!(
            "exit_criteria has {} entries (max {MAX_CRITERIA})",
            arr.len()
        ));
    }
    let mut out = Vec::with_capacity(arr.len());
    for (i, entry) in arr.iter().enumerate() {
        let criterion: ExitCriterion = serde_json::from_value(entry.clone()).map_err(|e| {
            format!(
                "exit_criteria[{i}] is invalid: {e}. Expected one of: \
                 {{type: file_exists, path}}, {{type: file_contains, path, needle}}, \
                 {{type: file_min_bytes, path, min_bytes}}, {{type: result_contains, needle}}, \
                 {{type: command, run, expect_contains?}}"
            )
        })?;
        if let ExitCriterion::FileExists { path }
        | ExitCriterion::FileContains { path, .. }
        | ExitCriterion::FileMinBytes { path, .. } = &criterion
        {
            validate_contract_path(path).map_err(|e| format!("exit_criteria[{i}]: {e}"))?;
        }
        out.push(criterion);
    }
    Ok(out)
}

/// File-criterion paths must stay inside the chat working dir: relative,
/// no parent traversal, no absolute/rooted forms.
fn validate_contract_path(path: &str) -> Result<(), String> {
    let p = Path::new(path);
    if p.is_absolute() || path.starts_with('~') {
        return Err(format!(
            "path `{path}` must be relative to the chat working directory"
        ));
    }
    if p.components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(format!("path `{path}` must not contain `..`"));
    }
    Ok(())
}

fn truncate_evidence(s: &str) -> String {
    let trimmed = s.trim();
    if trimmed.len() <= MAX_EVIDENCE_CHARS {
        return trimmed.to_string();
    }
    let end = microclaw_core::text::floor_char_boundary(trimmed, MAX_EVIDENCE_CHARS);
    format!("{}…", &trimmed[..end])
}

/// Check every criterion and collect evidence. Never panics; unreadable
/// files or runner errors surface as failed criteria with the error as
/// evidence (fail closed).
pub async fn verify_criteria(
    criteria: &[ExitCriterion],
    result_text: &str,
    working_dir: &Path,
    runner: Option<&dyn CommandRunner>,
) -> Vec<CriterionOutcome> {
    let mut outcomes = Vec::with_capacity(criteria.len());
    for criterion in criteria {
        let description = criterion.describe();
        let (passed, evidence) = match criterion {
            ExitCriterion::FileExists { path } => {
                let full = resolve(working_dir, path);
                if full.is_file() {
                    (true, format!("{} exists", full.display()))
                } else {
                    (false, format!("{} not found", full.display()))
                }
            }
            ExitCriterion::FileContains { path, needle } => {
                let full = resolve(working_dir, path);
                match std::fs::read_to_string(&full) {
                    Ok(content) if content.contains(needle.as_str()) => {
                        (true, format!("{needle:?} found in {path}"))
                    }
                    Ok(_) => (false, format!("{needle:?} not found in {path}")),
                    Err(e) => (false, format!("cannot read {path}: {e}")),
                }
            }
            ExitCriterion::FileMinBytes { path, min_bytes } => {
                let full = resolve(working_dir, path);
                match std::fs::metadata(&full) {
                    Ok(meta) if meta.len() >= *min_bytes => {
                        (true, format!("{path} is {} bytes", meta.len()))
                    }
                    Ok(meta) => (
                        false,
                        format!("{path} is {} bytes (need >= {min_bytes})", meta.len()),
                    ),
                    Err(e) => (false, format!("cannot stat {path}: {e}")),
                }
            }
            ExitCriterion::ResultContains { needle } => {
                if result_text.contains(needle.as_str()) {
                    (true, format!("{needle:?} present in result"))
                } else {
                    (false, format!("{needle:?} missing from result"))
                }
            }
            ExitCriterion::Command {
                run,
                expect_contains,
            } => match runner {
                Some(runner) => {
                    let (success, output) = runner.run(run).await;
                    match (success, expect_contains) {
                        (false, _) => (false, truncate_evidence(&output)),
                        (true, Some(needle)) if !output.contains(needle.as_str()) => (
                            false,
                            format!(
                                "command succeeded but output lacks {needle:?}: {}",
                                truncate_evidence(&output)
                            ),
                        ),
                        (true, _) => (true, truncate_evidence(&output)),
                    }
                }
                None => (
                    false,
                    "command criteria are not available in this runtime".to_string(),
                ),
            },
        };
        outcomes.push(CriterionOutcome {
            description,
            passed,
            evidence: truncate_evidence(&evidence),
        });
    }
    outcomes
}

fn resolve(working_dir: &Path, rel: &str) -> PathBuf {
    working_dir.join(rel)
}

/// Render the verification block prepended to the sub-agent's result text.
pub fn render_report(outcomes: &[CriterionOutcome]) -> String {
    let passed = outcomes.iter().filter(|o| o.passed).count();
    let total = outcomes.len();
    let mut out = if passed == total {
        format!("[completion contract] VERIFIED — {passed}/{total} criteria passed\n")
    } else {
        format!(
            "[completion contract] FAILED — {passed}/{total} criteria passed. \
             Do NOT treat this task as done; the failed criteria below are the \
             remaining work.\n"
        )
    };
    for o in outcomes {
        let mark = if o.passed { "✓" } else { "✗" };
        out.push_str(&format!("{mark} {} — {}\n", o.description, o.evidence));
    }
    out
}

/// Render the contract for the sub-agent's task prompt so it knows exactly
/// what will be checked when it declares completion.
pub fn render_for_prompt(criteria: &[ExitCriterion]) -> String {
    let mut out = String::from(
        "\n\nCompletion contract: after you finish, the runtime will VERIFY these \
         criteria with real checks (file reads / commands). Your result is only \
         accepted as done if all pass — make each one true before submitting:\n",
    );
    for c in criteria {
        out.push_str(&format!("- {}\n", c.describe()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct StubRunner {
        success: bool,
        output: &'static str,
    }

    #[async_trait]
    impl CommandRunner for StubRunner {
        async fn run(&self, _command: &str) -> (bool, String) {
            (self.success, self.output.to_string())
        }
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "microclaw-contract-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn parse_accepts_valid_and_rejects_invalid() {
        let ok = parse_exit_criteria(Some(&json!([
            {"type": "file_exists", "path": "report.md"},
            {"type": "file_contains", "path": "report.md", "needle": "## Summary"},
            {"type": "file_min_bytes", "path": "out.pdf", "min_bytes": 10240},
            {"type": "result_contains", "needle": "done"},
            {"type": "command", "run": "cargo test -q"},
            {"type": "command", "run": "wc -l x", "expect_contains": "30"}
        ])))
        .unwrap();
        assert_eq!(ok.len(), 6);

        assert!(parse_exit_criteria(None).unwrap().is_empty());
        assert!(parse_exit_criteria(Some(&json!(null))).unwrap().is_empty());
        assert!(parse_exit_criteria(Some(&json!("nope"))).is_err());
        assert!(parse_exit_criteria(Some(&json!([{"type": "bogus"}]))).is_err());
        // Unknown extra fields rejected (deny_unknown_fields).
        assert!(
            parse_exit_criteria(Some(&json!([{"type": "file_exists", "path": "a", "x": 1}])))
                .is_err()
        );
    }

    #[test]
    fn parse_rejects_unsafe_paths_and_oversize() {
        assert!(parse_exit_criteria(Some(&json!([
            {"type": "file_exists", "path": "/etc/passwd"}
        ])))
        .is_err());
        assert!(parse_exit_criteria(Some(&json!([
            {"type": "file_exists", "path": "../secrets"}
        ])))
        .is_err());
        assert!(parse_exit_criteria(Some(&json!([
            {"type": "file_contains", "path": "~/.ssh/id_rsa", "needle": "x"}
        ])))
        .is_err());
        let too_many: Vec<_> = (0..9)
            .map(|i| json!({"type": "file_exists", "path": format!("f{i}")}))
            .collect();
        assert!(parse_exit_criteria(Some(&json!(too_many))).is_err());
    }

    #[tokio::test]
    async fn file_criteria_verify_against_working_dir() {
        let dir = temp_dir("files");
        std::fs::write(dir.join("report.md"), "# Report\n## Summary\nAll good.").unwrap();

        let criteria = vec![
            ExitCriterion::FileExists {
                path: "report.md".into(),
            },
            ExitCriterion::FileContains {
                path: "report.md".into(),
                needle: "## Summary".into(),
            },
            ExitCriterion::FileMinBytes {
                path: "report.md".into(),
                min_bytes: 10,
            },
            ExitCriterion::FileExists {
                path: "missing.md".into(),
            },
        ];
        let outcomes = verify_criteria(&criteria, "", &dir, None).await;
        assert_eq!(
            outcomes.iter().map(|o| o.passed).collect::<Vec<_>>(),
            vec![true, true, true, false]
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn result_and_command_criteria() {
        let dir = temp_dir("cmd");
        let criteria = vec![
            ExitCriterion::ResultContains {
                needle: "30 files updated".into(),
            },
            ExitCriterion::Command {
                run: "true".into(),
                expect_contains: None,
            },
        ];

        let ok_runner = StubRunner {
            success: true,
            output: "ok",
        };
        let outcomes =
            verify_criteria(&criteria, "Done: 30 files updated.", &dir, Some(&ok_runner)).await;
        assert!(outcomes.iter().all(|o| o.passed));

        // Failing command + expect_contains mismatch + no runner.
        let fail_runner = StubRunner {
            success: true,
            output: "27 matches",
        };
        let criteria = vec![ExitCriterion::Command {
            run: "grep -c x".into(),
            expect_contains: Some("30".into()),
        }];
        let outcomes = verify_criteria(&criteria, "", &dir, Some(&fail_runner)).await;
        assert!(!outcomes[0].passed);
        assert!(outcomes[0].evidence.contains("lacks"));

        let outcomes = verify_criteria(&criteria, "", &dir, None).await;
        assert!(!outcomes[0].passed);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn report_renders_verified_and_failed() {
        let verified = render_report(&[CriterionOutcome {
            description: "file `x` exists".into(),
            passed: true,
            evidence: "x exists".into(),
        }]);
        assert!(verified.contains("VERIFIED — 1/1"));

        let failed = render_report(&[
            CriterionOutcome {
                description: "a".into(),
                passed: true,
                evidence: "e1".into(),
            },
            CriterionOutcome {
                description: "b".into(),
                passed: false,
                evidence: "e2".into(),
            },
        ]);
        assert!(failed.contains("FAILED — 1/2"));
        assert!(failed.contains("✗ b — e2"));
    }

    #[test]
    fn prompt_rendering_lists_criteria() {
        let text = render_for_prompt(&[ExitCriterion::FileExists {
            path: "out.pdf".into(),
        }]);
        assert!(text.contains("Completion contract"));
        assert!(text.contains("file `out.pdf` exists"));
    }
}
