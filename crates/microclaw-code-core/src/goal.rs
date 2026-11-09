//! `/goal`: keep working, turn after turn, until a goal is met.
//!
//! Front ends (the TUI, `mccode acp`, `mccode -p --goal`) share this state
//! machine. After every turn they hand it the [`TurnReport`] and, when the
//! goal has an `--until` command, that command's outcome
//! ([`run_until`]); [`Goal::judge`] says whether to stop or run another
//! round, and [`Goal::prompt`] writes the next round's prompt.
//!
//! The agent ends a reply with [`DONE_MARKER`] or `GOAL BLOCKED: <reason>`
//! on its last line. A goal is reached when the agent says so and no check
//! failed, or, with `--until`, only when that command succeeds. It stops
//! when the agent is blocked, after two rounds in a row that changed no
//! files, when the round limit is hit, or when a turn fails, is cancelled,
//! runs out of budget or waits for an approval.

use std::path::Path;

use crate::driver::TurnReport;
use crate::project::Check;
use crate::verify::{self, CheckOutcome};

/// Last line of a reply that says the goal is reached.
pub const DONE_MARKER: &str = "GOAL COMPLETE";
/// Last-line prefix of a reply that says the agent cannot go on.
pub const BLOCKED_PREFIX: &str = "GOAL BLOCKED:";
/// Rounds a goal may take when nothing else is configured.
pub const DEFAULT_MAX_ROUNDS: u32 = 8;
/// Hard upper bound for `--rounds`.
pub const MAX_ROUNDS_LIMIT: u32 = 50;
/// Rounds in a row without file changes after which a goal counts as stalled.
const STALL_ROUNDS: u32 = 2;
/// Output of a failing `--until` command handed to the next round.
const UNTIL_TAIL_CHARS: usize = 4_000;

/// What the user asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoalSpec {
    pub objective: String,
    pub max_rounds: u32,
    /// Shell command that must succeed for the goal to count as reached.
    pub until: Option<String>,
}

impl GoalSpec {
    /// Parse `/goal` arguments: `[--until <command>] [--rounds N] <objective>`.
    ///
    /// The command may be quoted (`--until "cargo test -p x"`) or a single
    /// word; `--until=…`, `--rounds=N` and `--max-rounds N` work too.
    pub fn parse(args: &str, default_rounds: u32) -> Result<Self, String> {
        let mut rest = args.trim();
        let mut until = None;
        let mut max_rounds = default_rounds.clamp(1, MAX_ROUNDS_LIMIT);
        while let Some((flag, after)) = split_flag(rest) {
            let (value, after) =
                take_value(after).ok_or_else(|| format!("{flag} needs a value"))?;
            match flag {
                "--until" => until = Some(value),
                "--rounds" | "--max-rounds" => {
                    max_rounds = value
                        .parse::<u32>()
                        .ok()
                        .filter(|n| (1..=MAX_ROUNDS_LIMIT).contains(n))
                        .ok_or_else(|| {
                            format!("{flag} takes a number from 1 to {MAX_ROUNDS_LIMIT}")
                        })?;
                }
                _ => unreachable!("split_flag only returns known flags"),
            }
            rest = after.trim_start();
        }
        let objective = rest.trim().to_string();
        if objective.is_empty() {
            return Err("usage: /goal [--until <command>] [--rounds N] <objective>".into());
        }
        Ok(Self {
            objective,
            max_rounds,
            until: until.filter(|u| !u.trim().is_empty()),
        })
    }
}

fn split_flag(text: &str) -> Option<(&'static str, &str)> {
    for flag in ["--until", "--max-rounds", "--rounds"] {
        if let Some(after) = text.strip_prefix(flag) {
            if let Some(after) = after.strip_prefix('=') {
                return Some((flag, after));
            }
            if after.starts_with(char::is_whitespace) {
                return Some((flag, after.trim_start()));
            }
        }
    }
    None
}

/// One flag value: a `"…"` / `'…'` quoted string or a single word.
fn take_value(text: &str) -> Option<(String, &str)> {
    let mut chars = text.chars();
    match chars.next()? {
        quote @ ('"' | '\'') => {
            let body = &text[1..];
            let end = body.find(quote)?;
            Some((body[..end].to_string(), &body[end + 1..]))
        }
        _ => {
            let end = text.find(char::is_whitespace).unwrap_or(text.len());
            Some((text[..end].to_string(), &text[end..]))
        }
    }
}

/// How a reached goal was confirmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confirmed {
    /// The `--until` command succeeded.
    Until,
    /// The agent said so and the project's checks passed.
    Checks,
    /// The agent said so; no check ran.
    AgentOnly,
}

/// What to do after a round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Run the next round with [`Goal::prompt`].
    Continue,
    Reached(Confirmed),
    /// The agent says it cannot go on.
    Blocked(String),
    /// Rounds in a row changed no files.
    Stalled,
    /// The round limit was hit.
    OutOfRounds,
    /// The turn was cancelled, failed, ran out of budget or waits for an
    /// approval; the reason is shown as is.
    Stopped(String),
}

impl Verdict {
    pub fn is_reached(&self) -> bool {
        matches!(self, Self::Reached(_))
    }

    pub fn is_final(&self) -> bool {
        !matches!(self, Self::Continue)
    }
}

/// A goal being worked on.
#[derive(Debug, Clone)]
pub struct Goal {
    pub spec: GoalSpec,
    /// The round now running (1-based).
    pub round: u32,
    idle_rounds: u32,
    last_until: Option<CheckOutcome>,
}

impl Goal {
    pub fn new(spec: GoalSpec) -> Self {
        Self {
            spec,
            round: 1,
            idle_rounds: 0,
            last_until: None,
        }
    }

    /// `round N/M` for status lines.
    pub fn progress(&self) -> String {
        format!("round {}/{}", self.round, self.spec.max_rounds)
    }

    /// The prompt of the current round.
    pub fn prompt(&self) -> String {
        let spec = &self.spec;
        let mut text = if self.round == 1 {
            format!("Goal: {}\n\nWork toward this goal.", spec.objective)
        } else {
            format!(
                "Continue working toward the goal: {}\n\nThis is round {} of at most {}.",
                spec.objective, self.round, spec.max_rounds
            )
        };
        if let Some(until) = &spec.until {
            text.push_str(&format!(
                " The goal counts as reached only when `{until}` succeeds; it runs after \
                 every round."
            ));
        }
        if let Some(outcome) = self.last_until.as_ref().filter(|o| !o.success) {
            text.push_str(&format!(
                "\n\nAfter the last round `{}` {}:\n```\n{}\n```",
                outcome.check.run,
                outcome.status_label(),
                verify::tail(&outcome.output, UNTIL_TAIL_CHARS).trim()
            ));
        }
        text.push_str(&format!(
            "\n\nWhen the goal is fully achieved and the project's checks pass, end your \
             reply with the line `{DONE_MARKER}`. If you cannot make progress without the \
             user, end it with `{BLOCKED_PREFIX} <reason>` instead."
        ));
        text
    }

    /// Judge the round that just finished. `until` is the outcome of the
    /// `--until` command, run after the turn (`None` when the goal has none
    /// or the turn did not complete). On [`Verdict::Continue`] the goal has
    /// moved to the next round.
    pub fn judge(&mut self, report: &TurnReport, until: Option<CheckOutcome>) -> Verdict {
        if report.cancelled {
            return Verdict::Stopped("stopped".into());
        }
        if report.approval_pending.is_some() {
            return Verdict::Stopped("waiting for an approval".into());
        }
        if report.budget_exhausted {
            return Verdict::Stopped("the session's token budget is used up".into());
        }
        if report.failed {
            return Verdict::Stopped("the turn failed".into());
        }
        let last = last_line(&report.final_text);
        if let Some(reason) = last.strip_prefix(BLOCKED_PREFIX) {
            let reason = reason.trim();
            return Verdict::Blocked(if reason.is_empty() {
                "no reason given".into()
            } else {
                reason.to_string()
            });
        }
        let claims_done = last == DONE_MARKER;
        let checks_ok = report.checks_passed != Some(false);
        if self.spec.until.is_some() {
            if until.as_ref().is_some_and(|o| o.success) && checks_ok {
                return Verdict::Reached(Confirmed::Until);
            }
        } else if claims_done && checks_ok {
            return Verdict::Reached(if report.checks_passed == Some(true) {
                Confirmed::Checks
            } else {
                Confirmed::AgentOnly
            });
        }
        self.last_until = until;
        if report.changed_files.is_empty() && !claims_done {
            self.idle_rounds += 1;
            if self.idle_rounds >= STALL_ROUNDS {
                return Verdict::Stalled;
            }
        } else {
            self.idle_rounds = 0;
        }
        if self.round >= self.spec.max_rounds {
            return Verdict::OutOfRounds;
        }
        self.round += 1;
        Verdict::Continue
    }

    /// One line for the user about a final verdict.
    pub fn summary(&self, verdict: &Verdict) -> String {
        let rounds = |n: u32| {
            if n == 1 {
                "1 round".to_string()
            } else {
                format!("{n} rounds")
            }
        };
        match verdict {
            Verdict::Continue => format!("goal: {}", self.progress()),
            Verdict::Reached(Confirmed::Until) => format!(
                "Goal reached in {}: `{}` succeeds.",
                rounds(self.round),
                self.spec.until.as_deref().unwrap_or_default()
            ),
            Verdict::Reached(Confirmed::Checks) => {
                format!("Goal reached in {}; the checks pass.", rounds(self.round))
            }
            Verdict::Reached(Confirmed::AgentOnly) => format!(
                "Goal reached in {}, by the agent's account (no check verified it).",
                rounds(self.round)
            ),
            Verdict::Blocked(reason) => {
                format!("Goal blocked after {}: {reason}", rounds(self.round))
            }
            Verdict::Stalled => format!(
                "Goal stopped after {}: {STALL_ROUNDS} rounds in a row changed no files.",
                rounds(self.round)
            ),
            Verdict::OutOfRounds => {
                format!("Goal not reached after {}; stopping.", rounds(self.round))
            }
            Verdict::Stopped(reason) => format!("Goal stopped: {reason}."),
        }
    }
}

/// Last non-empty line, without Markdown emphasis or code ticks around it.
fn last_line(text: &str) -> &str {
    text.lines()
        .map(str::trim)
        .rfind(|l| !l.is_empty())
        .unwrap_or("")
        .trim_matches(|c| c == '*' || c == '`' || c == '_')
        .trim()
}

/// Run a goal's `--until` command in `root`.
pub async fn run_until(root: &Path, command: &str) -> CheckOutcome {
    let check = Check {
        name: "until".into(),
        run: command.to_string(),
        auto: false,
        timeout_secs: None,
    };
    verify::run_check(root, &check).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn report(text: &str, changed: &[&str]) -> TurnReport {
        TurnReport {
            final_text: text.into(),
            changed_files: changed.iter().map(|s| s.to_string()).collect(),
            ..TurnReport::default()
        }
    }

    fn outcome(success: bool) -> CheckOutcome {
        CheckOutcome {
            check: Check {
                name: "until".into(),
                run: "cargo test".into(),
                auto: false,
                timeout_secs: None,
            },
            success,
            exit_code: Some(if success { 0 } else { 101 }),
            timed_out: false,
            duration: Duration::from_millis(5),
            output: "test result: FAILED. 1 failed".into(),
        }
    }

    fn goal(text: &str) -> Goal {
        Goal::new(GoalSpec::parse(text, DEFAULT_MAX_ROUNDS).unwrap())
    }

    #[test]
    fn parses_flags_in_any_order_and_quoted_commands() {
        let spec = GoalSpec::parse(
            r#"--rounds 3 --until "cargo test -p calc" make the tests pass"#,
            8,
        )
        .unwrap();
        assert_eq!(spec.objective, "make the tests pass");
        assert_eq!(spec.max_rounds, 3);
        assert_eq!(spec.until.as_deref(), Some("cargo test -p calc"));

        let spec = GoalSpec::parse("--until=make --max-rounds=12 ship it", 8).unwrap();
        assert_eq!(spec.until.as_deref(), Some("make"));
        assert_eq!(spec.max_rounds, 12);
        assert_eq!(spec.objective, "ship it");

        let spec = GoalSpec::parse("fix --until in the middle stays text", 5).unwrap();
        assert_eq!(spec.objective, "fix --until in the middle stays text");
        assert_eq!(spec.max_rounds, 5);
        assert_eq!(spec.until, None);
    }

    #[test]
    fn rejects_bad_arguments() {
        assert!(GoalSpec::parse("", 8).is_err());
        assert!(GoalSpec::parse("--until \"cargo test\"", 8).is_err());
        assert!(GoalSpec::parse("--rounds 0 x", 8).is_err());
        assert!(GoalSpec::parse("--rounds 99 x", 8).is_err());
        assert!(GoalSpec::parse("--until \"unterminated x", 8).is_err());
    }

    #[test]
    fn the_marker_counts_only_on_the_last_line() {
        let mut g = goal("x");
        let quoted = report(
            "I will print GOAL COMPLETE when done.\nStill working.",
            &["a"],
        );
        assert_eq!(g.judge(&quoted, None), Verdict::Continue);
        let done = report("All done.\n\n**GOAL COMPLETE**\n", &["a"]);
        assert_eq!(g.judge(&done, None), Verdict::Reached(Confirmed::AgentOnly));
    }

    #[test]
    fn a_failed_check_keeps_the_goal_going() {
        let mut g = goal("x");
        let mut r = report("done\nGOAL COMPLETE", &["a"]);
        r.checks_passed = Some(false);
        assert_eq!(g.judge(&r, None), Verdict::Continue);
        r.checks_passed = Some(true);
        assert_eq!(g.judge(&r, None), Verdict::Reached(Confirmed::Checks));
    }

    #[test]
    fn blocked_stops_with_the_reason() {
        let mut g = goal("x");
        let r = report("Tried.\nGOAL BLOCKED: needs the staging password", &[]);
        assert_eq!(
            g.judge(&r, None),
            Verdict::Blocked("needs the staging password".into())
        );
    }

    #[test]
    fn two_idle_rounds_stall() {
        let mut g = goal("x");
        assert_eq!(g.judge(&report("thinking", &[]), None), Verdict::Continue);
        assert_eq!(g.judge(&report("still", &[]), None), Verdict::Stalled);

        let mut g = goal("x");
        assert_eq!(g.judge(&report("a", &[]), None), Verdict::Continue);
        assert_eq!(g.judge(&report("b", &["f"]), None), Verdict::Continue);
        assert_eq!(g.judge(&report("c", &[]), None), Verdict::Continue);
    }

    #[test]
    fn the_round_limit_stops() {
        let mut g = goal("--rounds 2 x");
        assert_eq!(g.judge(&report("a", &["f"]), None), Verdict::Continue);
        assert_eq!(g.round, 2);
        assert_eq!(g.judge(&report("b", &["f"]), None), Verdict::OutOfRounds);
    }

    #[test]
    fn until_decides_and_its_failure_feeds_the_next_prompt() {
        let mut g = goal("--until \"cargo test\" fix it");
        let claimed = report("done\nGOAL COMPLETE", &["f"]);
        assert_eq!(g.judge(&claimed, Some(outcome(false))), Verdict::Continue);
        let prompt = g.prompt();
        assert!(prompt.contains("round 2 of at most 8"), "{prompt}");
        assert!(
            prompt.contains("`cargo test` failed (exit 101)"),
            "{prompt}"
        );
        assert!(prompt.contains("1 failed"), "{prompt}");
        let silent = report("changed more", &["f"]);
        assert_eq!(
            g.judge(&silent, Some(outcome(true))),
            Verdict::Reached(Confirmed::Until)
        );
    }

    #[test]
    fn interrupted_turns_stop() {
        let mut g = goal("x");
        let mut r = report("", &[]);
        r.cancelled = true;
        assert_eq!(g.judge(&r, None), Verdict::Stopped("stopped".into()));
        let mut r = report("", &[]);
        r.budget_exhausted = true;
        assert!(matches!(g.judge(&r, None), Verdict::Stopped(_)));
        let mut r = report("", &[]);
        r.failed = true;
        assert!(matches!(g.judge(&r, None), Verdict::Stopped(_)));
    }

    #[test]
    fn prompts_name_the_markers() {
        let g = goal("--until make ship");
        let p = g.prompt();
        assert!(p.starts_with("Goal: ship"));
        assert!(p.contains("`make` succeeds"));
        assert!(p.contains(DONE_MARKER) && p.contains(BLOCKED_PREFIX));
    }

    #[test]
    fn summaries_read_well() {
        let g = goal("--until \"cargo test\" x");
        assert_eq!(
            g.summary(&Verdict::Reached(Confirmed::Until)),
            "Goal reached in 1 round: `cargo test` succeeds."
        );
        assert!(g.summary(&Verdict::Stalled).contains("changed no files"));
    }
}
