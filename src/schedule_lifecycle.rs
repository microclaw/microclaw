//! Scheduled-task lifecycle: run caps, deadlines, and random ("spontaneous")
//! cadences.
//!
//! Design rule: flexibility never bends the state machine. Every lifecycle
//! feature resolves to the SAME primitive the scheduler already trusts —
//! "either there is a concrete `next_run`, or the task transitions to
//! `completed` with a logged reason". No new statuses, no background
//! bookkeeping; all decisions are pure functions over the task row, so every
//! edge is unit-testable without a database or a clock.
//!
//! Cadence types:
//! - `cron`   — unchanged (6-field expression, timezone-aware).
//! - `once`   — unchanged (single ISO timestamp).
//! - `random` — NEW: `schedule_value` is a duration range like `"2h..3d"`;
//!   after each run the next firing lands uniformly at random inside the
//!   window. Units: `s`, `m`, `h`, `d`, `w`, `mo` (≈30d). The window is
//!   clamped to [1 minute, 366 days] so a typo can neither hot-loop the
//!   scheduler nor silence a task for years.
//!
//! Lifecycle limits (orthogonal, apply to any cadence):
//! - `max_runs`  — retire the task as `completed` once it has run N times.
//! - `not_after` — retire the task as `completed` once the next firing would
//!   land past the deadline (checked again at claim time, so a task that was
//!   already queued cannot fire after its deadline either).

use chrono::{DateTime, Duration, Utc};

/// Outcome of post-run scheduling for a recurring task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NextRunDecision {
    /// Keep going: reschedule at this RFC 3339 instant.
    RunAt(String),
    /// Retire the task as `completed`, with a human-readable reason for logs.
    Finished(String),
}

/// Bounds for a `random` schedule window.
const MIN_RANDOM_INTERVAL: i64 = 60; // seconds
const MAX_RANDOM_INTERVAL: i64 = 366 * 24 * 3600;

/// Parse a single duration like `45s`, `30m`, `2h`, `3d`, `1w`, `2mo`.
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    let split = s
        .find(|c: char| !c.is_ascii_digit())
        .ok_or_else(|| format!("duration `{s}` is missing a unit (s/m/h/d/w/mo)"))?;
    let (num, unit) = s.split_at(split);
    let n: i64 = num
        .parse()
        .map_err(|_| format!("duration `{s}` has an invalid number"))?;
    if n <= 0 {
        return Err(format!("duration `{s}` must be positive"));
    }
    let seconds = match unit {
        "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        "d" => n * 86_400,
        "w" => n * 7 * 86_400,
        "mo" => n * 30 * 86_400,
        other => {
            return Err(format!(
                "duration `{s}` has unknown unit `{other}` (use s/m/h/d/w/mo)"
            ))
        }
    };
    Ok(Duration::seconds(seconds))
}

/// Parse a `random` schedule window: `"2h..3d"` (also accepts `"2h-3d"`).
/// Clamped to [1 minute, 366 days]; min must not exceed max.
pub fn parse_duration_range(spec: &str) -> Result<(Duration, Duration), String> {
    let spec = spec.trim();
    let (lo, hi) = spec
        .split_once("..")
        .or_else(|| spec.split_once('-'))
        .ok_or_else(|| {
            format!("random schedule `{spec}` must be a range like `2h..3d` or `30m..4h`")
        })?;
    let min = parse_duration(lo)?;
    let max = parse_duration(hi)?;
    if min.num_seconds() < MIN_RANDOM_INTERVAL {
        return Err(format!(
            "random window minimum `{lo}` is below 1 minute — that would hot-loop the scheduler"
        ));
    }
    if max.num_seconds() > MAX_RANDOM_INTERVAL {
        return Err(format!(
            "random window maximum `{hi}` exceeds 366 days — pick a shorter window"
        ));
    }
    if min > max {
        return Err(format!("random window `{spec}` has min > max"));
    }
    Ok((min, max))
}

/// Uniform sample inside the window. `unit` is injected (0.0 ≤ unit < 1.0)
/// so tests are deterministic; production passes [`random_unit`].
pub fn sample_random_next(
    now: DateTime<Utc>,
    min: Duration,
    max: Duration,
    unit: f64,
) -> DateTime<Utc> {
    let span = (max - min).num_seconds().max(0);
    let offset = min.num_seconds() + ((span as f64) * unit.clamp(0.0, 0.999_999)) as i64;
    now + Duration::seconds(offset)
}

/// Entropy in [0, 1) without adding an RNG dependency: the v4 UUID source is
/// already a CSPRNG. Scheduling jitter needs unpredictability, not statistics.
pub fn random_unit() -> f64 {
    let bytes = *uuid::Uuid::new_v4().as_bytes();
    let mut v: u64 = 0;
    for b in &bytes[..8] {
        v = (v << 8) | u64::from(*b);
    }
    // 53 usable mantissa bits keeps the conversion exact.
    (v >> 11) as f64 / (1u64 << 53) as f64
}

/// Decide what happens to a recurring (`cron` | `random`) task after a run.
/// `run_count_after` is the count INCLUDING the run that just finished.
#[allow(clippy::too_many_arguments)]
pub fn decide_next_run(
    schedule_type: &str,
    schedule_value: &str,
    tz: chrono_tz::Tz,
    now: DateTime<Utc>,
    run_count_after: i64,
    max_runs: Option<i64>,
    not_after: Option<DateTime<Utc>>,
    unit: f64,
) -> NextRunDecision {
    if let Some(max) = max_runs {
        if run_count_after >= max {
            return NextRunDecision::Finished(format!(
                "reached max_runs ({run_count_after}/{max})"
            ));
        }
    }

    let candidate: Option<DateTime<Utc>> = match schedule_type {
        "cron" => {
            use std::str::FromStr;
            match cron::Schedule::from_str(schedule_value) {
                Ok(schedule) => schedule
                    .upcoming(tz)
                    .next()
                    .map(|t| t.with_timezone(&Utc)),
                Err(_) => None,
            }
        }
        "random" => match parse_duration_range(schedule_value) {
            Ok((min, max)) => Some(sample_random_next(now, min, max, unit)),
            Err(_) => None,
        },
        _ => None,
    };

    let Some(candidate) = candidate else {
        return NextRunDecision::Finished(format!(
            "schedule `{schedule_value}` ({schedule_type}) is no longer computable"
        ));
    };

    if let Some(deadline) = not_after {
        if candidate > deadline {
            return NextRunDecision::Finished(format!(
                "next firing {} would pass not_after {}",
                candidate.to_rfc3339(),
                deadline.to_rfc3339()
            ));
        }
    }

    NextRunDecision::RunAt(candidate.to_rfc3339())
}

/// True when the task's deadline has already passed — checked at claim time
/// so an already-queued task cannot fire after `not_after`.
pub fn deadline_passed(not_after: Option<&str>, now: DateTime<Utc>) -> bool {
    not_after
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|d| d.with_timezone(&Utc) < now)
        .unwrap_or(false)
}

/// Human cadence summary for task listings.
pub fn describe_schedule(schedule_type: &str, schedule_value: &str) -> String {
    match schedule_type {
        "once" => format!("once at {schedule_value}"),
        "cron" => format!("cron `{schedule_value}`"),
        "random" => format!("randomly every {schedule_value}"),
        other => format!("{other} `{schedule_value}`"),
    }
}

/// Compact "in 3h 12m" / "overdue" rendering for a future RFC 3339 instant.
pub fn humanize_until(now: DateTime<Utc>, ts: &str) -> Option<String> {
    let when = DateTime::parse_from_rfc3339(ts).ok()?.with_timezone(&Utc);
    let secs = (when - now).num_seconds();
    if secs <= 0 {
        return Some("due now".to_string());
    }
    let (d, rem) = (secs / 86_400, secs % 86_400);
    let (h, rem) = (rem / 3600, rem % 3600);
    let m = rem / 60;
    Some(match (d, h, m) {
        (0, 0, m) => format!("in {}m", m.max(1)),
        (0, h, m) => format!("in {h}h {m}m"),
        (d, h, _) => format!("in {d}d {h}h"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn duration_parsing_units_and_errors() {
        assert_eq!(parse_duration("90s").unwrap().num_seconds(), 90);
        assert_eq!(parse_duration("30m").unwrap().num_minutes(), 30);
        assert_eq!(parse_duration("2h").unwrap().num_hours(), 2);
        assert_eq!(parse_duration("3d").unwrap().num_days(), 3);
        assert_eq!(parse_duration("1w").unwrap().num_days(), 7);
        assert_eq!(parse_duration("2mo").unwrap().num_days(), 60);
        assert!(parse_duration("5x").is_err());
        assert!(parse_duration("h").is_err());
        assert!(parse_duration("0m").is_err());
    }

    #[test]
    fn range_parsing_accepts_both_separators_and_clamps() {
        let (min, max) = parse_duration_range("2h..3d").unwrap();
        assert_eq!(min.num_hours(), 2);
        assert_eq!(max.num_days(), 3);
        let (min, _) = parse_duration_range("30m-4h").unwrap();
        assert_eq!(min.num_minutes(), 30);
        // Guard rails: hot-loop and multi-year windows rejected.
        assert!(parse_duration_range("5s..1h").is_err());
        assert!(parse_duration_range("1d..24mo").is_err());
        assert!(parse_duration_range("3d..2h").is_err());
        assert!(parse_duration_range("2h").is_err());
    }

    #[test]
    fn random_sampling_stays_inside_window() {
        let now = t("2026-07-11T00:00:00Z");
        let (min, max) = parse_duration_range("2h..3d").unwrap();
        for unit in [0.0, 0.25, 0.5, 0.999] {
            let next = sample_random_next(now, min, max, unit);
            assert!(next >= now + Duration::hours(2), "unit={unit}");
            assert!(next <= now + Duration::days(3), "unit={unit}");
        }
        // Degenerate window (min == max) is exact.
        let next = sample_random_next(now, min, min, 0.7);
        assert_eq!(next, now + Duration::hours(2));
    }

    #[test]
    fn random_unit_is_in_range() {
        for _ in 0..64 {
            let u = random_unit();
            assert!((0.0..1.0).contains(&u));
        }
    }

    #[test]
    fn max_runs_retires_task() {
        let d = decide_next_run(
            "random",
            "2h..3d",
            chrono_tz::UTC,
            t("2026-07-11T00:00:00Z"),
            5,
            Some(5),
            None,
            0.5,
        );
        assert!(matches!(d, NextRunDecision::Finished(ref r) if r.contains("max_runs")));
        // Under the cap: keeps running.
        let d = decide_next_run(
            "random",
            "2h..3d",
            chrono_tz::UTC,
            t("2026-07-11T00:00:00Z"),
            4,
            Some(5),
            None,
            0.5,
        );
        assert!(matches!(d, NextRunDecision::RunAt(_)));
    }

    #[test]
    fn deadline_retires_task_when_next_firing_passes_it() {
        let now = t("2026-07-11T00:00:00Z");
        // Next random firing lands at now+2h..3d; deadline in 1h -> retire.
        let d = decide_next_run(
            "random",
            "2h..3d",
            chrono_tz::UTC,
            now,
            1,
            None,
            Some(t("2026-07-11T01:00:00Z")),
            0.0,
        );
        assert!(matches!(d, NextRunDecision::Finished(ref r) if r.contains("not_after")));
        // Deadline far away -> keeps running.
        let d = decide_next_run(
            "random",
            "2h..3d",
            chrono_tz::UTC,
            now,
            1,
            None,
            Some(t("2026-12-31T00:00:00Z")),
            0.0,
        );
        assert!(matches!(d, NextRunDecision::RunAt(_)));
    }

    #[test]
    fn cron_still_schedules_and_respects_deadline() {
        let now = t("2026-07-11T00:00:00Z");
        let d = decide_next_run(
            "cron",
            "0 0 * * * *", // hourly
            chrono_tz::UTC,
            now,
            10,
            None,
            None,
            0.5,
        );
        assert!(matches!(d, NextRunDecision::RunAt(_)));
        let d = decide_next_run(
            "cron",
            "0 0 12 1 1 *", // once a year
            chrono_tz::UTC,
            now,
            1,
            None,
            Some(t("2026-08-01T00:00:00Z")),
            0.5,
        );
        assert!(matches!(d, NextRunDecision::Finished(_)));
    }

    #[test]
    fn invalid_schedule_finishes_instead_of_looping() {
        let d = decide_next_run(
            "cron",
            "not a cron",
            chrono_tz::UTC,
            t("2026-07-11T00:00:00Z"),
            1,
            None,
            None,
            0.5,
        );
        assert!(matches!(d, NextRunDecision::Finished(_)));
    }

    #[test]
    fn deadline_passed_checks_claim_time() {
        let now = t("2026-07-11T12:00:00Z");
        assert!(deadline_passed(Some("2026-07-11T11:00:00Z"), now));
        assert!(!deadline_passed(Some("2026-07-11T13:00:00Z"), now));
        assert!(!deadline_passed(None, now));
        // Unparseable deadline fails open (does not silently kill the task);
        // creation-time validation is the real gate.
        assert!(!deadline_passed(Some("garbage"), now));
    }

    #[test]
    fn humanize_until_renders_compact() {
        let now = t("2026-07-11T00:00:00Z");
        assert_eq!(
            humanize_until(now, "2026-07-11T00:05:00Z").unwrap(),
            "in 5m"
        );
        assert_eq!(
            humanize_until(now, "2026-07-11T03:30:00Z").unwrap(),
            "in 3h 30m"
        );
        assert_eq!(
            humanize_until(now, "2026-07-13T06:00:00Z").unwrap(),
            "in 2d 6h"
        );
        assert_eq!(
            humanize_until(now, "2026-07-10T00:00:00Z").unwrap(),
            "due now"
        );
    }
}
