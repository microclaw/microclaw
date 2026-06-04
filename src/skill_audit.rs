//! Deterministic skill curation audit.
//!
//! `skill_review` distills a reusable skill from a *single* completed session,
//! and the reflector retires skills purely by inactivity age. Neither gives a
//! cross-skill view of the on-disk corpus. This module fills that gap with a
//! read-only, deterministic audit — no LLM, no DB, no mutation — that surfaces
//! the signals a curator (human or, later, an LLM pass) needs:
//!
//! * **near-duplicate** skills (token-Jaccard over name + description) — merge
//!   candidates, and a strong retire signal when an `agent-created` skill
//!   shadows a built-in one;
//! * **stale** `agent-created` skills (no recent `updated_at`) — retire
//!   candidates;
//! * **thin** `agent-created` skills (near-empty body) — flesh-out or retire;
//! * **cap headroom** against the `agent-created` ceiling.
//!
//! Built-in / human-curated skills (`source` other than `agent-created`) are
//! immutable, so they are never flagged as stale/thin retire candidates; they
//! still participate in duplicate detection so an agent skill that merely
//! restates a built-in is caught.

use crate::skills::parse_skill_md;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::HashSet;
use std::path::Path;

/// The `agent-created` ceiling enforced by `skill_review`. Mirrored here so the
/// audit can report headroom against the same number.
pub const DEFAULT_MAX_AGENT_SKILLS: usize = 20;

/// Tunable thresholds for the audit.
#[derive(Debug, Clone)]
pub struct AuditConfig {
    /// Token-Jaccard at or above which two skills are "near-duplicate" (0.0-1.0).
    pub similarity: f64,
    /// An `agent-created` skill whose `updated_at` is older than this many days
    /// (or absent) is a stale retire candidate.
    pub stale_days: i64,
    /// An `agent-created` skill whose body is shorter than this many characters
    /// (after trimming) is a thin retire candidate.
    pub min_body_chars: usize,
    /// The `agent-created` ceiling, for headroom reporting.
    pub max_agent_skills: usize,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            similarity: 0.5,
            stale_days: 30,
            min_body_chars: 80,
            max_agent_skills: DEFAULT_MAX_AGENT_SKILLS,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct DuplicatePair {
    pub a: String,
    pub b: String,
    pub similarity: f64,
    /// Names that are `agent-created` (and thus the side(s) safe to retire).
    pub retire_candidates: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct StaleSkill {
    pub name: String,
    /// Age in whole days, or `None` when `updated_at` is missing/unparseable.
    pub age_days: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct ThinSkill {
    pub name: String,
    pub body_chars: usize,
}

#[derive(Debug, Serialize)]
pub struct CapStatus {
    pub agent_created: usize,
    pub max: usize,
    /// True once the ceiling is reached (no further agent skills can be created).
    pub at_capacity: bool,
}

#[derive(Debug, Serialize)]
pub struct AuditReport {
    pub skills_dir: String,
    pub total_skills: usize,
    pub agent_created: usize,
    pub near_duplicates: Vec<DuplicatePair>,
    pub stale: Vec<StaleSkill>,
    pub thin: Vec<ThinSkill>,
    pub cap: CapStatus,
    /// True when nothing actionable was found.
    pub clean: bool,
}

impl AuditReport {
    /// Whether the audit found anything a curator should act on. Drives the
    /// `--strict` exit code.
    pub fn has_findings(&self) -> bool {
        !self.near_duplicates.is_empty()
            || !self.stale.is_empty()
            || !self.thin.is_empty()
            || self.cap.at_capacity
    }
}

/// One parsed skill, reduced to the fields the audit reasons about.
struct ParsedSkill {
    name: String,
    source: String,
    updated_at: Option<String>,
    /// Lowercased token set over name + description, for similarity.
    tokens: HashSet<String>,
    body_chars: usize,
}

impl ParsedSkill {
    fn is_agent_created(&self) -> bool {
        self.source == "agent-created"
    }
}

/// Split text into lowercased alphanumeric tokens of length >= 3.
fn tokenize(text: &str) -> HashSet<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.len() >= 3)
        .map(|t| t.to_lowercase())
        .collect()
}

/// Jaccard index of two token sets: |A∩B| / |A∪B|. Empty/empty is 0.0.
fn jaccard(a: &HashSet<String>, b: &HashSet<String>) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 0.0;
    }
    let inter = a.intersection(b).count() as f64;
    let union = a.union(b).count() as f64;
    if union == 0.0 {
        0.0
    } else {
        inter / union
    }
}

/// Whole-day age of an RFC3339 timestamp relative to `now`. `None` if unparseable.
fn age_days(updated_at: &str, now: DateTime<Utc>) -> Option<i64> {
    let parsed = DateTime::parse_from_rfc3339(updated_at).ok()?;
    Some((now - parsed.with_timezone(&Utc)).num_days())
}

/// Read and parse every `<dir>/*/SKILL.md` into the reduced form.
fn load_skills(skills_dir: &Path) -> Vec<ParsedSkill> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(skills_dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        let skill_md = dir.join("SKILL.md");
        let Ok(content) = std::fs::read_to_string(&skill_md) else {
            continue;
        };
        let Some((meta, body)) = parse_skill_md(&content, &dir) else {
            continue;
        };
        let mut tokens = tokenize(&meta.name);
        tokens.extend(tokenize(&meta.description));
        out.push(ParsedSkill {
            name: meta.name,
            source: meta.source,
            updated_at: meta.updated_at,
            tokens,
            body_chars: body.trim().chars().count(),
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Run the audit against a parsed corpus at a fixed `now` (injected for tests).
fn audit_at(skills_dir: &str, skills: &[ParsedSkill], cfg: &AuditConfig, now: DateTime<Utc>) -> AuditReport {
    // Near-duplicates: every unordered pair at or above the threshold.
    let mut near_duplicates = Vec::new();
    for i in 0..skills.len() {
        for j in (i + 1)..skills.len() {
            let sim = jaccard(&skills[i].tokens, &skills[j].tokens);
            if sim >= cfg.similarity {
                let mut retire_candidates = Vec::new();
                if skills[i].is_agent_created() {
                    retire_candidates.push(skills[i].name.clone());
                }
                if skills[j].is_agent_created() {
                    retire_candidates.push(skills[j].name.clone());
                }
                near_duplicates.push(DuplicatePair {
                    a: skills[i].name.clone(),
                    b: skills[j].name.clone(),
                    similarity: (sim * 1000.0).round() / 1000.0,
                    retire_candidates,
                });
            }
        }
    }

    // Stale / thin: agent-created skills only (others are immutable).
    let mut stale = Vec::new();
    let mut thin = Vec::new();
    let mut agent_created = 0usize;
    for s in skills {
        if !s.is_agent_created() {
            continue;
        }
        agent_created += 1;

        let age = s.updated_at.as_deref().and_then(|ts| age_days(ts, now));
        let is_stale = match age {
            Some(d) => d >= cfg.stale_days,
            None => true, // missing/unparseable timestamp: can't prove fresh
        };
        if is_stale {
            stale.push(StaleSkill { name: s.name.clone(), age_days: age });
        }

        if s.body_chars < cfg.min_body_chars {
            thin.push(ThinSkill { name: s.name.clone(), body_chars: s.body_chars });
        }
    }

    let cap = CapStatus {
        agent_created,
        max: cfg.max_agent_skills,
        at_capacity: agent_created >= cfg.max_agent_skills,
    };

    let mut report = AuditReport {
        skills_dir: skills_dir.to_string(),
        total_skills: skills.len(),
        agent_created,
        near_duplicates,
        stale,
        thin,
        cap,
        clean: false,
    };
    report.clean = !report.has_findings();
    report
}

/// Audit the skills directory and return a structured report.
pub fn audit_skills(skills_dir: &str, cfg: &AuditConfig) -> AuditReport {
    let skills = load_skills(Path::new(skills_dir));
    audit_at(skills_dir, &skills, cfg, Utc::now())
}

/// CLI entry point. Prints the report (text or `--json`) and returns the
/// process exit code: always 0 unless `strict` is set and there are findings.
pub fn run_audit(skills_dir: &str, cfg: &AuditConfig, json: bool, strict: bool) -> i32 {
    let report = audit_skills(skills_dir, cfg);

    if json {
        match serde_json::to_string_pretty(&report) {
            Ok(s) => println!("{s}"),
            Err(e) => eprintln!("failed to serialize report: {e}"),
        }
    } else {
        print_text(&report);
    }

    if strict && report.has_findings() {
        1
    } else {
        0
    }
}

fn print_text(r: &AuditReport) {
    println!(
        "Skill audit: {} ({} skills, {} agent-created)",
        r.skills_dir, r.total_skills, r.agent_created
    );

    if !r.near_duplicates.is_empty() {
        println!("\nNear-duplicate skills (merge candidates):");
        for d in &r.near_duplicates {
            let retire = if d.retire_candidates.is_empty() {
                "both built-in/curated".to_string()
            } else {
                format!("retire candidate(s): {}", d.retire_candidates.join(", "))
            };
            println!("  - {} ~ {}  (similarity {:.3}; {})", d.a, d.b, d.similarity, retire);
        }
    }

    if !r.stale.is_empty() {
        println!("\nStale agent-created skills (retire candidates):");
        for s in &r.stale {
            match s.age_days {
                Some(d) => println!("  - {}  ({d} days since last update)", s.name),
                None => println!("  - {}  (no/invalid updated_at)", s.name),
            }
        }
    }

    if !r.thin.is_empty() {
        println!("\nThin agent-created skills (flesh out or retire):");
        for t in &r.thin {
            println!("  - {}  ({} body chars)", t.name, t.body_chars);
        }
    }

    if r.cap.at_capacity {
        println!(
            "\nAgent-created skill cap reached: {}/{} — retire some before new ones can be distilled.",
            r.cap.agent_created, r.cap.max
        );
    } else {
        println!(
            "\nAgent-created cap: {}/{} ({} slot(s) free).",
            r.cap.agent_created,
            r.cap.max,
            r.cap.max.saturating_sub(r.cap.agent_created)
        );
    }

    if r.clean {
        println!("\nNo curation actions needed.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn skill(name: &str, source: &str, desc: &str, updated_at: Option<&str>, body_chars: usize) -> ParsedSkill {
        let mut tokens = tokenize(name);
        tokens.extend(tokenize(desc));
        ParsedSkill {
            name: name.into(),
            source: source.into(),
            updated_at: updated_at.map(|s| s.into()),
            tokens,
            body_chars,
        }
    }

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-06-04T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn jaccard_basics() {
        let a = tokenize("deploy the web server quickly");
        let b = tokenize("deploy the web server quickly");
        assert!((jaccard(&a, &b) - 1.0).abs() < 1e-9);
        let c = tokenize("bake a chocolate cake");
        assert!(jaccard(&a, &c) < 0.2);
    }

    #[test]
    fn flags_near_duplicate_and_marks_agent_side() {
        let skills = vec![
            skill("deploy-web", "builtin", "deploy the web server to production", None, 500),
            skill("ship-web", "agent-created", "deploy the web server to production", Some("2026-06-01T00:00:00Z"), 500),
        ];
        let r = audit_at("d", &skills, &AuditConfig::default(), now());
        assert_eq!(r.near_duplicates.len(), 1);
        // Only the agent-created side is a retire candidate.
        assert_eq!(r.near_duplicates[0].retire_candidates, vec!["ship-web".to_string()]);
        assert!(r.has_findings());
    }

    #[test]
    fn distinct_skills_are_clean() {
        let skills = vec![
            skill("bake-cake", "builtin", "bake a chocolate cake in the oven", None, 500),
            skill("file-taxes", "builtin", "compute and submit annual income taxes", None, 500),
        ];
        let r = audit_at("d", &skills, &AuditConfig::default(), now());
        assert!(r.near_duplicates.is_empty());
        assert!(r.clean, "report: {r:?}");
    }

    #[test]
    fn stale_only_applies_to_agent_created() {
        let skills = vec![
            // Old built-in: immutable, never flagged stale.
            skill("old-builtin", "builtin", "alpha beta gamma", Some("2000-01-01T00:00:00Z"), 500),
            // Old agent skill: stale.
            skill("old-agent", "agent-created", "delta epsilon zeta", Some("2026-01-01T00:00:00Z"), 500),
            // Fresh agent skill: not stale.
            skill("fresh-agent", "agent-created", "eta theta iota", Some("2026-06-03T00:00:00Z"), 500),
        ];
        let r = audit_at("d", &skills, &AuditConfig::default(), now());
        let names: Vec<&str> = r.stale.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["old-agent"]);
    }

    #[test]
    fn missing_timestamp_is_stale() {
        let skills = vec![skill("no-date", "agent-created", "kappa lambda mu", None, 500)];
        let r = audit_at("d", &skills, &AuditConfig::default(), now());
        assert_eq!(r.stale.len(), 1);
        assert_eq!(r.stale[0].age_days, None);
    }

    #[test]
    fn thin_body_flagged() {
        let skills = vec![
            skill("thin", "agent-created", "nu xi omicron", Some("2026-06-03T00:00:00Z"), 10),
            skill("rich", "agent-created", "pi rho sigma", Some("2026-06-03T00:00:00Z"), 500),
        ];
        let r = audit_at("d", &skills, &AuditConfig::default(), now());
        let names: Vec<&str> = r.thin.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, vec!["thin"]);
    }

    #[test]
    fn cap_at_capacity() {
        let cfg = AuditConfig { max_agent_skills: 2, ..AuditConfig::default() };
        let skills = vec![
            skill("a", "agent-created", "aaa bbb ccc", Some("2026-06-03T00:00:00Z"), 500),
            skill("b", "agent-created", "ddd eee fff", Some("2026-06-03T00:00:00Z"), 500),
        ];
        let r = audit_at("d", &skills, &cfg, now());
        assert!(r.cap.at_capacity);
        assert!(r.has_findings());
    }
}
