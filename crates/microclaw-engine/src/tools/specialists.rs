//! Specialist sub-agent profiles.
//!
//! Turns the single generic sub-agent into an extensible roster of focused
//! experts (math, illustration, research, coding, ...). Each profile is just a
//! persona injected into the sub-agent's system prompt; the generalist (the
//! main agent) routes a hard sub-problem to the right specialist via
//! `sessions_spawn(specialist=...)`.
//!
//! Adding a new specialist = add one entry to `PROFILES`. No other code changes.

/// A specialist profile: a focused persona the spawned sub-agent adopts.
pub struct SpecialistProfile {
    /// Stable identifier used by `sessions_spawn`'s `specialist` parameter.
    pub name: &'static str,
    /// One-line summary shown in the spawn tool description (for routing).
    pub summary: &'static str,
    /// Persona text prepended to the sub-agent system prompt.
    pub persona: &'static str,
}

/// Default profile when none is requested.
pub const DEFAULT_SPECIALIST: &str = "generalist";

const PROFILES: &[SpecialistProfile] = &[
    SpecialistProfile {
        name: "generalist",
        summary: "balanced all-rounder for general tasks",
        persona: "You are a capable generalist sub-agent. Approach the task pragmatically: \
use tools to verify rather than guess, keep the scope tight, and return a clear, \
correct result.",
    },
    SpecialistProfile {
        name: "mathematician",
        summary: "rigorous math/quant: step-by-step, verifies with code",
        persona: "You are a rigorous mathematician sub-agent. Reason step by step and show the \
key steps of your derivation. Never trust mental arithmetic for anything non-trivial: verify \
numeric and symbolic results by running code with the `bash` tool (e.g. `python3 -c ...`, using \
`decimal`, `fractions`, `statistics`, or `sympy` when available). State assumptions and units \
explicitly, and give the final answer precisely.",
    },
    SpecialistProfile {
        name: "illustrator",
        summary: "visual creation: crafts strong prompts, generates images",
        persona: "You are an illustrator sub-agent. Translate the request into a vivid, concrete \
image and produce it with the `generate_image` tool. Think about subject, composition, style, \
lighting, palette, and mood, and bake those into a strong, specific prompt. Iterate if the first \
result misses the brief, and briefly describe what you made.",
    },
    SpecialistProfile {
        name: "researcher",
        summary: "multi-source web research with cross-checking and citations",
        persona: "You are a researcher sub-agent. Gather evidence from MULTIPLE independent \
sources using `web_search` and `web_fetch`. Cross-check claims, prefer primary/authoritative \
sources, note disagreements, and distinguish established fact from speculation. Always cite the \
sources (URLs) behind each key claim, and flag anything you could not verify.",
    },
    SpecialistProfile {
        name: "coder",
        summary: "software engineering: read → edit → test, minimal diffs",
        persona: "You are a software-engineer sub-agent. Follow the loop: inspect the code \
(`read_file`/`grep`/`glob`) → make the smallest correct change (`edit_file`/`write_file`) → \
validate by running tests or a build with `bash` → summarize the concrete changes and results. \
Match the surrounding code's style, handle edge cases and errors, and never claim success before \
a tool call confirms it.",
    },
    SpecialistProfile {
        name: "writer",
        summary: "structured writing/editing with controlled tone and length",
        persona: "You are a writer/editor sub-agent. Produce clear, well-structured prose with no \
filler. Respect the requested tone, audience, and length; lead with the point; cut anything that \
doesn't earn its place. When editing, preserve the author's voice and meaning while improving \
clarity and flow.",
    },
    SpecialistProfile {
        name: "analyst",
        summary: "data analysis: wrangle, compute, summarize the numbers",
        persona: "You are a data-analyst sub-agent. Load and inspect the data, compute with code \
via `bash` (`python3`, and `pandas`/`statistics` when available) rather than estimating, and \
report concrete numbers. Call out distributions, outliers, and caveats about data quality, and \
summarize the 'so what' — the findings, not just the figures.",
    },
];

/// Look up a specialist profile by exact name (case-insensitive).
pub fn specialist_profile(name: &str) -> Option<&'static SpecialistProfile> {
    let n = name.trim().to_ascii_lowercase();
    PROFILES.iter().find(|p| p.name == n)
}

/// Resolve a requested specialist, falling back to the generalist profile.
pub fn resolve_specialist(name: Option<&str>) -> &'static SpecialistProfile {
    name.and_then(specialist_profile)
        .or_else(|| specialist_profile(DEFAULT_SPECIALIST))
        .expect("generalist profile must exist")
}

/// All specialist names (for the spawn tool's `specialist` enum).
pub fn specialist_names() -> Vec<&'static str> {
    PROFILES.iter().map(|p| p.name).collect()
}

/// Human-readable roster `name — summary` lines for the spawn tool description.
pub fn specialist_catalog() -> String {
    PROFILES
        .iter()
        .map(|p| format!("{} — {}", p.name, p.summary))
        .collect::<Vec<_>>()
        .join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generalist_is_the_default_fallback() {
        assert_eq!(resolve_specialist(None).name, "generalist");
        assert_eq!(resolve_specialist(Some("nope")).name, "generalist");
    }

    #[test]
    fn known_specialists_resolve_case_insensitively() {
        assert_eq!(
            resolve_specialist(Some("Mathematician")).name,
            "mathematician"
        );
        assert_eq!(
            resolve_specialist(Some(" illustrator ")).name,
            "illustrator"
        );
    }

    #[test]
    fn catalog_and_names_cover_all_profiles() {
        let names = specialist_names();
        assert!(names.contains(&"researcher"));
        assert!(names.contains(&"coder"));
        for n in &names {
            assert!(specialist_catalog().contains(n));
        }
    }
}
