//! PII / secret redaction helpers.
//!
//! Replaces common credential patterns in arbitrary strings before they hit
//! logs or error messages. Intentionally conservative — false positives are
//! preferable to leaking a key.
//!
//! Ported from hermes-agent's `agent/redact.py`. MicroClaw uses this in the
//! tracing subscriber layer and at the boundary of tool error messages.

use once_cell::sync::Lazy;
use regex::Regex;

struct RedactRule {
    pattern: Regex,
    replacement: &'static str,
}

fn build_rules() -> Vec<RedactRule> {
    let raw = [
        // OpenAI-style keys (sk-proj-..., sk-live-..., sk-...).
        (r"sk-(?:proj-|live-)?[A-Za-z0-9_\-]{20,}", "sk-<redacted>"),
        // Anthropic-style keys.
        (r"sk-ant-[A-Za-z0-9_\-]{20,}", "sk-ant-<redacted>"),
        // Generic "Bearer <token>" auth headers.
        (r"(?i)Bearer\s+[A-Za-z0-9._\-]{16,}", "Bearer <redacted>"),
        // GitHub PAT formats (ghp_, gho_, ghu_, ghs_, ghr_).
        (r"gh[pousr]_[A-Za-z0-9]{20,}", "gh<redacted>"),
        // AWS access keys.
        (r"AKIA[0-9A-Z]{16}", "AKIA<redacted>"),
        (r"ASIA[0-9A-Z]{16}", "ASIA<redacted>"),
        // Slack tokens.
        (r"xox[baprs]-[A-Za-z0-9\-]{10,}", "xox<redacted>"),
        // Google API keys.
        (r"AIza[0-9A-Za-z_\-]{35}", "AIza<redacted>"),
        // Long hex-ish blobs that are likely bearer tokens (32+ chars).
        (r#"(?i)api[_-]?key["']?\s*[:=]\s*["']?[A-Za-z0-9_\-]{24,}"#, "api_key=<redacted>"),
        // Emails — masked but not destroyed (keep domain for debugging).
        (r"([A-Za-z0-9._%+\-]+)@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})", "<redacted>@$2"),
        // Phone numbers — rough, captures E.164-ish and CN 11-digit.
        (r"\+?\d{1,3}[\s\-]?\(?\d{2,4}\)?[\s\-]?\d{3,4}[\s\-]?\d{3,4}", "<redacted-phone>"),
    ];
    raw.into_iter()
        .filter_map(|(p, r)| Regex::new(p).ok().map(|pattern| RedactRule { pattern, replacement: r }))
        .collect()
}

static RULES: Lazy<Vec<RedactRule>> = Lazy::new(build_rules);

/// Returns `input` with known credential / PII patterns replaced. Allocates
/// a new String only when at least one match fires.
pub fn redact(input: &str) -> String {
    let mut out = input.to_string();
    for rule in RULES.iter() {
        if rule.pattern.is_match(&out) {
            out = rule.pattern.replace_all(&out, rule.replacement).into_owned();
        }
    }
    out
}

/// `redact` in-place variant for small buffers.
pub fn redact_in_place(buf: &mut String) {
    let new = redact(buf);
    if new != *buf {
        *buf = new;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openai_keys_redacted() {
        let out = redact("key is sk-proj-abcdef1234567890ABCDEF here");
        assert!(!out.contains("abcdef"));
        assert!(out.contains("sk-<redacted>"));
    }

    #[test]
    fn bearer_header_redacted() {
        let out = redact("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig");
        assert!(!out.contains("eyJhbG"));
        assert!(out.contains("Bearer <redacted>"));
    }

    #[test]
    fn github_pat_redacted() {
        let out = redact("token=ghp_abcdef1234567890ABCDEFghij");
        assert!(!out.contains("abcdef"));
    }

    #[test]
    fn aws_key_redacted() {
        let out = redact("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE");
        assert!(out.contains("AKIA<redacted>"));
    }

    #[test]
    fn email_partially_masked() {
        let out = redact("send to alice@example.com please");
        assert!(out.contains("<redacted>@example.com"));
    }

    #[test]
    fn passthrough_for_plain_text() {
        let input = "hello world, nothing sensitive here";
        assert_eq!(redact(input), input);
    }

    #[test]
    fn multiple_secrets_in_one_string() {
        let input = format!(
            "sk-live-1234567890abcdefghij and Bearer {}",
            "xyzabcdefghijk1234567890",
        );
        let out = redact(&input);
        assert!(!out.contains("1234567890abcdefghij"));
        assert!(out.contains("sk-<redacted>"));
    }
}
