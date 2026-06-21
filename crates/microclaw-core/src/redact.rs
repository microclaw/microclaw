//! PII / secret redaction helpers.
//!
//! Replaces common credential patterns in arbitrary strings before they hit
//! logs or error messages. Intentionally conservative — false positives are
//! preferable to leaking a key.
//!
//! Ported from hermes-agent's `agent/redact.py`. MicroClaw uses this in the
//! tracing subscriber layer and at the boundary of tool error messages.
//!
//! Two rule sets are kept separate:
//!
//! * **secret rules** — high-confidence credential formats (API keys, tokens,
//!   private-key material). These have effectively zero false positives, so
//!   they are safe to strip from *outbound* messages via the output guardrail
//!   ([`apply_output_guardrail`]).
//! * **PII rules** — emails / phone numbers. Useful for log scrubbing, but they
//!   must NOT be applied to outbound replies (the bot legitimately sends email
//!   addresses and phone numbers to users). They are only used by [`redact`].

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

struct RedactRule {
    pattern: Regex,
    replacement: &'static str,
    category: &'static str,
}

fn compile(rules: &[(&str, &'static str, &'static str)]) -> Vec<RedactRule> {
    rules
        .iter()
        .filter_map(|(p, r, c)| {
            Regex::new(p).ok().map(|pattern| RedactRule {
                pattern,
                replacement: r,
                category: c,
            })
        })
        .collect()
}

/// High-confidence credential patterns. Safe to strip from outbound text.
fn secret_rules() -> Vec<RedactRule> {
    compile(&[
        // OpenAI-style keys (sk-proj-..., sk-live-..., sk-...).
        (
            r"sk-(?:proj-|live-)?[A-Za-z0-9_\-]{20,}",
            "sk-<redacted>",
            "openai_key",
        ),
        // Anthropic-style keys.
        (
            r"sk-ant-[A-Za-z0-9_\-]{20,}",
            "sk-ant-<redacted>",
            "anthropic_key",
        ),
        // Generic "Bearer <token>" auth headers.
        (
            r"(?i)Bearer\s+[A-Za-z0-9._\-]{16,}",
            "Bearer <redacted>",
            "bearer_token",
        ),
        // GitHub PAT formats (ghp_, gho_, ghu_, ghs_, ghr_).
        (r"gh[pousr]_[A-Za-z0-9]{20,}", "gh<redacted>", "github_pat"),
        // AWS access keys.
        (r"AKIA[0-9A-Z]{16}", "AKIA<redacted>", "aws_key"),
        (r"ASIA[0-9A-Z]{16}", "ASIA<redacted>", "aws_key"),
        // Slack tokens.
        (
            r"xox[baprs]-[A-Za-z0-9\-]{10,}",
            "xox<redacted>",
            "slack_token",
        ),
        // Google API keys.
        (r"AIza[0-9A-Za-z_\-]{35}", "AIza<redacted>", "google_key"),
        // PEM private-key blocks.
        (
            r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
            "<redacted-private-key>",
            "private_key",
        ),
        // `api_key = <value>` style assignments.
        (
            r#"(?i)api[_-]?key["']?\s*[:=]\s*["']?[A-Za-z0-9_\-]{24,}"#,
            "api_key=<redacted>",
            "api_key_assignment",
        ),
    ])
}

/// PII patterns. Used for log scrubbing only — never on outbound replies.
fn pii_rules() -> Vec<RedactRule> {
    compile(&[
        // Emails — masked but not destroyed (keep domain for debugging).
        (
            r"([A-Za-z0-9._%+\-]+)@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})",
            "<redacted>@$2",
            "email",
        ),
        // Phone numbers — rough, captures E.164-ish and CN 11-digit.
        (
            r"\+?\d{1,3}[\s\-]?\(?\d{2,4}\)?[\s\-]?\d{3,4}[\s\-]?\d{3,4}",
            "<redacted-phone>",
            "phone",
        ),
    ])
}

static SECRET_RULES: Lazy<Vec<RedactRule>> = Lazy::new(secret_rules);
static PII_RULES: Lazy<Vec<RedactRule>> = Lazy::new(pii_rules);

fn apply_rules(input: &str, rules: &[RedactRule]) -> String {
    let mut out = input.to_string();
    for rule in rules {
        if rule.pattern.is_match(&out) {
            out = rule.pattern.replace_all(&out, rule.replacement).into_owned();
        }
    }
    out
}

/// Returns `input` with known credential **and** PII patterns replaced. Use for
/// logs and error messages. Allocates a new String only when a match fires.
pub fn redact(input: &str) -> String {
    let secrets = apply_rules(input, &SECRET_RULES);
    apply_rules(&secrets, &PII_RULES)
}

/// `redact` in-place variant for small buffers.
pub fn redact_in_place(buf: &mut String) {
    let new = redact(buf);
    if new != *buf {
        *buf = new;
    }
}

/// Returns `input` with **credential** patterns replaced, leaving PII (emails /
/// phone numbers) intact. This is the variant safe to apply to outbound bot
/// messages.
pub fn redact_secrets(input: &str) -> String {
    apply_rules(input, &SECRET_RULES)
}

/// Returns the distinct credential categories detected in `input` (e.g.
/// `["openai_key", "github_pat"]`), or empty if none.
pub fn scan_secrets(input: &str) -> Vec<&'static str> {
    let mut found: Vec<&'static str> = Vec::new();
    for rule in SECRET_RULES.iter() {
        if rule.pattern.is_match(input) && !found.contains(&rule.category) {
            found.push(rule.category);
        }
    }
    found
}

/// Output guardrail policy for outbound bot messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputGuardrailMode {
    /// No scanning — historical behavior (default).
    #[default]
    Off,
    /// Replace detected credentials with placeholders; still deliver.
    Redact,
    /// Withhold the whole message when a credential is detected.
    Block,
}

/// Output guardrail configuration block.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct OutputGuardrailConfig {
    #[serde(default)]
    pub mode: OutputGuardrailMode,
}

/// Result of applying the output guardrail to a piece of text.
pub struct OutputGuardrailOutcome {
    /// The text to actually deliver (redacted, or a block notice).
    pub text: String,
    /// Credential categories that were detected.
    pub categories: Vec<&'static str>,
    /// True when the message was withheld (block mode).
    pub blocked: bool,
}

/// Notice substituted for a message that the guardrail blocked.
pub const OUTPUT_BLOCKED_NOTICE: &str =
    "[message withheld by output guardrail: a credential-like string was detected]";

/// Apply the output guardrail to outbound `text`. Returns `None` when the mode
/// is `Off` or no credential is detected (the caller delivers `text` unchanged);
/// returns `Some` when the text was modified or blocked.
pub fn apply_output_guardrail(
    text: &str,
    mode: OutputGuardrailMode,
) -> Option<OutputGuardrailOutcome> {
    if mode == OutputGuardrailMode::Off {
        return None;
    }
    let categories = scan_secrets(text);
    if categories.is_empty() {
        return None;
    }
    match mode {
        OutputGuardrailMode::Off => None,
        OutputGuardrailMode::Redact => Some(OutputGuardrailOutcome {
            text: redact_secrets(text),
            categories,
            blocked: false,
        }),
        OutputGuardrailMode::Block => Some(OutputGuardrailOutcome {
            text: OUTPUT_BLOCKED_NOTICE.to_string(),
            categories,
            blocked: true,
        }),
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

    #[test]
    fn redact_secrets_keeps_pii() {
        // Outbound variant must NOT touch emails / phones.
        let out = redact_secrets("email alice@example.com, key sk-live-1234567890abcdefghij");
        assert!(out.contains("alice@example.com"));
        assert!(out.contains("sk-<redacted>"));
    }

    #[test]
    fn scan_secrets_reports_categories() {
        let cats = scan_secrets("ghp_abcdef1234567890ABCDEFghij and AKIAIOSFODNN7EXAMPLE");
        assert!(cats.contains(&"github_pat"));
        assert!(cats.contains(&"aws_key"));
    }

    #[test]
    fn private_key_block_redacted() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEabc\n-----END RSA PRIVATE KEY-----";
        assert!(scan_secrets(pem).contains(&"private_key"));
        assert!(redact_secrets(pem).contains("<redacted-private-key>"));
    }

    #[test]
    fn guardrail_off_is_noop() {
        assert!(
            apply_output_guardrail("sk-live-1234567890abcdefghij", OutputGuardrailMode::Off)
                .is_none()
        );
    }

    #[test]
    fn guardrail_passes_clean_text() {
        assert!(
            apply_output_guardrail("just a normal reply", OutputGuardrailMode::Redact).is_none()
        );
    }

    #[test]
    fn guardrail_redacts_secret() {
        let out = apply_output_guardrail(
            "here is ghp_abcdef1234567890ABCDEFghij",
            OutputGuardrailMode::Redact,
        )
        .expect("should fire");
        assert!(!out.blocked);
        assert!(out.text.contains("gh<redacted>"));
        assert!(out.categories.contains(&"github_pat"));
    }

    #[test]
    fn guardrail_blocks_secret() {
        let out = apply_output_guardrail(
            "here is ghp_abcdef1234567890ABCDEFghij",
            OutputGuardrailMode::Block,
        )
        .expect("should fire");
        assert!(out.blocked);
        assert_eq!(out.text, OUTPUT_BLOCKED_NOTICE);
    }
}
