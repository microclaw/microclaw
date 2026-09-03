//! `@`-prefix context references in user messages.
//!
//! Lets the user write `@file:src/main.rs`, `@folder:src/`, `@diff`, `@staged`,
//! or `@url:https://example.com` and have those expand server-side into an
//! attached context block before the LLM sees the message. Avoids round-trips
//! through `read_file` / `web_fetch` for trivial cases that the user clearly
//! intends.
//!
//! Hermes reference: `agent/context_references.py`. This is a focused port:
//! we cover file (with optional `:line` or `:start-end` suffix), folder
//! (1-deep listing), diff/staged, and url. We don't yet implement quoted
//! values (`@file:"path with spaces"`) or `@git:` refs.
//!
//! Sensitive-path guard: refuses to read out of `~/.ssh`, `~/.aws`, `~/.gnupg`,
//! `~/.kube`, `~/.docker`, dotfiles like `~/.bashrc`/`~/.netrc`/`~/.npmrc`.
//! The existing `path_guard` module catches these too, but enforcing here
//! avoids spending time fetching only to reject.
//!
//! URL fetching delegates to `microclaw_tools::web_fetch::fetch_url_with_timeout`,
//! which already enforces the SSRF guard from PR #335.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use regex::Regex;

const MAX_FILE_BYTES: usize = 64 * 1024;
const MAX_FOLDER_ENTRIES: usize = 200;
const MAX_DIFF_BYTES: usize = 32 * 1024;
const MAX_URL_BYTES: usize = 64 * 1024;
const URL_FETCH_TIMEOUT_SECS: u64 = 15;

fn reference_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Matches:  @diff, @staged, @file:VALUE, @folder:VALUE, @url:VALUE.
        // VALUE is whitespace-terminated, optionally followed by `:N` or `:N-M`.
        // The leading boundary uses `\s` rather than a look-behind because the
        // `regex` crate's default engine doesn't support look-around; we
        // post-filter for "start-of-line OR preceded by whitespace" separately.
        Regex::new(r"@(?:(?P<simple>diff|staged)\b|(?P<kind>file|folder|url):(?P<value>\S+))")
            .expect("static regex")
    })
}

const SENSITIVE_HOME_DIRS: &[&str] = &[".ssh", ".aws", ".gnupg", ".kube", ".docker", ".azure"];

const SENSITIVE_HOME_FILES: &[&str] = &[
    ".bashrc",
    ".zshrc",
    ".profile",
    ".bash_profile",
    ".zprofile",
    ".netrc",
    ".pgpass",
    ".npmrc",
    ".pypirc",
];

/// Result of reference expansion.
#[derive(Debug, Clone)]
pub struct ExpansionResult {
    /// The user-visible part of the message, with `@…` tokens stripped.
    pub stripped_message: String,
    /// Final message to pass to the LLM (stripped + attached blocks + warnings).
    pub final_message: String,
    /// Per-reference warnings to surface to the user.
    pub warnings: Vec<String>,
    /// Whether any reference was successfully expanded.
    pub expanded: bool,
}

/// Expand all `@`-prefix references in `message` against `cwd`. URL fetches
/// honor the same SSRF guard `web_fetch` uses.
///
/// If `message` contains no references, returns the original text unchanged.
pub async fn expand_references(message: &str, cwd: &Path) -> ExpansionResult {
    let refs: Vec<ReferenceMatch> = parse_references(message);
    if refs.is_empty() {
        return ExpansionResult {
            stripped_message: message.to_string(),
            final_message: message.to_string(),
            warnings: Vec::new(),
            expanded: false,
        };
    }

    let mut blocks: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    for r in &refs {
        match expand_one(r, cwd).await {
            Ok(block) => blocks.push(block),
            Err(w) => warnings.push(w),
        }
    }

    let stripped = strip_reference_tokens(message, &refs);
    let mut final_msg = stripped.clone();
    if !warnings.is_empty() {
        final_msg.push_str("\n\n--- Context Warnings ---\n");
        for w in &warnings {
            final_msg.push_str("- ");
            final_msg.push_str(w);
            final_msg.push('\n');
        }
    }
    if !blocks.is_empty() {
        final_msg.push_str("\n\n--- Attached Context ---\n\n");
        final_msg.push_str(&blocks.join("\n\n"));
    }

    ExpansionResult {
        stripped_message: stripped,
        final_message: final_msg.trim().to_string(),
        warnings,
        expanded: !blocks.is_empty(),
    }
}

#[derive(Debug, Clone)]
struct ReferenceMatch {
    #[allow(dead_code)]
    raw: String,
    kind: ReferenceKind,
    target: String,
    line_start: Option<usize>,
    line_end: Option<usize>,
    /// Byte offsets in the original message of the `@…` token, for stripping.
    token_start: usize,
    token_end: usize,
}

#[derive(Debug, Clone, Copy)]
enum ReferenceKind {
    File,
    Folder,
    Url,
    Diff,
    Staged,
}

fn parse_references(message: &str) -> Vec<ReferenceMatch> {
    let mut out = Vec::new();
    for cap in reference_re().captures_iter(message) {
        let m = cap.get(0).unwrap();
        // Reject mid-word matches: `foo@file:bar` should not parse. The match
        // must be at start-of-string or preceded by whitespace.
        if m.start() > 0 {
            let prev = message[..m.start()].chars().next_back();
            if let Some(c) = prev {
                if !c.is_whitespace() {
                    continue;
                }
            }
        }
        if let Some(simple) = cap.name("simple") {
            let kind = if simple.as_str() == "staged" {
                ReferenceKind::Staged
            } else {
                ReferenceKind::Diff
            };
            out.push(ReferenceMatch {
                raw: m.as_str().to_string(),
                kind,
                target: String::new(),
                line_start: None,
                line_end: None,
                token_start: m.start(),
                token_end: m.end(),
            });
            continue;
        }

        let kind = match cap.name("kind").map(|m| m.as_str()) {
            Some("file") => ReferenceKind::File,
            Some("folder") => ReferenceKind::Folder,
            Some("url") => ReferenceKind::Url,
            _ => continue,
        };
        let value_raw = cap.name("value").map(|m| m.as_str()).unwrap_or("");
        let value = strip_trailing_punctuation(value_raw);
        let (target, line_start, line_end) = match kind {
            ReferenceKind::File => parse_file_value(value),
            _ => (value.to_string(), None, None),
        };
        out.push(ReferenceMatch {
            raw: m.as_str().to_string(),
            kind,
            target,
            line_start,
            line_end,
            token_start: m.start(),
            token_end: m.end(),
        });
    }
    out
}

fn strip_trailing_punctuation(value: &str) -> &str {
    value.trim_end_matches([',', '.', ';', '!', '?'])
}

fn parse_file_value(value: &str) -> (String, Option<usize>, Option<usize>) {
    // Last `:` separates path from line spec, but only if the suffix is digits
    // (or digits-digits). Otherwise treat the whole thing as a path (handles
    // Windows drive letters).
    if let Some((rest, suffix)) = value.rsplit_once(':') {
        if let Some((a, b)) = suffix.split_once('-') {
            if let (Ok(a), Ok(b)) = (a.parse(), b.parse()) {
                return (rest.to_string(), Some(a), Some(b));
            }
        } else if let Ok(n) = suffix.parse() {
            return (rest.to_string(), Some(n), Some(n));
        }
    }
    (value.to_string(), None, None)
}

fn strip_reference_tokens(message: &str, refs: &[ReferenceMatch]) -> String {
    if refs.is_empty() {
        return message.to_string();
    }
    let mut out = String::with_capacity(message.len());
    let mut last = 0;
    for r in refs {
        if r.token_start >= last {
            out.push_str(&message[last..r.token_start]);
            last = r.token_end;
        }
    }
    out.push_str(&message[last..]);
    // Collapse runs of whitespace introduced by removal.
    let collapsed = out.trim().to_string();
    collapsed
}

async fn expand_one(r: &ReferenceMatch, cwd: &Path) -> Result<String, String> {
    match r.kind {
        ReferenceKind::File => expand_file(&r.target, r.line_start, r.line_end, cwd).await,
        ReferenceKind::Folder => expand_folder(&r.target, cwd).await,
        ReferenceKind::Url => expand_url(&r.target).await,
        ReferenceKind::Diff => expand_git_diff(false, cwd).await,
        ReferenceKind::Staged => expand_git_diff(true, cwd).await,
    }
}

fn resolve_path_safe(target: &str, cwd: &Path) -> Result<PathBuf, String> {
    let raw = PathBuf::from(target);
    let path = if raw.is_absolute() {
        raw
    } else {
        cwd.join(raw)
    };
    let canonical = path
        .canonicalize()
        .map_err(|e| format!("@{} not found: {e}", target))?;
    // Sensitive-path block list, evaluated against canonical. We walk the
    // resolved path's components and reject when any component name matches
    // a known sensitive directory — works on both Unix and Windows because
    // we never split on a separator string.
    let component_names: Vec<String> = canonical
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(s) => Some(s.to_string_lossy().to_string()),
            _ => None,
        })
        .collect();
    for d in SENSITIVE_HOME_DIRS {
        if component_names.iter().any(|name| name == d) {
            return Err(format!("@{} blocked: refuses to read inside `{d}`", target));
        }
    }
    if let Some(home) = dirs_home() {
        for d in SENSITIVE_HOME_DIRS {
            let blocked = home.join(d);
            if canonical.starts_with(&blocked) {
                return Err(format!(
                    "@{} blocked: refuses to read inside {}",
                    target,
                    blocked.display()
                ));
            }
        }
        for f in SENSITIVE_HOME_FILES {
            if canonical == home.join(f) {
                return Err(format!(
                    "@{} blocked: refuses to read sensitive dotfile {}",
                    target, f
                ));
            }
        }
    }
    Ok(canonical)
}

fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

async fn expand_file(
    target: &str,
    line_start: Option<usize>,
    line_end: Option<usize>,
    cwd: &Path,
) -> Result<String, String> {
    let path = resolve_path_safe(target, cwd)?;
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|e| format!("@file:{target} read failed: {e}"))?;
    if bytes.len() > MAX_FILE_BYTES * 8 {
        return Err(format!(
            "@file:{target} too large ({} bytes); read with read_file instead",
            bytes.len()
        ));
    }
    let text = String::from_utf8_lossy(&bytes).into_owned();
    let snippet = match (line_start, line_end) {
        (Some(s), Some(e)) if e >= s => {
            let lines: Vec<&str> = text.lines().collect();
            let s = s.saturating_sub(1).min(lines.len());
            let e = e.min(lines.len());
            lines[s..e].join("\n")
        }
        _ => text,
    };
    let snippet = if snippet.len() > MAX_FILE_BYTES {
        format!(
            "{}\n... [truncated to {} bytes]",
            &snippet[..MAX_FILE_BYTES],
            MAX_FILE_BYTES
        )
    } else {
        snippet
    };
    let mut header = format!("@file:{}", target);
    if let (Some(s), Some(e)) = (line_start, line_end) {
        header.push_str(&format!(" (lines {s}-{e})"));
    }
    Ok(format!("**{}**\n```\n{}\n```", header, snippet))
}

async fn expand_folder(target: &str, cwd: &Path) -> Result<String, String> {
    let path = resolve_path_safe(target, cwd)?;
    let mut rd = tokio::fs::read_dir(&path)
        .await
        .map_err(|e| format!("@folder:{target} read failed: {e}"))?;
    let mut entries: Vec<String> = Vec::new();
    let mut total = 0usize;
    while let Ok(Some(entry)) = rd.next_entry().await {
        if total >= MAX_FOLDER_ENTRIES {
            entries.push(format!("... (more, capped at {MAX_FOLDER_ENTRIES})"));
            break;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let kind = entry
            .file_type()
            .await
            .ok()
            .map(|t| if t.is_dir() { "/" } else { "" })
            .unwrap_or("");
        entries.push(format!("{name}{kind}"));
        total += 1;
    }
    entries.sort();
    Ok(format!(
        "**@folder:{}** ({} entries)\n```\n{}\n```",
        target,
        entries.len(),
        entries.join("\n")
    ))
}

async fn expand_url(target: &str) -> Result<String, String> {
    let body = microclaw_tools::web_fetch::fetch_url_with_timeout(target, URL_FETCH_TIMEOUT_SECS)
        .await
        .map_err(|e| format!("@url:{target} fetch failed: {e}"))?;
    let snippet = if body.len() > MAX_URL_BYTES {
        format!(
            "{}\n... [truncated to {} bytes]",
            &body[..MAX_URL_BYTES],
            MAX_URL_BYTES
        )
    } else {
        body
    };
    Ok(format!("**@url:{}**\n```\n{}\n```", target, snippet))
}

async fn expand_git_diff(staged: bool, cwd: &Path) -> Result<String, String> {
    let args: &[&str] = if staged {
        &["diff", "--cached"]
    } else {
        &["diff"]
    };
    let label = if staged { "@staged" } else { "@diff" };
    let output = tokio::process::Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .await
        .map_err(|e| format!("{label}: git not available ({e})"))?;
    if !output.status.success() {
        return Err(format!(
            "{label} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let body = String::from_utf8_lossy(&output.stdout).into_owned();
    if body.trim().is_empty() {
        return Ok(format!("**{label}** (no changes)"));
    }
    let snippet = if body.len() > MAX_DIFF_BYTES {
        format!(
            "{}\n... [truncated to {} bytes]",
            &body[..MAX_DIFF_BYTES],
            MAX_DIFF_BYTES
        )
    } else {
        body
    };
    Ok(format!("**{label}**\n```diff\n{}\n```", snippet))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("microclaw_ctxref_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn no_refs_passthrough() {
        let cwd = tmp_dir();
        let r = expand_references("plain text, no refs", &cwd).await;
        assert!(!r.expanded);
        assert_eq!(r.final_message, "plain text, no refs");
        let _ = std::fs::remove_dir_all(&cwd);
    }

    #[tokio::test]
    async fn expands_file_reference() {
        let cwd = tmp_dir();
        std::fs::write(cwd.join("hello.txt"), "world").unwrap();
        let r = expand_references("look at @file:hello.txt please", &cwd).await;
        assert!(r.expanded);
        assert!(r.final_message.contains("@file:hello.txt"));
        assert!(r.final_message.contains("world"));
        assert!(r.final_message.contains("look at"));
        assert!(r.final_message.contains("please"));
        // The @file:hello.txt token itself was stripped from the user-visible
        // sentence (it appears only inside the attached-context header).
        assert!(!r.stripped_message.contains("@file:hello.txt"));
        let _ = std::fs::remove_dir_all(&cwd);
    }

    #[tokio::test]
    async fn file_with_line_range() {
        let cwd = tmp_dir();
        std::fs::write(cwd.join("multi.txt"), "line1\nline2\nline3\nline4\n").unwrap();
        let r = expand_references("@file:multi.txt:2-3", &cwd).await;
        assert!(r.expanded);
        assert!(r.final_message.contains("line2\nline3"));
        assert!(!r.final_message.contains("line1"));
        assert!(!r.final_message.contains("line4"));
        let _ = std::fs::remove_dir_all(&cwd);
    }

    #[tokio::test]
    async fn folder_lists_entries() {
        let cwd = tmp_dir();
        std::fs::create_dir_all(cwd.join("sub/inner")).unwrap();
        std::fs::write(cwd.join("sub/a.txt"), "a").unwrap();
        std::fs::write(cwd.join("sub/b.txt"), "b").unwrap();
        let r = expand_references("@folder:sub", &cwd).await;
        assert!(r.expanded);
        assert!(r.final_message.contains("a.txt"));
        assert!(r.final_message.contains("b.txt"));
        assert!(r.final_message.contains("inner/"));
        let _ = std::fs::remove_dir_all(&cwd);
    }

    #[tokio::test]
    async fn missing_file_warns_does_not_panic() {
        let cwd = tmp_dir();
        let r = expand_references("@file:nope.txt", &cwd).await;
        assert!(!r.expanded);
        assert!(r.warnings.iter().any(|w| w.contains("nope.txt")));
        let _ = std::fs::remove_dir_all(&cwd);
    }

    #[test]
    fn sensitive_path_blocked() {
        // Component-based block list works on both Unix and Windows. We
        // run the expansion under env_lock and then drop the lock before
        // asserting, so a failed assertion can't poison the lock for other
        // tests.
        let home = std::env::temp_dir().join(format!("fake_home_{}", uuid::Uuid::new_v4()));
        let secrets = home.join(".ssh");
        std::fs::create_dir_all(&secrets).unwrap();
        std::fs::write(secrets.join("id_rsa"), "secret").unwrap();
        let target = format!("@file:{}/id_rsa", secrets.display());

        let r = {
            let _guard = crate::test_support::env_lock();
            let prev_home = std::env::var_os("HOME");
            std::env::set_var("HOME", &home);

            let r = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(expand_references(&target, &home));

            if let Some(prev) = prev_home {
                std::env::set_var("HOME", prev);
            } else {
                std::env::remove_var("HOME");
            }
            r
            // _guard dropped here, before any assert!
        };

        let _ = std::fs::remove_dir_all(&home);
        assert!(!r.expanded, "expected expansion to be blocked");
        assert!(
            r.warnings.iter().any(|w| w.contains("blocked")),
            "expected a 'blocked' warning, got: {:?}",
            r.warnings
        );
    }

    #[test]
    fn parse_extracts_token_offsets() {
        let msg = "before @file:foo.txt:10-20 after";
        let refs = parse_references(msg);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].target, "foo.txt");
        assert_eq!(refs[0].line_start, Some(10));
        assert_eq!(refs[0].line_end, Some(20));
        assert_eq!(refs[0].token_start, 7);
        assert_eq!(
            &msg[refs[0].token_start..refs[0].token_end],
            "@file:foo.txt:10-20"
        );
    }

    #[test]
    fn parse_handles_trailing_punctuation() {
        let refs = parse_references("see @file:hello.txt, please");
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].target, "hello.txt");
    }

    #[test]
    fn parse_recognizes_diff_and_staged() {
        let refs = parse_references("@diff and @staged");
        assert_eq!(refs.len(), 2);
        assert!(matches!(refs[0].kind, ReferenceKind::Diff));
        assert!(matches!(refs[1].kind, ReferenceKind::Staged));
    }

    #[test]
    fn ref_at_start_of_message_matches() {
        let refs = parse_references("@file:foo.txt explain");
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].target, "foo.txt");
    }
}
