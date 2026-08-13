//! Unified-diff rendering for file-modifying tools.
//!
//! Produces a compact, user-facing unified diff (with `+N -M` stats and a
//! line cap) so channel adapters and the web UI can show exactly what an
//! `edit_file` / `write_file` call changed, instead of a bare success line.

use similar::{ChangeTag, TextDiff};

/// Default cap on rendered diff lines (matching the 120-line convention
/// popularized by Grok Build's diff view).
pub const DEFAULT_DIFF_MAX_LINES: usize = 120;

/// A rendered unified diff plus its summary stats.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnifiedDiff {
    /// Unified-diff body (hunk headers + context/insert/delete lines), capped
    /// at the requested line count. No `--- a/…` / `+++ b/…` file header —
    /// callers render the path themselves.
    pub text: String,
    /// Total inserted lines (uncapped — counted before truncation).
    pub added: usize,
    /// Total removed lines (uncapped — counted before truncation).
    pub removed: usize,
    /// `true` when the rendered body was cut at `max_lines`.
    pub truncated: bool,
}

impl UnifiedDiff {
    /// `+N -M` summary, e.g. `+3 -1`.
    pub fn stats(&self) -> String {
        format!("+{} -{}", self.added, self.removed)
    }
}

/// Compute a unified diff between `old` and `new`, capped at `max_lines`
/// rendered lines. Returns `None` when the contents are identical.
pub fn unified_diff(old: &str, new: &str, max_lines: usize) -> Option<UnifiedDiff> {
    if old == new {
        return None;
    }
    let diff = TextDiff::from_lines(old, new);
    let mut added = 0usize;
    let mut removed = 0usize;
    for change in diff.iter_all_changes() {
        match change.tag() {
            ChangeTag::Insert => added += 1,
            ChangeTag::Delete => removed += 1,
            ChangeTag::Equal => {}
        }
    }

    let max_lines = max_lines.max(4);
    let mut lines: Vec<String> = Vec::new();
    let mut truncated = false;
    'outer: for hunk in diff.unified_diff().context_radius(3).iter_hunks() {
        if lines.len() + 1 > max_lines {
            truncated = true;
            break;
        }
        lines.push(hunk.header().to_string());
        for change in hunk.iter_changes() {
            if lines.len() + 1 > max_lines {
                truncated = true;
                break 'outer;
            }
            let sign = match change.tag() {
                ChangeTag::Insert => "+",
                ChangeTag::Delete => "-",
                ChangeTag::Equal => " ",
            };
            let value = change.value();
            lines.push(format!(
                "{sign}{}",
                value.strip_suffix('\n').unwrap_or(value)
            ));
        }
    }
    if truncated {
        lines.push(format!("… (diff truncated at {max_lines} lines)"));
    }
    Some(UnifiedDiff {
        text: lines.join("\n"),
        added,
        removed,
        truncated,
    })
}

/// Key under which file-modifying tools attach their diff payload to
/// `ToolResult::metadata`. Shared so the producer (tools) and consumers
/// (tool executor → `AgentEvent::FileDiff`) cannot silently desync.
pub const FILE_DIFF_METADATA_KEY: &str = "file_diff";

/// Build the metadata payload for a file edit diff.
pub fn file_diff_metadata(path: &str, diff: &UnifiedDiff) -> serde_json::Value {
    serde_json::json!({
        FILE_DIFF_METADATA_KEY: {
            "path": path,
            "diff": diff.text,
            "added": diff.added,
            "removed": diff.removed,
            "truncated": diff.truncated,
        }
    })
}

/// Format a chat-facing message for a file diff: a one-line header with the
/// path and `+N -M` stats, followed by a fenced ```diff block.
pub fn format_diff_chat_message(
    path: &str,
    diff_text: &str,
    added: usize,
    removed: usize,
) -> String {
    format!("📝 `{path}` (+{added} -{removed})\n```diff\n{diff_text}\n```")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_content_yields_none() {
        assert!(unified_diff("a\nb\n", "a\nb\n", 120).is_none());
    }

    #[test]
    fn counts_added_and_removed_lines() {
        let old = "one\ntwo\nthree\n";
        let new = "one\n2\nthree\nfour\n";
        let d = unified_diff(old, new, 120).expect("diff");
        assert_eq!(d.added, 2); // "2" and "four"
        assert_eq!(d.removed, 1); // "two"
        assert_eq!(d.stats(), "+2 -1");
        assert!(!d.truncated);
        assert!(d.text.contains("-two"));
        assert!(d.text.contains("+2"));
        assert!(d.text.contains("+four"));
        assert!(d.text.contains("@@"));
    }

    #[test]
    fn truncates_at_max_lines() {
        let old = (0..200).map(|i| format!("line{i}\n")).collect::<String>();
        let new = (0..200).map(|i| format!("LINE{i}\n")).collect::<String>();
        let d = unified_diff(&old, &new, 20).expect("diff");
        assert!(d.truncated);
        // 20 rendered lines + 1 truncation notice.
        assert_eq!(d.text.lines().count(), 21);
        assert!(d.text.ends_with("… (diff truncated at 20 lines)"));
        // Stats stay uncapped.
        assert_eq!(d.added, 200);
        assert_eq!(d.removed, 200);
    }

    #[test]
    fn new_file_diff_from_empty() {
        let d = unified_diff("", "hello\nworld\n", 120).expect("diff");
        assert_eq!(d.added, 2);
        assert_eq!(d.removed, 0);
    }

    #[test]
    fn chat_message_format() {
        let msg = format_diff_chat_message("src/x.rs", "@@ -1 +1 @@\n-a\n+b", 1, 1);
        assert!(msg.starts_with("📝 `src/x.rs` (+1 -1)\n```diff\n"));
        assert!(msg.ends_with("\n```"));
    }

    #[test]
    fn metadata_shape() {
        let d = unified_diff("a\n", "b\n", 120).unwrap();
        let meta = file_diff_metadata("f.txt", &d);
        let fd = &meta[FILE_DIFF_METADATA_KEY];
        assert_eq!(fd["path"], "f.txt");
        assert_eq!(fd["added"], 1);
        assert_eq!(fd["removed"], 1);
        assert_eq!(fd["truncated"], false);
    }
}
