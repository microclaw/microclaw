pub fn floor_char_boundary(s: &str, mut index: usize) -> usize {
    let len = s.len();
    if index >= len {
        return len;
    }

    while index > 0 && !s.is_char_boundary(index) {
        index -= 1;
    }

    index
}

pub fn split_text(text: &str, max_len: usize) -> Vec<String> {
    if text.len() <= max_len {
        return vec![text.to_string()];
    }

    let mut chunks = Vec::new();
    let mut remaining = text;
    while !remaining.is_empty() {
        let chunk_len = if remaining.len() <= max_len {
            remaining.len()
        } else {
            let boundary = floor_char_boundary(remaining, max_len.min(remaining.len()));
            remaining[..boundary]
                .rfind('\n')
                .map(|index| index + '\n'.len_utf8())
                .unwrap_or(boundary)
        };
        chunks.push(remaining[..chunk_len].to_string());
        remaining = &remaining[chunk_len..];
    }
    chunks
}

/// Remove private reasoning and textual protocol artifacts before content is
/// handed to a user-facing channel. Real tool calls are structured blocks; a
/// literal `[tool_use: ...]` line is therefore always an implementation leak.
/// Cap on the excerpt embedded by [`quoted_context_prefix`].
pub const QUOTED_CONTEXT_MAX_CHARS: usize = 400;

/// Build the `[quoted from …]` prefix that channel adapters prepend when a
/// user replies to an earlier message, so terse follow-ups ("why?", "fix
/// it") keep their referent even after the original scrolled out of the
/// session window. Returns `None` when the referenced content is empty.
pub fn quoted_context_prefix(author: Option<&str>, excerpt: &str) -> Option<String> {
    let trimmed = excerpt.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut capped: String = trimmed.chars().take(QUOTED_CONTEXT_MAX_CHARS).collect();
    if capped.chars().count() < trimmed.chars().count() {
        capped.push('…');
    }
    let author = author.map(str::trim).filter(|a| !a.is_empty());
    Some(match author {
        Some(a) => format!("[quoted from {a}: {capped}]\n"),
        None => format!("[quoted: {capped}]\n"),
    })
}

pub fn sanitize_user_visible_text(text: &str) -> String {
    fn strip_tag_blocks(input: &str, open: &str, close: &str) -> String {
        let mut result = String::with_capacity(input.len());
        let mut rest = input;
        while let Some(start) = rest.find(open) {
            result.push_str(&rest[..start]);
            if let Some(end) = rest[start..].find(close) {
                rest = &rest[start + end + close.len()..];
            } else {
                rest = "";
                break;
            }
        }
        result.push_str(rest);
        result
    }

    let mut visible = text.to_string();
    for (open, close) in [
        ("<think>", "</think>"),
        ("<thought>", "</thought>"),
        ("<thinking>", "</thinking>"),
        ("<reasoning>", "</reasoning>"),
    ] {
        visible = strip_tag_blocks(&visible, open, close);
    }

    visible
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            !(trimmed.starts_with("[tool_use:") && trimmed.ends_with(']'))
        })
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::{
        quoted_context_prefix, sanitize_user_visible_text, split_text, QUOTED_CONTEXT_MAX_CHARS,
    };

    #[test]
    fn quoted_context_includes_author_and_caps_length() {
        let p = quoted_context_prefix(Some("alice"), "hello world").unwrap();
        assert_eq!(p, "[quoted from alice: hello world]\n");
        let p = quoted_context_prefix(None, "hi").unwrap();
        assert_eq!(p, "[quoted: hi]\n");
        assert!(quoted_context_prefix(Some("bob"), "   ").is_none());
        let long = "x".repeat(QUOTED_CONTEXT_MAX_CHARS + 50);
        let p = quoted_context_prefix(None, &long).unwrap();
        assert!(p.contains('…'));
        assert!(p.chars().count() < long.chars().count());
    }

    #[test]
    fn sanitizes_private_reasoning_and_fake_tool_calls() {
        let text = "<think>secret</think>\nVisible\n[tool_use: bash({\"command\":\"pwd\"})]";
        assert_eq!(sanitize_user_visible_text(text), "Visible");
    }

    #[test]
    fn split_text_respects_utf8_boundaries() {
        let chunks = split_text("你好世界", 7);
        assert_eq!(chunks, vec!["你好", "世界"]);
    }

    #[test]
    fn split_text_preserves_every_byte_at_newline_boundaries() {
        let text = "first paragraph\nsecond paragraph\nthird paragraph";
        let chunks = split_text(text, 18);
        assert!(chunks.iter().all(|chunk| chunk.len() <= 18));
        assert_eq!(chunks.concat(), text);
    }
}
