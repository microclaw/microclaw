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
            remaining[..boundary].rfind('\n').unwrap_or(boundary)
        };
        chunks.push(remaining[..chunk_len].to_string());
        remaining = &remaining[chunk_len..];
        if remaining.starts_with('\n') {
            remaining = &remaining[1..];
        }
    }
    chunks
}

/// Remove private reasoning and textual protocol artifacts before content is
/// handed to a user-facing channel. Real tool calls are structured blocks; a
/// literal `[tool_use: ...]` line is therefore always an implementation leak.
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
    use super::{sanitize_user_visible_text, split_text};

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
}
