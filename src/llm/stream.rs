use super::*;

#[derive(Default)]
pub(crate) struct StreamToolUseBlock {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) input_json: String,
    pub(crate) thought_signature: Option<String>,
}

pub(crate) fn usage_from_json(v: &serde_json::Value) -> Option<Usage> {
    let input = v
        .get("input_tokens")
        .and_then(json_u64)
        .or_else(|| v.get("prompt_tokens").and_then(json_u64))?;
    let output = v
        .get("output_tokens")
        .and_then(json_u64)
        .or_else(|| v.get("completion_tokens").and_then(json_u64))
        .unwrap_or(0);
    Some(Usage {
        input_tokens: u32::try_from(input).unwrap_or(u32::MAX),
        output_tokens: u32::try_from(output).unwrap_or(u32::MAX),
    })
}

pub(crate) fn json_u64(v: &serde_json::Value) -> Option<u64> {
    match v {
        serde_json::Value::Number(n) => n.as_u64(),
        serde_json::Value::String(s) => s.parse::<u64>().ok(),
        _ => None,
    }
}

// OpenAI-compatible streaming usage is cumulative (running total), not per-chunk delta.
// We therefore keep the max seen values instead of summing to avoid double counting.
pub(crate) fn merge_usage_max(slot: &mut Option<Usage>, incoming: Usage) {
    match slot {
        Some(current) => {
            current.input_tokens = current.input_tokens.max(incoming.input_tokens);
            current.output_tokens = current.output_tokens.max(incoming.output_tokens);
        }
        None => {
            *slot = Some(incoming);
        }
    }
}

pub(crate) fn normalize_stop_reason(reason: Option<String>) -> Option<String> {
    match reason.as_deref() {
        Some("tool_use") | Some("tool_calls") => Some("tool_use".into()),
        Some("max_tokens") | Some("length") => Some("max_tokens".into()),
        Some("stop") | Some("end_turn") | None => Some("end_turn".into()),
        Some(other) => Some(other.to_string()),
    }
}

pub(crate) fn parse_tool_input(input_json: &str) -> serde_json::Value {
    let trimmed = input_json.trim();
    if trimmed.is_empty() {
        return json!({});
    }
    serde_json::from_str(trimmed).unwrap_or_else(|_| json!({}))
}

pub(crate) fn normalize_tool_input_for_request(input: &serde_json::Value) -> serde_json::Value {
    match input {
        serde_json::Value::Object(_) => input.clone(),
        serde_json::Value::String(text) => {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                return json!({});
            }
            match serde_json::from_str::<serde_json::Value>(trimmed) {
                Ok(serde_json::Value::Object(map)) => serde_json::Value::Object(map),
                _ => json!({}),
            }
        }
        _ => json!({}),
    }
}

pub(crate) fn minimax_tool_wrapper_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"</?(?:minimax:tool_call|invoke|parameter)>")
            .expect("MiniMax tool wrapper regex must compile")
    })
}

pub(crate) fn strip_minimax_tool_wrappers(text: &str) -> String {
    minimax_tool_wrapper_regex()
        .replace_all(text, " ")
        .into_owned()
}

pub(crate) fn parse_raw_tool_use_block(
    input: &str,
    call_number: usize,
) -> Option<(StreamToolUseBlock, &str)> {
    let rest = input.trim_start();
    let prefix = "[tool_use:";
    if !rest.starts_with(prefix) {
        return None;
    }

    let mut cursor = prefix.len();
    let after_prefix = &rest[cursor..];
    let name_and_args = after_prefix.trim_start();
    cursor += after_prefix.len().saturating_sub(name_and_args.len());

    let open_paren_rel = name_and_args.find('(')?;
    let name = name_and_args[..open_paren_rel].trim();
    if name.is_empty() {
        return None;
    }
    cursor += open_paren_rel + 1;

    let mut depth = 1usize;
    let mut in_string = false;
    let mut escaping = false;
    let mut close_paren_at: Option<usize> = None;

    for (offset, ch) in rest[cursor..].char_indices() {
        if in_string {
            if escaping {
                escaping = false;
                continue;
            }
            match ch {
                '\\' => escaping = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }

        match ch {
            '"' => in_string = true,
            '(' => depth += 1,
            ')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    close_paren_at = Some(cursor + offset);
                    break;
                }
            }
            _ => {}
        }
    }

    let close_paren_at = close_paren_at?;
    let args = rest[cursor..close_paren_at].trim();
    let mut tail = &rest[close_paren_at + 1..];
    tail = tail.trim_start();
    if !tail.starts_with(']') {
        return None;
    }

    Some((
        StreamToolUseBlock {
            id: format!("raw_tool_call_{call_number}"),
            name: name.to_string(),
            input_json: if args.is_empty() {
                "{}".to_string()
            } else {
                args.to_string()
            },
            thought_signature: None,
        },
        &tail[1..],
    ))
}

pub(crate) fn extract_raw_tool_use_blocks(text: &str) -> Option<Vec<StreamToolUseBlock>> {
    let normalized = strip_minimax_tool_wrappers(text);
    if !normalized.contains("[tool_use:") {
        return None;
    }

    let mut calls = Vec::new();
    let mut rest = normalized.as_str();
    loop {
        let trimmed = rest.trim();
        if trimmed.is_empty() {
            break;
        }
        let (call, tail) = parse_raw_tool_use_block(trimmed, calls.len() + 1)?;
        calls.push(call);
        rest = tail;
    }

    if calls.is_empty() {
        None
    } else {
        Some(calls)
    }
}

pub(crate) fn has_tool_use_block(content: &[ResponseContentBlock]) -> bool {
    content
        .iter()
        .any(|b| matches!(b, ResponseContentBlock::ToolUse { .. }))
}

pub(crate) fn combine_visible_and_reasoning_text(visible: &str, reasoning: &str) -> String {
    let visible = visible.trim();
    let reasoning = reasoning.trim();
    if reasoning.is_empty() {
        return visible.to_string();
    }
    if visible.is_empty() {
        return format!("<thought>\n{}\n</thought>", reasoning);
    }
    format!("<thought>\n{}\n</thought>\n\n{}", reasoning, visible)
}

pub(crate) fn combine_response_text_for_display(
    visible: &str,
    reasoning: &str,
    show_thinking: bool,
) -> String {
    if show_thinking {
        combine_visible_and_reasoning_text(visible, reasoning)
    } else {
        visible.trim().to_string()
    }
}

pub(crate) fn build_stream_response(
    ordered_indexes: Vec<usize>,
    text_blocks: std::collections::HashMap<usize, String>,
    tool_blocks: std::collections::HashMap<usize, StreamToolUseBlock>,
    stop_reason: Option<String>,
    usage: Option<Usage>,
) -> MessagesResponse {
    let mut content = Vec::new();
    for index in ordered_indexes {
        if let Some(text) = text_blocks.get(&index) {
            if !text.is_empty() {
                content.push(ResponseContentBlock::Text { text: text.clone() });
            }
        }
        if let Some(tool) = tool_blocks.get(&index) {
            content.push(ResponseContentBlock::ToolUse {
                id: sanitize_tool_id(&tool.id),
                name: tool.name.clone(),
                input: parse_tool_input(&tool.input_json),
                thought_signature: tool.thought_signature.clone(),
            });
        }
    }

    if content.is_empty() {
        content.push(ResponseContentBlock::Text {
            text: String::new(),
        });
    }

    let mut normalized_stop_reason = normalize_stop_reason(stop_reason);
    if !tool_blocks.is_empty() {
        normalized_stop_reason = Some("tool_use".to_string());
    } else if normalized_stop_reason.as_deref() == Some("tool_use") && !has_tool_use_block(&content)
    {
        warn!("Downgrading stop_reason=tool_use to end_turn because no tool_calls were parsed");
        normalized_stop_reason = Some("end_turn".into());
    }

    MessagesResponse {
        content,
        stop_reason: normalized_stop_reason,
        usage,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use crate::llm::test_prelude::*;

    #[test]
    fn test_normalize_stop_reason_stream_variants() {
        assert_eq!(
            normalize_stop_reason(Some("tool_calls".into())).as_deref(),
            Some("tool_use")
        );
        assert_eq!(
            normalize_stop_reason(Some("length".into())).as_deref(),
            Some("max_tokens")
        );
        assert_eq!(
            normalize_stop_reason(Some("stop".into())).as_deref(),
            Some("end_turn")
        );
    }

    #[test]
    fn test_build_stream_response_tool_calls_without_blocks_downgrades_to_end_turn() {
        let resp = build_stream_response(
            vec![],
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            Some("tool_calls".into()),
            None,
        );
        assert_eq!(resp.stop_reason.as_deref(), Some("end_turn"));
        assert!(!resp
            .content
            .iter()
            .any(|b| matches!(b, ResponseContentBlock::ToolUse { .. })));
    }

    #[test]
    fn test_extract_raw_tool_use_blocks_from_minimax_wrappers() {
        let text = "<minimax:tool_call>\n<invoke>\n<parameter>\n[tool_use: bash({\"command\":\"uptime\"})]\n</parameter>\n</invoke>\n</minimax:tool_call>";
        let calls = extract_raw_tool_use_blocks(text).expect("should parse raw tool calls");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "bash");
        assert_eq!(calls[0].input_json, "{\"command\":\"uptime\"}");
    }

    #[test]
    fn test_usage_from_json_supports_openai_prompt_completion_tokens() {
        let v = json!({
            "prompt_tokens": 12,
            "completion_tokens": 34
        });
        let usage = usage_from_json(&v).expect("usage should parse");
        assert_eq!(usage.input_tokens, 12);
        assert_eq!(usage.output_tokens, 34);
    }

    #[test]
    fn test_usage_from_json_supports_numeric_strings() {
        let v = json!({
            "input_tokens": "56",
            "output_tokens": "78"
        });
        let usage = usage_from_json(&v).expect("usage should parse");
        assert_eq!(usage.input_tokens, 56);
        assert_eq!(usage.output_tokens, 78);
    }

    #[test]
    fn test_build_stream_response_tool_json_parsing() {
        let mut tool_blocks = std::collections::HashMap::new();
        tool_blocks.insert(
            0,
            StreamToolUseBlock {
                id: "call_1".into(),
                name: "bash".into(),
                input_json: r#"{"command":"ls","cwd":"/tmp"}"#.into(),
                thought_signature: None,
            },
        );
        let resp = build_stream_response(
            vec![0],
            std::collections::HashMap::new(),
            tool_blocks,
            Some("tool_use".into()),
            None,
        );
        assert_eq!(resp.stop_reason.as_deref(), Some("tool_use"));
        match &resp.content[0] {
            ResponseContentBlock::ToolUse {
                id,
                name,
                input,
                thought_signature,
            } => {
                assert_eq!(id, "call_1");
                assert_eq!(name, "bash");
                assert_eq!(input["command"], "ls");
                assert_eq!(input["cwd"], "/tmp");
                assert!(thought_signature.is_none());
            }
            _ => panic!("Expected ToolUse"),
        }
    }

    // -----------------------------------------------------------------------
    // create_provider
    // -----------------------------------------------------------------------
}
