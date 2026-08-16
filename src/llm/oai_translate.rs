use super::*;

pub(crate) fn translate_messages_to_oai(
    system: &str,
    messages: &[Message],
) -> Vec<serde_json::Value> {
    translate_messages_to_oai_with_reasoning(system, messages, false)
}

pub(crate) fn translate_messages_to_oai_with_reasoning(
    system: &str,
    messages: &[Message],
    include_reasoning_for_tool_calls: bool,
) -> Vec<serde_json::Value> {
    let mut out: Vec<serde_json::Value> = Vec::new();
    let mut pending_tool_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
    // Track the index of the last assistant message that had tool_calls
    // so we can strip orphaned calls when no tool results follow.
    let mut last_tool_call_assistant_idx: Option<usize> = None;

    // If `pending_tool_ids` is non-empty, the last assistant's tool_calls
    // were never resolved by subsequent tool results. Strip the tool_calls
    // from that assistant message to avoid API errors.
    let strip_orphaned_tool_calls =
        |out: &mut Vec<serde_json::Value>,
         pending: &mut std::collections::HashSet<String>,
         last_idx: &mut Option<usize>| {
            if !pending.is_empty() {
                if let Some(idx) = last_idx.take() {
                    if let Some(obj) = out.get_mut(idx).and_then(|e| e.as_object_mut()) {
                        // Keep entries whose results were already emitted; dropping the
                        // whole array would orphan those tool messages instead.
                        let resolved: Vec<serde_json::Value> = obj
                            .get("tool_calls")
                            .and_then(|tc| tc.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter(|tc| {
                                        tc["id"].as_str().is_none_or(|id| !pending.contains(id))
                                    })
                                    .cloned()
                                    .collect()
                            })
                            .unwrap_or_default();
                        if resolved.is_empty() {
                            obj.remove("tool_calls");
                            // On the reasoning-bridge path the assistant's text lives in
                            // reasoning_content; fold it back into content. On the plain
                            // path content is already set — leave it untouched.
                            if let Some(text) = obj
                                .remove("reasoning_content")
                                .and_then(|v| v.as_str().map(|s| s.to_string()))
                            {
                                obj.insert("content".to_string(), json!(text));
                            } else if obj.get("content").is_none_or(|c| c.is_null()) {
                                obj.insert("content".to_string(), json!(""));
                            }
                        } else {
                            obj.insert("tool_calls".to_string(), json!(resolved));
                        }
                    }
                }
                pending.clear();
            }
        };

    // System message
    if !system.is_empty() {
        out.push(json!({"role": "system", "content": system}));
    }

    for msg in messages {
        match &msg.content {
            MessageContent::Text(text) => {
                strip_orphaned_tool_calls(
                    &mut out,
                    &mut pending_tool_ids,
                    &mut last_tool_call_assistant_idx,
                );
                out.push(json!({"role": msg.role, "content": text}));
            }
            MessageContent::Blocks(blocks) => {
                if msg.role == "assistant" {
                    let assistant_tool_ids: std::collections::HashSet<String> = blocks
                        .iter()
                        .filter_map(|b| match b {
                            ContentBlock::ToolUse { id, .. } => Some(id.clone()),
                            _ => None,
                        })
                        .collect();
                    // Collect text and tool_calls
                    let text: String = blocks
                        .iter()
                        .filter_map(|b| match b {
                            ContentBlock::Text { text } => Some(text.as_str()),
                            _ => None,
                        })
                        .collect::<Vec<_>>()
                        .join("");

                    let tool_calls: Vec<serde_json::Value> = blocks
                        .iter()
                        .filter_map(|b| match b {
                            ContentBlock::ToolUse {
                                id,
                                name,
                                input,
                                thought_signature,
                            } => {
                                let arguments = normalize_tool_input_for_request(input);
                                let mut tc = json!({
                                    "id": id,
                                    "type": "function",
                                    "function": {
                                        "name": name,
                                        "arguments": serde_json::to_string(&arguments).unwrap_or_default()
                                    }
                                });
                                if let Some(sig) = thought_signature {
                                    tc["extra_content"] = json!({
                                        "google": {
                                            "thought_signature": sig
                                        }
                                    });
                                }
                                Some(tc)
                            }
                            _ => None,
                        })
                        .collect();

                    // If the previous assistant's tool_calls were never resolved,
                    // strip them before emitting a new assistant.
                    strip_orphaned_tool_calls(
                        &mut out,
                        &mut pending_tool_ids,
                        &mut last_tool_call_assistant_idx,
                    );

                    let mut m = json!({"role": "assistant"});
                    if include_reasoning_for_tool_calls && !tool_calls.is_empty() {
                        m["reasoning_content"] = json!(text);
                        m["content"] = serde_json::Value::Null;
                    } else if !text.is_empty() || tool_calls.is_empty() {
                        m["content"] = json!(text);
                    }
                    if !tool_calls.is_empty() {
                        m["tool_calls"] = json!(tool_calls);
                    }
                    out.push(m);
                    let has_any = !assistant_tool_ids.is_empty();
                    pending_tool_ids = assistant_tool_ids;
                    last_tool_call_assistant_idx = if has_any { Some(out.len() - 1) } else { None };
                } else {
                    // User role — tool_results, images, or text
                    let has_tool_results = blocks
                        .iter()
                        .any(|b| matches!(b, ContentBlock::ToolResult { .. }));

                    if has_tool_results {
                        let mut emitted_any_tool = false;
                        // Each tool result → separate "tool" message
                        for block in blocks {
                            if let ContentBlock::ToolResult {
                                tool_use_id,
                                content,
                                is_error,
                            } = block
                            {
                                if !pending_tool_ids.contains(tool_use_id) {
                                    continue;
                                }
                                emitted_any_tool = true;
                                pending_tool_ids.remove(tool_use_id);
                                let c = if is_error == &Some(true) {
                                    format!("[Error] {content}")
                                } else {
                                    content.clone()
                                };
                                out.push(json!({
                                    "role": "tool",
                                    "tool_call_id": tool_use_id,
                                    "content": c,
                                }));
                            }
                        }
                        if !emitted_any_tool {
                            strip_orphaned_tool_calls(
                                &mut out,
                                &mut pending_tool_ids,
                                &mut last_tool_call_assistant_idx,
                            );
                        }
                        // Text blocks co-located with tool_results (e.g. iteration-budget
                        // warnings, mid-turn user message injections) have no place in the
                        // OpenAI "role=tool" scheme. Emit them as a follow-up user message
                        // so they still reach the model instead of being silently dropped.
                        let extra_text: String = blocks
                            .iter()
                            .filter_map(|b| match b {
                                ContentBlock::Text { text } => Some(text.as_str()),
                                _ => None,
                            })
                            .collect::<Vec<_>>()
                            .join("\n");
                        if !extra_text.trim().is_empty() {
                            out.push(json!({"role": "user", "content": extra_text}));
                        }
                    } else {
                        strip_orphaned_tool_calls(
                            &mut out,
                            &mut pending_tool_ids,
                            &mut last_tool_call_assistant_idx,
                        );
                        // Images + text → multipart content array
                        let has_images = blocks
                            .iter()
                            .any(|b| matches!(b, ContentBlock::Image { .. }));
                        if has_images {
                            let parts: Vec<serde_json::Value> = blocks
                                .iter()
                                .filter_map(|b| match b {
                                    ContentBlock::Text { text } => {
                                        Some(json!({"type": "text", "text": text}))
                                    }
                                    ContentBlock::Image {
                                        source:
                                            ImageSource {
                                                media_type, data, ..
                                            },
                                    } => {
                                        let url = format!("data:{media_type};base64,{data}");
                                        Some(json!({
                                            "type": "image_url",
                                            "image_url": {"url": url}
                                        }))
                                    }
                                    _ => None,
                                })
                                .collect();
                            out.push(json!({"role": "user", "content": parts}));
                        } else {
                            let text: String = blocks
                                .iter()
                                .filter_map(|b| match b {
                                    ContentBlock::Text { text } => Some(text.as_str()),
                                    _ => None,
                                })
                                .collect::<Vec<_>>()
                                .join("\n");
                            out.push(json!({"role": "user", "content": text}));
                        }
                    }
                }
            }
        }
    }

    // Final cleanup: strip unresolved tool_calls from trailing assistant
    strip_orphaned_tool_calls(
        &mut out,
        &mut pending_tool_ids,
        &mut last_tool_call_assistant_idx,
    );

    out
}

pub(crate) fn translate_tools_to_oai(tools: &[ToolDefinition]) -> Vec<serde_json::Value> {
    tools
        .iter()
        .map(|t| {
            json!({
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.input_schema,
                }
            })
        })
        .collect()
}

pub(crate) fn translate_tools_to_oai_responses(tools: &[ToolDefinition]) -> Vec<serde_json::Value> {
    tools
        .iter()
        .map(|t| {
            json!({
                "type": "function",
                "name": t.name,
                "description": t.description,
                "parameters": t.input_schema,
            })
        })
        .collect()
}

pub(crate) fn translate_messages_to_oai_responses_input(
    messages: &[Message],
) -> Vec<serde_json::Value> {
    let mut out: Vec<serde_json::Value> = Vec::new();
    let mut pending_tool_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
    for msg in messages {
        match &msg.content {
            MessageContent::Text(text) => {
                pending_tool_ids.clear();
                out.push(json!({
                    "type": "message",
                    "role": msg.role,
                    "content": text,
                }));
            }
            MessageContent::Blocks(blocks) => {
                if msg.role == "assistant" {
                    let assistant_tool_ids: std::collections::HashSet<String> = blocks
                        .iter()
                        .filter_map(|b| match b {
                            ContentBlock::ToolUse { id, .. } => Some(id.clone()),
                            _ => None,
                        })
                        .collect();
                    let text: String = blocks
                        .iter()
                        .filter_map(|b| match b {
                            ContentBlock::Text { text } => Some(text.as_str()),
                            _ => None,
                        })
                        .collect::<Vec<_>>()
                        .join("");
                    if !text.is_empty() {
                        out.push(json!({
                            "type": "message",
                            "role": "assistant",
                            "content": text,
                        }));
                    }

                    for block in blocks {
                        if let ContentBlock::ToolUse {
                            id, name, input, ..
                        } = block
                        {
                            let arguments = normalize_tool_input_for_request(input);
                            out.push(json!({
                                "type": "function_call",
                                "call_id": id,
                                "name": name,
                                "arguments": serde_json::to_string(&arguments).unwrap_or_default(),
                            }));
                        }
                    }
                    pending_tool_ids = assistant_tool_ids;
                } else {
                    let has_tool_results = blocks
                        .iter()
                        .any(|b| matches!(b, ContentBlock::ToolResult { .. }));
                    if has_tool_results {
                        let mut emitted_any_tool = false;
                        for block in blocks {
                            if let ContentBlock::ToolResult {
                                tool_use_id,
                                content,
                                is_error,
                            } = block
                            {
                                if !pending_tool_ids.contains(tool_use_id) {
                                    continue;
                                }
                                emitted_any_tool = true;
                                pending_tool_ids.remove(tool_use_id);
                                let c = if is_error == &Some(true) {
                                    format!("[Error] {content}")
                                } else {
                                    content.clone()
                                };
                                out.push(json!({
                                    "type": "function_call_output",
                                    "call_id": tool_use_id,
                                    "output": c,
                                }));
                            }
                        }
                        if !emitted_any_tool {
                            pending_tool_ids.clear();
                        }
                        // Preserve text blocks co-located with tool_results (budget
                        // warnings, mid-turn injections) by emitting them as a follow-up
                        // user message.
                        let extra_text: String = blocks
                            .iter()
                            .filter_map(|b| match b {
                                ContentBlock::Text { text } => Some(text.as_str()),
                                _ => None,
                            })
                            .collect::<Vec<_>>()
                            .join("\n");
                        if !extra_text.trim().is_empty() {
                            out.push(json!({
                                "type": "message",
                                "role": "user",
                                "content": extra_text,
                            }));
                        }
                    } else {
                        pending_tool_ids.clear();
                        let has_images = blocks
                            .iter()
                            .any(|b| matches!(b, ContentBlock::Image { .. }));
                        if has_images {
                            let parts: Vec<serde_json::Value> = blocks
                                .iter()
                                .filter_map(|b| match b {
                                    ContentBlock::Text { text } => {
                                        Some(json!({"type": "input_text", "text": text}))
                                    }
                                    ContentBlock::Image {
                                        source:
                                            ImageSource {
                                                media_type, data, ..
                                            },
                                    } => Some(json!({
                                        "type": "input_image",
                                        "source": {
                                            "type": "base64",
                                            "media_type": media_type,
                                            "data": data,
                                        }
                                    })),
                                    _ => None,
                                })
                                .collect();
                            out.push(json!({
                                "type": "message",
                                "role": "user",
                                "content": parts,
                            }));
                        } else {
                            let text: String = blocks
                                .iter()
                                .filter_map(|b| match b {
                                    ContentBlock::Text { text } => Some(text.as_str()),
                                    _ => None,
                                })
                                .collect::<Vec<_>>()
                                .join("\n");
                            out.push(json!({
                                "type": "message",
                                "role": "user",
                                "content": text,
                            }));
                        }
                    }
                }
            }
        }
    }

    out
}

pub(crate) fn translate_oai_responses_response(resp: OaiResponsesResponse) -> MessagesResponse {
    let mut content: Vec<ResponseContentBlock> = Vec::new();
    let mut saw_tool_use = false;
    let mut call_idx = 0usize;

    for item in resp.output {
        match item {
            OaiResponsesOutputItem::Message { content: parts } => {
                for part in parts {
                    if let OaiResponsesOutputContentPart::OutputText { text } = part {
                        if !text.is_empty() {
                            content.push(ResponseContentBlock::Text { text });
                        }
                    }
                }
            }
            OaiResponsesOutputItem::FunctionCall {
                id,
                call_id,
                name,
                arguments,
            } => {
                let parsed_args: serde_json::Value =
                    serde_json::from_str(&arguments).unwrap_or_default();
                let call_id = call_id.or(id).unwrap_or_else(|| {
                    call_idx += 1;
                    format!("call_{call_idx}")
                });
                content.push(ResponseContentBlock::ToolUse {
                    id: sanitize_tool_id(&call_id),
                    name,
                    input: parsed_args,
                    thought_signature: None,
                });
                saw_tool_use = true;
            }
            OaiResponsesOutputItem::Other => {}
        }
    }

    if content.is_empty() {
        content.push(ResponseContentBlock::Text {
            text: String::new(),
        });
    }

    MessagesResponse {
        content,
        stop_reason: Some(if saw_tool_use {
            "tool_use".into()
        } else {
            "end_turn".into()
        }),
        usage: resp.usage.map(|usage| Usage {
            input_tokens: usage.input_tokens,
            output_tokens: usage.output_tokens,
        }),
    }
}

/// Ensure a tool-call / tool-use ID only contains characters accepted by all
/// major providers (Anthropic requires `^[a-zA-Z0-9_-]+$`).  If the ID
/// contains any illegal characters, a fresh unique ID is generated to avoid
/// potential collisions from character replacement.
pub(crate) fn sanitize_tool_id(id: &str) -> String {
    if id.is_empty()
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return format!("call_{}", uuid::Uuid::new_v4().simple());
    }
    id.to_string()
}

#[cfg(test)]
pub(crate) fn translate_oai_response(oai: OaiResponse) -> MessagesResponse {
    translate_oai_response_with_display_reasoning(oai, true)
}

pub(crate) fn translate_oai_response_with_display_reasoning(
    oai: OaiResponse,
    show_thinking: bool,
) -> MessagesResponse {
    let choice = match oai.choices.into_iter().next() {
        Some(c) => c,
        None => {
            return MessagesResponse {
                content: vec![ResponseContentBlock::Text {
                    text: "(empty response)".into(),
                }],
                stop_reason: Some("end_turn".into()),
                usage: None,
            };
        }
    };

    let mut content = Vec::new();
    let OaiMessage {
        content: message_content,
        reasoning_content,
        tool_calls,
    } = choice.message;

    let mut visible = message_content.unwrap_or_default();
    let reasoning = reasoning_content.unwrap_or_default();
    let mut raw_text_tool_calls = None;
    if let Some(parsed_raw_calls) = extract_raw_tool_use_blocks(&visible) {
        let has_explicit_tool_calls = tool_calls
            .as_ref()
            .map(|calls| !calls.is_empty())
            .unwrap_or(false);
        if !has_explicit_tool_calls {
            raw_text_tool_calls = Some(parsed_raw_calls);
        }
        visible.clear();
    }
    let combined_text = combine_response_text_for_display(&visible, &reasoning, show_thinking);
    if !combined_text.is_empty() {
        content.push(ResponseContentBlock::Text {
            text: combined_text,
        });
    }

    if let Some(tool_calls) = tool_calls {
        for tc in tool_calls {
            let input: serde_json::Value =
                serde_json::from_str(&tc.function.arguments).unwrap_or_default();
            let thought_signature = tc
                .extra_content
                .and_then(|e| e.get("google").cloned())
                .and_then(|g| g.get("thought_signature").cloned())
                .and_then(|s| s.as_str().map(|s| s.to_string()))
                .or(tc.function.thought_signature);
            content.push(ResponseContentBlock::ToolUse {
                id: sanitize_tool_id(&tc.id),
                name: tc.function.name,
                input,
                thought_signature,
            });
        }
    } else if let Some(parsed_raw_calls) = raw_text_tool_calls {
        for tc in parsed_raw_calls {
            content.push(ResponseContentBlock::ToolUse {
                id: tc.id,
                name: tc.name,
                input: parse_tool_input(&tc.input_json),
                thought_signature: tc.thought_signature,
            });
        }
    }

    if content.is_empty() {
        content.push(ResponseContentBlock::Text {
            text: String::new(),
        });
    }

    let mut stop_reason = match choice.finish_reason.as_deref() {
        Some("tool_calls") => Some("tool_use".into()),
        Some("length") => Some("max_tokens".into()),
        _ => Some("end_turn".into()),
    };
    if has_tool_use_block(&content) {
        stop_reason = Some("tool_use".into());
    } else if stop_reason.as_deref() == Some("tool_use") && !has_tool_use_block(&content) {
        warn!("Downgrading stop_reason=tool_use to end_turn because response had no tool_calls");
        stop_reason = Some("end_turn".into());
    }

    let usage = oai.usage.map(|u| Usage {
        input_tokens: u.prompt_tokens,
        output_tokens: u.completion_tokens,
    });

    MessagesResponse {
        content,
        stop_reason,
        usage,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use crate::llm::test_prelude::*;

    #[test]
    fn test_retry_backoff_honors_retry_after_floor() {
        // A server-provided Retry-After is a floor the computed backoff cannot
        // undercut.
        let d = retry_backoff(1, Some(Duration::from_secs(45)));
        assert_eq!(d.as_secs(), 45);
    }

    // -----------------------------------------------------------------------
    // translate_messages_to_oai
    // -----------------------------------------------------------------------

    #[test]
    fn test_translate_messages_system_only() {
        let msgs: Vec<Message> = vec![];
        let out = translate_messages_to_oai("You are a bot.", &msgs);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["role"], "system");
        assert_eq!(out[0]["content"], "You are a bot.");
    }

    #[test]
    fn test_translate_messages_empty_system_omitted() {
        let msgs: Vec<Message> = vec![];
        let out = translate_messages_to_oai("", &msgs);
        assert!(out.is_empty());
    }

    #[test]
    fn test_translate_messages_text_roundtrip() {
        let msgs = vec![
            Message {
                role: "user".into(),
                content: MessageContent::Text("hello".into()),
            },
            Message {
                role: "assistant".into(),
                content: MessageContent::Text("hi".into()),
            },
        ];
        let out = translate_messages_to_oai("sys", &msgs);
        assert_eq!(out.len(), 3); // system + user + assistant
        assert_eq!(out[1]["role"], "user");
        assert_eq!(out[1]["content"], "hello");
        assert_eq!(out[2]["role"], "assistant");
        assert_eq!(out[2]["content"], "hi");
    }

    #[test]
    fn test_translate_messages_assistant_tool_use() {
        let msgs = vec![
            Message {
                role: "assistant".into(),
                content: MessageContent::Blocks(vec![
                    ContentBlock::Text {
                        text: "Let me check.".into(),
                    },
                    ContentBlock::ToolUse {
                        id: "t1".into(),
                        name: "bash".into(),
                        input: json!({"command": "ls"}),
                        thought_signature: None,
                    },
                ]),
            },
            Message {
                role: "user".into(),
                content: MessageContent::Blocks(vec![ContentBlock::ToolResult {
                    tool_use_id: "t1".into(),
                    content: "ok".into(),
                    is_error: None,
                }]),
            },
        ];
        let out = translate_messages_to_oai("", &msgs);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0]["role"], "assistant");
        assert_eq!(out[0]["content"], "Let me check.");
        let tc = out[0]["tool_calls"].as_array().unwrap();
        assert_eq!(tc.len(), 1);
        assert_eq!(tc[0]["id"], "t1");
        assert_eq!(tc[0]["function"]["name"], "bash");
    }

    #[test]
    fn test_translate_messages_assistant_tool_use_includes_thought_signature() {
        let msgs = vec![
            Message {
                role: "assistant".into(),
                content: MessageContent::Blocks(vec![ContentBlock::ToolUse {
                    id: "t1".into(),
                    name: "bash".into(),
                    input: json!({"command": "ls"}),
                    thought_signature: Some("sig_abc".into()),
                }]),
            },
            Message {
                role: "user".into(),
                content: MessageContent::Blocks(vec![ContentBlock::ToolResult {
                    tool_use_id: "t1".into(),
                    content: "ok".into(),
                    is_error: None,
                }]),
            },
        ];
        let out = translate_messages_to_oai("", &msgs);
        let tc = out[0]["tool_calls"].as_array().unwrap();
        assert_eq!(
            tc[0]["extra_content"]["google"]["thought_signature"],
            "sig_abc"
        );
    }

    #[test]
    fn test_translate_messages_assistant_tool_use_normalizes_stringified_json_input() {
        let msgs = vec![
            Message {
                role: "assistant".into(),
                content: MessageContent::Blocks(vec![ContentBlock::ToolUse {
                    id: "t1".into(),
                    name: "web_search".into(),
                    input: json!("{\"query\":\"油价\"}"),
                    thought_signature: None,
                }]),
            },
            Message {
                role: "user".into(),
                content: MessageContent::Blocks(vec![ContentBlock::ToolResult {
                    tool_use_id: "t1".into(),
                    content: "ok".into(),
                    is_error: None,
                }]),
            },
        ];

        let out = translate_messages_to_oai("", &msgs);
        let tc = out[0]["tool_calls"].as_array().unwrap();
        assert_eq!(tc[0]["function"]["arguments"], "{\"query\":\"油价\"}");
    }

    #[test]
    fn test_translate_messages_assistant_tool_use_deepseek_reasoning() {
        let msgs = vec![
            Message {
                role: "assistant".into(),
                content: MessageContent::Blocks(vec![
                    ContentBlock::Text {
                        text: "reasoning".into(),
                    },
                    ContentBlock::ToolUse {
                        id: "t1".into(),
                        name: "bash".into(),
                        input: json!({"command": "ls"}),
                        thought_signature: None,
                    },
                ]),
            },
            Message {
                role: "user".into(),
                content: MessageContent::Blocks(vec![ContentBlock::ToolResult {
                    tool_use_id: "t1".into(),
                    content: "ok".into(),
                    is_error: None,
                }]),
            },
        ];
        let out = translate_messages_to_oai_with_reasoning("", &msgs, true);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0]["role"], "assistant");
        assert_eq!(out[0]["reasoning_content"], "reasoning");
        assert!(out[0]["content"].is_null());
        let tc = out[0]["tool_calls"].as_array().unwrap();
        assert_eq!(tc.len(), 1);
        assert_eq!(tc[0]["id"], "t1");
    }

    #[test]
    fn test_translate_messages_orphaned_tool_calls_stripped_reasoning_bridge() {
        // Compaction can split a tool_use from its tool_result across the summary
        // boundary; the orphaned tool_calls must be stripped and the reasoning
        // text folded back into content, or DeepSeek rejects the request.
        let msgs = vec![
            Message {
                role: "assistant".into(),
                content: MessageContent::Blocks(vec![
                    ContentBlock::Text {
                        text: "thinking".into(),
                    },
                    ContentBlock::ToolUse {
                        id: "t1".into(),
                        name: "bash".into(),
                        input: json!({"command": "ls"}),
                        thought_signature: None,
                    },
                ]),
            },
            Message {
                role: "user".into(),
                content: MessageContent::Text("continue".into()),
            },
        ];
        let out = translate_messages_to_oai_with_reasoning("", &msgs, true);
        assert_eq!(out.len(), 2);
        assert!(out[0].get("tool_calls").is_none());
        assert!(out[0].get("reasoning_content").is_none());
        assert_eq!(out[0]["content"], "thinking");
        assert_eq!(out[1]["role"], "user");
    }

    #[test]
    fn test_translate_messages_orphaned_tool_calls_stripped_trailing() {
        let msgs = vec![Message {
            role: "assistant".into(),
            content: MessageContent::Blocks(vec![ContentBlock::ToolUse {
                id: "t1".into(),
                name: "bash".into(),
                input: json!({"command": "ls"}),
                thought_signature: None,
            }]),
        }];
        let out = translate_messages_to_oai_with_reasoning("", &msgs, true);
        assert_eq!(out.len(), 1);
        assert!(out[0].get("tool_calls").is_none());
        assert_eq!(out[0]["content"], "");
    }

    #[test]
    fn test_translate_messages_orphaned_tool_calls_plain_path_keeps_content() {
        let msgs = vec![
            Message {
                role: "assistant".into(),
                content: MessageContent::Blocks(vec![
                    ContentBlock::Text {
                        text: "Let me check.".into(),
                    },
                    ContentBlock::ToolUse {
                        id: "t1".into(),
                        name: "bash".into(),
                        input: json!({"command": "ls"}),
                        thought_signature: None,
                    },
                ]),
            },
            Message {
                role: "user".into(),
                content: MessageContent::Text("hi".into()),
            },
        ];
        let out = translate_messages_to_oai("", &msgs);
        assert_eq!(out.len(), 2);
        assert!(out[0].get("tool_calls").is_none());
        assert_eq!(out[0]["content"], "Let me check.");
    }

    #[test]
    fn test_translate_messages_partially_resolved_tool_calls_keep_resolved() {
        let msgs = vec![
            Message {
                role: "assistant".into(),
                content: MessageContent::Blocks(vec![
                    ContentBlock::ToolUse {
                        id: "t1".into(),
                        name: "bash".into(),
                        input: json!({}),
                        thought_signature: None,
                    },
                    ContentBlock::ToolUse {
                        id: "t2".into(),
                        name: "glob".into(),
                        input: json!({}),
                        thought_signature: None,
                    },
                ]),
            },
            Message {
                role: "user".into(),
                content: MessageContent::Blocks(vec![ContentBlock::ToolResult {
                    tool_use_id: "t1".into(),
                    content: "ok".into(),
                    is_error: None,
                }]),
            },
            Message {
                role: "user".into(),
                content: MessageContent::Text("continue".into()),
            },
        ];
        let out = translate_messages_to_oai_with_reasoning("", &msgs, true);
        // assistant + tool(t1) + user; only the unresolved t2 entry is stripped
        assert_eq!(out.len(), 3);
        let tc = out[0]["tool_calls"].as_array().unwrap();
        assert_eq!(tc.len(), 1);
        assert_eq!(tc[0]["id"], "t1");
        assert_eq!(out[1]["role"], "tool");
        assert_eq!(out[1]["tool_call_id"], "t1");
    }

    #[test]
    fn test_translate_messages_tool_result() {
        let msgs = vec![
            Message {
                role: "assistant".into(),
                content: MessageContent::Blocks(vec![ContentBlock::ToolUse {
                    id: "t1".into(),
                    name: "glob".into(),
                    input: json!({}),
                    thought_signature: None,
                }]),
            },
            Message {
                role: "user".into(),
                content: MessageContent::Blocks(vec![ContentBlock::ToolResult {
                    tool_use_id: "t1".into(),
                    content: "file1.rs\nfile2.rs".into(),
                    is_error: None,
                }]),
            },
        ];
        let out = translate_messages_to_oai("", &msgs);
        // assistant + tool = 2 messages
        assert_eq!(out.len(), 2);
        assert_eq!(out[1]["role"], "tool");
        assert_eq!(out[1]["tool_call_id"], "t1");
        assert_eq!(out[1]["content"], "file1.rs\nfile2.rs");
    }

    #[test]
    fn test_translate_messages_tool_result_error() {
        let msgs = vec![
            Message {
                role: "assistant".into(),
                content: MessageContent::Blocks(vec![ContentBlock::ToolUse {
                    id: "t1".into(),
                    name: "glob".into(),
                    input: json!({}),
                    thought_signature: None,
                }]),
            },
            Message {
                role: "user".into(),
                content: MessageContent::Blocks(vec![ContentBlock::ToolResult {
                    tool_use_id: "t1".into(),
                    content: "not found".into(),
                    is_error: Some(true),
                }]),
            },
        ];
        let out = translate_messages_to_oai("", &msgs);
        assert_eq!(out[1]["content"], "[Error] not found");
    }

    #[test]
    fn test_translate_messages_tool_result_with_sidecar_text_emits_user_message() {
        // When a user turn bundles tool_result blocks with free-form Text blocks
        // (e.g. iteration-budget warnings or mid-turn user message injections),
        // the Text content must not be dropped — emit it as a follow-up user message.
        let msgs = vec![
            Message {
                role: "assistant".into(),
                content: MessageContent::Blocks(vec![ContentBlock::ToolUse {
                    id: "t1".into(),
                    name: "glob".into(),
                    input: json!({}),
                    thought_signature: None,
                }]),
            },
            Message {
                role: "user".into(),
                content: MessageContent::Blocks(vec![
                    ContentBlock::ToolResult {
                        tool_use_id: "t1".into(),
                        content: "file.rs".into(),
                        is_error: None,
                    },
                    ContentBlock::Text {
                        text: "<system_notice>follow-up from user</system_notice>".into(),
                    },
                ]),
            },
        ];
        let out = translate_messages_to_oai("", &msgs);
        // assistant + tool + user (text sidecar) = 3 messages
        assert_eq!(out.len(), 3);
        assert_eq!(out[1]["role"], "tool");
        assert_eq!(out[1]["tool_call_id"], "t1");
        assert_eq!(out[2]["role"], "user");
        assert_eq!(
            out[2]["content"],
            "<system_notice>follow-up from user</system_notice>"
        );
    }

    #[test]
    fn test_translate_messages_orphaned_tool_result_skipped() {
        // tool_result without matching tool_use should be stripped
        let msgs = vec![Message {
            role: "user".into(),
            content: MessageContent::Blocks(vec![ContentBlock::ToolResult {
                tool_use_id: "orphan_id".into(),
                content: "stale result".into(),
                is_error: None,
            }]),
        }];
        let out = translate_messages_to_oai("", &msgs);
        assert!(out.is_empty());
    }

    #[test]
    fn test_translate_messages_tool_result_with_intervening_turn_is_skipped() {
        // Even if tool_use_id exists somewhere in history, it must be tied to the
        // most recent assistant tool_calls turn.
        let msgs = vec![
            Message {
                role: "assistant".into(),
                content: MessageContent::Blocks(vec![ContentBlock::ToolUse {
                    id: "t1".into(),
                    name: "glob".into(),
                    input: json!({}),
                    thought_signature: None,
                }]),
            },
            Message {
                role: "assistant".into(),
                content: MessageContent::Text("intervening assistant message".into()),
            },
            Message {
                role: "user".into(),
                content: MessageContent::Blocks(vec![ContentBlock::ToolResult {
                    tool_use_id: "t1".into(),
                    content: "stale result".into(),
                    is_error: None,
                }]),
            },
        ];
        let out = translate_messages_to_oai("", &msgs);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0]["role"], "assistant");
        assert_eq!(out[1]["role"], "assistant");
        assert_eq!(out[1]["content"], "intervening assistant message");
    }

    #[test]
    fn test_translate_messages_image_block() {
        let msgs = vec![Message {
            role: "user".into(),
            content: MessageContent::Blocks(vec![
                ContentBlock::Image {
                    source: ImageSource {
                        source_type: "base64".into(),
                        media_type: "image/png".into(),
                        data: "AAAA".into(),
                    },
                },
                ContentBlock::Text {
                    text: "describe".into(),
                },
            ]),
        }];
        let out = translate_messages_to_oai("", &msgs);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["role"], "user");
        let content = out[0]["content"].as_array().unwrap();
        assert_eq!(content.len(), 2);
        assert_eq!(content[0]["type"], "image_url");
        assert!(content[0]["image_url"]["url"]
            .as_str()
            .unwrap()
            .starts_with("data:image/png;base64,"));
        assert_eq!(content[1]["type"], "text");
        assert_eq!(content[1]["text"], "describe");
    }

    #[test]
    fn test_translate_messages_to_oai_responses_skips_stale_function_call_output() {
        let msgs = vec![
            Message {
                role: "assistant".into(),
                content: MessageContent::Blocks(vec![ContentBlock::ToolUse {
                    id: "t1".into(),
                    name: "glob".into(),
                    input: json!({}),
                    thought_signature: None,
                }]),
            },
            Message {
                role: "assistant".into(),
                content: MessageContent::Text("intervening assistant message".into()),
            },
            Message {
                role: "user".into(),
                content: MessageContent::Blocks(vec![ContentBlock::ToolResult {
                    tool_use_id: "t1".into(),
                    content: "stale result".into(),
                    is_error: None,
                }]),
            },
        ];

        let out = translate_messages_to_oai_responses_input(&msgs);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0]["type"], "function_call");
        assert_eq!(out[1]["type"], "message");
        assert_eq!(out[1]["role"], "assistant");
    }

    #[test]
    fn test_translate_messages_to_oai_responses_preserves_sidecar_text_with_tool_result() {
        let msgs = vec![
            Message {
                role: "assistant".into(),
                content: MessageContent::Blocks(vec![ContentBlock::ToolUse {
                    id: "t1".into(),
                    name: "glob".into(),
                    input: json!({}),
                    thought_signature: None,
                }]),
            },
            Message {
                role: "user".into(),
                content: MessageContent::Blocks(vec![
                    ContentBlock::ToolResult {
                        tool_use_id: "t1".into(),
                        content: "file.rs".into(),
                        is_error: None,
                    },
                    ContentBlock::Text {
                        text: "<system_notice>follow-up</system_notice>".into(),
                    },
                ]),
            },
        ];
        let out = translate_messages_to_oai_responses_input(&msgs);
        // function_call + function_call_output + user message = 3 items
        assert_eq!(out.len(), 3);
        assert_eq!(out[1]["type"], "function_call_output");
        assert_eq!(out[2]["type"], "message");
        assert_eq!(out[2]["role"], "user");
        assert_eq!(
            out[2]["content"],
            "<system_notice>follow-up</system_notice>"
        );
    }

    #[test]
    fn test_translate_messages_to_oai_responses_normalizes_malformed_tool_input() {
        let msgs = vec![Message {
            role: "assistant".into(),
            content: MessageContent::Blocks(vec![ContentBlock::ToolUse {
                id: "t1".into(),
                name: "web_search".into(),
                input: json!("{"),
                thought_signature: None,
            }]),
        }];

        let out = translate_messages_to_oai_responses_input(&msgs);
        assert_eq!(out[0]["type"], "function_call");
        assert_eq!(out[0]["arguments"], "{}");
    }

    // -----------------------------------------------------------------------
    // translate_tools_to_oai
    // -----------------------------------------------------------------------

    #[test]
    fn test_translate_tools_to_oai() {
        let tools = vec![ToolDefinition {
            name: "bash".into(),
            description: "Run bash".into(),
            input_schema: json!({"type": "object", "properties": {"cmd": {"type": "string"}}}),
        }];
        let out = translate_tools_to_oai(&tools);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["type"], "function");
        assert_eq!(out[0]["function"]["name"], "bash");
        assert_eq!(out[0]["function"]["description"], "Run bash");
    }

    #[test]
    fn test_translate_tools_to_oai_responses() {
        let tools = vec![ToolDefinition {
            name: "bash".into(),
            description: "Run bash".into(),
            input_schema: json!({"type": "object", "properties": {"cmd": {"type": "string"}}}),
        }];
        let out = translate_tools_to_oai_responses(&tools);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["type"], "function");
        assert_eq!(out[0]["name"], "bash");
        assert_eq!(out[0]["description"], "Run bash");
        assert_eq!(out[0]["parameters"]["type"], "object");
    }

    // -----------------------------------------------------------------------
    // translate_oai_response
    // -----------------------------------------------------------------------

    #[test]
    fn test_translate_oai_response_turns_raw_tool_text_into_tool_use() {
        let raw = r#"{"choices":[{"message":{"content":"<minimax:tool_call>\n[tool_use: bash({\"command\":\"free -h\"})]\n</minimax:tool_call>","tool_calls":null},"finish_reason":"stop"}],"usage":null}"#;
        let resp = translate_oai_response(serde_json::from_str(raw).unwrap());
        assert_eq!(resp.stop_reason.as_deref(), Some("tool_use"));
        assert_eq!(resp.content.len(), 1);
        match &resp.content[0] {
            ResponseContentBlock::ToolUse { name, input, .. } => {
                assert_eq!(name, "bash");
                assert_eq!(input["command"], "free -h");
            }
            other => panic!("expected tool use, got {other:?}"),
        }
    }

    #[test]
    fn test_translate_messages_user_text_blocks_no_images_no_tool_results() {
        // User message with only text blocks (no images, no tool results) → plain text
        let msgs = vec![Message {
            role: "user".into(),
            content: MessageContent::Blocks(vec![
                ContentBlock::Text {
                    text: "first".into(),
                },
                ContentBlock::Text {
                    text: "second".into(),
                },
            ]),
        }];
        let out = translate_messages_to_oai("", &msgs);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["role"], "user");
        assert_eq!(out[0]["content"], "first\nsecond");
    }

    // -----------------------------------------------------------------------
    // sanitize_messages
    // -----------------------------------------------------------------------
}
