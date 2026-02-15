use async_trait::async_trait;
use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::json;
use tokio::sync::mpsc::UnboundedSender;
use tracing::warn;

use std::collections::HashSet;

use crate::codex_auth::{
    codex_config_default_openai_base_url, is_openai_codex_provider,
    refresh_openai_codex_auth_if_needed, resolve_openai_codex_auth,
};
use crate::config::Config;
#[cfg(test)]
use crate::config::WorkingDirIsolation;
use crate::error::MicroClawError;
use crate::llm_types::{
    ContentBlock, ImageSource, Message, MessageContent, MessagesRequest, MessagesResponse,
    ResponseContentBlock, ToolDefinition, Usage,
};

/// Remove orphaned `ToolResult` blocks whose `tool_use_id` does not match any
/// `ToolUse` block in the conversation.  This can happen after session
/// compaction splits a tool_use / tool_result pair.
fn sanitize_messages(messages: Vec<Message>) -> Vec<Message> {
    // Collect all tool_use IDs from assistant messages (owned to avoid borrow conflicts).
    let known_ids: HashSet<String> = messages
        .iter()
        .filter(|m| m.role == "assistant")
        .flat_map(|m| match &m.content {
            MessageContent::Blocks(blocks) => blocks
                .iter()
                .filter_map(|b| match b {
                    ContentBlock::ToolUse { id, .. } => Some(id.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>(),
            _ => vec![],
        })
        .collect();

    messages
        .into_iter()
        .filter_map(|msg| {
            if msg.role != "user" {
                return Some(msg);
            }
            match msg.content {
                MessageContent::Blocks(blocks) => {
                    let filtered: Vec<ContentBlock> = blocks
                        .into_iter()
                        .filter(|b| match b {
                            ContentBlock::ToolResult { tool_use_id, .. } => {
                                known_ids.contains(tool_use_id)
                            }
                            _ => true,
                        })
                        .collect();
                    if filtered.is_empty() {
                        None // Drop entirely empty user messages
                    } else {
                        Some(Message {
                            role: msg.role,
                            content: MessageContent::Blocks(filtered),
                        })
                    }
                }
                other => Some(Message {
                    role: msg.role,
                    content: other,
                }),
            }
        })
        .collect()
}

#[derive(Default)]
struct SseEventParser {
    pending: String,
    data_lines: Vec<String>,
}

impl SseEventParser {
    fn push_chunk(&mut self, chunk: &str) -> Vec<String> {
        self.pending.push_str(chunk);
        let mut events = Vec::new();

        while let Some(pos) = self.pending.find('\n') {
            let mut line = self.pending[..pos].to_string();
            self.pending = self.pending[pos + 1..].to_string();
            if line.ends_with('\r') {
                line.pop();
            }
            if let Some(event_data) = self.handle_line(&line) {
                events.push(event_data);
            }
        }

        events
    }

    fn finish(&mut self) -> Vec<String> {
        let mut events = Vec::new();
        if !self.pending.is_empty() {
            let mut line = std::mem::take(&mut self.pending);
            if line.ends_with('\r') {
                line.pop();
            }
            if let Some(event_data) = self.handle_line(&line) {
                events.push(event_data);
            }
        }
        if let Some(event_data) = self.flush_event() {
            events.push(event_data);
        }
        events
    }

    fn handle_line(&mut self, line: &str) -> Option<String> {
        if line.is_empty() {
            return self.flush_event();
        }
        if line.starts_with(':') {
            return None;
        }

        let (field, value) = match line.split_once(':') {
            Some((f, v)) => {
                let v = v.strip_prefix(' ').unwrap_or(v);
                (f, v)
            }
            None => (line, ""),
        };

        if field == "data" {
            self.data_lines.push(value.to_string());
        }
        None
    }

    fn flush_event(&mut self) -> Option<String> {
        if self.data_lines.is_empty() {
            return None;
        }
        let data = self.data_lines.join("\n");
        self.data_lines.clear();
        Some(data)
    }
}

// ---------------------------------------------------------------------------
// Provider trait
// ---------------------------------------------------------------------------

#[async_trait]
pub trait LlmProvider: Send + Sync {
    async fn send_message(
        &self,
        system: &str,
        messages: Vec<Message>,
        tools: Option<Vec<ToolDefinition>>,
    ) -> Result<MessagesResponse, MicroClawError>;

    async fn send_message_stream(
        &self,
        system: &str,
        messages: Vec<Message>,
        tools: Option<Vec<ToolDefinition>>,
        text_tx: Option<&UnboundedSender<String>>,
    ) -> Result<MessagesResponse, MicroClawError> {
        let response = self.send_message(system, messages, tools).await?;
        if let Some(tx) = text_tx {
            for block in &response.content {
                if let ResponseContentBlock::Text { text } = block {
                    let _ = tx.send(text.clone());
                }
            }
        }
        Ok(response)
    }
}

pub fn create_provider(config: &Config) -> Box<dyn LlmProvider> {
    match config.llm_provider.trim().to_lowercase().as_str() {
        "anthropic" => Box::new(AnthropicProvider::new(config)),
        _ => Box::new(OpenAiProvider::new(config)),
    }
}

// ---------------------------------------------------------------------------
// Anthropic provider
// ---------------------------------------------------------------------------

pub struct AnthropicProvider {
    http: reqwest::Client,
    api_key: String,
    model: String,
    max_tokens: u32,
    base_url: String,
}

impl AnthropicProvider {
    pub fn new(config: &Config) -> Self {
        AnthropicProvider {
            http: reqwest::Client::new(),
            api_key: config.api_key.clone(),
            model: config.model.clone(),
            max_tokens: config.max_tokens,
            base_url: resolve_anthropic_messages_url(config.llm_base_url.as_deref().unwrap_or("")),
        }
    }

    async fn send_message_stream_single_pass(
        &self,
        request: &MessagesRequest,
        text_tx: Option<&UnboundedSender<String>>,
    ) -> Result<MessagesResponse, MicroClawError> {
        let mut streamed_request = request.clone();
        streamed_request.stream = Some(true);

        let response = self
            .http
            .post(&self.base_url)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&streamed_request)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            if let Ok(api_err) = serde_json::from_str::<AnthropicApiError>(&body) {
                return Err(MicroClawError::LlmApi(format!(
                    "{}: {}",
                    api_err.error.error_type, api_err.error.message
                )));
            }
            return Err(MicroClawError::LlmApi(format!("HTTP {status}: {body}")));
        }

        let mut byte_stream = response.bytes_stream();
        let mut sse = SseEventParser::default();
        let mut stop_reason: Option<String> = None;
        let mut usage: Option<Usage> = None;
        let mut text_blocks: std::collections::HashMap<usize, String> =
            std::collections::HashMap::new();
        let mut tool_blocks: std::collections::HashMap<usize, StreamToolUseBlock> =
            std::collections::HashMap::new();
        let mut ordered_indexes: Vec<usize> = Vec::new();

        'outer: while let Some(chunk_res) = byte_stream.next().await {
            let chunk = match chunk_res {
                Ok(c) => c,
                Err(_) => break,
            };
            for data in sse.push_chunk(&String::from_utf8_lossy(&chunk)) {
                if data == "[DONE]" {
                    break 'outer;
                }
                process_anthropic_stream_event(
                    &data,
                    text_tx,
                    &mut stop_reason,
                    &mut usage,
                    &mut text_blocks,
                    &mut tool_blocks,
                    &mut ordered_indexes,
                );
            }
        }
        for data in sse.finish() {
            if data == "[DONE]" {
                break;
            }
            process_anthropic_stream_event(
                &data,
                text_tx,
                &mut stop_reason,
                &mut usage,
                &mut text_blocks,
                &mut tool_blocks,
                &mut ordered_indexes,
            );
        }

        Ok(build_stream_response(
            ordered_indexes,
            text_blocks,
            tool_blocks,
            stop_reason,
            usage,
        ))
    }
}

fn resolve_anthropic_messages_url(configured_base: &str) -> String {
    let trimmed = configured_base.trim().trim_end_matches('/').to_string();
    if trimmed.is_empty() {
        return "https://api.anthropic.com/v1/messages".to_string();
    }
    if trimmed.ends_with("/v1/messages") {
        return trimmed;
    }
    format!("{trimmed}/v1/messages")
}

#[derive(Default)]
struct StreamToolUseBlock {
    id: String,
    name: String,
    input_json: String,
}

fn usage_from_json(v: &serde_json::Value) -> Option<Usage> {
    let input = v.get("input_tokens").and_then(|n| n.as_u64())?;
    let output = v
        .get("output_tokens")
        .and_then(|n| n.as_u64())
        .or_else(|| v.get("completion_tokens").and_then(|n| n.as_u64()))
        .unwrap_or(0);
    Some(Usage {
        input_tokens: u32::try_from(input).unwrap_or(u32::MAX),
        output_tokens: u32::try_from(output).unwrap_or(u32::MAX),
    })
}

fn process_anthropic_stream_event(
    data: &str,
    text_tx: Option<&UnboundedSender<String>>,
    stop_reason: &mut Option<String>,
    usage: &mut Option<Usage>,
    text_blocks: &mut std::collections::HashMap<usize, String>,
    tool_blocks: &mut std::collections::HashMap<usize, StreamToolUseBlock>,
    ordered_indexes: &mut Vec<usize>,
) {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(data) else {
        return;
    };

    let event_type = v.get("type").and_then(|t| t.as_str()).unwrap_or_default();
    match event_type {
        "content_block_start" => {
            if let Some(index) = v
                .get("index")
                .and_then(|i| i.as_u64())
                .and_then(|i| usize::try_from(i).ok())
            {
                if !ordered_indexes.contains(&index) {
                    ordered_indexes.push(index);
                }
                if let Some(block) = v.get("content_block") {
                    match block.get("type").and_then(|t| t.as_str()) {
                        Some("text") => {
                            let text = block
                                .get("text")
                                .and_then(|t| t.as_str())
                                .unwrap_or_default()
                                .to_string();
                            text_blocks.insert(index, text);
                        }
                        Some("tool_use") => {
                            let id = block
                                .get("id")
                                .and_then(|s| s.as_str())
                                .unwrap_or_default()
                                .to_string();
                            let name = block
                                .get("name")
                                .and_then(|s| s.as_str())
                                .unwrap_or_default()
                                .to_string();
                            let input = block.get("input").cloned().unwrap_or_else(|| json!({}));
                            let input_json = if input.is_object()
                                && input.as_object().is_some_and(|m| m.is_empty())
                            {
                                String::new()
                            } else {
                                serde_json::to_string(&input).unwrap_or_else(|_| "{}".to_string())
                            };
                            tool_blocks.insert(
                                index,
                                StreamToolUseBlock {
                                    id,
                                    name,
                                    input_json,
                                },
                            );
                        }
                        _ => {}
                    }
                }
            }
        }
        "content_block_delta" => {
            let Some(index) = v
                .get("index")
                .and_then(|i| i.as_u64())
                .and_then(|i| usize::try_from(i).ok())
            else {
                return;
            };
            let Some(delta) = v.get("delta") else {
                return;
            };
            match delta.get("type").and_then(|t| t.as_str()) {
                Some("text_delta") => {
                    let piece = delta
                        .get("text")
                        .and_then(|t| t.as_str())
                        .unwrap_or_default();
                    if !piece.is_empty() {
                        text_blocks.entry(index).or_default().push_str(piece);
                        if let Some(tx) = text_tx {
                            let _ = tx.send(piece.to_string());
                        }
                    }
                }
                Some("input_json_delta") => {
                    let piece = delta
                        .get("partial_json")
                        .and_then(|t| t.as_str())
                        .unwrap_or_default();
                    if !piece.is_empty() {
                        tool_blocks
                            .entry(index)
                            .or_default()
                            .input_json
                            .push_str(piece);
                    }
                }
                _ => {}
            }
        }
        "message_delta" => {
            if let Some(reason) = v
                .get("delta")
                .and_then(|d| d.get("stop_reason"))
                .and_then(|s| s.as_str())
            {
                *stop_reason = Some(reason.to_string());
            }
            if let Some(u) = v.get("usage") {
                *usage = usage_from_json(u);
            }
        }
        "message_start" => {
            if let Some(u) = v.get("message").and_then(|m| m.get("usage")) {
                *usage = usage_from_json(u);
            }
        }
        _ => {}
    }
}

fn process_openai_stream_event(
    data: &str,
    text_tx: Option<&UnboundedSender<String>>,
    text: &mut String,
    stop_reason: &mut Option<String>,
    usage: &mut Option<Usage>,
    tool_calls: &mut std::collections::BTreeMap<usize, StreamToolUseBlock>,
) {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(data) else {
        return;
    };

    if usage.is_none() {
        *usage = v.get("usage").and_then(usage_from_json);
    }

    let Some(choice) = v
        .get("choices")
        .and_then(|c| c.as_array())
        .and_then(|arr| arr.first())
    else {
        return;
    };

    if let Some(reason) = choice.get("finish_reason").and_then(|r| r.as_str()) {
        *stop_reason = Some(reason.to_string());
    }

    let Some(delta) = choice.get("delta") else {
        return;
    };

    if let Some(piece) = delta.get("content").and_then(|t| t.as_str()) {
        if !piece.is_empty() {
            text.push_str(piece);
            if let Some(tx) = text_tx {
                let _ = tx.send(piece.to_string());
            }
        }
    }

    if let Some(tc_arr) = delta.get("tool_calls").and_then(|v| v.as_array()) {
        for tc in tc_arr {
            let Some(index) = tc
                .get("index")
                .and_then(|i| i.as_u64())
                .and_then(|i| usize::try_from(i).ok())
            else {
                continue;
            };
            let entry = tool_calls.entry(index).or_default();
            if let Some(id) = tc.get("id").and_then(|v| v.as_str()) {
                entry.id = id.to_string();
            }
            if let Some(function) = tc.get("function") {
                if let Some(name) = function.get("name").and_then(|v| v.as_str()) {
                    entry.name = name.to_string();
                }
                if let Some(args) = function.get("arguments").and_then(|v| v.as_str()) {
                    entry.input_json.push_str(args);
                }
            }
        }
    }
}

fn normalize_stop_reason(reason: Option<String>) -> Option<String> {
    match reason.as_deref() {
        Some("tool_use") | Some("tool_calls") => Some("tool_use".into()),
        Some("max_tokens") | Some("length") => Some("max_tokens".into()),
        Some("stop") | Some("end_turn") | None => Some("end_turn".into()),
        Some(other) => Some(other.to_string()),
    }
}

fn parse_tool_input(input_json: &str) -> serde_json::Value {
    let trimmed = input_json.trim();
    if trimmed.is_empty() {
        return json!({});
    }
    serde_json::from_str(trimmed).unwrap_or_else(|_| json!({}))
}

fn build_stream_response(
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
                id: tool.id.clone(),
                name: tool.name.clone(),
                input: parse_tool_input(&tool.input_json),
            });
        }
    }

    if content.is_empty() {
        content.push(ResponseContentBlock::Text {
            text: String::new(),
        });
    }

    MessagesResponse {
        content,
        stop_reason: normalize_stop_reason(stop_reason),
        usage,
    }
}

#[derive(Debug, Deserialize)]
struct AnthropicApiError {
    error: AnthropicApiErrorDetail,
}

#[derive(Debug, Deserialize)]
struct AnthropicApiErrorDetail {
    message: String,
    #[serde(rename = "type")]
    error_type: String,
}

#[async_trait]
impl LlmProvider for AnthropicProvider {
    async fn send_message(
        &self,
        system: &str,
        messages: Vec<Message>,
        tools: Option<Vec<ToolDefinition>>,
    ) -> Result<MessagesResponse, MicroClawError> {
        let messages = sanitize_messages(messages);

        let request = MessagesRequest {
            model: self.model.clone(),
            max_tokens: self.max_tokens,
            system: system.to_string(),
            messages,
            tools,
            stream: None,
        };

        let mut retries = 0u32;
        let max_retries = 3;

        loop {
            let response = self
                .http
                .post(&self.base_url)
                .header("x-api-key", &self.api_key)
                .header("anthropic-version", "2023-06-01")
                .header("content-type", "application/json")
                .json(&request)
                .send()
                .await?;

            let status = response.status();

            if status.is_success() {
                let body = response.text().await?;
                let parsed: MessagesResponse = serde_json::from_str(&body).map_err(|e| {
                    MicroClawError::LlmApi(format!("Failed to parse response: {e}\nBody: {body}"))
                })?;
                return Ok(parsed);
            }

            if status.as_u16() == 429 && retries < max_retries {
                retries += 1;
                let delay = std::time::Duration::from_secs(2u64.pow(retries));
                warn!(
                    "Rate limited, retrying in {:?} (attempt {retries}/{max_retries})",
                    delay
                );
                tokio::time::sleep(delay).await;
                continue;
            }

            let body = response.text().await.unwrap_or_default();
            if let Ok(api_err) = serde_json::from_str::<AnthropicApiError>(&body) {
                return Err(MicroClawError::LlmApi(format!(
                    "{}: {}",
                    api_err.error.error_type, api_err.error.message
                )));
            }
            return Err(MicroClawError::LlmApi(format!("HTTP {status}: {body}")));
        }
    }

    async fn send_message_stream(
        &self,
        system: &str,
        messages: Vec<Message>,
        tools: Option<Vec<ToolDefinition>>,
        text_tx: Option<&UnboundedSender<String>>,
    ) -> Result<MessagesResponse, MicroClawError> {
        let messages = sanitize_messages(messages);
        let request = MessagesRequest {
            model: self.model.clone(),
            max_tokens: self.max_tokens,
            system: system.to_string(),
            messages,
            tools,
            stream: Some(true),
        };

        self.send_message_stream_single_pass(&request, text_tx)
            .await
    }
}

// ---------------------------------------------------------------------------
// OpenAI-compatible provider  (OpenAI, OpenRouter, DeepSeek, Groq, Ollama …)
// ---------------------------------------------------------------------------

pub struct OpenAiProvider {
    http: reqwest::Client,
    api_key: String,
    codex_account_id: Option<String>,
    model: String,
    max_tokens: u32,
    is_openai_codex: bool,
    chat_url: String,
    responses_url: String,
}

fn resolve_openai_compat_base(provider: &str, configured_base: &str) -> String {
    let trimmed = configured_base.trim().trim_end_matches('/').to_string();
    if is_openai_codex_provider(provider) {
        if let Some(codex_base) = codex_config_default_openai_base_url() {
            return codex_base.trim_end_matches('/').to_string();
        }
        return "https://chatgpt.com/backend-api/codex".to_string();
    }

    if trimmed.is_empty() {
        "https://api.openai.com/v1".to_string()
    } else {
        trimmed
    }
}

impl OpenAiProvider {
    pub fn new(config: &Config) -> Self {
        let is_openai_codex = is_openai_codex_provider(&config.llm_provider);
        let configured_base = config.llm_base_url.as_deref().unwrap_or("");
        let base = resolve_openai_compat_base(&config.llm_provider, configured_base);

        let (api_key, codex_account_id) = if is_openai_codex {
            let _ = refresh_openai_codex_auth_if_needed();
            match resolve_openai_codex_auth("") {
                Ok(auth) => (auth.bearer_token, auth.account_id),
                Err(e) => {
                    warn!("{}", e);
                    (String::new(), None)
                }
            }
        } else {
            (config.api_key.clone(), None)
        };

        OpenAiProvider {
            http: reqwest::Client::new(),
            api_key,
            codex_account_id,
            model: config.model.clone(),
            max_tokens: config.max_tokens,
            is_openai_codex,
            chat_url: format!("{}/chat/completions", base.trim_end_matches('/')),
            responses_url: format!("{}/responses", base.trim_end_matches('/')),
        }
    }
}

// --- OpenAI response types ---

#[derive(Debug, Deserialize)]
struct OaiResponse {
    choices: Vec<OaiChoice>,
    usage: Option<OaiUsage>,
}

#[derive(Debug, Deserialize)]
struct OaiChoice {
    message: OaiMessage,
    finish_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OaiMessage {
    content: Option<String>,
    tool_calls: Option<Vec<OaiToolCall>>,
}

#[derive(Debug, Deserialize)]
struct OaiToolCall {
    id: String,
    function: OaiFunction,
}

#[derive(Debug, Deserialize)]
struct OaiFunction {
    name: String,
    arguments: String,
}

#[derive(Debug, Deserialize)]
struct OaiUsage {
    prompt_tokens: u32,
    completion_tokens: u32,
}

#[derive(Debug, Deserialize)]
struct OaiErrorResponse {
    error: OaiErrorDetail,
}

#[derive(Debug, Deserialize)]
struct OaiErrorDetail {
    message: String,
}

#[derive(Debug, Deserialize)]
struct OaiResponsesResponse {
    output: Vec<OaiResponsesOutputItem>,
    usage: Option<OaiResponsesUsage>,
}

#[derive(Debug, Deserialize)]
struct OaiResponsesUsage {
    input_tokens: u32,
    output_tokens: u32,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum OaiResponsesOutputItem {
    #[serde(rename = "message")]
    Message {
        content: Vec<OaiResponsesOutputContentPart>,
    },
    #[serde(rename = "function_call")]
    FunctionCall {
        id: Option<String>,
        call_id: Option<String>,
        name: String,
        arguments: String,
    },
    #[serde(other)]
    Other,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum OaiResponsesOutputContentPart {
    #[serde(rename = "output_text")]
    OutputText { text: String },
    #[serde(other)]
    Other,
}

#[async_trait]
impl LlmProvider for OpenAiProvider {
    async fn send_message(
        &self,
        system: &str,
        messages: Vec<Message>,
        tools: Option<Vec<ToolDefinition>>,
    ) -> Result<MessagesResponse, MicroClawError> {
        if self.is_openai_codex {
            return self.send_codex_message(system, messages, tools).await;
        }

        let oai_messages = translate_messages_to_oai(system, &messages);

        let mut body = json!({
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": oai_messages,
        });

        if let Some(ref tool_defs) = tools {
            if !tool_defs.is_empty() {
                body["tools"] = json!(translate_tools_to_oai(tool_defs));
            }
        }

        let mut retries = 0u32;
        let max_retries = 3;

        loop {
            let mut req = self
                .http
                .post(&self.chat_url)
                .header("Content-Type", "application/json")
                .json(&body);
            if !self.api_key.trim().is_empty() {
                req = req.header("Authorization", format!("Bearer {}", self.api_key));
            }
            let response = req.send().await?;

            let status = response.status();

            if status.is_success() {
                let text = response.text().await?;
                let oai: OaiResponse = serde_json::from_str(&text).map_err(|e| {
                    MicroClawError::LlmApi(format!(
                        "Failed to parse OpenAI response: {e}\nBody: {text}"
                    ))
                })?;
                return Ok(translate_oai_response(oai));
            }

            if status.as_u16() == 429 && retries < max_retries {
                retries += 1;
                let delay = std::time::Duration::from_secs(2u64.pow(retries));
                warn!(
                    "Rate limited, retrying in {:?} (attempt {retries}/{max_retries})",
                    delay
                );
                tokio::time::sleep(delay).await;
                continue;
            }

            let text = response.text().await.unwrap_or_default();
            if let Ok(err) = serde_json::from_str::<OaiErrorResponse>(&text) {
                return Err(MicroClawError::LlmApi(err.error.message));
            }
            return Err(MicroClawError::LlmApi(format!("HTTP {status}: {text}")));
        }
    }

    async fn send_message_stream(
        &self,
        system: &str,
        messages: Vec<Message>,
        tools: Option<Vec<ToolDefinition>>,
        text_tx: Option<&UnboundedSender<String>>,
    ) -> Result<MessagesResponse, MicroClawError> {
        if self.is_openai_codex {
            let response = self.send_codex_message(system, messages, tools).await?;
            if let Some(tx) = text_tx {
                let text = response
                    .content
                    .iter()
                    .filter_map(|block| match block {
                        ResponseContentBlock::Text { text } => Some(text.as_str()),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
                    .join("");
                if !text.is_empty() {
                    let _ = tx.send(text);
                }
            }
            return Ok(response);
        }

        let oai_messages = translate_messages_to_oai(system, &messages);

        let mut body = json!({
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": oai_messages,
            "stream": true,
        });

        if let Some(ref tool_defs) = tools {
            if !tool_defs.is_empty() {
                body["tools"] = json!(translate_tools_to_oai(tool_defs));
            }
        }

        let mut req = self
            .http
            .post(&self.chat_url)
            .header("Content-Type", "application/json")
            .json(&body);
        if !self.api_key.trim().is_empty() {
            req = req.header("Authorization", format!("Bearer {}", self.api_key));
        }
        let response = req.send().await?;
        let status = response.status();
        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            if let Ok(err) = serde_json::from_str::<OaiErrorResponse>(&text) {
                return Err(MicroClawError::LlmApi(err.error.message));
            }
            return Err(MicroClawError::LlmApi(format!("HTTP {status}: {text}")));
        }

        let mut byte_stream = response.bytes_stream();
        let mut sse = SseEventParser::default();
        let mut text = String::new();
        let mut stop_reason: Option<String> = None;
        let mut usage: Option<Usage> = None;
        let mut tool_calls: std::collections::BTreeMap<usize, StreamToolUseBlock> =
            std::collections::BTreeMap::new();

        'outer: while let Some(chunk_res) = byte_stream.next().await {
            let chunk = match chunk_res {
                Ok(c) => c,
                Err(_) => break,
            };
            for data in sse.push_chunk(&String::from_utf8_lossy(&chunk)) {
                if data == "[DONE]" {
                    break 'outer;
                }
                process_openai_stream_event(
                    &data,
                    text_tx,
                    &mut text,
                    &mut stop_reason,
                    &mut usage,
                    &mut tool_calls,
                );
            }
        }
        for data in sse.finish() {
            if data == "[DONE]" {
                break;
            }
            process_openai_stream_event(
                &data,
                text_tx,
                &mut text,
                &mut stop_reason,
                &mut usage,
                &mut tool_calls,
            );
        }

        let mut content = Vec::new();
        if !text.is_empty() {
            content.push(ResponseContentBlock::Text { text });
        }
        for (_index, tool) in tool_calls {
            content.push(ResponseContentBlock::ToolUse {
                id: tool.id,
                name: tool.name,
                input: parse_tool_input(&tool.input_json),
            });
        }
        if content.is_empty() {
            content.push(ResponseContentBlock::Text {
                text: String::new(),
            });
        }

        Ok(MessagesResponse {
            content,
            stop_reason: normalize_stop_reason(stop_reason),
            usage,
        })
    }
}

impl OpenAiProvider {
    async fn send_codex_message(
        &self,
        system: &str,
        messages: Vec<Message>,
        tools: Option<Vec<ToolDefinition>>,
    ) -> Result<MessagesResponse, MicroClawError> {
        let instructions = if system.trim().is_empty() {
            "You are a helpful assistant."
        } else {
            system
        };
        let mut input = translate_messages_to_oai_responses_input(&messages);
        if input.is_empty() {
            input.push(json!({
                "type": "message",
                "role": "user",
                "content": "",
            }));
        }
        let mut body = json!({
            "model": self.model,
            "input": input,
            "instructions": instructions,
            "store": false,
            "stream": true,
        });
        if let Some(ref tool_defs) = tools {
            if !tool_defs.is_empty() {
                body["tools"] = json!(translate_tools_to_oai_responses(tool_defs));
                body["tool_choice"] = json!("auto");
            }
        }

        let mut retries = 0u32;
        let max_retries = 3;

        loop {
            let mut req = self
                .http
                .post(&self.responses_url)
                .header("Content-Type", "application/json")
                .json(&body);
            if !self.api_key.trim().is_empty() {
                req = req.header("Authorization", format!("Bearer {}", self.api_key));
            }
            if let Some(account_id) = self.codex_account_id.as_deref() {
                if !account_id.trim().is_empty() {
                    req = req.header("ChatGPT-Account-ID", account_id);
                }
            }
            let response = req.send().await?;
            let status = response.status();

            if status.is_success() {
                let text = response.text().await?;
                let parsed = parse_openai_codex_response_payload(&text)?;
                return Ok(translate_oai_responses_response(parsed));
            }

            if status.as_u16() == 429 && retries < max_retries {
                retries += 1;
                let delay = std::time::Duration::from_secs(2u64.pow(retries));
                warn!(
                    "Rate limited, retrying in {:?} (attempt {retries}/{max_retries})",
                    delay
                );
                tokio::time::sleep(delay).await;
                continue;
            }

            let text = response.text().await.unwrap_or_default();
            if let Ok(err) = serde_json::from_str::<OaiErrorResponse>(&text) {
                return Err(MicroClawError::LlmApi(err.error.message));
            }
            return Err(MicroClawError::LlmApi(format!("HTTP {status}: {text}")));
        }
    }
}

fn parse_openai_codex_response_payload(text: &str) -> Result<OaiResponsesResponse, MicroClawError> {
    if let Ok(parsed) = serde_json::from_str::<OaiResponsesResponse>(text) {
        return Ok(parsed);
    }

    let mut from_done_event: Option<OaiResponsesResponse> = None;
    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with("data:") {
            continue;
        }
        let payload = line.trim_start_matches("data:").trim();
        if payload.is_empty() || payload == "[DONE]" {
            continue;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(payload) else {
            continue;
        };

        if let Some(response_value) = value.get("response") {
            if let Ok(parsed) =
                serde_json::from_value::<OaiResponsesResponse>(response_value.clone())
            {
                from_done_event = Some(parsed);
                if value.get("type").and_then(|v| v.as_str()) == Some("response.done") {
                    break;
                }
            }
        }
    }

    if let Some(parsed) = from_done_event {
        return Ok(parsed);
    }

    Err(MicroClawError::LlmApi(format!(
        "Failed to parse OpenAI Codex response payload. Body: {text}"
    )))
}

// ---------------------------------------------------------------------------
// Format translation helpers  (internal Anthropic-style ↔ OpenAI)
// ---------------------------------------------------------------------------

fn translate_messages_to_oai(system: &str, messages: &[Message]) -> Vec<serde_json::Value> {
    // Collect all tool_use IDs present in assistant messages so we can
    // skip orphaned tool_results (e.g. after session compaction).
    let known_tool_ids: std::collections::HashSet<&str> = messages
        .iter()
        .filter(|m| m.role == "assistant")
        .flat_map(|m| match &m.content {
            MessageContent::Blocks(blocks) => blocks
                .iter()
                .filter_map(|b| match b {
                    ContentBlock::ToolUse { id, .. } => Some(id.as_str()),
                    _ => None,
                })
                .collect::<Vec<_>>(),
            _ => vec![],
        })
        .collect();

    let mut out: Vec<serde_json::Value> = Vec::new();

    // System message
    if !system.is_empty() {
        out.push(json!({"role": "system", "content": system}));
    }

    for msg in messages {
        match &msg.content {
            MessageContent::Text(text) => {
                out.push(json!({"role": msg.role, "content": text}));
            }
            MessageContent::Blocks(blocks) => {
                if msg.role == "assistant" {
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
                            ContentBlock::ToolUse { id, name, input } => Some(json!({
                                "id": id,
                                "type": "function",
                                "function": {
                                    "name": name,
                                    "arguments": serde_json::to_string(input).unwrap_or_default()
                                }
                            })),
                            _ => None,
                        })
                        .collect();

                    let mut m = json!({"role": "assistant"});
                    if !text.is_empty() || tool_calls.is_empty() {
                        m["content"] = json!(text);
                    }
                    if !tool_calls.is_empty() {
                        m["tool_calls"] = json!(tool_calls);
                    }
                    out.push(m);
                } else {
                    // User role — tool_results, images, or text
                    let has_tool_results = blocks
                        .iter()
                        .any(|b| matches!(b, ContentBlock::ToolResult { .. }));

                    if has_tool_results {
                        // Each tool result → separate "tool" message
                        // Skip orphaned tool_results whose IDs are not in any assistant message
                        for block in blocks {
                            if let ContentBlock::ToolResult {
                                tool_use_id,
                                content,
                                is_error,
                            } = block
                            {
                                if !known_tool_ids.contains(tool_use_id.as_str()) {
                                    continue;
                                }
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
                    } else {
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

    out
}

fn translate_tools_to_oai(tools: &[ToolDefinition]) -> Vec<serde_json::Value> {
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

fn translate_tools_to_oai_responses(tools: &[ToolDefinition]) -> Vec<serde_json::Value> {
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

fn translate_messages_to_oai_responses_input(messages: &[Message]) -> Vec<serde_json::Value> {
    let known_tool_ids: std::collections::HashSet<&str> = messages
        .iter()
        .filter(|m| m.role == "assistant")
        .flat_map(|m| match &m.content {
            MessageContent::Blocks(blocks) => blocks
                .iter()
                .filter_map(|b| match b {
                    ContentBlock::ToolUse { id, .. } => Some(id.as_str()),
                    _ => None,
                })
                .collect::<Vec<_>>(),
            _ => vec![],
        })
        .collect();

    let mut out: Vec<serde_json::Value> = Vec::new();
    for msg in messages {
        match &msg.content {
            MessageContent::Text(text) => {
                out.push(json!({
                    "type": "message",
                    "role": msg.role,
                    "content": text,
                }));
            }
            MessageContent::Blocks(blocks) => {
                if msg.role == "assistant" {
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
                        if let ContentBlock::ToolUse { id, name, input } = block {
                            out.push(json!({
                                "type": "function_call",
                                "call_id": id,
                                "name": name,
                                "arguments": serde_json::to_string(input).unwrap_or_default(),
                            }));
                        }
                    }
                } else {
                    let has_tool_results = blocks
                        .iter()
                        .any(|b| matches!(b, ContentBlock::ToolResult { .. }));
                    if has_tool_results {
                        for block in blocks {
                            if let ContentBlock::ToolResult {
                                tool_use_id,
                                content,
                                is_error,
                            } = block
                            {
                                if !known_tool_ids.contains(tool_use_id.as_str()) {
                                    continue;
                                }
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
                    } else {
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

fn translate_oai_responses_response(resp: OaiResponsesResponse) -> MessagesResponse {
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
                    id: call_id,
                    name,
                    input: parsed_args,
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

fn translate_oai_response(oai: OaiResponse) -> MessagesResponse {
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

    if let Some(text) = choice.message.content {
        if !text.is_empty() {
            content.push(ResponseContentBlock::Text { text });
        }
    }

    if let Some(tool_calls) = choice.message.tool_calls {
        for tc in tool_calls {
            let input: serde_json::Value =
                serde_json::from_str(&tc.function.arguments).unwrap_or_default();
            content.push(ResponseContentBlock::ToolUse {
                id: tc.id,
                name: tc.function.name,
                input,
            });
        }
    }

    if content.is_empty() {
        content.push(ResponseContentBlock::Text {
            text: String::new(),
        });
    }

    let stop_reason = match choice.finish_reason.as_deref() {
        Some("tool_calls") => Some("tool_use".into()),
        Some("length") => Some("max_tokens".into()),
        _ => Some("end_turn".into()),
    };

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
    use serde_json::json;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::sync::{Mutex, OnceLock};
    use std::time::Duration;

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env lock poisoned")
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
        let msgs = vec![Message {
            role: "assistant".into(),
            content: MessageContent::Blocks(vec![
                ContentBlock::Text {
                    text: "Let me check.".into(),
                },
                ContentBlock::ToolUse {
                    id: "t1".into(),
                    name: "bash".into(),
                    input: json!({"command": "ls"}),
                },
            ]),
        }];
        let out = translate_messages_to_oai("", &msgs);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["role"], "assistant");
        assert_eq!(out[0]["content"], "Let me check.");
        let tc = out[0]["tool_calls"].as_array().unwrap();
        assert_eq!(tc.len(), 1);
        assert_eq!(tc[0]["id"], "t1");
        assert_eq!(tc[0]["function"]["name"], "bash");
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
    fn test_translate_oai_response_text() {
        let oai = OaiResponse {
            choices: vec![OaiChoice {
                message: OaiMessage {
                    content: Some("Hello!".into()),
                    tool_calls: None,
                },
                finish_reason: Some("stop".into()),
            }],
            usage: Some(OaiUsage {
                prompt_tokens: 10,
                completion_tokens: 5,
            }),
        };
        let resp = translate_oai_response(oai);
        assert_eq!(resp.stop_reason.as_deref(), Some("end_turn"));
        assert_eq!(resp.content.len(), 1);
        match &resp.content[0] {
            ResponseContentBlock::Text { text } => assert_eq!(text, "Hello!"),
            _ => panic!("Expected Text"),
        }
        let usage = resp.usage.unwrap();
        assert_eq!(usage.input_tokens, 10);
        assert_eq!(usage.output_tokens, 5);
    }

    #[test]
    fn test_translate_oai_response_tool_calls() {
        let oai = OaiResponse {
            choices: vec![OaiChoice {
                message: OaiMessage {
                    content: None,
                    tool_calls: Some(vec![OaiToolCall {
                        id: "call_1".into(),
                        function: OaiFunction {
                            name: "bash".into(),
                            arguments: r#"{"command":"ls"}"#.into(),
                        },
                    }]),
                },
                finish_reason: Some("tool_calls".into()),
            }],
            usage: None,
        };
        let resp = translate_oai_response(oai);
        assert_eq!(resp.stop_reason.as_deref(), Some("tool_use"));
        match &resp.content[0] {
            ResponseContentBlock::ToolUse { id, name, input } => {
                assert_eq!(id, "call_1");
                assert_eq!(name, "bash");
                assert_eq!(input["command"], "ls");
            }
            _ => panic!("Expected ToolUse"),
        }
    }

    #[test]
    fn test_translate_oai_response_empty_choices() {
        let oai = OaiResponse {
            choices: vec![],
            usage: None,
        };
        let resp = translate_oai_response(oai);
        assert_eq!(resp.stop_reason.as_deref(), Some("end_turn"));
        match &resp.content[0] {
            ResponseContentBlock::Text { text } => assert_eq!(text, "(empty response)"),
            _ => panic!("Expected Text"),
        }
    }

    #[test]
    fn test_translate_oai_response_length_stop() {
        let oai = OaiResponse {
            choices: vec![OaiChoice {
                message: OaiMessage {
                    content: Some("partial".into()),
                    tool_calls: None,
                },
                finish_reason: Some("length".into()),
            }],
            usage: None,
        };
        let resp = translate_oai_response(oai);
        assert_eq!(resp.stop_reason.as_deref(), Some("max_tokens"));
    }

    #[test]
    fn test_translate_oai_response_text_and_tool_calls() {
        let oai = OaiResponse {
            choices: vec![OaiChoice {
                message: OaiMessage {
                    content: Some("thinking...".into()),
                    tool_calls: Some(vec![OaiToolCall {
                        id: "c1".into(),
                        function: OaiFunction {
                            name: "read_file".into(),
                            arguments: r#"{"path":"/tmp/x"}"#.into(),
                        },
                    }]),
                },
                finish_reason: Some("tool_calls".into()),
            }],
            usage: None,
        };
        let resp = translate_oai_response(oai);
        assert_eq!(resp.content.len(), 2);
        match &resp.content[0] {
            ResponseContentBlock::Text { text } => assert_eq!(text, "thinking..."),
            _ => panic!("Expected Text"),
        }
        match &resp.content[1] {
            ResponseContentBlock::ToolUse { name, .. } => assert_eq!(name, "read_file"),
            _ => panic!("Expected ToolUse"),
        }
    }

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
    fn test_build_stream_response_tool_json_parsing() {
        let mut tool_blocks = std::collections::HashMap::new();
        tool_blocks.insert(
            0,
            StreamToolUseBlock {
                id: "call_1".into(),
                name: "bash".into(),
                input_json: r#"{"command":"ls","cwd":"/tmp"}"#.into(),
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
            ResponseContentBlock::ToolUse { id, name, input } => {
                assert_eq!(id, "call_1");
                assert_eq!(name, "bash");
                assert_eq!(input["command"], "ls");
                assert_eq!(input["cwd"], "/tmp");
            }
            _ => panic!("Expected ToolUse"),
        }
    }

    // -----------------------------------------------------------------------
    // create_provider
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_provider_anthropic() {
        let config = Config {
            telegram_bot_token: "tok".into(),
            bot_username: "bot".into(),
            llm_provider: "anthropic".into(),
            api_key: "key".into(),
            model: "claude-sonnet-4-5-20250929".into(),
            llm_base_url: None,
            max_tokens: 8192,
            max_tool_iterations: 100,
            max_history_messages: 50,
            max_document_size_mb: 100,
            memory_token_budget: 1500,
            data_dir: "/tmp".into(),
            working_dir: "/tmp".into(),
            working_dir_isolation: WorkingDirIsolation::Shared,
            openai_api_key: None,
            timezone: "UTC".into(),
            allowed_groups: vec![],
            control_chat_ids: vec![],
            max_session_messages: 40,
            compact_keep_recent: 20,
            discord_bot_token: None,
            discord_allowed_channels: vec![],
            show_thinking: false,
            web_enabled: false,
            web_host: "127.0.0.1".into(),
            web_port: 3900,
            web_auth_token: None,
            web_max_inflight_per_session: 2,
            web_max_requests_per_window: 8,
            web_rate_window_seconds: 10,
            web_run_history_limit: 512,
            web_session_idle_ttl_seconds: 300,
            model_prices: vec![],
            embedding_provider: None,
            embedding_api_key: None,
            embedding_base_url: None,
            embedding_model: None,
            embedding_dim: None,
            reflector_enabled: true,
            reflector_interval_mins: 15,
            soul_path: None,
            channels: std::collections::HashMap::new(),
        };
        // Should not panic
        let _provider = create_provider(&config);
    }

    #[test]
    fn test_create_provider_openai() {
        let config = Config {
            telegram_bot_token: "tok".into(),
            bot_username: "bot".into(),
            llm_provider: "openai".into(),
            api_key: "key".into(),
            model: "gpt-5.2".into(),
            llm_base_url: None,
            max_tokens: 8192,
            max_tool_iterations: 100,
            max_history_messages: 50,
            max_document_size_mb: 100,
            memory_token_budget: 1500,
            data_dir: "/tmp".into(),
            working_dir: "/tmp".into(),
            working_dir_isolation: WorkingDirIsolation::Shared,
            openai_api_key: None,
            timezone: "UTC".into(),
            allowed_groups: vec![],
            control_chat_ids: vec![],
            max_session_messages: 40,
            compact_keep_recent: 20,
            discord_bot_token: None,
            discord_allowed_channels: vec![],
            show_thinking: false,
            web_enabled: false,
            web_host: "127.0.0.1".into(),
            web_port: 3900,
            web_auth_token: None,
            web_max_inflight_per_session: 2,
            web_max_requests_per_window: 8,
            web_rate_window_seconds: 10,
            web_run_history_limit: 512,
            web_session_idle_ttl_seconds: 300,
            model_prices: vec![],
            embedding_provider: None,
            embedding_api_key: None,
            embedding_base_url: None,
            embedding_model: None,
            embedding_dim: None,
            reflector_enabled: true,
            reflector_interval_mins: 15,
            soul_path: None,
            channels: std::collections::HashMap::new(),
        };
        let _provider = create_provider(&config);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_openai_codex_stream_uses_responses_endpoint() {
        let _guard = env_lock();
        let prev_access = std::env::var("OPENAI_CODEX_ACCESS_TOKEN").ok();
        let prev_codex_home = std::env::var("CODEX_HOME").ok();
        std::env::set_var("OPENAI_CODEX_ACCESS_TOKEN", "oauth-token");

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let codex_home = std::env::temp_dir().join(format!(
            "microclaw-codex-home-oauth-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&codex_home).unwrap();
        std::fs::write(
            codex_home.join("config.toml"),
            format!(
                "model_provider = \"test\"\n\n[model_providers.test]\nbase_url = \"http://{}\"\n",
                addr
            ),
        )
        .unwrap();
        std::env::set_var("CODEX_HOME", &codex_home);
        let (request_tx, request_rx) = mpsc::channel::<(String, Option<String>)>();

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();

            let mut buf = [0u8; 8192];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let path = req
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or("")
                .to_string();
            let auth_header = req.lines().find_map(|line| {
                let lower = line.to_ascii_lowercase();
                if lower.starts_with("authorization:") {
                    Some(
                        line.split_once(':')
                            .map(|(_, v)| v.trim().to_string())
                            .unwrap_or_default(),
                    )
                } else {
                    None
                }
            });
            let _ = request_tx.send((path, auth_header));

            let body = r#"{"output":[{"type":"message","content":[{"type":"output_text","text":"ok"}]}],"usage":{"input_tokens":1,"output_tokens":1}}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        });

        let config = Config {
            telegram_bot_token: "tok".into(),
            bot_username: "bot".into(),
            llm_provider: "openai-codex".into(),
            api_key: "fallback-key".into(),
            model: "gpt-5.3-codex".into(),
            llm_base_url: Some("http://should-be-ignored".into()),
            max_tokens: 8192,
            max_tool_iterations: 100,
            max_history_messages: 50,
            max_document_size_mb: 100,
            memory_token_budget: 1500,
            data_dir: "/tmp".into(),
            working_dir: "/tmp".into(),
            working_dir_isolation: WorkingDirIsolation::Shared,
            openai_api_key: None,
            timezone: "UTC".into(),
            allowed_groups: vec![],
            control_chat_ids: vec![],
            max_session_messages: 40,
            compact_keep_recent: 20,
            discord_bot_token: None,
            discord_allowed_channels: vec![],
            show_thinking: false,
            web_enabled: false,
            web_host: "127.0.0.1".into(),
            web_port: 3900,
            web_auth_token: None,
            web_max_inflight_per_session: 2,
            web_max_requests_per_window: 8,
            web_rate_window_seconds: 10,
            web_run_history_limit: 512,
            web_session_idle_ttl_seconds: 300,
            model_prices: vec![],
            embedding_provider: None,
            embedding_api_key: None,
            embedding_base_url: None,
            embedding_model: None,
            embedding_dim: None,
            reflector_enabled: true,
            reflector_interval_mins: 15,
            soul_path: None,
            channels: std::collections::HashMap::new(),
        };
        let provider = OpenAiProvider::new(&config);
        let messages = vec![Message {
            role: "user".into(),
            content: MessageContent::Text("hi".into()),
        }];
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let resp = LlmProvider::send_message_stream(&provider, "", messages, None, Some(&tx))
            .await
            .unwrap();
        drop(tx);

        let (path, auth_header) = request_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        server.join().unwrap();
        if let Some(prev) = prev_access {
            std::env::set_var("OPENAI_CODEX_ACCESS_TOKEN", prev);
        } else {
            std::env::remove_var("OPENAI_CODEX_ACCESS_TOKEN");
        }
        if let Some(prev) = prev_codex_home {
            std::env::set_var("CODEX_HOME", prev);
        } else {
            std::env::remove_var("CODEX_HOME");
        }
        let _ = std::fs::remove_file(codex_home.join("config.toml"));
        let _ = std::fs::remove_dir(codex_home);

        assert_eq!(path, "/responses");
        assert_eq!(auth_header.as_deref(), Some("Bearer oauth-token"));
        assert_eq!(resp.stop_reason.as_deref(), Some("end_turn"));
        match &resp.content[0] {
            ResponseContentBlock::Text { text } => assert_eq!(text, "ok"),
            _ => panic!("Expected text block"),
        }
        assert_eq!(rx.recv().await.as_deref(), Some("ok"));
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_openai_codex_stream_uses_auth_json_openai_api_key_when_oauth_missing() {
        let _guard = env_lock();
        let prev_access = std::env::var("OPENAI_CODEX_ACCESS_TOKEN").ok();
        let prev_codex_home = std::env::var("CODEX_HOME").ok();
        std::env::remove_var("OPENAI_CODEX_ACCESS_TOKEN");

        let auth_dir = std::env::temp_dir().join(format!(
            "microclaw-codex-auth-empty-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&auth_dir).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::fs::write(
            auth_dir.join("auth.json"),
            r#"{"OPENAI_API_KEY":"sk-from-auth-json"}"#,
        )
        .unwrap();
        std::fs::write(
            auth_dir.join("config.toml"),
            format!(
                "model_provider = \"test\"\n\n[model_providers.test]\nbase_url = \"http://{}\"\n",
                addr
            ),
        )
        .unwrap();
        std::env::set_var("CODEX_HOME", &auth_dir);

        let (request_tx, request_rx) = mpsc::channel::<(String, Option<String>)>();

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();

            let mut buf = [0u8; 8192];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let path = req
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or("")
                .to_string();
            let auth_header = req.lines().find_map(|line| {
                let lower = line.to_ascii_lowercase();
                if lower.starts_with("authorization:") {
                    Some(
                        line.split_once(':')
                            .map(|(_, v)| v.trim().to_string())
                            .unwrap_or_default(),
                    )
                } else {
                    None
                }
            });
            let _ = request_tx.send((path, auth_header));

            let body = r#"{"output":[{"type":"message","content":[{"type":"output_text","text":"ok"}]}],"usage":{"input_tokens":1,"output_tokens":1}}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        });

        let config = Config {
            telegram_bot_token: "tok".into(),
            bot_username: "bot".into(),
            llm_provider: "openai-codex".into(),
            api_key: "should-be-ignored".into(),
            model: "gpt-5.3-codex".into(),
            llm_base_url: Some("http://should-be-ignored".into()),
            max_tokens: 8192,
            max_tool_iterations: 100,
            max_history_messages: 50,
            max_document_size_mb: 100,
            memory_token_budget: 1500,
            data_dir: "/tmp".into(),
            working_dir: "/tmp".into(),
            working_dir_isolation: WorkingDirIsolation::Shared,
            openai_api_key: None,
            timezone: "UTC".into(),
            allowed_groups: vec![],
            control_chat_ids: vec![],
            max_session_messages: 40,
            compact_keep_recent: 20,
            discord_bot_token: None,
            discord_allowed_channels: vec![],
            show_thinking: false,
            web_enabled: false,
            web_host: "127.0.0.1".into(),
            web_port: 3900,
            web_auth_token: None,
            web_max_inflight_per_session: 2,
            web_max_requests_per_window: 8,
            web_rate_window_seconds: 10,
            web_run_history_limit: 512,
            web_session_idle_ttl_seconds: 300,
            model_prices: vec![],
            embedding_provider: None,
            embedding_api_key: None,
            embedding_base_url: None,
            embedding_model: None,
            embedding_dim: None,
            reflector_enabled: true,
            reflector_interval_mins: 15,
            soul_path: None,
            channels: std::collections::HashMap::new(),
        };
        let provider = OpenAiProvider::new(&config);
        let messages = vec![Message {
            role: "user".into(),
            content: MessageContent::Text("hi".into()),
        }];
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let resp = LlmProvider::send_message_stream(&provider, "", messages, None, Some(&tx))
            .await
            .unwrap();
        drop(tx);

        let (path, auth_header) = request_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        server.join().unwrap();
        if let Some(prev) = prev_codex_home {
            std::env::set_var("CODEX_HOME", prev);
        } else {
            std::env::remove_var("CODEX_HOME");
        }
        if let Some(prev) = prev_access {
            std::env::set_var("OPENAI_CODEX_ACCESS_TOKEN", prev);
        } else {
            std::env::remove_var("OPENAI_CODEX_ACCESS_TOKEN");
        }
        let _ = std::fs::remove_file(auth_dir.join("auth.json"));
        let _ = std::fs::remove_file(auth_dir.join("config.toml"));
        let _ = std::fs::remove_dir(auth_dir);

        assert_eq!(path, "/responses");
        assert_eq!(auth_header.as_deref(), Some("Bearer sk-from-auth-json"));
        assert_eq!(resp.stop_reason.as_deref(), Some("end_turn"));
        match &resp.content[0] {
            ResponseContentBlock::Text { text } => assert_eq!(text, "ok"),
            _ => panic!("Expected text block"),
        }
        assert_eq!(rx.recv().await.as_deref(), Some("ok"));
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

    #[test]
    fn test_sanitize_messages_removes_orphaned_tool_results() {
        let msgs = vec![
            Message {
                role: "assistant".into(),
                content: MessageContent::Blocks(vec![ContentBlock::ToolUse {
                    id: "t1".into(),
                    name: "bash".into(),
                    input: json!({}),
                }]),
            },
            Message {
                role: "user".into(),
                content: MessageContent::Blocks(vec![
                    ContentBlock::ToolResult {
                        tool_use_id: "t1".into(),
                        content: "ok".into(),
                        is_error: None,
                    },
                    ContentBlock::ToolResult {
                        tool_use_id: "orphan".into(),
                        content: "stale".into(),
                        is_error: None,
                    },
                ]),
            },
        ];
        let sanitized = sanitize_messages(msgs);
        assert_eq!(sanitized.len(), 2);
        // The user message should only contain t1's result
        if let MessageContent::Blocks(blocks) = &sanitized[1].content {
            assert_eq!(blocks.len(), 1);
            if let ContentBlock::ToolResult { tool_use_id, .. } = &blocks[0] {
                assert_eq!(tool_use_id, "t1");
            } else {
                panic!("Expected ToolResult");
            }
        } else {
            panic!("Expected Blocks");
        }
    }

    #[test]
    fn test_sanitize_messages_drops_empty_user_message() {
        // User message with only orphaned tool_results → dropped entirely
        let msgs = vec![Message {
            role: "user".into(),
            content: MessageContent::Blocks(vec![ContentBlock::ToolResult {
                tool_use_id: "orphan".into(),
                content: "stale".into(),
                is_error: None,
            }]),
        }];
        let sanitized = sanitize_messages(msgs);
        assert!(sanitized.is_empty());
    }

    #[test]
    fn test_sanitize_messages_preserves_text_messages() {
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
        let sanitized = sanitize_messages(msgs);
        assert_eq!(sanitized.len(), 2);
    }

    #[test]
    fn test_sse_event_parser_multiline_data() {
        let mut parser = SseEventParser::default();
        let events = parser
            .push_chunk("event: message\n: keep-alive\ndata: {\"type\":\"x\",\ndata: \"v\":1}\n\n");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], "{\"type\":\"x\",\n\"v\":1}");
    }

    #[test]
    fn test_sse_event_parser_finish_flushes_unterminated_event() {
        let mut parser = SseEventParser::default();
        let events = parser.push_chunk("data: hello");
        assert!(events.is_empty());
        let tail = parser.finish();
        assert_eq!(tail, vec!["hello".to_string()]);
    }

    #[test]
    fn test_resolve_openai_compat_base_defaults_openai() {
        let base = resolve_openai_compat_base("openai", "");
        assert_eq!(base, "https://api.openai.com/v1");
    }

    #[test]
    fn test_resolve_anthropic_messages_url_defaults() {
        let url = resolve_anthropic_messages_url("");
        assert_eq!(url, "https://api.anthropic.com/v1/messages");
    }

    #[test]
    fn test_resolve_anthropic_messages_url_accepts_full_messages_path() {
        let url = resolve_anthropic_messages_url("http://127.0.0.1:3000/api/v1/messages");
        assert_eq!(url, "http://127.0.0.1:3000/api/v1/messages");
    }

    #[test]
    fn test_resolve_anthropic_messages_url_appends_messages_path_for_prefix_base() {
        let url = resolve_anthropic_messages_url("http://127.0.0.1:3000/api/");
        assert_eq!(url, "http://127.0.0.1:3000/api/v1/messages");
    }

    #[test]
    fn test_resolve_openai_compat_base_defaults_openai_codex() {
        let _guard = env_lock();
        let prev_codex_home = std::env::var("CODEX_HOME").ok();
        let temp = std::env::temp_dir().join(format!(
            "microclaw-llm-codex-base-default-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&temp).unwrap();
        std::env::set_var("CODEX_HOME", &temp);

        let base = resolve_openai_compat_base("openai-codex", "");
        assert_eq!(base, "https://chatgpt.com/backend-api/codex");

        if let Some(prev) = prev_codex_home {
            std::env::set_var("CODEX_HOME", prev);
        } else {
            std::env::remove_var("CODEX_HOME");
        }
        let _ = std::fs::remove_dir(temp);
    }

    #[test]
    fn test_resolve_openai_compat_base_codex_uses_codex_config_toml_base() {
        let _guard = env_lock();
        let prev_codex_home = std::env::var("CODEX_HOME").ok();
        let temp = std::env::temp_dir().join(format!(
            "microclaw-llm-codex-base-file-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&temp).unwrap();
        std::fs::write(
            temp.join("config.toml"),
            "model_provider = \"tabcode\"\n\n[model_providers.tabcode]\nbase_url = \"https://api.tabcode.cc/openai\"\n",
        )
        .unwrap();
        std::env::set_var("CODEX_HOME", &temp);

        let base = resolve_openai_compat_base("openai-codex", "https://ignored.example.com");
        assert_eq!(base, "https://api.tabcode.cc/openai");

        if let Some(prev) = prev_codex_home {
            std::env::set_var("CODEX_HOME", prev);
        } else {
            std::env::remove_var("CODEX_HOME");
        }
        let _ = std::fs::remove_file(temp.join("config.toml"));
        let _ = std::fs::remove_dir(temp);
    }

    #[test]
    fn test_parse_openai_codex_response_payload_json() {
        let body = r#"{
          "output":[{"type":"message","content":[{"type":"output_text","text":"Hello"}]}],
          "usage":{"input_tokens":12,"output_tokens":34}
        }"#;
        let parsed = parse_openai_codex_response_payload(body).unwrap();
        let translated = translate_oai_responses_response(parsed);
        assert_eq!(translated.stop_reason.as_deref(), Some("end_turn"));
        match &translated.content[0] {
            ResponseContentBlock::Text { text } => assert_eq!(text, "Hello"),
            _ => panic!("Expected text block"),
        }
    }

    #[test]
    fn test_parse_openai_codex_response_payload_sse_response_done() {
        let body = r#"event: response.created
data: {"type":"response.created","response":{"output":[]}}

event: response.done
data: {"type":"response.done","response":{"output":[{"type":"message","content":[{"type":"output_text","text":"From SSE"}]}],"usage":{"input_tokens":1,"output_tokens":2}}}

data: [DONE]
"#;
        let parsed = parse_openai_codex_response_payload(body).unwrap();
        let translated = translate_oai_responses_response(parsed);
        assert_eq!(translated.stop_reason.as_deref(), Some("end_turn"));
        match &translated.content[0] {
            ResponseContentBlock::Text { text } => assert_eq!(text, "From SSE"),
            _ => panic!("Expected text block"),
        }
    }
}
