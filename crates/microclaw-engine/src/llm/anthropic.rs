use super::*;

pub struct AnthropicProvider {
    http: reqwest::Client,
    key_pool: KeyPool,
    model: String,
    max_tokens: u32,
    base_url: String,
    prompt_cache_enabled: bool,
    prompt_cache_ttl: String,
}

impl AnthropicProvider {
    pub fn new(config: &Config) -> Self {
        AnthropicProvider {
            http: reqwest::Client::new(),
            key_pool: KeyPool::new(&config.api_key, &config.api_keys),
            model: config.model.clone(),
            max_tokens: config.max_tokens,
            base_url: resolve_anthropic_messages_url(config.llm_base_url.as_deref().unwrap_or("")),
            prompt_cache_enabled: config.anthropic_prompt_cache_enabled,
            prompt_cache_ttl: config.anthropic_prompt_cache_ttl.clone(),
        }
    }

    /// Serialize the request and, if prompt caching is enabled, mutate the
    /// JSON body to add cache_control breakpoints.
    fn build_request_body(
        &self,
        request: &MessagesRequest,
    ) -> Result<serde_json::Value, MicroClawError> {
        let mut body = serde_json::to_value(request).map_err(|e| {
            MicroClawError::LlmApi(format!("failed to serialize Anthropic request: {e}"))
        })?;
        if self.prompt_cache_enabled {
            crate::prompt_cache::apply_anthropic_prompt_cache(&mut body, &self.prompt_cache_ttl);
        }
        Ok(body)
    }

    async fn send_message_stream_single_pass(
        &self,
        request: &MessagesRequest,
        text_tx: Option<&UnboundedSender<String>>,
    ) -> Result<MessagesResponse, MicroClawError> {
        let mut streamed_request = request.clone();
        streamed_request.stream = Some(true);

        debug!(
            provider = "anthropic",
            model = %request.model,
            url = %self.base_url,
            messages_count = request.messages.len(),
            "Sending LLM stream request"
        );

        let body = self.build_request_body(&streamed_request)?;
        let response = self
            .http
            .post(&self.base_url)
            .header("x-api-key", self.key_pool.current())
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
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
            for data in sse.push_chunk(chunk.as_ref()) {
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

pub(crate) fn resolve_anthropic_messages_url(configured_base: &str) -> String {
    let trimmed = configured_base.trim().trim_end_matches('/').to_string();
    if trimmed.is_empty() {
        return "https://api.anthropic.com/v1/messages".to_string();
    }
    if trimmed.ends_with("/v1/messages") {
        return trimmed;
    }
    format!("{trimmed}/v1/messages")
}

pub(crate) fn process_anthropic_stream_event(
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
                                    thought_signature: None,
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

#[derive(Debug, Deserialize)]
pub(crate) struct AnthropicApiError {
    error: AnthropicApiErrorDetail,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AnthropicApiErrorDetail {
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
        self.send_message_with_model(system, messages, tools, None)
            .await
    }

    async fn send_message_with_model(
        &self,
        system: &str,
        messages: Vec<Message>,
        tools: Option<Vec<ToolDefinition>>,
        model_override: Option<&str>,
    ) -> Result<MessagesResponse, MicroClawError> {
        let messages = sanitize_messages(messages);
        let model = resolve_request_model("anthropic", &self.model, model_override);

        let request = MessagesRequest {
            model,
            max_tokens: self.max_tokens,
            system: system.to_string(),
            messages,
            tools,
            stream: None,
        };

        let mut retries = 0u32;
        let max_retries = 3;
        let body = self.build_request_body(&request)?;

        loop {
            let send_result = self
                .http
                .post(&self.base_url)
                .header("x-api-key", self.key_pool.current())
                .header("anthropic-version", "2023-06-01")
                .header("content-type", "application/json")
                .json(&body)
                .send()
                .await;
            let response = match send_result {
                Ok(r) => r,
                Err(e) if is_retryable_transport_error(&e) && retries < max_retries => {
                    retries += 1;
                    let delay = retry_backoff(retries, None);
                    warn!(
                        "LLM transport error ({e}), retrying in {delay:?} (attempt {retries}/{max_retries})"
                    );
                    tokio::time::sleep(delay).await;
                    continue;
                }
                Err(e) => return Err(e.into()),
            };

            let status = response.status();

            if status.is_success() {
                let body = response.text().await?;
                let parsed: MessagesResponse = serde_json::from_str(&body).map_err(|e| {
                    MicroClawError::LlmApi(format!("Failed to parse response: {e}\nBody: {body}"))
                })?;
                return Ok(parsed);
            }

            let rotated = is_key_rotation_status(status.as_u16())
                && retries < max_retries
                && self.key_pool.advance();
            if rotated {
                warn!(
                    "Auth/rate-limit error (HTTP {status}); rotated to next API key ({} in pool)",
                    self.key_pool.len()
                );
            }
            if (is_retryable_status(status.as_u16()) || rotated) && retries < max_retries {
                retries += 1;
                let retry_after = parse_retry_after(response.headers());
                let delay = if rotated && !is_retryable_status(status.as_u16()) {
                    std::time::Duration::from_millis(200)
                } else {
                    retry_backoff(retries, retry_after)
                };
                warn!(
                    "Transient LLM error (HTTP {status}), retrying in {delay:?} (attempt {retries}/{max_retries})"
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
        self.send_message_stream_with_model(system, messages, tools, text_tx, None)
            .await
    }

    async fn send_message_stream_with_model(
        &self,
        system: &str,
        messages: Vec<Message>,
        tools: Option<Vec<ToolDefinition>>,
        text_tx: Option<&UnboundedSender<String>>,
        model_override: Option<&str>,
    ) -> Result<MessagesResponse, MicroClawError> {
        let messages = sanitize_messages(messages);
        let model = resolve_request_model("anthropic", &self.model, model_override);
        let request = MessagesRequest {
            model,
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

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use crate::llm::test_prelude::*;

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
}
