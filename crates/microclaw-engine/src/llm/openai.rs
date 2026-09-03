use super::*;

pub(crate) fn process_openai_stream_event(
    data: &str,
    text_tx: Option<&UnboundedSender<String>>,
    text: &mut String,
    reasoning_text: &mut String,
    stop_reason: &mut Option<String>,
    usage: &mut Option<Usage>,
    tool_calls: &mut std::collections::BTreeMap<usize, StreamToolUseBlock>,
) {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(data) else {
        return;
    };

    if let Some(parsed_usage) = v.get("usage").and_then(usage_from_json).or_else(|| {
        v.get("response")
            .and_then(|r| r.get("usage"))
            .and_then(usage_from_json)
    }) {
        merge_usage_max(usage, parsed_usage);
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

    if let Some(piece) = delta.get("content").and_then(extract_text_from_oai_value) {
        if !piece.is_empty() {
            text.push_str(&piece);
            if let Some(tx) = text_tx {
                let _ = tx.send(piece);
            }
        }
    }

    if let Some(piece) = delta
        .get("thought")
        .and_then(extract_text_from_oai_value)
        .or_else(|| delta.get("thinking").and_then(extract_text_from_oai_value))
    {
        if !piece.is_empty() {
            if reasoning_text.is_empty() {
                debug!("AI started generating thinking/thought");
            }
            reasoning_text.push_str(&piece);
        }
    }

    if let Some(piece) = delta
        .get("reasoning_content")
        .or_else(|| delta.get("reasoning_details"))
        .and_then(extract_text_from_oai_value)
    {
        if !piece.is_empty() {
            if reasoning_text.is_empty() {
                debug!("AI started generating reasoning_content");
            }
            reasoning_text.push_str(&piece);
        }
    }

    if let Some(tc_arr) = delta.get("tool_calls").and_then(|v| v.as_array()) {
        for tc in tc_arr {
            let index = if let Some(i) = tc.get("index").and_then(|i| i.as_u64()) {
                usize::try_from(i).ok()
            } else if let Some(id) = tc.get("id").and_then(|v| v.as_str()) {
                tool_calls
                    .iter()
                    .find(|(_, entry)| entry.id == id)
                    .map(|(idx, _)| *idx)
            } else {
                None
            };

            let index =
                index.unwrap_or_else(|| tool_calls.keys().last().map(|last| last + 1).unwrap_or(0));

            let entry = tool_calls.entry(index).or_default();
            if let Some(id) = tc.get("id").and_then(|v| v.as_str()) {
                if !id.is_empty() {
                    entry.id = id.to_string();
                }
            }
            if let Some(function) = tc.get("function") {
                if let Some(name) = function.get("name").and_then(|v| v.as_str()) {
                    if !name.is_empty() {
                        entry.name = name.to_string();
                    }
                }
                if let Some(args) = function.get("arguments") {
                    match args {
                        serde_json::Value::String(s) => {
                            if !s.is_empty() {
                                entry.input_json.push_str(s);
                            }
                        }
                        serde_json::Value::Null => {}
                        other => entry.input_json.push_str(&other.to_string()),
                    }
                }
                if let Some(sig) = function.get("thought_signature").and_then(|s| s.as_str()) {
                    entry.thought_signature = Some(sig.to_string());
                }
            }
            if let Some(sig) = tc
                .get("extra_content")
                .and_then(|e| e.get("google"))
                .and_then(|g| g.get("thought_signature"))
                .and_then(|s| s.as_str())
            {
                entry.thought_signature = Some(sig.to_string());
            }
        }
    }
}

pub struct OpenAiProvider {
    http: reqwest::Client,
    key_pool: KeyPool,
    codex_account_id: Option<String>,
    provider: String,
    model: String,
    max_tokens: u32,
    is_openai_codex: bool,
    enable_reasoning_content_bridge: bool,
    enable_thinking_param: bool,
    show_thinking: bool,
    prefer_max_completion_tokens: bool,
    openai_compat_body_overrides: HashMap<String, serde_json::Value>,
    openai_compat_body_overrides_by_provider: HashMap<String, HashMap<String, serde_json::Value>>,
    openai_compat_body_overrides_by_model: HashMap<String, HashMap<String, serde_json::Value>>,
    chat_url: String,
    responses_url: String,
}

pub(crate) fn resolve_openai_compat_base(provider: &str, configured_base: &str) -> String {
    let trimmed = configured_base.trim().trim_end_matches('/').to_string();
    if is_openai_codex_provider(provider) {
        if let Some(codex_base) = codex_config_default_openai_base_url() {
            return codex_base.trim_end_matches('/').to_string();
        }
        return "https://chatgpt.com/backend-api/codex".to_string();
    }

    if trimmed.is_empty() {
        default_base_url_for_provider(provider)
            .unwrap_or("https://api.openai.com/v1")
            .to_string()
    } else {
        trimmed
    }
}

impl OpenAiProvider {
    pub fn new(config: &Config) -> Self {
        let is_openai_codex = is_openai_codex_provider(&config.llm_provider);
        let is_deepseek_provider = config.llm_provider.eq_ignore_ascii_case("deepseek");
        let is_google_provider = config.llm_provider.eq_ignore_ascii_case("google");
        let enable_reasoning_content_bridge =
            is_google_provider || (config.show_thinking && is_deepseek_provider);
        let enable_thinking_param =
            (is_deepseek_provider || is_google_provider) && config.show_thinking;
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
        } else if is_qwen_portal_provider(&config.llm_provider) && config.api_key.trim().is_empty()
        {
            match resolve_qwen_portal_auth("") {
                Ok(auth) => (auth.bearer_token, None),
                Err(e) => {
                    warn!("{}", e);
                    (String::new(), None)
                }
            }
        } else {
            (config.api_key.clone(), None)
        };

        OpenAiProvider {
            http: reqwest::Client::builder()
                .user_agent(llm_user_agent(&config.llm_user_agent))
                .build()
                .unwrap_or_else(|e| {
                    warn!("Failed to build LLM HTTP client with user-agent: {e}");
                    reqwest::Client::new()
                }),
            key_pool: KeyPool::new(&api_key, &config.api_keys),
            codex_account_id,
            provider: config.llm_provider.clone(),
            model: config.model.clone(),
            max_tokens: config.max_tokens,
            is_openai_codex,
            enable_reasoning_content_bridge,
            enable_thinking_param,
            show_thinking: config.show_thinking,
            prefer_max_completion_tokens: config.llm_provider.eq_ignore_ascii_case("openai"),
            openai_compat_body_overrides: config.openai_compat_body_overrides.clone(),
            openai_compat_body_overrides_by_provider: config
                .openai_compat_body_overrides_by_provider
                .clone(),
            openai_compat_body_overrides_by_model: config
                .openai_compat_body_overrides_by_model
                .clone(),
            chat_url: format!("{}/chat/completions", base.trim_end_matches('/')),
            responses_url: format!("{}/responses", base.trim_end_matches('/')),
        }
    }
}

pub(crate) fn maybe_enable_thinking_param(
    body: &mut serde_json::Value,
    provider: &str,
    enabled: bool,
) {
    if !enabled {
        return;
    }
    if let Some(obj) = body.as_object_mut() {
        match provider.to_ascii_lowercase().as_str() {
            "google" => {
                obj.remove("thinking");
                obj.remove("thinking_config");
                let extra_body = obj
                    .entry("extra_body".to_string())
                    .or_insert_with(|| json!({}));
                if !extra_body.is_object() {
                    *extra_body = json!({});
                }
                if let Some(extra_obj) = extra_body.as_object_mut() {
                    let google = extra_obj
                        .entry("google".to_string())
                        .or_insert_with(|| json!({}));
                    if !google.is_object() {
                        *google = json!({});
                    }
                    if let Some(google_obj) = google.as_object_mut() {
                        google_obj.insert(
                            "thinking_config".to_string(),
                            json!({"include_thoughts": true}),
                        );
                    }
                }
            }
            "deepseek" => {
                obj.insert("thinking".to_string(), json!({"type": "enabled"}));
            }
            // Alibaba DashScope (Qwen OpenAI-compatible): enable_thinking controls mixed thinking mode.
            "alibaba" => {
                obj.insert("enable_thinking".to_string(), json!(true));
            }
            // MiniMax OpenAI-compatible: reasoning_split separates thinking into reasoning_details.
            "minimax" => {
                obj.insert("reasoning_split".to_string(), json!(true));
            }
            // OpenRouter unified reasoning config.
            "openrouter" => {
                obj.insert("reasoning".to_string(), json!({}));
            }
            _ => {
                error!(
                    provider = provider,
                    "show_thinking is enabled, but no supported thinking parameter mapping is configured for this provider"
                );
            }
        }
    }
}

pub(crate) fn apply_body_override_map(
    body: &mut serde_json::Value,
    overrides: Option<&HashMap<String, serde_json::Value>>,
) {
    let Some(overrides) = overrides else {
        return;
    };
    let Some(obj) = body.as_object_mut() else {
        return;
    };
    for (key, value) in overrides {
        if value.is_null() {
            obj.remove(key);
        } else {
            obj.insert(key.clone(), value.clone());
        }
    }
}

pub(crate) fn apply_openai_compat_body_overrides(
    body: &mut serde_json::Value,
    provider: &str,
    model: &str,
    global: &HashMap<String, serde_json::Value>,
    by_provider: &HashMap<String, HashMap<String, serde_json::Value>>,
    by_model: &HashMap<String, HashMap<String, serde_json::Value>>,
) {
    apply_body_override_map(body, Some(global));
    apply_body_override_map(body, by_provider.get(&provider.to_ascii_lowercase()));
    apply_body_override_map(body, by_model.get(model));
}

pub(crate) fn resolve_request_model(
    provider: &str,
    configured_model: &str,
    model_override: Option<&str>,
) -> String {
    resolve_model_name_with_fallback(provider, model_override, Some(configured_model))
}

pub(crate) fn has_visible_reply_runtime_guard(messages: &[Message]) -> bool {
    messages.iter().rev().any(|m| {
        if m.role != "user" {
            return false;
        }
        match &m.content {
            MessageContent::Text(t) => {
                t.contains("[runtime_guard]: Your previous reply had no user-visible text.")
            }
            MessageContent::Blocks(blocks) => blocks.iter().any(|b| match b {
                ContentBlock::Text { text } => {
                    text.contains("[runtime_guard]: Your previous reply had no user-visible text.")
                }
                _ => false,
            }),
        }
    })
}

// --- OpenAI response types ---

#[derive(Debug, Deserialize)]
pub(crate) struct OaiResponse {
    #[serde(default, deserialize_with = "deserialize_oai_choices")]
    pub(crate) choices: Vec<OaiChoice>,
    pub(crate) usage: Option<OaiUsage>,
}

pub(crate) fn deserialize_oai_choices<'de, D>(deserializer: D) -> Result<Vec<OaiChoice>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<Vec<OaiChoice>>::deserialize(deserializer)?.unwrap_or_default())
}

pub(crate) fn deserialize_optional_oai_text<'de, D>(
    deserializer: D,
) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(value.and_then(|v| extract_text_from_oai_value(&v)))
}

pub(crate) fn extract_text_from_oai_value(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::Null => None,
        serde_json::Value::String(text) => Some(text.clone()),
        serde_json::Value::Array(items) => {
            let combined = items
                .iter()
                .filter_map(extract_text_from_oai_value)
                .collect::<Vec<_>>()
                .join("");
            if combined.is_empty() {
                None
            } else {
                Some(combined)
            }
        }
        serde_json::Value::Object(map) => map
            .get("text")
            .and_then(|v| v.as_str())
            .map(|v| v.to_string())
            .or_else(|| map.get("content").and_then(extract_text_from_oai_value))
            .or_else(|| map.get("parts").and_then(extract_text_from_oai_value))
            .or_else(|| map.get("value").and_then(extract_text_from_oai_value)),
        _ => None,
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct OaiChoice {
    pub(crate) message: OaiMessage,
    pub(crate) finish_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct OaiMessage {
    #[serde(default, deserialize_with = "deserialize_optional_oai_text")]
    pub(crate) content: Option<String>,
    #[serde(
        default,
        alias = "reasoning_details",
        deserialize_with = "deserialize_optional_oai_text"
    )]
    pub(crate) reasoning_content: Option<String>,
    pub(crate) tool_calls: Option<Vec<OaiToolCall>>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct OaiToolCall {
    pub(crate) id: String,
    pub(crate) function: OaiFunction,
    #[serde(default)]
    pub(crate) extra_content: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct OaiFunction {
    pub(crate) name: String,
    pub(crate) arguments: String,
    #[serde(default)]
    pub(crate) thought_signature: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct OaiUsage {
    pub(crate) prompt_tokens: u32,
    pub(crate) completion_tokens: u32,
}

#[derive(Debug, Deserialize)]
pub(crate) struct OaiErrorResponse {
    pub(crate) error: OaiErrorDetail,
}

#[derive(Debug, Deserialize)]
pub(crate) struct OaiErrorDetail {
    pub(crate) message: String,
    #[serde(default)]
    pub(crate) code: Option<serde_json::Value>,
    #[serde(default)]
    pub(crate) r#type: Option<String>,
    #[serde(default)]
    pub(crate) metadata: Option<serde_json::Value>,
}

impl OaiErrorDetail {
    fn display(&self) -> String {
        let mut parts = Vec::new();
        if let Some(code) = &self.code {
            let code_str = match code {
                serde_json::Value::Number(n) => n.to_string(),
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            parts.push(code_str);
        }
        if let Some(t) = &self.r#type {
            if !t.is_empty() {
                parts.push(t.clone());
            }
        }
        let prefix = if parts.is_empty() {
            String::new()
        } else {
            format!("{}: ", parts.join(" "))
        };
        // OpenRouter includes upstream error details in metadata.raw
        let raw_detail = self
            .metadata
            .as_ref()
            .and_then(|m| m.get("raw"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if raw_detail.is_empty() {
            format!("{prefix}{}", self.message)
        } else {
            format!("{prefix}{} — {raw_detail}", self.message)
        }
    }
}

pub(crate) fn should_retry_with_max_completion_tokens(error_text: &str) -> bool {
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(error_text) {
        let param_is_max_tokens = value
            .get("error")
            .and_then(|e| e.get("param"))
            .and_then(|p| p.as_str())
            .map(|p| p == "max_tokens")
            .unwrap_or(false);
        if param_is_max_tokens {
            return true;
        }
    }

    let lower = error_text.to_ascii_lowercase();
    lower.contains("max_tokens") && lower.contains("max_completion_tokens")
}

pub(crate) fn should_retry_without_stream_options(error_text: &str) -> bool {
    let lower = error_text.to_ascii_lowercase();
    (lower.contains("stream_options") || lower.contains("include_usage"))
        && (lower.contains("unsupported")
            || lower.contains("unknown")
            || lower.contains("invalid")
            || lower.contains("not supported")
            || lower.contains("unrecognized"))
}

pub(crate) fn switch_to_max_completion_tokens(body: &mut serde_json::Value) -> bool {
    if body.get("max_completion_tokens").is_some() {
        return false;
    }
    let Some(max_tokens) = body.get("max_tokens").cloned() else {
        return false;
    };
    if let Some(obj) = body.as_object_mut() {
        obj.remove("max_tokens");
        obj.insert("max_completion_tokens".to_string(), max_tokens);
        return true;
    }
    false
}

pub(crate) fn set_output_token_limit(
    body: &mut serde_json::Value,
    max_tokens: u32,
    prefer_max_completion_tokens: bool,
) {
    if let Some(obj) = body.as_object_mut() {
        obj.remove("max_tokens");
        obj.remove("max_completion_tokens");
        let key = if prefer_max_completion_tokens {
            "max_completion_tokens"
        } else {
            "max_tokens"
        };
        obj.insert(key.to_string(), json!(max_tokens));
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct OaiResponsesResponse {
    pub(crate) output: Vec<OaiResponsesOutputItem>,
    pub(crate) usage: Option<OaiResponsesUsage>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct OaiResponsesUsage {
    pub(crate) input_tokens: u32,
    pub(crate) output_tokens: u32,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub(crate) enum OaiResponsesOutputItem {
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
pub(crate) enum OaiResponsesOutputContentPart {
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
        let model = resolve_request_model(&self.provider, &self.model, model_override);
        if self.is_openai_codex {
            return self
                .send_codex_message(system, messages, tools, &model)
                .await;
        }

        let sanitized = sanitize_messages(messages);
        let oai_messages = if self.enable_reasoning_content_bridge {
            translate_messages_to_oai_with_reasoning(system, &sanitized, true)
        } else {
            translate_messages_to_oai(system, &sanitized)
        };

        let mut body = json!({
            "model": model,
            "messages": oai_messages,
        });
        set_output_token_limit(
            &mut body,
            self.max_tokens,
            self.prefer_max_completion_tokens,
        );
        let thinking_enabled =
            self.enable_thinking_param && !has_visible_reply_runtime_guard(&sanitized);
        maybe_enable_thinking_param(&mut body, &self.provider, thinking_enabled);
        apply_openai_compat_body_overrides(
            &mut body,
            &self.provider,
            &self.model,
            &self.openai_compat_body_overrides,
            &self.openai_compat_body_overrides_by_provider,
            &self.openai_compat_body_overrides_by_model,
        );
        if let Some(obj) = body.as_object_mut() {
            obj.remove("stream");
        }

        if let Some(ref tool_defs) = tools {
            if !tool_defs.is_empty() {
                body["tools"] = json!(translate_tools_to_oai(tool_defs));
            }
        }

        let mut retries = 0u32;
        let max_retries = 3;

        debug!(
            provider = %self.provider,
            model = %model,
            url = %self.chat_url,
            has_api_key = !self.key_pool.current().trim().is_empty(),
            "Sending LLM request"
        );

        loop {
            let mut req = self
                .http
                .post(&self.chat_url)
                .header("Content-Type", "application/json")
                .json(&body);
            let api_key = self.key_pool.current();
            if !api_key.trim().is_empty() {
                req = req.header("Authorization", format!("Bearer {api_key}"));
            }
            let response = match req.send().await {
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
                let text = response.text().await?;
                let oai: OaiResponse = serde_json::from_str(&text).map_err(|e| {
                    MicroClawError::LlmApi(format!(
                        "Failed to parse OpenAI response: {e}\nBody: {text}"
                    ))
                })?;
                return Ok(translate_oai_response_with_display_reasoning(
                    oai,
                    self.show_thinking,
                ));
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

            let text = response.text().await.unwrap_or_default();
            if should_retry_with_max_completion_tokens(&text)
                && switch_to_max_completion_tokens(&mut body)
            {
                warn!(
                    "OpenAI-compatible API rejected max_tokens; retrying with max_completion_tokens"
                );
                continue;
            }
            if let Ok(err) = serde_json::from_str::<OaiErrorResponse>(&text) {
                return Err(MicroClawError::LlmApi(format!(
                    "{} (url={})",
                    err.error.display(),
                    self.chat_url
                )));
            }
            return Err(MicroClawError::LlmApi(format!(
                "HTTP {status} {}: {text}",
                self.chat_url
            )));
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
        let model = resolve_request_model(&self.provider, &self.model, model_override);
        if self.is_openai_codex {
            let response = self
                .send_codex_message(system, messages, tools, &model)
                .await?;
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

        let sanitized = sanitize_messages(messages);
        let oai_messages = if self.enable_reasoning_content_bridge {
            translate_messages_to_oai_with_reasoning(system, &sanitized, true)
        } else {
            translate_messages_to_oai(system, &sanitized)
        };

        let mut body = json!({
            "model": model,
            "messages": oai_messages,
            "stream": true,
        });
        set_output_token_limit(
            &mut body,
            self.max_tokens,
            self.prefer_max_completion_tokens,
        );
        let thinking_enabled =
            self.enable_thinking_param && !has_visible_reply_runtime_guard(&sanitized);
        maybe_enable_thinking_param(&mut body, &self.provider, thinking_enabled);
        apply_openai_compat_body_overrides(
            &mut body,
            &self.provider,
            &self.model,
            &self.openai_compat_body_overrides,
            &self.openai_compat_body_overrides_by_provider,
            &self.openai_compat_body_overrides_by_model,
        );
        body["stream"] = json!(true);
        if body.get("stream_options").is_none() {
            body["stream_options"] = json!({
                "include_usage": true
            });
        } else if let Some(obj) = body
            .get_mut("stream_options")
            .and_then(|v| v.as_object_mut())
        {
            obj.entry("include_usage".to_string())
                .or_insert_with(|| json!(true));
        }

        if let Some(ref tool_defs) = tools {
            if !tool_defs.is_empty() {
                body["tools"] = json!(translate_tools_to_oai(tool_defs));
            }
        }

        debug!(
            provider = %self.provider,
            model = %model,
            url = %self.chat_url,
            messages_count = sanitized.len(),
            "Sending LLM stream request"
        );

        let response = loop {
            let mut req = self
                .http
                .post(&self.chat_url)
                .header("Content-Type", "application/json")
                .json(&body);
            let api_key = self.key_pool.current();
            if !api_key.trim().is_empty() {
                req = req.header("Authorization", format!("Bearer {api_key}"));
            }
            let response = req.send().await?;
            let status = response.status();
            if status.is_success() {
                break response;
            }

            let text = response.text().await.unwrap_or_default();
            if should_retry_with_max_completion_tokens(&text)
                && switch_to_max_completion_tokens(&mut body)
            {
                warn!(
                    "OpenAI-compatible API rejected max_tokens; retrying stream with max_completion_tokens"
                );
                continue;
            }
            if body.get("stream_options").is_some() && should_retry_without_stream_options(&text) {
                if let Some(obj) = body.as_object_mut() {
                    obj.remove("stream_options");
                }
                warn!(
                    "OpenAI-compatible API rejected stream_options/include_usage; retrying stream without stream_options"
                );
                continue;
            }
            if let Ok(err) = serde_json::from_str::<OaiErrorResponse>(&text) {
                return Err(MicroClawError::LlmApi(format!(
                    "{} (url={})",
                    err.error.display(),
                    self.chat_url
                )));
            }
            return Err(MicroClawError::LlmApi(format!(
                "HTTP {status} {}: {text}",
                self.chat_url
            )));
        };

        let mut byte_stream = response.bytes_stream();
        let mut sse = SseEventParser::default();
        let mut text = String::new();
        let mut reasoning_text = String::new();
        let mut stop_reason: Option<String> = None;
        let mut usage: Option<Usage> = None;
        let mut tool_calls: std::collections::BTreeMap<usize, StreamToolUseBlock> =
            std::collections::BTreeMap::new();

        'outer: while let Some(chunk_res) = byte_stream.next().await {
            let chunk = match chunk_res {
                Ok(c) => c,
                Err(_) => break,
            };
            for data in sse.push_chunk(chunk.as_ref()) {
                if data == "[DONE]" {
                    break 'outer;
                }
                process_openai_stream_event(
                    &data,
                    text_tx,
                    &mut text,
                    &mut reasoning_text,
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
                &mut reasoning_text,
                &mut stop_reason,
                &mut usage,
                &mut tool_calls,
            );
        }

        let mut content = Vec::new();
        let mut visible_text =
            combine_response_text_for_display(&text, &reasoning_text, self.show_thinking);
        let mut raw_text_tool_calls = None;
        if let Some(parsed_raw_calls) = extract_raw_tool_use_blocks(&visible_text) {
            if tool_calls.is_empty() {
                raw_text_tool_calls = Some(parsed_raw_calls);
            }
            visible_text.clear();
        }
        if !visible_text.is_empty() {
            content.push(ResponseContentBlock::Text { text: visible_text });
        }
        for tool in tool_calls.values() {
            content.push(ResponseContentBlock::ToolUse {
                id: sanitize_tool_id(&tool.id),
                name: tool.name.clone(),
                input: parse_tool_input(&tool.input_json),
                thought_signature: tool.thought_signature.clone(),
            });
        }
        if let Some(parsed_raw_calls) = raw_text_tool_calls {
            for tool in parsed_raw_calls {
                content.push(ResponseContentBlock::ToolUse {
                    id: sanitize_tool_id(&tool.id),
                    name: tool.name,
                    input: parse_tool_input(&tool.input_json),
                    thought_signature: tool.thought_signature,
                });
            }
        }
        if content.is_empty() {
            content.push(ResponseContentBlock::Text {
                text: String::new(),
            });
        }

        let mut normalized_stop_reason = normalize_stop_reason(stop_reason);
        if !tool_calls.is_empty() {
            normalized_stop_reason = Some("tool_use".to_string());
        }

        Ok(MessagesResponse {
            content,
            stop_reason: normalized_stop_reason,
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
        model: &str,
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
            "model": model,
            "input": input,
            "instructions": instructions,
            "store": false,
            "stream": true,
        });
        apply_openai_compat_body_overrides(
            &mut body,
            &self.provider,
            &self.model,
            &self.openai_compat_body_overrides,
            &self.openai_compat_body_overrides_by_provider,
            &self.openai_compat_body_overrides_by_model,
        );
        body["stream"] = json!(true);
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
            let api_key = self.key_pool.current();
            if !api_key.trim().is_empty() {
                req = req.header("Authorization", format!("Bearer {api_key}"));
            }
            if let Some(account_id) = self.codex_account_id.as_deref() {
                if !account_id.trim().is_empty() {
                    req = req.header("ChatGPT-Account-ID", account_id);
                }
            }
            let response = match req.send().await {
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
                let text = response.text().await?;
                let parsed = parse_openai_codex_response_payload(&text)?;
                return Ok(translate_oai_responses_response(parsed));
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

            let text = response.text().await.unwrap_or_default();
            if let Ok(err) = serde_json::from_str::<OaiErrorResponse>(&text) {
                return Err(MicroClawError::LlmApi(err.error.display()));
            }
            return Err(MicroClawError::LlmApi(format!("HTTP {status}: {text}")));
        }
    }
}

pub(crate) fn parse_openai_codex_response_payload(
    text: &str,
) -> Result<OaiResponsesResponse, MicroClawError> {
    if let Ok(parsed) = serde_json::from_str::<OaiResponsesResponse>(text) {
        return Ok(parsed);
    }

    let mut from_done_event: Option<OaiResponsesResponse> = None;
    let mut streamed_output_text = String::new();
    let mut streamed_function_calls = Vec::new();
    let mut pending_event_type: Option<&str> = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(event_type) = line.strip_prefix("event:") {
            pending_event_type = Some(event_type.trim());
            continue;
        }
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
        let event_type = value
            .get("type")
            .and_then(|value| value.as_str())
            .or(pending_event_type);

        match event_type {
            Some("response.output_text.delta") => {
                if let Some(delta) = value.get("delta").and_then(|value| value.as_str()) {
                    streamed_output_text.push_str(delta);
                }
            }
            Some("response.output_text.done") if streamed_output_text.is_empty() => {
                if let Some(done) = value.get("text").and_then(|value| value.as_str()) {
                    streamed_output_text.push_str(done);
                }
            }
            Some("response.output_item.done") => {
                if let Some(item) = value.get("item") {
                    if let Ok(OaiResponsesOutputItem::FunctionCall {
                        id,
                        call_id,
                        name,
                        arguments,
                    }) = serde_json::from_value::<OaiResponsesOutputItem>(item.clone())
                    {
                        streamed_function_calls.push(OaiResponsesOutputItem::FunctionCall {
                            id,
                            call_id,
                            name,
                            arguments,
                        });
                    }
                }
            }
            _ => {}
        }

        if let Some(response_value) = value.get("response") {
            if let Ok(parsed) =
                serde_json::from_value::<OaiResponsesResponse>(response_value.clone())
            {
                from_done_event = Some(parsed);
                if matches!(event_type, Some("response.done" | "response.completed")) {
                    break;
                }
            }
        }
        pending_event_type = None;
    }

    if let Some(mut parsed) = from_done_event {
        if !streamed_function_calls.is_empty()
            && !parsed
                .output
                .iter()
                .any(|item| matches!(item, OaiResponsesOutputItem::FunctionCall { .. }))
        {
            parsed.output.append(&mut streamed_function_calls);
        }
        if !streamed_output_text.is_empty()
            && !parsed.output.iter().any(|item| match item {
                OaiResponsesOutputItem::Message { content } => content.iter().any(|part| {
                    matches!(part, OaiResponsesOutputContentPart::OutputText { text } if !text.is_empty())
                }),
                _ => false,
            })
        {
            parsed.output.push(OaiResponsesOutputItem::Message {
                content: vec![OaiResponsesOutputContentPart::OutputText {
                    text: streamed_output_text,
                }],
            });
        }
        return Ok(parsed);
    }

    if !streamed_output_text.is_empty() || !streamed_function_calls.is_empty() {
        let mut output = streamed_function_calls;
        if !streamed_output_text.is_empty() {
            output.push(OaiResponsesOutputItem::Message {
                content: vec![OaiResponsesOutputContentPart::OutputText {
                    text: streamed_output_text,
                }],
            });
        }
        return Ok(OaiResponsesResponse {
            output,
            usage: None,
        });
    }

    Err(MicroClawError::LlmApi(format!(
        "Failed to parse OpenAI Codex response payload. Body: {text}"
    )))
}

// ---------------------------------------------------------------------------
// Format translation helpers  (internal Anthropic-style ↔ OpenAI)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use crate::llm::test_prelude::*;

    #[test]
    fn test_translate_oai_response_tool_calls_legacy_function_thought_signature() {
        let raw = r#"{"choices":[{"message":{"content":null,"reasoning_content":null,"tool_calls":[{"id":"call_1","function":{"name":"bash","arguments":"{\"command\":\"ls\"}","thought_signature":"sig_legacy"}}]},"finish_reason":"tool_calls"}],"usage":null}"#;
        let oai: OaiResponse = serde_json::from_str(raw).unwrap();
        let resp = translate_oai_response(oai);
        match &resp.content[0] {
            ResponseContentBlock::ToolUse {
                thought_signature, ..
            } => assert_eq!(thought_signature.as_deref(), Some("sig_legacy")),
            _ => panic!("Expected ToolUse"),
        }
    }

    #[test]
    fn test_translate_oai_response_text() {
        let oai = OaiResponse {
            choices: vec![OaiChoice {
                message: OaiMessage {
                    content: Some("Hello!".into()),
                    reasoning_content: None,
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
                    reasoning_content: None,
                    tool_calls: Some(vec![OaiToolCall {
                        id: "call_1".into(),
                        function: OaiFunction {
                            name: "bash".into(),
                            arguments: r#"{"command":"ls"}"#.into(),
                            thought_signature: None,
                        },
                        extra_content: None,
                    }]),
                },
                finish_reason: Some("tool_calls".into()),
            }],
            usage: None,
        };
        let resp = translate_oai_response(oai);
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
                assert!(thought_signature.is_none());
            }
            _ => panic!("Expected ToolUse"),
        }
    }

    #[test]
    fn test_translate_oai_response_tool_calls_without_calls_downgrades_to_end_turn() {
        let oai = OaiResponse {
            choices: vec![OaiChoice {
                message: OaiMessage {
                    content: None,
                    reasoning_content: None,
                    tool_calls: None,
                },
                finish_reason: Some("tool_calls".into()),
            }],
            usage: None,
        };

        let resp = translate_oai_response(oai);
        assert_eq!(resp.stop_reason.as_deref(), Some("end_turn"));
        assert!(!resp
            .content
            .iter()
            .any(|b| matches!(b, ResponseContentBlock::ToolUse { .. })));
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
    fn test_deserialize_oai_response_null_choices() {
        let raw = r#"{"id":"x","choices":null,"usage":null}"#;
        let parsed: OaiResponse = serde_json::from_str(raw).unwrap();
        assert!(parsed.choices.is_empty());
    }

    #[test]
    fn test_translate_oai_response_length_stop() {
        let oai = OaiResponse {
            choices: vec![OaiChoice {
                message: OaiMessage {
                    content: Some("partial".into()),
                    reasoning_content: None,
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
                    reasoning_content: None,
                    tool_calls: Some(vec![OaiToolCall {
                        id: "c1".into(),
                        function: OaiFunction {
                            name: "read_file".into(),
                            arguments: r#"{"path":"/tmp/x"}"#.into(),
                            thought_signature: None,
                        },
                        extra_content: None,
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
    fn test_translate_oai_response_reasoning_content_and_tool_calls() {
        let oai = OaiResponse {
            choices: vec![OaiChoice {
                message: OaiMessage {
                    content: None,
                    reasoning_content: Some("plan".into()),
                    tool_calls: Some(vec![OaiToolCall {
                        id: "c1".into(),
                        function: OaiFunction {
                            name: "bash".into(),
                            arguments: r#"{"command":"ls"}"#.into(),
                            thought_signature: None,
                        },
                        extra_content: None,
                    }]),
                },
                finish_reason: Some("tool_calls".into()),
            }],
            usage: None,
        };
        let resp = translate_oai_response(oai);
        assert_eq!(resp.content.len(), 2);
        match &resp.content[0] {
            ResponseContentBlock::Text { text } => {
                assert_eq!(text, "<thought>\nplan\n</thought>")
            }
            _ => panic!("Expected Text"),
        }
        match &resp.content[1] {
            ResponseContentBlock::ToolUse { name, .. } => assert_eq!(name, "bash"),
            _ => panic!("Expected ToolUse"),
        }
    }

    #[test]
    fn test_translate_oai_response_accepts_structured_content_arrays() {
        let raw = r#"{"choices":[{"message":{"content":[{"type":"text","text":"Hello "},{"type":"text","text":"Gemini"}],"reasoning_content":[{"type":"text","text":"plan "},{"type":"text","text":"steps"}],"tool_calls":null},"finish_reason":"stop"}],"usage":null}"#;
        let oai: OaiResponse = serde_json::from_str(raw).unwrap();
        let resp = translate_oai_response(oai);
        match &resp.content[0] {
            ResponseContentBlock::Text { text } => {
                assert_eq!(text, "<thought>\nplan steps\n</thought>\n\nHello Gemini")
            }
            _ => panic!("Expected Text"),
        }
    }

    #[test]
    fn test_translate_oai_response_reasoning_only() {
        let oai = OaiResponse {
            choices: vec![OaiChoice {
                message: OaiMessage {
                    content: None,
                    reasoning_content: Some("internal".into()),
                    tool_calls: None,
                },
                finish_reason: Some("stop".into()),
            }],
            usage: None,
        };
        let resp = translate_oai_response(oai);
        match &resp.content[0] {
            ResponseContentBlock::Text { text } => {
                assert_eq!(text, "<thought>\ninternal\n</thought>")
            }
            _ => panic!("Expected Text"),
        }
    }

    #[test]
    fn test_translate_oai_response_omits_reasoning_when_disabled() {
        let oai = OaiResponse {
            choices: vec![OaiChoice {
                message: OaiMessage {
                    content: Some("Visible".into()),
                    reasoning_content: Some("internal".into()),
                    tool_calls: None,
                },
                finish_reason: Some("stop".into()),
            }],
            usage: None,
        };
        let resp = translate_oai_response_with_display_reasoning(oai, false);
        match &resp.content[0] {
            ResponseContentBlock::Text { text } => assert_eq!(text, "Visible"),
            _ => panic!("Expected Text"),
        }
    }

    #[test]
    fn test_process_openai_stream_event_collects_reasoning_content() {
        let data = r#"{"choices":[{"delta":{"reasoning_content":"think","tool_calls":[{"index":0,"id":"c1","function":{"name":"bash","arguments":"{\"command\":\"ls\"}","thought_signature":"sig_123"}}]},"finish_reason":null}],"usage":null}"#;
        let mut text = String::new();
        let mut reasoning_text = String::new();
        let mut stop_reason = None;
        let mut usage = None;
        let mut tool_calls = std::collections::BTreeMap::new();

        process_openai_stream_event(
            data,
            None,
            &mut text,
            &mut reasoning_text,
            &mut stop_reason,
            &mut usage,
            &mut tool_calls,
        );

        assert!(text.is_empty());
        assert_eq!(reasoning_text, "think");
        assert_eq!(stop_reason, None);
        let call = tool_calls.get(&0).unwrap();
        assert_eq!(call.id, "c1");
        assert_eq!(call.name, "bash");
        assert_eq!(call.input_json, r#"{"command":"ls"}"#);
        assert_eq!(call.thought_signature.as_deref(), Some("sig_123"));
    }

    #[test]
    fn test_process_openai_stream_event_collects_reasoning_details_alias() {
        let data = r#"{"choices":[{"delta":{"reasoning_details":"step-by-step"}}],"usage":null}"#;
        let mut text = String::new();
        let mut reasoning_text = String::new();
        let mut stop_reason = None;
        let mut usage = None;
        let mut tool_calls = std::collections::BTreeMap::new();

        process_openai_stream_event(
            data,
            None,
            &mut text,
            &mut reasoning_text,
            &mut stop_reason,
            &mut usage,
            &mut tool_calls,
        );

        assert!(text.is_empty());
        assert_eq!(reasoning_text, "step-by-step");
        assert!(tool_calls.is_empty());
    }

    #[test]
    fn test_process_openai_stream_event_accepts_structured_delta_content() {
        let data = r#"{"choices":[{"delta":{"content":[{"type":"text","text":"Hello "},{"type":"text","text":"Gemini"}],"reasoning_content":[{"type":"text","text":"plan"},{"type":"text","text":" more"}]}}],"usage":null}"#;
        let mut text = String::new();
        let mut reasoning_text = String::new();
        let mut stop_reason = None;
        let mut usage = None;
        let mut tool_calls = std::collections::BTreeMap::new();

        process_openai_stream_event(
            data,
            None,
            &mut text,
            &mut reasoning_text,
            &mut stop_reason,
            &mut usage,
            &mut tool_calls,
        );

        assert_eq!(text, "Hello Gemini");
        assert_eq!(reasoning_text, "plan more");
        assert_eq!(stop_reason, None);
        assert!(usage.is_none());
        assert!(tool_calls.is_empty());
    }

    #[test]
    fn test_process_openai_stream_event_collects_thinking_aliases() {
        let data = r#"{"choices":[{"delta":{"thought":"alpha","thinking":"beta"}}]}"#;
        let mut text = String::new();
        let mut reasoning_text = String::new();
        let mut stop_reason = None;
        let mut usage = None;
        let mut tool_calls = std::collections::BTreeMap::new();

        process_openai_stream_event(
            data,
            None,
            &mut text,
            &mut reasoning_text,
            &mut stop_reason,
            &mut usage,
            &mut tool_calls,
        );

        assert!(text.is_empty());
        assert_eq!(reasoning_text, "alpha");
        assert_eq!(stop_reason, None);
        assert!(usage.is_none());
        assert!(tool_calls.is_empty());
    }

    #[test]
    fn test_process_openai_stream_event_tool_calls_without_index_and_object_args() {
        let data = r#"{"choices":[{"delta":{"tool_calls":[{"id":"call_1","function":{"name":"weather","arguments":{"location":"Shanghai"}}}]}}]}"#;
        let mut text = String::new();
        let mut reasoning_text = String::new();
        let mut stop_reason = None;
        let mut usage = None;
        let mut tool_calls = std::collections::BTreeMap::new();

        process_openai_stream_event(
            data,
            None,
            &mut text,
            &mut reasoning_text,
            &mut stop_reason,
            &mut usage,
            &mut tool_calls,
        );

        assert!(text.is_empty());
        assert!(reasoning_text.is_empty());
        assert_eq!(stop_reason, None);
        let call = tool_calls.get(&0).unwrap();
        assert_eq!(call.id, "call_1");
        assert_eq!(call.name, "weather");
        assert_eq!(call.input_json, r#"{"location":"Shanghai"}"#);
    }

    #[test]
    fn test_process_openai_stream_event_ignores_minimax_malformed_trailing_tool_chunks() {
        let first = r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_ok","type":"function","function":{"name":"get_oil_price","arguments":""}}]}}]}"#;
        let second = r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"","type":"function","function":{"name":"","arguments":"{"}}]}}]}"#;
        let third = r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"","type":"function","function":{"name":"","arguments":"}"}}]}}]}"#;
        let fourth = r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"","type":"function","function":{"arguments":null}}]}}]}"#;
        let mut text = String::new();
        let mut reasoning_text = String::new();
        let mut stop_reason = None;
        let mut usage = None;
        let mut tool_calls = std::collections::BTreeMap::new();

        for data in [first, second, third, fourth] {
            process_openai_stream_event(
                data,
                None,
                &mut text,
                &mut reasoning_text,
                &mut stop_reason,
                &mut usage,
                &mut tool_calls,
            );
        }

        let call = tool_calls.get(&0).unwrap();
        assert_eq!(call.id, "call_ok");
        assert_eq!(call.name, "get_oil_price");
        assert_eq!(call.input_json, "{}");
    }

    #[test]
    fn test_process_openai_stream_event_ignores_qwen_malformed_trailing_tool_chunks() {
        let first = r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_ok","type":"function","function":{"name":"get_oil_price","arguments":""}}]}}]}"#;
        let second = r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"","type":"function","function":{"arguments":"{}"}}]}}]}"#;
        let third = r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"","type":"function","function":{"arguments":""}}]}}]}"#;
        let mut text = String::new();
        let mut reasoning_text = String::new();
        let mut stop_reason = None;
        let mut usage = None;
        let mut tool_calls = std::collections::BTreeMap::new();

        for data in [first, second, third] {
            process_openai_stream_event(
                data,
                None,
                &mut text,
                &mut reasoning_text,
                &mut stop_reason,
                &mut usage,
                &mut tool_calls,
            );
        }

        let call = tool_calls.get(&0).unwrap();
        assert_eq!(call.id, "call_ok");
        assert_eq!(call.name, "get_oil_price");
        assert_eq!(call.input_json, "{}");
    }

    #[test]
    fn test_process_openai_stream_event_updates_usage_with_max_values() {
        let first = r#"{"choices":[{"delta":{"content":"a"}}],"usage":{"prompt_tokens":10,"completion_tokens":0}}"#;
        let second = r#"{"choices":[{"delta":{"content":"b"}}],"usage":{"prompt_tokens":10,"completion_tokens":7}}"#;
        let mut text = String::new();
        let mut reasoning_text = String::new();
        let mut stop_reason = None;
        let mut usage = None;
        let mut tool_calls = std::collections::BTreeMap::new();

        process_openai_stream_event(
            first,
            None,
            &mut text,
            &mut reasoning_text,
            &mut stop_reason,
            &mut usage,
            &mut tool_calls,
        );
        process_openai_stream_event(
            second,
            None,
            &mut text,
            &mut reasoning_text,
            &mut stop_reason,
            &mut usage,
            &mut tool_calls,
        );

        let usage = usage.expect("usage should exist");
        assert_eq!(usage.input_tokens, 10);
        assert_eq!(usage.output_tokens, 7);
    }

    #[test]
    fn test_process_openai_stream_event_parses_response_done_usage() {
        let data = r#"{"type":"response.done","response":{"usage":{"input_tokens":11,"output_tokens":5}}}"#;
        let mut text = String::new();
        let mut reasoning_text = String::new();
        let mut stop_reason = None;
        let mut usage = None;
        let mut tool_calls = std::collections::BTreeMap::new();

        process_openai_stream_event(
            data,
            None,
            &mut text,
            &mut reasoning_text,
            &mut stop_reason,
            &mut usage,
            &mut tool_calls,
        );

        let usage = usage.expect("usage should exist");
        assert_eq!(usage.input_tokens, 11);
        assert_eq!(usage.output_tokens, 5);
    }

    #[test]
    fn test_should_retry_with_max_completion_tokens() {
        let err = r#"{"error":{"message":"Unsupported parameter: 'max_tokens' is not supported with this model. Use 'max_completion_tokens' instead.","param":"max_tokens"}}"#;
        assert!(should_retry_with_max_completion_tokens(err));
        assert!(!should_retry_with_max_completion_tokens(
            r#"{"error":{"message":"bad request","param":"messages"}}"#
        ));
    }

    #[test]
    fn test_switch_to_max_completion_tokens() {
        let mut body = json!({"model":"gpt-5.2","max_tokens":128});
        assert!(switch_to_max_completion_tokens(&mut body));
        assert_eq!(body.get("max_tokens"), None);
        assert_eq!(body["max_completion_tokens"], 128);
        assert!(!switch_to_max_completion_tokens(&mut body));
    }

    #[test]
    fn test_maybe_enable_thinking_param_enabled() {
        let mut body = json!({"model":"test-model","messages":[]});
        maybe_enable_thinking_param(&mut body, "deepseek", true);
        assert_eq!(body["thinking"]["type"], "enabled");
        assert!(body.get("thinking_config").is_none());
    }

    #[test]
    fn test_maybe_enable_thinking_param_disabled() {
        let mut body = json!({"model":"test-model","messages":[]});
        maybe_enable_thinking_param(&mut body, "deepseek", false);
        assert!(body.get("thinking").is_none());
        assert!(body.get("thinking_config").is_none());
    }

    #[test]
    fn test_maybe_enable_thinking_param_google_uses_thinking_config() {
        let mut body = json!({"model":"gemini-2.5-flash","messages":[]});
        maybe_enable_thinking_param(&mut body, "google", true);
        assert!(body.get("thinking").is_none());
        assert!(body.get("thinking_config").is_none());
        assert_eq!(
            body["extra_body"]["google"]["thinking_config"]["include_thoughts"],
            true
        );
    }

    #[test]
    fn test_maybe_enable_thinking_param_unknown_provider_does_not_set_fields() {
        let mut body = json!({"model":"unknown","messages":[]});
        maybe_enable_thinking_param(&mut body, "openrouter", true);
        assert!(body.get("reasoning").is_some());
    }

    #[test]
    fn test_maybe_enable_thinking_param_alibaba_uses_enable_thinking() {
        let mut body = json!({"model":"qwen-plus","messages":[]});
        maybe_enable_thinking_param(&mut body, "alibaba", true);
        assert_eq!(body["enable_thinking"], true);
        assert!(body.get("thinking").is_none());
    }

    #[test]
    fn test_maybe_enable_thinking_param_minimax_uses_reasoning_split() {
        let mut body = json!({"model":"MiniMax-M2.5","messages":[]});
        maybe_enable_thinking_param(&mut body, "minimax", true);
        assert_eq!(body["reasoning_split"], true);
    }

    #[test]
    fn test_maybe_enable_thinking_param_unsupported_provider_does_not_set_fields() {
        let mut body = json!({"model":"unknown","messages":[]});
        maybe_enable_thinking_param(&mut body, "qwen-portal", true);
        assert!(body.get("thinking").is_none());
        assert!(body.get("thinking_config").is_none());
        assert!(body.get("enable_thinking").is_none());
        assert!(body.get("reasoning_split").is_none());
        assert!(body.get("reasoning").is_none());
    }

    #[test]
    fn test_has_visible_reply_runtime_guard_detects_guard_message() {
        let msgs = vec![Message {
            role: "user".into(),
            content: MessageContent::Text(
                "[runtime_guard]: Your previous reply had no user-visible text. Reply again now."
                    .into(),
            ),
        }];
        assert!(has_visible_reply_runtime_guard(&msgs));
    }

    #[test]
    fn test_apply_openai_compat_body_overrides_merges_global_provider_model() {
        let mut body = json!({
            "model": "gpt-5.2",
            "temperature": 0.5,
            "top_p": 0.9,
            "stream": false
        });
        let mut global = HashMap::new();
        global.insert("temperature".into(), json!(0.2));
        global.insert("seed".into(), json!(42));
        let mut by_provider = HashMap::new();
        by_provider.insert(
            "openai".into(),
            HashMap::from([("top_p".into(), json!(0.8))]),
        );
        let mut by_model = HashMap::new();
        by_model.insert(
            "gpt-5.2".into(),
            HashMap::from([("stream".into(), json!(true))]),
        );

        apply_openai_compat_body_overrides(
            &mut body,
            "openai",
            "gpt-5.2",
            &global,
            &by_provider,
            &by_model,
        );

        assert_eq!(body["temperature"], 0.2);
        assert_eq!(body["top_p"], 0.8);
        assert_eq!(body["seed"], 42);
        assert_eq!(body["stream"], true);
    }

    #[test]
    fn test_apply_openai_compat_body_overrides_null_unsets_key() {
        let mut body = json!({"temperature": 0.7, "top_p": 0.9});
        let mut by_provider = HashMap::new();
        by_provider.insert(
            "deepseek".into(),
            HashMap::from([("top_p".into(), serde_json::Value::Null)]),
        );

        apply_openai_compat_body_overrides(
            &mut body,
            "deepseek",
            "deepseek-chat",
            &HashMap::new(),
            &by_provider,
            &HashMap::new(),
        );

        assert!(body.get("top_p").is_none());
        assert_eq!(body["temperature"], 0.7);
    }

    #[test]
    fn test_openai_provider_capability_flags_for_deepseek() {
        let mut config = Config::test_defaults();
        config.llm_provider = "deepseek".into();
        config.model = "test-model".into();
        config.show_thinking = true;
        config.data_dir = "/tmp".into();
        config.working_dir = "/tmp".into();
        config.working_dir_isolation = WorkingDirIsolation::Shared;
        config.web_enabled = false;
        config.web_port = 3900;

        let provider = OpenAiProvider::new(&config);
        assert!(provider.enable_thinking_param);
        assert!(provider.enable_reasoning_content_bridge);
    }

    #[test]
    fn test_openai_provider_capability_flags_for_google() {
        let mut config = Config::test_defaults();
        config.llm_provider = "google".into();
        config.model = "gemini-3-flash-preview".into();
        config.show_thinking = true;
        config.data_dir = "/tmp".into();
        config.working_dir = "/tmp".into();
        config.working_dir_isolation = WorkingDirIsolation::Shared;
        config.web_enabled = false;
        config.web_port = 3900;

        let provider = OpenAiProvider::new(&config);
        assert!(provider.enable_thinking_param);
        assert!(provider.enable_reasoning_content_bridge);
    }

    #[test]
    fn test_openai_provider_disables_google_thinking_param_when_show_thinking_is_false() {
        let mut config = Config::test_defaults();
        config.llm_provider = "google".into();
        config.model = "gemini-3-flash-preview".into();
        config.show_thinking = false;
        config.data_dir = "/tmp".into();
        config.working_dir = "/tmp".into();
        config.working_dir_isolation = WorkingDirIsolation::Shared;
        config.web_enabled = false;
        config.web_port = 3900;

        let provider = OpenAiProvider::new(&config);
        assert!(!provider.enable_thinking_param);
        assert!(!provider.show_thinking);
        assert!(provider.enable_reasoning_content_bridge);
    }

    #[test]
    fn test_set_output_token_limit_prefers_max_completion_tokens() {
        let mut body = json!({"model":"gpt-5.2","messages":[],"max_tokens":1});
        set_output_token_limit(&mut body, 256, true);
        assert_eq!(body.get("max_tokens"), None);
        assert_eq!(body["max_completion_tokens"], 256);
    }

    #[test]
    fn test_set_output_token_limit_uses_max_tokens_for_compat() {
        let mut body = json!({"model":"qwen","messages":[],"max_completion_tokens":1});
        set_output_token_limit(&mut body, 512, false);
        assert_eq!(body.get("max_completion_tokens"), None);
        assert_eq!(body["max_tokens"], 512);
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

        let mut config = Config::test_defaults();
        config.llm_provider = "openai-codex".into();
        config.api_key = "fallback-key".into();
        config.model = "gpt-5.3-codex".into();
        config.llm_base_url = Some("http://should-be-ignored".into());
        config.data_dir = "/tmp".into();
        config.working_dir = "/tmp".into();
        config.working_dir_isolation = WorkingDirIsolation::Shared;
        config.web_enabled = false;
        config.web_port = 3900;
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

        let mut config = Config::test_defaults();
        config.llm_provider = "openai-codex".into();
        config.api_key = "should-be-ignored".into();
        config.model = "gpt-5.3-codex".into();
        config.llm_base_url = Some("http://should-be-ignored".into());
        config.data_dir = "/tmp".into();
        config.working_dir = "/tmp".into();
        config.working_dir_isolation = WorkingDirIsolation::Shared;
        config.web_enabled = false;
        config.web_port = 3900;
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
    fn test_resolve_openai_compat_base_defaults_openai() {
        let base = resolve_openai_compat_base("openai", "");
        assert_eq!(base, "https://api.openai.com/v1");
    }

    #[test]
    fn test_resolve_openai_compat_base_defaults_openrouter() {
        let base = resolve_openai_compat_base("openrouter", "");
        assert_eq!(base, "https://openrouter.ai/api/v1");
    }

    #[test]
    fn test_resolve_openai_compat_base_defaults_deepseek() {
        let base = resolve_openai_compat_base("deepseek", "");
        assert_eq!(base, "https://api.deepseek.com/v1");
    }

    #[test]
    fn test_resolve_openai_compat_base_defaults_ollama() {
        let base = resolve_openai_compat_base("ollama", "");
        assert_eq!(base, "http://127.0.0.1:11434/v1");
    }

    #[test]
    fn test_resolve_openai_compat_base_defaults_google() {
        let base = resolve_openai_compat_base("google", "");
        assert_eq!(
            base,
            "https://generativelanguage.googleapis.com/v1beta/openai"
        );
    }

    #[test]
    fn test_resolve_openai_compat_base_unknown_provider_falls_back_to_openai() {
        let base = resolve_openai_compat_base("some-unknown-provider", "");
        assert_eq!(base, "https://api.openai.com/v1");
    }

    #[test]
    fn test_resolve_openai_compat_base_custom_overrides_provider_default() {
        let base = resolve_openai_compat_base("openrouter", "https://custom.example.com/v1");
        assert_eq!(base, "https://custom.example.com/v1");
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

    #[test]
    fn test_parse_openai_codex_response_payload_recovers_streamed_text() {
        let body = r#"data: {"type":"response.output_text.delta","delta":"Hello "}

data: {"type":"response.output_text.delta","delta":"from stream"}

data: {"type":"response.done","response":{"output":[],"usage":{"input_tokens":1,"output_tokens":2}}}

data: [DONE]
"#;
        let parsed = parse_openai_codex_response_payload(body).unwrap();
        let translated = translate_oai_responses_response(parsed);
        match &translated.content[0] {
            ResponseContentBlock::Text { text } => assert_eq!(text, "Hello from stream"),
            _ => panic!("Expected recovered text block"),
        }
    }

    #[test]
    fn test_parse_openai_codex_response_payload_accepts_delta_only_stream() {
        let body = r#"data: {"type":"response.output_text.delta","delta":"Visible"}

data: [DONE]
"#;
        let parsed = parse_openai_codex_response_payload(body).unwrap();
        let translated = translate_oai_responses_response(parsed);
        match &translated.content[0] {
            ResponseContentBlock::Text { text } => assert_eq!(text, "Visible"),
            _ => panic!("Expected recovered text block"),
        }
    }

    #[test]
    fn test_parse_openai_codex_response_payload_recovers_streamed_function_call() {
        let body = r#"data: {"type":"response.output_item.done","output_index":0,"item":{"type":"function_call","id":"fc_1","call_id":"call_1","name":"read_file","arguments":"{\"path\":\"TASK.md\"}"}}

data: {"type":"response.done","response":{"output":[],"usage":{"input_tokens":10,"output_tokens":5}}}

data: [DONE]
"#;
        let parsed = parse_openai_codex_response_payload(body).unwrap();
        let translated = translate_oai_responses_response(parsed);
        assert_eq!(translated.stop_reason.as_deref(), Some("tool_use"));
        match &translated.content[0] {
            ResponseContentBlock::ToolUse {
                id, name, input, ..
            } => {
                assert_eq!(id, "call_1");
                assert_eq!(name, "read_file");
                assert_eq!(input, &serde_json::json!({"path": "TASK.md"}));
            }
            _ => panic!("Expected recovered tool call"),
        }
    }

    #[test]
    fn test_parse_openai_codex_response_payload_accepts_function_call_only_stream() {
        let body = r#"data: {"type":"response.output_item.done","output_index":0,"item":{"type":"function_call","id":"fc_1","call_id":"call_1","name":"write_file","arguments":"{\"path\":\"RESULT.md\",\"content\":\"done\"}"}}

data: [DONE]
"#;
        let parsed = parse_openai_codex_response_payload(body).unwrap();
        let translated = translate_oai_responses_response(parsed);
        assert_eq!(translated.stop_reason.as_deref(), Some("tool_use"));
        assert!(matches!(
            &translated.content[0],
            ResponseContentBlock::ToolUse { name, .. } if name == "write_file"
        ));
    }

    #[test]
    fn test_parse_openai_codex_response_payload_uses_sse_event_name() {
        let body = r#"event: response.output_item.done
data: {"output_index":0,"item":{"type":"function_call","id":"fc_1","call_id":"call_1","name":"read_file","arguments":"{\"path\":\"TASK.md\"}"}}

event: response.completed
data: {"response":{"output":[],"usage":{"input_tokens":10,"output_tokens":5}}}

data: [DONE]
"#;
        let parsed = parse_openai_codex_response_payload(body).unwrap();
        let translated = translate_oai_responses_response(parsed);
        assert_eq!(translated.stop_reason.as_deref(), Some("tool_use"));
        assert!(matches!(
            &translated.content[0],
            ResponseContentBlock::ToolUse { name, .. } if name == "read_file"
        ));
    }
}
