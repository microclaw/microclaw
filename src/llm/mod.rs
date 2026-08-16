use async_trait::async_trait;
use futures_util::StreamExt;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, error, warn};

use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use crate::codex_auth::{
    codex_config_default_openai_base_url, is_openai_codex_provider, is_qwen_portal_provider,
    refresh_openai_codex_auth_if_needed, resolve_openai_codex_auth, resolve_qwen_portal_auth,
};
#[cfg(test)]
use crate::config::WorkingDirIsolation;
use crate::config::{resolve_model_name_with_fallback, Config};
use crate::http_client::llm_user_agent;
use crate::setup::default_base_url_for_provider;
use microclaw_core::error::MicroClawError;
use microclaw_core::llm_types::{
    ContentBlock, ImageSource, Message, MessageContent, MessagesRequest, MessagesResponse,
    ResponseContentBlock, ToolDefinition, Usage,
};

/// HTTP statuses worth retrying: rate limit (429), Anthropic "overloaded"
/// (529), and transient server errors (500/502/503/504). Everything else
/// (400/401/403/404/422 …) is terminal — retrying just fails again and hides
/// the real problem.
pub(crate) fn is_retryable_status(status: u16) -> bool {
    matches!(status, 429 | 529 | 500 | 502 | 503 | 504)
}

/// Transport-level failures (connection refused, reset, timeout) are transient
/// and safe to retry on a fresh request — the server never saw a complete
/// request, so there is no risk of duplicating a side effect.
pub(crate) fn is_retryable_transport_error(err: &reqwest::Error) -> bool {
    err.is_timeout() || err.is_connect() || err.is_request()
}

/// Provider-agnostic detection of a "request exceeds the model context
/// window" error. The agent loop compacts the session and retries once when
/// it sees one of these instead of failing the turn.
pub fn is_context_overflow_error(err: &microclaw_core::error::MicroClawError) -> bool {
    let text = err.to_string().to_ascii_lowercase();
    text.contains("context_length_exceeded")     // OpenAI
        || text.contains("prompt is too long")   // Anthropic
        || text.contains("input is too long")    // Anthropic (older phrasing)
        || text.contains("maximum context length")
        || text.contains("exceed context limit")
        || text.contains("exceeds the context window")
}

/// Parse a `Retry-After` header in delta-seconds form (the HTTP-date form is
/// ignored — providers use seconds in practice).
fn parse_retry_after(headers: &reqwest::header::HeaderMap) -> Option<std::time::Duration> {
    headers
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
        .map(std::time::Duration::from_secs)
}

/// Backoff for retry `attempt` (1-based): exponential (2^attempt seconds) capped
/// at 32s, with "equal jitter" (half fixed, half random) so a burst of callers
/// — e.g. many cron tasks firing at once — don't retry in lockstep and stampede
/// the provider. Never returns less than a server-provided `Retry-After`.
fn retry_backoff(attempt: u32, retry_after: Option<std::time::Duration>) -> std::time::Duration {
    let exp = 2u64.saturating_pow(attempt).min(32);
    let half = (exp / 2).max(1);
    // Cheap jitter source; randomness quality is irrelevant, we only need to
    // desynchronize concurrent retriers.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::from(d.subsec_nanos()))
        .unwrap_or(0);
    let jittered = half + (nanos % (half + 1));
    let base = std::time::Duration::from_secs(jittered);
    match retry_after {
        Some(ra) => base.max(ra),
        None => base,
    }
}

/// Remove invalid `ToolResult` blocks that cannot be matched to the most recent
/// assistant `ToolUse` turn. This can happen after session compaction or
/// malformed history reconstruction.
fn sanitize_messages(messages: Vec<Message>) -> Vec<Message> {
    let mut pending_tool_ids: HashSet<String> = HashSet::new();
    let mut sanitized = Vec::new();

    for msg in messages {
        match msg.content {
            MessageContent::Text(text) => {
                pending_tool_ids.clear();
                sanitized.push(Message {
                    role: msg.role,
                    content: MessageContent::Text(text),
                });
            }
            MessageContent::Blocks(blocks) => {
                if msg.role == "assistant" {
                    let assistant_tool_ids: HashSet<String> = blocks
                        .iter()
                        .filter_map(|b| match b {
                            ContentBlock::ToolUse { id, .. } => Some(id.clone()),
                            _ => None,
                        })
                        .collect();
                    pending_tool_ids = assistant_tool_ids;
                    sanitized.push(Message {
                        role: msg.role,
                        content: MessageContent::Blocks(blocks),
                    });
                    continue;
                }

                if msg.role != "user" {
                    pending_tool_ids.clear();
                    sanitized.push(Message {
                        role: msg.role,
                        content: MessageContent::Blocks(blocks),
                    });
                    continue;
                }

                let has_tool_results = blocks
                    .iter()
                    .any(|b| matches!(b, ContentBlock::ToolResult { .. }));
                if !has_tool_results {
                    pending_tool_ids.clear();
                    sanitized.push(Message {
                        role: msg.role,
                        content: MessageContent::Blocks(blocks),
                    });
                    continue;
                }

                let mut filtered = Vec::new();
                for block in blocks {
                    let keep = match &block {
                        ContentBlock::ToolResult { tool_use_id, .. } => {
                            pending_tool_ids.contains(tool_use_id)
                        }
                        _ => true,
                    };
                    if keep {
                        if let ContentBlock::ToolResult { tool_use_id, .. } = &block {
                            pending_tool_ids.remove(tool_use_id);
                        }
                        filtered.push(block);
                    }
                }

                if !filtered.is_empty() {
                    sanitized.push(Message {
                        role: msg.role,
                        content: MessageContent::Blocks(filtered),
                    });
                }
            }
        }
    }

    sanitized
}

#[async_trait]
pub trait LlmProvider: Send + Sync {
    async fn send_message(
        &self,
        system: &str,
        messages: Vec<Message>,
        tools: Option<Vec<ToolDefinition>>,
    ) -> Result<MessagesResponse, MicroClawError>;

    async fn send_message_with_model(
        &self,
        system: &str,
        messages: Vec<Message>,
        tools: Option<Vec<ToolDefinition>>,
        _model_override: Option<&str>,
    ) -> Result<MessagesResponse, MicroClawError> {
        self.send_message(system, messages, tools).await
    }

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

    async fn send_message_stream_with_model(
        &self,
        system: &str,
        messages: Vec<Message>,
        tools: Option<Vec<ToolDefinition>>,
        text_tx: Option<&UnboundedSender<String>>,
        _model_override: Option<&str>,
    ) -> Result<MessagesResponse, MicroClawError> {
        self.send_message_stream(system, messages, tools, text_tx)
            .await
    }
}

pub fn create_provider(config: &Config) -> Box<dyn LlmProvider> {
    let inner: Box<dyn LlmProvider> = match config.llm_provider.trim().to_lowercase().as_str() {
        "anthropic" => Box::new(AnthropicProvider::new(config)),
        _ => Box::new(OpenAiProvider::new(config)),
    };
    // Wrap with the resilience layer only when a distinct fallback model is
    // configured. Without one, behaviour is identical to the bare provider.
    match config.fallback_model.as_deref().map(str::trim) {
        Some(fb) if !fb.is_empty() && fb != config.model.trim() => {
            Box::new(ResilientProvider::new(inner, fb.to_string()))
        }
        _ => inner,
    }
}

pub mod anthropic;
pub mod key_pool;
pub mod oai_translate;
pub mod openai;
pub mod resilience;
pub mod sse;
pub mod stream;
#[cfg(test)]
pub(crate) mod test_prelude;

pub use self::anthropic::*;
pub use self::key_pool::*;
pub(crate) use self::oai_translate::*;
pub use self::openai::*;
pub use self::resilience::*;
pub(crate) use self::sse::*;
pub(crate) use self::stream::*;

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use crate::llm::test_prelude::*;

    #[test]
    fn test_is_retryable_status_classification() {
        // Transient: rate limit, overloaded, 5xx.
        for s in [429, 529, 500, 502, 503, 504] {
            assert!(is_retryable_status(s), "{s} should be retryable");
        }
        // Terminal: client errors and success must not retry.
        for s in [200, 400, 401, 403, 404, 422] {
            assert!(!is_retryable_status(s), "{s} should be terminal");
        }
    }

    #[test]
    fn test_retry_backoff_grows_and_is_bounded() {
        // Equal-jitter range is [2^a/2, 2^a], capped at 32s.
        let d1 = retry_backoff(1, None).as_secs();
        assert!(
            (1..=2).contains(&d1),
            "attempt 1 backoff {d1}s out of range"
        );
        let d3 = retry_backoff(3, None).as_secs();
        assert!(
            (4..=8).contains(&d3),
            "attempt 3 backoff {d3}s out of range"
        );
        // Cap holds for large attempts.
        let dbig = retry_backoff(20, None).as_secs();
        assert!(
            (16..=32).contains(&dbig),
            "large backoff {dbig}s exceeds cap"
        );
    }

    #[test]
    fn test_create_provider_anthropic() {
        let mut config = Config::test_defaults();
        config.data_dir = "/tmp".into();
        config.working_dir = "/tmp".into();
        config.working_dir_isolation = WorkingDirIsolation::Shared;
        config.web_enabled = false;
        config.web_port = 3900;
        // Should not panic
        let _provider = create_provider(&config);
    }

    #[test]
    fn test_create_provider_openai() {
        let mut config = Config::test_defaults();
        config.llm_provider = "openai".into();
        config.model = "gpt-5.2".into();
        config.data_dir = "/tmp".into();
        config.working_dir = "/tmp".into();
        config.working_dir_isolation = WorkingDirIsolation::Shared;
        config.web_enabled = false;
        config.web_port = 3900;
        let _provider = create_provider(&config);
    }

    #[test]
    fn test_sanitize_messages_removes_orphaned_tool_results() {
        let msgs = vec![
            Message {
                role: "assistant".into(),
                content: MessageContent::Blocks(vec![ContentBlock::ToolUse {
                    id: "t1".into(),
                    name: "bash".into(),
                    input: json!({}),
                    thought_signature: None,
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
    fn test_sanitize_messages_drops_stale_tool_result_after_intervening_message() {
        let msgs = vec![
            Message {
                role: "assistant".into(),
                content: MessageContent::Blocks(vec![ContentBlock::ToolUse {
                    id: "t1".into(),
                    name: "bash".into(),
                    input: json!({}),
                    thought_signature: None,
                }]),
            },
            Message {
                role: "assistant".into(),
                content: MessageContent::Text("unrelated assistant turn".into()),
            },
            Message {
                role: "user".into(),
                content: MessageContent::Blocks(vec![ContentBlock::ToolResult {
                    tool_use_id: "t1".into(),
                    content: "stale".into(),
                    is_error: None,
                }]),
            },
        ];

        let sanitized = sanitize_messages(msgs);
        assert_eq!(sanitized.len(), 2);
        assert_eq!(sanitized[0].role, "assistant");
        assert_eq!(sanitized[1].role, "assistant");
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
}
