use async_trait::async_trait;
use serde_json::json;
use std::sync::Arc;

use microclaw_channels::channel::deliver_and_store_bot_message;
use microclaw_channels::channel_adapter::ChannelRegistry;
use microclaw_core::llm_types::ToolDefinition;
use microclaw_storage::db::Database;
use microclaw_tools::runtime::auth_context_from_input;

use super::{schema_object, Tool, ToolResult};

/// Maximum number of structured choices the agent can offer. Matches the
/// cap enforced by hermes-agent's `clarify_tool.py`.
const MAX_CHOICES: usize = 4;

/// Clarify tool — ask the user a structured question and immediately return
/// control so the next user turn supplies the answer.
///
/// Unlike hermes-agent's Python clarify tool (which blocks in CLI mode), the
/// microclaw equivalent is send-and-release: the formatted question is
/// delivered through the caller's channel via `deliver_and_store_bot_message`,
/// and the tool result reminds the agent to stop and wait. The next user
/// message continues the conversation naturally via microclaw's existing
/// session-resume path.
pub struct ClarifyTool {
    channels: Arc<ChannelRegistry>,
    db: Arc<Database>,
    default_bot_username: String,
    channel_bot_usernames: std::collections::HashMap<String, String>,
}

impl ClarifyTool {
    pub fn new(
        channels: Arc<ChannelRegistry>,
        db: Arc<Database>,
        default_bot_username: String,
        channel_bot_usernames: std::collections::HashMap<String, String>,
    ) -> Self {
        Self {
            channels,
            db,
            default_bot_username,
            channel_bot_usernames,
        }
    }

    fn bot_username_for_channel(&self, channel_name: &str) -> String {
        self.channel_bot_usernames
            .get(channel_name)
            .cloned()
            .unwrap_or_else(|| self.default_bot_username.clone())
    }
}

fn render_message(question: &str, choices: &[String]) -> String {
    if choices.is_empty() {
        return question.to_string();
    }
    let mut lines = Vec::with_capacity(choices.len() + 2);
    lines.push(question.to_string());
    for (i, choice) in choices.iter().enumerate() {
        lines.push(format!("{}. {choice}", i + 1));
    }
    lines.push(format!(
        "{}. Other — reply with your own answer",
        choices.len() + 1
    ));
    lines.join("\n")
}

#[async_trait]
impl Tool for ClarifyTool {
    fn name(&self) -> &str {
        "clarify"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: self.name().into(),
            description: "Ask the user a clarifying question and pause for a \
                reply. Use when the request is ambiguous, a decision has \
                meaningful trade-offs, or you want post-task feedback. Supports \
                up to 4 multiple-choice options (an 'Other' option is appended \
                automatically) or pure open-ended mode. Do NOT use for yes/no \
                confirmation of dangerous commands — the bash-tool approval \
                path handles that."
                .into(),
            input_schema: schema_object(
                json!({
                    "question": {
                        "type": "string",
                        "description": "The question to present to the user."
                    },
                    "choices": {
                        "type": "array",
                        "items": {"type": "string"},
                        "maxItems": MAX_CHOICES,
                        "description": "Up to 4 predefined answer choices. Omit for free-form response."
                    }
                }),
                &["question"],
            ),
        }
    }

    async fn execute(&self, input: serde_json::Value) -> ToolResult {
        let Some(auth) = auth_context_from_input(&input) else {
            return ToolResult::error(
                "clarify requires an auth context (caller_chat_id) on the input".into(),
            );
        };
        let question = match input.get("question").and_then(|v| v.as_str()) {
            Some(q) if !q.trim().is_empty() => q.trim().to_string(),
            _ => return ToolResult::error("Missing or empty required parameter: question".into()),
        };
        let choices: Vec<String> = input
            .get("choices")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.trim().to_string()))
                    .filter(|s| !s.is_empty())
                    .take(MAX_CHOICES)
                    .collect()
            })
            .unwrap_or_default();

        let rendered = render_message(&question, &choices);
        let bot_username = self.bot_username_for_channel(auth.caller_channel.as_str());
        if let Err(e) = deliver_and_store_bot_message(
            &self.channels,
            self.db.clone(),
            &bot_username,
            auth.caller_chat_id,
            &rendered,
        )
        .await
        {
            return ToolResult::error(format!("failed to deliver clarify question: {e}"));
        }

        let mut summary = format!(
            "clarify question sent on channel '{}' — stop this turn and wait for the \
             user's next reply; session resume will pick up their answer.",
            auth.caller_channel
        );
        if !choices.is_empty() {
            summary.push_str(&format!(" Offered {} choice(s).", choices.len()));
        }
        ToolResult::success(summary)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_open_ended() {
        assert_eq!(render_message("hi?", &[]), "hi?");
    }

    #[test]
    fn renders_with_choices_and_other_option() {
        let out = render_message("pick?", &["A".into(), "B".into()]);
        assert!(out.contains("1. A"));
        assert!(out.contains("2. B"));
        assert!(out.contains("3. Other"));
    }
}
