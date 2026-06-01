use async_trait::async_trait;
use serde_json::json;

use super::{schema_object, Tool, ToolResult};
use crate::config::Config;
use crate::tools::specialists::{resolve_specialist, specialist_catalog, specialist_names};
use microclaw_core::llm_types::{Message, MessageContent, ResponseContentBlock, ToolDefinition};

/// Lets one agent get a quick, inline second opinion from a different specialist
/// without spawning a full async run. It's a single, bounded LLM call with the
/// chosen specialist's persona — no tools, no recursion — so a researcher can ask
/// the writer to polish a paragraph, or the coder can ask the mathematician to
/// sanity-check a formula, and weave the answer straight back into their work.
pub struct ConsultSpecialistTool {
    config: Config,
}

impl ConsultSpecialistTool {
    pub fn new(config: &Config) -> Self {
        Self {
            config: config.clone(),
        }
    }
}

#[async_trait]
impl Tool for ConsultSpecialistTool {
    fn name(&self) -> &str {
        "consult_specialist"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "consult_specialist".into(),
            description: format!(
                "Get a quick, inline expert opinion from a different specialist when a sub-problem is outside your expertise (e.g. ask the writer to polish a draft, the mathematician to check a formula). One focused round, no tools — give them everything they need in `question`. Returns their answer for you to use. Specialists: {}.",
                specialist_catalog()
            ),
            input_schema: schema_object(
                json!({
                    "specialist": {
                        "type": "string",
                        "enum": specialist_names(),
                        "description": "Which specialist to consult."
                    },
                    "question": {
                        "type": "string",
                        "description": "The focused question plus all context they need (they have no tools and can't see your conversation)."
                    }
                }),
                &["specialist", "question"],
            ),
        }
    }

    async fn execute(&self, input: serde_json::Value) -> ToolResult {
        let specialist_name = input.get("specialist").and_then(|v| v.as_str());
        let profile = resolve_specialist(specialist_name);
        let question = input
            .get("question")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        if question.is_empty() {
            return ToolResult::error("Missing required parameter: question".into());
        }

        let system_prompt = format!(
            "{persona}\n\nYou are being consulted by a colleague for a focused expert opinion. \
You have NO tools and cannot see their conversation — work only from what they give you. \
Answer concisely and directly with your expert take; if their question lacks something you'd \
need, say what's missing.",
            persona = profile.persona
        );
        let messages = vec![Message {
            role: "user".into(),
            content: MessageContent::Text(question),
        }];

        let llm = crate::llm::create_provider(&self.config);
        // Single bounded round, no tools → no recursion, no chat side effects.
        let response = match llm.send_message(&system_prompt, messages, None).await {
            Ok(r) => r,
            Err(e) => return ToolResult::error(format!("consult_specialist LLM error: {e}")),
        };
        let answer = response
            .content
            .iter()
            .filter_map(|block| match block {
                ResponseContentBlock::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("");
        let answer = answer.trim();
        if answer.is_empty() {
            return ToolResult::error("consult_specialist: the specialist returned no answer".into());
        }

        ToolResult::success(
            json!({ "specialist": profile.name, "answer": answer }).to_string(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn missing_question_errors_before_any_llm_call() {
        let tool = ConsultSpecialistTool::new(&Config::test_defaults());
        // No `question` → returns early, never reaches the provider.
        let res = tool
            .execute(json!({ "specialist": "writer" }))
            .await;
        assert!(res.is_error);
        assert!(res.content.contains("question"));
    }

    #[test]
    fn definition_lists_specialists() {
        let tool = ConsultSpecialistTool::new(&Config::test_defaults());
        assert_eq!(tool.name(), "consult_specialist");
        let def = tool.definition();
        assert!(def.description.contains("writer"));
    }
}
