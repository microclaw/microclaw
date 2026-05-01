//! Auto-generate session titles once a chat has enough context.
//!
//! Port of hermes-agent's `agent/title_generator.py`. The core contract:
//! given the first few turns of a session, ask the LLM to produce a 3-8
//! word title, and persist it into `sessions.label`. Runs in the
//! background scheduler — the agent loop itself never blocks on title
//! generation.

use std::sync::Arc;

use microclaw_core::error::MicroClawError;
use microclaw_core::llm_types::{Message, MessageContent, ResponseContentBlock};
use microclaw_storage::db::{call_blocking, Database};

use crate::config::Config;
use crate::llm::create_provider;

const MIN_MESSAGES_BEFORE_TITLE: usize = 4;
const MAX_MESSAGES_SAMPLED: usize = 8;

/// Produce and persist a short title for `chat_id`. Returns Ok(None) when
/// the chat doesn't yet meet the threshold (already labeled, too few
/// messages, or no session row). Returns Ok(Some(title)) on success.
pub async fn generate_and_save_title(
    config: &Config,
    db: Arc<Database>,
    chat_id: i64,
) -> Result<Option<String>, MicroClawError> {
    let snapshot = call_blocking(db.clone(), move |d| {
        let info = d.get_session_label_and_length(chat_id)?;
        let messages = d.get_recent_messages(chat_id, MAX_MESSAGES_SAMPLED)?;
        Ok::<_, MicroClawError>((info, messages))
    })
    .await?;
    let (info, recent) = snapshot;
    let Some((existing_label, total_len)) = info else {
        return Ok(None);
    };
    if existing_label
        .as_deref()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
    {
        return Ok(None);
    }
    if total_len < MIN_MESSAGES_BEFORE_TITLE {
        return Ok(None);
    }
    if recent.is_empty() {
        return Ok(None);
    }

    let transcript = build_transcript(&recent);
    let provider = create_provider(config);
    let system = "You generate a short session title — 3 to 8 English or Chinese words, no quotes, no punctuation at end. The title should capture the dominant topic. Do not explain.".to_string();
    let user = format!(
        "Produce a title for the following conversation. Reply with the title only.\n\n{transcript}"
    );
    let response = provider
        .send_message(
            &system,
            vec![Message {
                role: "user".to_string(),
                content: MessageContent::Text(user),
            }],
            None,
        )
        .await?;
    let title = first_text(&response.content)
        .map(|t| clean_title(&t))
        .filter(|t| !t.is_empty());
    let Some(title) = title else {
        return Ok(None);
    };
    let title_for_db = title.clone();
    call_blocking(db, move |d| d.set_session_label(chat_id, &title_for_db)).await?;
    Ok(Some(title))
}

fn build_transcript(messages: &[microclaw_storage::db::StoredMessage]) -> String {
    let mut out = String::new();
    for m in messages.iter().rev().take(MAX_MESSAGES_SAMPLED) {
        let role = if m.is_from_bot { "Assistant" } else { "User" };
        let trimmed = m.content.chars().take(1500).collect::<String>();
        out.push_str(role);
        out.push_str(": ");
        out.push_str(&trimmed);
        out.push_str("\n\n");
    }
    out
}

fn first_text(blocks: &[ResponseContentBlock]) -> Option<String> {
    for block in blocks {
        if let ResponseContentBlock::Text { text } = block {
            if !text.trim().is_empty() {
                return Some(text.clone());
            }
        }
    }
    None
}

fn clean_title(raw: &str) -> String {
    let first_line = raw.lines().next().unwrap_or("");
    let quote_chars: &[char] = &['"', '\'', '«', '»', '“', '”', '‘', '’'];
    let end_punct: &[char] = &['.', '。', '!', '?', '；', ';'];
    let cleaned: String = first_line
        .trim()
        .trim_matches(quote_chars)
        .trim_end_matches(end_punct)
        .chars()
        .take(80)
        .collect();
    cleaned.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleans_quotes_and_trailing_punctuation() {
        assert_eq!(clean_title("\"Rust async deep dive.\""), "Rust async deep dive");
        assert_eq!(clean_title("  Hello world!  "), "Hello world");
        assert_eq!(clean_title("“写 Rust 好处”"), "写 Rust 好处");
    }

    #[test]
    fn strips_extra_lines() {
        assert_eq!(clean_title("Title here\nExplanation ..."), "Title here");
    }

    #[test]
    fn caps_long_titles() {
        let long = "a".repeat(200);
        let out = clean_title(&long);
        assert!(out.chars().count() <= 80);
    }
}
