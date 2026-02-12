use teloxide::prelude::*;

use crate::config::Config;
use crate::text::floor_char_boundary;

fn split_text(text: &str, max_len: usize) -> Vec<String> {
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

pub async fn send_telegram_text(bot: &Bot, chat_id: i64, text: &str) -> Result<(), String> {
    crate::telegram::send_response(bot, ChatId(chat_id), text).await;
    Ok(())
}

pub async fn send_discord_text(config: &Config, chat_id: i64, text: &str) -> Result<(), String> {
    let token = config
        .discord_bot_token
        .as_deref()
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| "discord_bot_token not configured".to_string())?;

    let client = reqwest::Client::new();
    let url = format!("https://discord.com/api/v10/channels/{chat_id}/messages");

    for chunk in split_text(text, 2000) {
        let body = serde_json::json!({ "content": chunk });
        let resp = client
            .post(&url)
            .header(reqwest::header::AUTHORIZATION, format!("Bot {token}"))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("Failed to send Discord message: {e}"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!(
                "Failed to send Discord message: HTTP {status} {}",
                body.chars().take(300).collect::<String>()
            ));
        }
    }

    Ok(())
}
