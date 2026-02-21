use std::sync::Arc;

use crate::config::Config;
use microclaw_core::llm_types::Message;
use microclaw_storage::db::{call_blocking, Database};

pub async fn build_status_response(
    db: Arc<Database>,
    config: &Config,
    chat_id: i64,
    caller_channel: &str,
) -> String {
    let provider = config.llm_provider.trim();
    let model = config.model.trim();

    let session_line = match call_blocking(db.clone(), move |db| db.load_session(chat_id)).await {
        Ok(Some((json, updated_at))) => {
            let messages: Vec<Message> = serde_json::from_str(&json).unwrap_or_default();
            format!(
                "Session: active ({} messages, updated at {})",
                messages.len(),
                updated_at
            )
        }
        Ok(None) => "Session: empty".to_string(),
        Err(e) => format!("Session: unavailable ({e})"),
    };

    let task_line = match call_blocking(db.clone(), move |db| db.get_tasks_for_chat(chat_id)).await
    {
        Ok(tasks) => {
            let mut active = 0usize;
            let mut paused = 0usize;
            let mut completed = 0usize;
            let mut cancelled = 0usize;
            let mut other = 0usize;

            for task in tasks {
                match task.status.as_str() {
                    "active" => active += 1,
                    "paused" => paused += 1,
                    "completed" => completed += 1,
                    "cancelled" => cancelled += 1,
                    _ => other += 1,
                }
            }

            let total = active + paused + completed + cancelled + other;
            if other == 0 {
                format!(
                    "Scheduled tasks: total={total}, active={active}, paused={paused}, completed={completed}, cancelled={cancelled}"
                )
            } else {
                format!(
                    "Scheduled tasks: total={total}, active={active}, paused={paused}, completed={completed}, cancelled={cancelled}, other={other}"
                )
            }
        }
        Err(e) => format!("Scheduled tasks: unavailable ({e})"),
    };

    format!(
        "Status\nChannel: {caller_channel}\nProvider: {provider}\nModel: {model}\n{session_line}\n{task_line}"
    )
}

pub fn build_model_response(config: &Config, command_text: &str) -> String {
    let provider = config.llm_provider.trim();
    let model = config.model.trim();
    let requested = command_text
        .trim()
        .strip_prefix("/model")
        .map(str::trim)
        .unwrap_or("");

    if requested.is_empty() {
        format!("Current provider/model: {provider} / {model}")
    } else {
        format!(
            "Model switching is not supported yet. Current provider/model: {provider} / {model}"
        )
    }
}
