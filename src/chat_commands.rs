use std::sync::Arc;

use crate::agent_engine::archive_conversation;
use crate::config::Config;
use crate::runtime::AppState;
use microclaw_core::llm_types::Message;
use microclaw_storage::db::{call_blocking, Database};
use microclaw_storage::usage::build_usage_report;

pub async fn handle_chat_command(
    state: &AppState,
    chat_id: i64,
    caller_channel: &str,
    command_text: &str,
) -> Option<String> {
    let trimmed = command_text.trim();

    if trimmed == "/reset" {
        let _ = call_blocking(state.db.clone(), move |db| db.clear_chat_context(chat_id)).await;
        return Some("Context cleared (session + chat history).".to_string());
    }

    if trimmed == "/skills" {
        return Some(state.skills.list_skills_formatted());
    }

    if trimmed == "/reload-skills" {
        let count = state.skills.reload().len();
        return Some(format!("Reloaded {count} skills from disk."));
    }

    if trimmed == "/archive" {
        if let Ok(Some((json, _))) =
            call_blocking(state.db.clone(), move |db| db.load_session(chat_id)).await
        {
            let messages: Vec<Message> = serde_json::from_str(&json).unwrap_or_default();
            if messages.is_empty() {
                return Some("No session to archive.".to_string());
            }
            archive_conversation(&state.config.data_dir, caller_channel, chat_id, &messages);
            return Some(format!("Archived {} messages.", messages.len()));
        }
        return Some("No session to archive.".to_string());
    }

    if trimmed == "/usage" {
        let text = match build_usage_report(state.db.clone(), chat_id).await {
            Ok(v) => v,
            Err(e) => format!("Failed to query usage statistics: {e}"),
        };
        return Some(text);
    }

    if trimmed == "/status" {
        return Some(
            build_status_response(
                state.db.clone(),
                &state.config,
                &state.llm_model_overrides,
                chat_id,
                caller_channel,
            )
            .await,
        );
    }

    if trimmed == "/model" || trimmed.starts_with("/model ") {
        return Some(build_model_response(
            &state.config,
            &state.llm_model_overrides,
            caller_channel,
            trimmed,
        ));
    }

    None
}

pub async fn build_status_response(
    db: Arc<Database>,
    config: &Config,
    llm_model_overrides: &std::collections::HashMap<String, String>,
    chat_id: i64,
    caller_channel: &str,
) -> String {
    let provider = config.llm_provider.trim();
    let model = llm_model_overrides
        .get(caller_channel)
        .map(String::as_str)
        .unwrap_or(config.model.as_str())
        .trim();

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

pub fn build_model_response(
    config: &Config,
    llm_model_overrides: &std::collections::HashMap<String, String>,
    caller_channel: &str,
    command_text: &str,
) -> String {
    let provider = config.llm_provider.trim();
    let model = llm_model_overrides
        .get(caller_channel)
        .map(String::as_str)
        .unwrap_or(config.model.as_str())
        .trim();
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

pub async fn maybe_handle_plugin_command(
    config: &Config,
    command_text: &str,
    chat_id: i64,
    caller_channel: &str,
) -> Option<String> {
    if let Some(admin) = crate::plugins::handle_plugins_admin_command(config, chat_id, command_text)
    {
        return Some(admin);
    }
    crate::plugins::execute_plugin_slash_command(config, caller_channel, chat_id, command_text)
        .await
}
