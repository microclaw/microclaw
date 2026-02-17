use std::str::FromStr;
use std::sync::Arc;

use chrono::Utc;
use tracing::{error, info};

use crate::channel::deliver_and_store_bot_message;
use crate::db::call_blocking;
use crate::telegram::{AgentRequestContext, AppState};

fn channel_from_chat_type(chat_type: &str) -> &'static str {
    match chat_type {
        "discord" => "discord",
        "whatsapp" => "whatsapp",
        "web" => "web",
        _ => "telegram",
    }
}

pub fn spawn_scheduler(state: Arc<AppState>) {
    tokio::spawn(async move {
        info!("Scheduler started");
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            run_due_tasks(&state).await;
        }
    });
}

async fn run_due_tasks(state: &Arc<AppState>) {
    let now = Utc::now().to_rfc3339();
    let tasks = match call_blocking(state.db.clone(), move |db| db.get_due_tasks(&now)).await {
        Ok(t) => t,
        Err(e) => {
            error!("Scheduler: failed to query due tasks: {e}");
            return;
        }
    };

    for task in tasks {
        let task_id = task.id;
        let chat_id = task.chat_id;
        let prompt = task.prompt.clone();

        info!(
            "Scheduler: executing task #{} for chat {}",
            task_id, chat_id
        );

        let started_at = Utc::now();
        let started_at_str = started_at.to_rfc3339();

        // Claim task immediately so the next scheduler tick (60s) won't pick it again
        // while we're still running the agent (which can take minutes).
        // Use after(started_at) so the next run is strictly in the future; store in UTC
        // so get_due_tasks' string comparison (next_run <= now) is reliable.
        let tz: chrono_tz::Tz = state.config.timezone.parse().unwrap_or(chrono_tz::Tz::UTC);
        let next_run = if task.schedule_type == "cron" {
            match cron::Schedule::from_str(&task.schedule_value) {
                Ok(schedule) => schedule
                    .after(&started_at.with_timezone(&tz))
                    .next()
                    .map(|t| t.with_timezone(&Utc).to_rfc3339()),
                Err(e) => {
                    error!("Scheduler: invalid cron for task #{}: {e}", task_id);
                    None
                }
            }
        } else {
            None // one-shot: will be marked completed by update_task_after_run
        };

        let started_for_claim = started_at_str.clone();
        let next_run_claim = next_run.clone();
        if let Err(e) = call_blocking(state.db.clone(), move |db| {
            db.update_task_after_run(task_id, &started_for_claim, next_run_claim.as_deref())?;
            Ok(())
        })
        .await
        {
            error!("Scheduler: failed to claim task #{}: {e}", task_id);
            continue;
        }

        let channel =
            match call_blocking(state.db.clone(), move |db| db.get_chat_type(chat_id)).await {
                Ok(Some(chat_type)) => channel_from_chat_type(&chat_type),
                _ => "telegram",
            };

        let persona_id = call_blocking(state.db.clone(), move |db| db.get_current_persona_id(chat_id)).await.unwrap_or(0);
        if persona_id == 0 {
            error!("Scheduler: could not resolve persona for chat {}", chat_id);
            continue;
        }

        // Run agent loop with the task prompt (may take a long time)
        let (success, result_summary) = match crate::telegram::process_with_agent(
            state,
            AgentRequestContext {
                caller_channel: channel,
                chat_id,
                chat_type: "private",
                persona_id,
            },
            Some(&prompt),
            None,
        )
        .await
        {
            Ok(response) => {
                if !response.is_empty() {
                    let _ = deliver_and_store_bot_message(
                        &state.bot,
                        state.db.clone(),
                        &state.config.bot_username,
                        chat_id,
                        persona_id,
                        &response,
                    )
                    .await;
                }
                let summary = if response.len() > 200 {
                    format!("{}...", &response[..response.floor_char_boundary(200)])
                } else {
                    response
                };
                (true, Some(summary))
            }
            Err(e) => {
                error!("Scheduler: task #{} failed: {e}", task_id);
                let err_text = format!("Scheduled task #{} failed: {e}", task_id);
                let _ = deliver_and_store_bot_message(
                    &state.bot,
                    state.db.clone(),
                    &state.config.bot_username,
                    chat_id,
                    persona_id,
                    &err_text,
                )
                .await;
                (false, Some(format!("Error: {e}")))
            }
        };

        let finished_at = Utc::now();
        let finished_at_str = finished_at.to_rfc3339();
        let duration_ms = (finished_at - started_at).num_milliseconds();

        // Log the task run
        let log_summary = result_summary.clone();
        let started_for_log = started_at_str.clone();
        let finished_for_log = finished_at_str.clone();
        if let Err(e) = call_blocking(state.db.clone(), move |db| {
            db.log_task_run(
                task_id,
                chat_id,
                &started_for_log,
                &finished_for_log,
                duration_ms,
                success,
                log_summary.as_deref(),
            )?;
            Ok(())
        })
        .await
        {
            error!("Scheduler: failed to log task run for #{}: {e}", task_id);
        }
        // Task was already claimed (next_run / status updated) before the run
    }
}
