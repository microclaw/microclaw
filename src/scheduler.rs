use std::str::FromStr;
use std::sync::Arc;

use chrono::Utc;
use tracing::{error, info};

use crate::agent_engine::process_with_agent;
use crate::agent_engine::AgentRequestContext;
use crate::channel::{
    deliver_and_store_bot_message, get_chat_routing, ChatChannel, ChatRouting, ConversationKind,
};
use crate::db::call_blocking;
use crate::runtime::AppState;
use crate::text::floor_char_boundary;

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
        info!(
            "Scheduler: executing task #{} for chat {}",
            task.id, task.chat_id
        );

        let started_at = Utc::now();
        let started_at_str = started_at.to_rfc3339();
        let routing = get_chat_routing(state.db.clone(), task.chat_id)
            .await
            .ok()
            .flatten()
            .unwrap_or(ChatRouting {
                channel: ChatChannel::Telegram,
                conversation: ConversationKind::Private,
            });

        // Run agent loop with the task prompt
        let (success, result_summary) = match process_with_agent(
            state,
            AgentRequestContext {
                caller_channel: routing.channel.as_caller_channel(),
                chat_id: task.chat_id,
                chat_type: routing.conversation.as_agent_chat_type(),
            },
            Some(&task.prompt),
            None,
        )
        .await
        {
            Ok(response) => {
                if !response.is_empty() {
                    let _ = deliver_and_store_bot_message(
                        state.telegram_bot.as_ref(),
                        Some(&state.config),
                        state.db.clone(),
                        &state.config.bot_username,
                        task.chat_id,
                        &response,
                    )
                    .await;
                }
                let summary = if response.len() > 200 {
                    format!("{}...", &response[..floor_char_boundary(&response, 200)])
                } else {
                    response
                };
                (true, Some(summary))
            }
            Err(e) => {
                error!("Scheduler: task #{} failed: {e}", task.id);
                let err_text = format!("Scheduled task #{} failed: {e}", task.id);
                let _ = deliver_and_store_bot_message(
                    state.telegram_bot.as_ref(),
                    Some(&state.config),
                    state.db.clone(),
                    &state.config.bot_username,
                    task.chat_id,
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
                task.id,
                task.chat_id,
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
            error!("Scheduler: failed to log task run for #{}: {e}", task.id);
        }

        // Compute next run
        let tz: chrono_tz::Tz = state.config.timezone.parse().unwrap_or(chrono_tz::Tz::UTC);
        let next_run = if task.schedule_type == "cron" {
            match cron::Schedule::from_str(&task.schedule_value) {
                Ok(schedule) => schedule.upcoming(tz).next().map(|t| t.to_rfc3339()),
                Err(e) => {
                    error!("Scheduler: invalid cron for task #{}: {e}", task.id);
                    None
                }
            }
        } else {
            None // one-shot
        };

        let started_for_update = started_at_str.clone();
        if let Err(e) = call_blocking(state.db.clone(), move |db| {
            db.update_task_after_run(task.id, &started_for_update, next_run.as_deref())?;
            Ok(())
        })
        .await
        {
            error!("Scheduler: failed to update task #{}: {e}", task.id);
        }
    }
}
