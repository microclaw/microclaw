//! Startup recovery for work that was in flight when the previous process
//! died.
//!
//! Scheduled tasks already recover through `recover_running_tasks` + the DLQ.
//! This module owns interactive turns and in-process sub-agent runs:
//!
//! * Safe provider-neutral interactive checkpoints resume automatically.
//! * A turn interrupted during tool execution stops with evidence instead of
//!   replaying a possibly committed side effect.
//! * Orphaned in-process sub-agent rows are retired as `interrupted`.

use std::sync::Arc;

use tracing::{info, warn};

use crate::runtime::AppState;
use microclaw_channels::channel::deliver_and_store_bot_message;
use microclaw_storage::db::call_blocking;

/// After a long outage, an automatic continuation is more surprising than
/// useful. Operators can still inspect the audit/session state.
const RESUME_MAX_AGE_HOURS: i64 = 24;

fn interruption_notice(
    lang: crate::config::UserMessageLanguage,
    progress: Option<&str>,
    tool_summary: Option<&str>,
) -> String {
    crate::messages::interruption_notice(lang, progress, tool_summary)
}

fn valid_checkpoint_session(json: &str) -> bool {
    let Ok(messages) = serde_json::from_str::<Vec<microclaw_core::llm_types::Message>>(json) else {
        return false;
    };
    if messages.is_empty() {
        return false;
    }
    let mut pending = std::collections::HashSet::new();
    let mut seen_tool_uses = std::collections::HashSet::new();
    for message in messages {
        match (&*message.role, message.content) {
            ("assistant", microclaw_core::llm_types::MessageContent::Blocks(blocks)) => {
                if !pending.is_empty() {
                    return false;
                }
                for block in blocks {
                    if let microclaw_core::llm_types::ContentBlock::ToolUse { id, .. } = block {
                        if id.is_empty()
                            || !seen_tool_uses.insert(id.clone())
                            || !pending.insert(id)
                        {
                            return false;
                        }
                    }
                }
            }
            ("user", microclaw_core::llm_types::MessageContent::Blocks(blocks)) => {
                let result_ids: Vec<String> = blocks
                    .into_iter()
                    .filter_map(|block| match block {
                        microclaw_core::llm_types::ContentBlock::ToolResult {
                            tool_use_id, ..
                        } => Some(tool_use_id),
                        _ => None,
                    })
                    .collect();
                let unique_result_ids: std::collections::HashSet<String> =
                    result_ids.iter().cloned().collect();
                if result_ids.len() != unique_result_ids.len() {
                    return false;
                }
                if (!unique_result_ids.is_empty() && pending.is_empty())
                    || (!pending.is_empty() && unique_result_ids != pending)
                {
                    return false;
                }
                pending.clear();
            }
            _ if !pending.is_empty() => return false,
            _ => {}
        }
    }
    pending.is_empty()
}

pub async fn run_startup_recovery(state: Arc<AppState>) {
    match call_blocking(state.db.clone(), |db| db.recover_orphaned_subagent_runs()).await {
        Ok(0) => {}
        Ok(n) => info!("Startup recovery: marked {n} orphaned sub-agent run(s) as interrupted"),
        Err(error) => warn!("Startup recovery: failed to recover sub-agent runs: {error}"),
    }

    // Keep rows in place until each recovery reaches a terminal outcome.
    // This avoids losing the checkpoint if the process crashes again between
    // startup discovery and the resumed agent loop's first database write.
    let turns = match call_blocking(state.db.clone(), |db| db.list_active_turns()).await {
        Ok(turns) => turns,
        Err(error) => {
            warn!("Startup recovery: failed to read interrupted turns: {error}");
            return;
        }
    };
    if turns.is_empty() {
        return;
    }

    let now = chrono::Utc::now();
    let mut resumed = 0usize;
    let mut stopped = 0usize;
    let mut skipped = 0usize;
    for turn in turns {
        let checkpoint_time = turn
            .last_checkpoint_at
            .as_deref()
            .unwrap_or(&turn.started_at);
        let fresh = chrono::DateTime::parse_from_rfc3339(checkpoint_time)
            .map(|timestamp| now.signed_duration_since(timestamp.with_timezone(&chrono::Utc)))
            .map(|age| age < chrono::Duration::hours(RESUME_MAX_AGE_HOURS))
            .unwrap_or(false);
        if !fresh {
            clear_recovered_turn(&state, turn.chat_id).await;
            skipped += 1;
            continue;
        }

        let bot_username = state.config.bot_username_for_channel(&turn.channel);
        let can_resume = turn.resumable
            && turn
                .session_json
                .as_deref()
                .is_some_and(valid_checkpoint_session);
        if can_resume {
            let chat_id = turn.chat_id;
            let session_json = turn.session_json.clone().unwrap_or_default();
            let restored = call_blocking(state.db.clone(), move |db| {
                db.save_session(chat_id, &session_json)
            })
            .await;
            if let Err(error) = restored {
                warn!(
                    "Startup recovery: failed to restore checkpoint for chat {}: {error}",
                    turn.chat_id
                );
            } else {
                let context = crate::agent_engine::AgentRequestContext {
                    caller_channel: &turn.channel,
                    chat_id: turn.chat_id,
                    chat_type: &turn.chat_type,
                };
                match crate::agent_engine::resume_interrupted_turn(&state, context).await {
                    Ok(reply) => {
                        let resumed_reply = format!("↻ Resumed after restart.\n\n{reply}");
                        match deliver_and_store_bot_message(
                            state.channel_registry.as_ref(),
                            state.db.clone(),
                            &bot_username,
                            turn.chat_id,
                            &resumed_reply,
                        )
                        .await
                        {
                            Ok(()) => {
                                resumed += 1;
                                log_recovery_audit(&state, &turn, "resume", "completed").await;
                                continue;
                            }
                            Err(error) => warn!(
                                "Startup recovery: resumed chat {} but delivery failed: {error}",
                                turn.chat_id
                            ),
                        }
                    }
                    Err(error) => warn!(
                        "Startup recovery: resume failed for chat {}: {error}",
                        turn.chat_id
                    ),
                }
            }
        }

        let notice = interruption_notice(
            state.config.user_message_language,
            turn.progress_text.as_deref(),
            turn.tool_summary.as_deref(),
        );
        match deliver_and_store_bot_message(
            state.channel_registry.as_ref(),
            state.db.clone(),
            &bot_username,
            turn.chat_id,
            &notice,
        )
        .await
        {
            Ok(()) => {
                stopped += 1;
                log_recovery_audit(&state, &turn, "stop_uncertain", "completed").await;
                clear_recovered_turn(&state, turn.chat_id).await;
            }
            Err(error) => warn!(
                "Startup recovery: failed to notify chat {} ({}) about interrupted turn: {error}",
                turn.chat_id, turn.channel
            ),
        }
    }
    info!(
        "Startup recovery: {resumed} turn(s) resumed, {stopped} uncertain turn(s) stopped with evidence, {skipped} stale turn(s) dropped"
    );
}

async fn clear_recovered_turn(state: &AppState, chat_id: i64) {
    if let Err(error) =
        call_blocking(state.db.clone(), move |db| db.clear_turn_active(chat_id)).await
    {
        warn!("Startup recovery: failed to clear terminal turn {chat_id}: {error}");
    }
}

async fn log_recovery_audit(
    state: &AppState,
    turn: &microclaw_storage::db::InterruptedTurn,
    action: &'static str,
    status: &'static str,
) {
    let actor = format!("chat:{}", turn.chat_id);
    let detail = format!(
        "phase={}, iteration={}, checkpoint={}, tools={}",
        turn.phase,
        turn.iteration,
        turn.last_checkpoint_at.as_deref().unwrap_or("unknown"),
        turn.tool_summary.as_deref().unwrap_or("none")
    );
    let _ = call_blocking(state.db.clone(), move |db| {
        db.log_audit_event("turn_recovery", &actor, action, None, status, Some(&detail))
            .map(|_| ())
    })
    .await;
}

#[cfg(test)]
mod tests {
    use super::{interruption_notice, valid_checkpoint_session};
    use microclaw_core::llm_types::{ContentBlock, Message, MessageContent};

    #[test]
    fn notice_includes_progress_and_uncertain_tool() {
        use crate::config::UserMessageLanguage;
        let plain = interruption_notice(UserMessageLanguage::En, None, None);
        assert!(plain.contains("restarted"));
        assert!(!plain.contains("Last durable progress"));
        assert_eq!(
            interruption_notice(UserMessageLanguage::En, Some("   "), None),
            plain
        );

        let with = interruption_notice(
            UserMessageLanguage::En,
            Some("step 4: web_search, execute_command"),
            Some("send_message(medium)"),
        );
        assert!(with.contains("step 4: web_search, execute_command"));
        assert!(with.starts_with("⚠️ I restarted while a tool operation was in progress."));
        assert!(with.contains("send_message(medium)"));

        let zh = interruption_notice(
            UserMessageLanguage::Zh,
            Some("step 4"),
            Some("send_message(medium)"),
        );
        assert!(zh.contains("不确定边界上的操作"));
        assert!(zh.contains("send_message(medium)"));
    }

    #[test]
    fn checkpoint_validation_rejects_dangling_tool_use() {
        let safe = serde_json::to_string(&vec![Message {
            role: "user".into(),
            content: MessageContent::Text("continue".into()),
        }])
        .unwrap();
        assert!(valid_checkpoint_session(&safe));

        let dangling = serde_json::to_string(&vec![Message {
            role: "assistant".into(),
            content: MessageContent::Blocks(vec![ContentBlock::ToolUse {
                id: "call-1".into(),
                name: "bash".into(),
                input: serde_json::json!({"command": "echo hi"}),
                thought_signature: None,
            }]),
        }])
        .unwrap();
        assert!(!valid_checkpoint_session(&dangling));

        let paired = serde_json::to_string(&vec![
            Message {
                role: "assistant".into(),
                content: MessageContent::Blocks(vec![ContentBlock::ToolUse {
                    id: "call-1".into(),
                    name: "bash".into(),
                    input: serde_json::json!({"command": "echo hi"}),
                    thought_signature: None,
                }]),
            },
            Message {
                role: "user".into(),
                content: MessageContent::Blocks(vec![ContentBlock::ToolResult {
                    tool_use_id: "call-1".into(),
                    content: "hi".into(),
                    is_error: None,
                }]),
            },
        ])
        .unwrap();
        assert!(valid_checkpoint_session(&paired));

        let duplicate_use = serde_json::to_string(&vec![
            Message {
                role: "assistant".into(),
                content: MessageContent::Blocks(vec![ContentBlock::ToolUse {
                    id: "call-1".into(),
                    name: "read_file".into(),
                    input: serde_json::json!({"path": "a"}),
                    thought_signature: None,
                }]),
            },
            Message {
                role: "user".into(),
                content: MessageContent::Blocks(vec![ContentBlock::ToolResult {
                    tool_use_id: "call-1".into(),
                    content: "a".into(),
                    is_error: Some(false),
                }]),
            },
            Message {
                role: "assistant".into(),
                content: MessageContent::Blocks(vec![ContentBlock::ToolUse {
                    id: "call-1".into(),
                    name: "read_file".into(),
                    input: serde_json::json!({"path": "b"}),
                    thought_signature: None,
                }]),
            },
            Message {
                role: "user".into(),
                content: MessageContent::Blocks(vec![ContentBlock::ToolResult {
                    tool_use_id: "call-1".into(),
                    content: "b".into(),
                    is_error: Some(false),
                }]),
            },
        ])
        .unwrap();
        assert!(!valid_checkpoint_session(&duplicate_use));
    }
}
