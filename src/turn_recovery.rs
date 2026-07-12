//! Startup recovery for work that was in flight when the previous process
//! died.
//!
//! Two kinds of orphans are handled here (scheduled tasks already have their
//! own path via `recover_running_tasks` + the DLQ):
//!
//! * **Interactive turns** — `active_turns` rows written by the agent engine
//!   while a user-facing turn runs. A row surviving into a new process means
//!   the user asked something and silently never got an answer; the chat gets
//!   a short "I was interrupted" notice so they know to re-ask.
//! * **Sub-agent runs** — rows still `accepted`/`queued`/`running` in
//!   `subagent_runs`. Sub-agents execute in-process, so these can never
//!   finish; they are retired as `interrupted` so status lists and
//!   concurrency gates stop counting them.

use std::sync::Arc;

use tracing::{info, warn};

use crate::runtime::AppState;
use microclaw_channels::channel::deliver_and_store_bot_message;
use microclaw_storage::db::call_blocking;

/// Turns older than this at boot are dropped without a notice: after a long
/// outage the user has almost certainly moved on, and a stale "I was
/// interrupted" message is noise rather than help.
const NOTIFY_MAX_AGE_HOURS: i64 = 24;

fn interruption_notice(progress: Option<&str>) -> String {
    let base = "⚠️ I was restarted while working on your last message, so that reply was \
     lost. Please send it again (or tell me to continue) if you still need it.";
    match progress {
        Some(p) if !p.trim().is_empty() => {
            format!("{base}\n\nBefore the restart I had gotten as far as: {p}.")
        }
        _ => base.to_string(),
    }
}

pub async fn run_startup_recovery(state: Arc<AppState>) {
    // 1) Retire orphaned sub-agent runs.
    match call_blocking(state.db.clone(), |db| db.recover_orphaned_subagent_runs()).await {
        Ok(0) => {}
        Ok(n) => info!(
            "Startup recovery: marked {n} orphaned sub-agent run(s) as interrupted"
        ),
        Err(e) => warn!("Startup recovery: failed to recover sub-agent runs: {e}"),
    }

    // 2) Notify chats whose interactive turns were killed mid-run.
    let turns = match call_blocking(state.db.clone(), |db| db.take_interrupted_turns()).await {
        Ok(t) => t,
        Err(e) => {
            warn!("Startup recovery: failed to read interrupted turns: {e}");
            return;
        }
    };
    if turns.is_empty() {
        return;
    }

    let now = chrono::Utc::now();
    let mut notified = 0usize;
    let mut skipped = 0usize;
    for turn in turns {
        let fresh = chrono::DateTime::parse_from_rfc3339(&turn.started_at)
            .map(|t| now.signed_duration_since(t.with_timezone(&chrono::Utc)))
            .map(|age| age < chrono::Duration::hours(NOTIFY_MAX_AGE_HOURS))
            .unwrap_or(false);
        if !fresh {
            skipped += 1;
            continue;
        }
        let bot_username = state.config.bot_username_for_channel(&turn.channel);
        let notice = interruption_notice(turn.progress_text.as_deref());
        match deliver_and_store_bot_message(
            state.channel_registry.as_ref(),
            state.db.clone(),
            &bot_username,
            turn.chat_id,
            &notice,
        )
        .await
        {
            Ok(()) => notified += 1,
            Err(e) => warn!(
                "Startup recovery: failed to notify chat {} ({}) about interrupted turn: {e}",
                turn.chat_id, turn.channel
            ),
        }
    }
    info!(
        "Startup recovery: {notified} chat(s) notified about interrupted turns, {skipped} stale turn(s) dropped"
    );
}

#[cfg(test)]
mod tests {
    use super::interruption_notice;

    #[test]
    fn notice_includes_progress_when_available() {
        let plain = interruption_notice(None);
        assert!(plain.contains("restarted"));
        assert!(!plain.contains("gotten as far as"));
        // Blank progress is treated like no progress.
        assert_eq!(interruption_notice(Some("   ")), plain);

        let with = interruption_notice(Some("step 4: web_search, execute_command"));
        assert!(with.contains("step 4: web_search, execute_command"));
        assert!(with.starts_with(&plain));
    }
}
