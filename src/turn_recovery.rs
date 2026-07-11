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

fn interruption_notice() -> &'static str {
    "⚠️ I was restarted while working on your last message, so that reply was \
     lost. Please send it again (or tell me to continue) if you still need it."
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
    for (chat_id, channel, started_at) in turns {
        let fresh = chrono::DateTime::parse_from_rfc3339(&started_at)
            .map(|t| now.signed_duration_since(t.with_timezone(&chrono::Utc)))
            .map(|age| age < chrono::Duration::hours(NOTIFY_MAX_AGE_HOURS))
            .unwrap_or(false);
        if !fresh {
            skipped += 1;
            continue;
        }
        let bot_username = state.config.bot_username_for_channel(&channel);
        match deliver_and_store_bot_message(
            state.channel_registry.as_ref(),
            state.db.clone(),
            &bot_username,
            chat_id,
            interruption_notice(),
        )
        .await
        {
            Ok(()) => notified += 1,
            Err(e) => warn!(
                "Startup recovery: failed to notify chat {chat_id} ({channel}) about interrupted turn: {e}"
            ),
        }
    }
    info!(
        "Startup recovery: {notified} chat(s) notified about interrupted turns, {skipped} stale turn(s) dropped"
    );
}
