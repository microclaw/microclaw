use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use chrono::Utc;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::{Duration, Instant, MissedTickBehavior};
use tracing::{error, info, warn};

/// Max number of distinct chats whose due tasks run concurrently per tick.
/// Bounds load on the LLM provider and DB while still letting independent
/// chats' tasks make progress in parallel.
const MAX_CONCURRENT_SCHEDULED_TASKS: usize = 4;
/// Wall-clock cap for a single scheduled task's agent run. A hung run is
/// stopped, marked failed (and DLQ'd) rather than pinning a slot indefinitely.
const SCHEDULED_TASK_TIMEOUT_SECS: u64 = 600;

use crate::agent_engine::process_with_agent;
use crate::agent_engine::AgentRequestContext;
use crate::memory_service::apply_reflector_extractions;
use crate::runtime::AppState;
use microclaw_channels::channel::{
    deliver_and_store_bot_message, get_chat_routing, ChatRouting, ConversationKind,
};
use microclaw_core::llm_types::{Message, MessageContent, ResponseContentBlock};
use microclaw_core::text::floor_char_boundary;
use microclaw_storage::db::call_blocking;

pub fn spawn_scheduler(state: Arc<AppState>) {
    tokio::spawn(async move {
        info!("Scheduler started");
        if let Ok(recovered) =
            call_blocking(state.db.clone(), move |db| db.recover_running_tasks()).await
        {
            if recovered > 0 {
                warn!(
                    "Scheduler: recovered {} task(s) left in running state from previous process",
                    recovered
                );
            }
        }
        // Run once at startup so overdue tasks are not delayed until the first tick.
        run_due_tasks(&state).await;

        // Align polling to wall-clock minute boundaries for stable "every minute" behavior.
        let now = Utc::now();
        let secs_into_minute = now.timestamp().rem_euclid(60) as u64;
        let nanos = now.timestamp_subsec_nanos() as u64;
        let mut delay = Duration::from_secs(60 - secs_into_minute);
        if secs_into_minute == 0 {
            delay = Duration::from_secs(60);
        }
        delay = delay.saturating_sub(Duration::from_nanos(nanos));

        let mut ticker = tokio::time::interval_at(Instant::now() + delay, Duration::from_secs(60));
        // If processing falls behind, skip missed ticks instead of burst catch-up runs.
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            ticker.tick().await;
            run_due_tasks(&state).await;
        }
    });
}

fn resolve_task_timezone(task_timezone: &str, default_timezone: &str) -> chrono_tz::Tz {
    if !task_timezone.trim().is_empty() {
        if let Ok(tz) = task_timezone.parse() {
            return tz;
        }
    }
    default_timezone.parse().unwrap_or(chrono_tz::Tz::UTC)
}

fn is_retryable_delivery_rate_limit(error_text: &str) -> bool {
    let lower = error_text.to_ascii_lowercase();
    lower.contains("rate limit")
        || lower.contains("429")
        || lower.contains("too many requests")
        || lower.contains("too many request")
        || lower.contains("too many")
        || lower.contains("频控")
        || lower.contains("限流")
        || lower.contains("请求过于频繁")
}

async fn deliver_scheduler_message_with_backoff(
    state: &Arc<AppState>,
    bot_username: &str,
    chat_id: i64,
    text: &str,
) -> Result<(), String> {
    let mut attempt = 0u32;
    let max_attempts = 3u32;
    loop {
        match deliver_and_store_bot_message(
            &state.channel_registry,
            state.db.clone(),
            bot_username,
            chat_id,
            text,
        )
        .await
        {
            Ok(()) => return Ok(()),
            Err(err) if attempt + 1 < max_attempts && is_retryable_delivery_rate_limit(&err) => {
                attempt += 1;
                let delay = Duration::from_secs(2u64.pow(attempt));
                warn!(
                    "Scheduler: delivery for chat {} hit rate limit, retrying in {:?} (attempt {}/{})",
                    chat_id, delay, attempt, max_attempts
                );
                tokio::time::sleep(delay).await;
            }
            Err(err) => return Err(err),
        }
    }
}

async fn run_due_tasks(state: &Arc<AppState>) {
    let now = Utc::now().to_rfc3339();
    let now_for_claim = now.clone();
    let tasks = match call_blocking(state.db.clone(), move |db| {
        db.claim_due_tasks(&now_for_claim, 200)
    })
    .await
    {
        Ok(t) => t,
        Err(e) => {
            error!("Scheduler: failed to query due tasks: {e}");
            return;
        }
    };

    if tasks.is_empty() {
        // Per-tick heartbeat at debug so an operator can confirm the poll loop
        // is alive without flooding info logs every minute.
        tracing::debug!("Scheduler: tick at {now}, no due tasks");
        return;
    }
    info!("Scheduler: {} due task(s) claimed at {}", tasks.len(), now);

    // Run distinct chats concurrently (bounded), but tasks WITHIN one chat
    // sequentially — two tasks for the same chat would otherwise race on that
    // chat's session/history. A single slow or hung task no longer blocks
    // unrelated chats' tasks for the rest of the tick.
    let mut by_chat: HashMap<i64, Vec<microclaw_storage::db::ScheduledTask>> = HashMap::new();
    for task in tasks {
        by_chat.entry(task.chat_id).or_default().push(task);
    }
    let sem = Arc::new(Semaphore::new(MAX_CONCURRENT_SCHEDULED_TASKS));
    let mut set = JoinSet::new();
    for (_chat_id, chat_tasks) in by_chat {
        let state = state.clone();
        let sem = sem.clone();
        set.spawn(async move {
            // One permit per chat group; bounds total concurrency across chats.
            let _permit = sem.acquire_owned().await;
            for task in chat_tasks {
                run_one_due_task(state.clone(), task).await;
            }
        });
    }
    while set.join_next().await.is_some() {}
}

/// Execute a single claimed scheduled task end-to-end: run the agent (bounded by
/// a wall-clock timeout so a hung run can't pin a slot forever), deliver the
/// reply, log the run, enqueue a DLQ entry on failure, and reschedule (or mark
/// terminal). Failures and timeouts are surfaced — never silently swallowed.
async fn run_one_due_task(state: Arc<AppState>, task: microclaw_storage::db::ScheduledTask) {
    info!(
        "Scheduler: executing task #{} for chat {} (schedule {}='{}', was due at {})",
        task.id, task.chat_id, task.schedule_type, task.schedule_value, task.next_run,
    );

    let started_at = Utc::now();
    let started_at_str = started_at.to_rfc3339();
    let routing = get_chat_routing(&state.channel_registry, state.db.clone(), task.chat_id)
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| {
            warn!(
                "Scheduler: no chat routing found for chat {}, defaulting to telegram/private",
                task.chat_id
            );
            ChatRouting {
                channel_name: "telegram".to_string(),
                conversation: ConversationKind::Private,
            }
        });

    // Run agent loop with the task prompt, bounded by a wall-clock timeout.
    let agent_future = process_with_agent(
        &state,
        AgentRequestContext {
            caller_channel: &routing.channel_name,
            chat_id: task.chat_id,
            chat_type: routing.conversation.as_agent_chat_type(),
        },
        Some(&task.prompt),
        None,
    );
    let timeout = Duration::from_secs(SCHEDULED_TASK_TIMEOUT_SECS);
    let (success, result_summary) = match tokio::time::timeout(timeout, agent_future).await {
        Err(_elapsed) => {
            error!(
                "Scheduler: task #{} timed out after {}s",
                task.id, SCHEDULED_TASK_TIMEOUT_SECS
            );
            let bot_username = state.config.bot_username_for_channel(&routing.channel_name);
            let err_text = format!(
                "Scheduled task #{} timed out after {}s and was stopped.",
                task.id, SCHEDULED_TASK_TIMEOUT_SECS
            );
            let _ = deliver_scheduler_message_with_backoff(
                &state,
                &bot_username,
                task.chat_id,
                &err_text,
            )
            .await;
            (
                false,
                Some(format!("Timed out after {}s", SCHEDULED_TASK_TIMEOUT_SECS)),
            )
        }
        Ok(Ok(response)) => {
            if !response.is_empty() {
                let bot_username = state.config.bot_username_for_channel(&routing.channel_name);
                if let Err(delivery_err) = deliver_scheduler_message_with_backoff(
                    &state,
                    &bot_username,
                    task.chat_id,
                    &response,
                )
                .await
                {
                    error!(
                        "Scheduler: task #{} generated a reply but delivery failed: {}",
                        task.id, delivery_err
                    );
                    (false, Some(format!("Delivery error: {delivery_err}")))
                } else {
                    let summary = if response.len() > 200 {
                        format!("{}...", &response[..floor_char_boundary(&response, 200)])
                    } else {
                        response
                    };
                    (true, Some(summary))
                }
            } else {
                (true, None)
            }
        }
        Ok(Err(e)) => {
            error!("Scheduler: task #{} failed: {e}", task.id);
            let err_text = format!("Scheduled task #{} failed: {e}", task.id);
            let bot_username = state.config.bot_username_for_channel(&routing.channel_name);
            let summary = match deliver_scheduler_message_with_backoff(
                &state,
                &bot_username,
                task.chat_id,
                &err_text,
            )
            .await
            {
                Ok(()) => format!("Error: {e}"),
                Err(delivery_err) => {
                    warn!(
                        "Scheduler: failed to notify chat {} about task #{} failure: {}",
                        task.chat_id, task.id, delivery_err
                    );
                    format!("Error: {e}; delivery error: {delivery_err}")
                }
            };
            (false, Some(summary))
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

    if !success {
        let started_for_dlq = started_at_str.clone();
        let finished_for_dlq = finished_at_str.clone();
        let dlq_summary = result_summary.clone();
        if let Err(e) = call_blocking(state.db.clone(), move |db| {
            db.insert_scheduled_task_dlq(
                task.id,
                task.chat_id,
                &started_for_dlq,
                &finished_for_dlq,
                duration_ms,
                dlq_summary.as_deref(),
            )?;
            Ok(())
        })
        .await
        {
            error!("Scheduler: failed to enqueue DLQ for task #{}: {e}", task.id);
        }
    }

    // Compute next run (prefer task-specific timezone; fallback to app timezone).
    let tz = resolve_task_timezone(&task.timezone, &state.config.timezone);
    let next_run = if task.schedule_type == "cron" {
        match cron::Schedule::from_str(&task.schedule_value) {
            Ok(schedule) => schedule
                .upcoming(tz)
                .next()
                .map(|t| t.with_timezone(&chrono::Utc).to_rfc3339()),
            Err(e) => {
                error!("Scheduler: invalid cron for task #{}: {e}", task.id);
                None
            }
        }
    } else {
        None // one-shot
    };

    match &next_run {
        Some(nr) => info!(
            "Scheduler: task #{} finished (success={}, {}ms); next run at {}",
            task.id, success, duration_ms, nr
        ),
        None => info!(
            "Scheduler: one-shot task #{} finished (success={}, {}ms); marked {}",
            task.id,
            success,
            duration_ms,
            if success { "completed" } else { "failed" }
        ),
    }

    let started_for_update = started_at_str.clone();
    if let Err(e) = call_blocking(state.db.clone(), move |db| {
        db.update_task_after_run(task.id, &started_for_update, next_run.as_deref(), success)?;
        Ok(())
    })
    .await
    {
        error!("Scheduler: failed to update task #{}: {e}", task.id);
    }
}

/// What to do with a dead-lettered task during the auto-replay sweep.
#[derive(Debug, PartialEq, Eq)]
enum DlqReplayAction {
    /// Re-activate the task for one more attempt.
    Requeue,
    /// Out of attempts — leave it in the DLQ for manual inspection.
    GiveUp,
    /// Not eligible (e.g. a cron task that reschedules itself, or a task that
    /// was cancelled/completed since it failed).
    Skip,
}

/// Pure replay decision so the policy is unit-testable without a DB.
///
/// Auto-replay only rescues tasks currently in `failed` state — i.e. one-shot
/// tasks that hit a transient failure. Recurring (cron) tasks reschedule
/// themselves on the next tick, so requeueing them would just run them
/// off-schedule. `failure_count` is the cumulative number of DLQ entries for
/// the task; once it reaches `max_attempts` we stop and leave it for a human.
fn dlq_replay_action(task_status: &str, failure_count: u32, max_attempts: u32) -> DlqReplayAction {
    if task_status != "failed" {
        return DlqReplayAction::Skip;
    }
    if failure_count >= max_attempts {
        return DlqReplayAction::GiveUp;
    }
    DlqReplayAction::Requeue
}

/// Periodically retry scheduled tasks that landed in the dead-letter queue.
/// A one-shot task that failed transiently is re-activated for another attempt,
/// bounded by `dlq_max_replay_attempts`; after that it's left in the DLQ for
/// manual inspection. OFF only if `dlq_replay_enabled` is false.
pub fn spawn_dlq_replay(state: Arc<AppState>) {
    if !state.config.dlq_replay_enabled {
        info!("DLQ auto-replay disabled by config");
        return;
    }
    let interval_secs = state.config.dlq_replay_interval_secs.max(30);
    tokio::spawn(async move {
        info!("DLQ auto-replay started (interval: {}s)", interval_secs);
        let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            run_dlq_replay(&state).await;
        }
    });
}

async fn run_dlq_replay(state: &Arc<AppState>) {
    let max_attempts = state.config.dlq_max_replay_attempts.max(1);
    let entries = match call_blocking(state.db.clone(), |db| {
        db.list_scheduled_task_dlq(None, None, false, 100)
    })
    .await
    {
        Ok(v) => v,
        Err(e) => {
            warn!("DLQ auto-replay: failed to list dead-lettered tasks: {e}");
            return;
        }
    };
    if entries.is_empty() {
        return;
    }

    let now = Utc::now().to_rfc3339();
    let mut requeued = 0usize;
    for entry in entries {
        let task_id = entry.task_id;
        let dlq_id = entry.id;

        let task = call_blocking(state.db.clone(), move |db| db.get_task_by_id(task_id))
            .await
            .ok()
            .flatten();
        let Some(task) = task else {
            // Parent task is gone; close out the DLQ entry so we don't rescan it.
            let _ = call_blocking(state.db.clone(), move |db| {
                db.mark_scheduled_task_dlq_replayed(dlq_id, Some("task no longer exists"))
            })
            .await;
            continue;
        };

        // Cumulative failure count for this task == number of DLQ rows.
        let failure_count = call_blocking(state.db.clone(), move |db| {
            db.list_scheduled_task_dlq(None, Some(task_id), true, 1000)
        })
        .await
        .map(|v| v.len() as u32)
        .unwrap_or(0);

        match dlq_replay_action(&task.status, failure_count, max_attempts) {
            DlqReplayAction::Skip => {
                let _ = call_blocking(state.db.clone(), move |db| {
                    db.mark_scheduled_task_dlq_replayed(
                        dlq_id,
                        Some("task not in failed state; no replay needed"),
                    )
                })
                .await;
            }
            DlqReplayAction::GiveUp => {
                warn!(
                    "DLQ auto-replay: task #{} exhausted {} attempt(s); leaving in DLQ for manual inspection",
                    task_id, max_attempts
                );
                let _ = call_blocking(state.db.clone(), move |db| {
                    db.mark_scheduled_task_dlq_replayed(
                        dlq_id,
                        Some("max replay attempts reached; left for manual inspection"),
                    )
                })
                .await;
            }
            DlqReplayAction::Requeue => {
                let now_for_requeue = now.clone();
                let ok = call_blocking(state.db.clone(), move |db| {
                    db.requeue_scheduled_task(task_id, &now_for_requeue)
                })
                .await
                .unwrap_or(false);
                if ok {
                    let note = format!("auto-replay attempt {failure_count}/{max_attempts}");
                    let _ = call_blocking(state.db.clone(), move |db| {
                        db.mark_scheduled_task_dlq_replayed(dlq_id, Some(&note))
                    })
                    .await;
                    info!(
                        "DLQ auto-replay: requeued task #{} (attempt {}/{})",
                        task_id, failure_count, max_attempts
                    );
                    requeued += 1;
                } else {
                    warn!("DLQ auto-replay: failed to requeue task #{}", task_id);
                }
            }
        }
    }
    if requeued > 0 {
        info!("DLQ auto-replay: requeued {requeued} task(s) for retry");
    }
}

const REFLECTOR_SYSTEM_PROMPT: &str = r#"You are a memory extraction specialist. Extract durable, factual information from conversations.

Rules:
- Extract ONLY concrete facts, preferences, expertise, or notable events
- IGNORE: greetings, small talk, unanswered questions, transient requests
- Each memory < 100 characters, specific and concrete
- Category must be exactly one of: PROFILE (user attributes/preferences), KNOWLEDGE (facts/expertise), EVENT (significant things that happened)
- ALSO capture how the user likes to COMMUNICATE as PROFILE memories when there's a clear, repeated signal: preferred language, short vs. detailed answers, formal vs. casual tone, emoji or no emoji, wants code/links vs. prose. E.g. "prefers concise, no-fluff answers", "writes in Chinese", "likes step-by-step detail". These help the bot match the user's style.
- If a new memory updates or supersedes an existing one, add "supersedes_id": <id> to replace it

Output format — a JSON object with three fields:
{
  "memories": [{"content":"...","category":"PROFILE","supersedes_id":null}],
  "triples": [{"subject":"User","predicate":"prefers","object":"Rust"}],
  "user_model": "..." | null
}

"memories" — flat text memories (same as before).
"triples" — structured entity relationships for the knowledge graph. Extract these when you see clear subject-predicate-object patterns:
  - subject: an entity name (person, project, service, tool)
  - predicate: a relationship (uses, prefers, located_at, version_is, works_on, manages, depends_on)
  - object: the related entity or value
  Only extract triples with clear, factual relationships. Skip vague or uncertain ones.
"user_model" — an updated USER.md narrative (single short paragraph or bullet list) describing who the user is: role, expertise, working style, preferences, ongoing goals.
  - Set to a string when you have new durable information that materially improves the current USER.md, or when none exists yet and there is enough signal to draft one.
  - Set to null when the existing USER.md is still accurate; do not rewrite cosmetically.
  - Output ONLY the file content — no commentary, no code fences. Drop stale or contradicted facts. Never invent.
  - Also keep a short "Working with them" note when you have evidence: what approaches land well with this person and what to avoid (e.g. "prefers a draft over questions", "wants the bottom line first then detail", "reacts badly to over-explaining", "appreciates a light tone"). Update it as you learn — this is how you get better at working with THIS person over time. Base it only on observed reactions, never assumptions.

If nothing worth remembering: {"memories":[],"triples":[],"user_model":null}

CRITICAL — how to memorize bugs and problems:
- NEVER describe broken behavior as a fact (e.g. "tool calls were broken", "agent typed tool calls as text"). This causes the agent to repeat the broken behavior in future sessions.
- Instead, frame bugs as ACTION ITEMS with the correct behavior. Use "TODO: fix" or "ensure" phrasing that tells the agent what TO DO, not what went wrong.
- Examples:
  BAD: "proactive-agent skill broke tool calling — tool calls posted as text" (agent reads this and keeps doing it)
  GOOD: "TODO: ensure tool calls always execute via tool system, never output as plain text"
  BAD: "got 401 authentication error on Discord"
  GOOD: "TODO: check API key config if Discord auth fails"
  BAD: "user said agent isn't following instructions"
  GOOD: "TODO: strictly follow TOOLS.md rules for every tool call"
- The memory should tell the agent HOW TO BEHAVE CORRECTLY, never describe the broken behavior."#;

#[cfg(feature = "sqlite-vec")]
async fn backfill_embeddings(state: &Arc<AppState>) {
    if state.embedding.is_none() {
        return;
    }
    let pending = match call_blocking(state.db.clone(), move |db| {
        db.get_memories_without_embedding(None, 50)
    })
    .await
    {
        Ok(rows) => rows,
        Err(_) => return,
    };
    for mem in pending {
        let _ = crate::memory_service::upsert_memory_embedding(state, mem.id, &mem.content).await;
    }
}

pub fn spawn_reflector(state: Arc<AppState>) {
    if !state.config.reflector_enabled {
        info!("Reflector disabled by config");
        return;
    }
    let interval_secs = state.config.reflector_interval_mins * 60;
    tokio::spawn(async move {
        info!(
            "Reflector started (interval: {}min)",
            state.config.reflector_interval_mins
        );
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;
            run_reflector(&state).await;
        }
    });
}

/// Proactive task standup: periodically post a one-line status for chats whose
/// sub-agents have been running a while. Off by default (it sends unprompted
/// messages); heavily throttled so it never spams.
pub fn spawn_task_standup(state: Arc<AppState>) {
    if !state.config.subagents.standup.enabled {
        return;
    }
    let interval_secs = state.config.subagents.standup.interval_secs.max(60);
    tokio::spawn(async move {
        info!("Task standup started (interval: {}s)", interval_secs);
        // Per-chat last standup time, so each chat gets at most one per interval.
        let mut last_standup: HashMap<i64, Instant> = HashMap::new();
        let mut ticker = tokio::time::interval(Duration::from_secs(60));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            run_task_standup(&state, interval_secs, &mut last_standup).await;
        }
    });
}

async fn run_task_standup(
    state: &Arc<AppState>,
    interval_secs: u64,
    last_standup: &mut HashMap<i64, Instant>,
) {
    let runs = match call_blocking(state.db.clone(), |db| db.list_active_subagent_runs()).await {
        Ok(v) => v,
        Err(e) => {
            warn!("task standup: failed to list active runs: {e}");
            return;
        }
    };
    if runs.is_empty() {
        return;
    }

    // Group active runs by chat.
    let mut by_chat: HashMap<i64, Vec<microclaw_storage::db::SubagentRunRecord>> = HashMap::new();
    for run in runs {
        by_chat.entry(run.chat_id).or_default().push(run);
    }

    let now = Utc::now();
    for (chat_id, chat_runs) in by_chat {
        // Only nudge when at least one task has been running longer than the
        // interval — short tasks are covered by their own completion message.
        let oldest_age_secs = chat_runs
            .iter()
            .filter_map(|r| chrono::DateTime::parse_from_rfc3339(&r.created_at).ok())
            .map(|c| (now - c.with_timezone(&Utc)).num_seconds())
            .max()
            .unwrap_or(0);
        if oldest_age_secs < interval_secs as i64 {
            continue;
        }
        // At most one standup per chat per interval.
        let due = last_standup
            .get(&chat_id)
            .map(|t| t.elapsed().as_secs() >= interval_secs)
            .unwrap_or(true);
        if !due {
            continue;
        }

        let channel = chat_runs
            .first()
            .map(|r| r.caller_channel.clone())
            .unwrap_or_default();
        let avg_duration_secs = call_blocking(state.db.clone(), move |db| {
            db.avg_completed_subagent_duration_secs(chat_id)
        })
        .await
        .ok()
        .flatten();
        let message = format_standup(&chat_runs, now, interval_secs, avg_duration_secs);
        let bot_username = state.config.bot_username_for_channel(&channel);
        match deliver_and_store_bot_message(
            &state.channel_registry,
            state.db.clone(),
            &bot_username,
            chat_id,
            &message,
        )
        .await
        {
            Ok(_) => {
                last_standup.insert(chat_id, Instant::now());
            }
            Err(e) => warn!("task standup: delivery failed for chat {chat_id}: {e}"),
        }
    }
}

/// Proactive long-silence check-in: after a chat has been quiet for a while,
/// let the agent reach out IF it has something genuinely useful to say.
/// OFF by default — outward-facing and uses an LLM call per idle chat.
pub fn spawn_idle_checkin(state: Arc<AppState>) {
    if !state.config.idle_checkin.enabled {
        return;
    }
    tokio::spawn(async move {
        info!(
            "Idle check-in started (idle_hours={}, min_interval_hours={})",
            state.config.idle_checkin.idle_hours, state.config.idle_checkin.min_interval_hours
        );
        let mut last_checkin: HashMap<i64, Instant> = HashMap::new();
        let mut ticker = tokio::time::interval(Duration::from_secs(1800));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            run_idle_checkin(&state, &mut last_checkin).await;
        }
    });
}

const IDLE_CHECKIN_PROMPT: &str = "[Proactive idle check-in] This chat has been quiet for a while. \
Review what you know about this user and any pending follow-ups, due reminders, or promises you made.\n\
- If — and ONLY if — you have something genuinely useful or kind to say right now (a due follow-up, a \
relevant update, a gentle nudge on something they asked for), write ONE short, friendly message.\n\
- Otherwise, reply with exactly: SKIP\n\
Do not invent reasons to message; silence is the right default. Do not use the send_message tool — just \
return the message text, or SKIP.";

async fn run_idle_checkin(state: &Arc<AppState>, last_checkin: &mut HashMap<i64, Instant>) {
    let idle_hours = state.config.idle_checkin.idle_hours.max(1) as i64;
    let min_interval = Duration::from_secs(
        state
            .config
            .idle_checkin
            .min_interval_hours
            .max(1)
            .saturating_mul(3600),
    );
    let cutoff = (Utc::now() - chrono::Duration::hours(idle_hours)).to_rfc3339();
    let chats = match call_blocking(state.db.clone(), move |db| db.list_idle_chats(&cutoff, 100))
        .await
    {
        Ok(v) => v,
        Err(e) => {
            warn!("idle check-in: failed to list idle chats: {e}");
            return;
        }
    };

    for chat_id in chats {
        // Respect the per-chat min interval.
        if let Some(t) = last_checkin.get(&chat_id) {
            if t.elapsed() < min_interval {
                continue;
            }
        }
        // Skip chats with active background work — they get their own updates.
        let active = call_blocking(state.db.clone(), move |db| {
            db.count_active_subagent_runs_for_chat(chat_id)
        })
        .await
        .unwrap_or(0);
        if active > 0 {
            continue;
        }

        let routing = match get_chat_routing(&state.channel_registry, state.db.clone(), chat_id)
            .await
            .ok()
            .flatten()
        {
            Some(r) => r,
            None => continue,
        };

        let response = match process_with_agent(
            state,
            AgentRequestContext {
                caller_channel: &routing.channel_name,
                chat_id,
                chat_type: routing.conversation.as_agent_chat_type(),
            },
            Some(IDLE_CHECKIN_PROMPT),
            None,
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!("idle check-in: agent run failed for chat {chat_id}: {e}");
                last_checkin.insert(chat_id, Instant::now());
                continue;
            }
        };

        // Mark as checked-in regardless, so we don't retry every tick.
        last_checkin.insert(chat_id, Instant::now());

        let trimmed = response.trim();
        if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("skip") {
            continue;
        }

        let bot_username = state.config.bot_username_for_channel(&routing.channel_name);
        if let Err(e) = deliver_and_store_bot_message(
            &state.channel_registry,
            state.db.clone(),
            &bot_username,
            chat_id,
            trimmed,
        )
        .await
        {
            warn!("idle check-in: delivery failed for chat {chat_id}: {e}");
        }
    }
}

/// OpenClaw-style proactive heartbeat: every `interval_mins`, read each chat's
/// `runtime/groups/<chat_id>/HEARTBEAT.md` checklist and run an agent turn over
/// it. The agent may use tools to check on items and messages the chat only
/// when something genuinely needs attention (otherwise it replies SKIP and the
/// sweep stays silent). OFF by default; chats without a HEARTBEAT.md are never
/// touched, so enabling the loop alone changes nothing until a user (or the
/// agent, via write_file) creates a checklist.
pub fn spawn_heartbeat(state: Arc<AppState>) {
    if !state.config.heartbeat.enabled {
        return;
    }
    tokio::spawn(async move {
        let interval_mins = state.config.heartbeat.interval_mins.max(1);
        info!("Heartbeat started (interval_mins={interval_mins})");
        let mut ticker = tokio::time::interval(Duration::from_secs(interval_mins * 60));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        // First tick fires immediately; skip it so a restart doesn't
        // instantly re-run every checklist.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            run_heartbeat(&state).await;
        }
    });
}

const HEARTBEAT_PROMPT_PREFIX: &str = "[Heartbeat] Periodic proactive check for this chat. Below is \
the chat's HEARTBEAT.md checklist, maintained by the user (and you, via file tools).\n\
- Work through the items. Use tools where needed to check on things (schedules, files, web, memory).\n\
- If — and ONLY if — something needs the user's attention right now, write ONE short message about it.\n\
- If nothing needs attention, reply with exactly: SKIP\n\
Silence is the right default; do not narrate checks that came back clean. Do not use the send_message \
tool — just return the message text, or SKIP.\n\n--- HEARTBEAT.md ---\n";

/// Collect `(chat_id, checklist)` pairs from `<groups_dir>/<chat_id>/HEARTBEAT.md`.
/// Non-numeric directory names and empty/unreadable files are skipped.
fn heartbeat_checklists(groups_dir: &std::path::Path, max_chars: usize) -> Vec<(i64, String)> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(groups_dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let Some(chat_id) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<i64>().ok())
        else {
            continue;
        };
        let Ok(content) = std::fs::read_to_string(entry.path().join("HEARTBEAT.md")) else {
            continue;
        };
        let trimmed = content.trim();
        if trimmed.is_empty() {
            continue;
        }
        let capped = if trimmed.len() > max_chars {
            let end = floor_char_boundary(trimmed, max_chars);
            format!("{}\n[... truncated at {max_chars} chars]", &trimmed[..end])
        } else {
            trimmed.to_string()
        };
        out.push((chat_id, capped));
    }
    out.sort_by_key(|(id, _)| *id);
    out
}

async fn run_heartbeat(state: &Arc<AppState>) {
    let groups_dir = crate::agent_engine::effective_runtime_data_dir(&state.config).join("groups");
    let checklists = heartbeat_checklists(&groups_dir, state.config.heartbeat.max_chars);
    if checklists.is_empty() {
        return;
    }
    for (chat_id, checklist) in checklists {
        // Chats with active background work already get their own updates.
        let active = call_blocking(state.db.clone(), move |db| {
            db.count_active_subagent_runs_for_chat(chat_id)
        })
        .await
        .unwrap_or(0);
        if active > 0 {
            continue;
        }

        let routing = match get_chat_routing(&state.channel_registry, state.db.clone(), chat_id)
            .await
            .ok()
            .flatten()
        {
            Some(r) => r,
            None => continue,
        };

        let prompt = format!("{HEARTBEAT_PROMPT_PREFIX}{checklist}");
        let response = match process_with_agent(
            state,
            AgentRequestContext {
                caller_channel: &routing.channel_name,
                chat_id,
                chat_type: routing.conversation.as_agent_chat_type(),
            },
            Some(&prompt),
            None,
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!("heartbeat: agent run failed for chat {chat_id}: {e}");
                continue;
            }
        };

        let trimmed = response.trim();
        if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("skip") {
            continue;
        }

        let bot_username = state.config.bot_username_for_channel(&routing.channel_name);
        if let Err(e) = deliver_and_store_bot_message(
            &state.channel_registry,
            state.db.clone(),
            &bot_username,
            chat_id,
            trimmed,
        )
        .await
        {
            warn!("heartbeat: delivery failed for chat {chat_id}: {e}");
        }
    }
}

/// "Sleep-time" memory consolidation loop: when a chat has been idle for a while,
/// run a deterministic (no-LLM) pass that archives near-duplicate memories so the
/// store stops accumulating redundancy between reflector runs. OFF by default.
pub fn spawn_memory_consolidation(state: Arc<AppState>) {
    if !state.config.sleep_time.enabled {
        return;
    }
    tokio::spawn(async move {
        info!(
            "Sleep-time consolidation started (idle_hours={}, min_interval_hours={}, threshold={})",
            state.config.sleep_time.idle_hours,
            state.config.sleep_time.min_interval_hours,
            state.config.sleep_time.similarity_threshold
        );
        let mut last_run: HashMap<i64, Instant> = HashMap::new();
        let mut ticker = tokio::time::interval(Duration::from_secs(1800));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            run_memory_consolidation(&state, &mut last_run).await;
        }
    });
}

async fn run_memory_consolidation(state: &Arc<AppState>, last_run: &mut HashMap<i64, Instant>) {
    let cfg = &state.config.sleep_time;
    let idle_hours = cfg.idle_hours.max(1) as i64;
    let min_interval = Duration::from_secs(cfg.min_interval_hours.max(1).saturating_mul(3600));
    let threshold = cfg.similarity_threshold;
    let max_archived = cfg.max_archived_per_pass.max(1);
    let cutoff = (Utc::now() - chrono::Duration::hours(idle_hours)).to_rfc3339();

    let chats = match call_blocking(state.db.clone(), move |db| db.list_idle_chats(&cutoff, 100))
        .await
    {
        Ok(v) => v,
        Err(e) => {
            warn!("sleep-time consolidation: failed to list idle chats: {e}");
            return;
        }
    };

    for chat_id in chats {
        // Respect the per-chat min interval.
        if let Some(t) = last_run.get(&chat_id) {
            if t.elapsed() < min_interval {
                continue;
            }
        }

        let memories = match call_blocking(state.db.clone(), move |db| {
            db.get_all_memories_for_chat(Some(chat_id))
        })
        .await
        {
            Ok(m) => m,
            Err(e) => {
                warn!("sleep-time consolidation: failed to load memories for chat {chat_id}: {e}");
                continue;
            }
        };

        let now = Utc::now().to_rfc3339();
        // Active, non-expired memories, sorted best-first (confidence desc, recency desc)
        // so the strongest member of each duplicate group is the one kept.
        let mut active: Vec<_> = memories
            .into_iter()
            .filter(|m| !m.is_archived)
            .filter(|m| m.expires_at.as_deref().map(|e| e > now.as_str()).unwrap_or(true))
            .collect();
        active.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| b.last_seen_at.cmp(&a.last_seen_at))
        });

        let items: Vec<crate::memory_service::ConsolidationItem> = active
            .iter()
            .map(|m| crate::memory_service::ConsolidationItem {
                id: m.id,
                content: m.content.clone(),
                category: m.category.clone(),
            })
            .collect();
        let to_archive = crate::memory_service::select_duplicate_memories_to_archive(
            &items,
            threshold,
            max_archived,
        );

        // Mark the chat as processed regardless, so we don't rescan every tick.
        last_run.insert(chat_id, Instant::now());

        if to_archive.is_empty() {
            continue;
        }

        let mut archived = 0usize;
        for id in &to_archive {
            let id = *id;
            match call_blocking(state.db.clone(), move |db| db.archive_memory(id)).await {
                Ok(true) => archived += 1,
                Ok(false) => {}
                Err(e) => warn!("sleep-time consolidation: archive {id} failed: {e}"),
            }
        }
        if archived > 0 {
            info!(
                "Sleep-time consolidation: archived {} duplicate memories in chat {}",
                archived, chat_id
            );
        }
    }
}

/// "Inner thoughts" interjection: in an active group chat where the bot wasn't
/// addressed, occasionally evaluate whether it has something genuinely worth
/// saying and, if so, chime in once. OFF by default — outward-facing and uses
/// an LLM call per evaluation.
pub fn spawn_interjection(state: Arc<AppState>) {
    if !state.config.interjection.enabled {
        return;
    }
    tokio::spawn(async move {
        info!(
            "Interjection started (min_interval_secs={}, lookback_mins={})",
            state.config.interjection.min_interval_secs, state.config.interjection.lookback_mins
        );
        let mut last_interjection: HashMap<i64, Instant> = HashMap::new();
        let mut ticker = tokio::time::interval(Duration::from_secs(120));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            run_interjection(&state, &mut last_interjection).await;
        }
    });
}

const INTERJECTION_PROMPT: &str = "[Group interjection check] You were NOT addressed in this group, \
but the recent conversation is visible to you.\n\
- Only if you have something genuinely valuable, welcome, and on-topic to add (a useful fact, a \
correction of a clear factual error, a helpful pointer), write ONE short message that fits in \
naturally.\n\
- Otherwise — which is most of the time — reply with exactly: SKIP\n\
Do not butt in, do not police the conversation, do not restate what others said. When in doubt, \
SKIP. Do not use the send_message tool — just return the message, or SKIP.";

async fn run_interjection(state: &Arc<AppState>, last_interjection: &mut HashMap<i64, Instant>) {
    let min_interval = Duration::from_secs(state.config.interjection.min_interval_secs.max(60));
    let lookback = state.config.interjection.lookback_mins.max(1) as i64;
    let since = (Utc::now() - chrono::Duration::minutes(lookback)).to_rfc3339();
    let chats = match call_blocking(state.db.clone(), move |db| {
        db.get_active_chat_ids_since(&since)
    })
    .await
    {
        Ok(v) => v,
        Err(e) => {
            warn!("interjection: failed to list active chats: {e}");
            return;
        }
    };

    for chat_id in chats {
        if let Some(t) = last_interjection.get(&chat_id) {
            if t.elapsed() < min_interval {
                continue;
            }
        }

        let routing = match get_chat_routing(&state.channel_registry, state.db.clone(), chat_id)
            .await
            .ok()
            .flatten()
        {
            Some(r) => r,
            None => continue,
        };
        // Interjection only makes sense in group conversations.
        if !matches!(routing.conversation, ConversationKind::Group) {
            continue;
        }

        // Only consider chats with messages the bot hasn't responded to yet.
        let pending = call_blocking(state.db.clone(), move |db| {
            db.get_messages_since_last_bot_response(chat_id, 50, 50)
        })
        .await
        .unwrap_or_default();
        if !pending.iter().any(|m| !m.is_from_bot) {
            continue;
        }

        let response = match process_with_agent(
            state,
            AgentRequestContext {
                caller_channel: &routing.channel_name,
                chat_id,
                chat_type: routing.conversation.as_agent_chat_type(),
            },
            Some(INTERJECTION_PROMPT),
            None,
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!("interjection: agent run failed for chat {chat_id}: {e}");
                last_interjection.insert(chat_id, Instant::now());
                continue;
            }
        };

        // Mark regardless so we don't re-evaluate every tick.
        last_interjection.insert(chat_id, Instant::now());

        let trimmed = response.trim();
        if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("skip") {
            continue;
        }

        let bot_username = state.config.bot_username_for_channel(&routing.channel_name);
        if let Err(e) = deliver_and_store_bot_message(
            &state.channel_registry,
            state.db.clone(),
            &bot_username,
            chat_id,
            trimmed,
        )
        .await
        {
            warn!("interjection: delivery failed for chat {chat_id}: {e}");
        }
    }
}

/// One-line-per-task standup digest, like a colleague's quick status. A task
/// that has run well past the interval without recent progress is flagged as
/// possibly stalled.
fn format_standup(
    runs: &[microclaw_storage::db::SubagentRunRecord],
    now: chrono::DateTime<Utc>,
    interval_secs: u64,
    avg_duration_secs: Option<i64>,
) -> String {
    let n = runs.len();
    let header = format!(
        "🛰️ Still on it — {n} task{} running:",
        if n == 1 { "" } else { "s" }
    );
    let interval = interval_secs as i64;
    let mut lines = vec![header];
    for r in runs {
        let name = r
            .label
            .clone()
            .filter(|l| !l.trim().is_empty())
            .unwrap_or_else(|| {
                let snippet: String = r.task.chars().take(40).collect();
                snippet
            });
        let age_secs = chrono::DateTime::parse_from_rfc3339(&r.created_at)
            .ok()
            .map(|c| (now - c.with_timezone(&Utc)).num_seconds().max(0));
        let age = age_secs.map(format_duration_secs).unwrap_or_default();
        let progress = r
            .progress_text
            .clone()
            .filter(|p| !p.trim().is_empty())
            .map(|p| format!(" — {p}"))
            .unwrap_or_default();
        // Stalled: running well past the interval with no recent progress.
        let progress_age = r
            .last_progress_at
            .as_deref()
            .and_then(|ts| chrono::DateTime::parse_from_rfc3339(ts).ok())
            .map(|c| (now - c.with_timezone(&Utc)).num_seconds().max(0));
        let stale_progress = progress_age.map(|a| a >= interval).unwrap_or(true);
        let stalled = age_secs.map(|a| a >= 2 * interval).unwrap_or(false) && stale_progress;
        let flag = if stalled { " ⚠️ no recent progress" } else { "" };
        // Rough ETA from the chat's historical average run duration, shown only
        // while the task is still under that average (and not flagged stalled).
        let eta = match (avg_duration_secs, age_secs) {
            (Some(avg), Some(age)) if !stalled && age < avg => {
                format!(", ~{} left", format_duration_secs(avg - age))
            }
            _ => String::new(),
        };
        lines.push(format!("• {name} ({age}{eta}){progress}{flag}"));
    }
    lines.join("\n")
}

fn format_duration_secs(secs: i64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else {
        format!("{}h{}m", secs / 3600, (secs % 3600) / 60)
    }
}

fn strip_reflector_thinking_tags(input: &str) -> String {
    fn strip_tag(text: &str, open: &str, close: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        while let Some(start) = rest.find(open) {
            out.push_str(&rest[..start]);
            let after_open = &rest[start + open.len()..];
            if let Some(end_rel) = after_open.find(close) {
                rest = &after_open[end_rel + close.len()..];
            } else {
                rest = "";
                break;
            }
        }
        out.push_str(rest);
        out
    }

    let cleaned = crate::agent_engine::strip_thinking(input);
    strip_tag(&cleaned, "<notepad>", "</notepad>")
}

/// Parse reflector LLM response. Supports two formats:
///
/// 1. New object: `{"memories":[...],"triples":[...]}`
/// 2. Legacy array: `[{"content":"...","category":"..."}]`
///
/// Returns `(memory_extractions, kg_triples)`.
/// Reflector LLM response decomposed into the three output channels:
/// memory rows, knowledge-graph triples, and an optional updated USER.md
/// narrative. The user_model is None when the model judged the existing
/// file accurate and did not propose a rewrite.
struct ReflectorOutputs {
    memories: Vec<serde_json::Value>,
    triples: Vec<serde_json::Value>,
    user_model: Option<String>,
}

fn extract_obj_outputs(obj: &serde_json::Map<String, serde_json::Value>) -> ReflectorOutputs {
    let memories = obj
        .get("memories")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let triples = obj
        .get("triples")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let user_model = obj
        .get("user_model")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    ReflectorOutputs {
        memories,
        triples,
        user_model,
    }
}

fn parse_reflector_response(raw_text: &str, chat_id: i64) -> ReflectorOutputs {
    let cleaned = strip_reflector_thinking_tags(raw_text);
    let trimmed = cleaned.trim();

    // 1. Try parsing the trimmed text as a top-level JSON value: object →
    //    new schema, array → legacy memories. We branch on the value type
    //    rather than on `as_object()` alone so a legacy array doesn't fall
    //    through to the embedded-object scan below (which would match the
    //    first array element and silently drop the rest).
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) {
        if let Some(obj) = value.as_object() {
            return extract_obj_outputs(obj);
        }
        if let Some(arr) = value.as_array() {
            return ReflectorOutputs {
                memories: arr.clone(),
                triples: Vec::new(),
                user_model: None,
            };
        }
    }

    // 2. Extract JSON object embedded in surrounding noise (e.g. ```json
    //    fences). Only attempted when the top-level parse failed, so a
    //    legacy array can't reach this branch.
    if let Some(start) = trimmed.find('{') {
        if let Some(end) = trimmed.rfind('}') {
            if end > start {
                if let Ok(obj) = serde_json::from_str::<serde_json::Value>(&trimmed[start..=end]) {
                    if let Some(obj) = obj.as_object() {
                        return extract_obj_outputs(obj);
                    }
                }
            }
        }
    }

    // 3. Legacy array embedded in noise.
    if let Ok(arr) = parse_reflector_json_array(trimmed) {
        return ReflectorOutputs {
            memories: arr,
            triples: Vec::new(),
            user_model: None,
        };
    }
    let start = trimmed.find('[').unwrap_or(0);
    let end = trimmed.rfind(']').map(|i| i + 1).unwrap_or(trimmed.len());
    if start < end {
        if let Ok(arr) = parse_reflector_json_array(&trimmed[start..end]) {
            return ReflectorOutputs {
                memories: arr,
                triples: Vec::new(),
                user_model: None,
            };
        }
    }

    // The model didn't produce parseable JSON. Distinguish two cases:
    //  - it explicitly signalled "nothing to extract" (empty / `null` /
    //    `[]` / `{}` / a one-line refusal). That's a benign no-op — log
    //    at info, not error.
    //  - anything else: a real schema break. Log at warn with a short
    //    preview so the operator can see what the provider actually
    //    returned without grepping the LLM debug stream.
    let preview: String = trimmed.chars().take(200).collect();
    let lower = trimmed.to_ascii_lowercase();
    let is_explicit_no_op = trimmed.is_empty()
        || matches!(lower.as_str(), "null" | "[]" | "{}" | "none" | "no")
        || trimmed.len() < 16;
    if is_explicit_no_op {
        info!(
            "Reflector: chat {} returned no updates (response: {:?})",
            chat_id, preview
        );
    } else {
        warn!(
            "Reflector: parse failed for chat {chat_id}: no valid JSON found. response_preview={:?}",
            preview
        );
    }
    ReflectorOutputs {
        memories: Vec::new(),
        triples: Vec::new(),
        user_model: None,
    }
}

fn parse_reflector_json_array(text: &str) -> Result<Vec<serde_json::Value>, serde_json::Error> {
    let cleaned = strip_reflector_thinking_tags(text);
    let trimmed = cleaned.trim();
    if let Ok(v) = serde_json::from_str::<Vec<serde_json::Value>>(trimmed) {
        return Ok(v);
    }

    let bytes = trimmed.as_bytes();
    let mut starts = Vec::new();
    let mut ends = Vec::new();
    for (i, b) in bytes.iter().enumerate() {
        if *b == b'[' {
            starts.push(i);
        } else if *b == b']' {
            ends.push(i);
        }
    }

    let mut last_err: Option<serde_json::Error> = None;
    for &start in &starts {
        for &end in ends.iter().rev() {
            if end <= start {
                continue;
            }
            let candidate = &trimmed[start..=end];
            match serde_json::from_str::<Vec<serde_json::Value>>(candidate) {
                Ok(v) => return Ok(v),
                Err(e) => last_err = Some(e),
            }
        }
    }

    serde_json::from_str::<Vec<serde_json::Value>>(trimmed).map_err(|e| last_err.unwrap_or(e))
}

async fn run_reflector(state: &Arc<AppState>) {
    #[cfg(feature = "sqlite-vec")]
    backfill_embeddings(state).await;

    let _ = call_blocking(state.db.clone(), move |db| db.archive_stale_memories(30)).await;

    // Hard-delete memories whose `expires_at` has elapsed. Distinct from
    // archive: TTL'd memories are gone for good once they expire.
    let now = Utc::now().to_rfc3339();
    let _ = call_blocking(state.db.clone(), move |db| {
        let pruned = db.prune_expired_memories(&now)?;
        if pruned > 0 {
            info!("Reflector: pruned {pruned} expired memories");
        }
        Ok(())
    })
    .await;

    // Same for stashed tool-result artifacts whose TTL has passed.
    let now = Utc::now().to_rfc3339();
    let _ = call_blocking(state.db.clone(), move |db| {
        let pruned = db.prune_tool_artifacts(&now)?;
        if pruned > 0 {
            info!("Reflector: pruned {pruned} expired tool artifacts");
        }
        Ok(())
    })
    .await;

    // Auto-archive agent-created skills that haven't been used in N days.
    let archive_days = state.config.skill_archive_after_days;
    if archive_days > 0 {
        let skills_root = std::path::PathBuf::from(state.config.skills_data_dir());
        let _ = call_blocking(state.db.clone(), move |db| {
            match crate::skill_review::archive_inactive_agent_skills(
                &skills_root,
                db,
                archive_days,
            ) {
                Ok(n) if n > 0 => {
                    info!("Reflector: archived {n} inactive agent-created skill(s)");
                }
                Ok(_) => {}
                Err(e) => warn!("Reflector: skill archive sweep failed: {e}"),
            }
            Ok(())
        })
        .await;
    }

    // Enforce global memory capacity limit
    if state.config.memory_max_global_entries > 0 {
        let max_global = state.config.memory_max_global_entries;
        let _ = call_blocking(state.db.clone(), move |db| {
            let archived = db.archive_excess_memories(None, max_global)?;
            if archived > 0 {
                info!(
                    "Reflector: archived {} excess global memories (limit: {})",
                    archived, max_global
                );
            }
            Ok(())
        })
        .await;
    }

    let lookback_secs = (state.config.reflector_interval_mins * 2 * 60) as i64;
    let since = (Utc::now() - chrono::Duration::seconds(lookback_secs)).to_rfc3339();

    let chat_ids = match call_blocking(state.db.clone(), move |db| {
        db.get_active_chat_ids_since(&since)
    })
    .await
    {
        Ok(ids) => ids,
        Err(e) => {
            error!("Reflector: failed to get active chats: {e}");
            return;
        }
    };

    for chat_id in chat_ids.iter().copied() {
        reflect_for_chat(state, chat_id).await;
    }

    // Skill review is now driven from the end-of-turn enqueue in the
    // agent loop (see `AppState.skill_review_queue`). The reflector tick
    // intentionally no longer initiates reviews — that path was both too
    // late (up to `reflector_interval_mins` of staleness) and too eager
    // (re-reviewed the same conversations on every tick).
    let _ = chat_ids;
}

async fn reflect_for_chat(state: &Arc<AppState>, chat_id: i64) {
    let started_at = Utc::now().to_rfc3339();
    // 1. Get message cursor for incremental reflection
    let cursor =
        match call_blocking(state.db.clone(), move |db| db.get_reflector_cursor(chat_id)).await {
            Ok(c) => c,
            Err(_) => return,
        };

    // 2. Load messages incrementally when cursor exists; otherwise bootstrap with recent context
    let messages = if let Some(since) = cursor {
        match call_blocking(state.db.clone(), move |db| {
            db.get_messages_since(chat_id, &since, 200)
        })
        .await
        {
            Ok(m) => m,
            Err(_) => return,
        }
    } else {
        match call_blocking(state.db.clone(), move |db| {
            db.get_recent_messages(chat_id, 30)
        })
        .await
        {
            Ok(m) => m,
            Err(_) => return,
        }
    };

    if messages.is_empty() {
        return;
    }
    let latest_message_ts = messages.last().map(|m| m.timestamp.clone());

    // 3. Format conversation for the LLM
    // Strip thinking tags from message content so they don't confuse the LLM's JSON output
    let conversation = messages
        .iter()
        .map(|m| format!(
            "[{}]: {}",
            m.sender_name,
            strip_reflector_thinking_tags(&m.content)
        ))
        .collect::<Vec<_>>()
        .join("\n");

    // 4. Load existing memories (needed for dedup and to pass to LLM for merge)
    let existing = match state
        .memory_backend
        .get_all_memories_for_chat(Some(chat_id))
        .await
    {
        Ok(m) => m,
        Err(_) => return,
    };

    let existing_hint = if existing.is_empty() {
        String::new()
    } else {
        let lines = existing
            .iter()
            .map(|m| format!("  [id={}] [{}] {}", m.id, m.category, m.content))
            .collect::<Vec<_>>()
            .join("\n");
        format!("\n\nExisting memories (use supersedes_id to replace stale ones):\n{lines}")
    };

    // 4b. Look up channel + current USER.md so the same LLM call can also
    //     curate the per-chat user model, avoiding a second round trip.
    let channel = call_blocking(state.db.clone(), move |db| db.get_chat_channel(chat_id))
        .await
        .ok()
        .flatten();
    let existing_user_model = channel
        .as_deref()
        .and_then(|ch| state.memory.read_chat_user_model(ch, chat_id));
    let user_model_cap = state.config.user_model_max_chars;
    let user_model_block = if user_model_cap == 0 {
        String::new()
    } else {
        let body = existing_user_model
            .as_deref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .unwrap_or("(none yet)");
        format!(
            "\n\nCurrent USER.md (rewrite only if you have new durable signal; cap {user_model_cap} chars):\n```\n{body}\n```"
        )
    };

    // 5. Call LLM directly (no tools, no session)
    let user_msg = Message {
        role: "user".into(),
        content: MessageContent::Text(format!(
            "Extract memories from this conversation (chat_id={chat_id}):{existing_hint}{user_model_block}\n\nConversation:\n{conversation}"
        )),
    };
    // The reflector is background, quality-tolerant work, so allow a (typically
    // cheaper) auxiliary model to handle it on the same provider. When no aux
    // model is configured, this passes `None` and behaves exactly as before.
    let response = match state
        .llm
        .send_message_with_model(
            REFLECTOR_SYSTEM_PROMPT,
            vec![user_msg],
            None,
            state.config.aux_models.reflector_model(),
        )
        .await
    {
        Ok(r) => r,
        Err(e) => {
            error!("Reflector: LLM call failed for chat {chat_id}: {e}");
            let finished_at = Utc::now().to_rfc3339();
            let error_msg = e.to_string();
            let _ = call_blocking(state.db.clone(), move |db| {
                db.log_reflector_run(
                    chat_id,
                    &started_at,
                    &finished_at,
                    0,
                    0,
                    0,
                    0,
                    "none",
                    false,
                    Some(&error_msg),
                )
                .map(|_| ())
            })
            .await;
            return;
        }
    };

    // 6. Extract text from response
    let text = response
        .content
        .iter()
        .filter_map(|b| {
            if let ResponseContentBlock::Text { text } = b {
                Some(text.as_str())
            } else {
                None
            }
        })
        .collect::<Vec<_>>()
        .join("");

    // 7. Parse response — supports the new object format
    //    {"memories":[...],"triples":[...],"user_model":...} and the legacy
    //    array format [{"content":"...","category":"..."}].
    let ReflectorOutputs {
        memories: extracted,
        triples: kg_triples,
        user_model: proposed_user_model,
    } = parse_reflector_response(&text, chat_id);

    // Persist any user_model the LLM proposed before the early-return path,
    // so a USER.md-only update isn't dropped on the floor when no new
    // memories or triples were extracted.
    if let (Some(model), Some(ch)) = (proposed_user_model.as_ref(), channel.as_deref()) {
        persist_curated_user_model(
            state,
            chat_id,
            ch,
            existing_user_model.as_deref(),
            model,
            user_model_cap,
        );
    }

    if extracted.is_empty() && kg_triples.is_empty() {
        if let Some(ts) = latest_message_ts {
            let _ = call_blocking(state.db.clone(), move |db| {
                db.set_reflector_cursor(chat_id, &ts)
            })
            .await;
        }
        return;
    }

    if state.memory_backend.should_pause_reflector_writes() {
        let snapshot = state.memory_backend.provider_health_snapshot();
        warn!(
            "Reflector: pausing background memory writes for chat {} because external memory provider is unhealthy; consecutive_failures={} startup_probe_ok={:?}",
            chat_id,
            snapshot.consecutive_primary_failures,
            snapshot.startup_probe_ok
        );
        let finished_at = Utc::now().to_rfc3339();
        let pause_reason = format!(
            "reflector paused: external memory provider unhealthy; last_fallback={}",
            snapshot
                .last_fallback_reason
                .as_deref()
                .unwrap_or("unknown")
        );
        let skipped_count = extracted.len() + kg_triples.len();
        let _ = call_blocking(state.db.clone(), move |db| {
            db.log_reflector_run(
                chat_id,
                &started_at,
                &finished_at,
                skipped_count,
                0,
                0,
                skipped_count,
                "paused",
                true,
                Some(&pause_reason),
            )
            .map(|_| ())
        })
        .await;
        return;
    }

    // 8. Insert new memories or update superseded ones.
    //    If the LLM returned triples but no memories, convert triples to memories as fallback
    //    so that facts are not silently lost from the structured_memories context.
    let extracted = if extracted.is_empty() && !kg_triples.is_empty() {
        info!(
            "Reflector: chat {} — LLM returned {} triples but 0 memories, converting triples to memories as fallback",
            chat_id, kg_triples.len()
        );
        kg_triples
            .iter()
            .filter_map(|t| {
                let s = t.get("subject")?.as_str()?;
                let p = t.get("predicate")?.as_str()?;
                let o = t.get("object")?.as_str()?;
                Some(serde_json::json!({
                    "content": format!("{s} {p} {o}"),
                    "category": "KNOWLEDGE",
                }))
            })
            .collect()
    } else {
        extracted
    };

    let outcome = apply_reflector_extractions(state, chat_id, &existing, &extracted).await;
    let inserted = outcome.inserted;
    let updated = outcome.updated;
    let skipped = outcome.skipped;
    let dedup_method = outcome.dedup_method;

    // 9. Populate knowledge graph from extracted triples
    if !kg_triples.is_empty() {
        let mut kg_inserted = 0usize;
        for triple in &kg_triples {
            let subject = match triple.get("subject").and_then(|v| v.as_str()) {
                Some(s) if !s.trim().is_empty() => s.trim(),
                _ => continue,
            };
            let predicate = match triple.get("predicate").and_then(|v| v.as_str()) {
                Some(p) if !p.trim().is_empty() => p.trim(),
                _ => continue,
            };
            let object = match triple.get("object").and_then(|v| v.as_str()) {
                Some(o) if !o.trim().is_empty() => o.trim(),
                _ => continue,
            };
            let now = Utc::now().to_rfc3339();
            let s = subject.to_string();
            let p = predicate.to_string();
            let o = object.to_string();
            let vf = now.clone();
            let _ = call_blocking(state.db.clone(), move |db| {
                db.kg_insert_triple(&s, &p, &o, Some(chat_id), &vf, 0.72, "reflector", None)
            })
            .await;
            kg_inserted += 1;
        }
        if kg_inserted > 0 {
            info!(
                "Reflector: chat {chat_id} -> {kg_inserted} knowledge graph triples added"
            );
        }
    }

    // 10. Enforce KG capacity limits — prune excess triples
    if state.config.kg_max_triples_per_chat > 0 {
        let max_kg = state.config.kg_max_triples_per_chat;
        let _ = call_blocking(state.db.clone(), move |db| {
            let pruned = db.kg_prune_excess(chat_id, max_kg)?;
            if pruned > 0 {
                info!(
                    "Reflector: pruned {} excess KG triples for chat {} (limit: {})",
                    pruned, chat_id, max_kg
                );
            }
            Ok(())
        })
        .await;
    }

    // 11. Enforce memory capacity limits — archive excess low-confidence memories
    if state.config.memory_max_entries_per_chat > 0 {
        let max_per_chat = state.config.memory_max_entries_per_chat;
        let _ = call_blocking(state.db.clone(), move |db| {
            let archived = db.archive_excess_memories(Some(chat_id), max_per_chat)?;
            if archived > 0 {
                info!(
                    "Reflector: archived {} excess memories for chat {} (limit: {})",
                    archived, chat_id, max_per_chat
                );
            }
            Ok(())
        })
        .await;
    }

    if let Some(ts) = latest_message_ts {
        let _ = call_blocking(state.db.clone(), move |db| {
            db.set_reflector_cursor(chat_id, &ts)
        })
        .await;
    }

    if inserted > 0 || updated > 0 {
        info!(
            "Reflector: chat {chat_id} -> {inserted} new ({dedup_method} dedup), {updated} updated, {skipped} skipped"
        );
    }

    // USER.md curation now rides on the same reflector LLM call (see step 4b
    // / step 7 above), so no separate round trip is needed here.

    let finished_at = Utc::now().to_rfc3339();
    let _ = call_blocking(state.db.clone(), move |db| {
        db.log_reflector_run(
            chat_id,
            &started_at,
            &finished_at,
            extracted.len(),
            inserted,
            updated,
            skipped,
            dedup_method,
            true,
            None,
        )
        .map(|_| ())
    })
    .await;
}

/// Persist a USER.md narrative the reflector LLM proposed inside its
/// combined memory/triples/user_model output. Returns silently on a no-op:
/// when the layer is disabled (`user_model_max_chars == 0`), when the
/// proposed text is empty, or when it is byte-identical to the existing
/// file (avoid touching mtime for nothing).
fn persist_curated_user_model(
    state: &Arc<AppState>,
    chat_id: i64,
    channel: &str,
    existing: Option<&str>,
    proposed: &str,
    cap: usize,
) {
    if cap == 0 {
        return;
    }
    let trimmed = proposed.trim();
    if trimmed.is_empty() {
        return;
    }
    let capped: String = if trimmed.chars().count() > cap {
        trimmed.chars().take(cap).collect()
    } else {
        trimmed.to_string()
    };
    if existing
        .map(|s| s.trim() == capped.as_str())
        .unwrap_or(false)
    {
        return;
    }
    match state.memory.write_chat_user_model(channel, chat_id, &capped) {
        Ok(()) => info!(
            "Reflector: USER.md updated for chat {chat_id} ({} chars)",
            capped.chars().count()
        ),
        Err(e) => warn!("Reflector: USER.md write failed for chat {chat_id}: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_heartbeat_checklists_scans_numeric_group_dirs() {
        let root = std::env::temp_dir().join(format!(
            "microclaw-heartbeat-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let groups = root.join("groups");
        // chat 42: has a checklist
        std::fs::create_dir_all(groups.join("42")).unwrap();
        std::fs::write(groups.join("42/HEARTBEAT.md"), "- check the deploy\n").unwrap();
        // chat 7: empty checklist -> skipped
        std::fs::create_dir_all(groups.join("7")).unwrap();
        std::fs::write(groups.join("7/HEARTBEAT.md"), "   \n").unwrap();
        // chat 9: no HEARTBEAT.md -> skipped
        std::fs::create_dir_all(groups.join("9")).unwrap();
        // non-numeric dir -> skipped even with a checklist
        std::fs::create_dir_all(groups.join("not-a-chat")).unwrap();
        std::fs::write(groups.join("not-a-chat/HEARTBEAT.md"), "- x\n").unwrap();

        let got = heartbeat_checklists(&groups, 8000);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, 42);
        assert_eq!(got[0].1, "- check the deploy");

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_heartbeat_checklists_caps_content() {
        let root = std::env::temp_dir().join(format!(
            "microclaw-heartbeat-cap-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let groups = root.join("groups");
        std::fs::create_dir_all(groups.join("1")).unwrap();
        std::fs::write(groups.join("1/HEARTBEAT.md"), "x".repeat(100)).unwrap();

        let got = heartbeat_checklists(&groups, 10);
        assert_eq!(got.len(), 1);
        assert!(got[0].1.starts_with("xxxxxxxxxx"));
        assert!(got[0].1.contains("truncated"));

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_heartbeat_checklists_missing_dir_is_empty() {
        let got = heartbeat_checklists(std::path::Path::new("/nonexistent/heartbeat-test"), 100);
        assert!(got.is_empty());
    }

    #[test]
    fn test_format_duration_secs() {
        assert_eq!(format_duration_secs(5), "5s");
        assert_eq!(format_duration_secs(125), "2m");
        assert_eq!(format_duration_secs(3 * 3600 + 25 * 60), "3h25m");
    }

    #[test]
    fn test_dlq_replay_action_policy() {
        // A failed one-shot under the attempt cap is requeued.
        assert_eq!(dlq_replay_action("failed", 1, 3), DlqReplayAction::Requeue);
        assert_eq!(dlq_replay_action("failed", 2, 3), DlqReplayAction::Requeue);
        // At/over the cap we give up and leave it for manual inspection.
        assert_eq!(dlq_replay_action("failed", 3, 3), DlqReplayAction::GiveUp);
        assert_eq!(dlq_replay_action("failed", 9, 3), DlqReplayAction::GiveUp);
        // Non-failed tasks (active cron, cancelled, completed) are skipped.
        assert_eq!(dlq_replay_action("active", 1, 3), DlqReplayAction::Skip);
        assert_eq!(dlq_replay_action("cancelled", 1, 3), DlqReplayAction::Skip);
        assert_eq!(dlq_replay_action("completed", 1, 3), DlqReplayAction::Skip);
    }

    #[test]
    fn test_format_standup_uses_label_and_progress() {
        use microclaw_storage::db::SubagentRunRecord;
        let now = Utc::now();
        let created = (now - chrono::Duration::seconds(630)).to_rfc3339();
        let run = SubagentRunRecord {
            run_id: "subrun-1".into(),
            parent_run_id: None,
            depth: 1,
            chat_id: 7,
            caller_channel: "telegram".into(),
            task: "research competitor pricing across five vendors".into(),
            context: String::new(),
            status: "running".into(),
            created_at: created,
            started_at: None,
            finished_at: None,
            cancel_requested: false,
            error_text: None,
            result_text: None,
            input_tokens: 0,
            output_tokens: 0,
            total_tokens: 0,
            provider: "anthropic".into(),
            model: "claude-test".into(),
            token_budget: 0,
            artifact_json: None,
            label: Some("competitor research".into()),
            progress_text: Some("checked 3/5 vendors".into()),
            last_progress_at: None,
        };
        let out = format_standup(std::slice::from_ref(&run), now, 1800, None);
        assert!(out.contains("1 task running"));
        assert!(out.contains("competitor research"));
        assert!(out.contains("checked 3/5 vendors"));
        assert!(out.contains("10m")); // 630s rounds to 10m
        // Fresh progress + short interval-relative age → not flagged stalled.
        assert!(!out.contains("no recent progress"));
    }

    #[test]
    fn test_format_standup_flags_stalled_task() {
        use microclaw_storage::db::SubagentRunRecord;
        let now = Utc::now();
        // Running 90 min, no progress ever, interval 30 min → stalled.
        let run = SubagentRunRecord {
            run_id: "subrun-2".into(),
            parent_run_id: None,
            depth: 1,
            chat_id: 7,
            caller_channel: "telegram".into(),
            task: "long grind".into(),
            context: String::new(),
            status: "running".into(),
            created_at: (now - chrono::Duration::seconds(5400)).to_rfc3339(),
            started_at: None,
            finished_at: None,
            cancel_requested: false,
            error_text: None,
            result_text: None,
            input_tokens: 0,
            output_tokens: 0,
            total_tokens: 0,
            provider: "anthropic".into(),
            model: "claude-test".into(),
            token_budget: 0,
            artifact_json: None,
            label: Some("long grind".into()),
            progress_text: None,
            last_progress_at: None,
        };
        let out = format_standup(std::slice::from_ref(&run), now, 1800, Some(600));
        assert!(out.contains("no recent progress"), "expected stalled flag: {out}");
    }

    #[test]
    fn test_format_standup_shows_eta_when_under_average() {
        use microclaw_storage::db::SubagentRunRecord;
        let now = Utc::now();
        // Running 2 min, average completed run is 10 min → ~8m left, no stall flag.
        let run = SubagentRunRecord {
            run_id: "subrun-eta".into(),
            parent_run_id: None,
            depth: 1,
            chat_id: 7,
            caller_channel: "telegram".into(),
            task: "build report".into(),
            context: String::new(),
            status: "running".into(),
            created_at: (now - chrono::Duration::seconds(120)).to_rfc3339(),
            started_at: None,
            finished_at: None,
            cancel_requested: false,
            error_text: None,
            result_text: None,
            input_tokens: 0,
            output_tokens: 0,
            total_tokens: 0,
            provider: "anthropic".into(),
            model: "claude-test".into(),
            token_budget: 0,
            artifact_json: None,
            label: Some("report".into()),
            progress_text: None,
            last_progress_at: None,
        };
        let out = format_standup(std::slice::from_ref(&run), now, 1800, Some(600));
        assert!(out.contains("left"), "expected ETA: {out}");
        assert!(!out.contains("no recent progress"));
    }

    #[test]
    fn test_parse_reflector_response_extracts_user_model() {
        let raw = r#"{
            "memories": [{"content":"likes Rust","category":"PROFILE"}],
            "triples": [],
            "user_model": "Senior Rust engineer at Acme."
        }"#;
        let out = super::parse_reflector_response(raw, 1);
        assert_eq!(out.memories.len(), 1);
        assert_eq!(out.user_model.as_deref(), Some("Senior Rust engineer at Acme."));
    }

    #[test]
    fn test_parse_reflector_response_user_model_null_yields_none() {
        let raw = r#"{"memories": [], "triples": [], "user_model": null}"#;
        let out = super::parse_reflector_response(raw, 1);
        assert!(out.user_model.is_none());
    }

    #[test]
    fn test_parse_reflector_response_legacy_array_has_no_user_model() {
        let raw = r#"[{"content":"x","category":"PROFILE"}]"#;
        let out = super::parse_reflector_response(raw, 1);
        assert_eq!(out.memories.len(), 1);
        assert!(out.user_model.is_none());
    }

    #[test]
    fn test_parse_reflector_response_user_model_empty_string_yields_none() {
        let raw = r#"{"memories": [], "triples": [], "user_model": "   "}"#;
        let out = super::parse_reflector_response(raw, 1);
        assert!(out.user_model.is_none());
    }

    #[test]
    fn test_parse_reflector_response_no_op_signal_returns_empty() {
        // Common shapes the model produces when there's nothing to extract.
        // The parser should treat them as empty outputs without panicking;
        // the log severity downgrade for these cases is verified by code
        // review (info! vs warn!) — here we just assert the shape.
        for raw in ["", "null", "[]", "{}", "none", "no"] {
            let out = super::parse_reflector_response(raw, 42);
            assert!(out.memories.is_empty(), "raw={raw:?} memories not empty");
            assert!(out.triples.is_empty(), "raw={raw:?} triples not empty");
            assert!(
                out.user_model.is_none(),
                "raw={raw:?} user_model not None"
            );
        }
    }

    #[test]
    fn test_parse_reflector_response_garbage_returns_empty_without_panic() {
        // Plain prose that has no JSON braces / brackets at all. Should
        // not panic and should return empty outputs (warn-level log).
        let raw = "I don't think there is anything new to remember from this conversation.";
        let out = super::parse_reflector_response(raw, 42);
        assert!(out.memories.is_empty());
        assert!(out.triples.is_empty());
        assert!(out.user_model.is_none());
    }

    #[test]
    fn test_jaccard_similar_identical() {
        assert!(crate::memory_service::jaccard_similar(
            "hello world",
            "hello world",
            0.5,
        ));
    }

    #[test]
    fn test_jaccard_similar_no_overlap() {
        assert!(!crate::memory_service::jaccard_similar(
            "hello world",
            "foo bar",
            0.5,
        ));
    }

    #[test]
    fn test_jaccard_similar_partial_overlap() {
        // "a b c" vs "a b d" => intersection=2, union=4 => 0.5 >= 0.5
        assert!(crate::memory_service::jaccard_similar(
            "a b c", "a b d", 0.5,
        ));
        // "a b c" vs "a d e" => intersection=1, union=5 => 0.2 < 0.5
        assert!(!crate::memory_service::jaccard_similar(
            "a b c", "a d e", 0.5,
        ));
    }

    #[test]
    fn test_jaccard_similar_empty_strings() {
        // Both empty => union=0 => returns true
        assert!(crate::memory_service::jaccard_similar("", "", 0.5));
        // One empty => intersection=0, union=1 => 0.0 < 0.5
        assert!(!crate::memory_service::jaccard_similar("hello", "", 0.5));
    }

    #[test]
    fn test_reflector_prompt_includes_memory_poisoning_guardrails() {
        assert!(REFLECTOR_SYSTEM_PROMPT.contains("CRITICAL"));
        assert!(REFLECTOR_SYSTEM_PROMPT.contains("NEVER describe broken behavior as a fact"));
        assert!(REFLECTOR_SYSTEM_PROMPT.contains("TODO: ensure tool calls always execute"));
    }

    #[test]
    fn test_should_skip_memory_poisoning_risk_for_broken_behavior_fact() {
        assert!(crate::memory_service::should_skip_memory_poisoning_risk(
            "proactive-agent skill broke tool calling; tool calls posted as text"
        ));
        assert!(crate::memory_service::should_skip_memory_poisoning_risk(
            "got 401 authentication error on Discord"
        ));
    }

    #[test]
    fn test_should_not_skip_memory_poisoning_risk_for_action_items() {
        assert!(!crate::memory_service::should_skip_memory_poisoning_risk(
            "TODO: ensure tool calls always execute via tool system"
        ));
        assert!(!crate::memory_service::should_skip_memory_poisoning_risk(
            "Ensure TOOLS.md rules are followed for every tool call"
        ));
    }

    #[test]
    fn test_resolve_task_timezone_prefers_task_timezone() {
        let tz = resolve_task_timezone("Asia/Shanghai", "UTC");
        assert_eq!(tz, chrono_tz::Tz::Asia__Shanghai);
    }

    #[test]
    fn test_resolve_task_timezone_falls_back_to_default_on_invalid_task_timezone() {
        let tz = resolve_task_timezone("Not/AZone", "US/Eastern");
        assert_eq!(tz, chrono_tz::Tz::US__Eastern);
    }

    #[test]
    fn test_parse_reflector_json_array_strips_thinking_tags() {
        let raw = "<thinking>plan</thinking><reasoning>private</reasoning><notepad>scratch</notepad>[{\"content\":\"x\",\"category\":\"KNOWLEDGE\"}]";
        let arr = parse_reflector_json_array(raw).expect("should parse");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["content"], "x");
    }

    #[test]
    fn test_strip_reflector_thinking_tags_removes_supported_tag_families() {
        let raw = "<thought>one</thought><think>two</think><thinking>three</thinking><reasoning>four</reasoning><notepad>five</notepad>Visible";
        assert_eq!(strip_reflector_thinking_tags(raw), "Visible");
    }

    #[test]
    fn test_parse_reflector_json_array_finds_array_inside_noise() {
        let raw = "notes...\n```json\n[{\"content\":\"y\",\"category\":\"PROFILE\"}]\n```\nthanks";
        let arr = parse_reflector_json_array(raw).expect("should parse");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["content"], "y");
    }

    #[test]
    fn test_is_retryable_delivery_rate_limit_recognizes_common_errors() {
        assert!(is_retryable_delivery_rate_limit(
            "HTTP 429: rate limit exceeded"
        ));
        assert!(is_retryable_delivery_rate_limit("Too many requests"));
        assert!(is_retryable_delivery_rate_limit("请求过于频繁，请稍后重试"));
        assert!(!is_retryable_delivery_rate_limit("permission denied"));
    }
}
