use std::str::FromStr;
use std::sync::Arc;

use chrono::Utc;
use tokio::time::{Duration, Instant, MissedTickBehavior};
use tracing::{error, info, warn};

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
    let tasks = match call_blocking(state.db.clone(), move |db| db.claim_due_tasks(&now, 200)).await
    {
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

        // Run agent loop with the task prompt
        let (success, result_summary) = match process_with_agent(
            state,
            AgentRequestContext {
                caller_channel: &routing.channel_name,
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
                    let bot_username = state.config.bot_username_for_channel(&routing.channel_name);
                    if let Err(delivery_err) = deliver_scheduler_message_with_backoff(
                        state,
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
            Err(e) => {
                error!("Scheduler: task #{} failed: {e}", task.id);
                let err_text = format!("Scheduled task #{} failed: {e}", task.id);
                let bot_username = state.config.bot_username_for_channel(&routing.channel_name);
                let summary = match deliver_scheduler_message_with_backoff(
                    state,
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
                error!(
                    "Scheduler: failed to enqueue DLQ for task #{}: {e}",
                    task.id
                );
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

const REFLECTOR_SYSTEM_PROMPT: &str = r#"You are a memory extraction specialist. Extract durable, factual information from conversations.

Rules:
- Extract ONLY concrete facts, preferences, expertise, or notable events
- IGNORE: greetings, small talk, unanswered questions, transient requests
- Each memory < 100 characters, specific and concrete
- Category must be exactly one of: PROFILE (user attributes/preferences), KNOWLEDGE (facts/expertise), EVENT (significant things that happened)
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

    error!(
        "Reflector: parse failed for chat {}: no valid JSON found",
        chat_id
    );
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
    let response = match state
        .llm
        .send_message(REFLECTOR_SYSTEM_PROMPT, vec![user_msg], None)
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
