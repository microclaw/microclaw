use std::str::FromStr;
use std::sync::Arc;

use chrono::Utc;
use tokio::time::{Duration, Instant, MissedTickBehavior};
use tracing::{error, info, warn};

use crate::agent_engine::process_with_agent;
use crate::agent_engine::AgentRequestContext;
use crate::runtime::AppState;
use crate::{db::Memory, memory_quality};
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
                    let _ = deliver_and_store_bot_message(
                        &state.channel_registry,
                        state.db.clone(),
                        &bot_username,
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
                let bot_username = state.config.bot_username_for_channel(&routing.channel_name);
                let _ = deliver_and_store_bot_message(
                    &state.channel_registry,
                    state.db.clone(),
                    &bot_username,
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

        // Compute next run
        let tz: chrono_tz::Tz = state.config.timezone.parse().unwrap_or(chrono_tz::Tz::UTC);
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
- Output ONLY valid JSON array: [{"content":"...","category":"PROFILE","supersedes_id":null}]
- If nothing worth remembering: []

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

fn jaccard_similar(a: &str, b: &str, threshold: f64) -> bool {
    use std::collections::HashSet;
    let a_words: HashSet<&str> = a.split_whitespace().collect();
    let b_words: HashSet<&str> = b.split_whitespace().collect();
    let intersection = a_words.intersection(&b_words).count();
    let union = a_words.len() + b_words.len() - intersection;
    if union == 0 {
        return true;
    }
    intersection as f64 / union as f64 >= threshold
}

fn should_merge_duplicate(
    existing: &Memory,
    incoming_content: &str,
    incoming_category: &str,
) -> bool {
    if existing.is_archived {
        return true;
    }
    if existing.content.eq_ignore_ascii_case(incoming_content) {
        return false;
    }
    if incoming_category == "PROFILE" && existing.category != "PROFILE" {
        return true;
    }
    incoming_content.len() > existing.content.len() + 8
}

fn is_corrective_action_item(content: &str) -> bool {
    let lower = content.to_ascii_lowercase();
    let trimmed = lower.trim();
    trimmed.starts_with("todo:")
        || trimmed.starts_with("todo ")
        || trimmed.contains(" ensure ")
        || trimmed.starts_with("ensure ")
}

fn looks_like_broken_behavior_fact(content: &str) -> bool {
    let lower = content.to_ascii_lowercase();
    let broken_cues = [
        "tool calls were broken",
        "typed tool calls as text",
        "posted as text",
        "authentication error",
        "auth fails",
        "not following instructions",
        "isn't following instructions",
        "failed",
        "broke ",
        "was broken",
        "error on",
    ];
    broken_cues.iter().any(|cue| lower.contains(cue))
}

fn should_skip_memory_poisoning_risk(content: &str) -> bool {
    looks_like_broken_behavior_fact(content) && !is_corrective_action_item(content)
}

#[cfg(feature = "sqlite-vec")]
async fn upsert_memory_embedding(
    state: &Arc<AppState>,
    memory_id: i64,
    content: &str,
) -> Result<(), ()> {
    let provider = match &state.embedding {
        Some(p) => p,
        None => return Ok(()),
    };
    let model_name = provider.model().to_string();
    let embedding = provider.embed(content).await.map_err(|_| ())?;
    call_blocking(state.db.clone(), move |db| {
        db.upsert_memory_vec(memory_id, &embedding)?;
        db.update_memory_embedding_model(memory_id, &model_name)?;
        Ok(())
    })
    .await
    .map_err(|_| ())
}

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
        let _ = upsert_memory_embedding(state, mem.id, &mem.content).await;
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

async fn run_reflector(state: &Arc<AppState>) {
    #[cfg(feature = "sqlite-vec")]
    backfill_embeddings(state).await;

    let _ = call_blocking(state.db.clone(), move |db| db.archive_stale_memories(30)).await;

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

    for chat_id in chat_ids {
        reflect_for_chat(state, chat_id).await;
    }
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
    let conversation = messages
        .iter()
        .map(|m| format!("[{}]: {}", m.sender_name, m.content))
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

    // 5. Call LLM directly (no tools, no session)
    let user_msg = Message {
        role: "user".into(),
        content: MessageContent::Text(format!(
            "Extract memories from this conversation (chat_id={chat_id}):{existing_hint}\n\nConversation:\n{conversation}"
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

    // 7. Parse JSON array
    let extracted: Vec<serde_json::Value> = match serde_json::from_str(text.trim()) {
        Ok(v) => v,
        Err(_) => {
            let start = text.find('[').unwrap_or(0);
            let end = text.rfind(']').map(|i| i + 1).unwrap_or(text.len());
            if start >= end {
                error!("Reflector: parse failed for chat {chat_id}: no JSON array found");
                let finished_at = Utc::now().to_rfc3339();
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
                        Some("no JSON array found"),
                    )
                    .map(|_| ())
                })
                .await;
                return;
            }
            match serde_json::from_str(&text[start..end]) {
                Ok(v) => v,
                Err(e) => {
                    error!("Reflector: parse failed for chat {chat_id}: {e}");
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
            }
        }
    };

    if extracted.is_empty() {
        if let Some(ts) = latest_message_ts {
            let _ = call_blocking(state.db.clone(), move |db| {
                db.set_reflector_cursor(chat_id, &ts)
            })
            .await;
        }
        return;
    }

    // 8. Insert new memories or update superseded ones
    let mut inserted = 0usize;
    let mut updated = 0usize;
    let mut skipped = 0usize;
    #[cfg(feature = "sqlite-vec")]
    let dedup_method = if state.embedding.is_some() {
        "semantic"
    } else {
        "jaccard"
    };
    #[cfg(not(feature = "sqlite-vec"))]
    let dedup_method = "jaccard";
    let mut seen_contents: Vec<(i64, String)> =
        existing.iter().map(|m| (m.id, m.content.clone())).collect();
    let existing_by_id: std::collections::HashMap<i64, &Memory> =
        existing.iter().map(|m| (m.id, m)).collect();
    let mut topic_latest: std::collections::HashMap<String, i64> = existing
        .iter()
        .filter(|m| !m.is_archived)
        .map(|m| (memory_quality::memory_topic_key(&m.content), m.id))
        .collect();
    for item in &extracted {
        let content = match item.get("content").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => continue,
        };
        let category = item
            .get("category")
            .and_then(|v| v.as_str())
            .unwrap_or("KNOWLEDGE")
            .to_ascii_uppercase();
        if !matches!(category.as_str(), "PROFILE" | "KNOWLEDGE" | "EVENT") {
            continue;
        }
        let content = match memory_quality::normalize_memory_content(content, 180) {
            Some(c) => c,
            None => continue,
        };
        if should_skip_memory_poisoning_risk(&content) {
            skipped += 1;
            continue;
        }
        if !memory_quality::memory_quality_ok(&content) {
            continue;
        }

        // If the LLM flagged an existing memory to supersede, update it
        let supersedes_id = item.get("supersedes_id").and_then(|v| v.as_i64());
        if let Some(sid) = supersedes_id {
            if existing.iter().any(|m| m.id == sid) {
                let content = content.to_string();
                let category = category.to_string();
                let db_content = content.clone();
                if state
                    .memory_backend
                    .update_memory_with_metadata(sid, &db_content, &category, 0.78, "reflector")
                    .await
                    .is_ok()
                {
                    updated += 1;
                    #[cfg(feature = "sqlite-vec")]
                    {
                        let _ = upsert_memory_embedding(state, sid, &content).await;
                    }
                    seen_contents.push((sid, content));
                }
                continue;
            }
        }

        let topic_key = memory_quality::memory_topic_key(&content);
        if let Some(prev_id) = topic_latest.get(&topic_key).copied() {
            if let Some(prev) = existing_by_id.get(&prev_id) {
                if !prev.content.eq_ignore_ascii_case(&content)
                    && !jaccard_similar(&prev.content, &content, 0.85)
                {
                    let new_content = content.to_string();
                    let new_category = category.to_string();
                    if let Ok(new_id) = state
                        .memory_backend
                        .supersede_memory(
                            prev_id,
                            &new_content,
                            &new_category,
                            "reflector_conflict",
                            0.74,
                            Some("topic_conflict"),
                        )
                        .await
                    {
                        updated += 1;
                        #[cfg(feature = "sqlite-vec")]
                        {
                            let _ = upsert_memory_embedding(state, new_id, &content).await;
                        }
                        topic_latest.insert(topic_key, new_id);
                        seen_contents.push((new_id, content));
                        continue;
                    }
                }
            }
        }

        // Dedup: semantic KNN when available, otherwise lexical Jaccard.
        let duplicate_id = {
            #[cfg(feature = "sqlite-vec")]
            {
                if let Some(provider) = &state.embedding {
                    if let Ok(query_vec) = provider.embed(&content).await {
                        let nearest = call_blocking(state.db.clone(), move |db| {
                            db.knn_memories(chat_id, &query_vec, 1)
                        })
                        .await
                        .ok()
                        .and_then(|rows| rows.first().copied());
                        nearest.and_then(|(id, dist)| if dist < 0.15 { Some(id) } else { None })
                    } else {
                        seen_contents
                            .iter()
                            .find(|(_, existing)| jaccard_similar(existing, &content, 0.5))
                            .map(|(id, _)| *id)
                    }
                } else {
                    seen_contents
                        .iter()
                        .find(|(_, existing)| jaccard_similar(existing, &content, 0.5))
                        .map(|(id, _)| *id)
                }
            }
            #[cfg(not(feature = "sqlite-vec"))]
            {
                seen_contents
                    .iter()
                    .find(|(_, existing)| jaccard_similar(existing, &content, 0.5))
                    .map(|(id, _)| *id)
            }
        };
        if let Some(dup_id) = duplicate_id {
            if let Some(existing_mem) = existing_by_id.get(&dup_id) {
                if should_merge_duplicate(existing_mem, &content, &category) {
                    let update_content = content.to_string();
                    let update_category = category.to_string();
                    if state
                        .memory_backend
                        .update_memory_with_metadata(
                            dup_id,
                            &update_content,
                            &update_category,
                            0.70,
                            "reflector",
                        )
                        .await
                        .is_ok()
                    {
                        updated += 1;
                    } else {
                        skipped += 1;
                    }
                } else {
                    let _ = state
                        .memory_backend
                        .touch_memory_last_seen(dup_id, Some(0.55))
                        .await;
                    skipped += 1;
                }
            } else {
                skipped += 1;
            }
            continue;
        }

        let content = content.to_string();
        let db_content = content.clone();
        let category = category.to_string();
        let inserted_id = state
            .memory_backend
            .insert_memory_with_metadata(Some(chat_id), &db_content, &category, "reflector", 0.68)
            .await
            .ok();
        if let Some(memory_id) = inserted_id {
            inserted += 1;
            #[cfg(feature = "sqlite-vec")]
            {
                let _ = upsert_memory_embedding(state, memory_id, &content).await;
            }
            #[cfg(not(feature = "sqlite-vec"))]
            let _ = memory_id;
            seen_contents.push((memory_id, content));
            topic_latest.insert(topic_key, memory_id);
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jaccard_similar_identical() {
        assert!(jaccard_similar("hello world", "hello world", 0.5));
    }

    #[test]
    fn test_jaccard_similar_no_overlap() {
        assert!(!jaccard_similar("hello world", "foo bar", 0.5));
    }

    #[test]
    fn test_jaccard_similar_partial_overlap() {
        // "a b c" vs "a b d" => intersection=2, union=4 => 0.5 >= 0.5
        assert!(jaccard_similar("a b c", "a b d", 0.5));
        // "a b c" vs "a d e" => intersection=1, union=5 => 0.2 < 0.5
        assert!(!jaccard_similar("a b c", "a d e", 0.5));
    }

    #[test]
    fn test_jaccard_similar_empty_strings() {
        // Both empty => union=0 => returns true
        assert!(jaccard_similar("", "", 0.5));
        // One empty => intersection=0, union=1 => 0.0 < 0.5
        assert!(!jaccard_similar("hello", "", 0.5));
    }

    #[test]
    fn test_reflector_prompt_includes_memory_poisoning_guardrails() {
        assert!(REFLECTOR_SYSTEM_PROMPT.contains("CRITICAL"));
        assert!(REFLECTOR_SYSTEM_PROMPT.contains("NEVER describe broken behavior as a fact"));
        assert!(REFLECTOR_SYSTEM_PROMPT.contains("TODO: ensure tool calls always execute"));
    }

    #[test]
    fn test_should_skip_memory_poisoning_risk_for_broken_behavior_fact() {
        assert!(should_skip_memory_poisoning_risk(
            "proactive-agent skill broke tool calling; tool calls posted as text"
        ));
        assert!(should_skip_memory_poisoning_risk(
            "got 401 authentication error on Discord"
        ));
    }

    #[test]
    fn test_should_not_skip_memory_poisoning_risk_for_action_items() {
        assert!(!should_skip_memory_poisoning_risk(
            "TODO: ensure tool calls always execute via tool system"
        ));
        assert!(!should_skip_memory_poisoning_risk(
            "Ensure TOOLS.md rules are followed for every tool call"
        ));
    }
}
