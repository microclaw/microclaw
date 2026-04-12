use std::sync::Arc;

use anyhow::Result;
use tracing::info;

use crate::agent_engine::is_slash_command_text;
use crate::embedding::EmbeddingProvider;
use crate::memory_backend::MemoryBackend;
use crate::runtime::AppState;
use microclaw_storage::db::{call_blocking, Database, Memory};
use microclaw_storage::memory_quality;

pub(crate) struct ReflectorApplyOutcome {
    pub inserted: usize,
    pub updated: usize,
    pub skipped: usize,
    pub dedup_method: &'static str,
}

fn jaccard_similarity_ratio(a: &str, b: &str) -> f64 {
    use std::collections::HashSet;
    let a_words: HashSet<&str> = a.split_whitespace().collect();
    let b_words: HashSet<&str> = b.split_whitespace().collect();
    let intersection = a_words.intersection(&b_words).count();
    let union = a_words.len() + b_words.len() - intersection;
    if union == 0 {
        1.0
    } else {
        intersection as f64 / union as f64
    }
}

fn tokenize_for_relevance(text: &str) -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();

    for token in text
        .split_whitespace()
        .map(|w| {
            w.chars()
                .filter(|c| c.is_alphanumeric())
                .collect::<String>()
                .to_lowercase()
        })
        .filter(|w| w.len() > 1)
    {
        out.insert(token);
    }

    let cjk_chars: Vec<char> = text.chars().filter(|c| is_cjk(*c)).collect();
    if cjk_chars.len() >= 2 {
        for pair in cjk_chars.windows(2) {
            let gram: String = pair.iter().collect();
            out.insert(gram);
        }
    } else if cjk_chars.len() == 1 {
        out.insert(cjk_chars[0].to_string());
    }

    out
}

fn score_relevance_with_cache(
    content: &str,
    query_tokens: &std::collections::HashSet<String>,
) -> usize {
    if query_tokens.is_empty() {
        return 0;
    }
    let content_tokens = tokenize_for_relevance(content);
    content_tokens
        .iter()
        .filter(|t| query_tokens.contains(*t))
        .count()
}

fn is_cjk(c: char) -> bool {
    matches!(
        c as u32,
        0x4E00..=0x9FFF
            | 0x3400..=0x4DBF
            | 0x20000..=0x2A6DF
            | 0x2A700..=0x2B73F
            | 0x2B740..=0x2B81F
            | 0x2B820..=0x2CEAF
            | 0xF900..=0xFAFF
            | 0x2F800..=0x2FA1F
    )
}

pub(crate) fn jaccard_similar(a: &str, b: &str, threshold: f64) -> bool {
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

pub(crate) fn should_skip_memory_poisoning_risk(content: &str) -> bool {
    looks_like_broken_behavior_fact(content) && !is_corrective_action_item(content)
}

#[cfg(feature = "sqlite-vec")]
pub(crate) async fn upsert_memory_embedding(
    state: &Arc<AppState>,
    memory_id: i64,
    content: &str,
) -> Result<(), ()> {
    let provider = match &state.embedding {
        Some(p) => p,
        None => return Ok(()),
    };
    upsert_memory_embedding_with_provider(state.db.clone(), provider, memory_id, content).await
}

#[cfg(feature = "sqlite-vec")]
async fn upsert_memory_embedding_with_provider(
    db: Arc<Database>,
    provider: &Arc<dyn EmbeddingProvider>,
    memory_id: i64,
    content: &str,
) -> Result<(), ()> {
    let model_name = provider.model().to_string();
    let embedding = provider.embed(content).await.map_err(|_| ())?;
    call_blocking(db, move |db| {
        db.upsert_memory_vec(memory_id, &embedding)?;
        db.update_memory_embedding_model(memory_id, &model_name)?;
        Ok(())
    })
    .await
    .map_err(|_| ())
}

pub(crate) async fn maybe_handle_explicit_memory_command(
    state: &AppState,
    chat_id: i64,
    override_prompt: Option<&str>,
    image_data: Option<(String, String)>,
) -> Result<Option<String>> {
    if override_prompt.is_some() || image_data.is_some() {
        return Ok(None);
    }

    let latest_user = call_blocking(state.db.clone(), move |db| {
        db.get_recent_messages(chat_id, 10)
    })
    .await?;
    let Some(last_user_text) = latest_user
        .into_iter()
        .rev()
        .find(|m| !m.is_from_bot && !is_slash_command_text(&m.content))
        .map(|m| m.content)
    else {
        return Ok(None);
    };

    let Some(explicit_content) = memory_quality::extract_explicit_memory_command(&last_user_text)
    else {
        return Ok(None);
    };
    if !memory_quality::memory_quality_ok(&explicit_content) {
        return Ok(Some(
            "I skipped saving that memory because it looked too vague. Please send a specific fact.".to_string(),
        ));
    }

    let existing = state
        .memory_backend
        .get_all_memories_for_chat(Some(chat_id))
        .await?;
    let explicit_topic = memory_quality::memory_topic_key(&explicit_content);
    if let Some(dup) = existing.iter().find(|m| {
        !m.is_archived
            && (m.content.eq_ignore_ascii_case(&explicit_content)
                || jaccard_similarity_ratio(&m.content, &explicit_content) >= 0.55)
    }) {
        let memory_id = dup.id;
        let content_for_update = explicit_content.clone();
        let _ = state
            .memory_backend
            .update_memory_with_metadata(
                memory_id,
                &content_for_update,
                "KNOWLEDGE",
                0.95,
                "explicit",
            )
            .await;
        return Ok(Some(format!(
            "Noted. Updated memory #{memory_id}: {explicit_content}"
        )));
    }

    if let Some(conflict) = existing.iter().find(|m| {
        !m.is_archived
            && m.category == "KNOWLEDGE"
            && memory_quality::memory_topic_key(&m.content) == explicit_topic
            && !m.content.eq_ignore_ascii_case(&explicit_content)
    }) {
        let from_id = conflict.id;
        let new_content = explicit_content.clone();
        let superseded_id = state
            .memory_backend
            .supersede_memory(
                from_id,
                &new_content,
                "KNOWLEDGE",
                "explicit_conflict",
                0.95,
                Some("explicit_topic_conflict"),
            )
            .await?;
        return Ok(Some(format!(
            "Noted. Superseded memory #{from_id} with #{superseded_id}: {explicit_content}"
        )));
    }

    let content_for_insert = explicit_content.clone();
    let inserted_id = state
        .memory_backend
        .insert_memory_with_metadata(
            Some(chat_id),
            &content_for_insert,
            "KNOWLEDGE",
            "explicit",
            0.95,
        )
        .await?;

    #[cfg(feature = "sqlite-vec")]
    {
        if let Some(provider) = &state.embedding {
            let _ = upsert_memory_embedding_with_provider(
                state.db.clone(),
                provider,
                inserted_id,
                &explicit_content,
            )
            .await;
        }
    }

    Ok(Some(format!(
        "Noted. Saved memory #{inserted_id}: {explicit_content}"
    )))
}

/// Sanitize a query string for memory retrieval.
///
/// AI agents sometimes prepend system prompts or tool definitions to user messages,
/// which destroys embedding quality for semantic search. This sanitizer extracts the
/// likely user intent by:
/// 1. Detecting and stripping common system prompt patterns
/// 2. Extracting the last meaningful sentence (most likely to be the actual query)
/// 3. Truncating overly long queries that are likely contaminated
fn sanitize_memory_query(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() < 200 {
        // Short queries are unlikely to contain system prompt contamination
        return trimmed.to_string();
    }

    // Check for system prompt contamination markers
    let lower = trimmed.to_ascii_lowercase();
    let contamination_markers = [
        "you are a",
        "you are an",
        "your role is",
        "system prompt",
        "instructions:",
        "<system>",
        "tool_use",
        "tool_result",
        "[scheduler]:",
        "as an ai assistant",
    ];
    let is_contaminated = contamination_markers.iter().any(|m| lower.contains(m));

    if !is_contaminated {
        // Not contaminated, but still truncate if very long
        if trimmed.len() > 500 {
            return trimmed.chars().take(500).collect();
        }
        return trimmed.to_string();
    }

    // Strategy: extract the last meaningful sentence (tail extraction)
    // Split on sentence boundaries and take the last non-trivial one
    let sentences: Vec<&str> = trimmed
        .split(['.', '?', '!', '\n'])
        .map(|s| s.trim())
        .filter(|s| s.len() > 10)
        .collect();

    if let Some(last) = sentences.last() {
        return last.chars().take(300).collect();
    }

    // Fallback: take the last 200 chars
    let start = trimmed
        .char_indices()
        .rev()
        .nth(199)
        .map(|(i, _)| i)
        .unwrap_or(0);
    trimmed[start..].to_string()
}

/// Build structured memory context using a 4-layer memory stack:
///
/// - **L0 (Identity)**: PROFILE memories — always loaded first. These define who the user is.
///   Budget: up to 20% of total. Cost: ~100-200 tokens typically.
/// - **L1 (Essential)**: Highest-confidence, most-recently-seen memories across all categories.
///   These are the "essential story" — durable facts the agent should always know.
///   Budget: up to 30% of total. Cost: ~300-500 tokens.
/// - **L2 (Relevance)**: Query-relevant memories via semantic/keyword ranking.
///   Loaded based on what the user is currently asking about.
///   Budget: remaining tokens. Cost: variable.
/// - **L3 (Deep Search)**: Not injected here — available via `structured_memory_search` tool
///   for on-demand deep retrieval when the agent needs more context.
pub(crate) async fn build_db_memory_context(
    memory_backend: &Arc<MemoryBackend>,
    db: &Arc<Database>,
    embedding: Option<&Arc<dyn EmbeddingProvider>>,
    chat_id: i64,
    query: &str,
    token_budget: usize,
) -> String {
    let query = &sanitize_memory_query(query);
    let memories = match memory_backend.get_memories_for_context(chat_id, 100).await {
        Ok(m) => m,
        Err(_) => return String::new(),
    };

    if memories.is_empty() {
        return String::new();
    }

    let budget = token_budget.max(1);
    let mut used_tokens = 0usize;
    let mut out = String::from("<structured_memories>\n");
    let mut injected_ids: std::collections::HashSet<i64> = std::collections::HashSet::new();

    // ── L0: Identity (PROFILE memories, up to 20% of budget) ──
    let l0_budget = budget * 20 / 100;
    let mut profile_memories: Vec<&Memory> = memories
        .iter()
        .filter(|m| m.category == "PROFILE" && !m.is_archived)
        .collect();
    // Sort profiles by confidence desc, then recency
    profile_memories.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    if !profile_memories.is_empty() {
        out.push_str("# Identity\n");
        for m in &profile_memories {
            let est = (m.content.len() / 4) + 10;
            if used_tokens + est > l0_budget && !injected_ids.is_empty() {
                break;
            }
            used_tokens += est;
            injected_ids.insert(m.id);
            let scope = if m.chat_id.is_none() { "global" } else { "chat" };
            out.push_str(&format!("[PROFILE] [{}] {}\n", scope, m.content));
        }
    }

    // ── L1: Essential Story (highest-confidence memories, up to 30% of budget) ──
    let l1_budget = used_tokens + (budget * 30 / 100);
    let mut essential: Vec<&Memory> = memories
        .iter()
        .filter(|m| !m.is_archived && !injected_ids.contains(&m.id))
        .collect();
    // Score by confidence + recency (higher = more essential)
    essential.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let mut l1_count = 0usize;
    if !essential.is_empty() {
        out.push_str("# Essential\n");
        for m in &essential {
            let est = (m.content.len() / 4) + 10;
            if used_tokens + est > l1_budget {
                break;
            }
            used_tokens += est;
            injected_ids.insert(m.id);
            l1_count += 1;
            let scope = if m.chat_id.is_none() { "global" } else { "chat" };
            out.push_str(&format!("[{}] [{}] {}\n", m.category, scope, m.content));
        }
    }

    // ── L2: Relevance-ranked (query-dependent, fills remaining budget) ──
    // Build relevance-ordered list from memories not yet injected
    let remaining: Vec<&Memory> = memories
        .iter()
        .filter(|m| !injected_ids.contains(&m.id) && !m.is_archived)
        .collect();

    if !remaining.is_empty() {
        let mut relevance_ordered: Vec<&Memory> = Vec::new();

        #[cfg(feature = "sqlite-vec")]
        let mut retrieval_method = if memory_supports_local_semantic_ranking(memory_backend) {
            "keyword"
        } else {
            "provider"
        };
        #[cfg(not(feature = "sqlite-vec"))]
        let retrieval_method = "keyword";

        #[cfg(feature = "sqlite-vec")]
        {
            if let Some(provider) = embedding {
                if memory_supports_local_semantic_ranking(memory_backend)
                    && !query.trim().is_empty()
                {
                    if let Ok(query_vec) = provider.embed(query).await {
                        let knn_result = call_blocking(db.clone(), move |db| {
                            db.knn_memories(chat_id, &query_vec, 20)
                        })
                        .await;
                        if let Ok(knn_rows) = knn_result {
                            let by_id: std::collections::HashMap<i64, &Memory> =
                                remaining.iter().map(|m| (m.id, m)).collect();
                            for (id, _) in knn_rows {
                                if let Some(mem) = by_id.get(&id) {
                                    relevance_ordered.push(*mem);
                                }
                            }
                            if !relevance_ordered.is_empty() {
                                retrieval_method = "knn";
                            }
                        }
                    }
                }
            }
        }

        #[cfg(not(feature = "sqlite-vec"))]
        {
            let _ = embedding;
        }

        if relevance_ordered.is_empty() {
            let query_tokens = tokenize_for_relevance(query);
            let mut scored: Vec<(usize, usize, &&Memory)> = remaining
                .iter()
                .enumerate()
                .map(|(idx, m)| {
                    (
                        score_relevance_with_cache(&m.content, &query_tokens),
                        idx,
                        m,
                    )
                })
                .collect();
            if !query.is_empty() {
                scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
            }
            relevance_ordered = scored.into_iter().map(|(_, _, m)| *m).collect();
        }

        let mut l2_count = 0usize;
        let mut l2_omitted = 0usize;
        if !relevance_ordered.is_empty() {
            out.push_str("# Relevant\n");
        }
        for (idx, m) in relevance_ordered.iter().enumerate() {
            let est = (m.content.len() / 4) + 10;
            if used_tokens + est > budget {
                l2_omitted = relevance_ordered.len().saturating_sub(idx);
                break;
            }
            used_tokens += est;
            injected_ids.insert(m.id);
            l2_count += 1;
            let scope = if m.chat_id.is_none() { "global" } else { "chat" };
            out.push_str(&format!("[{}] [{}] {}\n", m.category, scope, m.content));
        }

        if l2_omitted > 0 {
            out.push_str(&format!(
                "(+{l2_omitted} memories available via structured_memory_search tool)\n"
            ));
        }

        let _ = retrieval_method;
        let _ = l1_count;
        let _ = l2_count;
    }

    out.push_str("</structured_memories>\n");

    let candidate_count = memories.len();
    let selected_count = injected_ids.len();
    let omitted = candidate_count.saturating_sub(selected_count);
    let retrieval_method = "layered";
    let retrieval_method_owned = retrieval_method.to_string();
    let _ = call_blocking(db.clone(), move |d| {
        d.log_memory_injection(
            chat_id,
            &retrieval_method_owned,
            candidate_count,
            selected_count,
            omitted,
            used_tokens,
        )
        .map(|_| ())
    })
    .await;
    info!(
        "Memory injection (4-layer): chat {} -> {}/{} memories (L0:identity + L1:essential + L2:relevant), tokens_est={}, omitted={}",
        chat_id, selected_count, candidate_count, used_tokens, omitted
    );
    out
}

pub(crate) async fn apply_reflector_extractions(
    state: &Arc<AppState>,
    chat_id: i64,
    existing: &[Memory],
    extracted: &[serde_json::Value],
) -> ReflectorApplyOutcome {
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

    for item in extracted {
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

    ReflectorApplyOutcome {
        inserted,
        updated,
        skipped,
        dedup_method,
    }
}

#[cfg(feature = "sqlite-vec")]
pub(crate) fn memory_supports_local_semantic_ranking(memory_backend: &MemoryBackend) -> bool {
    memory_backend.supports_local_semantic_ranking()
}
