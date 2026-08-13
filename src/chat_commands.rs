use std::path::PathBuf;
use std::sync::Arc;

use crate::agent_engine::archive_conversation;
use crate::config::{
    normalize_model_name, resolve_model_name_with_fallback, Config, ResolvedLlmProviderProfile,
};
use crate::http_client::llm_user_agent;
use crate::run_control;
use crate::runtime::AppState;
use microclaw_core::llm_types::Message;
use microclaw_storage::db::{call_blocking, Database};
use microclaw_storage::usage::build_usage_report;
use microclaw_tools::todo_store::clear_todos;
use serde::Deserialize;
use tracing::warn;

pub fn is_slash_command(text: &str) -> bool {
    normalized_slash_command(text).is_some()
}

fn normalized_slash_command(text: &str) -> Option<&str> {
    let mut s = text.trim_start();
    loop {
        if s.starts_with('/') {
            return Some(s);
        }
        if s.starts_with("<@") {
            let end = s.find('>')?;
            s = s[end + 1..].trim_start();
            continue;
        }
        if let Some(rest) = s.strip_prefix('@') {
            if rest.is_empty() {
                return None;
            }
            let end = rest
                .char_indices()
                .find(|(_, c)| c.is_whitespace())
                .map(|(i, _)| i)
                .unwrap_or(rest.len());
            s = rest[end..].trim_start();
            continue;
        }
        return None;
    }
}

pub fn unknown_command_response() -> String {
    "Unknown command.".to_string()
}

/// Render the in-chat command reference. Pure (no `AppState`) so it can be
/// unit-tested and reused. Backs `/help`.
pub fn build_help_response() -> String {
    [
        "MicroClaw commands",
        "",
        "Session & context",
        "  /status              Session info: provider, model, message & task counts",
        "  /clear               Clear this chat's session + history (keep scheduled tasks)",
        "  /reset               Clear this chat's session + history",
        "  /reset memory        Clear this chat's long-term memory (AGENTS.md)",
        "  /stop                Abort the run currently in progress",
        "  /archive             Archive the current session to disk",
        "",
        "Model & provider",
        "  /model [name|reset]  Show or set the model for this chat",
        "  /models [provider]   List available models",
        "  /provider [name]     Show or set the provider for this chat",
        "  /providers           List configured providers",
        "",
        "Skills",
        "  /skills              List available skills",
        "  /reload-skills       Reload skills from disk",
        "  /learn               Distill this session into a reusable skill (control chats)",
        "",
        "Memory & usage",
        "  /user [clear]        View or clear your USER.md profile",
        "  /usage               Token usage report for this chat",
        "  /learning [run_id|journal] Show run evidence or the self-learning journal",
        "  /rewind [id]         List or restore conversation checkpoints",
        "",
        "Safety",
        "  /approvals [clear]   List or revoke standing high-risk tool approvals for this chat",
        "",
        "Diagnostics (admin only)",
        "  /log [N] [keyword]   Tail last N log lines (default 100, max 300); filter by keyword",
        "",
        "  /help                Show this message",
        "",
        "Tip: in groups, mention me first (e.g. @bot /status).",
    ]
    .join("\n")
}

async fn handle_learning_command(state: &AppState, chat_id: i64, args: &str) -> String {
    let requested = args.trim().to_string();
    if requested.len() > 128 {
        return "Usage: /learning [run_id|journal]".into();
    }
    if requested.eq_ignore_ascii_case("journal") {
        return match call_blocking(state.db.clone(), move |db| {
            Ok((
                db.get_learning_claims(Some(chat_id), 20)?,
                db.get_skill_candidates(Some(chat_id), 20)?,
                db.get_shadow_evaluations(Some(chat_id))?,
                db.get_learning_journal(Some(chat_id), 30)?,
            ))
        })
        .await
        {
            Ok((claims, candidates, evaluations, events)) => {
                let mut lines = vec![
                    "Learning Journal".to_string(),
                    format!(
                        "claims={} candidates={} shadow_evaluations={} events={}",
                        claims.len(),
                        candidates.len(),
                        evaluations.len(),
                        events.len()
                    ),
                ];
                for event in events {
                    lines.push(format!(
                        "  [{}] {} {}:{} — {}{}",
                        event.created_at,
                        event.event_type,
                        event.entity_type,
                        event.entity_id,
                        event.summary,
                        event
                            .undo_action
                            .as_deref()
                            .map(|action| format!(" (undo={action})"))
                            .unwrap_or_default()
                    ));
                }
                lines.join("\n")
            }
            Err(error) => format!("Failed to load Learning Journal: {error}"),
        };
    }
    let detail = call_blocking(state.db.clone(), move |db| {
        let run_id = if requested.is_empty() {
            db.latest_experience_run_id(chat_id)?
        } else {
            Some(requested)
        };
        let Some(run_id) = run_id else {
            return Ok(None);
        };
        Ok(db
            .get_experience_run_detail(&run_id)?
            .filter(|detail| detail.run.chat_id == chat_id))
    })
    .await;
    let detail = match detail {
        Ok(Some(detail)) => detail,
        Ok(None) => return "No matching learning run in this chat.".into(),
        Err(error) => return format!("Failed to load learning run: {error}"),
    };
    format_learning_run_detail(&detail)
}

fn format_learning_run_detail(detail: &microclaw_storage::db::ExperienceRunDetail) -> String {
    let mut lines = vec![
        format!("Learning run {}", detail.run.run_id),
        format!(
            "status={} kind={} duration_ms={} tokens={} tool_calls={} tool_errors={}",
            detail.run.status,
            detail.run.run_kind,
            detail.run.duration_ms.unwrap_or_default(),
            detail.run.input_tokens + detail.run.output_tokens,
            detail.run.tool_calls,
            detail.run.tool_errors
        ),
        format!("objective: {}", detail.run.objective),
        format!(
            "task: {} / {} [{}]",
            detail.run.task_signature.task_type,
            detail.run.task_signature.task_family,
            detail.run.task_signature.capability_tags.join(", ")
        ),
        format!(
            "result: {}",
            detail.run.result_summary.as_deref().unwrap_or("(none)")
        ),
        "".into(),
        format!("Experiences used ({})", detail.retrieved_experiences.len()),
    ];
    if detail.retrieved_experiences.is_empty() {
        lines.push("  (none)".into());
    } else {
        for retrieval in &detail.retrieved_experiences {
            lines.push(format!(
                "  #{} {} score={:.3} objective={} result={} reason={}",
                retrieval.rank,
                retrieval.source_run_id,
                retrieval.relevance_score,
                retrieval.source_objective,
                retrieval
                    .source_result_summary
                    .as_deref()
                    .unwrap_or("(none)"),
                retrieval.selection_reason
            ));
        }
    }
    lines.push(String::new());
    lines.push(format!(
        "Experiences rejected ({})",
        detail.rejected_experiences.len()
    ));
    if detail.rejected_experiences.is_empty() {
        lines.push("  (none)".into());
    } else {
        for rejection in &detail.rejected_experiences {
            lines.push(format!(
                "  {} score={:.3} objective={} reason={}",
                rejection.source_run_id,
                rejection.relevance_score,
                rejection.source_objective,
                rejection.rejection_reason
            ));
        }
    }
    lines.push(String::new());
    lines.push(format!("Outcome evidence ({})", detail.outcomes.len()));
    if detail.outcomes.is_empty() {
        lines.push("  (none)".into());
    } else {
        for outcome in &detail.outcomes {
            let evidence = outcome.evidence.as_deref().unwrap_or("(none)");
            let end = microclaw_core::text::floor_char_boundary(evidence, evidence.len().min(500));
            lines.push(format!(
                "  [{}:{}] {} confidence={:.2}: {}",
                outcome.source_kind,
                outcome.source_name,
                outcome.verdict,
                outcome.confidence,
                &evidence[..end]
            ));
        }
    }
    lines.push(String::new());
    lines.push(format!("Skills used ({})", detail.activated_skills.len()));
    for skill in &detail.activated_skills {
        lines.push(format!(
            "  {} v{}",
            skill.skill_name,
            skill
                .skill_version
                .map(|version| version.to_string())
                .unwrap_or_else(|| "?".into())
        ));
    }
    lines.join("\n")
}

/// `/learn` — user-triggered skill distillation (the Hermes `/learn`
/// pattern). Enqueues a forced skill-review job: the worker bypasses the
/// automatic threshold/success gates (the user explicitly asked) but keeps
/// all content-security scans and the agent-created cap, then posts the
/// outcome back to the chat. Queued rather than inline because slash
/// commands must stay fast — an inline LLM round-trip would stall
/// single-threaded channel loops (e.g. the Weixin poller) and webhook
/// handlers. Restricted to control chats: distilled skills alter future
/// agent behavior in every chat.
async fn handle_learn_command(state: &AppState, chat_id: i64) -> String {
    if !state.config.is_control_chat(chat_id) {
        return "Permission denied: /learn is restricted to control chats.".to_string();
    }
    state.skill_review_queue.enqueue_learn(chat_id);
    "Distilling this session into a skill — I'll post the result here shortly.".to_string()
}

pub(crate) fn format_learn_reply(outcome: &crate::skill_review::LearnOutcome) -> String {
    use crate::skill_review::LearnOutcome;
    match outcome {
        LearnOutcome::Applied(applied) => {
            let verb = match applied.action_kind {
                "create" => "Created",
                "edit" => "Updated",
                "patch" => "Patched",
                other => other,
            };
            format!(
                "{verb} skill '{}' (v{}) from this session. It will be considered in future \
                 conversations; use /skills to inspect it or skill_manage to edit/delete it.",
                applied.name, applied.version
            )
        }
        LearnOutcome::Nothing(reason) => format!("No skill saved: {reason}"),
        LearnOutcome::Skipped(reason) => format!("Nothing to learn: {reason}"),
        LearnOutcome::Error(e) => format!("Learn failed: {e}"),
    }
}

/// Show or clear the per-chat USER.md user model. Backs the `/user` slash
/// command. Lives outside `handle_chat_command` so it can be unit-tested
/// without spinning up the full AppState match arm.
fn handle_user_command(state: &AppState, caller_channel: &str, chat_id: i64, args: &str) -> String {
    let args = args.trim();
    if args == "clear" {
        match state.memory.clear_chat_user_model(caller_channel, chat_id) {
            Ok(true) => "USER.md cleared. The reflector will rebuild it on the next tick.".into(),
            Ok(false) => "No USER.md to clear for this chat.".into(),
            Err(e) => format!("Failed to clear USER.md: {e}"),
        }
    } else if args.is_empty() {
        match state.memory.read_chat_user_model(caller_channel, chat_id) {
            Some(content) if !content.trim().is_empty() => {
                let cap = state.config.user_model_max_chars;
                let cap_note = if cap == 0 {
                    "(layer disabled — user_model_max_chars=0)".to_string()
                } else {
                    format!("({}/{} chars)", content.chars().count(), cap)
                };
                format!("USER.md {cap_note}:\n\n{}", content.trim())
            }
            _ => "No USER.md yet — the reflector populates it from PROFILE memories. Send a few personal facts and check back after the next reflector tick.".into(),
        }
    } else {
        "Usage: /user            show current USER.md\n       /user clear     remove USER.md so the reflector rebuilds it".into()
    }
}

/// Handle `/rewind` (list checkpoints) or `/rewind <hash>` (restore).
async fn handle_rewind_command(
    state: &AppState,
    caller_channel: &str,
    chat_id: i64,
    args: &str,
) -> String {
    if !state.config.checkpoints_enabled {
        return "Checkpoints are disabled. Set `checkpoints_enabled: true` in microclaw.config.yaml \
                to record per-turn snapshots of this chat's working directory."
            .into();
    }

    let working_dir = microclaw_tools::runtime::chat_working_dir(
        std::path::Path::new(&state.config.working_dir),
        caller_channel,
        chat_id,
    );
    let shadow_root = std::path::PathBuf::from(&state.config.data_dir).join("checkpoints");
    let shadow_repo = crate::checkpoint::shadow_repo_path(&shadow_root, &working_dir);

    if args.is_empty() {
        match crate::checkpoint::list(&shadow_repo, &working_dir, 20).await {
            Ok(entries) if entries.is_empty() => {
                "No checkpoints yet — they're created at the start of each agent turn that modifies files."
                    .into()
            }
            Ok(entries) => {
                let mut out = String::from("Recent checkpoints (newest first):\n\n");
                for e in entries {
                    out.push_str(&format!(
                        "  {}  {}  {}\n",
                        e.commit, e.timestamp, e.label
                    ));
                }
                out.push_str("\nUse `/rewind <hash>` to restore.");
                out
            }
            Err(e) => format!("Failed to list checkpoints: {e}"),
        }
    } else {
        match crate::checkpoint::restore(&shadow_repo, &working_dir, args).await {
            Ok(()) => format!("Restored working directory to checkpoint {args}."),
            Err(e) => format!("Restore failed: {e}"),
        }
    }
}

#[derive(Clone, Copy)]
enum PersistedOverride<'a> {
    Unchanged,
    Clear,
    Set(&'a str),
}

fn config_path_for_save() -> Result<PathBuf, String> {
    match Config::resolve_config_path() {
        Ok(Some(path)) => Ok(path),
        Ok(None) => Ok(PathBuf::from("./microclaw.config.yaml")),
        Err(e) => Err(e.to_string()),
    }
}

fn persist_channel_llm_overrides(
    config: &Config,
    caller_channel: &str,
    provider: PersistedOverride<'_>,
    model: PersistedOverride<'_>,
) -> Result<(), String> {
    let path = config_path_for_save()?;
    let mut cfg = Config::load().unwrap_or_else(|_| config.clone());
    let before_cfg = cfg.clone();
    match provider {
        PersistedOverride::Unchanged => {}
        PersistedOverride::Clear => cfg.set_provider_override_for_channel(caller_channel, None),
        PersistedOverride::Set(value) => {
            cfg.set_provider_override_for_channel(caller_channel, Some(value))
        }
    }
    match model {
        PersistedOverride::Unchanged => {}
        PersistedOverride::Clear => cfg.set_model_override_for_channel(caller_channel, None),
        PersistedOverride::Set(value) => {
            cfg.set_model_override_for_channel(caller_channel, Some(value))
        }
    }
    cfg.post_deserialize().map_err(|e| e.to_string())?;
    crate::config_persistence::save_config_delta_preserving_comments(&path, &before_cfg, &cfg)
        .map_err(|e| e.to_string())
}

/// Default / maximum number of log lines a single `/log` invocation tails.
const LOG_TAIL_DEFAULT_LINES: usize = 100;
const LOG_TAIL_MAX_LINES: usize = 300;
/// When a keyword filter is given, scan up to this many recent lines for matches
/// before keeping the last N. Bounds the work while still reaching back far
/// enough to catch a rare term (e.g. an error from an hour ago).
const LOG_FILTER_SCAN_LINES: usize = 5000;

/// Tail the bot's own log files into chat for troubleshooting. Supports
/// `/log [N]`, `/log read 100`, and a keyword filter: `/log error`,
/// `/log 50 scheduler`. Admin-gated: logs can contain other chats' content and
/// secrets, so access is restricted to configured `control_chat_ids`. File
/// logging is only active under the gateway (`MICROCLAW_GATEWAY`); in console
/// mode logs stream to stdout and there is no file to read.
fn build_log_response(config: &Config, chat_id: i64, command: &str) -> String {
    // Default-deny when no control chats are configured.
    if config.control_chat_ids.is_empty() {
        return "Log access is disabled. Set `control_chat_ids` in the config to your admin chat(s) first — logs can contain other chats' content and secrets, so this is admin-only.".to_string();
    }
    if !config.is_control_chat(chat_id) {
        return "Not authorized: `/log` is restricted to the configured control chat(s)."
            .to_string();
    }

    // Parse the args after `/log`: a bare number sets the line count; the verbs
    // "read"/"print" are ignored; anything else becomes a case-insensitive
    // keyword filter (joined when multiple words are given).
    let mut requested_lines: Option<usize> = None;
    let mut filter_tokens: Vec<&str> = Vec::new();
    for tok in command.split_whitespace().skip(1) {
        if let Ok(n) = tok.parse::<usize>() {
            requested_lines.get_or_insert(n);
        } else if tok.eq_ignore_ascii_case("read") || tok.eq_ignore_ascii_case("print") {
            continue;
        } else {
            filter_tokens.push(tok);
        }
    }
    let lines = requested_lines
        .unwrap_or(LOG_TAIL_DEFAULT_LINES)
        .clamp(1, LOG_TAIL_MAX_LINES);
    let filter = (!filter_tokens.is_empty()).then(|| filter_tokens.join(" ").to_lowercase());

    let log_dir = PathBuf::from(config.runtime_data_dir()).join("logs");
    // With a filter, scan a wider window then keep the last N matches; otherwise
    // just tail the last N lines directly.
    let scan = if filter.is_some() {
        LOG_FILTER_SCAN_LINES
    } else {
        lines
    };
    match crate::logging::read_last_lines_from_logs(&log_dir, scan) {
        Ok(rows) if rows.is_empty() => format!(
            "No log lines found in {}. File logging is only active when running under the gateway (MICROCLAW_GATEWAY); in console mode logs go to stdout.",
            log_dir.display()
        ),
        Ok(rows) => {
            let (rows, suffix) = match &filter {
                Some(kw) => {
                    let mut matched: Vec<String> = rows
                        .into_iter()
                        .filter(|l| l.to_lowercase().contains(kw))
                        .collect();
                    if matched.len() > lines {
                        matched = matched.split_off(matched.len() - lines);
                    }
                    (matched, format!(" matching \"{kw}\""))
                }
                None => (rows, String::new()),
            };
            if rows.is_empty() {
                return format!("No log line{suffix} in the last {LOG_FILTER_SCAN_LINES} lines.");
            }
            let body = rows.join("\n");
            format!(
                "📜 Last {} log line(s){suffix}:\n```\n{body}\n```",
                rows.len()
            )
        }
        Err(e) => format!("Failed to read logs from {}: {e}", log_dir.display()),
    }
}

pub async fn handle_chat_command(
    state: &AppState,
    chat_id: i64,
    caller_channel: &str,
    command_text: &str,
    sender_id: Option<&str>,
) -> Option<String> {
    let trimmed = normalized_slash_command(command_text)?.trim();

    if trimmed == "/help" || trimmed == "/commands" || trimmed == "/?" {
        return Some(build_help_response());
    }

    if trimmed == "/reset memory" {
        let _ = call_blocking(state.db.clone(), move |db| db.clear_chat_memory(chat_id)).await;
        let groups_dir = std::path::PathBuf::from(&state.config.data_dir).join("groups");
        let chat_memory_path = groups_dir
            .join(caller_channel)
            .join(chat_id.to_string())
            .join("AGENTS.md");
        if let Err(e) = std::fs::remove_file(&chat_memory_path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                warn!(
                    "Failed to remove chat memory file for chat {} at {}: {}",
                    chat_id,
                    chat_memory_path.display(),
                    e
                );
            }
        }
        return Some("Memory cleared for this chat.".to_string());
    }

    if trimmed == "/clear" {
        let _ = call_blocking(state.db.clone(), move |db| {
            db.clear_chat_conversation(chat_id)
        })
        .await;
        let groups_dir = std::path::PathBuf::from(&state.config.data_dir).join("groups");
        if let Err(e) = clear_todos(&groups_dir, caller_channel, chat_id) {
            warn!("Failed to clear TODO.json for chat {}: {}", chat_id, e);
        }
        return Some("Context cleared (session + chat history, scheduled tasks kept).".to_string());
    }

    if trimmed == "/plan" || trimmed.starts_with("/plan ") {
        let arg = trimmed.strip_prefix("/plan").map(str::trim).unwrap_or("");
        let mode_key = format!("chat_mode:{chat_id}");
        if arg.eq_ignore_ascii_case("off") || arg.eq_ignore_ascii_case("exit") {
            let plan_key = format!("pending_plan_approval:{chat_id}");
            let _ = call_blocking(state.db.clone(), move |db| {
                db.delete_runtime_meta(&mode_key)?;
                db.delete_runtime_meta(&plan_key)?;
                Ok::<_, microclaw_core::error::MicroClawError>(())
            })
            .await;
            return Some("Plan mode off — back to normal execution.".to_string());
        }
        if arg.is_empty() || arg.eq_ignore_ascii_case("on") {
            let _ = call_blocking(state.db.clone(), move |db| {
                db.set_runtime_meta(&mode_key, "plan")
            })
            .await;
            return Some(
                "📋 Plan mode on: I'll research with read-only tools and present a plan for approval before changing anything. `/plan off` to exit."
                    .to_string(),
            );
        }
        return Some("Usage: /plan (enter plan mode), /plan off (exit).".to_string());
    }

    if trimmed == "/reset" {
        let _ = call_blocking(state.db.clone(), move |db| db.clear_chat_context(chat_id)).await;
        let groups_dir = std::path::PathBuf::from(&state.config.data_dir).join("groups");
        if let Err(e) = clear_todos(&groups_dir, caller_channel, chat_id) {
            warn!("Failed to clear TODO.json for chat {}: {}", chat_id, e);
        }
        return Some("Context cleared (session + chat history).".to_string());
    }

    if trimmed == "/stop" {
        let stopped = run_control::abort_runs(caller_channel, chat_id).await;
        if stopped > 0 {
            return Some(format!("Stopping current run ({stopped} active)."));
        }
        return Some("No active run in this chat.".to_string());
    }

    if trimmed == "/skills" {
        return Some(state.skills.list_skills_formatted());
    }

    if let Some(rest) = trimmed.strip_prefix("/rewind") {
        return Some(handle_rewind_command(state, caller_channel, chat_id, rest.trim()).await);
    }

    if let Some(args) = trimmed.strip_prefix("/user") {
        return Some(handle_user_command(state, caller_channel, chat_id, args));
    }

    if trimmed == "/reload-skills" {
        let count = state.skills.reload().len();
        return Some(format!("Reloaded {count} skills from disk."));
    }

    if trimmed == "/learn" {
        return Some(handle_learn_command(state, chat_id).await);
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

    if trimmed == "/learning" || trimmed.starts_with("/learning ") {
        let args = trimmed.strip_prefix("/learning").unwrap_or_default();
        return Some(handle_learning_command(state, chat_id, args).await);
    }

    if trimmed == "/status" {
        return Some(
            build_status_response(
                state.db.clone(),
                &state.config,
                state.llm_provider_overrides.clone(),
                state.llm_model_overrides.clone(),
                chat_id,
                caller_channel,
            )
            .await,
        );
    }

    if trimmed == "/approvals" || trimmed == "/approvals clear" {
        let prefix = format!("approved_tool:{chat_id}:");
        if trimmed == "/approvals clear" {
            let removed = call_blocking(state.db.clone(), {
                let prefix = prefix.clone();
                move |db| {
                    let removed = db.delete_runtime_meta_prefix(&prefix)?;
                    if removed > 0 {
                        db.log_audit_event(
                            "approval",
                            &format!("chat:{chat_id}"),
                            "standing_grants_cleared",
                            None,
                            "removed",
                            Some(&format!("{removed} grant(s)")),
                        )?;
                    }
                    Ok::<_, microclaw_core::error::MicroClawError>(removed)
                }
            })
            .await;
            return Some(match removed {
                Ok(0) => "No standing tool approvals to clear for this chat.".to_string(),
                Ok(n) => format!("Cleared {n} standing tool approval(s) for this chat."),
                Err(e) => format!("Failed to clear standing approvals: {e}"),
            });
        }
        let grants = call_blocking(state.db.clone(), move |db| {
            db.list_runtime_meta_prefix(&prefix)
        })
        .await;
        return Some(match grants {
            Ok(rows) if rows.is_empty() => {
                "No standing tool approvals for this chat. Reply \"2\" or \"always\" to an \
                 approval prompt to add one."
                    .to_string()
            }
            Ok(rows) => {
                let mut out = String::from("Standing tool approvals for this chat:\n");
                for (key, since) in rows {
                    let tool = key.rsplit(':').next().unwrap_or(&key);
                    out.push_str(&format!("- {tool} (since {since})\n"));
                }
                out.push_str("Revoke them all with /approvals clear.");
                out
            }
            Err(e) => format!("Failed to list standing approvals: {e}"),
        });
    }

    if trimmed == "/log"
        || trimmed == "/logs"
        || trimmed.starts_with("/log ")
        || trimmed.starts_with("/logs ")
    {
        return Some(build_log_response(&state.config, chat_id, trimmed));
    }

    if trimmed == "/start" {
        if let Some(id) = sender_id.map(str::trim).filter(|v| !v.is_empty()) {
            return Some(format!("Hello MicroClaw :) Your ID: {id}"));
        }
        return Some("Hello MicroClaw :)".to_string());
    }

    if trimmed == "/providers" {
        return Some(
            build_providers_response(
                &state.config,
                state.llm_provider_overrides.clone(),
                state.llm_model_overrides.clone(),
                caller_channel,
            )
            .await,
        );
    }

    if trimmed == "/provider" || trimmed.starts_with("/provider ") {
        return Some(
            build_provider_response_with_persistence(
                &state.config,
                state.llm_provider_overrides.clone(),
                state.llm_model_overrides.clone(),
                caller_channel,
                chat_id,
                trimmed,
                true,
            )
            .await,
        );
    }

    if trimmed == "/models" || trimmed.starts_with("/models ") {
        return Some(
            build_models_response(
                &state.config,
                state.llm_provider_overrides.clone(),
                state.llm_model_overrides.clone(),
                caller_channel,
                trimmed,
            )
            .await,
        );
    }

    if trimmed == "/model" || trimmed.starts_with("/model ") {
        return Some(
            build_model_response_with_persistence(
                &state.config,
                state.llm_provider_overrides.clone(),
                state.llm_model_overrides.clone(),
                caller_channel,
                chat_id,
                trimmed,
                true,
            )
            .await,
        );
    }

    if let Some(plugin_response) =
        maybe_handle_plugin_command(&state.config, trimmed, chat_id, caller_channel).await
    {
        return Some(plugin_response);
    }

    None
}

pub async fn build_status_response(
    db: Arc<Database>,
    config: &Config,
    llm_provider_overrides: Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>>,
    llm_model_overrides: Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>>,
    chat_id: i64,
    caller_channel: &str,
) -> String {
    let (profile, model) = resolve_effective_provider_and_model(
        config,
        &llm_provider_overrides,
        &llm_model_overrides,
        caller_channel,
    )
    .await;
    let provider = profile.alias.clone();

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

    let runtime_line = match call_blocking(db.clone(), move |db| {
        let active = db
            .list_active_turns()?
            .into_iter()
            .find(|turn| turn.chat_id == chat_id);
        let delivery = db.outbound_delivery_health()?;
        let recoveries = db.list_audit_logs(Some("turn_recovery"), 20)?.len();
        Ok::<_, microclaw_core::error::MicroClawError>((active, delivery, recoveries))
    })
    .await
    {
        Ok((Some(turn), delivery, recoveries)) => format!(
            "Durable run: {} iteration={} resumable={} progress={}\n\
             Delivery: pending={} retrying={} failed={}\n\
             Recoveries recorded: {}",
            turn.phase,
            turn.iteration + 1,
            turn.resumable,
            turn.progress_text.as_deref().unwrap_or("starting"),
            delivery.pending_chunks,
            delivery.retry_chunks,
            delivery.failed_chunks,
            recoveries
        ),
        Ok((None, delivery, recoveries)) => format!(
            "Durable run: idle\nDelivery: pending={} retrying={} failed={}\nRecoveries recorded: {}",
            delivery.pending_chunks, delivery.retry_chunks, delivery.failed_chunks, recoveries
        ),
        Err(error) => format!("Durable runtime: unavailable ({error})"),
    };

    let since_24h = (chrono::Utc::now() - chrono::Duration::hours(24)).to_rfc3339();
    let health_line = match call_blocking(db.clone(), {
        let since = since_24h.clone();
        move |db| {
            let dlq = db.count_scheduled_task_dlq(false)?;
            let contracts = db.contract_verdict_counts_since(&since)?;
            Ok::<_, microclaw_core::error::MicroClawError>((dlq, contracts))
        }
    })
    .await
    {
        Ok((dlq, (verified, failed))) => {
            let contracts = if verified + failed == 0 {
                "Contracts (24h): none".to_string()
            } else {
                format!("Contracts (24h): verified={verified} failed={failed}")
            };
            format!("Scheduler DLQ: {dlq} unreplayed\n{contracts}")
        }
        Err(e) => format!("Scheduler DLQ: unavailable ({e})"),
    };

    let budget_line = {
        let budget = config.token_budget.daily_per_chat;
        if budget > 0 {
            match call_blocking(db.clone(), move |db| {
                db.get_llm_usage_summary_since(Some(chat_id), Some(&since_24h))
            })
            .await
            {
                Ok(usage) => format!(
                    "Token budget: {} of {budget} used in the last 24h",
                    usage.total_tokens
                ),
                Err(e) => format!("Token budget: unavailable ({e})"),
            }
        } else {
            "Token budget: off".to_string()
        }
    };

    let provider_snapshot = crate::llm::provider_failover_snapshot();
    let provider_line = format!(
        "Provider health: fallbacks={} consecutive_failures={}{}",
        provider_snapshot.total_fallbacks,
        provider_snapshot.consecutive_failures,
        if provider_snapshot.breaker_open {
            " (circuit breaker OPEN)"
        } else {
            ""
        }
    );

    let restarts = crate::supervision::restart_counts();
    let restart_line = if restarts.is_empty() {
        "Loop restarts: none".to_string()
    } else {
        let parts: Vec<String> = restarts
            .iter()
            .map(|(name, count)| format!("{name}={count}"))
            .collect();
        format!("Loop restarts: {}", parts.join(" "))
    };

    format!(
        "Status\nChannel: {caller_channel}\nProvider: {provider}\nModel: {model}\n{session_line}\n{task_line}\n{runtime_line}\n{health_line}\n{budget_line}\n{provider_line}\n{restart_line}"
    )
}

pub async fn build_model_response(
    config: &Config,
    llm_provider_overrides: Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>>,
    llm_model_overrides: Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>>,
    caller_channel: &str,
    _chat_id: i64,
    command_text: &str,
) -> String {
    build_model_response_with_persistence(
        config,
        llm_provider_overrides,
        llm_model_overrides,
        caller_channel,
        _chat_id,
        command_text,
        false,
    )
    .await
}

/// Override-map key for a per-chat model/provider override
/// (`/model here …`). `#` cannot appear in channel names, so chat-scoped
/// keys never collide with channel-wide ones.
pub fn chat_scoped_override_key(channel: &str, chat_id: i64) -> String {
    format!("{channel}#{chat_id}")
}

async fn build_model_response_with_persistence(
    config: &Config,
    llm_provider_overrides: Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>>,
    llm_model_overrides: Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>>,
    caller_channel: &str,
    chat_id: i64,
    command_text: &str,
    persist_to_config: bool,
) -> String {
    let caller_channel = caller_channel.to_string();
    let requested = command_text
        .trim()
        .strip_prefix("/model")
        .map(str::trim)
        .unwrap_or("");
    let (profile, current_model) = resolve_effective_provider_and_model(
        config,
        &llm_provider_overrides,
        &llm_model_overrides,
        &caller_channel,
    )
    .await;
    let provider = profile.alias.clone();

    // `/model here <name>` — override for this chat only (runtime scope;
    // cleared with `/model here reset` or on restart).
    if let Some(rest) =
        requested
            .strip_prefix("here ")
            .or(if requested == "here" { Some("") } else { None })
    {
        let rest = rest.trim();
        let chat_key = chat_scoped_override_key(&caller_channel, chat_id);
        if rest.is_empty() {
            let overrides = llm_model_overrides.read().await;
            return match overrides.get(&chat_key) {
                Some(model) => format!("Model for this chat: {provider} / {model} (per-chat override; `/model here reset` to clear)"),
                None => format!("No per-chat model override. Current provider/model: {provider} / {current_model}. Set one with `/model here <name>`."),
            };
        }
        if rest.eq_ignore_ascii_case("reset") || rest.eq_ignore_ascii_case("default") {
            let mut overrides = llm_model_overrides.write().await;
            overrides.remove(&chat_key);
            return format!(
                "Per-chat model override cleared. Current provider/model: {provider} / {current_model}"
            );
        }
        if normalize_model_name(rest).is_none() {
            return format!(
                "Model '{rest}' is not a valid model id. Use `/model here reset` to clear the per-chat override."
            );
        }
        let mut allowed_models = profile.models.clone();
        if is_placeholder_model_list(&allowed_models) {
            if let Ok(live) = fetch_models_from_provider_api(&profile).await {
                if !live.is_empty() {
                    allowed_models = live;
                }
            }
        }
        if !allowed_models.is_empty() && !allowed_models.iter().any(|m| m == rest) {
            return format!(
                "Model '{rest}' is not configured for provider '{provider}'. Available: {}",
                allowed_models.join(", ")
            );
        }
        let mut overrides = llm_model_overrides.write().await;
        overrides.insert(chat_key, rest.to_string());
        return format!(
            "Model switched for this chat to: {provider} / {rest} (runtime only; `/model here reset` to clear)"
        );
    }

    if requested.is_empty() {
        return format!("Current provider/model: {provider} / {current_model}");
    }

    if requested.eq_ignore_ascii_case("reset") || requested.eq_ignore_ascii_case("default") {
        if persist_to_config {
            if let Err(e) = persist_channel_llm_overrides(
                config,
                &caller_channel,
                PersistedOverride::Unchanged,
                PersistedOverride::Clear,
            ) {
                return format!("Failed to persist model override reset: {e}");
            }
        }
        let mut overrides = llm_model_overrides.write().await;
        overrides.remove(&caller_channel);
        return format!(
            "Model override cleared. Current provider/model: {provider} / {}",
            profile.default_model
        );
    }

    if normalize_model_name(requested).is_none() {
        return format!(
            "Model '{requested}' is not a valid model id. Use `/model reset` to clear the override."
        );
    }

    let mut allowed_models = profile.models.clone();
    if is_placeholder_model_list(&allowed_models) {
        if let Ok(live) = fetch_models_from_provider_api(&profile).await {
            if !live.is_empty() {
                allowed_models = live;
            }
        }
    }
    if !allowed_models.is_empty() && !allowed_models.iter().any(|m| m == requested) {
        return format!(
            "Model '{requested}' is not configured for provider '{provider}'. Available: {}",
            allowed_models.join(", ")
        );
    }

    if persist_to_config {
        if let Err(e) = persist_channel_llm_overrides(
            config,
            &caller_channel,
            PersistedOverride::Unchanged,
            PersistedOverride::Set(requested),
        ) {
            return format!("Failed to persist model override: {e}");
        }
    }
    let mut overrides = llm_model_overrides.write().await;
    overrides.insert(caller_channel.clone(), requested.to_string());
    format!("Model switched for this channel to: {provider} / {requested}")
}

pub async fn build_providers_response(
    config: &Config,
    llm_provider_overrides: Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>>,
    llm_model_overrides: Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>>,
    caller_channel: &str,
) -> String {
    let (active_profile, active_model) = resolve_effective_provider_and_model(
        config,
        &llm_provider_overrides,
        &llm_model_overrides,
        caller_channel,
    )
    .await;
    let mut lines = vec!["Configured providers:".to_string()];
    for profile in config.list_llm_provider_profiles() {
        let marker = if profile.alias == active_profile.alias {
            " (active)"
        } else {
            ""
        };
        lines.push(format!(
            "- {}{} -> backend={}, default_model={}",
            profile.alias, marker, profile.provider, profile.default_model
        ));
    }
    lines.push(format!(
        "Current provider/model: {} / {}",
        active_profile.alias, active_model
    ));
    lines.join("\n")
}

pub async fn build_provider_response(
    config: &Config,
    llm_provider_overrides: Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>>,
    llm_model_overrides: Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>>,
    caller_channel: &str,
    command_text: &str,
) -> String {
    build_provider_response_with_persistence(
        config,
        llm_provider_overrides,
        llm_model_overrides,
        caller_channel,
        0,
        command_text,
        false,
    )
    .await
}

async fn build_provider_response_with_persistence(
    config: &Config,
    llm_provider_overrides: Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>>,
    llm_model_overrides: Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>>,
    caller_channel: &str,
    chat_id: i64,
    command_text: &str,
    persist_to_config: bool,
) -> String {
    let requested = command_text
        .trim()
        .strip_prefix("/provider")
        .map(str::trim)
        .unwrap_or("");

    // `/provider here <alias>` — override for this chat only (runtime
    // scope; cleared with `/provider here reset` or on restart).
    if let Some(rest) =
        requested
            .strip_prefix("here ")
            .or(if requested == "here" { Some("") } else { None })
    {
        let rest = rest.trim();
        let chat_key = chat_scoped_override_key(caller_channel, chat_id);
        if rest.is_empty() {
            let overrides = llm_provider_overrides.read().await;
            return match overrides.get(&chat_key) {
                Some(alias) => format!(
                    "Provider for this chat: {alias} (per-chat override; `/provider here reset` to clear)"
                ),
                None => "No per-chat provider override. Set one with `/provider here <alias>`."
                    .to_string(),
            };
        }
        if rest.eq_ignore_ascii_case("reset") || rest.eq_ignore_ascii_case("default") {
            {
                let mut provider_overrides = llm_provider_overrides.write().await;
                provider_overrides.remove(&chat_key);
            }
            {
                let mut model_overrides = llm_model_overrides.write().await;
                model_overrides.remove(&chat_key);
            }
            return "Per-chat provider override cleared.".to_string();
        }
        let requested_alias = rest.to_ascii_lowercase();
        let Some(profile) = config.resolve_llm_provider_profile(&requested_alias) else {
            let names = config
                .list_llm_provider_profiles()
                .into_iter()
                .map(|p| p.alias)
                .collect::<Vec<_>>()
                .join(", ");
            return format!("Unknown provider '{rest}'. Available providers: {names}");
        };
        {
            let mut provider_overrides = llm_provider_overrides.write().await;
            provider_overrides.insert(chat_key.clone(), profile.alias.clone());
        }
        {
            let mut model_overrides = llm_model_overrides.write().await;
            model_overrides.remove(&chat_key);
        }
        return format!(
            "Provider switched for this chat to: {} (backend={}), model {} (runtime only; `/provider here reset` to clear)",
            profile.alias, profile.provider, profile.default_model
        );
    }

    if requested.is_empty() {
        let (profile, model) = resolve_effective_provider_and_model(
            config,
            &llm_provider_overrides,
            &llm_model_overrides,
            caller_channel,
        )
        .await;
        return format!(
            "Current provider/model: {} / {} (backend={})",
            profile.alias, model, profile.provider
        );
    }

    if requested.eq_ignore_ascii_case("reset") || requested.eq_ignore_ascii_case("default") {
        if persist_to_config {
            if let Err(e) = persist_channel_llm_overrides(
                config,
                caller_channel,
                PersistedOverride::Clear,
                PersistedOverride::Clear,
            ) {
                return format!("Failed to persist provider override reset: {e}");
            }
        }
        {
            let mut provider_overrides = llm_provider_overrides.write().await;
            provider_overrides.remove(caller_channel);
        }
        {
            let mut model_overrides = llm_model_overrides.write().await;
            model_overrides.remove(caller_channel);
        }
        let profile = config
            .resolve_llm_provider_profile(&config.llm_provider)
            .expect("default provider should resolve");
        return format!(
            "Provider override cleared. Current provider/model: {} / {}",
            profile.alias, profile.default_model
        );
    }

    let requested_alias = requested.to_ascii_lowercase();
    let Some(profile) = config.resolve_llm_provider_profile(&requested_alias) else {
        let names = config
            .list_llm_provider_profiles()
            .into_iter()
            .map(|p| p.alias)
            .collect::<Vec<_>>()
            .join(", ");
        return format!("Unknown provider '{requested}'. Available providers: {names}");
    };
    if persist_to_config {
        if let Err(e) = persist_channel_llm_overrides(
            config,
            caller_channel,
            PersistedOverride::Set(&profile.alias),
            PersistedOverride::Clear,
        ) {
            return format!("Failed to persist provider override: {e}");
        }
    }
    {
        let mut provider_overrides = llm_provider_overrides.write().await;
        provider_overrides.insert(caller_channel.to_string(), profile.alias.clone());
    }
    {
        let mut model_overrides = llm_model_overrides.write().await;
        model_overrides.remove(caller_channel);
    }
    format!(
        "Provider switched for this channel to: {} (backend={}), model reset to {}",
        profile.alias, profile.provider, profile.default_model
    )
}

pub async fn build_models_response(
    config: &Config,
    llm_provider_overrides: Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>>,
    llm_model_overrides: Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>>,
    caller_channel: &str,
    command_text: &str,
) -> String {
    let requested = command_text
        .trim()
        .strip_prefix("/models")
        .map(str::trim)
        .unwrap_or("");
    let (api_mode, provider_arg) = parse_models_command_args(requested);
    let profile = if requested.is_empty() {
        resolve_effective_provider_and_model(
            config,
            &llm_provider_overrides,
            &llm_model_overrides,
            caller_channel,
        )
        .await
        .0
    } else {
        let alias = provider_arg.unwrap_or_default().to_ascii_lowercase();
        if alias.is_empty() && api_mode {
            resolve_effective_provider_and_model(
                config,
                &llm_provider_overrides,
                &llm_model_overrides,
                caller_channel,
            )
            .await
            .0
        } else {
            let Some(profile) = config.resolve_llm_provider_profile(&alias) else {
                return format!(
                    "Unknown provider '{}'. Try /providers",
                    provider_arg.unwrap_or_default()
                );
            };
            profile
        }
    };
    if api_mode {
        return match fetch_models_from_provider_api(&profile).await {
            Ok(models) => {
                let listed = models
                    .iter()
                    .take(50)
                    .map(|m| format!("- {m}"))
                    .collect::<Vec<_>>();
                let suffix = if models.len() > 50 {
                    format!("\n... and {} more", models.len() - 50)
                } else {
                    String::new()
                };
                format!(
                    "Live models from provider '{}' (backend={}):\n{}{}",
                    profile.alias,
                    profile.provider,
                    listed.join("\n"),
                    suffix
                )
            }
            Err(e) => format!("Failed to fetch live models for '{}': {e}", profile.alias),
        };
    }
    if is_placeholder_model_list(&profile.models) {
        return match fetch_models_from_provider_api(&profile).await {
            Ok(models) if !models.is_empty() => format!(
                "Live models for provider '{}': {}",
                profile.alias,
                models.join(", ")
            ),
            _ => format!(
                "Models for provider '{}': {}",
                profile.alias,
                profile.models.join(", ")
            ),
        };
    }
    format!(
        "Models for provider '{}': {}",
        profile.alias,
        profile.models.join(", ")
    )
}

fn is_placeholder_model_list(models: &[String]) -> bool {
    models.len() == 1 && models[0].eq_ignore_ascii_case("custom-model")
}

fn parse_models_command_args(requested: &str) -> (bool, Option<&str>) {
    let trimmed = requested.trim();
    if trimmed.is_empty() {
        return (false, None);
    }
    let parts = trimmed.split_whitespace().collect::<Vec<_>>();
    if parts.first().copied() == Some("api") {
        return (true, parts.get(1).copied());
    }
    (false, parts.first().copied())
}

#[derive(Debug, Deserialize)]
struct OpenAiModelsApiResponse {
    data: Vec<OpenAiModelItem>,
}

#[derive(Debug, Deserialize)]
struct OpenAiModelItem {
    id: String,
}

#[derive(Debug, Deserialize)]
struct AnthropicModelsApiResponse {
    data: Vec<AnthropicModelItem>,
}

#[derive(Debug, Deserialize)]
struct AnthropicModelItem {
    id: String,
    #[serde(default)]
    display_name: Option<String>,
}

fn resolve_openai_models_url(profile: &ResolvedLlmProviderProfile) -> String {
    let backend = profile.provider.trim().to_ascii_lowercase();
    let default_base = match backend.as_str() {
        "openai" => "https://api.openai.com/v1",
        "deepseek" => "https://api.deepseek.com/v1",
        "synthetic" => "https://api.synthetic.new/openai/v1",
        "chutes" => "https://llm.chutes.ai/v1",
        _ => "https://api.openai.com/v1",
    };
    let base = profile
        .llm_base_url
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .unwrap_or(default_base)
        .trim_end_matches('/');
    if base.ends_with("/models") {
        base.to_string()
    } else if base.ends_with("/chat/completions") {
        format!(
            "{}/models",
            base.trim_end_matches("/chat/completions")
                .trim_end_matches('/')
        )
    } else {
        format!("{base}/models")
    }
}

fn resolve_anthropic_models_url(profile: &ResolvedLlmProviderProfile) -> String {
    let configured = profile
        .llm_base_url
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .unwrap_or("https://api.anthropic.com/v1/models");
    let base = configured.trim_end_matches('/');
    if base.ends_with("/models") {
        base.to_string()
    } else if base.ends_with("/messages") {
        format!(
            "{}/models",
            base.trim_end_matches("/messages").trim_end_matches('/')
        )
    } else {
        format!("{base}/models")
    }
}

async fn fetch_models_from_provider_api(
    profile: &ResolvedLlmProviderProfile,
) -> Result<Vec<String>, String> {
    let backend = profile.provider.trim().to_ascii_lowercase();
    if backend == "openai-codex" && profile.api_key.trim().is_empty() {
        return Err(
            "openai-codex API listing requires provider api_key in llm_providers.<name>.api_key"
                .to_string(),
        );
    }
    if backend == "anthropic" {
        if profile.api_key.trim().is_empty() {
            return Err("missing api_key for anthropic profile".to_string());
        }
        let url = resolve_anthropic_models_url(profile);
        let client = reqwest::Client::builder()
            .user_agent(llm_user_agent(&profile.llm_user_agent))
            .build()
            .map_err(|e| e.to_string())?;
        let response = client
            .get(&url)
            .header("x-api-key", profile.api_key.as_str())
            .header("anthropic-version", "2023-06-01")
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let status = response.status();
        let body = response.text().await.map_err(|e| e.to_string())?;
        if !status.is_success() {
            return Err(format!("HTTP {status}: {body}"));
        }
        let mut out = parse_anthropic_models_json_ids(&body)?;
        out.sort();
        out.dedup();
        return Ok(out);
    }

    let url = resolve_openai_models_url(profile);
    let client = reqwest::Client::builder()
        .user_agent(llm_user_agent(&profile.llm_user_agent))
        .build()
        .map_err(|e| e.to_string())?;
    let mut request = client.get(&url);
    if !profile.api_key.trim().is_empty() {
        request = request.bearer_auth(profile.api_key.as_str());
    }
    let response = request.send().await.map_err(|e| e.to_string())?;
    let status = response.status();
    let body = response.text().await.map_err(|e| e.to_string())?;
    if !status.is_success() {
        return Err(format!("HTTP {status}: {body}"));
    }
    let mut out = parse_openai_models_json_ids(&body)?;
    out.sort();
    out.dedup();
    Ok(out)
}

fn parse_openai_models_json_ids(body: &str) -> Result<Vec<String>, String> {
    let parsed: OpenAiModelsApiResponse =
        serde_json::from_str(body).map_err(|e| format!("Invalid JSON response: {e}"))?;
    Ok(parsed.data.into_iter().map(|m| m.id).collect())
}

fn parse_anthropic_models_json_ids(body: &str) -> Result<Vec<String>, String> {
    let parsed: AnthropicModelsApiResponse =
        serde_json::from_str(body).map_err(|e| format!("Invalid JSON response: {e}"))?;
    Ok(parsed
        .data
        .into_iter()
        .map(|m| match m.display_name {
            Some(name) if !name.trim().is_empty() => format!("{} ({})", m.id, name),
            _ => m.id,
        })
        .collect())
}

async fn resolve_effective_provider_and_model(
    config: &Config,
    llm_provider_overrides: &Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>>,
    llm_model_overrides: &Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>>,
    caller_channel: &str,
) -> (ResolvedLlmProviderProfile, String) {
    let provider_alias = {
        let provider_overrides = llm_provider_overrides.read().await;
        provider_overrides
            .get(caller_channel)
            .cloned()
            .unwrap_or_else(|| config.llm_provider.clone())
    };
    let profile = config
        .resolve_llm_provider_profile(&provider_alias)
        .or_else(|| config.resolve_llm_provider_profile(&config.llm_provider))
        .expect("default provider should resolve");
    let raw_model_override = {
        let model_overrides = llm_model_overrides.read().await;
        model_overrides.get(caller_channel).cloned()
    };
    if raw_model_override
        .as_deref()
        .is_some_and(|model| normalize_model_name(model).is_none())
    {
        warn!(
            "Ignoring invalid model override '{}' for channel '{}'",
            raw_model_override.as_deref().unwrap_or_default(),
            caller_channel
        );
    }
    let model = resolve_model_name_with_fallback(
        &profile.provider,
        raw_model_override.as_deref(),
        Some(&profile.default_model),
    );
    (profile, model)
}

pub async fn maybe_handle_plugin_command(
    config: &Config,
    command_text: &str,
    chat_id: i64,
    caller_channel: &str,
) -> Option<String> {
    let normalized = normalized_slash_command(command_text)?;
    if let Some(admin) = crate::plugins::handle_plugins_admin_command(config, chat_id, normalized) {
        return Some(admin);
    }
    crate::plugins::execute_plugin_slash_command(config, caller_channel, chat_id, normalized).await
}

#[cfg(test)]
mod tests {
    use super::{
        build_model_response, build_model_response_with_persistence, build_models_response,
        build_provider_response, build_provider_response_with_persistence,
        is_placeholder_model_list, parse_anthropic_models_json_ids, parse_models_command_args,
        parse_openai_models_json_ids, resolve_effective_provider_and_model,
        resolve_openai_models_url,
    };
    use crate::config::{Config, LlmProviderProfile, ResolvedLlmProviderProfile};
    use chrono::Utc;
    use std::collections::HashMap;
    use std::fs;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::RwLock;

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::test_support::env_lock()
    }

    fn test_config() -> Config {
        let mut cfg = Config::test_defaults();
        cfg.llm_provider = "openai".to_string();
        cfg.model = "gpt-5.2".to_string();
        cfg.llm_providers.insert(
            "openai".to_string(),
            LlmProviderProfile {
                provider: Some("openai".to_string()),
                api_key: None,
                api_keys: Vec::new(),
                llm_base_url: None,
                llm_user_agent: None,
                default_model: Some("gpt-5.2".to_string()),
                models: vec!["gpt-5.2".to_string(), "gpt-5".to_string()],
                show_thinking: None,
            },
        );
        cfg.llm_providers.insert(
            "anthropic".to_string(),
            LlmProviderProfile {
                provider: Some("anthropic".to_string()),
                api_key: Some("k".to_string()),
                api_keys: Vec::new(),
                llm_base_url: None,
                llm_user_agent: None,
                default_model: Some("claude-sonnet-4-5-20250929".to_string()),
                models: vec![
                    "claude-sonnet-4-5-20250929".to_string(),
                    "claude-opus-4-6-20260205".to_string(),
                ],
                show_thinking: None,
            },
        );
        cfg
    }

    #[tokio::test]
    async fn model_command_reports_current_model() {
        let cfg = test_config();
        let provider_overrides = Arc::new(RwLock::new(HashMap::new()));
        let overrides = Arc::new(RwLock::new(HashMap::new()));
        let text =
            build_model_response(&cfg, provider_overrides, overrides, "telegram", 1, "/model")
                .await;
        assert_eq!(text, "Current provider/model: openai / gpt-5.2");
    }

    #[tokio::test]
    async fn model_command_sets_override() {
        let cfg = test_config();
        let provider_overrides = Arc::new(RwLock::new(HashMap::new()));
        let overrides = Arc::new(RwLock::new(HashMap::new()));
        let text = build_model_response(
            &cfg,
            provider_overrides,
            overrides.clone(),
            "telegram",
            1,
            "/model gpt-5",
        )
        .await;
        assert_eq!(text, "Model switched for this channel to: openai / gpt-5");
        let guard = overrides.read().await;
        assert_eq!(guard.get("telegram").map(String::as_str), Some("gpt-5"));
    }

    #[tokio::test]
    async fn model_command_here_sets_per_chat_override() {
        let cfg = test_config();
        let provider_overrides = Arc::new(RwLock::new(HashMap::new()));
        let overrides = Arc::new(RwLock::new(HashMap::new()));
        let text = build_model_response(
            &cfg,
            provider_overrides.clone(),
            overrides.clone(),
            "telegram",
            42,
            "/model here gpt-5",
        )
        .await;
        assert!(
            text.contains("Model switched for this chat to: openai / gpt-5"),
            "unexpected: {text}"
        );
        {
            let guard = overrides.read().await;
            assert_eq!(
                guard
                    .get(&super::chat_scoped_override_key("telegram", 42))
                    .map(String::as_str),
                Some("gpt-5")
            );
            // Channel-wide override untouched.
            assert!(guard.get("telegram").is_none());
        }
        let text = build_model_response(
            &cfg,
            provider_overrides,
            overrides.clone(),
            "telegram",
            42,
            "/model here reset",
        )
        .await;
        assert!(text.contains("Per-chat model override cleared"));
        let guard = overrides.read().await;
        assert!(guard
            .get(&super::chat_scoped_override_key("telegram", 42))
            .is_none());
    }

    #[tokio::test]
    async fn model_command_rejects_wildcard_override() {
        let cfg = test_config();
        let provider_overrides = Arc::new(RwLock::new(HashMap::new()));
        let overrides = Arc::new(RwLock::new(HashMap::new()));
        let text = build_model_response(
            &cfg,
            provider_overrides,
            overrides.clone(),
            "telegram",
            1,
            "/model *",
        )
        .await;
        assert_eq!(
            text,
            "Model '*' is not a valid model id. Use `/model reset` to clear the override."
        );
        let guard = overrides.read().await;
        assert!(!guard.contains_key("telegram"));
    }

    #[tokio::test]
    async fn model_command_resets_override() {
        let cfg = test_config();
        let provider_overrides = Arc::new(RwLock::new(HashMap::new()));
        let mut map = HashMap::new();
        map.insert("telegram".to_string(), "qwen".to_string());
        let overrides = Arc::new(RwLock::new(map));
        let text = build_model_response(
            &cfg,
            provider_overrides,
            overrides.clone(),
            "telegram",
            1,
            "/model reset",
        )
        .await;
        assert_eq!(
            text,
            "Model override cleared. Current provider/model: openai / gpt-5.2"
        );
        let guard = overrides.read().await;
        assert!(!guard.contains_key("telegram"));
    }

    #[tokio::test]
    async fn provider_resolution_ignores_invalid_runtime_model_override() {
        let cfg = test_config();
        let provider_overrides = Arc::new(RwLock::new(HashMap::new()));
        let mut map = HashMap::new();
        map.insert("telegram".to_string(), "*".to_string());
        let overrides = Arc::new(RwLock::new(map));

        let (profile, model) =
            resolve_effective_provider_and_model(&cfg, &provider_overrides, &overrides, "telegram")
                .await;
        assert_eq!(profile.alias, "openai");
        assert_eq!(model, "gpt-5.2");
    }

    #[tokio::test]
    async fn provider_command_switches_provider_and_resets_model() {
        let cfg = test_config();
        let provider_overrides = Arc::new(RwLock::new(HashMap::new()));
        let mut model_map = HashMap::new();
        model_map.insert("telegram".to_string(), "gpt-5".to_string());
        let model_overrides = Arc::new(RwLock::new(model_map));
        let text = build_provider_response(
            &cfg,
            provider_overrides.clone(),
            model_overrides.clone(),
            "telegram",
            "/provider anthropic",
        )
        .await;
        assert!(
            text.contains("Provider switched for this channel to: anthropic"),
            "unexpected text: {text}"
        );
        let provider_guard = provider_overrides.read().await;
        assert_eq!(
            provider_guard.get("telegram").map(String::as_str),
            Some("anthropic")
        );
        drop(provider_guard);
        let model_guard = model_overrides.read().await;
        assert!(!model_guard.contains_key("telegram"));
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn provider_command_persists_override_for_default_account_channel() {
        let _guard = env_lock();
        let temp = std::env::temp_dir().join(format!(
            "microclaw_chat_commands_provider_persist_{}",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        fs::create_dir_all(&temp).unwrap();
        let old_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(&temp).unwrap();
        fs::write(
            temp.join("microclaw.config.yaml"),
            r#"
bot_username: bot
api_key: key
llm_provider: openai
model: gpt-5.2
provider_presets:
  modal:
    provider: openai
    default_model: gpt-5.2
  cloudflare:
    provider: openai
    default_model: "@cf/zai-org/glm-4.7-flash"
channels:
  telegram:
    enabled: true
    default_account: sales
    accounts:
      sales:
        enabled: true
        bot_token: tok
        provider_preset: modal
"#,
        )
        .unwrap();

        let cfg = Config::load().unwrap();
        let provider_overrides = Arc::new(RwLock::new(cfg.llm_provider_overrides()));
        let model_overrides = Arc::new(RwLock::new(HashMap::new()));
        let text = build_provider_response_with_persistence(
            &cfg,
            provider_overrides.clone(),
            model_overrides,
            "telegram",
            0,
            "/provider cloudflare",
            true,
        )
        .await;
        assert!(text.contains("Provider switched for this channel to: cloudflare"));

        let saved = Config::load().unwrap();
        assert_eq!(
            saved.provider_override_for_channel("telegram").as_deref(),
            Some("cloudflare")
        );
        assert_eq!(
            provider_overrides
                .read()
                .await
                .get("telegram")
                .map(String::as_str),
            Some("cloudflare")
        );

        std::env::set_current_dir(old_cwd).unwrap();
        let _ = fs::remove_file(temp.join("microclaw.config.yaml"));
        let _ = fs::remove_dir_all(&temp);
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn model_command_persists_override_for_default_account_channel() {
        let _guard = env_lock();
        let temp = std::env::temp_dir().join(format!(
            "microclaw_chat_commands_model_persist_{}",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        fs::create_dir_all(&temp).unwrap();
        let old_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(&temp).unwrap();
        fs::write(
            temp.join("microclaw.config.yaml"),
            r#"
bot_username: bot
api_key: key
llm_provider: openai
model: gpt-5.2
provider_presets:
  cloudflare:
    provider: openai
    default_model: "@cf/zai-org/glm-4.7-flash"
channels:
  telegram:
    enabled: true
    default_account: sales
    accounts:
      sales:
        enabled: true
        bot_token: tok
        provider_preset: cloudflare
"#,
        )
        .unwrap();

        let cfg = Config::load().unwrap();
        let provider_overrides = Arc::new(RwLock::new(cfg.llm_provider_overrides()));
        let model_overrides = Arc::new(RwLock::new(HashMap::new()));
        let text = build_model_response_with_persistence(
            &cfg,
            provider_overrides,
            model_overrides.clone(),
            "telegram",
            1,
            "/model @cf/zai-org/glm-4.7-flash",
            true,
        )
        .await;
        assert_eq!(
            text,
            "Model switched for this channel to: cloudflare / @cf/zai-org/glm-4.7-flash"
        );

        let saved = fs::read_to_string(temp.join("microclaw.config.yaml")).unwrap();
        assert!(
            saved.contains("model: '@cf/zai-org/glm-4.7-flash'")
                || saved.contains("model: \"@cf/zai-org/glm-4.7-flash\"")
        );
        let saved_cfg = Config::load().unwrap();
        assert_eq!(
            saved_cfg.model_override_for_channel("telegram").as_deref(),
            Some("@cf/zai-org/glm-4.7-flash")
        );
        assert_eq!(
            model_overrides
                .read()
                .await
                .get("telegram")
                .map(String::as_str),
            Some("@cf/zai-org/glm-4.7-flash")
        );

        std::env::set_current_dir(old_cwd).unwrap();
        let _ = fs::remove_file(temp.join("microclaw.config.yaml"));
        let _ = fs::remove_dir_all(&temp);
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn model_command_persists_override_only_for_current_bot_account() {
        let _guard = env_lock();
        let temp = std::env::temp_dir().join(format!(
            "microclaw_chat_commands_model_bot_scope_{}",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        fs::create_dir_all(&temp).unwrap();
        let old_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(&temp).unwrap();
        fs::write(
            temp.join("microclaw.config.yaml"),
            r#"
bot_username: bot
api_key: key
llm_provider: openai
model: gpt-5.2
llm_providers:
  openai:
    provider: openai
    default_model: gpt-5.2
    models:
      - gpt-5.2
      - gpt-5
channels:
  telegram:
    enabled: true
    default_account: sales
    accounts:
      sales:
        enabled: true
        bot_token: sales-tok
        model: gpt-5.2
      ops:
        enabled: true
        bot_token: ops-tok
        model: gpt-5-mini
"#,
        )
        .unwrap();

        let cfg = Config::load().unwrap();
        let provider_overrides = Arc::new(RwLock::new(cfg.llm_provider_overrides()));
        let model_overrides = Arc::new(RwLock::new(HashMap::new()));
        let text = build_model_response_with_persistence(
            &cfg,
            provider_overrides,
            model_overrides.clone(),
            "telegram.ops",
            1,
            "/model gpt-5",
            true,
        )
        .await;
        assert_eq!(text, "Model switched for this channel to: openai / gpt-5");

        let saved_cfg = Config::load().unwrap();
        assert_eq!(
            saved_cfg.model_override_for_channel("telegram").as_deref(),
            Some("gpt-5.2")
        );
        assert_eq!(
            saved_cfg
                .model_override_for_channel("telegram.ops")
                .as_deref(),
            Some("gpt-5")
        );
        assert_eq!(
            model_overrides
                .read()
                .await
                .get("telegram.ops")
                .map(String::as_str),
            Some("gpt-5")
        );

        std::env::set_current_dir(old_cwd).unwrap();
        let _ = fs::remove_file(temp.join("microclaw.config.yaml"));
        let _ = fs::remove_dir_all(&temp);
    }

    #[tokio::test]
    async fn models_command_lists_profile_models() {
        let cfg = test_config();
        let provider_overrides = Arc::new(RwLock::new(HashMap::new()));
        let model_overrides = Arc::new(RwLock::new(HashMap::new()));
        let text = build_models_response(
            &cfg,
            provider_overrides,
            model_overrides,
            "telegram",
            "/models anthropic",
        )
        .await;
        assert!(text.contains("claude-sonnet-4-5-20250929"));
        assert!(text.contains("claude-opus-4-6-20260205"));
    }

    #[test]
    fn models_command_parses_api_mode() {
        assert_eq!(parse_models_command_args(""), (false, None));
        assert_eq!(
            parse_models_command_args("anthropic"),
            (false, Some("anthropic"))
        );
        assert_eq!(parse_models_command_args("api"), (true, None));
        assert_eq!(
            parse_models_command_args("api openai"),
            (true, Some("openai"))
        );
    }

    #[test]
    fn placeholder_models_detection() {
        assert!(is_placeholder_model_list(&["custom-model".to_string()]));
        assert!(!is_placeholder_model_list(&[
            "custom-model".to_string(),
            "other".to_string()
        ]));
        assert!(!is_placeholder_model_list(&["deepseek-chat".to_string()]));
    }

    #[test]
    fn parse_openai_models_ids() {
        let json = r#"{"data":[{"id":"gpt-5.2"},{"id":"gpt-5"}]}"#;
        let ids = parse_openai_models_json_ids(json).expect("openai parse");
        assert_eq!(ids, vec!["gpt-5.2".to_string(), "gpt-5".to_string()]);
    }

    #[test]
    fn parse_anthropic_models_ids() {
        let json = r#"{"data":[{"id":"claude-sonnet","display_name":"Claude Sonnet"},{"id":"claude-opus"}]}"#;
        let ids = parse_anthropic_models_json_ids(json).expect("anthropic parse");
        assert_eq!(
            ids,
            vec![
                "claude-sonnet (Claude Sonnet)".to_string(),
                "claude-opus".to_string()
            ]
        );
    }

    #[tokio::test]
    async fn models_command_uses_live_models_when_placeholder_profile() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (path_tx, path_rx) = mpsc::channel::<String>();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut buf = [0u8; 8192];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let path = req
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or("")
                .to_string();
            let _ = path_tx.send(path);
            let body = r#"{"data":[{"id":"model-live-a"},{"id":"model-live-b"}]}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        });

        let mut cfg = Config::test_defaults();
        cfg.llm_provider = "lab-local".to_string();
        cfg.api_key = "k".to_string();
        cfg.model = "custom-model".to_string();
        cfg.llm_base_url = Some(format!("http://{addr}/v1"));
        cfg.llm_providers.insert(
            "lab-local".to_string(),
            LlmProviderProfile {
                provider: Some("openai".to_string()),
                api_key: None,
                api_keys: Vec::new(),
                llm_base_url: Some(format!("http://{addr}/v1")),
                llm_user_agent: None,
                default_model: Some("custom-model".to_string()),
                models: vec!["custom-model".to_string()],
                show_thinking: None,
            },
        );
        let provider_overrides = Arc::new(RwLock::new(HashMap::new()));
        let model_overrides = Arc::new(RwLock::new(HashMap::new()));
        let text =
            build_models_response(&cfg, provider_overrides, model_overrides, "web", "/models")
                .await;
        let path = path_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        server.join().unwrap();
        assert_eq!(path, "/v1/models");
        assert!(text.contains("Live models for provider 'lab-local'"));
        assert!(text.contains("model-live-a"));
    }

    #[tokio::test]
    async fn model_command_validates_against_live_models_for_placeholder_profile() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut buf = [0u8; 8192];
                let _ = stream.read(&mut buf).unwrap_or(0);
                let body = r#"{"data":[{"id":"model-live-a"},{"id":"model-live-b"}]}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });

        let mut cfg = Config::test_defaults();
        cfg.llm_provider = "lab-local".to_string();
        cfg.api_key = "k".to_string();
        cfg.model = "custom-model".to_string();
        cfg.llm_base_url = Some(format!("http://{addr}/v1"));
        cfg.llm_providers.insert(
            "lab-local".to_string(),
            LlmProviderProfile {
                provider: Some("openai".to_string()),
                api_key: None,
                api_keys: Vec::new(),
                llm_base_url: Some(format!("http://{addr}/v1")),
                llm_user_agent: None,
                default_model: Some("custom-model".to_string()),
                models: vec!["custom-model".to_string()],
                show_thinking: None,
            },
        );
        let provider_overrides = Arc::new(RwLock::new(HashMap::new()));
        let model_overrides = Arc::new(RwLock::new(HashMap::new()));

        let ok = build_model_response(
            &cfg,
            provider_overrides.clone(),
            model_overrides.clone(),
            "web",
            1,
            "/model model-live-a",
        )
        .await;
        assert_eq!(
            ok,
            "Model switched for this channel to: lab-local / model-live-a"
        );

        let bad = build_model_response(
            &cfg,
            provider_overrides,
            model_overrides,
            "web",
            1,
            "/model not-real",
        )
        .await;
        server.join().unwrap();
        assert!(bad.contains("Model 'not-real' is not configured"));
        assert!(bad.contains("model-live-a"));
    }

    #[test]
    fn resolve_openai_models_url_supports_synthetic_and_chutes_defaults() {
        let mk = |provider: &str| ResolvedLlmProviderProfile {
            alias: provider.to_string(),
            provider: provider.to_string(),
            api_key: String::new(),
            api_keys: Vec::new(),
            llm_base_url: None,
            llm_user_agent: String::new(),
            default_model: "x".to_string(),
            models: vec!["x".to_string()],
            show_thinking: false,
        };
        assert_eq!(
            resolve_openai_models_url(&mk("synthetic")),
            "https://api.synthetic.new/openai/v1/models"
        );
        assert_eq!(
            resolve_openai_models_url(&mk("chutes")),
            "https://llm.chutes.ai/v1/models"
        );
    }
}

#[cfg(test)]
mod slash_command_tests {
    use super::{
        build_help_response, build_log_response, format_learn_reply, format_learning_run_detail,
        is_slash_command,
    };
    use crate::config::Config;

    #[test]
    fn test_log_command_denied_without_control_chats() {
        let mut cfg = Config::test_defaults();
        cfg.control_chat_ids = vec![];
        let resp = build_log_response(&cfg, 1, "/log");
        assert!(resp.contains("disabled"), "got: {resp}");
    }

    #[test]
    fn test_log_command_denied_for_non_control_chat() {
        let mut cfg = Config::test_defaults();
        cfg.control_chat_ids = vec![999];
        let resp = build_log_response(&cfg, 1, "/log 50");
        assert!(resp.contains("Not authorized"), "got: {resp}");
    }

    #[test]
    fn test_log_command_keyword_filter() {
        let dir = std::env::temp_dir().join(format!(
            "microclaw_log_cmd_test_{}/runtime",
            uuid::Uuid::new_v4()
        ));
        let logs = dir.join("logs");
        std::fs::create_dir_all(&logs).unwrap();
        std::fs::write(
            logs.join("microclaw-2026-02-08-10.log"),
            "INFO starting up\nERROR scheduler exploded\nINFO all good\n",
        )
        .unwrap();

        let mut cfg = Config::test_defaults();
        cfg.control_chat_ids = vec![7];
        cfg.data_dir = dir.to_string_lossy().to_string();

        // Keyword filter keeps only matching lines (case-insensitive).
        let resp = build_log_response(&cfg, 7, "/log error");
        assert!(resp.contains("scheduler exploded"), "got: {resp}");
        assert!(!resp.contains("all good"), "got: {resp}");
        assert!(resp.contains("matching \"error\""), "got: {resp}");

        // No filter tails everything.
        let all = build_log_response(&cfg, 7, "/log");
        assert!(
            all.contains("all good") && all.contains("starting up"),
            "got: {all}"
        );

        let _ = std::fs::remove_dir_all(dir.parent().unwrap());
    }

    #[test]
    fn test_is_slash_command_with_leading_mentions() {
        assert!(is_slash_command("/status"));
        assert!(is_slash_command("@bot /status"));
        assert!(is_slash_command("<@U123> /status"));
        assert!(is_slash_command(" <@U123>   @bot   /status"));
        assert!(!is_slash_command("@bot hello"));
    }

    #[test]
    fn help_lists_real_commands_and_is_recognized() {
        assert!(is_slash_command("/help"));
        let help = build_help_response();
        // Every command surfaced in help must be a real dispatch entry.
        for cmd in [
            "/status",
            "/clear",
            "/reset",
            "/stop",
            "/archive",
            "/model",
            "/models",
            "/provider",
            "/providers",
            "/skills",
            "/reload-skills",
            "/learn",
            "/user",
            "/usage",
            "/learning",
            "/rewind",
            "/log",
            "/help",
        ] {
            assert!(help.contains(cmd), "help missing {cmd}");
        }
    }

    #[test]
    fn learning_detail_cli_shows_used_experience_and_evidence() {
        let dir = std::env::temp_dir().join(format!("mc_learning_cli_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = microclaw_storage::db::Database::new(dir.to_str().unwrap()).unwrap();
        for (run_id, objective) in [
            ("cli-source", "deploy the service"),
            ("cli-query", "deploy it again"),
        ] {
            db.start_experience_run(run_id, None, 44, "web", "interactive", objective, None)
                .unwrap();
        }
        db.finish_experience_run("cli-source", "completed", Some("healthy"), 10)
            .unwrap();
        db.record_verifier_result(
            "cli-source",
            "deterministic",
            "health_check",
            "passed",
            1.0,
            Some("HTTP 200"),
            None,
            None,
        )
        .unwrap();
        db.record_experience_retrievals(
            "cli-query",
            &[(
                "cli-source".into(),
                "strong_verified; environment_match=true".into(),
                1.25,
            )],
        )
        .unwrap();
        db.record_verifier_result(
            "cli-query",
            "runtime",
            "agent_loop_completion",
            "passed",
            0.55,
            Some("finished"),
            None,
            None,
        )
        .unwrap();

        let detail = db.get_experience_run_detail("cli-query").unwrap().unwrap();
        let output = format_learning_run_detail(&detail);
        assert!(output.contains("Experiences used (1)"));
        assert!(output.contains("objective=deploy the service"));
        assert!(output.contains("result=healthy"));
        assert!(output.contains("Outcome evidence (1)"));
        assert!(output.contains("agent_loop_completion"));

        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn learn_reply_formats_all_outcomes() {
        use crate::skill_review::{AppliedAction, LearnOutcome};
        let applied = format_learn_reply(&LearnOutcome::Applied(AppliedAction {
            name: "deploy-checklist".into(),
            action_kind: "create",
            version: 1,
        }));
        assert!(applied.contains("Created skill 'deploy-checklist' (v1)"));
        assert!(
            format_learn_reply(&LearnOutcome::Nothing("nothing reusable".into()))
                .contains("No skill saved")
        );
        assert!(
            format_learn_reply(&LearnOutcome::Skipped("no session".into()))
                .contains("Nothing to learn")
        );
        assert!(format_learn_reply(&LearnOutcome::Error("boom".into())).contains("Learn failed"));
    }
}
