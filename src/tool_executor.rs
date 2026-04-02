//! Parallel tool execution within a single agent turn.
//!
//! When the LLM returns multiple tool_use blocks, this module partitions them into
//! execution "waves" based on their concurrency class and runs safe subsets in parallel
//! via `tokio::JoinSet`.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;
use tracing::{info, warn};

use crate::hooks::HookOutcome;
use crate::runtime::AppState;
use crate::tools::ToolAuthContext;
use microclaw_core::llm_types::ContentBlock;
use microclaw_observability::traces::{kv, new_span_id, now_unix_nano, SpanData};
use microclaw_tools::runtime::{
    parse_concurrency_class, tool_concurrency_class, ToolConcurrencyClass, ToolResult,
};
use opentelemetry_proto::tonic::trace::v1::Status;

use crate::agent_engine::AgentEvent;
use microclaw_observability::traces::OtlpTraceExporter;
use tokio::sync::mpsc::UnboundedSender;

/// A single pending tool call extracted from the LLM response.
#[derive(Clone, Debug)]
pub struct PendingToolCall {
    pub id: String,
    pub name: String,
    pub input: Value,
}

/// Mutable context accumulated across tool executions within a turn.
pub struct ToolBatchContext {
    pub failed_tools: std::collections::BTreeSet<String>,
    pub failed_tool_details: Vec<String>,
    pub seen_failed_tool_details: std::collections::HashSet<String>,
    pub consecutive_send_message_calls: usize,
    pub skill_env_files: Vec<String>,
    pub tool_auth: ToolAuthContext,
    pub waiting_for_user_approval: bool,
    pub waiting_approval_tool: Option<String>,
}

/// Metrics counters for tool execution.
pub struct ToolMetrics {
    pub tool_calls: i64,
    pub tool_errors: i64,
}


/// Resolve the effective concurrency class for a tool, respecting config overrides.
fn resolve_concurrency_class(name: &str, overrides: &HashMap<String, String>) -> ToolConcurrencyClass {
    if let Some(override_str) = overrides.get(name) {
        if let Some(class) = parse_concurrency_class(override_str) {
            return class;
        }
        warn!(
            "Invalid tool_concurrency_override for '{}': '{}'; using default",
            name, override_str
        );
    }
    tool_concurrency_class(name)
}

/// Partition tool calls into execution waves based on concurrency classes.
///
/// Rules:
/// 1. All ReadOnly -> single wave, all parallel
/// 2. Mixed ReadOnly + others -> wave 1 = ReadOnly parallel, then rest sequentially
/// 3. Exclusive -> runs alone in its own wave
fn partition_into_waves(
    calls: &[PendingToolCall],
    overrides: &HashMap<String, String>,
) -> Vec<Vec<usize>> {
    if calls.is_empty() {
        return Vec::new();
    }
    if calls.len() == 1 {
        return vec![vec![0]];
    }

    let classes: Vec<ToolConcurrencyClass> = calls
        .iter()
        .map(|c| resolve_concurrency_class(&c.name, overrides))
        .collect();

    let mut readonly_indices = Vec::new();
    let mut sideeffect_indices = Vec::new();
    let mut exclusive_indices = Vec::new();

    for (i, class) in classes.iter().enumerate() {
        match class {
            ToolConcurrencyClass::ReadOnly => readonly_indices.push(i),
            ToolConcurrencyClass::SideEffect => sideeffect_indices.push(i),
            ToolConcurrencyClass::Exclusive => exclusive_indices.push(i),
        }
    }

    let mut waves = Vec::new();

    // Wave 1: all ReadOnly tools in parallel
    if !readonly_indices.is_empty() {
        waves.push(readonly_indices);
    }

    // Then: SideEffect tools, one per wave (sequential)
    for idx in sideeffect_indices {
        waves.push(vec![idx]);
    }

    // Then: Exclusive tools, one per wave
    for idx in exclusive_indices {
        waves.push(vec![idx]);
    }

    waves
}

/// Execute a batch of tool calls, optionally in parallel.
///
/// When `parallel_enabled` is false, all tools execute sequentially (existing behavior).
/// When true, tools are partitioned into waves and ReadOnly tools within a wave run concurrently.
#[expect(clippy::too_many_arguments)]
pub async fn execute_tool_batch(
    state: &AppState,
    calls: &[PendingToolCall],
    ctx: &mut ToolBatchContext,
    metrics: &mut ToolMetrics,
    event_tx: Option<&UnboundedSender<AgentEvent>>,
    chat_id: i64,
    iteration: usize,
    caller_channel: &str,
    explicit_user_approval: bool,
    trace_id: &[u8],
    parent_span_id: &[u8],
) -> Vec<ContentBlock> {
    let max_concurrency = state.config.parallel_tool_max_concurrency;

    if calls.len() <= 1 {
        // Sequential execution (original behavior)
        return execute_sequentially(
            state,
            calls,
            ctx,
            metrics,
            event_tx,
            chat_id,
            iteration,
            caller_channel,
            explicit_user_approval,
            trace_id,
            parent_span_id,
        )
        .await;
    }

    let waves = partition_into_waves(calls, &state.config.tool_concurrency_overrides);
    let mut all_results: Vec<(usize, ContentBlock)> = Vec::with_capacity(calls.len());

    for (wave_idx, wave) in waves.iter().enumerate() {
        if let Some(tx) = event_tx {
            let _ = tx.send(AgentEvent::ToolWaveStart {
                wave: wave_idx + 1,
                tool_count: wave.len(),
            });
        }

        if wave.len() == 1 {
            // Single tool in wave — execute inline (no spawn overhead)
            let idx = wave[0];
            let result = execute_single_tool(
                state,
                &calls[idx],
                ctx,
                metrics,
                event_tx,
                chat_id,
                iteration,
                caller_channel,
                explicit_user_approval,
                trace_id,
                parent_span_id,
            )
            .await;
            all_results.push((idx, result));
        } else {
            // Multiple tools — run in parallel with JoinSet
            let results = execute_wave_parallel(
                state,
                calls,
                wave,
                ctx,
                metrics,
                event_tx,
                chat_id,
                iteration,
                caller_channel,
                explicit_user_approval,
                trace_id,
                parent_span_id,
                max_concurrency,
            )
            .await;
            all_results.extend(results);
        }

        if let Some(tx) = event_tx {
            let _ = tx.send(AgentEvent::ToolWaveComplete {
                wave: wave_idx + 1,
            });
        }
    }

    // Sort by original index to preserve order
    all_results.sort_by_key(|(idx, _)| *idx);
    all_results.into_iter().map(|(_, block)| block).collect()
}

/// Execute all tools sequentially (the original behavior).
#[expect(clippy::too_many_arguments)]
async fn execute_sequentially(
    state: &AppState,
    calls: &[PendingToolCall],
    ctx: &mut ToolBatchContext,
    metrics: &mut ToolMetrics,
    event_tx: Option<&UnboundedSender<AgentEvent>>,
    chat_id: i64,
    iteration: usize,
    caller_channel: &str,
    explicit_user_approval: bool,
    trace_id: &[u8],
    parent_span_id: &[u8],
) -> Vec<ContentBlock> {
    let mut results = Vec::with_capacity(calls.len());
    for call in calls {
        let block = execute_single_tool(
            state,
            call,
            ctx,
            metrics,
            event_tx,
            chat_id,
            iteration,
            caller_channel,
            explicit_user_approval,
            trace_id,
            parent_span_id,
        )
        .await;
        results.push(block);
    }
    results
}

/// Execute a single tool call with all the hooks, tracing, and guardrail logic.
#[expect(clippy::too_many_arguments)]
async fn execute_single_tool(
    state: &AppState,
    call: &PendingToolCall,
    ctx: &mut ToolBatchContext,
    metrics: &mut ToolMetrics,
    event_tx: Option<&UnboundedSender<AgentEvent>>,
    chat_id: i64,
    iteration: usize,
    caller_channel: &str,
    explicit_user_approval: bool,
    trace_id: &[u8],
    parent_span_id: &[u8],
) -> ContentBlock {
    let id = &call.id;
    let name = &call.name;
    let input = &call.input;

    // Malformed tool name check
    if name.trim().is_empty() {
        warn!(
            chat_id,
            iteration,
            tool_use_id = %id,
            "Skipping malformed tool call with empty tool name"
        );
        return ContentBlock::ToolResult {
            tool_use_id: id.clone(),
            content: "Malformed tool call: missing tool name. Retry with a valid registered tool."
                .to_string(),
            is_error: Some(true),
        };
    }

    // send_message consecutive call guardrail
    if name != "send_message" {
        ctx.consecutive_send_message_calls = 0;
    } else if ctx.consecutive_send_message_calls >= 3 {
        warn!(
            chat_id,
            iteration,
            "Guardrail: blocking repeated send_message loop"
        );
        let content = "send_message blocked: too many consecutive send_message calls in one request. Use normal assistant reply for final output instead of repeatedly calling send_message.".to_string();
        ctx.failed_tools.insert(name.clone());
        let detail = format!("send_message: {content}");
        if ctx.seen_failed_tool_details.insert(detail.clone()) {
            ctx.failed_tool_details.push(detail);
        }
        return ContentBlock::ToolResult {
            tool_use_id: id.clone(),
            content,
            is_error: Some(true),
        };
    }

    // Feishu send_message text restriction
    let is_feishu_turn =
        caller_channel.starts_with("feishu") || caller_channel.starts_with("lark");
    let send_message_has_attachment = input
        .get("attachment_path")
        .and_then(|v| v.as_str())
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false);
    if name == "send_message" && is_feishu_turn && !send_message_has_attachment {
        return ContentBlock::ToolResult {
            tool_use_id: id.clone(),
            content: "send_message text replies are disabled for Feishu runtime turns; return the final assistant text directly so channel reaction/text delivery can be handled correctly. If you need to send a file, call send_message with attachment_path.".to_string(),
            is_error: Some(true),
        };
    }

    // Before-tool hook
    let mut effective_input = input.clone();
    if let Ok(hook_outcome) = state
        .hooks
        .run_before_tool(chat_id, caller_channel, iteration, name, &effective_input)
        .await
    {
        match hook_outcome {
            HookOutcome::Block { reason } => {
                return ContentBlock::ToolResult {
                    tool_use_id: id.clone(),
                    content: if reason.trim().is_empty() {
                        format!("tool '{}' blocked by policy hook", name)
                    } else {
                        reason
                    },
                    is_error: Some(true),
                };
            }
            HookOutcome::Allow { patches } => {
                for patch in patches {
                    if let Some(v) = patch.get("tool_input") {
                        effective_input = v.clone();
                    }
                }
            }
        }
    }

    // Emit ToolStart event
    if let Some(tx) = event_tx {
        let _ = tx.send(AgentEvent::ToolStart {
            name: name.clone(),
            input: effective_input.clone(),
        });
    }
    info!(chat_id, tool = %name, iteration, "Executing tool");

    let started = std::time::Instant::now();
    let mut executed_input = effective_input.clone();
    let tool_span_id = new_span_id();
    let tool_start = now_unix_nano();
    metrics.tool_calls += 1;

    // Execute tool
    let mut result = state
        .tools
        .execute_with_auth(name, executed_input.clone(), &ctx.tool_auth)
        .await;

    // Trace span
    if let Some(exp) = &state.trace_exporter {
        emit_tool_span(
            exp,
            trace_id,
            tool_span_id,
            parent_span_id,
            name,
            &executed_input,
            &result,
            tool_start,
            "tool_execution",
        );
    }

    // Auto-retry on approval_required
    if result.is_error && result.error_type.as_deref() == Some("approval_required") {
        let can_retry_with_approval = if state.config.high_risk_tool_user_confirmation_required {
            explicit_user_approval
        } else {
            true
        };
        if can_retry_with_approval {
            executed_input = with_high_risk_approval_marker(&effective_input);
            if state.config.high_risk_tool_user_confirmation_required {
                info!("Retrying tool '{}' after explicit user approval", name);
            } else {
                info!("Auto-retrying tool '{}' after approval gate", name);
            }
            let retry_span_id = new_span_id();
            let retry_start = now_unix_nano();
            metrics.tool_calls += 1;

            result = state
                .tools
                .execute_with_auth(name, executed_input.clone(), &ctx.tool_auth)
                .await;

            if let Some(exp) = &state.trace_exporter {
                emit_tool_span(
                    exp,
                    trace_id,
                    retry_span_id,
                    parent_span_id,
                    name,
                    &executed_input,
                    &result,
                    retry_start,
                    "tool_execution_retry",
                );
            }
        } else if state.config.high_risk_tool_user_confirmation_required {
            ctx.waiting_for_user_approval = true;
            ctx.waiting_approval_tool = Some(name.clone());
        }
    }

    // activate_skill metadata handling
    if name == "activate_skill" && !result.is_error {
        if let Some(meta) = &result.metadata {
            if let Some(path) = meta.get("skill_env_file").and_then(|v| v.as_str()) {
                let path_str = path.to_string();
                if !ctx.skill_env_files.contains(&path_str) {
                    ctx.skill_env_files.push(path_str);
                    ctx.tool_auth.env_files = ctx.skill_env_files.clone();
                }
                if let Ok(files_json) = serde_json::to_string(&ctx.skill_env_files) {
                    let db = state.db.clone();
                    let _ = microclaw_storage::db::call_blocking(db, move |db| {
                        db.save_session_skill_envs(chat_id, &files_json)
                    })
                    .await;
                }
            }
        }
    }

    // After-tool hook
    if let Ok(hook_outcome) = state
        .hooks
        .run_after_tool(
            chat_id,
            caller_channel,
            iteration,
            name,
            &executed_input,
            &result,
        )
        .await
    {
        match hook_outcome {
            HookOutcome::Block { reason } => {
                result.is_error = true;
                if !reason.trim().is_empty() {
                    result.content = reason;
                }
                if result.error_type.is_none() {
                    result.error_type = Some("hook_blocked".to_string());
                }
            }
            HookOutcome::Allow { patches } => {
                for patch in patches {
                    if let Some(v) = patch.get("content").and_then(|v| v.as_str()) {
                        result.content = v.to_string();
                    }
                    if let Some(v) = patch.get("is_error").and_then(|v| v.as_bool()) {
                        result.is_error = v;
                    }
                    if let Some(v) = patch
                        .get("error_type")
                        .and_then(|v| v.as_str())
                        .map(str::to_string)
                    {
                        result.error_type = Some(v);
                    }
                    if let Some(v) = patch
                        .get("status_code")
                        .and_then(|v| v.as_i64())
                        .map(|x| x as i32)
                    {
                        result.status_code = Some(v);
                    }
                }
            }
        }
    }

    // Error tracking
    if result.is_error && result.error_type.as_deref() != Some("approval_required") {
        let suppress = result
            .error_type
            .as_deref()
            .map(|t| t == "feishu_reaction_protocol_text" || t == "feishu_send_message_disabled")
            .unwrap_or(false);
        if !suppress {
            ctx.failed_tools.insert(name.clone());
            let detail = format_failed_action_for_user(name, &executed_input, &result.content);
            if ctx.seen_failed_tool_details.insert(detail.clone()) {
                ctx.failed_tool_details.push(detail);
            }
        }
        let preview = truncate_for_log(&result.content, 300);
        warn!(
            chat_id,
            tool = %name,
            iteration,
            error_type = ?result.error_type,
            "Tool execution failed: {}",
            preview
        );
    }

    // Emit ToolResult event
    if let Some(tx) = event_tx {
        let preview = truncate_for_log(&result.content, 160);
        let _ = tx.send(AgentEvent::ToolResult {
            name: name.clone(),
            is_error: result.is_error,
            preview,
            duration_ms: result
                .duration_ms
                .unwrap_or_else(|| started.elapsed().as_millis()),
            status_code: result.status_code,
            bytes: result.bytes,
            error_type: result.error_type.clone(),
        });
    }
    if result.is_error {
        metrics.tool_errors += 1;
    }
    if name == "send_message" {
        ctx.consecutive_send_message_calls += 1;
    }

    ContentBlock::ToolResult {
        tool_use_id: id.clone(),
        content: result.content,
        is_error: if result.is_error { Some(true) } else { None },
    }
}

/// Execute a wave of tools in parallel using futures::join_all.
///
/// Before-tool hooks run sequentially first, then tools execute concurrently,
/// then after-tool hooks are handled per-tool. This preserves hook ordering.
#[expect(clippy::too_many_arguments)]
async fn execute_wave_parallel(
    state: &AppState,
    calls: &[PendingToolCall],
    wave_indices: &[usize],
    ctx: &mut ToolBatchContext,
    metrics: &mut ToolMetrics,
    event_tx: Option<&UnboundedSender<AgentEvent>>,
    chat_id: i64,
    iteration: usize,
    caller_channel: &str,
    _explicit_user_approval: bool,
    _trace_id: &[u8],
    _parent_span_id: &[u8],
    _max_concurrency: usize,
) -> Vec<(usize, ContentBlock)> {
    info!(
        chat_id,
        wave_size = wave_indices.len(),
        "Executing tool wave in parallel"
    );

    // Pre-process: run before_tool hooks sequentially and prepare inputs.
    struct PreparedCall {
        idx: usize,
        name: String,
        effective_input: Value,
        skipped: Option<ContentBlock>,
    }

    let mut prepared = Vec::with_capacity(wave_indices.len());
    for &idx in wave_indices {
        let call = &calls[idx];
        let name = &call.name;
        let mut effective_input = call.input.clone();

        if let Some(tx) = event_tx {
            let _ = tx.send(AgentEvent::ToolStart {
                name: name.clone(),
                input: effective_input.clone(),
            });
        }

        let mut skipped = None;
        if let Ok(hook_outcome) = state
            .hooks
            .run_before_tool(chat_id, caller_channel, iteration, name, &effective_input)
            .await
        {
            match hook_outcome {
                HookOutcome::Block { reason } => {
                    skipped = Some(ContentBlock::ToolResult {
                        tool_use_id: call.id.clone(),
                        content: if reason.trim().is_empty() {
                            format!("tool '{}' blocked by policy hook", name)
                        } else {
                            reason
                        },
                        is_error: Some(true),
                    });
                }
                HookOutcome::Allow { patches } => {
                    for patch in patches {
                        if let Some(v) = patch.get("tool_input") {
                            effective_input = v.clone();
                        }
                    }
                }
            }
        }

        prepared.push(PreparedCall {
            idx,
            name: name.clone(),
            effective_input,
            skipped,
        });
    }

    // Execute non-skipped tools in parallel using futures::join_all.
    // This borrows state rather than requiring 'static, which avoids the Clone issue.
    let tool_auth = ctx.tool_auth.clone();
    let futures: Vec<_> = prepared
        .iter()
        .filter(|p| p.skipped.is_none())
        .map(|prep| {
            let tool_auth = tool_auth.clone();
            let name = prep.name.clone();
            let input = prep.effective_input.clone();
            let idx = prep.idx;
            async move {
                let started = std::time::Instant::now();
                let result = state
                    .tools
                    .execute_with_auth(&name, input.clone(), &tool_auth)
                    .await;
                let duration = started.elapsed().as_millis();
                (idx, name, input, result, duration)
            }
        })
        .collect();

    let parallel_results = futures_util::future::join_all(futures).await;

    let mut results: Vec<(usize, ContentBlock)> = Vec::with_capacity(prepared.len());

    // Add skipped results first
    for prep in &prepared {
        if let Some(block) = &prep.skipped {
            results.push((prep.idx, block.clone()));
        }
    }

    // Process parallel results
    for (idx, name, _input, result, _duration) in parallel_results {
        let call_id = &calls[idx].id;
        metrics.tool_calls += 1;
        if result.is_error {
            metrics.tool_errors += 1;
            ctx.failed_tools.insert(name.clone());
        }
        if name == "send_message" {
            ctx.consecutive_send_message_calls += 1;
        }

        // Emit ToolResult event
        if let Some(tx) = event_tx {
            let preview = truncate_for_log(&result.content, 160);
            let _ = tx.send(AgentEvent::ToolResult {
                name: name.clone(),
                is_error: result.is_error,
                preview,
                duration_ms: result.duration_ms.unwrap_or(_duration),
                status_code: result.status_code,
                bytes: result.bytes,
                error_type: result.error_type.clone(),
            });
        }

        results.push((
            idx,
            ContentBlock::ToolResult {
                tool_use_id: call_id.clone(),
                content: result.content,
                is_error: if result.is_error { Some(true) } else { None },
            },
        ));
    }

    results
}

fn with_high_risk_approval_marker(input: &Value) -> Value {
    let mut approved_input = input.clone();
    if let Some(obj) = approved_input.as_object_mut() {
        obj.insert(
            "__microclaw_high_risk_approved".to_string(),
            Value::Bool(true),
        );
        return approved_input;
    }
    serde_json::json!({
        "__microclaw_high_risk_approved": true,
        "__microclaw_original_input": input,
    })
}

fn format_failed_action_for_user(tool_name: &str, input: &Value, result_content: &str) -> String {
    let error_summary = truncate_for_log(result_content, 140);
    if tool_name == "bash" {
        if let Some(command) = input
            .get("command")
            .or_else(|| input.get("cmd"))
            .and_then(|v| v.as_str())
        {
            let command_summary = truncate_for_log(command, 140);
            return format!("bash `{command_summary}` failed: {error_summary}");
        }
    }
    let input_summary = truncate_for_log(&input.to_string(), 100);
    format!("{tool_name} input `{input_summary}` failed: {error_summary}")
}

fn truncate_for_log(text: &str, max_chars: usize) -> String {
    let count = text.chars().count();
    if count <= max_chars {
        text.to_string()
    } else {
        let clipped = text.chars().take(max_chars).collect::<String>();
        format!("{clipped}...")
    }
}

#[expect(clippy::too_many_arguments)]
fn emit_tool_span(
    exp: &Arc<OtlpTraceExporter>,
    trace_id: &[u8],
    span_id: Vec<u8>,
    parent_span_id: &[u8],
    name: &str,
    input: &Value,
    result: &ToolResult,
    start_time: u64,
    span_name: &str,
) {
    let mut attrs = vec![
        kv("tool.name", name),
        kv("input", &input.to_string()),
    ];
    if result.is_error {
        attrs.push(kv(
            "error.type",
            result.error_type.as_deref().unwrap_or("unknown"),
        ));
        attrs.push(kv("output", &result.content));
    } else {
        attrs.push(kv("output", &truncate_for_log(&result.content, 1000)));
    }
    exp.send_span(SpanData {
        trace_id: trace_id.to_vec(),
        span_id,
        parent_span_id: parent_span_id.to_vec(),
        name: span_name.to_string(),
        start_time_unix_nano: start_time,
        end_time_unix_nano: now_unix_nano(),
        attributes: attrs,
        status: if result.is_error {
            Some(Status {
                message: result.content.clone(),
                code: 2,
            })
        } else {
            Some(Status {
                message: "".to_string(),
                code: 1,
            })
        },
        kind: 1,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_partition_single_readonly() {
        let calls = vec![PendingToolCall {
            id: "1".into(),
            name: "read_file".into(),
            input: Value::Null,
        }];
        let waves = partition_into_waves(&calls, &HashMap::new());
        assert_eq!(waves, vec![vec![0]]);
    }

    #[test]
    fn test_partition_all_readonly_parallel() {
        let calls = vec![
            PendingToolCall { id: "1".into(), name: "read_file".into(), input: Value::Null },
            PendingToolCall { id: "2".into(), name: "glob".into(), input: Value::Null },
            PendingToolCall { id: "3".into(), name: "web_search".into(), input: Value::Null },
        ];
        let waves = partition_into_waves(&calls, &HashMap::new());
        assert_eq!(waves, vec![vec![0, 1, 2]]);
    }

    #[test]
    fn test_partition_mixed_readonly_sideeffect() {
        let calls = vec![
            PendingToolCall { id: "1".into(), name: "read_file".into(), input: Value::Null },
            PendingToolCall { id: "2".into(), name: "write_file".into(), input: Value::Null },
            PendingToolCall { id: "3".into(), name: "glob".into(), input: Value::Null },
        ];
        let waves = partition_into_waves(&calls, &HashMap::new());
        // Wave 1: readonly [0, 2], Wave 2: sideeffect [1]
        assert_eq!(waves, vec![vec![0, 2], vec![1]]);
    }

    #[test]
    fn test_partition_exclusive_alone() {
        let calls = vec![
            PendingToolCall { id: "1".into(), name: "read_file".into(), input: Value::Null },
            PendingToolCall { id: "2".into(), name: "bash".into(), input: Value::Null },
            PendingToolCall { id: "3".into(), name: "glob".into(), input: Value::Null },
        ];
        let waves = partition_into_waves(&calls, &HashMap::new());
        // Wave 1: readonly [0, 2], Wave 2: exclusive [1]
        assert_eq!(waves, vec![vec![0, 2], vec![1]]);
    }

    #[test]
    fn test_partition_config_override() {
        let mut overrides = HashMap::new();
        overrides.insert("mcp_custom_search".to_string(), "read_only".to_string());

        let calls = vec![
            PendingToolCall { id: "1".into(), name: "read_file".into(), input: Value::Null },
            PendingToolCall { id: "2".into(), name: "mcp_custom_search".into(), input: Value::Null },
        ];
        let waves = partition_into_waves(&calls, &overrides);
        // Both should be in single parallel wave (mcp_custom_search overridden to ReadOnly)
        assert_eq!(waves, vec![vec![0, 1]]);
    }

    #[test]
    fn test_partition_empty() {
        let calls: Vec<PendingToolCall> = vec![];
        let waves = partition_into_waves(&calls, &HashMap::new());
        assert!(waves.is_empty());
    }
}
