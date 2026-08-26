//! Concurrent AgentEvent tap for channel adapters.
//!
//! Channel adapters previously drained their `AgentEvent` receiver only after
//! the agent loop returned, which made live-action events such as
//! `MidTurnInjection` invisible until the turn finished. This helper consumes
//! events concurrently with the running agent, runs an optional callback on
//! each `MidTurnInjection` (typically to ack the user immediately), and
//! forwards every event to a replay channel so existing post-hoc consumers
//! (Telegram streaming, `send_message` tool detection, ...) keep working.
//!
//! See `docs/roadmap/non-web-channel-progress-events-plan.md` for the larger
//! plan this is one phase of.
use crate::agent_engine::AgentEvent;
use std::future::Future;
use std::pin::Pin;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};
use tokio::task::JoinHandle;

/// Outcome of consuming the agent's event stream.
#[derive(Default, Clone, Copy, Debug)]
pub struct EventTapResult {
    /// `true` if any `ToolStart` for the `send_message` tool was observed.
    /// Channel adapters use this to suppress the duplicate final reply when
    /// the agent already delivered output via the `send_message` tool.
    pub used_send_message_tool: bool,
    /// `true` if the turn paused on a high-risk tool approval
    /// (`ApprovalRequired` observed). Channel adapters use this to attach
    /// interactive approve/deny buttons to the approval prompt.
    pub approval_requested: bool,
}

/// Concurrent event consumer.
///
/// `replay_rx` yields every event after it has been observed by the tap, in
/// the same order the agent emitted them. `join` resolves once the agent
/// drops its sender and the tap finishes processing the buffered tail.
pub struct EventTap {
    pub replay_rx: UnboundedReceiver<AgentEvent>,
    pub join: JoinHandle<EventTapResult>,
}

/// Async callback invoked when a `MidTurnInjection` event is observed.
pub type InjectionAck =
    Box<dyn Fn(usize) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + 'static>;

/// Throttle settings for the Phase-3 progress heartbeat.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProgressConfig {
    /// Don't emit anything for turns shorter than this.
    pub min_turn_secs: u64,
    /// Minimum spacing between progress emissions (also the edit-rate guard:
    /// 20s = 3/min, well under Telegram's 20 edits/min cap).
    pub interval_secs: u64,
}

/// Async progress emitter. `(text, terminal)`: the first call creates the
/// progress message, later calls edit it in place, and the terminal call
/// (fired once when the turn ends, only if progress was ever shown)
/// finalizes it.
pub type ProgressEmit =
    Box<dyn Fn(String, bool) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + 'static>;

/// Async emitter for a chat-facing file-diff message (already formatted).
pub type DiffEmit =
    Box<dyn Fn(String) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + 'static>;

/// Render a compact 6-slot progress bar for a 0-100 percent value.
pub fn progress_bar(percent: u8) -> String {
    let percent = percent.min(100);
    let filled = (usize::from(percent) * 6 + 50) / 100;
    let mut bar = String::new();
    for i in 0..6 {
        bar.push(if i < filled { '▰' } else { '▱' });
    }
    format!("{bar} {percent}%")
}

/// Blend an explicit percent (from a `report_progress` tool call) with an
/// activity-based fallback so weaker models that never report progress still
/// show motion. The fallback grows with iterations relative to the
/// configured cap and is itself capped at 90% (only a real terminal event
/// reaches 100%). Explicit reports always win and the result never goes
/// backwards.
pub fn estimate_percent(
    explicit: Option<u8>,
    iteration: usize,
    max_iterations: usize,
    floor: u8,
) -> u8 {
    let estimated = (iteration.min(max_iterations) * 90)
        .checked_div(max_iterations)
        .unwrap_or(0) as u8;
    explicit.map(|p| p.min(100)).unwrap_or(estimated).max(floor)
}

/// One-line progress text from the tap's view of the turn.
pub fn progress_text(iteration: usize, last_tool: Option<&str>) -> String {
    progress_text_rich(iteration, last_tool, None, 0)
}

/// Progress line with an optional percent bar and live sub-agent count.
pub fn progress_text_rich(
    iteration: usize,
    last_tool: Option<&str>,
    percent: Option<u8>,
    subagents_running: usize,
) -> String {
    let mut line = match last_tool {
        Some(tool) => format!("⏳ Working — step {iteration}, using `{tool}`…"),
        None => format!("⏳ Working — step {iteration}…"),
    };
    if let Some(p) = percent {
        line.push_str(&format!("\n{}", progress_bar(p)));
    }
    if subagents_running > 0 {
        line.push_str(&format!("\n🤖 {subagents_running} sub-agent(s) running"));
    }
    line
}

/// Terminal text the progress message is edited to when the turn completes.
pub fn progress_done_text() -> &'static str {
    "✅ Done — reply below."
}

/// Optional behaviors layered on the tap. `Default` is a bare pass-through.
#[derive(Default)]
pub struct TapOptions {
    pub on_inject: Option<InjectionAck>,
    pub progress: Option<(ProgressConfig, ProgressEmit)>,
    /// Chat-facing file-diff delivery (already-formatted message per diff).
    pub on_diff: Option<DiffEmit>,
    /// The turn's `max_tool_iterations` cap, used by the fallback percent
    /// estimator. 0 disables the estimator (percent shows only when the
    /// agent reports one explicitly).
    pub max_iterations: usize,
}

impl EventTap {
    /// Spawn a background task that reads from `event_rx`, runs `on_inject` on
    /// each `MidTurnInjection`, tracks `send_message` tool usage, and forwards
    /// every event to the returned `replay_rx`.
    pub fn spawn(event_rx: UnboundedReceiver<AgentEvent>, on_inject: Option<InjectionAck>) -> Self {
        Self::spawn_with_progress(event_rx, on_inject, None)
    }

    /// Like [`EventTap::spawn`], additionally emitting a throttled progress
    /// heartbeat built from `Iteration` / `ToolStart` events. Emission starts
    /// only once the turn has lasted `min_turn_secs` (short turns stay
    /// silent) and is spaced at least `interval_secs` apart; a terminal
    /// emission fires when the stream ends iff progress was ever shown.
    pub fn spawn_with_progress(
        event_rx: UnboundedReceiver<AgentEvent>,
        on_inject: Option<InjectionAck>,
        progress: Option<(ProgressConfig, ProgressEmit)>,
    ) -> Self {
        Self::spawn_with_options(
            event_rx,
            TapOptions {
                on_inject,
                progress,
                ..TapOptions::default()
            },
        )
    }

    /// Full-option variant: progress heartbeat (with percent estimation and
    /// live sub-agent count), mid-turn injection acks, and chat-facing file
    /// diff delivery.
    pub fn spawn_with_options(
        mut event_rx: UnboundedReceiver<AgentEvent>,
        options: TapOptions,
    ) -> Self {
        let TapOptions {
            on_inject,
            progress,
            on_diff,
            max_iterations,
        } = options;
        let (replay_tx, replay_rx) = unbounded_channel();
        let join = tokio::spawn(async move {
            let mut result = EventTapResult::default();
            let turn_start = tokio::time::Instant::now();
            let mut last_emit: Option<tokio::time::Instant> = None;
            let mut emitted = false;
            let mut iteration = 0usize;
            let mut last_tool: Option<String> = None;
            let mut explicit_percent: Option<u8> = None;
            let mut percent_floor: u8 = 0;
            let mut subagents_running: usize = 0;
            while let Some(event) = event_rx.recv().await {
                match &event {
                    AgentEvent::MidTurnInjection { count } => {
                        if let Some(cb) = on_inject.as_ref() {
                            cb(*count).await;
                        }
                    }
                    AgentEvent::ToolStart { name, input, .. } => {
                        if name == "send_message" {
                            result.used_send_message_tool = true;
                        }
                        // The agent's own progress reports double as the
                        // explicit percent source for the heartbeat bar.
                        if name == "report_progress" {
                            if let Some(p) = input.get("percent").and_then(|v| v.as_u64()) {
                                explicit_percent = Some(p.min(100) as u8);
                            }
                        }
                        last_tool = Some(name.clone());
                    }
                    AgentEvent::Iteration { iteration: i } => {
                        iteration = *i;
                    }
                    AgentEvent::ApprovalRequired { .. } => {
                        result.approval_requested = true;
                    }
                    AgentEvent::SubagentStarted { .. } => {
                        subagents_running += 1;
                    }
                    AgentEvent::SubagentFinished { .. } => {
                        subagents_running = subagents_running.saturating_sub(1);
                    }
                    AgentEvent::FileDiff {
                        path,
                        diff,
                        added,
                        removed,
                        ..
                    } => {
                        if let Some(cb) = on_diff.as_ref() {
                            cb(microclaw_core::diff::format_diff_chat_message(
                                path, diff, *added, *removed,
                            ))
                            .await;
                        }
                    }
                    _ => {}
                }
                if let Some((cfg, emit)) = progress.as_ref() {
                    let long_enough = turn_start.elapsed().as_secs() >= cfg.min_turn_secs;
                    let spaced = last_emit
                        .map(|t| t.elapsed().as_secs() >= cfg.interval_secs.max(5))
                        .unwrap_or(true);
                    if long_enough && spaced {
                        let percent = if max_iterations > 0 || explicit_percent.is_some() {
                            let p = estimate_percent(
                                explicit_percent,
                                iteration,
                                max_iterations,
                                percent_floor,
                            );
                            percent_floor = p;
                            Some(p)
                        } else {
                            None
                        };
                        emit(
                            progress_text_rich(
                                iteration.max(1),
                                last_tool.as_deref(),
                                percent,
                                subagents_running,
                            ),
                            false,
                        )
                        .await;
                        emitted = true;
                        last_emit = Some(tokio::time::Instant::now());
                    }
                }
                // Replay receiver may already be dropped (e.g. caller bailed).
                // We still keep tracking flags for the join result.
                let _ = replay_tx.send(event);
            }
            if emitted {
                if let Some((_, emit)) = progress.as_ref() {
                    emit(progress_done_text().to_string(), true).await;
                }
            }
            result
        });
        EventTap { replay_rx, join }
    }
}

/// Per-channel Phase-3 heartbeat settings, read from the free-form channel
/// config mapping (same pattern as the hooks runtime settings):
///
/// ```yaml
/// channels:
///   telegram:
///     progress_updates:
///       enabled: true
///       groups: false                 # default off for groups (noise)
///       min_turn_seconds: 30
///       update_interval_seconds: 20
/// ```
///
/// Default is fully OFF — no behavior change until an operator opts in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProgressUpdatesSettings {
    pub enabled: bool,
    pub groups: bool,
    /// Pin the progress message while the turn runs and unpin it on
    /// completion (Telegram only today). Default off.
    pub pin: bool,
    pub config: ProgressConfig,
}

pub fn progress_updates_settings(
    config: &crate::config::Config,
    channel: &str,
) -> ProgressUpdatesSettings {
    let mut out = ProgressUpdatesSettings {
        enabled: false,
        groups: false,
        pin: false,
        config: ProgressConfig {
            min_turn_secs: 30,
            interval_secs: 20,
        },
    };
    let Some(section) = config
        .channels
        .get(channel)
        .and_then(|v| v.as_mapping())
        .and_then(|m| m.get(serde_yaml::Value::String("progress_updates".into())))
        .and_then(|v| v.as_mapping())
    else {
        return out;
    };
    let get_bool = |k: &str| {
        section
            .get(serde_yaml::Value::String(k.to_string()))
            .and_then(|x| x.as_bool())
    };
    let get_u64 = |k: &str| {
        section
            .get(serde_yaml::Value::String(k.to_string()))
            .and_then(|x| x.as_u64())
    };
    if let Some(v) = get_bool("enabled") {
        out.enabled = v;
    }
    if let Some(v) = get_bool("groups") {
        out.groups = v;
    }
    if let Some(v) = get_bool("pin") {
        out.pin = v;
    }
    if let Some(v) = get_u64("min_turn_seconds") {
        out.config.min_turn_secs = v;
    }
    if let Some(v) = get_u64("update_interval_seconds") {
        out.config.interval_secs = v.max(5);
    }
    out
}

/// User-facing acknowledgement text for a `MidTurnInjection` event.
///
/// Kept here (rather than `microclaw-core::text`) because it is only used by
/// channel-side progress acks today. If more channels grow localized copy this
/// can move into a shared `text` module.
pub fn mid_turn_injection_ack_text(count: usize) -> String {
    if count == 1 {
        "📥 Got 1 follow-up message — folding it into the current turn.".to_string()
    } else {
        format!("📥 Got {count} follow-up messages — folding them into the current turn.")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn make_event_channel() -> (
        tokio::sync::mpsc::UnboundedSender<AgentEvent>,
        tokio::sync::mpsc::UnboundedReceiver<AgentEvent>,
    ) {
        unbounded_channel()
    }

    #[tokio::test]
    async fn forwards_all_events_to_replay() {
        let (tx, rx) = make_event_channel();
        let mut tap = EventTap::spawn(rx, None);

        tx.send(AgentEvent::Iteration { iteration: 1 }).unwrap();
        tx.send(AgentEvent::ToolStart {
            call_id: "read-1".into(),
            name: "read_file".into(),
            input: serde_json::json!({}),
        })
        .unwrap();
        tx.send(AgentEvent::FinalResponse { text: "ok".into() })
            .unwrap();
        drop(tx);

        let mut received = Vec::new();
        while let Some(ev) = tap.replay_rx.recv().await {
            received.push(ev);
        }
        let result = tap.join.await.expect("tap task did not panic");

        assert_eq!(received.len(), 3);
        assert!(!result.used_send_message_tool);
    }

    #[tokio::test]
    async fn detects_send_message_tool_usage() {
        let (tx, rx) = make_event_channel();
        let mut tap = EventTap::spawn(rx, None);

        tx.send(AgentEvent::ToolStart {
            call_id: "send-1".into(),
            name: "send_message".into(),
            input: serde_json::json!({}),
        })
        .unwrap();
        drop(tx);

        // Drain to keep the forwarder unblocked.
        while tap.replay_rx.recv().await.is_some() {}
        let result = tap.join.await.unwrap();
        assert!(result.used_send_message_tool);
    }

    #[tokio::test]
    async fn calls_inject_callback_in_real_time() {
        let (tx, rx) = make_event_channel();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_for_cb = counter.clone();
        let cb: InjectionAck = Box::new(move |count| {
            let counter_for_cb = counter_for_cb.clone();
            Box::pin(async move {
                counter_for_cb.fetch_add(count, Ordering::SeqCst);
            })
        });
        let mut tap = EventTap::spawn(rx, Some(cb));

        tx.send(AgentEvent::MidTurnInjection { count: 2 }).unwrap();
        tx.send(AgentEvent::Iteration { iteration: 5 }).unwrap();
        tx.send(AgentEvent::MidTurnInjection { count: 3 }).unwrap();
        drop(tx);

        while tap.replay_rx.recv().await.is_some() {}
        let _ = tap.join.await.unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 5);
    }

    #[test]
    fn ack_text_singular_and_plural() {
        let one = mid_turn_injection_ack_text(1);
        let many = mid_turn_injection_ack_text(7);
        assert!(one.contains("1 follow-up message"));
        assert!(many.contains("7 follow-up messages"));
    }

    #[tokio::test]
    async fn progress_heartbeat_throttles_and_finalizes() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};
        let (tx, rx) = unbounded_channel();
        let calls = Arc::new(AtomicUsize::new(0));
        let last: Arc<Mutex<(String, bool)>> = Arc::new(Mutex::new((String::new(), false)));
        let calls_in = calls.clone();
        let last_in = last.clone();
        let emit: ProgressEmit = Box::new(move |text, terminal| {
            let calls = calls_in.clone();
            let last = last_in.clone();
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                *last.lock().unwrap() = (text, terminal);
            })
        });
        let cfg = ProgressConfig {
            min_turn_secs: 0, // fire immediately in tests
            interval_secs: 3600,
        };
        let mut tap = EventTap::spawn_with_progress(rx, None, Some((cfg, emit)));
        tx.send(AgentEvent::Iteration { iteration: 1 }).unwrap();
        tx.send(AgentEvent::ToolStart {
            call_id: "search-1".into(),
            name: "web_search".into(),
            input: serde_json::json!({}),
        })
        .unwrap();
        // Burst of events inside the interval — throttled to the first emit.
        for i in 2..10 {
            tx.send(AgentEvent::Iteration { iteration: i }).unwrap();
        }
        drop(tx);
        while tap.replay_rx.recv().await.is_some() {}
        let _ = tap.join.await.unwrap();
        // 1 live emission + 1 terminal emission.
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        let (text, terminal) = last.lock().unwrap().clone();
        assert!(terminal);
        assert_eq!(text, progress_done_text());
    }

    #[tokio::test]
    async fn short_turns_stay_silent() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let (tx, rx) = unbounded_channel();
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_in = calls.clone();
        let emit: ProgressEmit = Box::new(move |_t, _f| {
            let calls = calls_in.clone();
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
            })
        });
        let cfg = ProgressConfig {
            min_turn_secs: 3600, // turn will never qualify
            interval_secs: 5,
        };
        let mut tap = EventTap::spawn_with_progress(rx, None, Some((cfg, emit)));
        tx.send(AgentEvent::Iteration { iteration: 1 }).unwrap();
        drop(tx);
        while tap.replay_rx.recv().await.is_some() {}
        let _ = tap.join.await.unwrap();
        // No live emission -> no terminal emission either.
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn progress_text_prefers_tool_name() {
        assert_eq!(
            progress_text(3, Some("web_search")),
            "⏳ Working — step 3, using `web_search`…"
        );
        assert_eq!(progress_text(1, None), "⏳ Working — step 1…");
    }

    #[test]
    fn progress_bar_renders_six_slots() {
        assert_eq!(progress_bar(0), "▱▱▱▱▱▱ 0%");
        assert_eq!(progress_bar(50), "▰▰▰▱▱▱ 50%");
        assert_eq!(progress_bar(100), "▰▰▰▰▰▰ 100%");
        assert_eq!(progress_bar(250), "▰▰▰▰▰▰ 100%");
    }

    #[test]
    fn estimate_percent_prefers_explicit_and_never_regresses() {
        // Explicit report wins over the estimator.
        assert_eq!(estimate_percent(Some(40), 1, 20, 0), 40);
        // Estimator: iteration 10 of 20 → 45% (of the 90% cap).
        assert_eq!(estimate_percent(None, 10, 20, 0), 45);
        // Estimator never exceeds 90 without an explicit report.
        assert_eq!(estimate_percent(None, 20, 20, 0), 90);
        assert_eq!(estimate_percent(None, 99, 20, 0), 90);
        // Floor keeps the bar from moving backwards.
        assert_eq!(estimate_percent(None, 1, 20, 60), 60);
    }

    #[test]
    fn rich_progress_text_includes_bar_and_subagents() {
        let line = progress_text_rich(3, Some("bash"), Some(50), 2);
        assert!(line.contains("step 3, using `bash`"));
        assert!(line.contains("▰▰▰▱▱▱ 50%"));
        assert!(line.contains("🤖 2 sub-agent(s) running"));
    }

    #[tokio::test]
    async fn file_diff_events_reach_diff_callback() {
        use std::sync::{Arc, Mutex};
        let (tx, rx) = unbounded_channel();
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_in = seen.clone();
        let on_diff: DiffEmit = Box::new(move |msg| {
            let seen = seen_in.clone();
            Box::pin(async move {
                seen.lock().unwrap().push(msg);
            })
        });
        let mut tap = EventTap::spawn_with_options(
            rx,
            TapOptions {
                on_diff: Some(on_diff),
                ..TapOptions::default()
            },
        );
        tx.send(AgentEvent::FileDiff {
            path: "src/x.rs".into(),
            diff: "@@ -1 +1 @@\n-a\n+b".into(),
            added: 1,
            removed: 1,
            truncated: false,
        })
        .unwrap();
        drop(tx);
        while tap.replay_rx.recv().await.is_some() {}
        let _ = tap.join.await.unwrap();
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert!(seen[0].starts_with("📝 `src/x.rs` (+1 -1)"));
        assert!(seen[0].contains("```diff"));
    }

    #[tokio::test]
    async fn subagent_events_adjust_running_count() {
        let (tx, rx) = unbounded_channel();
        let mut tap = EventTap::spawn(rx, None);
        tx.send(AgentEvent::SubagentStarted {
            run_id: "r1".into(),
            label: "worker".into(),
        })
        .unwrap();
        tx.send(AgentEvent::SubagentFinished {
            run_id: "r1".into(),
            status: "completed".into(),
        })
        .unwrap();
        drop(tx);
        let mut count = 0;
        while tap.replay_rx.recv().await.is_some() {
            count += 1;
        }
        assert_eq!(count, 2);
        let _ = tap.join.await.unwrap();
    }
}
