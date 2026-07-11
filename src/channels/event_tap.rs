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
pub type InjectionAck = Box<
    dyn Fn(usize) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + 'static,
>;

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
pub type ProgressEmit = Box<
    dyn Fn(String, bool) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + 'static,
>;

/// One-line progress text from the tap's view of the turn.
pub fn progress_text(iteration: usize, last_tool: Option<&str>) -> String {
    match last_tool {
        Some(tool) => format!("⏳ Working — step {iteration}, using `{tool}`…"),
        None => format!("⏳ Working — step {iteration}…"),
    }
}

/// Terminal text the progress message is edited to when the turn completes.
pub fn progress_done_text() -> &'static str {
    "✅ Done — reply below."
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
        mut event_rx: UnboundedReceiver<AgentEvent>,
        on_inject: Option<InjectionAck>,
        progress: Option<(ProgressConfig, ProgressEmit)>,
    ) -> Self {
        let (replay_tx, replay_rx) = unbounded_channel();
        let join = tokio::spawn(async move {
            let mut result = EventTapResult::default();
            let turn_start = tokio::time::Instant::now();
            let mut last_emit: Option<tokio::time::Instant> = None;
            let mut emitted = false;
            let mut iteration = 0usize;
            let mut last_tool: Option<String> = None;
            while let Some(event) = event_rx.recv().await {
                match &event {
                    AgentEvent::MidTurnInjection { count } => {
                        if let Some(cb) = on_inject.as_ref() {
                            cb(*count).await;
                        }
                    }
                    AgentEvent::ToolStart { name, .. } => {
                        if name == "send_message" {
                            result.used_send_message_tool = true;
                        }
                        last_tool = Some(name.clone());
                    }
                    AgentEvent::Iteration { iteration: i } => {
                        iteration = *i;
                    }
                    _ => {}
                }
                if let Some((cfg, emit)) = progress.as_ref() {
                    let long_enough =
                        turn_start.elapsed().as_secs() >= cfg.min_turn_secs;
                    let spaced = last_emit
                        .map(|t| t.elapsed().as_secs() >= cfg.interval_secs.max(5))
                        .unwrap_or(true);
                    if long_enough && spaced {
                        emit(progress_text(iteration.max(1), last_tool.as_deref()), false)
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
    pub config: ProgressConfig,
}

pub fn progress_updates_settings(
    config: &crate::config::Config,
    channel: &str,
) -> ProgressUpdatesSettings {
    let mut out = ProgressUpdatesSettings {
        enabled: false,
        groups: false,
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
        format!(
            "📥 Got {count} follow-up messages — folding them into the current turn."
        )
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
            name: "read_file".into(),
            input: serde_json::json!({}),
        })
        .unwrap();
        tx.send(AgentEvent::FinalResponse {
            text: "ok".into(),
        })
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
}
