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

impl EventTap {
    /// Spawn a background task that reads from `event_rx`, runs `on_inject` on
    /// each `MidTurnInjection`, tracks `send_message` tool usage, and forwards
    /// every event to the returned `replay_rx`.
    pub fn spawn(mut event_rx: UnboundedReceiver<AgentEvent>, on_inject: Option<InjectionAck>) -> Self {
        let (replay_tx, replay_rx) = unbounded_channel();
        let join = tokio::spawn(async move {
            let mut result = EventTapResult::default();
            while let Some(event) = event_rx.recv().await {
                match &event {
                    AgentEvent::MidTurnInjection { count } => {
                        if let Some(cb) = on_inject.as_ref() {
                            cb(*count).await;
                        }
                    }
                    AgentEvent::ToolStart { name, .. } if name == "send_message" => {
                        result.used_send_message_tool = true;
                    }
                    _ => {}
                }
                // Replay receiver may already be dropped (e.g. caller bailed).
                // We still keep tracking flags for the join result.
                let _ = replay_tx.send(event);
            }
            result
        });
        EventTap { replay_rx, join }
    }
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
}
