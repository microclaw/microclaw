//! UI-independent application service for running MicroClaw Work tasks.
//!
//! This crate owns the foreground worker lifecycle and bridges the shared
//! Agent Engine to versioned runtime events. UI packages consume this port;
//! they do not create Tokio runtimes or call the Agent Engine directly.

use microclaw::config::Config;
use microclaw::headless::{HeadlessRunRequest, HeadlessRuntime};
use microclaw_core::runtime_event::RuntimeEventEnvelope;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;

static NEXT_RUN_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone)]
pub struct WorkRunRequest {
    pub task: String,
    pub workspace: String,
    pub session: String,
}

#[derive(Debug, Clone)]
pub struct RuntimeConfigSummary {
    pub ready: bool,
    pub provider: String,
    pub model: String,
    pub detail: String,
}

pub fn load_runtime_config_summary() -> RuntimeConfigSummary {
    match Config::load() {
        Ok(config) => {
            let path = Config::resolve_config_path()
                .ok()
                .flatten()
                .unwrap_or_else(Config::config_path_for_setup);
            RuntimeConfigSummary {
                ready: true,
                provider: config.llm_provider,
                model: config.model,
                detail: path.display().to_string(),
            }
        }
        Err(error) => RuntimeConfigSummary {
            ready: false,
            provider: "Not configured".into(),
            model: "—".into(),
            detail: format!("{error} Run `microclaw setup` first."),
        },
    }
}

#[derive(Debug)]
pub enum WorkRuntimeMessage {
    Envelope(RuntimeEventEnvelope),
    Completed { run_id: String },
    Failed { run_id: String, message: String },
}

pub struct WorkRunHandle {
    pub messages: Receiver<WorkRuntimeMessage>,
    pub cancellation: WorkRunCancellation,
}

#[derive(Clone)]
pub struct WorkRunCancellation {
    cancel_tx: tokio::sync::mpsc::UnboundedSender<()>,
}

impl WorkRunCancellation {
    pub fn cancel(&self) -> Result<(), &'static str> {
        self.cancel_tx
            .send(())
            .map_err(|_| "The runtime has already exited; the stop request was not sent.")
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct WorkRuntimeService;

impl WorkRuntimeService {
    pub fn start(&self, request: WorkRunRequest) -> WorkRunHandle {
        let (message_tx, message_rx) = mpsc::channel();
        let (cancel_tx, cancel_rx) = tokio::sync::mpsc::unbounded_channel();
        let run_id = next_run_id();
        let thread_name = format!("microclaw-work-{run_id}");
        let worker_run_id = run_id.clone();
        let worker_message_tx = message_tx.clone();
        let spawn_result = std::thread::Builder::new()
            .name(thread_name)
            .spawn(move || run_worker(request, worker_run_id, worker_message_tx, cancel_rx));
        if let Err(error) = spawn_result {
            let _ = message_tx.send(WorkRuntimeMessage::Failed {
                run_id,
                message: format!("Could not start the runtime worker thread: {error}"),
            });
        }
        WorkRunHandle {
            messages: message_rx,
            cancellation: WorkRunCancellation { cancel_tx },
        }
    }
}

fn run_worker(
    request: WorkRunRequest,
    run_id: String,
    message_tx: Sender<WorkRuntimeMessage>,
    mut cancel_rx: tokio::sync::mpsc::UnboundedReceiver<()>,
) {
    let tokio_runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(error) => {
            send_failure(
                &message_tx,
                &run_id,
                format!("Could not create the Tokio runtime: {error}"),
            );
            return;
        }
    };

    let result = tokio_runtime.block_on(async {
        let mut config = Config::load()?;
        config.working_dir = request.workspace;
        let runtime = HeadlessRuntime::load(config).await?;
        let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel();
        let event_message_tx = message_tx.clone();
        let event_forwarder = tokio::spawn(async move {
            while let Some(envelope) = event_rx.recv().await {
                if event_message_tx
                    .send(WorkRuntimeMessage::Envelope(envelope))
                    .is_err()
                {
                    break;
                }
            }
        });

        let session = request.session.clone();
        let run = runtime.run(
            HeadlessRunRequest::work(request.task, Some(request.session), run_id.clone()),
            Some(event_tx),
        );
        tokio::pin!(run);
        let result = tokio::select! {
            result = &mut run => result,
            signal = cancel_rx.recv() => {
                if signal.is_some() {
                    let completed_while_waiting = loop {
                        let aborted = runtime.cancel_session(&session).await?;
                        if aborted > 0 {
                            break None;
                        }
                        tokio::select! {
                            result = &mut run => break Some(result),
                            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
                        }
                    };
                    match completed_while_waiting {
                        Some(result) => result,
                        None => run.await,
                    }
                } else {
                    run.await
                }
            }
        };
        event_forwarder.await?;
        result
    });

    match result {
        Ok(result) => {
            let _ = message_tx.send(WorkRuntimeMessage::Completed {
                run_id: result.run_id,
            });
        }
        Err(error) => send_failure(&message_tx, &run_id, error.to_string()),
    }
}

fn send_failure(message_tx: &Sender<WorkRuntimeMessage>, run_id: &str, message: String) {
    let _ = message_tx.send(WorkRuntimeMessage::Failed {
        run_id: run_id.to_string(),
        message,
    });
}

fn next_run_id() -> String {
    let counter = NEXT_RUN_ID.fetch_add(1, Ordering::Relaxed);
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis());
    format!("work-{millis}-{counter}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_run_ids_are_unique() {
        assert_ne!(next_run_id(), next_run_id());
    }

    #[test]
    fn cancellation_signal_is_runtime_independent() {
        let (cancel_tx, mut cancel_rx) = tokio::sync::mpsc::unbounded_channel();
        let cancellation = WorkRunCancellation { cancel_tx };

        cancellation.cancel().unwrap();
        assert_eq!(cancel_rx.try_recv(), Ok(()));
    }
}
