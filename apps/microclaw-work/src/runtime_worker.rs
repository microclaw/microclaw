use microclaw::config::Config;
use microclaw::headless::{HeadlessRunRequest, HeadlessRuntime};
use microclaw_core::runtime_event::RuntimeEventEnvelope;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};

static NEXT_RUN_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone)]
pub struct RuntimeRunSpec {
    pub task: String,
    pub workspace: String,
    pub session: String,
}

#[derive(Debug)]
pub enum RuntimeMessage {
    Envelope(RuntimeEventEnvelope),
    Completed { run_id: String },
    Failed { run_id: String, message: String },
}

pub fn spawn_runtime(spec: RuntimeRunSpec) -> Receiver<RuntimeMessage> {
    let (message_tx, message_rx) = mpsc::channel();
    let run_id = next_run_id();
    let thread_name = format!("microclaw-work-{run_id}");
    let worker_run_id = run_id.clone();
    let spawn_result = std::thread::Builder::new()
        .name(thread_name)
        .spawn(move || run_worker(spec, worker_run_id, message_tx));
    if let Err(error) = spawn_result {
        let (fallback_tx, fallback_rx) = mpsc::channel();
        let _ = fallback_tx.send(RuntimeMessage::Failed {
            run_id,
            message: format!("无法启动 Runtime 后台线程：{error}"),
        });
        return fallback_rx;
    }
    message_rx
}

fn run_worker(spec: RuntimeRunSpec, run_id: String, message_tx: Sender<RuntimeMessage>) {
    let tokio_runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(error) => {
            send_failure(
                &message_tx,
                &run_id,
                format!("无法创建 Tokio Runtime：{error}"),
            );
            return;
        }
    };

    let result = tokio_runtime.block_on(async {
        let mut config = Config::load()?;
        config.working_dir = spec.workspace;
        let runtime = HeadlessRuntime::load(config).await?;
        let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel();
        let event_message_tx = message_tx.clone();
        let event_forwarder = tokio::spawn(async move {
            while let Some(envelope) = event_rx.recv().await {
                if event_message_tx
                    .send(RuntimeMessage::Envelope(envelope))
                    .is_err()
                {
                    break;
                }
            }
        });

        let result = runtime
            .run(
                HeadlessRunRequest::work(spec.task, Some(spec.session), run_id.clone()),
                Some(event_tx),
            )
            .await;
        event_forwarder.await?;
        result
    });

    match result {
        Ok(result) => {
            let _ = message_tx.send(RuntimeMessage::Completed {
                run_id: result.run_id,
            });
        }
        Err(error) => send_failure(&message_tx, &run_id, error.to_string()),
    }
}

fn send_failure(message_tx: &Sender<RuntimeMessage>, run_id: &str, message: String) {
    let _ = message_tx.send(RuntimeMessage::Failed {
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
}
