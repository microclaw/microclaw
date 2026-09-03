//! Headless proof that Work state is driven by shared runtime events, not GPUI.

use microclaw_sdk::{MicroClaw, RunId, RunRequest, RuntimeEvent, RuntimeEventEnvelope, SessionId};
use microclaw_work_app::session::{WorkCommand, WorkSessionSnapshot};
use microclaw_work_app::store::WorkSessionStore;
use std::error::Error;
use std::io::{self, BufRead};

fn project_events(
    task: &str,
    events: impl IntoIterator<Item = RuntimeEventEnvelope>,
) -> Result<WorkSessionSnapshot, Box<dyn Error>> {
    let workspace = std::env::current_dir()?.display().to_string();
    let mut session = WorkSessionSnapshot::new(workspace);
    session.apply(WorkCommand::StartTask { task: task.into() })?;
    for event in events {
        session.apply(WorkCommand::ApplyRuntimeEvent(event))?;
    }
    Ok(session)
}

fn demo_events() -> Vec<RuntimeEventEnvelope> {
    let run_id = "headless-demo";
    vec![
        RuntimeEventEnvelope::new(run_id, 1, RuntimeEvent::Iteration { iteration: 1 }),
        RuntimeEventEnvelope::new(
            run_id,
            2,
            RuntimeEvent::ToolStart {
                call_id: "headless-read".into(),
                name: "read_file".into(),
                input: serde_json::json!({"path": "Cargo.toml"}),
            },
        ),
        RuntimeEventEnvelope::new(
            run_id,
            3,
            RuntimeEvent::ToolResult {
                call_id: "headless-read".into(),
                name: "read_file".into(),
                is_error: false,
                preview: "workspace manifest loaded".into(),
                duration_ms: 4,
                status_code: None,
                bytes: 512,
                error_type: None,
            },
        ),
        RuntimeEventEnvelope::new(
            run_id,
            4,
            RuntimeEvent::FinalResponse {
                text: "headless event projection completed".into(),
            },
        ),
    ]
}

fn recovery_crash(root: &str) -> Result<(), Box<dyn Error>> {
    let store = WorkSessionStore::new(root);
    let mut session = store.create(std::env::current_dir()?.display().to_string())?;
    session.apply(WorkCommand::StartTask {
        task: "Recover this durable Work thread".into(),
    })?;
    session.apply(WorkCommand::ApplyRuntimeEvent(RuntimeEventEnvelope::new(
        "process-recovery-run",
        1,
        RuntimeEvent::TextDelta {
            delta: "Partial provider response".into(),
        },
    )))?;
    session.apply(WorkCommand::ApplyRuntimeEvent(RuntimeEventEnvelope::new(
        "process-recovery-run",
        2,
        RuntimeEvent::FileDiff {
            path: "partial.txt".into(),
            diff: "+partial workspace change".into(),
            added: 1,
            removed: 0,
            truncated: false,
        },
    )))?;
    store.save(&session)?;
    std::process::abort();
}

fn recovery_resume(root: &str, retry: bool) -> Result<WorkSessionSnapshot, Box<dyn Error>> {
    let store = WorkSessionStore::new(root);
    let mut session = store.load_active_or_create()?;
    if retry {
        session.apply(WorkCommand::RetryTask)?;
        store.save(&session)?;
    }
    Ok(session)
}

async fn run_real(task: String) -> Result<WorkSessionSnapshot, Box<dyn Error>> {
    let workspace = std::env::current_dir()?.display().to_string();
    let microclaw = MicroClaw::builder_from_environment()
        .caller_channel("work-headless")
        .workspace(&workspace)
        .max_concurrent_runs(1)
        .build()
        .await?;
    let epoch_millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis();
    let run_id = format!("work-{}-{epoch_millis}", std::process::id());
    let mut session = WorkSessionSnapshot::new(workspace);
    session.apply(WorkCommand::StartTask { task: task.clone() })?;

    let agent = microclaw.agent("MicroClaw Work Headless").build()?;
    let mut request = RunRequest::new(task);
    request.run_id = Some(RunId::new(run_id));
    request.session_id = Some(SessionId::new("work-default"));
    let mut run = agent.run_request(request);
    while let Some(event) = run.next_event().await {
        session.apply(WorkCommand::ApplyRuntimeEvent(event))?;
    }
    let result = run.result().await?;
    if session.status != microclaw_work_app::session::WorkStatus::Completed {
        return Err(format!(
            "runtime completed without a final Work event: {}",
            result.run_id
        )
        .into());
    }
    Ok(session)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let mode = args.next().unwrap_or_else(|| "demo".into());
    let task = args
        .next()
        .unwrap_or_else(|| "验证共享 Runtime Event".into());
    let events = match mode.as_str() {
        "demo" => demo_events(),
        "replay" => io::stdin()
            .lock()
            .lines()
            .map(|line| Ok(serde_json::from_str(&line?)?))
            .collect::<Result<Vec<RuntimeEventEnvelope>, Box<dyn Error>>>()?,
        "real" => {
            let session = run_real(task).await?;
            println!("{}", serde_json::to_string_pretty(&session)?);
            return Ok(());
        }
        "recovery-crash" => return recovery_crash(&task),
        "recovery-resume" | "recovery-retry" => {
            let session = recovery_resume(&task, mode == "recovery-retry")?;
            println!("{}", serde_json::to_string_pretty(&session)?);
            return Ok(());
        }
        _ => {
            return Err(format!(
                "unknown mode {mode:?}; expected demo, replay, real, recovery-crash, recovery-resume, or recovery-retry"
            )
            .into());
        }
    };

    let session = project_events(&task, events)?;
    println!("{}", serde_json::to_string_pretty(&session)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use microclaw_work_app::session::WorkStatus;

    #[test]
    fn demo_reaches_completed_without_a_ui() {
        let session = project_events("headless task", demo_events()).unwrap();

        assert_eq!(session.status, WorkStatus::Completed);
        assert_eq!(session.runtime_run_id.as_deref(), Some("headless-demo"));
        assert_eq!(session.last_runtime_sequence, 4);
        assert!(session.plan.is_empty());
    }
}
