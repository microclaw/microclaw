//! Headless proof that Work state is driven by shared runtime events, not GPUI.

use microclaw::config::Config;
use microclaw::headless::{HeadlessRunRequest, HeadlessRuntime};
use microclaw_core::runtime_event::{RuntimeEvent, RuntimeEventEnvelope};
use microclaw_work_app::session::{WorkCommand, WorkSessionSnapshot};
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
                name: "read_file".into(),
                input: serde_json::json!({"path": "Cargo.toml"}),
            },
        ),
        RuntimeEventEnvelope::new(
            run_id,
            3,
            RuntimeEvent::ToolResult {
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

async fn run_real(task: String) -> Result<WorkSessionSnapshot, Box<dyn Error>> {
    let workspace = std::env::current_dir()?.display().to_string();
    let mut config = Config::load()?;
    config.working_dir = workspace.clone();
    let runtime = HeadlessRuntime::load(config).await?;
    let epoch_millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis();
    let run_id = format!("work-{}-{epoch_millis}", std::process::id());
    let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut session = WorkSessionSnapshot::new(workspace);
    session.apply(WorkCommand::StartTask { task: task.clone() })?;

    let run = runtime.run(
        HeadlessRunRequest::work(task, Some("work-default".into()), run_id),
        Some(event_tx),
    );
    tokio::pin!(run);
    let mut result = None;
    loop {
        tokio::select! {
            event = event_rx.recv() => match event {
                Some(event) => { session.apply(WorkCommand::ApplyRuntimeEvent(event))?; }
                None => break,
            },
            completed = &mut run, if result.is_none() => {
                result = Some(completed?);
            }
        }
    }
    let result = match result {
        Some(result) => result,
        None => run.await?,
    };
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
        _ => return Err(format!("unknown mode {mode:?}; expected demo, replay, or real").into()),
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
        assert!(session.plan.iter().all(|step| step.completed));
    }
}
