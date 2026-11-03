//! Headless proof that Desktop state is driven by shared runtime events, not GPUI.

use microclaw_desktop_app::session::{DesktopCommand, DesktopSessionSnapshot};
use microclaw_desktop_app::store::DesktopSessionStore;
use microclaw_desktop_runtime::{
    DesktopRunRequest, DesktopRuntimeMessage, RemoteRuntimeService, RemoteServerCredentials,
    credentials_path,
};
use microclaw_sdk::{MicroClaw, RunId, RunRequest, RuntimeEvent, RuntimeEventEnvelope, SessionId};
use std::error::Error;
use std::io::{self, BufRead};
use std::path::PathBuf;

fn project_events(
    task: &str,
    events: impl IntoIterator<Item = RuntimeEventEnvelope>,
) -> Result<DesktopSessionSnapshot, Box<dyn Error>> {
    let workspace = std::env::current_dir()?.display().to_string();
    let mut session = DesktopSessionSnapshot::new(workspace);
    session.apply(DesktopCommand::StartTask { task: task.into() })?;
    for event in events {
        session.apply(DesktopCommand::ApplyRuntimeEvent(event))?;
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
    let store = DesktopSessionStore::new(root);
    let mut session = store.create(std::env::current_dir()?.display().to_string())?;
    session.apply(DesktopCommand::StartTask {
        task: "Recover this durable Desktop thread".into(),
    })?;
    session.apply(DesktopCommand::ApplyRuntimeEvent(
        RuntimeEventEnvelope::new(
            "process-recovery-run",
            1,
            RuntimeEvent::TextDelta {
                delta: "Partial provider response".into(),
            },
        ),
    ))?;
    session.apply(DesktopCommand::ApplyRuntimeEvent(
        RuntimeEventEnvelope::new(
            "process-recovery-run",
            2,
            RuntimeEvent::FileDiff {
                path: "partial.txt".into(),
                diff: "+partial workspace change".into(),
                added: 1,
                removed: 0,
                truncated: false,
            },
        ),
    ))?;
    store.save(&session)?;
    std::process::abort();
}

fn recovery_resume(root: &str, retry: bool) -> Result<DesktopSessionSnapshot, Box<dyn Error>> {
    let store = DesktopSessionStore::new(root);
    let mut session = store.load_active_or_create()?;
    if retry {
        session.apply(DesktopCommand::RetryTask)?;
        store.save(&session)?;
    }
    Ok(session)
}

async fn run_real(task: String) -> Result<DesktopSessionSnapshot, Box<dyn Error>> {
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
    let mut session = DesktopSessionSnapshot::new(workspace);
    session.apply(DesktopCommand::StartTask { task: task.clone() })?;

    let agent = microclaw.agent("MicroClaw Desktop Headless").build()?;
    let mut request = RunRequest::new(task);
    request.run_id = Some(RunId::new(run_id));
    request.session_id = Some(SessionId::new("work-default"));
    let mut run = agent.run_request(request);
    while let Some(event) = run.next_event().await {
        session.apply(DesktopCommand::ApplyRuntimeEvent(event))?;
    }
    let result = run.result().await?;
    if session.status != microclaw_desktop_app::session::DesktopStatus::Completed {
        return Err(format!(
            "runtime completed without a final Desktop event: {}",
            result.run_id
        )
        .into());
    }
    Ok(session)
}

/// Desktop data root: `$MICROCLAW_DESKTOP_DATA_DIR`, else the platform-local data
/// directory, else the temporary directory (same rule as the desktop app).
fn desktop_data_root() -> PathBuf {
    resolve_desktop_data_root(
        std::env::var_os("MICROCLAW_DESKTOP_DATA_DIR"),
        dirs::data_local_dir(),
        std::env::temp_dir(),
    )
}

fn resolve_desktop_data_root(
    override_path: Option<std::ffi::OsString>,
    platform_data_dir: Option<PathBuf>,
    temporary_dir: PathBuf,
) -> PathBuf {
    override_path
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            platform_data_dir
                .unwrap_or(temporary_dir)
                .join("microclaw-desktop")
        })
}

/// Run `task` on the paired MicroClaw Server and project its events onto a
/// Desktop session, exactly as the desktop client does for the Server target.
fn run_server(
    task: String,
    desktop_data_root: &std::path::Path,
) -> Result<DesktopSessionSnapshot, Box<dyn Error + Send + Sync>> {
    let path = credentials_path(desktop_data_root);
    let Some(credentials) = RemoteServerCredentials::load(&path)? else {
        return Err(format!(
            "not paired: no Server credentials at {}; pair from MicroClaw Desktop settings first",
            path.display()
        )
        .into());
    };
    let service = RemoteRuntimeService::new(credentials)?;
    let workspace = std::env::current_dir()?.display().to_string();
    let mut session = DesktopSessionSnapshot::new(workspace.clone());
    session.apply(DesktopCommand::StartTask { task: task.clone() })?;
    let handle = service.start(DesktopRunRequest {
        task,
        workspace,
        session: "work-default".into(),
    })?;
    loop {
        match handle.messages.recv() {
            Ok(DesktopRuntimeMessage::Envelope(envelope)) => {
                session.apply(DesktopCommand::ApplyRuntimeEvent(envelope))?;
            }
            Ok(DesktopRuntimeMessage::SteeringResult { message, .. }) => {
                eprintln!("steering rejected: {message}");
            }
            Ok(DesktopRuntimeMessage::Completed { .. }) => return Ok(session),
            Ok(DesktopRuntimeMessage::Failed { run_id, message }) => {
                return Err(format!("server run {run_id} failed: {message}").into());
            }
            Err(_) => return Err("the remote runtime exited without completing the run".into()),
        }
    }
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
        "pair" => {
            // `pair <server_url> <code> [device_name]`: the task slot carries the URL.
            let server_url = task;
            let code = args
                .next()
                .ok_or("usage: pair <server_url> <code> [device_name]")?;
            let device_name = args.next().unwrap_or_else(|| {
                format!("microclaw-desktop-headless ({})", std::env::consts::OS)
            });
            let path = credentials_path(&desktop_data_root());
            let credentials = tokio::task::spawn_blocking(move || {
                microclaw_desktop_runtime::remote::pair_blocking(&server_url, &code, &device_name)
            })
            .await??;
            credentials.save(&path)?;
            println!(
                "{}",
                serde_json::json!({
                    "paired": true,
                    "server_url": credentials.server_url,
                    "device_id": credentials.device_id,
                    "label": credentials.label,
                    "server_version": credentials.server_version,
                    "credentials_path": path.display().to_string(),
                })
            );
            return Ok(());
        }
        "server" => {
            let session =
                tokio::task::spawn_blocking(move || run_server(task, &desktop_data_root()))
                    .await?
                    .map_err(|error| -> Box<dyn Error> { error })?;
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
                "unknown mode {mode:?}; expected demo, replay, real, pair, server, recovery-crash, recovery-resume, or recovery-retry"
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
    use microclaw_desktop_app::session::DesktopStatus;

    #[test]
    fn demo_reaches_completed_without_a_ui() {
        let session = project_events("headless task", demo_events()).unwrap();

        assert_eq!(session.status, DesktopStatus::Completed);
        assert_eq!(session.runtime_run_id.as_deref(), Some("headless-demo"));
        assert_eq!(session.last_runtime_sequence, 4);
        assert!(session.plan.is_empty());
    }

    #[test]
    fn work_data_root_prefers_the_override_then_platform_dir() {
        let temp = PathBuf::from("/tmp-fallback");
        assert_eq!(
            resolve_desktop_data_root(Some("/custom".into()), Some("/local".into()), temp.clone()),
            PathBuf::from("/custom")
        );
        assert_eq!(
            resolve_desktop_data_root(Some("".into()), Some("/local".into()), temp.clone()),
            PathBuf::from("/local/microclaw-desktop")
        );
        assert_eq!(
            resolve_desktop_data_root(None, None, temp),
            PathBuf::from("/tmp-fallback/microclaw-desktop")
        );
    }

    #[test]
    fn server_mode_reports_not_paired_without_credentials() {
        let directory = tempfile::tempdir().unwrap();
        let error = run_server("hello".into(), directory.path()).unwrap_err();
        assert!(error.to_string().starts_with("not paired"), "{error}");
    }
}
