use microclaw_work_app::session::{WorkSessionSnapshot, WorkStatus};
use std::process::Command;

fn run(mode: &str, root: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_microclaw-work-headless"))
        .arg(mode)
        .arg(root)
        .output()
        .unwrap()
}

fn snapshot(output: std::process::Output) -> WorkSessionSnapshot {
    assert!(
        output.status.success(),
        "harness failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn crash_resume_and_retry_cross_real_process_boundaries() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("work-sessions");

    let crashed = run("recovery-crash", &root);
    assert!(!crashed.status.success());

    let interrupted = snapshot(run("recovery-resume", &root));
    assert_eq!(interrupted.status, WorkStatus::Interrupted);
    assert_eq!(interrupted.task, "Recover this durable Work thread");
    assert_eq!(interrupted.messages.len(), 1);
    assert_eq!(interrupted.assistant_draft, "Partial provider response");
    assert_eq!(interrupted.file_changes.len(), 1);
    let session_id = interrupted.session_id.clone();

    let retried = snapshot(run("recovery-retry", &root));
    assert_eq!(retried.session_id, session_id);
    assert_eq!(retried.status, WorkStatus::Running);
    assert_eq!(retried.task, "Recover this durable Work thread");
    assert_eq!(retried.messages, interrupted.messages);
    assert!(retried.assistant_draft.is_empty());
    assert!(retried.file_changes.is_empty());
    assert!(retried.plan.is_empty());
    assert!(retried.pending_approval.is_none());
    assert!(retried.events.last().unwrap().message.contains("Retrying"));
}
