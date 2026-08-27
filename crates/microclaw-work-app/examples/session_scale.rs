use microclaw_core::runtime_event::RuntimeProcessKind;
use microclaw_work_app::session::{
    ConversationMessage, ConversationRole, FileChange, ProcessActivity, ToolActivity,
    ToolActivityStatus, WorkEvent, WorkEventKind, WorkSessionSnapshot,
};
use serde_json::json;
use std::fs;
use std::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!(
        "microclaw-work-session-scale-{}.json",
        std::process::id()
    ));
    let mut snapshot = WorkSessionSnapshot::new("/tmp/microclaw-work-scale-workspace");
    snapshot.title = "Maximum supported Work session fixture".into();
    snapshot.task = "Measure durable Work session storage at product limits".into();

    snapshot.messages = (0..WorkSessionSnapshot::MAX_MESSAGES)
        .map(|index| ConversationMessage {
            id: index as u64 + 1,
            role: if index % 2 == 0 {
                ConversationRole::User
            } else {
                ConversationRole::Assistant
            },
            content: format!("message-{index}: {}", "m".repeat(4_000)),
            attachments: Vec::new(),
        })
        .collect();
    snapshot.events = (0..WorkSessionSnapshot::MAX_EVENTS)
        .map(|index| WorkEvent {
            id: index as u64 + 1,
            kind: WorkEventKind::Tool,
            message: format!("event-{index}: {}", "e".repeat(1_000)),
        })
        .collect();
    snapshot.tool_activities = (0..WorkSessionSnapshot::MAX_TOOL_ACTIVITIES)
        .map(|index| ToolActivity {
            call_id: format!("tool-{index}"),
            name: "scale_fixture".into(),
            input_preview: "input".repeat(40),
            status: ToolActivityStatus::Succeeded,
            result_preview: Some("result".repeat(40)),
            duration_ms: Some(10),
            status_code: Some(0),
            bytes: Some(1_024),
            error_type: None,
        })
        .collect();
    snapshot.process_activities = (0..WorkSessionSnapshot::MAX_PROCESS_ACTIVITIES)
        .map(|index| ProcessActivity {
            call_id: format!("process-{index}"),
            command: "cargo check".into(),
            output: "output\n".repeat(2_800),
            exit_code: Some(0),
            duration_ms: 100,
            truncated: true,
            kind: RuntimeProcessKind::Verification,
        })
        .collect();
    snapshot.file_changes = (0..WorkSessionSnapshot::MAX_FILE_CHANGES)
        .map(|index| FileChange {
            path: format!("generated/file-{index}.txt"),
            diff: format!(
                "+{}",
                "d".repeat(WorkSessionSnapshot::MAX_FILE_DIFF_BYTES - 1)
            ),
            added: 4_000,
            removed: 0,
            truncated: true,
        })
        .collect();
    snapshot.selected_file_change = snapshot
        .file_changes
        .last()
        .map(|change| change.path.clone());

    let save_started = Instant::now();
    snapshot.save(&path)?;
    let save_ms = save_started.elapsed().as_secs_f64() * 1_000.0;
    let file_bytes = fs::metadata(&path)?.len();

    let load_started = Instant::now();
    let restored = WorkSessionSnapshot::load(&path)?;
    let load_ms = load_started.elapsed().as_secs_f64() * 1_000.0;
    fs::remove_file(&path)?;

    assert_eq!(restored.messages.len(), WorkSessionSnapshot::MAX_MESSAGES);
    assert_eq!(
        restored.file_changes.len(),
        WorkSessionSnapshot::MAX_FILE_CHANGES
    );
    assert_eq!(
        restored.process_activities.len(),
        WorkSessionSnapshot::MAX_PROCESS_ACTIVITIES
    );

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema_version": restored.schema_version,
            "messages": restored.messages.len(),
            "events": restored.events.len(),
            "tool_activities": restored.tool_activities.len(),
            "process_activities": restored.process_activities.len(),
            "file_changes": restored.file_changes.len(),
            "session_file_bytes": file_bytes,
            "save_ms": save_ms,
            "load_ms": load_ms
        }))?
    );
    Ok(())
}
