use microclaw_sdk::{RunRequest, RuntimeEvent, RuntimeEventEnvelope, WORKER_PROTOCOL_VERSION};

fn main() {
    let request = RunRequest::new("index this repository");
    let event = RuntimeEventEnvelope::new(
        "run-1",
        0,
        RuntimeEvent::FinalResponse {
            text: "done".into(),
        },
    );

    assert_eq!(request.prompt, "index this repository");
    assert_eq!(event.sequence, 0);
    println!("worker protocol v{WORKER_PROTOCOL_VERSION}");
}
