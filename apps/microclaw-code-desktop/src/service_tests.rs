//! The service end to end against a local mock OpenAI-compatible provider:
//! the engine is built by `code-core::launch` from a settings profile, as in
//! the app, and turns go through `CodeSession::turn`.
//!
//! One test drives every flow in order because `MCCODE_HOME` is process-wide.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use microclaw_code_core::driver::{ALLOW_RULE_OPTION, HistoryEntry, Update};
use microclaw_code_core::session_lock::{LockError, LockState, SessionLock, inspect};
use microclaw_sdk::RuntimeApprovalDecision;
use tokio::sync::mpsc::UnboundedReceiver;

use crate::service::{self, Command, Event, ProjectHandle};
use crate::state::{ApprovalState, Item, ToolState, Transcript};

const MODEL: &str = "mock-model";

fn sse(chunks: &[serde_json::Value]) -> String {
    let mut body = String::new();
    for chunk in chunks {
        body.push_str(&format!("data: {chunk}\n\n"));
    }
    body.push_str("data: [DONE]\n\n");
    format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n{body}")
}

fn text_reply(text: &str) -> String {
    sse(&[
        serde_json::json!({"choices": [{"index": 0, "delta": {"role": "assistant", "content": text}, "finish_reason": null}]}),
        serde_json::json!({"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12}}),
    ])
}

fn bash_call(command: &str) -> String {
    let arguments = serde_json::json!({ "command": command }).to_string();
    sse(&[
        serde_json::json!({"choices": [{"index": 0, "delta": {"role": "assistant", "tool_calls": [
            {"index": 0, "id": "call_1", "type": "function",
             "function": {"name": "bash", "arguments": arguments}}]}, "finish_reason": null}]}),
        serde_json::json!({"choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}}),
    ])
}

fn message_text(message: &serde_json::Value) -> String {
    match &message["content"] {
        serde_json::Value::String(text) => text.clone(),
        serde_json::Value::Array(parts) => parts
            .iter()
            .filter_map(|p| p["text"].as_str())
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

/// The scripted model: a tool result gets "ran it"; a prompt with RUN gets
/// a `bash` call; SLOW answers late (to be stopped); anything else "pong".
fn answer(mut stream: TcpStream) {
    let mut data = Vec::new();
    let mut buf = [0u8; 16 * 1024];
    let body = loop {
        let n = stream.read(&mut buf).unwrap_or(0);
        if n == 0 {
            return;
        }
        data.extend_from_slice(&buf[..n]);
        let text = String::from_utf8_lossy(&data).to_string();
        let Some(end) = text.find("\r\n\r\n") else {
            continue;
        };
        let length = text[..end]
            .lines()
            .find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.eq_ignore_ascii_case("content-length")
                    .then(|| v.trim().parse::<usize>().ok())?
            })
            .unwrap_or(0);
        if data.len() >= end + 4 + length {
            break data[end + 4..end + 4 + length].to_vec();
        }
    };
    let request: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
    let messages = request["messages"].as_array().cloned().unwrap_or_default();
    // The latest prompt of the test (the engine may add its own notes).
    let asked = messages.iter().rposition(|m| {
        m["role"] == "user"
            && ["say pong", "RUN", "SLOW"]
                .iter()
                .any(|k| message_text(m).contains(k))
    });
    let prompt = asked
        .map(|i| message_text(&messages[i]))
        .unwrap_or_default();
    let tool_result_since =
        asked.is_some_and(|i| messages[i..].iter().any(|m| m["role"] == "tool"));
    let reply = if tool_result_since {
        text_reply("ran it")
    } else {
        if prompt.contains("RUN") {
            bash_call("echo approved-run")
        } else if prompt.contains("SLOW") {
            std::thread::sleep(Duration::from_secs(20));
            text_reply("too late")
        } else {
            text_reply("pong")
        }
    };
    let _ = stream.write_all(reply.as_bytes());
    let _ = stream.flush();
}

fn mock_provider() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || answer(stream));
        }
    });
    format!("http://{address}/v1")
}

fn write_settings(home: &Path, base_url: &str) {
    std::fs::create_dir_all(home).unwrap();
    std::fs::write(
        home.join("settings.yaml"),
        format!(
            "version: 1\nmodel:\n  default: mock/{MODEL}\n  profiles:\n    mock:\n      type: openai\n      api_key: test-key\n      base_url: {base_url}\n      model: {MODEL}\n"
        ),
    )
    .unwrap();
}

/// Feed events to `transcript` until `stop` matches; panics after 60s.
async fn until(
    events: &mut UnboundedReceiver<Event>,
    transcript: &mut Transcript,
    what: &str,
    stop: impl Fn(&Event) -> bool,
) -> Event {
    let wait = async {
        while let Some(event) = events.recv().await {
            match &event {
                Event::TurnStarted(prompt) => transcript.begin_turn(prompt),
                Event::Update(update) => transcript.apply(update),
                Event::TurnFinished { receipt, .. } => transcript.finish_turn(receipt.clone()),
                Event::Failed(message) => {
                    panic!("service failed while waiting for {what}: {message}")
                }
                _ => {}
            }
            if stop(&event) {
                return event;
            }
        }
        panic!("service stopped while waiting for {what}");
    };
    tokio::time::timeout(Duration::from_secs(60), wait)
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
}

async fn open(
    root: PathBuf,
    session: Option<String>,
) -> (ProjectHandle, String, Vec<HistoryEntry>) {
    let mut handle = service::spawn(&tokio::runtime::Handle::current(), root, session);
    let mut transcript = Transcript::default();
    let ready = until(&mut handle.events, &mut transcript, "ready", |e| {
        matches!(e, Event::Ready { .. } | Event::NeedsSetup(_))
    })
    .await;
    match ready {
        Event::Ready { model, .. } => assert!(model.contains(MODEL), "model {model}"),
        other => panic!("expected Ready, got {other:?}"),
    }
    match until(&mut handle.events, &mut transcript, "session", |e| {
        matches!(e, Event::SessionOpened { .. })
    })
    .await
    {
        Event::SessionOpened { id, history } => (handle, id, history),
        _ => unreachable!(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn conversation_approval_stop_and_handoff_against_a_mock_provider() {
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(project.path()).unwrap();
    write_settings(home.path(), &mock_provider());
    // SAFETY: no other test in this binary reads or writes the environment.
    unsafe { std::env::set_var(microclaw_code_core::home::HOME_ENV, home.path()) };

    // 1. A plain turn streams the reply.
    let (mut app, id, history) = open(root.clone(), None).await;
    assert!(history.is_empty());
    assert!(matches!(inspect(home.path(), &id), LockState::Held(h) if h.front_end == "desktop"));
    let mut t = Transcript::default();
    app.commands.send(Command::Send("say pong".into())).unwrap();
    let finished = until(&mut app.events, &mut t, "first turn", |e| {
        matches!(e, Event::TurnFinished { .. })
    })
    .await;
    assert!(
        matches!(finished, Event::TurnFinished { ok: true, .. }),
        "{finished:?}"
    );
    assert!(
        t.items.contains(&Item::Agent("pong".into())),
        "{:?}",
        t.items
    );

    // 2. A shell command waits for an in-run approval, then runs.
    app.commands
        .send(Command::Send("RUN something".into()))
        .unwrap();
    let approval = match until(&mut app.events, &mut t, "approval", |e| {
        matches!(e, Event::Update(Update::ApprovalRequested(_)))
    })
    .await
    {
        Event::Update(Update::ApprovalRequested(approval)) => approval,
        _ => unreachable!(),
    };
    assert_eq!(approval.tool, "bash");
    assert!(
        approval
            .preview
            .as_deref()
            .unwrap_or("")
            .contains("echo approved-run")
    );
    let once = approval
        .options
        .iter()
        .find(|o| o.decision == RuntimeApprovalDecision::Approve && o.value != ALLOW_RULE_OPTION)
        .expect("an approve option")
        .value
        .clone();
    app.commands.send(Command::Approve(once)).unwrap();
    let finished = until(&mut app.events, &mut t, "approved turn", |e| {
        matches!(e, Event::TurnFinished { .. })
    })
    .await;
    assert!(
        matches!(finished, Event::TurnFinished { ok: true, .. }),
        "{finished:?}"
    );
    assert!(
        t.items.iter().any(|i| matches!(
            i,
            Item::Approval {
                state: ApprovalState::Answered { denied: false, .. },
                ..
            }
        )),
        "{:?}",
        t.items
    );
    let ran = t.items.iter().any(|i| match i {
        Item::Tool(call) => {
            call.name == "bash"
                && matches!(call.state, ToolState::Done { .. })
                && call.output.iter().any(|l| l.contains("approved-run"))
        }
        _ => false,
    });
    assert!(ran, "the approved command ran: {:?}", t.items);
    assert!(
        t.items.contains(&Item::Agent("ran it".into())),
        "{:#?}",
        t.items
    );

    // 3. Stop ends a turn whose model has not answered.
    app.commands
        .send(Command::Send("SLOW please".into()))
        .unwrap();
    until(&mut app.events, &mut t, "slow turn start", |e| {
        matches!(e, Event::TurnStarted(_))
    })
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    app.commands.send(Command::Cancel).unwrap();
    match until(&mut app.events, &mut t, "stopped turn", |e| {
        matches!(e, Event::TurnFinished { .. })
    })
    .await
    {
        Event::TurnFinished { receipt, ok } => {
            assert!(!ok, "a stopped turn is not ok");
            assert!(
                receipt.as_deref().unwrap_or("").contains("stopped"),
                "{receipt:?}"
            )
        }
        _ => unreachable!(),
    }
    assert!(!t.items.contains(&Item::Agent("too late".into())));

    // 4. Closing the window releases the session.
    let ProjectHandle {
        commands, stopped, ..
    } = app;
    drop(commands);
    tokio::time::timeout(Duration::from_secs(30), stopped)
        .await
        .expect("service stops")
        .unwrap();
    assert_eq!(inspect(home.path(), &id), LockState::Free);

    // 5. Another front end continues it (as `mccode --session <id>` does):
    //    same index, same engine store, the history comes along.
    let (mut other, same_id, history) = open(root.clone(), Some(id.clone())).await;
    assert_eq!(same_id, id);
    assert!(
        history
            .iter()
            .any(|h| matches!(h, HistoryEntry::User(u) if u.contains("say pong"))),
        "{history:?}"
    );
    assert!(
        history.contains(&HistoryEntry::Agent("pong".into())),
        "{history:?}"
    );
    let index = microclaw_code_core::sessions::SessionIndex::load(
        microclaw_code_core::sessions::SessionIndex::default_path(),
    );
    assert_eq!(index.get(&id).map(|r| r.turns), Some(3));
    assert_eq!(index.get(&id).map(|r| r.title.as_str()), Some("say pong"));

    // 6. While it is open there, the TUI is refused; taking over stops this
    //    one from driving it until the TUI lets go.
    match SessionLock::acquire(home.path(), &id, "tui", false) {
        Err(LockError::Held(holder)) => assert_eq!(holder.front_end, "desktop"),
        other => panic!("expected the session to be held, got {other:?}"),
    }
    let tui = SessionLock::acquire(home.path(), &id, "tui", true).unwrap();
    let mut t2 = Transcript::default();
    other
        .commands
        .send(Command::Send("say pong".into()))
        .unwrap();
    match until(&mut other.events, &mut t2, "locked", |e| {
        matches!(e, Event::SessionLocked { .. } | Event::TurnStarted(_))
    })
    .await
    {
        Event::SessionLocked { holder } => assert!(holder.contains("mccode"), "{holder}"),
        other => panic!("expected SessionLocked, got {other:?}"),
    }
    drop(tui);
    other
        .commands
        .send(Command::Send("say pong".into()))
        .unwrap();
    until(&mut other.events, &mut t2, "turn after the TUI left", |e| {
        matches!(e, Event::TurnFinished { .. })
    })
    .await;
    assert!(
        t2.items.contains(&Item::Agent("pong".into())),
        "{:?}",
        t2.items
    );
}
