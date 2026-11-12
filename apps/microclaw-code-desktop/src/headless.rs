//! `--smoke <dir> <prompt>`: drive one turn through [`crate::service`] with no
//! window and print what the window would show. Approvals are answered with
//! the first "approve once" option so scripted runs finish.

use std::path::PathBuf;
use std::process::ExitCode;

use microclaw_sdk::RuntimeApprovalDecision;

use crate::service::{self, Command, Event};
use crate::state::{Item, Transcript};

pub fn run(
    runtime: &tokio::runtime::Runtime,
    dir: PathBuf,
    prompt: String,
    session: Option<String>,
) -> ExitCode {
    let root = std::fs::canonicalize(&dir).unwrap_or(dir);
    runtime.block_on(async move {
        let mut handle = service::spawn(&tokio::runtime::Handle::current(), root, session);
        let mut transcript = Transcript::default();
        let mut sent = false;
        let mut shown = 0usize;
        let mut ok = true;
        while let Some(event) = handle.events.recv().await {
            match event {
                Event::Project(info) => eprintln!(
                    "project {} ({}){}",
                    info.name,
                    info.root.display(),
                    if info.trusted { "" } else { " — not trusted" }
                ),
                Event::NeedsSetup(message) => {
                    eprintln!("setup needed: {message}");
                    return ExitCode::from(2);
                }
                Event::Starting => eprintln!("starting the Agent Engine…"),
                Event::Ready {
                    model,
                    mode,
                    sandbox,
                    warnings,
                    ..
                } => {
                    eprintln!(
                        "ready: model {model} · {} mode · {}",
                        mode.as_str(),
                        sandbox.as_deref().unwrap_or("no sandbox")
                    );
                    for w in warnings {
                        eprintln!("warning: {w}");
                    }
                }
                Event::Failed(message) => {
                    eprintln!("failed: {message}");
                    return ExitCode::from(1);
                }
                Event::SessionOpened { id, history } => {
                    eprintln!("session {id} ({} earlier messages)", history.len());
                    if !sent {
                        sent = true;
                        let _ = handle.commands.send(Command::Send(prompt.clone()));
                    }
                }
                Event::SessionLocked { holder, .. } => {
                    eprintln!("session is open in {holder}");
                    return ExitCode::from(1);
                }
                Event::TurnStarted(prompt) => transcript.begin_turn(&prompt),
                Event::Update(update) => {
                    transcript.apply(&update);
                    if let Some(approval) = transcript.pending.clone() {
                        let value = approval
                            .options
                            .iter()
                            .find(|o| o.decision == RuntimeApprovalDecision::Approve)
                            .map(|o| o.value.clone());
                        eprintln!(
                            "approval: {} {}",
                            approval.tool,
                            approval.preview.as_deref().unwrap_or("")
                        );
                        if let Some(value) = value {
                            let _ = handle.commands.send(Command::Approve(value));
                        }
                        transcript.pending = None;
                    }
                }
                Event::TurnFinished { receipt } => {
                    transcript.finish_turn(receipt);
                    print_items(&transcript.items[shown..]);
                    break;
                }
                Event::Notice(text) => eprintln!("note: {text}"),
                Event::Error(text) => {
                    ok = false;
                    eprintln!("error: {text}");
                }
                Event::Sessions(_) | Event::ModeChanged(_) | Event::ModelChanged(_) => {}
            }
            // Print finished items as they settle (all but the streaming one).
            let settled = transcript.items.len().saturating_sub(1);
            if settled > shown {
                print_items(&transcript.items[shown..settled]);
                shown = settled;
            }
        }
        if ok {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        }
    })
}

fn print_items(items: &[Item]) {
    for item in items {
        match item {
            Item::User(text) => println!("> {text}"),
            Item::Steer(text) => println!(">> {text}"),
            Item::Agent(text) => println!("{text}"),
            Item::Tool(call) => println!("· {} {} [{:?}]", call.name, call.summary, call.state),
            Item::Diff {
                path,
                added,
                removed,
                ..
            } => println!("· edited {path} (+{added} -{removed})"),
            Item::Approval { approval, state } => {
                println!("· approval {} → {state:?}", approval.tool)
            }
            Item::Check {
                name,
                passed,
                detail,
            } => println!("· check {name}: {passed:?} {detail}"),
            Item::Notice(text, _) => println!("· {text}"),
            Item::Receipt(text) => println!("= {text}"),
        }
    }
}
