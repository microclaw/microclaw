//! One conversation row per [`Item`].

use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::text::TextView;
use gpui_kit::component::{ActiveTheme as _, Sizable as _, h_flex, v_flex};
use gpui_kit::prelude::*;
use gpui_kit::*;
use microclaw_sdk::{RuntimeApprovalDecision, RuntimeApprovalOptionKind};
use tokio::sync::mpsc::UnboundedSender;

use crate::service::Command;
use crate::state::{ApprovalState, Item, Tone, ToolCall, ToolState};

/// Diff lines shown inline (the rest is summarized).
const DIFF_LINES: usize = 40;

fn mono() -> SharedString {
    "Menlo".into()
}

fn tool_row(call: &ToolCall, cx: &App) -> AnyElement {
    let theme = cx.theme();
    let (mark, color, detail) = match &call.state {
        ToolState::Running => ("…", theme.muted_foreground, String::new()),
        ToolState::WaitingForApproval => ("?", theme.warning, "waiting for approval".into()),
        ToolState::Done { duration_ms } => (
            "✓",
            theme.success,
            if *duration_ms >= 1000 {
                format!("{:.1}s", *duration_ms as f64 / 1000.0)
            } else {
                String::new()
            },
        ),
        ToolState::Failed(message) => ("✗", theme.danger, message.clone()),
    };
    v_flex()
        .gap_1()
        .child(
            h_flex()
                .gap_2()
                .text_sm()
                .child(div().text_color(color).child(mark))
                .child(
                    div()
                        .font_weight(FontWeight::SEMIBOLD)
                        .child(call.name.clone()),
                )
                .child(
                    div()
                        .font_family(mono())
                        .text_color(theme.muted_foreground)
                        .overflow_hidden()
                        .text_ellipsis()
                        .child(call.summary.clone()),
                )
                .when(!detail.is_empty(), |row| {
                    row.child(
                        div()
                            .text_xs()
                            .text_color(theme.muted_foreground)
                            .child(detail),
                    )
                }),
        )
        .when(!call.output.is_empty(), |this| {
            this.child(
                div()
                    .ml_5()
                    .p_2()
                    .rounded_md()
                    .bg(theme.muted)
                    .font_family(mono())
                    .text_xs()
                    .text_color(theme.muted_foreground)
                    .child(call.output.join("\n")),
            )
        })
        .into_any_element()
}

fn diff_row(path: &str, added: usize, removed: usize, diff: &str, cx: &App) -> AnyElement {
    let theme = cx.theme();
    let lines: Vec<&str> = diff.lines().collect();
    let hidden = lines.len().saturating_sub(DIFF_LINES);
    let body = v_flex()
        .p_2()
        .rounded_md()
        .bg(theme.muted)
        .font_family(mono())
        .text_xs()
        .children(lines.iter().take(DIFF_LINES).map(|line| {
            let color = if line.starts_with('+') {
                theme.success
            } else if line.starts_with('-') {
                theme.danger
            } else if line.starts_with("@@") {
                theme.info
            } else {
                theme.muted_foreground
            };
            div().text_color(color).child(line.to_string())
        }))
        .when(hidden > 0, |this| {
            this.child(
                div()
                    .text_color(theme.muted_foreground)
                    .child(format!("… {hidden} more lines")),
            )
        });
    v_flex()
        .gap_1()
        .child(
            h_flex()
                .gap_2()
                .text_sm()
                .child(div().font_weight(FontWeight::SEMIBOLD).child("Edited"))
                .child(div().font_family(mono()).child(path.to_string()))
                .child(div().text_color(theme.success).child(format!("+{added}")))
                .child(div().text_color(theme.danger).child(format!("-{removed}"))),
        )
        .child(body)
        .into_any_element()
}

fn approval_row(
    ix: usize,
    approval: &microclaw_code_core::driver::PendingApproval,
    state: &ApprovalState,
    commands: &UnboundedSender<Command>,
    cx: &App,
) -> AnyElement {
    let theme = cx.theme();
    let waiting = *state == ApprovalState::Waiting;
    let mut card = v_flex()
        .gap_2()
        .p_3()
        .rounded_lg()
        .border_1()
        .border_color(if waiting { theme.warning } else { theme.border })
        .bg(theme.background)
        .child(
            h_flex()
                .gap_2()
                .child(
                    div()
                        .font_weight(FontWeight::SEMIBOLD)
                        .child(format!("Allow {}?", approval.tool)),
                )
                .when(!waiting, |row| {
                    let ApprovalState::Answered { label, denied } = state else {
                        return row;
                    };
                    row.child(
                        div()
                            .text_sm()
                            .text_color(if *denied { theme.danger } else { theme.success })
                            .child(label.clone()),
                    )
                }),
        );
    if let Some(preview) = &approval.preview {
        card = card.child(
            div()
                .p_2()
                .rounded_md()
                .bg(theme.muted)
                .font_family(mono())
                .text_xs()
                .child(preview.chars().take(4000).collect::<String>()),
        );
    }
    if let Some(advisory) = &approval.advisory {
        card = card.child(
            div()
                .text_sm()
                .text_color(theme.muted_foreground)
                .child(format!("Reviewer: {advisory}")),
        );
    }
    if waiting {
        card = card.child(h_flex().gap_2().flex_wrap().children(
            approval.options.iter().enumerate().map(|(i, option)| {
                let commands = commands.clone();
                let value = option.value.clone();
                let button = Button::new(SharedString::from(format!("approve-{ix}-{i}")))
                    .small()
                    .label(option.label.clone())
                    .on_click(move |_, _, _| {
                        let _ = commands.send(Command::Approve(value.clone()));
                    });
                match (option.decision, option.kind) {
                    (RuntimeApprovalDecision::Deny, _) => button.danger(),
                    (_, RuntimeApprovalOptionKind::Primary) => button.primary(),
                    _ => button.outline(),
                }
            }),
        ));
    }
    card.into_any_element()
}

/// The row for item `ix`.
pub fn render_item(
    ix: usize,
    item: &Item,
    commands: &UnboundedSender<Command>,
    cx: &App,
) -> AnyElement {
    let theme = cx.theme();
    let row = match item {
        Item::User(text) => div()
            .p_3()
            .rounded_lg()
            .bg(theme.secondary)
            .child(text.clone())
            .into_any_element(),
        Item::Steer(text) => div()
            .pl_3()
            .border_l_2()
            .border_color(theme.info)
            .text_sm()
            .child(format!("Guidance: {text}"))
            .into_any_element(),
        Item::Agent(text) => TextView::markdown(("agent", ix), text.clone())
            .selectable(true)
            .into_any_element(),
        Item::Tool(call) => tool_row(call, cx),
        Item::Diff {
            path,
            added,
            removed,
            diff,
        } => diff_row(path, *added, *removed, diff, cx),
        Item::Approval { approval, state } => approval_row(ix, approval, state, commands, cx),
        Item::Check {
            name,
            passed,
            detail,
        } => {
            let (mark, color) = match passed {
                None => ("…", theme.muted_foreground),
                Some(true) => ("✓", theme.success),
                Some(false) => ("✗", theme.danger),
            };
            v_flex()
                .gap_1()
                .text_sm()
                .child(
                    h_flex()
                        .gap_2()
                        .child(div().text_color(color).child(mark))
                        .child(format!("check {name}")),
                )
                .child(
                    div()
                        .ml_5()
                        .font_family(mono())
                        .text_xs()
                        .text_color(theme.muted_foreground)
                        .child(detail.clone()),
                )
                .into_any_element()
        }
        Item::Notice(text, tone) => div()
            .text_sm()
            .text_color(match tone {
                Tone::Info => theme.muted_foreground,
                Tone::Warning => theme.warning,
                Tone::Error => theme.danger,
            })
            .child(text.clone())
            .into_any_element(),
        Item::Receipt(text) => div()
            .text_xs()
            .text_color(theme.muted_foreground)
            .border_t_1()
            .border_color(theme.border)
            .pt_1()
            .child(text.clone())
            .into_any_element(),
    };
    div().px_5().py_1p5().child(row).into_any_element()
}

#[cfg(test)]
mod tests {
    // No `gpui_kit::*` glob here: it re-exports GPUI's `test` macro, which
    // would shadow the plain `#[test]` the macro expands to.
    use super::render_item;
    use crate::service::Command;
    use crate::state::{ApprovalState, Item, Tone, ToolCall, ToolState};
    use gpui_kit::component::v_flex;
    use gpui_kit::prelude::*;
    use gpui_kit::{Context, Window};
    use microclaw_code_core::driver::PendingApproval;
    use microclaw_sdk::{
        RuntimeApprovalDecision, RuntimeApprovalOption, RuntimeApprovalOptionKind,
    };
    use tokio::sync::mpsc::{self, UnboundedSender};

    struct Rows {
        items: Vec<Item>,
        commands: UnboundedSender<Command>,
    }

    impl Render for Rows {
        fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
            v_flex().size_full().children(
                self.items
                    .iter()
                    .enumerate()
                    .map(|(ix, item)| render_item(ix, item, &self.commands, cx)),
            )
        }
    }

    fn approval() -> PendingApproval {
        PendingApproval::from_event(
            "a1",
            "bash",
            Some("cargo test"),
            &[
                RuntimeApprovalOption {
                    value: "1".into(),
                    label: "Approve once".into(),
                    kind: RuntimeApprovalOptionKind::Primary,
                    decision: RuntimeApprovalDecision::Approve,
                },
                RuntimeApprovalOption {
                    value: "3".into(),
                    label: "Deny".into(),
                    kind: RuntimeApprovalOptionKind::Secondary,
                    decision: RuntimeApprovalDecision::Deny,
                },
            ],
            Some("SAFE: runs tests"),
        )
    }

    /// GPUI's own test platform (gpui-kit 0.9.1's `test-support` feature does
    /// not resolve): every row type lays out and paints without panicking.
    #[::gpui::test]
    fn every_row_renders(cx: &mut ::gpui::TestAppContext) {
        cx.update(gpui_kit::init);
        let (tx, _rx) = mpsc::unbounded_channel();
        let items = vec![
            Item::User("fix the parser".into()),
            Item::Agent("Looking at **src/parser.rs**.\n\n```rust\nfn main() {}\n```".into()),
            Item::Tool(ToolCall {
                call_id: "c1".into(),
                name: "bash".into(),
                summary: "cargo test".into(),
                state: ToolState::Done { duration_ms: 1500 },
                output: vec!["test result: ok".into()],
            }),
            Item::Tool(ToolCall {
                call_id: "c2".into(),
                name: "bash".into(),
                summary: "rm -rf target".into(),
                state: ToolState::WaitingForApproval,
                output: Vec::new(),
            }),
            Item::Diff {
                path: "src/parser.rs".into(),
                added: 1,
                removed: 1,
                diff: "@@ -1 +1 @@\n-old\n+new".into(),
            },
            Item::Approval {
                approval: approval(),
                state: ApprovalState::Waiting,
            },
            Item::Approval {
                approval: approval(),
                state: ApprovalState::Answered {
                    label: "Deny".into(),
                    denied: true,
                },
            },
            Item::Check {
                name: "test".into(),
                passed: Some(false),
                detail: "failed (exit 101)".into(),
            },
            Item::Steer("also update the docs".into()),
            Item::Notice("stopped".into(), Tone::Warning),
            Item::Receipt("changed 1 file · checks failing".into()),
        ];
        let count = items.len();
        let (view, cx) = cx.add_window_view(|_, _| Rows {
            items,
            commands: tx,
        });
        cx.run_until_parked();
        view.update(cx, |rows, cx| {
            assert_eq!(rows.items.len(), count);
            cx.notify();
        });
        cx.run_until_parked();
    }
}
