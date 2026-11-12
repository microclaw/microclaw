//! Rendering tests and an HTML preview of the whole screen.
//!
//! `MCCODE_PREVIEW_DIR=/some/dir cargo test -p microclaw-code preview` also
//! writes `<theme>-<width>.html` files: the terminal buffer with its colours,
//! for looking at the design without a model.

use std::time::Instant;

use microclaw_code_core::driver::Update;
use microclaw_code_core::project::Mode;
use microclaw_code_core::sessions::SessionIndex;
use microclaw_code_core::settings::CodeSettings;
use microclaw_code_core::trust::TrustStore;
use microclaw_sdk::{RuntimeEvent, RuntimeEventEnvelope, RuntimePlanStep, RuntimePlanStepStatus};
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::style::{Color, Modifier};
use tokio::sync::mpsc;

use super::transcript::{Item, RenderOptions, Transcript};
use super::*;

fn ev(seq: u64, event: RuntimeEvent) -> Update {
    Update::Runtime(RuntimeEventEnvelope::new("demo", seq, event))
}

fn demo_transcript() -> Transcript {
    let mut t = Transcript::default();
    t.notice(
        "MicroClaw Code in ~/src/parser · ask mode · trusted",
        transcript::Tone::Info,
    );
    t.push(Item::User(
        "修一下 parser 里的空行 bug，并补测试".to_string(),
    ));
    t.begin_turn();
    let mut seq = 0;
    let mut send = |t: &mut Transcript, e: RuntimeEvent| {
        seq += 1;
        t.apply(&ev(seq, e));
    };
    send(
        &mut t,
        RuntimeEvent::TextDelta {
            delta: "先看一下解析入口和现有测试。".into(),
        },
    );
    for (i, (name, input)) in [
        ("read_file", serde_json::json!({"path": "src/parser.rs"})),
        ("grep", serde_json::json!({"pattern": "parse_block"})),
        ("read_file", serde_json::json!({"path": "tests/parse.rs"})),
    ]
    .into_iter()
    .enumerate()
    {
        let id = format!("r{i}");
        send(
            &mut t,
            RuntimeEvent::ToolStart {
                call_id: id.clone(),
                name: name.into(),
                input,
            },
        );
        send(
            &mut t,
            RuntimeEvent::ToolResult {
                call_id: id,
                name: name.into(),
                is_error: false,
                preview: "ok".into(),
                duration_ms: 40,
                status_code: None,
                bytes: 0,
                error_type: None,
            },
        );
    }
    send(
        &mut t,
        RuntimeEvent::PlanUpdated {
            steps: vec![
                RuntimePlanStep {
                    title: "定位空行处理".into(),
                    status: RuntimePlanStepStatus::Completed,
                },
                RuntimePlanStep {
                    title: "修改 parse_block".into(),
                    status: RuntimePlanStepStatus::InProgress,
                },
                RuntimePlanStep {
                    title: "补测试".into(),
                    status: RuntimePlanStepStatus::Pending,
                },
            ],
        },
    );
    send(
        &mut t,
        RuntimeEvent::FileDiff {
            path: "src/parser.rs".into(),
            diff: "--- a/src/parser.rs\n+++ b/src/parser.rs\n@@ -40,6 +40,7 @@ impl Parser {\n     /// Parse one block of input.\n     fn parse_block(input: &str) -> Block {\n-        let lines = input.lines();\n+        // Blank lines separate blocks; skip them here.\n+        let lines = input.lines().filter(|l| !l.trim().is_empty());\n         let mut block = Block::default();\n         for line in lines {\n             block.push(line);\n".into(),
            added: 2,
            removed: 1,
            truncated: false,
        },
    );
    send(
        &mut t,
        RuntimeEvent::ToolStart {
            call_id: "b1".into(),
            name: "bash".into(),
            input: serde_json::json!({"command": "cargo test parser"}),
        },
    );
    send(
        &mut t,
        RuntimeEvent::ToolResult {
            call_id: "b1".into(),
            name: "bash".into(),
            is_error: false,
            preview: "   Compiling parser v0.1.0\n    Finished test profile\n     Running unittests\nrunning 14 tests\ntest parse::blank_lines ... ok\ntest result: ok. 14 passed; 0 failed".into(),
            duration_ms: 2300,
            status_code: Some(0),
            bytes: 0,
            error_type: None,
        },
    );
    send(
        &mut t,
        RuntimeEvent::TextDelta {
            delta: "\n\n修好了。`parse_block` 现在会**跳过空行**：\n\n- 改动在 `src/parser.rs`\n- 新增测试 `blank_lines`\n\n```rust\nlet lines = input.lines().filter(|l| !l.trim().is_empty());\n```\n\n| 检查 | 结果 |\n|---|---|\n| cargo test | 14 passed |\n".into(),
        },
    );
    t.apply(&Update::CheckStarted(microclaw_code_core::project::Check {
        name: "test".into(),
        run: "cargo test".into(),
        auto: true,
        timeout_secs: None,
    }));
    t.apply(&Update::CheckFinished(
        microclaw_code_core::verify::CheckOutcome {
            check: microclaw_code_core::project::Check {
                name: "test".into(),
                run: "cargo test".into(),
                auto: true,
                timeout_secs: None,
            },
            success: true,
            exit_code: Some(0),
            timed_out: false,
            duration: std::time::Duration::from_millis(4100),
            output: String::new(),
        },
    ));
    if let Some(mut receipt) = t.take_receipt() {
        receipt.tokens_in = 18_400;
        receipt.tokens_out = 1_220;
        receipt.cost = Some(0.06);
        receipt.sandbox = Some("seatbelt".into());
        receipt.checkpoint = Some("c7a91f2".into());
        receipt.status = "done".into();
        t.push(Item::Receipt(receipt));
    }
    t
}

fn demo_app(theme: &str) -> App {
    let (updates_tx, updates_rx) = mpsc::unbounded_channel();
    let (ui_tx, ui_rx) = mpsc::unbounded_channel();
    let dir = std::env::temp_dir();
    let (theme, _) = crate::ui::theme::resolve(theme, None, Some(true));
    App {
        session: None,
        session_lock: None,
        jobs: None,
        running: None,
        updates_tx,
        updates_rx,
        ui_tx,
        ui_rx,
        gate_rx: None,
        transcript: demo_transcript(),
        input: InputBox::default(),
        dialog: None,
        popup: None,
        mode: Mode::Ask,
        trusted: true,
        project_name: "parser".into(),
        branch: Some("main".into()),
        session_label: "code-1".into(),
        model: "deepseek-v4-pro".into(),
        scroll: 0,
        hint: None,
        pending_editor: None,
        last_request_end: None,
        idle_plan: None,
        context_pct: Some(34),
        session_tokens: (18_400, 1_220),
        session_cost: Some(0.06),
        queue: vec!["顺便看看 lexer 有没有同样的问题".into()],
        shell_mode: false,
        shell_running: false,
        shell_context: Vec::new(),
        goal: None,
        goal_until: Default::default(),
        settings: CodeSettings::default(),
        theme,
        keymap: keymap::Keymap::default(),
        render: RenderOptions::default(),
        show_sidebar: true,
        inline: false,
        flushed: 0,
        focused: true,
        last_input: Instant::now(),
        last_esc: None,
        notifier: notify::Notifier {
            method: notify::Method::Off,
            always: false,
        },
        remote: None,
        pending_usage: None,
        line_owners: Vec::new(),
        transcript_area: ratatui::layout::Rect::default(),
        quit_armed: None,
        should_quit: false,
        files: Some(vec!["src/parser.rs".into(), "src/lexer.rs".into()]),
        index: SessionIndex::load(dir.join("mccode-preview-index.json")),
        trust_store: TrustStore::load(dir.join("mccode-preview-trust.json")),
        checks_task: None,
        user_settings_path: dir.join("mccode-preview-settings.yaml"),
        themes_dir: dir.join("mccode-preview-themes"),
        last_title: String::new(),
        side_asker: None,
        on_settings_reload: None,
    }
}

fn render(app: &mut App, width: u16, height: u16) -> Buffer {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|frame| view::draw(frame, app)).unwrap();
    terminal.backend().buffer().clone()
}

fn text(buffer: &Buffer) -> String {
    let area = buffer.area;
    let mut out = String::new();
    for y in 0..area.height {
        let mut x = 0;
        while x < area.width {
            let symbol = buffer[(x, y)].symbol();
            out.push_str(symbol);
            x += unicode_width::UnicodeWidthStr::width(symbol).max(1) as u16;
        }
        out.push('\n');
    }
    out
}

fn css(color: Color, fallback: &str) -> String {
    match color {
        Color::Rgb(r, g, b) => format!("#{r:02x}{g:02x}{b:02x}"),
        Color::Reset => fallback.to_string(),
        Color::Black => "#000000".into(),
        Color::Red => "#cd3131".into(),
        Color::Green => "#0dbc79".into(),
        Color::Yellow => "#e5e510".into(),
        Color::Blue => "#2472c8".into(),
        Color::Magenta => "#bc3fbc".into(),
        Color::Cyan => "#11a8cd".into(),
        Color::Gray => "#cccccc".into(),
        Color::DarkGray => "#666666".into(),
        Color::LightRed => "#f14c4c".into(),
        Color::LightGreen => "#23d18b".into(),
        Color::LightYellow => "#f5f543".into(),
        Color::LightBlue => "#3b8eea".into(),
        Color::LightMagenta => "#d670d6".into(),
        Color::LightCyan => "#29b8db".into(),
        Color::White => "#e5e5e5".into(),
        Color::Indexed(i) => format!("var(--i{i}, #888)"),
    }
}

/// The buffer as an HTML page (monospace grid with colours).
fn html(buffer: &Buffer, title: &str, dark: bool) -> String {
    let (bg, fg) = if dark {
        ("#16161e", "#c0caf5")
    } else {
        ("#fafafa", "#24292f")
    };
    let mut body = String::new();
    let area = buffer.area;
    for y in 0..area.height {
        let mut x = 0;
        while x < area.width {
            let cell = &buffer[(x, y)];
            let mut style = format!(
                "color:{};background:{};",
                css(cell.fg, fg),
                css(cell.bg, "transparent")
            );
            if cell.modifier.contains(Modifier::BOLD) {
                style.push_str("font-weight:700;");
            }
            if cell.modifier.contains(Modifier::ITALIC) {
                style.push_str("font-style:italic;");
            }
            if cell.modifier.contains(Modifier::DIM) {
                style.push_str("opacity:.6;");
            }
            if cell.modifier.contains(Modifier::CROSSED_OUT) {
                style.push_str("text-decoration:line-through;");
            }
            let symbol = cell.symbol();
            let escaped = symbol
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;");
            let w = unicode_width::UnicodeWidthStr::width(symbol).max(1) as u16;
            body.push_str(&format!(
                "<span style=\"{style}display:inline-block;width:{}ch\">{}</span>",
                w,
                if escaped.trim().is_empty() {
                    "&nbsp;".to_string()
                } else {
                    escaped
                }
            ));
            x += w;
        }
        body.push('\n');
    }
    format!(
        "<!doctype html><meta charset=utf-8><title>{title}</title><style>body{{margin:0;background:{bg};color:{fg}}}pre{{font:14px/1.35 'JetBrains Mono','SF Mono',Menlo,monospace;margin:16px;white-space:pre}}</style><pre>{body}</pre>"
    )
}

#[test]
fn full_screen_renders_every_region() {
    let mut app = demo_app("dark");
    let buffer = render(&mut app, 150, 48);
    let screen = text(&buffer);
    for expected in [
        "◆ parser",
        "deepseek-v4-pro",
        "Explored 2 files · 1 search",
        "src/parser.rs  +2 −1",
        "Bash  cargo test parser",
        "PLAN",
        "CHECKS",
        "CHANGES",
        "test ✓",
        "checkpoint c7a91f2",
        "ctx",
        "1 顺便看看 lexer",
        "╭",
    ] {
        assert!(
            screen.contains(expected),
            "missing {expected:?} in\n{screen}"
        );
    }
}

#[test]
fn narrow_screen_drops_the_sidebar() {
    let mut app = demo_app("light");
    let screen = text(&render(&mut app, 80, 40));
    assert!(!screen.contains("CHECKS"), "{screen}");
    assert!(screen.contains("Bash  cargo test parser"));
}

#[test]
fn approval_dialog_and_popup_render() {
    let mut app = demo_app("tokyonight");
    app.dialog = Some(Dialog::Approval(ApprovalDialog::new(
        microclaw_code_core::driver::PendingApproval {
            approval_id: "a1".into(),
            tool: "bash".into(),
            preview: Some("git push origin main".into()),
            options: vec![
                microclaw_sdk::RuntimeApprovalOption {
                    value: "1".into(),
                    label: "Yes, once".into(),
                    kind: microclaw_sdk::RuntimeApprovalOptionKind::Primary,
                    decision: microclaw_sdk::RuntimeApprovalDecision::Approve,
                },
                microclaw_sdk::RuntimeApprovalOption {
                    value: "3".into(),
                    label: "No".into(),
                    kind: microclaw_sdk::RuntimeApprovalOptionKind::Danger,
                    decision: microclaw_sdk::RuntimeApprovalDecision::Deny,
                },
            ],
            advisory: Some("CAUTION: pushes to the remote".into()),
            suggested_rule: None,
        },
    )));
    let screen = text(&render(&mut app, 120, 40));
    assert!(screen.contains("Approval needed"), "{screen}");
    assert!(screen.contains("git push origin main"));
    assert!(screen.contains("tell the agent what to do instead"));

    let mut app = demo_app("dark");
    app.input.insert_str("/th");
    app.refresh_popup();
    let screen = text(&render(&mut app, 120, 40));
    assert!(screen.contains("/theme"), "{screen}");
}

#[test]
fn writes_html_previews_when_asked() {
    let Some(dir) = std::env::var_os("MCCODE_PREVIEW_DIR") else {
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    std::fs::create_dir_all(&dir).unwrap();
    for (theme, dark) in [
        ("dark", true),
        ("light", false),
        ("tokyonight", true),
        ("catppuccin", true),
        ("github-light", false),
        ("ansi", true),
    ] {
        let mut app = demo_app(theme);
        if !dark {
            let (t, _) = crate::ui::theme::resolve(theme, None, Some(false));
            app.theme = t;
        }
        let buffer = render(&mut app, 150, 46);
        std::fs::write(
            dir.join(format!("{theme}-150.html")),
            html(&buffer, theme, dark),
        )
        .unwrap();
    }
    let mut app = demo_app("dark");
    app.dialog = Some(Dialog::Review(super::review::ReviewState::new(
        std::env::temp_dir(),
        super::review::parse_diff(
            "diff --git a/src/parser.rs b/src/parser.rs\n--- a/src/parser.rs\n+++ b/src/parser.rs\n@@ -40,3 +40,4 @@\n fn parse_block(input: &str) -> Block {\n-    let lines = input.lines();\n+    // skip blank lines\n+    let lines = input.lines().filter(|l| !l.trim().is_empty());\n     let mut block = Block::default();\n",
        ),
    )));
    let buffer = render(&mut app, 150, 46);
    std::fs::write(dir.join("review-150.html"), html(&buffer, "review", true)).unwrap();
    let mut app = demo_app("dark");
    let buffer = render(&mut app, 90, 40);
    std::fs::write(dir.join("dark-90.html"), html(&buffer, "dark narrow", true)).unwrap();
}
