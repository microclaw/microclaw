use gpui::*;
use gpui_component::{
    ActiveTheme, Root, StyledExt,
    button::{Button, ButtonVariants},
    h_flex, v_flex,
};
use microclaw_work::session::{WorkSessionSnapshot, WorkStatus};
use std::path::PathBuf;

struct WorkApp {
    session: WorkSessionSnapshot,
    session_path: PathBuf,
    persistence_message: String,
}

impl WorkApp {
    fn new() -> Self {
        let session_path = dirs::data_local_dir()
            .unwrap_or_else(std::env::temp_dir)
            .join("microclaw-work")
            .join("spike-session.json");
        let (session, persistence_message) = match WorkSessionSnapshot::load(&session_path) {
            Ok(session) => (session, "已从上次运行恢复".into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let session = WorkSessionSnapshot::spike_demo();
                let message = match session.save(&session_path) {
                    Ok(()) => "已创建可恢复的演示任务".into(),
                    Err(error) => format!("无法保存演示任务：{error}"),
                };
                (session, message)
            }
            Err(error) => (
                WorkSessionSnapshot::spike_demo(),
                format!("恢复失败，已使用演示状态：{error}"),
            ),
        };

        Self {
            session,
            session_path,
            persistence_message,
        }
    }

    fn persist(&mut self) {
        self.persistence_message = match self.session.save(&self.session_path) {
            Ok(()) => "任务状态已保存".into(),
            Err(error) => format!("保存失败：{error}"),
        };
    }

    fn approve(&mut self, _: &ClickEvent, _: &mut Window, cx: &mut Context<Self>) {
        self.session.status = WorkStatus::Verifying;
        self.session.approval_reason = None;
        if let Some(step) = self.session.plan.get_mut(2) {
            step.completed = true;
        }
        self.persist();
        cx.notify();
    }

    fn reset(&mut self, _: &ClickEvent, _: &mut Window, cx: &mut Context<Self>) {
        self.session = WorkSessionSnapshot::spike_demo();
        self.persist();
        cx.notify();
    }
}

impl Render for WorkApp {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let status = match self.session.status {
            WorkStatus::Planning => "规划中",
            WorkStatus::Running => "执行中",
            WorkStatus::AwaitingApproval => "等待审批",
            WorkStatus::Verifying => "验证中",
            WorkStatus::Completed => "已完成",
        };

        h_flex()
            .size_full()
            .bg(cx.theme().background)
            .text_color(cx.theme().foreground)
            .child(
                v_flex()
                    .w(px(260.))
                    .h_full()
                    .p_4()
                    .gap_3()
                    .border_r_1()
                    .border_color(cx.theme().border)
                    .child(div().text_xl().font_bold().child("MicroClaw Work"))
                    .child(
                        div()
                            .text_sm()
                            .text_color(cx.theme().muted_foreground)
                            .child("Workspace"),
                    )
                    .child(div().child(self.session.workspace.clone()))
                    .child(
                        div()
                            .mt_4()
                            .text_sm()
                            .text_color(cx.theme().muted_foreground)
                            .child("最近任务"),
                    )
                    .child(
                        div()
                            .p_3()
                            .rounded(cx.theme().radius)
                            .bg(cx.theme().accent)
                            .child(self.session.task.clone()),
                    )
                    .child(
                        div()
                            .mt_auto()
                            .text_xs()
                            .text_color(cx.theme().muted_foreground)
                            .child(self.persistence_message.clone())
                            .child(div().mt_1().child(self.session_path.display().to_string())),
                    ),
            )
            .child(
                v_flex()
                    .flex_1()
                    .min_w_0()
                    .h_full()
                    .p_6()
                    .gap_5()
                    .child(
                        h_flex()
                            .items_center()
                            .justify_between()
                            .child(
                                v_flex()
                                    .gap_1()
                                    .child(div().text_2xl().font_bold().child("工作任务"))
                                    .child(self.session.task.clone()),
                            )
                            .child(
                                div()
                                    .px_3()
                                    .py_1()
                                    .rounded_full()
                                    .bg(cx.theme().warning.opacity(0.18))
                                    .child(status),
                            ),
                    )
                    .child(
                        h_flex()
                            .flex_1()
                            .min_h_0()
                            .gap_5()
                            .child(
                                v_flex()
                                    .flex_1()
                                    .gap_3()
                                    .p_4()
                                    .rounded(cx.theme().radius)
                                    .border_1()
                                    .border_color(cx.theme().border)
                                    .child(div().text_lg().font_bold().child("Plan"))
                                    .children(self.session.plan.iter().enumerate().map(
                                        |(index, step)| {
                                            h_flex()
                                                .gap_3()
                                                .child(if step.completed { "✓" } else { "○" })
                                                .child(format!("{}. {}", index + 1, step.title))
                                        },
                                    )),
                            )
                            .child(
                                v_flex()
                                    .w(px(360.))
                                    .gap_3()
                                    .child(
                                        v_flex()
                                            .gap_3()
                                            .p_4()
                                            .rounded(cx.theme().radius)
                                            .border_1()
                                            .border_color(cx.theme().border)
                                            .child(div().text_lg().font_bold().child("Approval"))
                                            .child(
                                                self.session
                                                    .approval_reason
                                                    .clone()
                                                    .unwrap_or_else(|| "没有待审批操作".into()),
                                            )
                                            .child(
                                                h_flex()
                                                    .gap_2()
                                                    .child(
                                                        Button::new("approve")
                                                            .primary()
                                                            .label("允许并继续")
                                                            .on_click(cx.listener(Self::approve)),
                                                    )
                                                    .child(
                                                        Button::new("reset")
                                                            .outline()
                                                            .label("恢复演示")
                                                            .on_click(cx.listener(Self::reset)),
                                                    ),
                                            ),
                                    )
                                    .child(
                                        v_flex()
                                            .gap_3()
                                            .p_4()
                                            .rounded(cx.theme().radius)
                                            .border_1()
                                            .border_color(cx.theme().border)
                                            .child(
                                                div()
                                                    .text_lg()
                                                    .font_bold()
                                                    .child("Diff / Artifact"),
                                            )
                                            .child(
                                                div()
                                                    .font_family("monospace")
                                                    .child(self.session.diff_summary.clone()),
                                            ),
                                    ),
                            ),
                    ),
            )
    }
}

fn main() {
    gpui_platform::application().run(move |cx| {
        gpui_component::init(cx);

        let options = WindowOptions {
            window_bounds: Some(WindowBounds::centered(size(px(1180.), px(760.)), cx)),
            ..Default::default()
        };

        cx.spawn(async move |cx| {
            cx.open_window(options, |window, cx| {
                let view = cx.new(|_| WorkApp::new());
                cx.new(|cx| Root::new(view, window, cx))
            })
            .expect("failed to open MicroClaw Work window");
        })
        .detach();
    });
}
