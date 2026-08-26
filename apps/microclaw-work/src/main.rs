use gpui::*;
use gpui_component::{
    ActiveTheme, Root, StyledExt,
    button::{Button, ButtonVariants},
    h_flex,
    input::{Input, InputEvent, InputState},
    v_flex,
};
use microclaw_work::session::{WorkEventKind, WorkSessionSnapshot, WorkStatus};
use smol::Timer;
use std::path::PathBuf;
use std::time::Duration;

struct WorkApp {
    session: WorkSessionSnapshot,
    session_path: PathBuf,
    persistence_message: String,
    task_input: Entity<InputState>,
    active_run_id: u64,
    _subscriptions: Vec<Subscription>,
}

impl WorkApp {
    fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
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
            Err(error) => {
                let session = WorkSessionSnapshot::spike_demo();
                let message = match session.save(&session_path) {
                    Ok(()) => format!("恢复失败，已重建演示状态：{error}"),
                    Err(save_error) => {
                        format!("恢复失败：{error}；保存新状态也失败：{save_error}")
                    }
                };
                (session, message)
            }
        };

        let task_input = cx.new(|cx| {
            InputState::new(window, cx)
                .default_value(session.task.clone())
                .placeholder("描述希望 MicroClaw Work 完成的任务…")
        });
        let _subscriptions = vec![cx.subscribe_in(&task_input, window, {
            let task_input = task_input.clone();
            move |this, _, event: &InputEvent, _, cx| {
                if matches!(event, InputEvent::Change) {
                    this.session.task = task_input.read(cx).value().to_string();
                    cx.notify();
                }
            }
        })];

        Self {
            session,
            session_path,
            persistence_message,
            task_input,
            active_run_id: 0,
            _subscriptions,
        }
    }

    fn persist(&mut self) {
        self.persistence_message = match self.session.save(&self.session_path) {
            Ok(()) => "任务状态已保存".into(),
            Err(error) => format!("保存失败：{error}"),
        };
    }

    fn approve(&mut self, _: &ClickEvent, _: &mut Window, cx: &mut Context<Self>) {
        self.session.approve();
        self.persist();
        cx.notify();
    }

    fn start_demo(&mut self, _: &ClickEvent, _: &mut Window, cx: &mut Context<Self>) {
        let task = self.session.task.clone();
        if let Err(error) = self.session.start_task(task) {
            self.persistence_message = error.into();
            cx.notify();
            return;
        }

        self.active_run_id += 1;
        let run_id = self.active_run_id;
        self.persist();
        cx.notify();

        cx.spawn(async move |this, cx| {
            let events = [
                (WorkEventKind::Plan, "正在分析 Workspace 与任务目标"),
                (WorkEventKind::Plan, "已生成四步执行计划"),
                (WorkEventKind::Tool, "读取 Cargo workspace 和桌面应用代码"),
                (WorkEventKind::Tool, "准备修改 Work projection"),
            ];

            for (index, (kind, message)) in events.into_iter().enumerate() {
                Timer::after(Duration::from_millis(650)).await;
                let result = this.update(cx, |this, cx| {
                    if this.active_run_id != run_id {
                        return;
                    }
                    this.session
                        .record_progress(kind, message, Some(index.min(1)));
                    this.persist();
                    cx.notify();
                });
                if result.is_err() {
                    return;
                }
            }

            Timer::after(Duration::from_millis(650)).await;
            let _ = this.update(cx, |this, cx| {
                if this.active_run_id != run_id {
                    return;
                }
                this.session
                    .request_approval("允许演示任务写入 Workspace 并运行验证");
                this.persist();
                cx.notify();
            });
        })
        .detach();
    }

    fn reset(&mut self, _: &ClickEvent, window: &mut Window, cx: &mut Context<Self>) {
        self.session = WorkSessionSnapshot::spike_demo();
        self.active_run_id += 1;
        let task = self.session.task.clone();
        self.task_input.update(cx, |input, cx| {
            input.set_value(task, window, cx);
        });
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
                            .gap_3()
                            .child(div().flex_1().child(Input::new(&self.task_input)))
                            .child(
                                Button::new("run-demo")
                                    .primary()
                                    .label("运行演示任务")
                                    .on_click(cx.listener(Self::start_demo)),
                            ),
                    )
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
                                    ))
                                    .child(
                                        div()
                                            .mt_3()
                                            .pt_3()
                                            .border_t_1()
                                            .border_color(cx.theme().border)
                                            .text_sm()
                                            .font_bold()
                                            .child("Live events"),
                                    )
                                    .child(v_flex().gap_2().children(
                                        self.session.events.iter().rev().take(8).map(|event| {
                                            h_flex()
                                                .gap_2()
                                                .text_sm()
                                                .child(format!("#{:03}", event.id))
                                                .child(event.message.clone())
                                        }),
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
                let view = cx.new(|cx| WorkApp::new(window, cx));
                cx.new(|cx| Root::new(view, window, cx))
            })
            .expect("failed to open MicroClaw Work window");
        })
        .detach();
    });
}
