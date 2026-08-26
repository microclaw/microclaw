mod runtime_worker;

use gpui::*;
use gpui_component::{
    ActiveTheme, Root, StyledExt,
    button::{Button, ButtonVariants},
    h_flex,
    input::{Input, InputEvent, InputState},
    v_flex,
};
use microclaw_work_app::session::{WorkCommand, WorkEventKind, WorkSessionSnapshot, WorkStatus};
use runtime_worker::{RuntimeMessage, RuntimeRunSpec, spawn_runtime};
use smol::Timer;
use std::path::PathBuf;
use std::sync::mpsc::TryRecvError;
use std::time::Duration;

struct WorkApp {
    session: WorkSessionSnapshot,
    session_path: PathBuf,
    persistence_message: String,
    task_input: Entity<InputState>,
    active_run_id: u64,
    runtime_active: bool,
    last_run_was_demo: bool,
    _subscriptions: Vec<Subscription>,
}

impl WorkApp {
    fn runtime_busy(&self) -> bool {
        self.runtime_active
    }

    fn reject_if_runtime_busy(&mut self, cx: &mut Context<Self>) -> bool {
        if self.runtime_busy() {
            self.persistence_message = "已有真实任务正在运行；请等待完成或审批".into();
            cx.notify();
            true
        } else {
            false
        }
    }

    fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let session_path = dirs::data_local_dir()
            .unwrap_or_else(std::env::temp_dir)
            .join("microclaw-work")
            .join("spike-session.json");
        let (mut session, persistence_message) = match WorkSessionSnapshot::load(&session_path) {
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
        session.workspace = std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .display()
            .to_string();

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
            runtime_active: false,
            last_run_was_demo: false,
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
        if let Err(error) = self.session.apply(WorkCommand::Approve) {
            self.persistence_message = error.to_string();
            cx.notify();
            return;
        }
        self.persist();
        cx.notify();
        if !self.last_run_was_demo {
            self.launch_runtime_prompt("1".into(), cx);
        }
    }

    fn start_runtime(&mut self, _: &ClickEvent, _: &mut Window, cx: &mut Context<Self>) {
        if self.reject_if_runtime_busy(cx) {
            return;
        }
        let task = self.session.task.clone();
        if let Err(error) = self
            .session
            .apply(WorkCommand::StartTask { task: task.clone() })
        {
            self.persistence_message = error.to_string();
            cx.notify();
            return;
        }
        self.last_run_was_demo = false;
        self.persist();
        self.launch_runtime_prompt(task, cx);
    }

    fn launch_runtime_prompt(&mut self, prompt: String, cx: &mut Context<Self>) {
        self.active_run_id = self.active_run_id.saturating_add(1);
        self.runtime_active = true;
        let generation = self.active_run_id;
        let receiver = spawn_runtime(RuntimeRunSpec {
            task: prompt,
            workspace: self.session.workspace.clone(),
            session: "desktop-default".into(),
        });
        self.persistence_message = "正在连接 MicroClaw Runtime…".into();
        cx.notify();

        cx.spawn(async move |this, cx| {
            loop {
                match receiver.try_recv() {
                    Ok(message) => {
                        let terminal = matches!(
                            &message,
                            RuntimeMessage::Completed { .. } | RuntimeMessage::Failed { .. }
                        );
                        if this
                            .update(cx, |this, cx| {
                                if this.active_run_id != generation {
                                    return;
                                }
                                match message {
                                    RuntimeMessage::Envelope(envelope) => {
                                        if let Err(error) = this
                                            .session
                                            .apply(WorkCommand::ApplyRuntimeEvent(envelope))
                                        {
                                            this.persistence_message = error.to_string();
                                        }
                                    }
                                    RuntimeMessage::Completed { run_id } => {
                                        this.runtime_active = false;
                                        this.persistence_message = if this.session.status
                                            == WorkStatus::AwaitingApproval
                                        {
                                            format!("Runtime {run_id} 已暂停，等待审批")
                                        } else {
                                            format!("Runtime {run_id} 已完成")
                                        };
                                    }
                                    RuntimeMessage::Failed { run_id, message } => {
                                        this.runtime_active = false;
                                        let display = format!("Runtime {run_id} 失败：{message}");
                                        let _ = this.session.apply(WorkCommand::FailRun {
                                            message: message.clone(),
                                        });
                                        this.persistence_message = display;
                                    }
                                }
                                if let Err(error) = this.session.save(&this.session_path) {
                                    this.persistence_message = format!("保存失败：{error}");
                                }
                                cx.notify();
                            })
                            .is_err()
                        {
                            return;
                        }
                        if terminal {
                            return;
                        }
                    }
                    Err(TryRecvError::Empty) => {
                        Timer::after(Duration::from_millis(40)).await;
                    }
                    Err(TryRecvError::Disconnected) => {
                        let _ = this.update(cx, |this, cx| {
                            if this.active_run_id != generation || !this.runtime_active {
                                return;
                            }
                            this.runtime_active = false;
                            let message = "Runtime 消息通道意外断开".to_string();
                            let _ = this.session.apply(WorkCommand::FailRun {
                                message: message.clone(),
                            });
                            this.persistence_message = message;
                            if let Err(error) = this.session.save(&this.session_path) {
                                this.persistence_message = format!("保存失败：{error}");
                            }
                            cx.notify();
                        });
                        return;
                    }
                }
            }
        })
        .detach();
    }

    fn start_demo(&mut self, _: &ClickEvent, _: &mut Window, cx: &mut Context<Self>) {
        if self.reject_if_runtime_busy(cx) {
            return;
        }
        let task = self.session.task.clone();
        if let Err(error) = self.session.apply(WorkCommand::StartTask { task }) {
            self.persistence_message = error.to_string();
            cx.notify();
            return;
        }

        self.active_run_id += 1;
        self.runtime_active = true;
        self.last_run_was_demo = true;
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
                    let _ = this.session.apply(WorkCommand::RecordProgress {
                        kind,
                        message: message.into(),
                        completed_step: Some(index.min(1)),
                    });
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
                let _ = this.session.apply(WorkCommand::RequestApproval {
                    reason: "允许演示任务写入 Workspace 并运行验证".into(),
                });
                this.runtime_active = false;
                this.persist();
                cx.notify();
            });
        })
        .detach();
    }

    fn reset(&mut self, _: &ClickEvent, window: &mut Window, cx: &mut Context<Self>) {
        if self.reject_if_runtime_busy(cx) {
            return;
        }
        let _ = self.session.apply(WorkCommand::ResetDemo);
        self.active_run_id += 1;
        self.runtime_active = false;
        self.last_run_was_demo = true;
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
            WorkStatus::Cancelled => "已取消",
            WorkStatus::Failed => "失败",
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
                                Button::new("run-runtime")
                                    .primary()
                                    .label("运行真实任务")
                                    .on_click(cx.listener(Self::start_runtime)),
                            )
                            .child(
                                Button::new("run-demo")
                                    .outline()
                                    .label("演示")
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
