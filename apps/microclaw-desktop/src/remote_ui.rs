//! Settings → Server: pair this Desktop client with a MicroClaw Server and pick
//! where tasks execute (the embedded engine or the paired Server).

use super::*;
use microclaw_desktop_runtime::remote::{
    RemoteError, RemoteServerCredentials, pair_blocking, whoami_blocking,
};
use std::sync::mpsc::{Receiver, channel};

/// Where a task runs. Persisted as plain text next to the appearance
/// preference so the choice survives restarts and is always visible.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum ExecutionTarget {
    #[default]
    Local,
    Server,
}

impl ExecutionTarget {
    pub(crate) fn load(path: &Path) -> Self {
        match fs::read_to_string(path).as_deref().map(str::trim) {
            Ok("server") => Self::Server,
            _ => Self::Local,
        }
    }

    pub(crate) fn save(self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, self.name())
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Server => "server",
        }
    }
}

pub(crate) enum ServerActionResult {
    Paired(RemoteServerCredentials),
    Checked {
        actor: String,
        server_version: Option<String>,
    },
    Failed(String),
    Revoked,
}

fn describe_remote_error(error: &RemoteError) -> String {
    match error {
        RemoteError::Unauthorized => {
            "The Server rejected this device's credentials. It was probably revoked; pair again."
                .into()
        }
        other => other.to_string(),
    }
}

impl DesktopApp {
    /// True when tasks will be sent to the paired Server.
    pub(crate) fn remote_target_ready(&self) -> bool {
        self.execution_target == ExecutionTarget::Server && self.remote_credentials.is_some()
    }

    pub(crate) fn remote_target_label(&self) -> String {
        match &self.remote_credentials {
            Some(credentials) => format!("Server · {}", credentials.label),
            None => "Server · not paired".into(),
        }
    }

    pub(crate) fn execution_target_chip(&self) -> String {
        match self.execution_target {
            ExecutionTarget::Local => format!(
                "Local · {} / {}",
                self.runtime_config.provider, self.runtime_config.model
            ),
            ExecutionTarget::Server => self.remote_target_label(),
        }
    }

    pub(crate) fn set_execution_target(&mut self, target: ExecutionTarget, cx: &mut Context<Self>) {
        if self.runtime_active {
            self.server_message =
                "Finish or stop the running task before switching targets.".into();
            cx.notify();
            return;
        }
        if target == ExecutionTarget::Server && self.remote_credentials.is_none() {
            self.server_message = "Pair with a Server before selecting it as the target.".into();
            cx.notify();
            return;
        }
        self.execution_target = target;
        self.server_message = match target.save(&self.execution_target_path) {
            Ok(()) => match target {
                ExecutionTarget::Local => "Tasks run on this computer.".into(),
                ExecutionTarget::Server => format!("Tasks run on {}.", self.remote_target_label()),
            },
            Err(error) => format!("Target changed, but the preference was not saved: {error}"),
        };
        cx.notify();
    }

    fn poll_server_action(
        &mut self,
        receiver: Receiver<ServerActionResult>,
        cx: &mut Context<Self>,
    ) {
        self.server_action_active = true;
        cx.spawn(async move |this, cx| {
            loop {
                match receiver.try_recv() {
                    Ok(result) => {
                        let _ = this.update(cx, |this, cx| {
                            this.server_action_active = false;
                            match result {
                                ServerActionResult::Paired(credentials) => {
                                    let label = credentials.label.clone();
                                    let version = credentials.server_version.clone();
                                    this.remote_credentials = Some(credentials);
                                    this.server_message = match version {
                                        Some(version) => format!(
                                            "Paired as {label} with MicroClaw Server {version}."
                                        ),
                                        None => format!("Paired as {label}."),
                                    };
                                    if this.execution_target == ExecutionTarget::Local {
                                        this.set_execution_target(ExecutionTarget::Server, cx);
                                    }
                                }
                                ServerActionResult::Checked {
                                    actor,
                                    server_version,
                                } => {
                                    this.server_message = match server_version {
                                        Some(version) => format!(
                                            "Connected: {actor} on MicroClaw Server {version}."
                                        ),
                                        None => format!("Connected: {actor}."),
                                    };
                                }
                                ServerActionResult::Revoked => {
                                    this.remote_credentials = None;
                                    if this.execution_target == ExecutionTarget::Server {
                                        this.execution_target = ExecutionTarget::Local;
                                        let _ = ExecutionTarget::Local
                                            .save(&this.execution_target_path);
                                    }
                                    this.server_message = "This device is no longer paired. Tasks run locally until you pair again.".into();
                                }
                                ServerActionResult::Failed(message) => {
                                    this.server_message = format!("Server action failed: {message}");
                                }
                            }
                            cx.notify();
                        });
                        break;
                    }
                    Err(TryRecvError::Empty) => {
                        Timer::after(Duration::from_millis(50)).await;
                    }
                    Err(TryRecvError::Disconnected) => {
                        let _ = this.update(cx, |this, cx| {
                            this.server_action_active = false;
                            this.server_message = "Server action worker exited unexpectedly.".into();
                            cx.notify();
                        });
                        break;
                    }
                }
            }
        })
        .detach();
        cx.notify();
    }

    pub(crate) fn pair_server(&mut self, _: &ClickEvent, _: &mut Window, cx: &mut Context<Self>) {
        if self.server_action_active {
            return;
        }
        let server_url = self.server_url_input.read(cx).value().trim().to_string();
        let code = self.pairing_code_input.read(cx).value().trim().to_string();
        let device_name = self.device_name_input.read(cx).value().trim().to_string();
        if server_url.is_empty() || code.is_empty() {
            self.server_message =
                "Enter the Server URL and the pairing code from its Web console.".into();
            cx.notify();
            return;
        }
        let device_name = if device_name.is_empty() {
            default_device_name()
        } else {
            device_name
        };
        self.server_message = format!("Pairing with {server_url}…");
        let credentials_path = self.remote_credentials_path.clone();
        let (sender, receiver) = channel();
        std::thread::Builder::new()
            .name("microclaw-desktop-pair".into())
            .spawn(move || {
                let result = match pair_blocking(&server_url, &code, &device_name) {
                    Ok(credentials) => match credentials.save(&credentials_path) {
                        Ok(()) => ServerActionResult::Paired(credentials),
                        Err(error) => ServerActionResult::Failed(format!(
                            "paired, but the credential file was not saved: {error}"
                        )),
                    },
                    Err(error) => ServerActionResult::Failed(describe_remote_error(&error)),
                };
                let _ = sender.send(result);
            })
            .expect("spawn pairing thread");
        self.poll_server_action(receiver, cx);
    }

    pub(crate) fn check_server(&mut self, _: &ClickEvent, _: &mut Window, cx: &mut Context<Self>) {
        if self.server_action_active {
            return;
        }
        let Some(credentials) = self.remote_credentials.clone() else {
            self.server_message = "Not paired with a Server yet.".into();
            cx.notify();
            return;
        };
        self.server_message = format!("Checking {}…", credentials.server_url);
        let (sender, receiver) = channel();
        std::thread::Builder::new()
            .name("microclaw-desktop-whoami".into())
            .spawn(move || {
                let result = match whoami_blocking(&credentials) {
                    Ok(identity) => ServerActionResult::Checked {
                        actor: identity.actor,
                        server_version: identity.server_version,
                    },
                    Err(RemoteError::Unauthorized) => ServerActionResult::Revoked,
                    Err(error) => ServerActionResult::Failed(describe_remote_error(&error)),
                };
                let _ = sender.send(result);
            })
            .expect("spawn whoami thread");
        self.poll_server_action(receiver, cx);
    }

    pub(crate) fn unpair_server(&mut self, _: &ClickEvent, _: &mut Window, cx: &mut Context<Self>) {
        if self.runtime_active {
            self.server_message = "Stop the running task before unpairing.".into();
            cx.notify();
            return;
        }
        match RemoteServerCredentials::remove(&self.remote_credentials_path) {
            Ok(()) => {
                self.remote_credentials = None;
                if self.execution_target == ExecutionTarget::Server {
                    self.execution_target = ExecutionTarget::Local;
                    let _ = ExecutionTarget::Local.save(&self.execution_target_path);
                }
                self.server_message =
                    "Unpaired. The device token was deleted from this computer; revoke it in the Server console too if it may have leaked.".into();
            }
            Err(error) => {
                self.server_message = format!("Could not remove the credential file: {error}");
            }
        }
        cx.notify();
    }

    pub(crate) fn render_server_settings(&self, cx: &mut Context<Self>) -> AnyElement {
        let paired = self.remote_credentials.clone();
        let message_color = if self.server_message.starts_with("Paired")
            || self.server_message.starts_with("Connected")
        {
            cx.theme().success
        } else if self.server_message.contains("failed")
            || self.server_message.contains("rejected")
            || self.server_message.contains("no longer")
        {
            cx.theme().danger
        } else {
            cx.theme().muted_foreground
        };

        let mut status_children: Vec<AnyElement> = vec![self.settings_label("Pairing status")];
        match &paired {
            Some(credentials) => {
                status_children.push(
                    v_flex()
                        .gap_0p5()
                        .child(
                            div()
                                .text_size(UI_TEXT_SIZE)
                                .font_semibold()
                                .child(format!("Paired as {}", credentials.label)),
                        )
                        .child(
                            div()
                                .text_size(UI_CAPTION_SIZE)
                                .text_color(cx.theme().muted_foreground)
                                .child(format!(
                                    "{} · device {} · scopes operator.read, operator.write",
                                    credentials.server_url,
                                    credentials.device_id.chars().take(8).collect::<String>()
                                )),
                        )
                        .into_any_element(),
                );
                status_children.push(
                    h_flex()
                        .gap_2()
                        .child(
                            Button::new("check-server")
                                .small()
                                .disabled(self.server_action_active)
                                .label(if self.server_action_active {
                                    "Checking…"
                                } else {
                                    "Check connection"
                                })
                                .on_click(cx.listener(Self::check_server)),
                        )
                        .child(
                            Button::new("unpair-server")
                                .ghost()
                                .small()
                                .disabled(self.server_action_active || self.runtime_active)
                                .label("Unpair")
                                .on_click(cx.listener(Self::unpair_server)),
                        )
                        .into_any_element(),
                );
            }
            None => {
                status_children.push(
                    div()
                        .text_size(UI_CAPTION_SIZE)
                        .text_color(cx.theme().muted_foreground)
                        .child("Not paired. Create a pairing code in the Server's Web console under Settings → Access → Paired devices, then enter it below.")
                        .into_any_element(),
                );
            }
        }

        v_flex()
            .w_full()
            .gap_4()
            .child(self.settings_page_header(
                "Pair this computer with a MicroClaw Server you run, and choose where tasks execute.",
                cx,
            ))
            .child(self.settings_group(
                vec![
                    self.settings_label("Execution target"),
                    h_flex()
                        .w_full()
                        .gap_2()
                        .children(
                            [
                                (
                                    "target-local",
                                    "Local",
                                    "Embedded engine on this computer; your Workspace and permissions.",
                                    ExecutionTarget::Local,
                                    true,
                                ),
                                (
                                    "target-server",
                                    "Server",
                                    "Paired MicroClaw Server; it owns the working directory and scope.",
                                    ExecutionTarget::Server,
                                    paired.is_some(),
                                ),
                            ]
                            .into_iter()
                            .map(|(id, label, detail, target, enabled)| {
                                let selected = self.execution_target == target;
                                BaseButton::new(id)
                                    .flex_1()
                                    .h(px(76.))
                                    .p_3()
                                    .items_start()
                                    .justify_start()
                                    .rounded(px(9.))
                                    .border_1()
                                    .border_color(if selected {
                                        cx.theme().primary.opacity(0.72)
                                    } else {
                                        cx.theme().border
                                    })
                                    .bg(if selected {
                                        cx.theme().accent.opacity(0.14)
                                    } else {
                                        cx.theme().background.opacity(0.48)
                                    })
                                    .when(!enabled, |button| button.opacity(0.5))
                                    .hover(|style| style.bg(cx.theme().accent.opacity(0.10)))
                                    .child(
                                        v_flex()
                                            .gap_1()
                                            .child(
                                                h_flex()
                                                    .w_full()
                                                    .justify_between()
                                                    .child(
                                                        div()
                                                            .text_size(UI_TEXT_SIZE)
                                                            .font_semibold()
                                                            .child(label),
                                                    )
                                                    .child(
                                                        div()
                                                            .size(px(10.))
                                                            .rounded_full()
                                                            .border_1()
                                                            .border_color(cx.theme().primary)
                                                            .when(selected, |dot| {
                                                                dot.bg(cx.theme().primary)
                                                            }),
                                                    ),
                                            )
                                            .child(
                                                div()
                                                    .text_size(UI_CAPTION_SIZE)
                                                    .text_color(cx.theme().muted_foreground)
                                                    .child(detail),
                                            ),
                                    )
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.set_execution_target(target, cx);
                                    }))
                            }),
                        )
                        .into_any_element(),
                ],
                cx,
            ))
            .child(self.settings_group(status_children, cx))
            .child(self.settings_group(
                vec![
                    self.settings_label("Server URL"),
                    Input::new(&self.server_url_input)
                        .aria_label("MicroClaw Server URL")
                        .content_type(InputContentType::Url)
                        .into_any_element(),
                    self.settings_label("Pairing code"),
                    Input::new(&self.pairing_code_input)
                        .aria_label("Pairing code")
                        .into_any_element(),
                    self.settings_label("Device name"),
                    Input::new(&self.device_name_input)
                        .aria_label("Device name shown in the Server console")
                        .into_any_element(),
                    h_flex()
                        .w_full()
                        .items_center()
                        .justify_between()
                        .gap_4()
                        .child(
                            div()
                                .flex_1()
                                .text_size(UI_CAPTION_SIZE)
                                .text_color(message_color)
                                .child(self.server_message.clone()),
                        )
                        .child(
                            Button::new("pair-server")
                                .primary()
                                .small()
                                .disabled(self.server_action_active)
                                .label(if self.server_action_active {
                                    "Pairing…"
                                } else if paired.is_some() {
                                    "Pair again"
                                } else {
                                    "Pair"
                                })
                                .on_click(cx.listener(Self::pair_server)),
                        )
                        .into_any_element(),
                ],
                cx,
            ))
            .child(
                div()
                    .text_size(UI_CAPTION_SIZE)
                    .text_color(cx.theme().muted_foreground)
                    .child("The device token is stored with owner-only permissions in Desktop's data directory and only grants operator.read and operator.write on the Server."),
            )
            .into_any_element()
    }
}

pub(crate) fn default_device_name() -> String {
    let host = std::env::var("HOSTNAME")
        .ok()
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
        .or_else(|| {
            std::process::Command::new("hostname")
                .output()
                .ok()
                .and_then(|out| String::from_utf8(out.stdout).ok())
                .map(|h| h.trim().trim_end_matches(".local").to_string())
                .filter(|h| !h.is_empty())
        })
        .unwrap_or_else(|| "MicroClaw Desktop".into());
    format!("{host} ({})", std::env::consts::OS)
}

#[cfg(test)]
mod tests {
    use super::{ExecutionTarget, default_device_name};
    use std::fs;

    #[test]
    fn execution_target_round_trips_through_the_preference_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("execution-target");
        assert_eq!(ExecutionTarget::load(&path), ExecutionTarget::Local);
        ExecutionTarget::Server.save(&path).unwrap();
        assert_eq!(ExecutionTarget::load(&path), ExecutionTarget::Server);
        ExecutionTarget::Local.save(&path).unwrap();
        assert_eq!(ExecutionTarget::load(&path), ExecutionTarget::Local);
        fs::write(&path, "garbage").unwrap();
        assert_eq!(ExecutionTarget::load(&path), ExecutionTarget::Local);
    }

    #[test]
    fn default_device_name_mentions_the_platform() {
        assert!(default_device_name().contains(std::env::consts::OS));
    }
}
