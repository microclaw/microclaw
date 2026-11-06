//! Hand a task to a paired MicroClaw Server (`mccode -p … --remote`).
//!
//! Pairing trades a one-time code (minted in the Server's web console,
//! Access tab) for a device token via `POST /api/pairing/claim`. The token is
//! stored in the Code home (`remote.json`, mode 0600). A remote run posts the
//! prompt to `POST /api/send_stream`, follows `GET /api/stream` (Server-Sent
//! Events) and maps the events onto the same [`Update`]s a local turn
//! produces; `Control::Cancel` calls `POST /api/runs/:id/cancel`.
//!
//! The task runs on the Server, in the Server's own working directory and
//! with its tools and approval policy — useful for long jobs or work that
//! belongs on that machine. Approvals follow the Server's text path: the run
//! ends with an approval prompt, answered by the next `--remote` message.

use std::path::PathBuf;

use futures_util::StreamExt;
use microclaw_sdk::{RunStatus, RuntimeEvent, RuntimeEventEnvelope};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use crate::driver::{Control, PendingApproval, TurnReport, Update};

/// A paired Server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteConfig {
    pub url: String,
    pub token: String,
    pub device_id: String,
    pub label: String,
}

impl RemoteConfig {
    pub fn default_path() -> PathBuf {
        crate::home::code_home().join("remote.json")
    }

    pub fn load() -> Option<Self> {
        Self::load_from(&Self::default_path())
    }

    pub fn load_from(path: &std::path::Path) -> Option<Self> {
        let text = std::fs::read_to_string(path).ok()?;
        serde_json::from_str(&text).ok()
    }

    pub fn save_to(&self, path: &std::path::Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let text = serde_json::to_string_pretty(self).map_err(std::io::Error::other)?;
        std::fs::write(path, text)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    pub fn save(&self) -> std::io::Result<()> {
        self.save_to(&Self::default_path())
    }

    /// Remove the stored pairing. Returns whether one existed.
    pub fn forget() -> std::io::Result<bool> {
        match std::fs::remove_file(Self::default_path()) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Absolute URL of `path` on the paired Server.
    pub fn endpoint(&self, path: &str) -> String {
        format!("{}{path}", self.url.trim_end_matches('/'))
    }
}

/// HTTP client used for every Server call (shared with `remote_notify`).
pub(crate) fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent(concat!("mccode/", env!("CARGO_PKG_VERSION")))
        .build()
        .unwrap_or_default()
}

/// `"<status>: <body>"` for an unsuccessful Server response.
pub(crate) async fn error_text(response: reqwest::Response) -> String {
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    format!("{status}: {}", body.trim())
}

/// Claim a pairing code on `url` and return the new pairing.
pub async fn pair(url: &str, code: &str, device_name: &str) -> anyhow::Result<RemoteConfig> {
    let url = url.trim_end_matches('/').to_string();
    let response = client()
        .post(format!("{url}/api/pairing/claim"))
        .json(&serde_json::json!({
            "code": code,
            "device_name": device_name,
            "platform": std::env::consts::OS,
        }))
        .send()
        .await?;
    if !response.status().is_success() {
        anyhow::bail!("pairing failed ({})", error_text(response).await);
    }
    let body: Value = response.json().await?;
    let field = |key: &str| {
        body.get(key)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let token = field("device_token");
    if token.is_empty() {
        anyhow::bail!("the Server did not return a device token");
    }
    Ok(RemoteConfig {
        url,
        token,
        device_id: field("device_id"),
        label: field("label"),
    })
}

/// Check the pairing; returns the Server's description of this device.
pub async fn whoami(config: &RemoteConfig) -> anyhow::Result<Value> {
    let response = client()
        .get(config.endpoint("/api/pairing/whoami"))
        .bearer_auth(&config.token)
        .send()
        .await?;
    if !response.status().is_success() {
        anyhow::bail!("{}", error_text(response).await);
    }
    Ok(response.json().await?)
}

/// One Server-Sent Event.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SseEvent {
    pub event: String,
    pub data: String,
}

/// Incremental SSE parser.
#[derive(Debug, Default)]
pub struct SseParser {
    buffer: String,
    event: String,
    data: Vec<String>,
}

impl SseParser {
    pub fn push(&mut self, chunk: &str) -> Vec<SseEvent> {
        self.buffer.push_str(chunk);
        let mut out = Vec::new();
        while let Some(pos) = self.buffer.find('\n') {
            let line = self.buffer[..pos].trim_end_matches('\r').to_string();
            self.buffer.drain(..=pos);
            if line.is_empty() {
                if !self.data.is_empty() || !self.event.is_empty() {
                    out.push(SseEvent {
                        event: std::mem::take(&mut self.event),
                        data: std::mem::take(&mut self.data).join("\n"),
                    });
                }
            } else if let Some(value) = line.strip_prefix("event:") {
                self.event = value.trim().to_string();
            } else if let Some(value) = line.strip_prefix("data:") {
                self.data
                    .push(value.strip_prefix(' ').unwrap_or(value).to_string());
            }
        }
        out
    }
}

/// Translate one Server stream event into a runtime event.
pub fn runtime_event(event: &SseEvent) -> Option<RuntimeEvent> {
    let data: Value = serde_json::from_str(&event.data).ok()?;
    let s = |key: &str| {
        data.get(key)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let n = |key: &str| data.get(key).and_then(Value::as_u64).unwrap_or(0);
    Some(match event.event.as_str() {
        "delta" => RuntimeEvent::TextDelta { delta: s("delta") },
        "tool_start" => RuntimeEvent::ToolStart {
            call_id: s("call_id"),
            name: s("name"),
            input: data.get("input").cloned().unwrap_or(Value::Null),
        },
        "tool_result" => RuntimeEvent::ToolResult {
            call_id: s("call_id"),
            name: s("name"),
            is_error: data
                .get("is_error")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            preview: s("preview"),
            duration_ms: n("duration_ms"),
            status_code: data
                .get("status_code")
                .and_then(Value::as_i64)
                .map(|c| c as i32),
            bytes: n("bytes") as usize,
            error_type: data
                .get("error_type")
                .and_then(Value::as_str)
                .map(str::to_string),
        },
        "file_diff" => RuntimeEvent::FileDiff {
            path: s("path"),
            diff: s("diff"),
            added: n("added") as usize,
            removed: n("removed") as usize,
            truncated: data
                .get("truncated")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        },
        "approval_required" => RuntimeEvent::ApprovalRequired {
            approval_id: s("approval_id"),
            tool: s("tool"),
            preview: data
                .get("preview")
                .and_then(Value::as_str)
                .map(str::to_string),
            options: data
                .get("options")
                .cloned()
                .and_then(|v| serde_json::from_value(v).ok())
                .unwrap_or_default(),
            advisory: data
                .get("advisory")
                .and_then(Value::as_str)
                .map(str::to_string),
        },
        "plan_updated" => RuntimeEvent::PlanUpdated {
            steps: data
                .get("steps")
                .cloned()
                .and_then(|v| serde_json::from_value(v).ok())
                .unwrap_or_default(),
        },
        _ => return None,
    })
}

/// Run `prompt` on the paired Server in session `session_key`.
pub async fn run(
    config: &RemoteConfig,
    session_key: &str,
    prompt: &str,
    updates: &UnboundedSender<Update>,
    controls: &mut UnboundedReceiver<Control>,
) -> anyhow::Result<TurnReport> {
    let http = client();
    let started = http
        .post(config.endpoint("/api/send_stream"))
        .bearer_auth(&config.token)
        .json(&serde_json::json!({
            "session_key": session_key,
            "sender_name": "mccode",
            "message": prompt,
        }))
        .send()
        .await?;
    if !started.status().is_success() {
        anyhow::bail!(
            "the Server refused the task ({})",
            error_text(started).await
        );
    }
    let started: Value = started.json().await?;
    let run_id = started
        .get("run_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("the Server did not return a run id"))?
        .to_string();
    let stream = http
        .get(config.endpoint("/api/stream"))
        .query(&[("run_id", run_id.as_str())])
        .bearer_auth(&config.token)
        .send()
        .await?;
    if !stream.status().is_success() {
        anyhow::bail!("could not follow the run ({})", error_text(stream).await);
    }
    let mut body = stream.bytes_stream();
    let mut parser = SseParser::default();
    let mut report = TurnReport::default();
    let mut sequence = 0u64;
    let mut controls_open = true;
    let mut status = RunStatus::Completed;
    let mut error = None;
    'stream: loop {
        tokio::select! {
            chunk = body.next() => {
                let Some(chunk) = chunk else { break };
                let chunk = chunk?;
                for event in parser.push(&String::from_utf8_lossy(&chunk)) {
                    match event.event.as_str() {
                        "done" => {
                            let data: Value = serde_json::from_str(&event.data).unwrap_or_default();
                            report.final_text = data
                                .get("response")
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_string();
                            break 'stream;
                        }
                        "aborted" => {
                            status = RunStatus::Cancelled;
                            report.cancelled = true;
                            break 'stream;
                        }
                        "error" => {
                            status = RunStatus::Failed;
                            report.failed = true;
                            let data: Value = serde_json::from_str(&event.data).unwrap_or_default();
                            error = Some(
                                data.get("error")
                                    .and_then(Value::as_str)
                                    .unwrap_or(event.data.as_str())
                                    .to_string(),
                            );
                            break 'stream;
                        }
                        _ => {}
                    }
                    let Some(runtime) = runtime_event(&event) else { continue };
                    match &runtime {
                        RuntimeEvent::FileDiff { path, .. } if !report.changed_files.contains(path) => {
                            report.changed_files.push(path.clone());
                        }
                        RuntimeEvent::ApprovalRequired { approval_id, tool, preview, options, advisory } => {
                            report.approval_pending = Some(PendingApproval::from_event(
                                approval_id,
                                tool,
                                preview.as_deref(),
                                options,
                                advisory.as_deref(),
                            ).without_code_options());
                        }
                        _ => {}
                    }
                    sequence += 1;
                    let _ = updates.send(Update::Runtime(RuntimeEventEnvelope::new(&run_id, sequence, runtime)));
                }
            }
            control = controls.recv(), if controls_open => match control {
                Some(Control::Cancel) => {
                    let _ = http
                        .post(config.endpoint(&format!("/api/runs/{run_id}/cancel")))
                        .bearer_auth(&config.token)
                        .send()
                        .await;
                }
                Some(_) => {}
                None => controls_open = false,
            },
        }
    }
    report.status = format!("{status:?}").to_lowercase();
    let _ = updates.send(Update::RunFinished {
        status,
        final_text: report.final_text.clone(),
        error,
    });
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_server_sent_events_across_chunks() {
        let mut parser = SseParser::default();
        assert!(parser.push("event: delta\ndata: {\"del").is_empty());
        let events = parser.push("ta\":\"hi\"}\n\n: keepalive\n\nevent: done\r\ndata: {}\r\n\r\n");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event, "delta");
        assert_eq!(
            runtime_event(&events[0]),
            Some(RuntimeEvent::TextDelta { delta: "hi".into() })
        );
        assert_eq!(events[1].event, "done");
    }

    #[test]
    fn maps_tool_and_approval_events() {
        let tool = SseEvent {
            event: "tool_start".into(),
            data: r#"{"call_id":"c","name":"bash","input":{"command":"ls"}}"#.into(),
        };
        assert!(matches!(
            runtime_event(&tool),
            Some(RuntimeEvent::ToolStart { ref name, .. }) if name == "bash"
        ));
        let approval = SseEvent {
            event: "approval_required".into(),
            data: r#"{"approval_id":"a","tool":"bash","preview":"rm x","options":[{"value":"1","label":"Approve once","kind":"primary","decision":"approve"}],"advisory":null}"#.into(),
        };
        match runtime_event(&approval) {
            Some(RuntimeEvent::ApprovalRequired {
                options, preview, ..
            }) => {
                assert_eq!(options.len(), 1);
                assert_eq!(preview.as_deref(), Some("rm x"));
            }
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(
            runtime_event(&SseEvent {
                event: "status".into(),
                data: "{}".into()
            }),
            None
        );
    }

    #[test]
    fn pairing_round_trips_with_private_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("remote.json");
        let config = RemoteConfig {
            url: "http://127.0.0.1:10961".into(),
            token: "tok".into(),
            device_id: "d".into(),
            label: "laptop".into(),
        };
        config.save_to(&path).unwrap();
        assert_eq!(RemoteConfig::load_from(&path), Some(config.clone()));
        assert_eq!(config.endpoint("/api/x"), "http://127.0.0.1:10961/api/x");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }
}
