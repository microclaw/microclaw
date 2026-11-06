//! Notifications and approvals through a paired MicroClaw Server (chat channels).
//!
//! When `mccode` needs a person while they are away from the terminal, it can
//! ask the paired Server (`mccode remote pair`) to post into a chat app:
//!
//! - [`RemoteNotifier::notify`] posts a one-way message
//!   (`POST /api/code/notify`);
//! - [`RemoteNotifier::request_approval`] posts a card with option buttons
//!   (`POST /api/code/approvals`); [`RemoteNotifier::poll`] reads its state
//!   (`GET /api/code/approvals/:id`) and [`RemoteNotifier::cancel`] withdraws
//!   it (`DELETE …`, the chat then shows it was answered in the terminal).
//!
//! The chat is named `<channel>:<chat id>`, e.g. `telegram:123456789`. The
//! Server only sends approval cards to its control chats and only accepts an
//! answer from the chat that received the card.

use std::time::Duration;

use serde_json::Value;
use tokio::sync::watch;

use crate::remote::{RemoteConfig, client, error_text};

/// A card the Server posted; poll it by `id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteApproval {
    pub id: String,
    /// RFC 3339 expiry reported by the Server.
    pub expires_at: Option<String>,
}

/// State of a remote approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteStatus {
    Pending,
    Answered {
        value: String,
        answered_by: Option<String>,
    },
    Expired,
    Cancelled,
    /// The Server no longer knows it (restarted, or pruned long after it
    /// finished).
    Gone,
}

impl RemoteStatus {
    pub fn is_final(&self) -> bool {
        !matches!(self, RemoteStatus::Pending)
    }
}

/// Posts notifications and approval cards to one chat via the paired Server.
#[derive(Debug, Clone)]
pub struct RemoteNotifier {
    config: RemoteConfig,
    chat: String,
    http: reqwest::Client,
}

/// Check the `<channel>:<chat id>` shape locally so a typo fails early.
fn validate_chat(chat: &str) -> anyhow::Result<String> {
    let chat = chat.trim();
    match chat.split_once(':') {
        Some((channel, id)) if !channel.trim().is_empty() && !id.trim().is_empty() => {
            Ok(chat.to_string())
        }
        _ => anyhow::bail!(
            "notify chat must look like <channel>:<chat id> (for example telegram:123456789), got '{chat}'"
        ),
    }
}

impl RemoteNotifier {
    pub fn new(config: RemoteConfig, chat: &str) -> anyhow::Result<Self> {
        Ok(Self {
            config,
            chat: validate_chat(chat)?,
            http: client(),
        })
    }

    /// Use the stored pairing (`~/.mccode/remote.json`); `None` when
    /// this machine is not paired with a Server.
    pub fn from_pairing(chat: &str) -> anyhow::Result<Option<Self>> {
        let chat = validate_chat(chat)?;
        Ok(RemoteConfig::load().map(|config| Self {
            config,
            chat,
            http: client(),
        }))
    }

    pub fn chat(&self) -> &str {
        &self.chat
    }

    async fn post(&self, path: &str, body: Value) -> anyhow::Result<Value> {
        let response = self
            .http
            .post(self.config.endpoint(path))
            .bearer_auth(&self.config.token)
            .json(&body)
            .send()
            .await?;
        if !response.status().is_success() {
            anyhow::bail!("the Server refused ({})", error_text(response).await);
        }
        Ok(response.json().await?)
    }

    /// Post a one-way message. An empty `title` sends the text alone.
    pub async fn notify(&self, title: &str, text: &str) -> anyhow::Result<()> {
        let mut body = serde_json::json!({ "chat": self.chat, "text": text });
        if !title.trim().is_empty() {
            body["title"] = Value::String(title.to_string());
        }
        self.post("/api/code/notify", body).await.map(|_| ())
    }

    /// Post an approval card. `options` are `(value, label)` pairs, at most
    /// five; the answer is reported as the chosen `value`. The Server expires
    /// it after 30 minutes.
    pub async fn request_approval(
        &self,
        title: &str,
        text: &str,
        options: &[(String, String)],
    ) -> anyhow::Result<RemoteApproval> {
        self.request_approval_with_ttl(title, text, options, None)
            .await
    }

    /// [`Self::request_approval`] with an explicit lifetime (the Server
    /// clamps it to 30 s – 24 h).
    pub async fn request_approval_with_ttl(
        &self,
        title: &str,
        text: &str,
        options: &[(String, String)],
        ttl: Option<Duration>,
    ) -> anyhow::Result<RemoteApproval> {
        let options: Vec<Value> = options
            .iter()
            .map(|(value, label)| serde_json::json!({ "value": value, "label": label }))
            .collect();
        let mut body = serde_json::json!({
            "chat": self.chat,
            "title": title,
            "text": text,
            "options": options,
        });
        if let Some(ttl) = ttl {
            body["ttl_secs"] = Value::from(ttl.as_secs());
        }
        let created = self.post("/api/code/approvals", body).await?;
        let id = created
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| anyhow::anyhow!("the Server did not return an approval id"))?;
        Ok(RemoteApproval {
            id: id.to_string(),
            expires_at: created
                .get("expires_at")
                .and_then(Value::as_str)
                .map(str::to_string),
        })
    }

    fn approval_url(&self, id: &str) -> String {
        self.config.endpoint(&format!("/api/code/approvals/{id}"))
    }

    /// Current state of approval `id`.
    pub async fn poll(&self, id: &str) -> anyhow::Result<RemoteStatus> {
        let response = self
            .http
            .get(self.approval_url(id))
            .bearer_auth(&self.config.token)
            .send()
            .await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(RemoteStatus::Gone);
        }
        if !response.status().is_success() {
            anyhow::bail!("the Server refused ({})", error_text(response).await);
        }
        let body: Value = response.json().await?;
        let field = |key: &str| body.get(key).and_then(Value::as_str).map(str::to_string);
        Ok(match field("status").as_deref() {
            Some("pending") => RemoteStatus::Pending,
            Some("answered") => RemoteStatus::Answered {
                value: field("value").unwrap_or_default(),
                answered_by: field("answered_by"),
            },
            Some("expired") => RemoteStatus::Expired,
            Some("cancelled") => RemoteStatus::Cancelled,
            other => anyhow::bail!("unexpected approval status {other:?}"),
        })
    }

    /// Withdraw approval `id` (e.g. it was answered in the terminal). The
    /// card in the chat is updated to say so. Unknown ids are not an error.
    pub async fn cancel(&self, id: &str) -> anyhow::Result<()> {
        let response = self
            .http
            .delete(self.approval_url(id))
            .query(&[("reason", "answered_locally")])
            .bearer_auth(&self.config.token)
            .send()
            .await?;
        if response.status().is_success() || response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(());
        }
        anyhow::bail!("the Server refused ({})", error_text(response).await)
    }

    /// Poll approval `id` every `poll_interval` until it is answered (returns
    /// the chosen value) or expires, is cancelled or disappears (`None`).
    ///
    /// When `cancel` flips to `true` (the user answered in the terminal),
    /// the approval is withdrawn on the Server and `None` is returned.
    /// Transient network errors are retried.
    pub async fn wait_for_answer(
        &self,
        id: &str,
        mut cancel: watch::Receiver<bool>,
        poll_interval: Duration,
    ) -> Option<String> {
        let poll_interval = poll_interval.max(Duration::from_millis(10));
        let mut watching = true;
        loop {
            if *cancel.borrow() {
                let _ = self.cancel(id).await;
                return None;
            }
            match self.poll(id).await {
                Ok(RemoteStatus::Answered { value, .. }) => return Some(value),
                Ok(RemoteStatus::Pending) | Err(_) => {}
                Ok(_) => return None,
            }
            if watching {
                tokio::select! {
                    changed = cancel.changed() => {
                        // A dropped sender can no longer cancel; keep polling.
                        if changed.is_err() {
                            watching = false;
                        }
                    }
                    _ = tokio::time::sleep(poll_interval) => {}
                }
            } else {
                tokio::time::sleep(poll_interval).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Clone)]
    struct Seen {
        method: String,
        path: String,
        auth: String,
        body: String,
    }

    type Handler = dyn Fn(&Seen) -> (u16, String) + Send + Sync;

    /// A tiny blocking HTTP/1.1 server (one request per connection).
    fn mock_server(handler: Arc<Handler>) -> (String, Arc<Mutex<Vec<Seen>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request_line = String::new();
                if reader.read_line(&mut request_line).is_err() {
                    continue;
                }
                let mut parts = request_line.split_whitespace();
                let method = parts.next().unwrap_or("").to_string();
                let path = parts.next().unwrap_or("").to_string();
                let mut auth = String::new();
                let mut length = 0usize;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        break;
                    }
                    let line = line.trim_end();
                    if line.is_empty() {
                        break;
                    }
                    if let Some((name, value)) = line.split_once(':') {
                        match name.to_ascii_lowercase().as_str() {
                            "authorization" => auth = value.trim().to_string(),
                            "content-length" => length = value.trim().parse().unwrap_or(0),
                            _ => {}
                        }
                    }
                }
                let mut body = vec![0u8; length];
                let _ = reader.read_exact(&mut body);
                let request = Seen {
                    method,
                    path,
                    auth,
                    body: String::from_utf8_lossy(&body).to_string(),
                };
                let (status, payload) = handler(&request);
                log.lock().unwrap().push(request);
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{payload}",
                    payload.len()
                );
            }
        });
        (url, seen)
    }

    fn notifier(url: &str) -> RemoteNotifier {
        RemoteNotifier::new(
            RemoteConfig {
                url: url.to_string(),
                token: "mcd_test".into(),
                device_id: "d1".into(),
                label: "laptop".into(),
            },
            "telegram:42",
        )
        .unwrap()
    }

    fn options() -> Vec<(String, String)> {
        vec![
            ("approve".into(), "Approve".into()),
            ("deny".into(), "Deny".into()),
        ]
    }

    #[test]
    fn chat_spec_is_checked_locally() {
        assert!(validate_chat("telegram:1").is_ok());
        assert!(validate_chat("slack:C1:1700.1").is_ok());
        assert!(validate_chat("telegram").is_err());
        assert!(validate_chat(":1").is_err());
        assert!(validate_chat("telegram: ").is_err());
        assert!(RemoteNotifier::from_pairing("nope").is_err());
        assert!(RemoteStatus::Expired.is_final());
        assert!(!RemoteStatus::Pending.is_final());
    }

    #[tokio::test]
    async fn notify_and_request_approval_post_the_documented_payloads() {
        let (url, seen) = mock_server(Arc::new(|req: &Seen| {
            match req.path.as_str() {
            "/api/code/notify" => (200, r#"{"ok":true,"delivery":"delivered"}"#.into()),
            "/api/code/approvals" => (
                200,
                r#"{"ok":true,"id":"abc123","status":"pending","expires_at":"2026-11-05T10:30:00Z"}"#
                    .into(),
            ),
            _ => (404, "not found".into()),
        }
        }));
        let n = notifier(&url);
        n.notify("Checks failed", "cargo test: 2 failures")
            .await
            .unwrap();
        let approval = n
            .request_approval_with_ttl(
                "Run cargo test?",
                "bash: cargo test",
                &options(),
                Some(Duration::from_secs(600)),
            )
            .await
            .unwrap();
        assert_eq!(approval.id, "abc123");
        assert_eq!(approval.expires_at.as_deref(), Some("2026-11-05T10:30:00Z"));

        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 2);
        assert!(
            seen.iter()
                .all(|r| r.method == "POST" && r.auth == "Bearer mcd_test")
        );
        let notify: Value = serde_json::from_str(&seen[0].body).unwrap();
        assert_eq!(notify["chat"], "telegram:42");
        assert_eq!(notify["title"], "Checks failed");
        assert_eq!(notify["text"], "cargo test: 2 failures");
        let create: Value = serde_json::from_str(&seen[1].body).unwrap();
        assert_eq!(create["ttl_secs"], 600);
        assert_eq!(
            create["options"],
            serde_json::json!([
                {"value": "approve", "label": "Approve"},
                {"value": "deny", "label": "Deny"}
            ])
        );
    }

    #[tokio::test]
    async fn server_errors_surface_with_the_reason() {
        let (url, _) = mock_server(Arc::new(|_: &Seen| {
            (
                403,
                "chat telegram:42 is not a control chat; add 42 to control_chat_ids".into(),
            )
        }));
        let err = notifier(&url)
            .request_approval("t", "x", &options())
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("403"), "{err}");
        assert!(err.contains("control_chat_ids"), "{err}");
    }

    #[tokio::test]
    async fn poll_maps_statuses_and_wait_returns_the_answer() {
        let polls = Arc::new(Mutex::new(0usize));
        let counter = polls.clone();
        let (url, _) = mock_server(Arc::new(move |req: &Seen| match req.path.as_str() {
            "/api/code/approvals/a1" => {
                let mut n = counter.lock().unwrap();
                *n += 1;
                if *n < 3 {
                    (200, r#"{"status":"pending"}"#.into())
                } else {
                    (
                        200,
                        r#"{"status":"answered","value":"deny","answered_by":"telegram:ann"}"#
                            .into(),
                    )
                }
            }
            "/api/code/approvals/e1" => (200, r#"{"status":"expired"}"#.into()),
            "/api/code/approvals/c1" => (200, r#"{"status":"cancelled"}"#.into()),
            _ => (404, "approval not found".into()),
        }));
        let n = notifier(&url);
        assert_eq!(n.poll("e1").await.unwrap(), RemoteStatus::Expired);
        assert_eq!(n.poll("c1").await.unwrap(), RemoteStatus::Cancelled);
        assert_eq!(n.poll("zz").await.unwrap(), RemoteStatus::Gone);

        let (_tx, rx) = watch::channel(false);
        let answer = n
            .wait_for_answer("a1", rx.clone(), Duration::from_millis(10))
            .await;
        assert_eq!(answer.as_deref(), Some("deny"));
        assert_eq!(*polls.lock().unwrap(), 3);
        assert_eq!(
            n.poll("a1").await.unwrap(),
            RemoteStatus::Answered {
                value: "deny".into(),
                answered_by: Some("telegram:ann".into())
            }
        );
        assert_eq!(
            n.wait_for_answer("e1", rx.clone(), Duration::from_millis(10))
                .await,
            None
        );
        assert_eq!(
            n.wait_for_answer("zz", rx, Duration::from_millis(10)).await,
            None
        );
    }

    #[tokio::test]
    async fn local_cancel_withdraws_the_card() {
        let (url, seen) = mock_server(Arc::new(|req: &Seen| match req.method.as_str() {
            "DELETE" => (
                200,
                r#"{"ok":true,"cancelled":true,"status":"cancelled"}"#.into(),
            ),
            _ => (200, r#"{"status":"pending"}"#.into()),
        }));
        let n = notifier(&url);
        let (tx, rx) = watch::channel(false);
        let waiter = {
            let n = n.clone();
            tokio::spawn(
                async move { n.wait_for_answer("p1", rx, Duration::from_millis(20)).await },
            )
        };
        tokio::time::sleep(Duration::from_millis(60)).await;
        tx.send(true).unwrap();
        let answer = tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(answer, None);
        let seen = seen.lock().unwrap().clone();
        let delete = seen.iter().find(|r| r.method == "DELETE").unwrap();
        assert_eq!(
            delete.path,
            "/api/code/approvals/p1?reason=answered_locally"
        );
        // Unknown ids are not an error when cancelling.
        let (url, _) = mock_server(Arc::new(|_: &Seen| (404, "approval not found".into())));
        notifier(&url).cancel("gone").await.unwrap();
    }
}
