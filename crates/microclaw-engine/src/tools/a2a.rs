use async_trait::async_trait;
use serde_json::json;

use super::{schema_object, Tool, ToolResult};
use crate::a2a::{
    normalize_base_url, normalize_peer_name, A2AMessageRequest, A2AMessageResponse,
    A2A_AGENT_CARD_PATH, A2A_MESSAGE_PATH, A2A_PROTOCOL_VERSION,
};
use crate::config::Config;
use crate::http_client::default_llm_user_agent;
use crate::internal::tool_runtime::runtime::HIGH_RISK_APPROVED_KEY as A2A_HIGH_RISK_APPROVED_KEY;
use microclaw_core::llm_types::ToolDefinition;

pub struct A2AListPeersTool {
    config: Config,
}

impl A2AListPeersTool {
    pub fn new(config: &Config) -> Self {
        Self {
            config: config.clone(),
        }
    }
}

pub struct A2ASendTool {
    client: reqwest::Client,
    config: Config,
}

impl A2ASendTool {
    pub fn new(config: &Config) -> Self {
        let user_agent = format!("{}/a2a", default_llm_user_agent());
        let client = reqwest::Client::builder()
            .user_agent(user_agent)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            client,
            config: config.clone(),
        }
    }
}

#[async_trait]
impl Tool for A2AListPeersTool {
    fn name(&self) -> &str {
        "a2a_list_peers"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: self.name().into(),
            description:
                "List configured agent-to-agent peers that can receive remote tasks over HTTP."
                    .into(),
            input_schema: schema_object(json!({}), &[]),
        }
    }

    async fn execute(&self, _input: serde_json::Value) -> ToolResult {
        if !self.config.a2a.enabled {
            return ToolResult::error("A2A is disabled in config (`a2a.enabled: true`).".into());
        }
        let peers = self
            .config
            .a2a
            .peers
            .iter()
            .filter(|(_, peer)| peer.enabled)
            .map(|(name, peer)| {
                json!({
                    "peer": name,
                    "base_url": peer.base_url,
                    "message_endpoint": format!("{}{}", peer.base_url, A2A_MESSAGE_PATH),
                    "agent_card_endpoint": format!("{}{}", peer.base_url, A2A_AGENT_CARD_PATH),
                    "default_session_key": peer.default_session_key,
                    "description": peer.description,
                    "has_bearer_token": peer.bearer_token.is_some(),
                })
            })
            .collect::<Vec<_>>();
        ToolResult::success(
            serde_json::to_string_pretty(&json!({
                "protocol_version": A2A_PROTOCOL_VERSION,
                "peers": peers
            }))
            .unwrap_or_else(|_| "{\"peers\":[]}".to_string()),
        )
    }
}

#[async_trait]
impl Tool for A2ASendTool {
    fn name(&self) -> &str {
        "a2a_send"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: self.name().into(),
            description:
                "Send a task or question to a configured remote MicroClaw peer via the A2A HTTP protocol."
                    .into(),
            input_schema: schema_object(
                json!({
                    "peer": {
                        "type": "string",
                        "description": "Configured peer name from `a2a.peers`."
                    },
                    "message": {
                        "type": "string",
                        "description": "The task or question to send to the remote agent."
                    },
                    "session_key": {
                        "type": "string",
                        "description": "Optional remote session key. Defaults to the peer's configured default or `a2a:<peer>`."
                    },
                    "timeout_secs": {
                        "type": "integer",
                        "description": "HTTP timeout in seconds."
                    }
                }),
                &["peer", "message"],
            ),
        }
    }

    async fn execute(&self, input: serde_json::Value) -> ToolResult {
        if !self.config.a2a.enabled {
            return ToolResult::error("A2A is disabled in config (`a2a.enabled: true`).".into());
        }

        let Some(peer_name) = input.get("peer").and_then(|v| v.as_str()) else {
            return ToolResult::error("Missing required parameter: peer".into());
        };
        let Some(message) = input.get("message").and_then(|v| v.as_str()) else {
            return ToolResult::error("Missing required parameter: message".into());
        };
        let message = message.trim();
        if message.is_empty() {
            return ToolResult::error("Parameter `message` cannot be empty".into());
        }
        let Some(peer_key) = normalize_peer_name(peer_name) else {
            return ToolResult::error("Parameter `peer` cannot be empty".into());
        };
        let Some(peer) = self.config.a2a.peers.get(&peer_key) else {
            return ToolResult::error(format!("Unknown A2A peer: {peer_name}"));
        };
        if !peer.enabled {
            return ToolResult::error(format!("A2A peer `{peer_name}` is disabled"));
        }
        if peer.trust == crate::config::A2ATrust::Sandboxed {
            // A sandboxed peer makes this specific send high-risk regardless
            // of which chat invoked it (same shape as the bash
            // dangerous-pattern gate): the executor sees `approval_required`
            // and pauses for explicit operator approval before anything
            // leaves for the peer.
            let already_approved = input
                .get(A2A_HIGH_RISK_APPROVED_KEY)
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if !already_approved {
                return ToolResult::error(format!(
                    "Approval required: A2A peer `{peer_name}` has trust tier `sandboxed`. \
                     Operator must explicitly approve before this message is sent."
                ))
                .with_error_type("approval_required");
            }
        }
        let Some(base_url) = normalize_base_url(&peer.base_url) else {
            return ToolResult::error(format!("A2A peer `{peer_name}` has invalid base_url"));
        };
        let session_key = input
            .get("session_key")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(ToOwned::to_owned)
            .or_else(|| peer.default_session_key.clone())
            .unwrap_or_else(|| format!("a2a:{peer_key}"));
        let timeout_secs = input
            .get("timeout_secs")
            .and_then(|v| v.as_u64())
            .unwrap_or_else(|| self.config.tool_timeout_secs(self.name(), 60));
        let body = A2AMessageRequest {
            session_key: Some(session_key.clone()),
            sender_name: None,
            source_agent: Some(crate::a2a::local_agent_name(&self.config)),
            source_url: self.config.a2a.public_base_url.clone(),
            message: message.to_string(),
        };

        let mut request = self
            .client
            .post(format!("{base_url}{A2A_MESSAGE_PATH}"))
            .timeout(std::time::Duration::from_secs(timeout_secs))
            .header("x-microclaw-a2a-version", A2A_PROTOCOL_VERSION)
            .json(&body);
        if let Some(token) = peer.bearer_token.as_deref() {
            request = request.bearer_auth(token);
        }
        let response = match request.send().await {
            Ok(resp) => resp,
            Err(err) => {
                return ToolResult::error(format!("A2A request to `{peer_name}` failed: {err}"))
            }
        };
        let status = response.status();
        let body_text = match response.text().await {
            Ok(text) => text,
            Err(err) => {
                return ToolResult::error(format!(
                    "A2A peer `{peer_name}` returned unreadable body: {err}"
                ))
            }
        };
        if !status.is_success() {
            return ToolResult::error(format!(
                "A2A peer `{peer_name}` returned HTTP {}: {}",
                status.as_u16(),
                body_text.trim()
            ))
            .with_status_code(status.as_u16().into());
        }
        let parsed: A2AMessageResponse = match serde_json::from_str(&body_text) {
            Ok(body) => body,
            Err(err) => {
                return ToolResult::error(format!(
                    "A2A peer `{peer_name}` returned invalid JSON: {err}"
                ))
            }
        };
        ToolResult::success(
            serde_json::to_string_pretty(&json!({
                "peer": peer_key,
                "protocol_version": parsed.protocol_version,
                "agent_name": parsed.agent_name,
                "session_key": parsed.session_key,
                "response": parsed.response
            }))
            .unwrap_or(parsed.response),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_a2a_list_peers_returns_enabled_peers() {
        let mut cfg = Config::test_defaults();
        cfg.a2a.enabled = true;
        cfg.a2a.peers.insert(
            "planner".into(),
            crate::config::A2APeerConfig {
                enabled: true,
                base_url: "https://planner.example.com".into(),
                bearer_token: Some("secret".into()),
                description: Some("plans".into()),
                default_session_key: Some("a2a:planner".into()),
                trust: Default::default(),
            },
        );
        let tool = A2AListPeersTool::new(&cfg);
        let result = tool.execute(json!({})).await;
        assert!(!result.is_error);
        assert!(result.content.contains("\"peer\": \"planner\""));
    }

    #[tokio::test]
    async fn test_a2a_send_to_sandboxed_peer_requires_approval() {
        let mut cfg = Config::test_defaults();
        cfg.a2a.enabled = true;
        cfg.a2a.peers.insert(
            "risky".into(),
            crate::config::A2APeerConfig {
                enabled: true,
                base_url: "https://risky.example.com".into(),
                bearer_token: None,
                description: None,
                default_session_key: None,
                trust: crate::config::A2ATrust::Sandboxed,
            },
        );
        let tool = A2ASendTool::new(&cfg);
        let result = tool
            .execute(json!({"peer": "risky", "message": "do work"}))
            .await;
        assert!(result.is_error);
        assert_eq!(result.error_type.as_deref(), Some("approval_required"));
        // No network request was attempted: the gate fires before the URL
        // is even normalized.
        assert!(result.content.contains("sandboxed"));
    }

    #[tokio::test]
    async fn test_a2a_send_posts_to_peer() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4096];
            loop {
                let bytes_read = stream.read(&mut buffer).await.unwrap();
                if bytes_read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..bytes_read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") && request.ends_with(b"}")
                {
                    break;
                }
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with(&format!("POST {A2A_MESSAGE_PATH} HTTP/1.1")));
            assert!(request
                .to_ascii_lowercase()
                .contains("authorization: bearer secret"));
            assert!(request.contains("\"message\":\"do work\""));

            let response = serde_json::to_vec(&A2AMessageResponse {
                ok: true,
                protocol_version: A2A_PROTOCOL_VERSION.to_string(),
                agent_name: "Worker".into(),
                session_key: "a2a:worker".into(),
                response: "done".into(),
            })
            .unwrap();
            let headers = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                response.len()
            );
            stream.write_all(headers.as_bytes()).await.unwrap();
            stream.write_all(&response).await.unwrap();
        });

        let mut cfg = Config::test_defaults();
        cfg.a2a.enabled = true;
        cfg.a2a.agent_name = Some("Planner".into());
        cfg.a2a.peers.insert(
            "worker".into(),
            crate::config::A2APeerConfig {
                enabled: true,
                base_url: format!("http://{}", addr),
                bearer_token: Some("secret".into()),
                description: None,
                default_session_key: None,
                trust: Default::default(),
            },
        );
        let tool = A2ASendTool::new(&cfg);
        let result = tool
            .execute(json!({"peer":"worker","message":"do work","timeout_secs":5}))
            .await;
        assert!(!result.is_error, "{}", result.content);
        assert!(result.content.contains("\"response\": \"done\""));
    }
}
