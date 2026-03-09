use async_trait::async_trait;
use serde_json::json;

use super::{schema_object, Tool, ToolResult};
use crate::a2a::{
    normalize_base_url, normalize_peer_name, A2AMessageRequest, A2AMessageResponse,
    A2A_AGENT_CARD_PATH, A2A_MESSAGE_PATH, A2A_PROTOCOL_VERSION,
};
use crate::config::Config;
use crate::http_client::default_llm_user_agent;
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
            .unwrap_or_else(|_| parsed.response),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{extract::State, routing::post, Json, Router};
    use serde_json::Value;
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
            },
        );
        let tool = A2AListPeersTool::new(&cfg);
        let result = tool.execute(json!({})).await;
        assert!(!result.is_error);
        assert!(result.content.contains("\"peer\": \"planner\""));
    }

    #[tokio::test]
    async fn test_a2a_send_posts_to_peer() {
        async fn handler(
            State(expected): State<String>,
            headers: axum::http::HeaderMap,
            Json(body): Json<Value>,
        ) -> Json<A2AMessageResponse> {
            assert_eq!(
                headers
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default(),
                format!("Bearer {expected}")
            );
            assert_eq!(body["message"], "do work");
            Json(A2AMessageResponse {
                ok: true,
                protocol_version: A2A_PROTOCOL_VERSION.to_string(),
                agent_name: "Worker".into(),
                session_key: "a2a:worker".into(),
                response: "done".into(),
            })
        }

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new()
            .route(A2A_MESSAGE_PATH, post(handler))
            .with_state("secret".to_string());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
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
