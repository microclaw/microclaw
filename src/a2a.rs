use serde::{Deserialize, Serialize};

use crate::config::Config;

pub const A2A_PROTOCOL_VERSION: &str = "microclaw-a2a/v1";
pub const A2A_AGENT_CARD_PATH: &str = "/api/a2a/agent-card";
pub const A2A_MESSAGE_PATH: &str = "/api/a2a/message";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct A2AAgentCard {
    pub protocol_version: String,
    pub agent_id: String,
    pub agent_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_base_url: Option<String>,
    pub endpoints: A2AEndpoints,
    pub capabilities: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct A2AEndpoints {
    pub agent_card: String,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct A2AMessageRequest {
    #[serde(default)]
    pub session_key: Option<String>,
    #[serde(default)]
    pub sender_name: Option<String>,
    #[serde(default)]
    pub source_agent: Option<String>,
    #[serde(default)]
    pub source_url: Option<String>,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct A2AMessageResponse {
    pub ok: bool,
    pub protocol_version: String,
    pub agent_name: String,
    pub session_key: String,
    pub response: String,
}

pub fn normalize_peer_name(name: &str) -> Option<String> {
    let trimmed = name.trim().to_ascii_lowercase();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

pub fn normalize_base_url(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    let parsed = reqwest::Url::parse(trimmed).ok()?;
    match parsed.scheme() {
        "http" | "https" => Some(trimmed.to_string()),
        _ => None,
    }
}

pub fn local_agent_name(config: &Config) -> String {
    config
        .a2a
        .agent_name
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            let bot = config.bot_username.trim();
            if bot.is_empty() {
                None
            } else {
                Some(bot.to_string())
            }
        })
        .unwrap_or_else(|| "MicroClaw".to_string())
}

pub fn default_session_key_for_source(source_agent: Option<&str>) -> String {
    source_agent
        .and_then(normalize_peer_name)
        .map(|v| format!("a2a:{v}"))
        .unwrap_or_else(|| "a2a:remote".to_string())
}

pub fn build_agent_card(config: &Config) -> A2AAgentCard {
    let base_url = config
        .a2a
        .public_base_url
        .as_deref()
        .and_then(normalize_base_url);
    let agent_name = local_agent_name(config);
    let agent_id = agent_name
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string();
    let prefix = base_url.clone().unwrap_or_default();
    A2AAgentCard {
        protocol_version: A2A_PROTOCOL_VERSION.to_string(),
        agent_id: if agent_id.is_empty() {
            "microclaw".to_string()
        } else {
            agent_id
        },
        agent_name,
        description: config.a2a.agent_description.clone(),
        public_base_url: base_url,
        endpoints: A2AEndpoints {
            agent_card: format!("{prefix}{A2A_AGENT_CARD_PATH}"),
            message: format!("{prefix}{A2A_MESSAGE_PATH}"),
        },
        capabilities: vec!["sync-message".to_string()],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{A2APeerConfig, Config};

    #[test]
    fn test_normalize_base_url() {
        assert_eq!(
            normalize_base_url(" https://example.com/base/ "),
            Some("https://example.com/base".to_string())
        );
        assert_eq!(normalize_base_url("file:///tmp"), None);
    }

    #[test]
    fn test_build_agent_card_uses_config() {
        let mut cfg = Config::test_defaults();
        cfg.a2a.enabled = true;
        cfg.a2a.agent_name = Some("Planner".into());
        cfg.a2a.agent_description = Some("Routes work".into());
        cfg.a2a.public_base_url = Some("https://mc.example.com/".into());
        cfg.a2a.peers.insert(
            "worker".into(),
            A2APeerConfig {
                enabled: true,
                base_url: "https://worker.example.com".into(),
                bearer_token: None,
                description: None,
                default_session_key: None,
            },
        );

        let card = build_agent_card(&cfg);
        assert_eq!(card.agent_name, "Planner");
        assert_eq!(card.agent_id, "planner");
        assert_eq!(
            card.endpoints.message,
            "https://mc.example.com/api/a2a/message"
        );
    }
}
