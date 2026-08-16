use super::*;

pub(crate) fn default_rtk_binary_path() -> String {
    "rtk".to_string()
}

/// Opt-in RTK (Rust Token Killer) integration for the bash tool.
/// When enabled, commands are passed through `rtk rewrite` before execution;
/// commands RTK recognizes run as `rtk <command>` and return compressed
/// output, reducing token consumption. Commands without an RTK equivalent
/// (or any rtk failure) run unchanged.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RtkConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Path to the rtk binary. Defaults to `rtk` resolved from PATH.
    #[serde(default = "default_rtk_binary_path")]
    pub binary_path: String,
}

impl Default for RtkConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            binary_path: default_rtk_binary_path(),
        }
    }
}

pub(crate) fn default_a2a_enabled() -> bool {
    false
}

pub(crate) fn default_clawhub_registry() -> String {
    "https://clawhub.ai".into()
}

pub(crate) fn default_true() -> bool {
    true
}

/// Load-time verification policy for ClawHub-managed skill trees.
///
/// `block` (default) makes a skill whose on-disk tree no longer matches the
/// lockfile hash unavailable until it is reinstalled; `warn` only logs;
/// `off` disables the check. Entries installed before tree hashing existed
/// (no recorded hash) always warn instead of blocking.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClawHubVerifyMode {
    Off,
    Warn,
    #[default]
    Block,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClawHubConfig {
    /// ClawHub registry URL
    #[serde(default = "default_clawhub_registry", rename = "clawhub_registry")]
    pub registry: String,
    /// ClawHub API token (optional)
    #[serde(default, rename = "clawhub_token")]
    pub token: Option<String>,
    /// Enable agent tools for ClawHub (search, install)
    #[serde(default = "default_true", rename = "clawhub_agent_tools_enabled")]
    pub agent_tools_enabled: bool,
    /// Skip security warnings for ClawHub installs
    #[serde(default, rename = "clawhub_skip_security_warnings")]
    pub skip_security_warnings: bool,
    /// Verify installed skill trees against the lockfile whenever skills load
    #[serde(default, rename = "clawhub_verify_on_load")]
    pub verify_on_load: ClawHubVerifyMode,
}

impl Default for ClawHubConfig {
    fn default() -> Self {
        Self {
            registry: default_clawhub_registry(),
            token: None,
            agent_tools_enabled: default_true(),
            skip_security_warnings: false,
            verify_on_load: ClawHubVerifyMode::default(),
        }
    }
}

/// Named per-peer trust tier for outbound A2A sends. `limited` (default)
/// keeps the historical behavior; `sandboxed` treats a send to this peer
/// as high-risk — on web/control chats it requires the explicit approval
/// flow before the message leaves. `trusted` is currently equivalent to
/// `limited` and reserved for future capability widening; tiers never
/// lower existing guardrails.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum A2ATrust {
    Trusted,
    #[default]
    Limited,
    Sandboxed,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct A2APeerConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub base_url: String,
    #[serde(default)]
    pub bearer_token: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub default_session_key: Option<String>,
    /// Trust tier for sends to this peer. Default: limited.
    #[serde(default)]
    pub trust: A2ATrust,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct A2AConfig {
    #[serde(default = "default_a2a_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub public_base_url: Option<String>,
    #[serde(default)]
    pub agent_name: Option<String>,
    #[serde(default)]
    pub agent_description: Option<String>,
    #[serde(default)]
    pub shared_tokens: Vec<String>,
    #[serde(default)]
    pub peers: HashMap<String, A2APeerConfig>,
}

impl Default for A2AConfig {
    fn default() -> Self {
        Self {
            enabled: default_a2a_enabled(),
            public_base_url: None,
            agent_name: None,
            agent_description: None,
            shared_tokens: Vec::new(),
            peers: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use crate::config::test_prelude::*;

    #[test]
    fn test_post_deserialize_normalizes_a2a_config() {
        let mut config = Config::test_defaults();
        config.a2a.enabled = true;
        config.a2a.public_base_url = Some(" https://mc.example.com/ ".into());
        config.a2a.agent_name = Some(" Planner ".into());
        config.a2a.agent_description = Some(" Plans ".into());
        config.a2a.shared_tokens = vec!["  ".into(), " secret ".into()];
        config.a2a.peers.insert(
            " Worker ".into(),
            A2APeerConfig {
                enabled: true,
                base_url: " https://worker.example.com/ ".into(),
                bearer_token: Some(" token ".into()),
                description: Some(" executes ".into()),
                default_session_key: Some(" team/work ".into()),
                trust: Default::default(),
            },
        );

        config.post_deserialize().unwrap();

        assert_eq!(
            config.a2a.public_base_url.as_deref(),
            Some("https://mc.example.com")
        );
        assert_eq!(config.a2a.agent_name.as_deref(), Some("Planner"));
        assert_eq!(config.a2a.agent_description.as_deref(), Some("Plans"));
        assert_eq!(config.a2a.shared_tokens, vec!["secret".to_string()]);
        let peer = config.a2a.peers.get("worker").unwrap();
        assert_eq!(peer.base_url, "https://worker.example.com");
        assert_eq!(peer.bearer_token.as_deref(), Some("token"));
        assert_eq!(peer.description.as_deref(), Some("executes"));
        assert_eq!(peer.default_session_key.as_deref(), Some("team/work"));
    }
}
