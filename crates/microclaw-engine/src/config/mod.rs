use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::codex_auth::{
    codex_auth_file_has_access_token, is_openai_codex_provider, is_qwen_portal_provider,
    provider_allows_empty_api_key, qwen_oauth_file_has_access_token,
};
use crate::plugins::PluginsConfig;
use microclaw_core::error::MicroClawError;
use microclaw_core::redact::OutputGuardrailConfig;
pub use microclaw_tools::egress::{EgressPolicyConfig, EgressPolicyMode};
pub use microclaw_tools::sandbox::{SandboxBackend, SandboxConfig, SandboxMode, SecurityProfile};
pub use microclaw_tools::types::WorkingDirIsolation;
use microclaw_tools::web_content_validation::WebContentValidationConfig;
use microclaw_tools::web_fetch::WebFetchUrlValidationConfig;
use microclaw_tools::web_search::SearchProviderConfig;

pub mod autonomy;
pub mod core;
pub mod defaults;
pub mod governance;
pub mod integrations;
pub mod llm_profiles;
pub mod media;
pub mod subagents;
#[cfg(test)]
pub(crate) mod test_prelude;

pub use self::autonomy::*;
pub use self::core::*;
pub use self::defaults::*;
pub use self::governance::*;
pub use self::integrations::*;
pub use self::llm_profiles::*;
pub use self::media::*;
pub use self::subagents::*;

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use crate::config::test_prelude::*;

    #[test]
    fn test_config_default_values() {
        let mut config = test_config();
        config.openai_api_key = Some("sk-test".into());
        config.timezone = "US/Eastern".into();
        config.allowed_groups = vec![123, 456];
        config.control_chat_ids = vec![999];
        assert_eq!(config.model, "claude-sonnet-4-5-20250929");
        assert!(config.data_dir.ends_with(".microclaw"));
        assert!(std::path::PathBuf::from(&config.working_dir)
            .ends_with(std::path::Path::new(".microclaw").join("working_dir")));
        assert_eq!(config.openai_api_key.as_deref(), Some("sk-test"));
        assert_eq!(config.timezone, "US/Eastern");
        assert_eq!(config.allowed_groups, vec![123, 456]);
        assert_eq!(config.control_chat_ids, vec![999]);
    }

    #[test]
    fn test_llm_provider_overrides_support_provider_preset_and_legacy_llm_provider_keys() {
        let mut config = test_config();
        config.channels = serde_yaml::from_str(
            r#"
telegram:
  enabled: true
  provider_preset: channel-default
  default_account: sales
  accounts:
    sales:
      enabled: true
      bot_token: tg_sales
      provider_preset: sales-preset
    ops:
      enabled: true
      bot_token: tg_ops
      llm_provider: ops-legacy
discord:
  enabled: true
  llm_provider: discord-legacy
"#,
        )
        .unwrap();

        assert_eq!(
            config.provider_override_for_channel("telegram").as_deref(),
            Some("sales-preset")
        );
        assert_eq!(
            config
                .provider_override_for_channel("telegram.ops")
                .as_deref(),
            Some("ops-legacy")
        );
        assert_eq!(
            config.provider_override_for_channel("discord").as_deref(),
            Some("discord-legacy")
        );

        let overrides = config.llm_provider_overrides();
        assert_eq!(
            overrides.get("telegram").map(String::as_str),
            Some("sales-preset")
        );
        assert_eq!(
            overrides.get("telegram.ops").map(String::as_str),
            Some("ops-legacy")
        );
        assert_eq!(
            overrides.get("discord").map(String::as_str),
            Some("discord-legacy")
        );
    }

    #[test]
    fn test_runtime_and_skills_dirs_from_root_data_dir() {
        let mut config = test_config();
        config.data_dir = "./microclaw.data".into();

        let runtime = std::path::PathBuf::from(config.runtime_data_dir());
        let skills = std::path::PathBuf::from(config.skills_data_dir());

        assert!(runtime.ends_with(std::path::Path::new("microclaw.data").join("runtime")));
        assert!(skills.ends_with(std::path::Path::new("microclaw.data").join("skills")));
    }

    #[test]
    fn test_runtime_and_skills_dirs_from_runtime_data_dir() {
        let mut config = test_config();
        config.data_dir = "./microclaw.data".into();

        let runtime = std::path::PathBuf::from(config.runtime_data_dir());
        let skills = std::path::PathBuf::from(config.skills_data_dir());

        assert!(runtime.ends_with(std::path::Path::new("microclaw.data").join("runtime")));
        assert!(skills.ends_with(std::path::Path::new("microclaw.data").join("skills")));
    }

    #[test]
    fn test_skills_dir_uses_config_override() {
        let mut config = test_config();
        config.skills_dir = Some("./microclaw.data/skills".to_string());
        let skills = std::path::PathBuf::from(config.skills_data_dir());
        assert!(skills.ends_with(std::path::Path::new("microclaw.data").join("skills")));
    }

    #[test]
    fn test_post_deserialize_egress_policy_blocks_private_endpoint() {
        let mut config = test_config();
        config.llm_base_url = Some("http://127.0.0.1:11434/v1".into());
        config.egress_policy.mode = EgressPolicyMode::Block;

        let err = config.post_deserialize().unwrap_err().to_string();

        assert!(err.contains("blocked by egress policy"), "{err}");
        assert!(err.contains("127.0.0.1"), "{err}");
    }

    #[test]
    fn test_post_deserialize_egress_allowlist_applies_to_configured_endpoint() {
        let mut config = test_config();
        config.llm_base_url = Some("https://api.example.test/v1".into());
        config.clawhub.agent_tools_enabled = false;
        config.egress_policy = EgressPolicyConfig {
            mode: EgressPolicyMode::Block,
            allow_hosts: vec!["api.example.test".into()],
            block_private_ips: false,
            ..Default::default()
        };

        config.post_deserialize().unwrap();
    }

    #[test]
    fn test_post_deserialize_egress_ignores_non_endpoint_urls() {
        let mut config = test_config();
        config.clawhub.agent_tools_enabled = false;
        config.soul_path = Some("https://docs.example.test/SOUL.md".into());
        config.egress_policy = EgressPolicyConfig {
            mode: EgressPolicyMode::Block,
            allow_hosts: vec!["api.example.test".into()],
            block_private_ips: false,
            ..Default::default()
        };

        config.post_deserialize().unwrap();
    }

    #[test]
    fn test_post_deserialize_egress_checks_enabled_channel_endpoint() {
        let mut config = test_config();
        config.clawhub.agent_tools_enabled = false;
        config.channels.insert(
            "matrix".into(),
            serde_yaml::from_str(
                "enabled: true\nhomeserver_url: http://127.0.0.1:8008\naccess_token: tok\nbot_user_id: '@bot:localhost'\n",
            )
            .unwrap(),
        );
        config.egress_policy.mode = EgressPolicyMode::Block;

        let err = config.post_deserialize().unwrap_err().to_string();

        assert!(err.contains("127.0.0.1"), "{err}");
    }

    #[test]
    fn test_config_save_yaml() {
        let config = test_config();
        let dir = std::env::temp_dir();
        let path = dir.join("microclaw_test_config.yaml");
        config.save_yaml(path.to_str().unwrap()).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("telegram_bot_token"));
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_post_deserialize_expands_paths() {
        let mut config = test_config();
        config.data_dir = "~/.microclaw".into();
        config.working_dir = "~/workspace".into();
        config.skills_dir = Some("~/skills".into());

        config.post_deserialize().unwrap();

        let home = PathBuf::from(shellexpand::tilde("~").as_ref());
        // Use PathBuf comparison to handle separator differences on Windows
        assert_eq!(PathBuf::from(&config.data_dir), home.join(".microclaw"));
        assert_eq!(PathBuf::from(&config.working_dir), home.join("workspace"));
        assert_eq!(
            PathBuf::from(config.skills_dir.unwrap()),
            home.join("skills")
        );
    }
}
