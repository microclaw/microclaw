use super::*;

pub(crate) fn default_model() -> String {
    String::new()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ModelPrice {
    pub model: String,
    pub input_per_million_usd: f64,
    pub output_per_million_usd: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct LlmProviderProfile {
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub api_key: Option<String>,
    /// Additional API keys rotated on auth/rate-limit errors.
    #[serde(default)]
    pub api_keys: Vec<String>,
    #[serde(default)]
    pub llm_base_url: Option<String>,
    #[serde(default)]
    pub llm_user_agent: Option<String>,
    #[serde(default)]
    pub default_model: Option<String>,
    #[serde(default)]
    pub models: Vec<String>,
    #[serde(default)]
    pub show_thinking: Option<bool>,
}

#[derive(Clone, Debug)]
pub struct ResolvedLlmProviderProfile {
    pub alias: String,
    pub provider: String,
    pub api_key: String,
    /// Additional API keys rotated on auth/rate-limit errors.
    pub api_keys: Vec<String>,
    pub llm_base_url: Option<String>,
    pub llm_user_agent: String,
    pub default_model: String,
    pub models: Vec<String>,
    pub show_thinking: bool,
}

/// Per-task auxiliary model overrides.
///
/// Each slot names a (typically cheaper) model used for a specific ancillary task
/// instead of the main conversation model. Auxiliary models run on the *same*
/// provider profile and credentials as the main model — only the model name is
/// swapped — so the common case (e.g. a small/fast model for summarization) needs
/// no extra provider configuration. An empty or unset slot falls back to the main
/// model, so the default behavior is unchanged.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AuxModels {
    /// Model used for context compaction / history summarization. Falls back to the
    /// main model when unset or empty.
    #[serde(default)]
    pub compaction: Option<String>,
    /// Model used by the background memory reflector (fact/triple extraction). This
    /// runs periodically per active chat, so a cheaper model here is pure savings.
    /// Falls back to the main model when unset or empty.
    #[serde(default)]
    pub reflector: Option<String>,
    /// Model used to generate short session titles. This is a one-shot
    /// summarization, so a cheaper model is pure savings. Falls back to the
    /// provider's default model when unset or empty.
    #[serde(default)]
    pub title: Option<String>,
    /// Model used for image description (the `describe_image` tool). Overrides
    /// `media.vision.model` when set; falls back to it when unset or empty.
    #[serde(default)]
    pub vision: Option<String>,
    /// Model that writes a short advisory verdict on high-risk tool
    /// approval prompts. Unlike the other slots this does NOT fall back to
    /// the main model: unset means the reviewer is off (the default), so
    /// enabling it is an explicit operator choice. Advisory only — it never
    /// approves or denies anything itself.
    #[serde(default)]
    pub approval_reviewer: Option<String>,
}

impl AuxModels {
    /// Resolve the model to use for context compaction, falling back to `main` when
    /// no auxiliary model is configured.
    pub fn compaction_model<'a>(&'a self, main: &'a str) -> &'a str {
        match self.compaction.as_deref() {
            Some(m) if !m.trim().is_empty() => m,
            _ => main,
        }
    }

    /// Optional model override for the memory reflector. Returns `None` (use the
    /// provider's default model) when unset or empty, preserving prior behavior.
    pub fn reflector_model(&self) -> Option<&str> {
        match self.reflector.as_deref() {
            Some(m) if !m.trim().is_empty() => Some(m),
            _ => None,
        }
    }

    /// Optional model override for session-title generation. Returns `None` (use
    /// the provider's default model) when unset or empty, preserving prior behavior.
    pub fn title_model(&self) -> Option<&str> {
        match self.title.as_deref() {
            Some(m) if !m.trim().is_empty() => Some(m),
            _ => None,
        }
    }

    /// Optional model override for image description. Returns `None` (use
    /// `media.vision.model`) when unset or empty, preserving prior behavior.
    pub fn vision_model(&self) -> Option<&str> {
        match self.vision.as_deref() {
            Some(m) if !m.trim().is_empty() => Some(m),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use crate::config::test_prelude::*;

    #[test]
    fn aux_models_default_falls_back_to_main_model() {
        let aux = AuxModels::default();
        assert_eq!(aux.compaction_model("main-model"), "main-model");
    }

    #[test]
    fn aux_models_compaction_override_is_used() {
        let aux = AuxModels {
            compaction: Some("cheap-model".to_string()),
            ..Default::default()
        };
        assert_eq!(aux.compaction_model("main-model"), "cheap-model");
    }

    #[test]
    fn aux_models_blank_override_falls_back() {
        let aux = AuxModels {
            compaction: Some("   ".to_string()),
            ..Default::default()
        };
        assert_eq!(aux.compaction_model("main-model"), "main-model");
    }

    #[test]
    fn aux_models_reflector_default_is_none() {
        let aux = AuxModels::default();
        assert_eq!(aux.reflector_model(), None);
    }

    #[test]
    fn aux_models_reflector_blank_is_none() {
        let aux = AuxModels {
            reflector: Some("  ".to_string()),
            ..Default::default()
        };
        assert_eq!(aux.reflector_model(), None);
    }

    #[test]
    fn aux_models_title_and_vision_default_none() {
        let aux = AuxModels::default();
        assert_eq!(aux.title_model(), None);
        assert_eq!(aux.vision_model(), None);
    }

    #[test]
    fn aux_models_title_and_vision_override_used() {
        let aux = AuxModels {
            title: Some("title-model".to_string()),
            vision: Some("vision-model".to_string()),
            ..Default::default()
        };
        assert_eq!(aux.title_model(), Some("title-model"));
        assert_eq!(aux.vision_model(), Some("vision-model"));
    }

    #[test]
    fn aux_models_title_and_vision_blank_is_none() {
        let aux = AuxModels {
            title: Some("  ".to_string()),
            vision: Some(String::new()),
            ..Default::default()
        };
        assert_eq!(aux.title_model(), None);
        assert_eq!(aux.vision_model(), None);
    }

    #[test]
    fn test_post_deserialize_merges_provider_presets_with_legacy_profiles() {
        let yaml = r#"
telegram_bot_token: tok
bot_username: bot
api_key: key
provider_presets:
  lab:
    provider: OPENAI
    api_key: preset-key
    llm_base_url: https://preset.example/v1
    llm_user_agent: preset-agent
    default_model: preset-model
    models: [preset-model, preset-model]
    show_thinking: true
llm_providers:
  lab:
    api_key: legacy-key
    models: [legacy-model]
"#;
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        config.post_deserialize().unwrap();

        let profile = config.resolve_llm_provider_profile("lab").unwrap();
        assert_eq!(profile.provider, "openai");
        assert_eq!(profile.api_key, "legacy-key");
        assert_eq!(
            profile.llm_base_url.as_deref(),
            Some("https://preset.example/v1")
        );
        assert_eq!(profile.llm_user_agent, "preset-agent");
        assert_eq!(profile.default_model, "preset-model");
        assert_eq!(
            profile.models,
            vec!["legacy-model".to_string(), "preset-model".to_string()]
        );
        assert!(profile.show_thinking);
    }

    #[test]
    fn test_resolve_llm_provider_profile_ignores_wildcard_profile_model() {
        let yaml = r#"
telegram_bot_token: tok
bot_username: bot
api_key: key
llm_provider: openai
model: gpt-5.2
llm_providers:
  openai:
    provider: openai
    default_model: "*"
    models: ["*", "gpt-5-mini"]
"#;
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        config.post_deserialize().unwrap();

        let profile = config.resolve_llm_provider_profile("openai").unwrap();
        assert_eq!(profile.default_model, "gpt-5.2");
        assert_eq!(
            profile.models,
            vec!["gpt-5-mini".to_string(), "gpt-5.2".to_string()]
        );
    }

    #[test]
    fn test_post_deserialize_migrates_profile_aliases_out_of_channel_model_fields() {
        let yaml = r#"
telegram_bot_token: tok
bot_username: bot
api_key: key
provider_presets:
  googlegemini:
    provider: google
    default_model: gemini-2.5-pro
channels:
  telegram:
    enabled: true
    model: googlegemini
    default_account: sales
    accounts:
      sales:
        enabled: true
        bot_token: tg_sales
        model: googlegemini
  discord:
    enabled: true
    model: googlegemini
    accounts:
      default:
        enabled: true
        bot_token: dc_tok
"#;
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        config.post_deserialize().unwrap();

        assert_eq!(
            config.provider_override_for_channel("telegram").as_deref(),
            Some("googlegemini")
        );
        assert_eq!(
            config.provider_override_for_channel("discord").as_deref(),
            Some("googlegemini")
        );

        let telegram = config.channels.get("telegram").unwrap();
        assert_eq!(
            telegram
                .get("provider_preset")
                .and_then(|v| v.as_str())
                .map(str::trim),
            Some("googlegemini")
        );
        assert!(telegram.get("model").is_none());

        let sales = telegram
            .get("accounts")
            .and_then(|v| v.get("sales"))
            .unwrap();
        assert_eq!(
            sales
                .get("provider_preset")
                .and_then(|v| v.as_str())
                .map(str::trim),
            Some("googlegemini")
        );
        assert!(sales.get("model").is_none());
    }
}
