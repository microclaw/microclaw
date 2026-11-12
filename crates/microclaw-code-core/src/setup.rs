//! First-run model setup shared by `mccode setup` and the desktop app's
//! onboarding: pick a provider, a model and a key, then write Code's own
//! `~/.mccode/config.yaml`.

use std::path::PathBuf;

use microclaw_sdk::{ModelProvider, model_providers};

use crate::home::{self, ModelSettings};

/// Providers offered first, in this order.
pub const POPULAR: &[&str] = &[
    "anthropic",
    "openai",
    "openai-codex",
    "deepseek",
    "openrouter",
    "google",
    "moonshot",
    "alibaba",
    "zhipu",
    "minimax",
    "xai",
    "ollama",
];

/// Providers that work without an API key.
pub fn keyless(provider: &str) -> bool {
    matches!(provider, "ollama" | "openai-codex" | "qwen-portal")
}

/// Every provider the engine knows, popular ones first.
pub fn providers() -> Vec<ModelProvider> {
    let mut all = model_providers();
    all.sort_by_key(|p| {
        POPULAR
            .iter()
            .position(|id| *id == p.id)
            .unwrap_or(usize::MAX)
    });
    all
}

/// A complete setup answer.
#[derive(Debug, Default, Clone)]
pub struct SetupChoice {
    pub provider: String,
    /// Empty: the provider's first suggested model.
    pub model: String,
    pub api_key: String,
    /// Empty or the provider's default: not written.
    pub base_url: Option<String>,
}

/// Check a choice and fill defaults.
pub fn resolve(choice: SetupChoice) -> anyhow::Result<ModelSettings> {
    let provider = choice.provider.trim().to_string();
    anyhow::ensure!(!provider.is_empty(), "choose a model provider");
    let catalog = model_providers();
    let preset = catalog.iter().find(|p| p.id == provider);
    let model = match choice.model.trim() {
        "" => preset
            .and_then(|p| p.models.first().copied())
            .unwrap_or("")
            .to_string(),
        m => m.to_string(),
    };
    anyhow::ensure!(!model.is_empty(), "a model is required for {provider}");
    let api_key = choice.api_key.trim().to_string();
    anyhow::ensure!(
        keyless(&provider) || !api_key.is_empty(),
        "an API key is required for {provider}"
    );
    let default_url = preset.map(|p| p.default_base_url).unwrap_or("");
    let base_url = choice
        .base_url
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty() && u != default_url);
    Ok(ModelSettings {
        provider,
        model,
        api_key,
        base_url,
    })
}

/// Write `settings` to Code's config file and validate it; returns the path.
pub fn write(settings: &ModelSettings) -> anyhow::Result<PathBuf> {
    let path = home::config_path();
    home::write_config(&path, settings)?;
    microclaw_sdk::validate_config_file(&path)
        .map_err(|e| anyhow::anyhow!("the written configuration is invalid: {e}"))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn popular_providers_exist_and_come_first() {
        let all = providers();
        for id in ["anthropic", "openai", "deepseek", "ollama"] {
            assert!(all.iter().any(|p| p.id == id), "{id} missing");
        }
        assert_eq!(all[0].id, "anthropic");
    }

    #[test]
    fn resolve_fills_the_model_and_requires_a_key() {
        let resolved = resolve(SetupChoice {
            provider: "deepseek".into(),
            api_key: " k ".into(),
            ..Default::default()
        })
        .unwrap();
        assert!(!resolved.model.is_empty());
        assert_eq!(resolved.api_key, "k");
        assert!(resolved.base_url.is_none());
        assert!(
            resolve(SetupChoice {
                provider: "deepseek".into(),
                ..Default::default()
            })
            .is_err()
        );
        assert!(
            resolve(SetupChoice {
                provider: "ollama".into(),
                model: "llama3".into(),
                ..Default::default()
            })
            .is_ok()
        );
    }
}
