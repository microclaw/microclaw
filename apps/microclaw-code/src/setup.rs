//! `mccode setup`: write Code's own model configuration.

use std::io::{BufRead, IsTerminal, Write};

use microclaw_code_core::home::{self, ModelSettings};
use microclaw_sdk::{ModelProvider, model_providers};

/// Values given on the command line; missing ones are asked interactively.
#[derive(Debug, Default, Clone)]
pub struct SetupArgs {
    pub provider: Option<String>,
    pub model: Option<String>,
    pub api_key: Option<String>,
    pub base_url: Option<String>,
}

/// Providers that work without an API key.
fn keyless(provider: &str) -> bool {
    matches!(provider, "ollama" | "openai-codex" | "qwen-portal")
}

const POPULAR: &[&str] = &[
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

fn ask(prompt: &str, default: Option<&str>) -> anyhow::Result<String> {
    match default {
        Some(d) if !d.is_empty() => eprint!("{prompt} [{d}]: "),
        _ => eprint!("{prompt}: "),
    }
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    let value = line.trim().to_string();
    Ok(if value.is_empty() {
        default.unwrap_or_default().to_string()
    } else {
        value
    })
}

fn choose_provider(providers: &[ModelProvider]) -> anyhow::Result<String> {
    let popular: Vec<&ModelProvider> = POPULAR
        .iter()
        .filter_map(|id| providers.iter().find(|p| p.id == *id))
        .collect();
    eprintln!("Model provider:");
    for (i, p) in popular.iter().enumerate() {
        eprintln!("  {:>2}) {:<14} {}", i + 1, p.id, p.label);
    }
    eprintln!("  (or type any provider id: {})", providers.len());
    loop {
        let answer = ask("Choose", Some("1"))?;
        if let Ok(n) = answer.parse::<usize>() {
            if let Some(p) = popular.get(n.wrapping_sub(1)) {
                return Ok(p.id.to_string());
            }
        } else if providers.iter().any(|p| p.id == answer) {
            return Ok(answer);
        }
        eprintln!("Unknown choice {answer:?}.");
    }
}

/// Run setup; returns the written config path.
pub fn run(args: SetupArgs) -> anyhow::Result<std::path::PathBuf> {
    let interactive = std::io::stdin().is_terminal();
    let providers = model_providers();
    let provider = match args.provider {
        Some(p) => p,
        None if interactive => choose_provider(&providers)?,
        None => anyhow::bail!("--provider is required when stdin is not a terminal"),
    };
    let preset = providers.iter().find(|p| p.id == provider);
    let suggested_model = preset.and_then(|p| p.models.first().copied()).unwrap_or("");
    let model = match args.model {
        Some(m) => m,
        None if interactive => {
            if let Some(p) = preset.filter(|p| p.models.len() > 1) {
                eprintln!("Suggested models: {}", p.models.join(", "));
            }
            ask("Model", Some(suggested_model))?
        }
        None if !suggested_model.is_empty() => suggested_model.to_string(),
        None => anyhow::bail!("--model is required for provider {provider}"),
    };
    anyhow::ensure!(!model.trim().is_empty(), "a model is required");
    let api_key = match args.api_key {
        Some(k) => k,
        None if keyless(&provider) => String::new(),
        None if interactive => ask("API key", None)?,
        None => std::env::var("MICROCLAW_API_KEY").unwrap_or_default(),
    };
    anyhow::ensure!(
        keyless(&provider) || !api_key.trim().is_empty(),
        "an API key is required for provider {provider}"
    );
    let default_url = preset.map(|p| p.default_base_url).unwrap_or("");
    let base_url = match args.base_url {
        Some(u) => Some(u),
        None if interactive && !default_url.is_empty() => {
            let url = ask("Base URL", Some(default_url))?;
            (url != default_url).then_some(url)
        }
        None => None,
    };

    let path = home::config_path();
    home::write_config(
        &path,
        &ModelSettings {
            provider,
            model,
            api_key,
            base_url,
        },
    )?;
    microclaw_sdk::validate_config_file(&path)
        .map_err(|e| anyhow::anyhow!("the written configuration is invalid: {e}"))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn popular_providers_exist_in_the_catalog() {
        let providers = model_providers();
        for id in ["anthropic", "openai", "deepseek", "ollama"] {
            assert!(providers.iter().any(|p| p.id == id), "{id} missing");
        }
    }
}
