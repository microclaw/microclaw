//! Model presets: context window, output limit, prices and capabilities of coding models.
//!
//! One table, looked up by model name ([`lookup`]) for `mccode setup`, the
//! `/model` picker and cost display. Context windows mirror the engine's
//! built-in table (`microclaw-engine/src/context_window.rs`, which the
//! engine uses for compaction) so Code and the engine agree; keep the two in
//! step. Values the repository has no source for are left unset: prices are
//! `None` (configure `model_prices` for cost tracking) and `max_output` is
//! `None` (the engine's `max_tokens`, default 8192, applies).

/// One model family.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ModelPreset {
    /// Canonical id (lower case), e.g. `deepseek-v4-pro` or `claude`.
    pub id: &'static str,
    /// Lower-case globs (`*` only) matched against the normalized model
    /// name; the first preset with a matching pattern wins.
    pub patterns: &'static [&'static str],
    /// Usual provider (a MicroClaw `llm_provider` id).
    pub provider: &'static str,
    /// Context window in tokens (input + output).
    pub context_window: u32,
    /// Largest output the model allows, when known.
    pub max_output: Option<u32>,
    /// USD per million input tokens, when known.
    pub input_price_per_mtok: Option<f64>,
    /// USD per million output tokens, when known.
    pub output_price_per_mtok: Option<f64>,
    /// Accepts image input.
    pub image_input: bool,
    /// Has a reasoning / thinking mode.
    pub reasoning: bool,
    pub notes: &'static str,
}

const fn preset(
    id: &'static str,
    patterns: &'static [&'static str],
    provider: &'static str,
    context_window: u32,
    image_input: bool,
    reasoning: bool,
    notes: &'static str,
) -> ModelPreset {
    ModelPreset {
        id,
        patterns,
        provider,
        context_window,
        max_output: None,
        input_price_per_mtok: None,
        output_price_per_mtok: None,
        image_input,
        reasoning,
        notes,
    }
}

/// Presets in match order: specific families before general ones (the
/// same order as the engine's window table).
static PRESETS: &[ModelPreset] = &[
    // 1M-context variants (`claude-sonnet-4-6[1m]`, `…-1m`).
    preset(
        "claude-1m",
        &["claude*[1m]*", "claude*-1m*"],
        "anthropic",
        1_000_000,
        true,
        true,
        "Claude with the 1M-token context window enabled",
    ),
    preset(
        "claude-opus",
        &["*claude-opus*", "*claude*opus*"],
        "anthropic",
        200_000,
        true,
        true,
        "Anthropic's largest Claude models",
    ),
    preset(
        "claude-sonnet",
        &["*claude-sonnet*", "*claude*sonnet*"],
        "anthropic",
        200_000,
        true,
        true,
        "",
    ),
    preset(
        "claude-haiku",
        &["*claude-haiku*", "*claude*haiku*"],
        "anthropic",
        200_000,
        true,
        true,
        "",
    ),
    preset(
        "claude",
        &["*claude*"],
        "anthropic",
        200_000,
        true,
        true,
        "Other Claude models",
    ),
    preset(
        "gpt-5",
        &["gpt-5*"],
        "openai",
        272_000,
        true,
        true,
        "Includes gpt-5.x and gpt-5-codex",
    ),
    preset(
        "gpt-4.1",
        &["gpt-4.1*"],
        "openai",
        1_000_000,
        true,
        false,
        "",
    ),
    preset("gpt-4o", &["gpt-4o*"], "openai", 128_000, true, false, ""),
    preset("o4-mini", &["o4-mini*"], "openai", 200_000, true, true, ""),
    preset("o3", &["o3", "o3-*"], "openai", 200_000, true, true, ""),
    preset(
        "codex",
        &["*codex*"],
        "openai-codex",
        272_000,
        true,
        true,
        "",
    ),
    preset("gemini", &["*gemini*"], "google", 1_000_000, true, true, ""),
    preset(
        "deepseek-v4-flash",
        &["deepseek-v4*flash*"],
        "deepseek",
        1_000_000,
        false,
        true,
        "DeepSeek V4 Flash (fast, cheaper tier)",
    ),
    preset(
        "deepseek-v4-pro",
        &["deepseek-v4*"],
        "deepseek",
        1_000_000,
        false,
        true,
        "DeepSeek V4 / V4.1 Pro",
    ),
    preset(
        "deepseek-flash",
        &["deepseek-flash*"],
        "deepseek",
        1_000_000,
        false,
        true,
        "Alias of the current DeepSeek Flash model",
    ),
    preset(
        "deepseek-reasoner",
        &["deepseek-reasoner*", "deepseek-r1*"],
        "deepseek",
        128_000,
        false,
        true,
        "",
    ),
    preset(
        "deepseek",
        &["*deepseek*"],
        "deepseek",
        128_000,
        false,
        false,
        "Older DeepSeek models (V3, V3.x, deepseek-chat)",
    ),
    preset(
        "qwen3-coder",
        &["*qwen3-coder*"],
        "alibaba",
        256_000,
        false,
        false,
        "Qwen3 Coder (also on Ollama / Hugging Face)",
    ),
    preset(
        "qwen",
        &["*qwen*"],
        "alibaba",
        128_000,
        false,
        false,
        "Qwen family, e.g. qwen3.8-max; local `qwen3.6` on Ollama",
    ),
    preset(
        "kimi",
        &["*kimi*"],
        "moonshot",
        256_000,
        false,
        false,
        "Kimi K2 / K3",
    ),
    preset(
        "moonshot",
        &["*moonshot*"],
        "moonshot",
        128_000,
        false,
        false,
        "",
    ),
    preset(
        "glm-4.6",
        &["*glm-4.6*"],
        "zhipu",
        200_000,
        false,
        false,
        "",
    ),
    preset(
        "glm",
        &["*glm*"],
        "zhipu",
        128_000,
        false,
        false,
        "GLM family, e.g. glm-4.7",
    ),
    preset("grok-4", &["*grok-4*"], "xai", 256_000, false, true, ""),
    preset("grok", &["*grok*"], "xai", 128_000, false, false, ""),
    preset(
        "minimax",
        &["*minimax*"],
        "minimax",
        200_000,
        false,
        false,
        "",
    ),
    preset(
        "llama",
        &["*llama*"],
        "ollama",
        128_000,
        false,
        false,
        "Llama, hosted (Groq, NVIDIA) or local",
    ),
    preset(
        "mistral",
        &["*mistral*"],
        "mistral",
        128_000,
        false,
        false,
        "",
    ),
    preset(
        "codestral",
        &["*codestral*"],
        "mistral",
        256_000,
        false,
        false,
        "",
    ),
];

/// Every preset, in match order.
pub fn all() -> &'static [ModelPreset] {
    PRESETS
}

/// Normalizes a model name for lookup: trimmed, lower case, without a
/// `provider/` (or `org/`) prefix. A `[1m]` suffix is kept.
pub fn normalize(model: &str) -> String {
    let model = model.trim().to_ascii_lowercase();
    match model.rsplit_once('/') {
        Some((_, name)) if !name.is_empty() => name.to_string(),
        _ => model,
    }
}

/// The preset for `model` (`deepseek/deepseek-v4-pro`, `Qwen/Qwen3-Coder-Next`,
/// `claude-sonnet-4-6[1m]`, …): an exact id first, then the first matching
/// pattern.
pub fn lookup(model: &str) -> Option<&'static ModelPreset> {
    let name = normalize(model);
    if name.is_empty() {
        return None;
    }
    PRESETS.iter().find(|p| p.id == name).or_else(|| {
        PRESETS
            .iter()
            .find(|p| p.patterns.iter().any(|pattern| glob_match(pattern, &name)))
    })
}

/// `*`-only glob match (both inputs lower case).
fn glob_match(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == text;
    }
    let (first, last) = (parts[0], parts[parts.len() - 1]);
    if text.len() < first.len() + last.len() || !text.starts_with(first) || !text.ends_with(last) {
        return false;
    }
    let mut rest = &text[first.len()..text.len() - last.len()];
    for middle in &parts[1..parts.len() - 1] {
        match rest.find(middle) {
            Some(at) => rest = &rest[at + middle.len()..],
            None => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob() {
        assert!(glob_match("gpt-5*", "gpt-5.6-sol"));
        assert!(glob_match("*qwen*", "qwen3.6"));
        assert!(glob_match("claude*[1m]*", "claude-sonnet-4-6[1m]"));
        assert!(glob_match("deepseek-v4*flash*", "deepseek-v4-flash"));
        assert!(!glob_match("deepseek-v4*flash*", "deepseek-v4-pro"));
        assert!(glob_match("o3", "o3"));
        assert!(!glob_match("o3", "o3-mini"));
        assert!(!glob_match("a*a", "a"));
    }

    fn window(model: &str) -> Option<u32> {
        lookup(model).map(|p| p.context_window)
    }

    #[test]
    fn lookup_normalizes_and_matches_families() {
        assert_eq!(
            lookup("deepseek/deepseek-v4-pro").unwrap().id,
            "deepseek-v4-pro"
        );
        assert_eq!(lookup("DeepSeek-V4-Flash").unwrap().id, "deepseek-v4-flash");
        assert_eq!(lookup("deepseek-flash").unwrap().id, "deepseek-flash");
        assert_eq!(lookup("deepseek-ai/DeepSeek-V3.2").unwrap().id, "deepseek");
        assert_eq!(lookup("Qwen/Qwen3-Coder-Next").unwrap().id, "qwen3-coder");
        assert_eq!(lookup("qwen3.6").unwrap().id, "qwen");
        assert_eq!(lookup("kimi-k3").unwrap().id, "kimi");
        assert_eq!(
            lookup("accounts/fireworks/routers/kimi-k2p5-turbo")
                .unwrap()
                .id,
            "kimi"
        );
        assert_eq!(lookup("zai-glm-4.7").unwrap().id, "glm");
        assert_eq!(lookup("glm-4.6").unwrap().id, "glm-4.6");
        assert_eq!(
            lookup("anthropic/claude-opus-4.6").unwrap().id,
            "claude-opus"
        );
        assert_eq!(lookup("claude-sonnet-4-6[1m]").unwrap().id, "claude-1m");
        assert_eq!(lookup("gpt-5.6-sol").unwrap().id, "gpt-5");
        assert_eq!(lookup("gemini-3.7-flash").unwrap().id, "gemini");
        assert_eq!(lookup("meta/llama-3.3-70b-instruct").unwrap().id, "llama");
        assert!(lookup("custom-model").is_none());
        assert!(lookup("").is_none());
    }

    /// Mirrors the engine's `MODEL_WINDOWS` table; update both together.
    #[test]
    fn windows_match_engine_table() {
        let cases = [
            ("claude-opus-5-5", 200_000),
            ("claude-sonnet-4-6[1m]", 1_000_000),
            ("gpt-5.2", 272_000),
            ("gpt-4.1-mini", 1_000_000),
            ("gpt-4o", 128_000),
            ("o4-mini", 200_000),
            ("o3", 200_000),
            ("gemini-3.7-flash", 1_000_000),
            ("deepseek-v4-pro", 1_000_000),
            ("deepseek-flash", 1_000_000),
            ("deepseek-chat", 128_000),
            ("qwen3-coder-plus", 256_000),
            ("qwen3.8-max", 128_000),
            ("kimi-k3", 256_000),
            ("moonshot-v1-128k", 128_000),
            ("glm-4.6", 200_000),
            ("glm-4.7", 128_000),
            ("grok-4", 256_000),
            ("grok-3", 128_000),
            ("MiniMax-M3", 200_000),
            ("llama-3.3-70b-versatile", 128_000),
            ("mistral-large-latest", 128_000),
            ("codestral-latest", 256_000),
        ];
        for (model, expected) in cases {
            assert_eq!(window(model), Some(expected), "{model}");
        }
    }

    #[test]
    fn no_invented_prices_and_unique_ids() {
        let mut ids: Vec<_> = all().iter().map(|p| p.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), all().len());
        assert!(all().iter().all(|p| p.input_price_per_mtok.is_none()
            && p.output_price_per_mtok.is_none()
            && p.context_window > 0));
    }
}
