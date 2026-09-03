#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ProviderProtocol {
    Anthropic,
    OpenAiCompat,
}

#[derive(Clone, Copy)]
pub struct ProviderPreset {
    pub id: &'static str,
    pub label: &'static str,
    pub protocol: ProviderProtocol,
    pub default_base_url: &'static str,
    pub models: &'static [&'static str],
}

// Sorted A→Z by `id`. Keep this invariant when adding new providers — the
// setup wizard's preset picker and the generated provider matrix mirror
// this order verbatim.
pub const PROVIDER_PRESETS: &[ProviderPreset] = &[
    ProviderPreset {
        id: "alibaba",
        label: "Alibaba Cloud (Qwen / DashScope)",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://dashscope.aliyuncs.com/compatible-mode/v1",
        models: &["qwen3.8-max", "qwen3.7-max", "qwen3.7-plus"],
    },
    ProviderPreset {
        id: "aliyun-bailian",
        label: "Alibaba Cloud Bailian",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://coding.dashscope.aliyuncs.com/v1",
        models: &["qwen3.8-max", "qwen3.7-plus", "qwen3.6-plus"],
    },
    ProviderPreset {
        id: "anthropic",
        label: "Anthropic",
        protocol: ProviderProtocol::Anthropic,
        default_base_url: "",
        models: &[
            "claude-fable-5",
            "claude-opus-5",
            "claude-sonnet-5",
            "claude-haiku-4-5-20251001",
        ],
    },
    ProviderPreset {
        id: "arcee",
        label: "Arcee AI",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://api.arcee.ai/api/v1",
        models: &["trinity-large-thinking", "trinity-large", "blitz"],
    },
    ProviderPreset {
        id: "azure",
        label: "Microsoft Azure AI",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url:
            "https://YOUR-RESOURCE.openai.azure.com/openai/deployments/YOUR-DEPLOYMENT",
        models: &["gpt-5.2", "gpt-5", "gpt-4.1"],
    },
    ProviderPreset {
        id: "bedrock",
        label: "Amazon AWS Bedrock",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://bedrock-runtime.YOUR-REGION.amazonaws.com/openai/v1",
        models: &[
            "anthropic.claude-opus-4-6-v1",
            "anthropic.claude-sonnet-4-5-v2",
            "anthropic.claude-haiku-4-5-v1",
        ],
    },
    ProviderPreset {
        id: "cerebras",
        label: "Cerebras",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://api.cerebras.ai/v1",
        models: &["zai-glm-4.7", "llama3.3-70b", "qwen-3-235b"],
    },
    ProviderPreset {
        id: "chutes",
        label: "Chutes",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://llm.chutes.ai/v1",
        models: &[
            "deepseek-ai/DeepSeek-V3-0324",
            "Qwen/Qwen3-Coder-480B-A35B-Instruct",
        ],
    },
    ProviderPreset {
        id: "cloudflare-ai-gateway",
        label: "Cloudflare AI Gateway",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://gateway.ai.cloudflare.com/v1/YOUR-ACCOUNT/YOUR-GATEWAY/openai",
        models: &["claude-sonnet-4-6", "gpt-5.2", "openrouter/auto"],
    },
    ProviderPreset {
        id: "cohere",
        label: "Cohere",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://api.cohere.ai/compatibility/v1",
        models: &[
            "command-a-03-2025",
            "command-r-plus-08-2024",
            "command-r-08-2024",
        ],
    },
    ProviderPreset {
        id: "custom",
        label: "Custom (manual config)",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "",
        models: &["custom-model"],
    },
    ProviderPreset {
        id: "deepinfra",
        label: "DeepInfra",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://api.deepinfra.com/v1/openai",
        models: &[
            "deepseek-ai/DeepSeek-V3.2",
            "meta-llama/Meta-Llama-3.1-70B-Instruct",
            "Qwen/Qwen2.5-72B-Instruct",
        ],
    },
    ProviderPreset {
        id: "deepseek",
        label: "DeepSeek",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://api.deepseek.com/v1",
        models: &["deepseek-v4-pro", "deepseek-v4-flash"],
    },
    ProviderPreset {
        id: "fireworks",
        label: "Fireworks AI",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://api.fireworks.ai/inference/v1",
        models: &[
            "accounts/fireworks/routers/kimi-k2p5-turbo",
            "accounts/fireworks/models/llama-v3p3-70b-instruct",
            "accounts/fireworks/models/qwen3-coder",
        ],
    },
    ProviderPreset {
        id: "google",
        label: "Google DeepMind",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://generativelanguage.googleapis.com/v1beta/openai",
        models: &[
            "gemini-3.7-flash",
            "gemini-3.1-pro-preview",
            "gemini-3.6-flash",
            "gemini-3.5-flash-lite",
        ],
    },
    ProviderPreset {
        id: "groq",
        label: "Groq",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://api.groq.com/openai/v1",
        models: &[
            "llama-3.3-70b-versatile",
            "llama-3.1-70b-versatile",
            "mixtral-8x7b-32768",
        ],
    },
    ProviderPreset {
        id: "huggingface",
        label: "Hugging Face",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://router.huggingface.co/v1",
        models: &[
            "Qwen/Qwen3-Coder-Next",
            "meta-llama/Llama-3.3-70B-Instruct",
            "deepseek-ai/DeepSeek-V3",
        ],
    },
    ProviderPreset {
        id: "inferrs",
        label: "Inferrs (local)",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "http://127.0.0.1:8080/v1",
        models: &["google/gemma-4-E2B-it", "custom-model"],
    },
    ProviderPreset {
        id: "kilocode",
        label: "KiloCode",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://api.kilo.ai/api/gateway/",
        models: &["kilo/auto", "kilo/anthropic/claude-sonnet-4.5"],
    },
    ProviderPreset {
        id: "litellm",
        label: "LiteLLM (proxy)",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "http://localhost:4000",
        models: &["claude-opus-4-6", "gpt-5", "custom-model"],
    },
    ProviderPreset {
        id: "lmstudio",
        label: "LM Studio (local)",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "http://localhost:1234/v1",
        models: &["custom-model"],
    },
    ProviderPreset {
        id: "minimax",
        label: "MiniMax",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://api.minimax.io/v1",
        models: &["MiniMax-M3", "MiniMax-M2.7", "MiniMax-M2.7-highspeed"],
    },
    ProviderPreset {
        id: "mistral",
        label: "Mistral AI",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://api.mistral.ai/v1",
        models: &[
            "mistral-large-latest",
            "mistral-medium-latest",
            "ministral-8b-latest",
        ],
    },
    ProviderPreset {
        id: "moonshot",
        label: "Moonshot AI (Kimi)",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://api.moonshot.cn/v1",
        models: &["kimi-k3", "kimi-k2.7-code-highspeed", "kimi-k2.6"],
    },
    ProviderPreset {
        id: "nvidia",
        label: "NVIDIA NIM",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://integrate.api.nvidia.com/v1",
        models: &[
            "meta/llama-3.3-70b-instruct",
            "meta/llama-3.1-70b-instruct",
            "nvidia/llama-3.1-nemotron-ultra-253b-v1",
        ],
    },
    ProviderPreset {
        id: "ollama",
        label: "Ollama (local)",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "http://127.0.0.1:11434/v1",
        models: &["qwen3.6", "qwen3-coder:30b", "gpt-oss:20b", "llama3.3"],
    },
    ProviderPreset {
        id: "openai",
        label: "OpenAI",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://api.openai.com/v1",
        models: &["gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna"],
    },
    ProviderPreset {
        id: "openai-codex",
        label: "OpenAI Codex",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "",
        models: &["gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna"],
    },
    ProviderPreset {
        id: "openrouter",
        label: "OpenRouter",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://openrouter.ai/api/v1",
        models: &[
            "openrouter/auto",
            "openai/gpt-5.6-sol",
            "anthropic/claude-opus-5",
            "google/gemini-3.7-flash",
        ],
    },
    ProviderPreset {
        id: "qianfan",
        label: "Baidu Qianfan",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://qianfan.baidubce.com/v2",
        models: &["deepseek-v3.2", "ernie-5.0-thinking-preview"],
    },
    ProviderPreset {
        id: "qwen-portal",
        label: "Qwen Portal (OAuth)",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://portal.qwen.ai/v1",
        models: &["coder-model", "vision-model", "qwen3.5-plus"],
    },
    ProviderPreset {
        id: "sglang",
        label: "SGLang (local)",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "http://127.0.0.1:30000/v1",
        models: &["custom-model"],
    },
    ProviderPreset {
        id: "stepfun",
        label: "StepFun",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://api.stepfun.ai/v1",
        models: &["step-3.5-flash", "step-3.5-pro"],
    },
    ProviderPreset {
        id: "synthetic",
        label: "Synthetic",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://api.synthetic.new/openai/v1",
        models: &["hf:openai/gpt-oss-120b", "hf:deepseek-ai/DeepSeek-V3-0324"],
    },
    ProviderPreset {
        id: "tencent",
        label: "Tencent AI Lab",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://api.hunyuan.cloud.tencent.com/v1",
        models: &[
            "hunyuan-t1-latest",
            "hunyuan-turbos-latest",
            "hunyuan-standard-latest",
        ],
    },
    ProviderPreset {
        id: "together",
        label: "Together AI",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://api.together.xyz/v1",
        models: &[
            "deepseek-ai/DeepSeek-V3",
            "meta-llama/Llama-3.3-70B-Instruct-Turbo",
            "Qwen/Qwen3-Coder-480B-A35B-Instruct-FP8",
        ],
    },
    ProviderPreset {
        id: "venice",
        label: "Venice",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://api.venice.ai/api/v1",
        models: &["kimi-k2-5", "qwen-3-coder-480b"],
    },
    ProviderPreset {
        id: "vercel-ai-gateway",
        label: "Vercel AI Gateway",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://ai-gateway.vercel.sh/v1",
        models: &[
            "anthropic/claude-opus-4.6",
            "openai/gpt-5.2",
            "google/gemini-2.5-pro",
        ],
    },
    ProviderPreset {
        id: "vllm",
        label: "vLLM (local)",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "http://127.0.0.1:8000/v1",
        models: &["custom-model"],
    },
    ProviderPreset {
        id: "volcengine",
        label: "Volcano Engine (Doubao)",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://ark.cn-beijing.volces.com/api/v3",
        models: &["doubao-1.5-pro-256k", "doubao-pro-32k"],
    },
    ProviderPreset {
        id: "xai",
        label: "xAI",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://api.x.ai/v1",
        models: &["grok-4", "grok-4-fast", "grok-3"],
    },
    ProviderPreset {
        id: "xiaomi",
        label: "Xiaomi (MiMo)",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://api.xiaomimimo.com/v1",
        models: &[
            "mimo-v2.5-pro",
            "mimo-v2.5",
            "mimo-v2-pro",
            "mimo-v2-flash",
            "mimo-v2-omni",
        ],
    },
    ProviderPreset {
        id: "zhipu",
        label: "Zhipu AI (GLM / Z.AI)",
        protocol: ProviderProtocol::OpenAiCompat,
        default_base_url: "https://open.bigmodel.cn/api/paas/v4",
        models: &["glm-4.7", "glm-4.7-flash", "glm-4.5-air"],
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderCatalogEntry {
    pub id: &'static str,
    pub label: &'static str,
    pub default_base_url: &'static str,
    pub models: &'static [&'static str],
}

pub fn provider_catalog() -> impl Iterator<Item = ProviderCatalogEntry> {
    PROVIDER_PRESETS.iter().map(|preset| ProviderCatalogEntry {
        id: preset.id,
        label: preset.label,
        default_base_url: preset.default_base_url,
        models: preset.models,
    })
}

pub fn find_provider_preset(provider: &str) -> Option<&'static ProviderPreset> {
    PROVIDER_PRESETS
        .iter()
        .find(|p| p.id.eq_ignore_ascii_case(provider))
}

/// Returns the default base URL for a known provider, or `None` if the
/// provider is unknown or has no preset base URL.
pub fn default_base_url_for_provider(provider: &str) -> Option<&'static str> {
    find_provider_preset(provider)
        .map(|p| p.default_base_url)
        .filter(|url| !url.is_empty())
}

pub fn provider_protocol(provider: &str) -> ProviderProtocol {
    find_provider_preset(provider)
        .map(|p| p.protocol)
        .unwrap_or(ProviderProtocol::OpenAiCompat)
}

pub fn default_model_for_provider(provider: &str) -> &'static str {
    find_provider_preset(provider)
        .and_then(|p| p.models.first().copied())
        .unwrap_or("gpt-5.2")
}

pub fn is_placeholder_provider_model_list(models: &[&str]) -> bool {
    models.len() == 1 && models[0].eq_ignore_ascii_case("custom-model")
}

pub fn normalize_setup_provider_id(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if find_provider_preset(trimmed).is_some() {
        return trimmed.to_ascii_lowercase();
    }
    let lower = trimmed.to_ascii_lowercase();
    if let Some(suffix) = lower.strip_prefix("custom") {
        if !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()) {
            return "custom".to_string();
        }
    }
    trimmed.to_string()
}

pub fn provider_display(provider: &str) -> String {
    if let Some(preset) = find_provider_preset(provider) {
        format!("{} - {}", preset.id, preset.label)
    } else {
        format!("{provider} - custom")
    }
}
