use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProviderProtocol {
    Anthropic,
    OpenAiCompat,
}

#[derive(Clone, Copy)]
pub(crate) struct ProviderPreset {
    pub(crate) id: &'static str,
    pub(crate) label: &'static str,
    pub(crate) protocol: ProviderProtocol,
    pub(crate) default_base_url: &'static str,
    pub(crate) models: &'static [&'static str],
}

// Sorted A→Z by `id`. Keep this invariant when adding new providers — the
// setup wizard's preset picker and the generated provider matrix mirror
// this order verbatim.
pub(crate) const PROVIDER_PRESETS: &[ProviderPreset] = &[
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

pub(crate) fn find_provider_preset(provider: &str) -> Option<&'static ProviderPreset> {
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

pub(crate) fn provider_protocol(provider: &str) -> ProviderProtocol {
    find_provider_preset(provider)
        .map(|p| p.protocol)
        .unwrap_or(ProviderProtocol::OpenAiCompat)
}

pub(crate) fn default_model_for_provider(provider: &str) -> &'static str {
    find_provider_preset(provider)
        .and_then(|p| p.models.first().copied())
        .unwrap_or("gpt-5.2")
}

pub(crate) fn is_placeholder_provider_model_list(models: &[&str]) -> bool {
    models.len() == 1 && models[0].eq_ignore_ascii_case("custom-model")
}

pub(crate) fn normalize_setup_provider_id(raw: &str) -> String {
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

pub(crate) fn provider_display(provider: &str) -> String {
    if let Some(preset) = find_provider_preset(provider) {
        format!("{} - {}", preset.id, preset.label)
    } else {
        format!("{provider} - custom")
    }
}

#[derive(Clone)]
pub(crate) struct ProviderPresetDraft {
    pub(crate) id: String,
    pub(crate) provider: String,
    pub(crate) api_key: String,
    pub(crate) base_url: String,
    pub(crate) user_agent: String,
    pub(crate) default_model: String,
    pub(crate) show_thinking: bool,
}

pub(crate) struct ProviderPresetValidationRequest {
    pub(crate) profile_id: String,
    pub(crate) provider: String,
    pub(crate) api_key: String,
    pub(crate) base_url: String,
    pub(crate) user_agent: String,
    pub(crate) model: String,
    pub(crate) codex_account_id: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProviderPresetPageMode {
    List,
    Edit,
}

#[derive(Clone)]
pub(crate) struct ProviderPresetPage {
    pub(crate) entries: Vec<ProviderPresetDraft>,
    pub(crate) selected: usize,
    pub(crate) mode: ProviderPresetPageMode,
    pub(crate) field_selected: usize,
    pub(crate) editing: bool,
    pub(crate) picker: Option<LlmOverridePicker>,
}

impl SetupApp {
    pub(crate) fn llm_provider_presets(&self) -> HashMap<String, LlmProviderProfile> {
        parse_provider_presets_json_value(
            &self.field_value(llm_provider_profiles_key()),
            llm_provider_profiles_key(),
        )
        .unwrap_or_default()
    }

    pub(crate) fn provider_preset_drafts(&self) -> Vec<ProviderPresetDraft> {
        let mut entries: Vec<(String, LlmProviderProfile)> =
            self.llm_provider_presets().into_iter().collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        entries
            .into_iter()
            .map(|(id, profile)| ProviderPresetDraft {
                id,
                provider: profile.provider.unwrap_or_default(),
                api_key: profile.api_key.unwrap_or_default(),
                base_url: profile.llm_base_url.unwrap_or_default(),
                user_agent: profile.llm_user_agent.unwrap_or_default(),
                default_model: profile.default_model.unwrap_or_default(),
                show_thinking: profile.show_thinking.unwrap_or(false),
            })
            .collect()
    }

    pub(crate) fn serialize_provider_preset_drafts(
        drafts: &[ProviderPresetDraft],
    ) -> Result<String, MicroClawError> {
        let mut presets = HashMap::new();
        for draft in drafts {
            let id = draft.id.trim().to_ascii_lowercase();
            if id.is_empty() {
                continue;
            }
            if id == "main" {
                return Err(MicroClawError::Config(
                    "provider preset id 'main' is reserved for the global default".into(),
                ));
            }
            if !is_valid_account_id(&id) {
                return Err(MicroClawError::Config(format!(
                    "provider preset id '{id}' must use only letters, numbers, '_' or '-'"
                )));
            }
            let profile = LlmProviderProfile {
                provider: Some(draft.provider.trim().to_ascii_lowercase())
                    .filter(|v| !v.is_empty()),
                api_key: Some(draft.api_key.trim().to_string()).filter(|v| !v.is_empty()),
                api_keys: Vec::new(),
                llm_base_url: Some(draft.base_url.trim().to_string()).filter(|v| !v.is_empty()),
                llm_user_agent: Some(draft.user_agent.trim().to_string()).filter(|v| !v.is_empty()),
                default_model: Some(draft.default_model.trim().to_string())
                    .filter(|v| !v.is_empty()),
                models: Vec::new(),
                show_thinking: Some(draft.show_thinking),
            };
            presets.insert(id, profile);
        }
        serde_json::to_string(&presets).map_err(|e| {
            MicroClawError::Config(format!("Failed to serialize provider profiles: {e}"))
        })
    }

    pub(crate) fn sync_provider_preset_page_field(&mut self) -> Result<(), MicroClawError> {
        let Some(page) = self.provider_preset_page.as_ref() else {
            return Ok(());
        };
        let json = Self::serialize_provider_preset_drafts(&page.entries)?;
        self.set_field_value(llm_provider_profiles_key(), json);
        Ok(())
    }

    pub(crate) fn next_provider_preset_id(entries: &[ProviderPresetDraft]) -> String {
        let mut used = entries
            .iter()
            .map(|entry| entry.id.trim().to_ascii_lowercase())
            .collect::<Vec<_>>();
        used.sort();
        for idx in 1usize.. {
            let candidate = format!("provider{idx}");
            if !used.iter().any(|id| id == &candidate) {
                return candidate;
            }
        }
        "provider1".to_string()
    }

    pub(crate) fn next_cloned_provider_preset_id(
        entries: &[ProviderPresetDraft],
        source_id: &str,
    ) -> String {
        let base = source_id.trim().to_ascii_lowercase();
        if base.is_empty() {
            return Self::next_provider_preset_id(entries);
        }
        let used = entries
            .iter()
            .map(|entry| entry.id.trim().to_ascii_lowercase())
            .collect::<std::collections::HashSet<_>>();
        for idx in 2usize.. {
            let candidate = format!("{base}-{idx}");
            if !used.contains(&candidate) {
                return candidate;
            }
        }
        format!("{base}-2")
    }

    pub(crate) fn open_provider_preset_page(&mut self) {
        self.provider_preset_page = Some(ProviderPresetPage {
            entries: self.provider_preset_drafts(),
            selected: 0,
            mode: ProviderPresetPageMode::List,
            field_selected: 0,
            editing: false,
            picker: None,
        });
        self.status = "Editing provider profiles".to_string();
    }

    pub(crate) fn provider_preset_references(&self, preset_id: &str) -> Vec<String> {
        let needle = preset_id.trim();
        if needle.is_empty() {
            return Vec::new();
        }
        let mut refs = Vec::new();
        if self
            .field_value(telegram_llm_provider_key())
            .eq_ignore_ascii_case(needle)
        {
            refs.push("telegram channel".to_string());
        }
        if self
            .field_value(discord_llm_provider_key())
            .eq_ignore_ascii_case(needle)
        {
            refs.push("discord channel".to_string());
        }
        for slot in 1..=MAX_BOT_SLOTS {
            if self
                .field_value(&telegram_slot_model_key(slot))
                .eq_ignore_ascii_case(needle)
            {
                let id = self.field_value(&telegram_slot_id_key(slot));
                let label = if id.trim().is_empty() {
                    format!("telegram.bot{slot}")
                } else {
                    format!("telegram.{}", id.trim())
                };
                refs.push(label);
            }
        }
        for ch in DYNAMIC_CHANNELS {
            for slot in 1..=MAX_BOT_SLOTS {
                let key = dynamic_slot_llm_provider_key(ch.name, slot);
                if self.field_value(&key).eq_ignore_ascii_case(needle) {
                    let id = self.field_value(&dynamic_slot_id_field_key(ch.name, slot));
                    let label = if id.trim().is_empty() {
                        format!("{}.bot{}", ch.name, slot)
                    } else {
                        format!("{}.{}", ch.name, id.trim())
                    };
                    refs.push(label);
                }
            }
        }
        refs.sort();
        refs.dedup();
        refs
    }

    pub(crate) fn provider_preset_reference_summary(&self, preset_id: &str) -> String {
        let refs = self.provider_preset_references(preset_id);
        if refs.is_empty() {
            "unused".to_string()
        } else {
            format!("{} ref(s)", refs.len())
        }
    }

    pub(crate) fn provider_preset_field_labels() -> [&'static str; 7] {
        [
            "Preset ID",
            "Provider",
            "API key",
            "Default model",
            "Base URL",
            "Show thinking",
            "User-Agent (optional)",
        ]
    }

    pub(crate) fn provider_preset_selected_field_value(page: &ProviderPresetPage) -> String {
        let Some(entry) = page.entries.get(page.selected) else {
            return String::new();
        };
        match page.field_selected {
            0 => entry.id.clone(),
            1 => entry.provider.clone(),
            2 => entry.api_key.clone(),
            3 => entry.default_model.clone(),
            4 => entry.base_url.clone(),
            5 => entry.show_thinking.to_string(),
            6 => entry.user_agent.clone(),
            _ => String::new(),
        }
    }

    pub(crate) fn rename_provider_preset_references(
        &mut self,
        old_id: &str,
        new_id: &str,
    ) -> usize {
        let old_id = old_id.trim();
        if old_id.is_empty() || old_id.eq_ignore_ascii_case(new_id.trim()) {
            return 0;
        }
        let mut updated = 0usize;
        let mut maybe_replace = |key: &str, this: &mut SetupApp| {
            if this.field_value(key).eq_ignore_ascii_case(old_id) {
                this.set_field_value(key, new_id.trim().to_string());
                updated += 1;
            }
        };
        maybe_replace(telegram_llm_provider_key(), self);
        maybe_replace(discord_llm_provider_key(), self);
        for slot in 1..=MAX_BOT_SLOTS {
            maybe_replace(&telegram_slot_model_key(slot), self);
        }
        for ch in DYNAMIC_CHANNELS {
            for slot in 1..=MAX_BOT_SLOTS {
                let key = dynamic_slot_llm_provider_key(ch.name, slot);
                maybe_replace(&key, self);
            }
        }
        updated
    }

    pub(crate) fn selected_provider_preset_id(&self) -> Option<String> {
        self.provider_preset_page
            .as_ref()
            .and_then(|page| page.entries.get(page.selected))
            .map(|entry| entry.id.trim().to_string())
            .filter(|id| !id.is_empty())
    }

    pub(crate) fn clone_selected_provider_preset(
        &mut self,
    ) -> Result<Option<String>, MicroClawError> {
        let Some(page) = self.provider_preset_page.as_mut() else {
            return Ok(None);
        };
        let Some(selected_entry) = page.entries.get(page.selected).cloned() else {
            return Ok(None);
        };
        let mut cloned = selected_entry.clone();
        cloned.id = Self::next_cloned_provider_preset_id(&page.entries, &selected_entry.id);
        page.entries.push(cloned.clone());
        page.selected = page.entries.len().saturating_sub(1);
        page.mode = ProviderPresetPageMode::Edit;
        page.field_selected = 3;
        page.editing = false;
        self.sync_provider_preset_page_field()?;
        Ok(Some(cloned.id))
    }

    pub(crate) fn delete_selected_provider_preset(
        &mut self,
        fallback_to_main: bool,
    ) -> Result<Vec<String>, MicroClawError> {
        let Some(preset_id) = self.selected_provider_preset_id() else {
            return Ok(Vec::new());
        };
        let refs = self.provider_preset_references(&preset_id);
        if !refs.is_empty() && !fallback_to_main {
            return Err(MicroClawError::Config(format!(
                "Preset '{preset_id}' is still referenced by {}. Press x to reset those references to main and delete it.",
                refs.join(", ")
            )));
        }
        let reset_refs = if fallback_to_main { refs } else { Vec::new() };
        if fallback_to_main {
            self.rename_provider_preset_references(&preset_id, "");
        }
        if let Some(page) = self.provider_preset_page.as_mut() {
            if page.selected < page.entries.len() {
                page.entries.remove(page.selected);
                if page.selected >= page.entries.len() && !page.entries.is_empty() {
                    page.selected = page.entries.len() - 1;
                }
            }
        }
        self.sync_provider_preset_page_field()?;
        Ok(reset_refs)
    }

    pub(crate) fn set_provider_preset_selected_field_value(&mut self, value: String) {
        let mut old_id = String::new();
        let mut rename_target = false;
        let new_value_for_rename = value.clone();
        if let Some(page) = self.provider_preset_page.as_ref() {
            if page.field_selected == 0 {
                old_id = Self::provider_preset_selected_field_value(page);
                rename_target = true;
            }
        }
        if let Some(page) = self.provider_preset_page.as_mut() {
            let Some(entry) = page.entries.get_mut(page.selected) else {
                return;
            };
            match page.field_selected {
                0 => entry.id = value.clone(),
                1 => entry.provider = value,
                2 => entry.api_key = value,
                3 => entry.default_model = value,
                4 => entry.base_url = value,
                5 => entry.show_thinking = parse_bool_like(&value).unwrap_or(false),
                6 => entry.user_agent = value,
                _ => {}
            }
        }
        if rename_target {
            self.rename_provider_preset_references(&old_id, &new_value_for_rename);
        }
    }

    pub(crate) fn toggle_selected_provider_preset_show_thinking(&mut self) {
        if let Some(page) = self.provider_preset_page.as_mut() {
            let Some(entry) = page.entries.get_mut(page.selected) else {
                return;
            };
            entry.show_thinking = !entry.show_thinking;
        }
    }

    pub(crate) fn clear_selected_provider_preset_field(&mut self) {
        self.set_provider_preset_selected_field_value(String::new());
    }

    pub(crate) fn provider_preset_selected_field_default(&self) -> Option<String> {
        let page = self.provider_preset_page.as_ref()?;
        let entry = page.entries.get(page.selected)?;
        match page.field_selected {
            0 => Some(SetupApp::next_provider_preset_id(&page.entries)),
            1 => Some("anthropic".to_string()),
            2 => Some(String::new()),
            3 => Some(default_model_for_provider(&entry.provider).to_string()),
            4 => Some(
                find_provider_preset(&entry.provider)
                    .map(|preset| preset.default_base_url.to_string())
                    .unwrap_or_default(),
            ),
            5 => Some("false".to_string()),
            6 => Some(String::new()),
            _ => None,
        }
    }

    pub(crate) fn restore_selected_provider_preset_field_default(&mut self) -> Option<String> {
        let default = self.provider_preset_selected_field_default()?;
        self.set_provider_preset_selected_field_value(default.clone());
        Some(default)
    }

    pub(crate) fn open_provider_preset_provider_picker(&mut self) {
        let Some(page) = self.provider_preset_page.as_ref() else {
            return;
        };
        let current = page
            .entries
            .get(page.selected)
            .map(|entry| entry.provider.clone())
            .unwrap_or_default();
        let mut options = PROVIDER_PRESETS
            .iter()
            .map(|preset| {
                (
                    format!("{} - {}", preset.id, preset.label),
                    preset.id.to_string(),
                )
            })
            .collect::<Vec<_>>();
        if !current.trim().is_empty()
            && !options
                .iter()
                .any(|(_, value)| value.eq_ignore_ascii_case(current.trim()))
        {
            options.push((
                format!("{} - legacy/manual", current.trim()),
                current.clone(),
            ));
        }
        let selected = options
            .iter()
            .position(|(_, value)| value.eq_ignore_ascii_case(current.trim()))
            .unwrap_or(0);
        if let Some(page_mut) = self.provider_preset_page.as_mut() {
            page_mut.picker = Some(LlmOverridePicker {
                title: "Select Provider".to_string(),
                target_key: "provider".to_string(),
                options,
                selected,
            });
        }
    }

    pub(crate) fn open_provider_preset_model_picker(&mut self) {
        let (provider_value, current_default_model) = {
            let Some(page) = self.provider_preset_page.as_ref() else {
                return;
            };
            let Some(entry) = page.entries.get(page.selected) else {
                return;
            };
            (entry.provider.clone(), entry.default_model.clone())
        };
        let provider = provider_value.trim().to_string();
        let Some(preset) = find_provider_preset(&provider) else {
            if let Some(page_mut) = self.provider_preset_page.as_mut() {
                page_mut.editing = true;
            }
            self.status = "Unknown provider; switched to manual model input".to_string();
            return;
        };
        let mut options = if is_placeholder_provider_model_list(preset.models) {
            Vec::new()
        } else {
            preset
                .models
                .iter()
                .map(|model| ((*model).to_string(), (*model).to_string()))
                .collect::<Vec<_>>()
        };
        options.push((
            MODEL_PICKER_MANUAL_INPUT.to_string(),
            MODEL_PICKER_MANUAL_INPUT.to_string(),
        ));
        let selected = options
            .iter()
            .position(|(_, value)| value == &current_default_model)
            .unwrap_or(options.len().saturating_sub(1));
        if let Some(page_mut) = self.provider_preset_page.as_mut() {
            page_mut.picker = Some(LlmOverridePicker {
                title: format!("Select Model ({provider})"),
                target_key: "default_model".to_string(),
                options,
                selected,
            });
        }
    }

    pub(crate) fn apply_provider_preset_picker_selection(&mut self) {
        let status = {
            let Some(page) = self.provider_preset_page.as_mut() else {
                return;
            };
            let Some(picker) = page.picker.take() else {
                return;
            };
            let Some((_, value)) = picker.options.get(picker.selected) else {
                return;
            };
            if value == MODEL_PICKER_MANUAL_INPUT {
                page.editing = true;
                page.field_selected = 3;
                self.status = "Editing default model (manual input)".to_string();
                return;
            }
            let Some(entry) = page.entries.get_mut(page.selected) else {
                return;
            };
            match picker.target_key.as_str() {
                "provider" => {
                    let old_provider = entry.provider.clone();
                    let old_base_url = entry.base_url.clone();
                    let old_model = entry.default_model.clone();
                    entry.provider = value.clone();
                    let old_default_base_url = find_provider_preset(&old_provider)
                        .map(|preset| preset.default_base_url)
                        .unwrap_or("");
                    let next_default_base_url = find_provider_preset(value)
                        .map(|preset| preset.default_base_url)
                        .unwrap_or("");
                    if old_base_url.trim().is_empty() || old_base_url == old_default_base_url {
                        entry.base_url = next_default_base_url.to_string();
                    }
                    let old_model_in_old_preset = find_provider_preset(&old_provider)
                        .map(|preset| preset.models.iter().any(|model| *model == old_model))
                        .unwrap_or(false);
                    if old_model.trim().is_empty() || old_model_in_old_preset {
                        entry.default_model = default_model_for_provider(value).to_string();
                    }
                }
                "default_model" => entry.default_model = value.clone(),
                _ => {}
            }
            Some(format!("Updated provider preset {}", entry.id))
        };
        let _ = self.sync_provider_preset_page_field();
        if let Some(status) = status {
            self.status = status;
        }
    }

    pub(crate) fn handle_provider_preset_enter(&mut self) {
        let selected_field = self
            .provider_preset_page
            .as_ref()
            .map(|page| page.field_selected)
            .unwrap_or(0);
        let editing = self
            .provider_preset_page
            .as_ref()
            .map(|page| page.editing)
            .unwrap_or(false);
        if editing {
            if let Some(page) = self.provider_preset_page.as_mut() {
                page.editing = false;
            }
            let _ = self.sync_provider_preset_page_field();
            self.status = "Updated provider profile field".into();
            return;
        }

        match selected_field {
            1 => self.open_provider_preset_provider_picker(),
            3 => self.open_provider_preset_model_picker(),
            5 => {
                self.toggle_selected_provider_preset_show_thinking();
                let _ = self.sync_provider_preset_page_field();
                self.status = "Toggled provider profile show_thinking".into();
            }
            _ => {
                if let Some(page) = self.provider_preset_page.as_mut() {
                    page.editing = true;
                    self.status = "Editing provider profile field".into();
                }
            }
        }
    }

    pub(crate) fn llm_provider_preset_choices(&self, current: &str) -> Vec<(String, String)> {
        let mut options = vec![("main (global default)".to_string(), String::new())];
        let mut presets: Vec<(String, LlmProviderProfile)> =
            self.llm_provider_presets().into_iter().collect();
        presets.sort_by(|a, b| a.0.cmp(&b.0));
        for (preset_id, profile) in presets {
            let provider = profile.provider.unwrap_or_else(|| preset_id.clone());
            let model = profile.default_model.unwrap_or_default();
            let suffix = if model.is_empty() {
                provider
            } else {
                format!("{provider} / {model}")
            };
            options.push((format!("{preset_id} - {suffix}"), preset_id));
        }
        let trimmed_current = current.trim();
        if !trimmed_current.is_empty()
            && !options
                .iter()
                .any(|(_, value)| value.eq_ignore_ascii_case(trimmed_current))
        {
            options.push((
                format!("{trimmed_current} - legacy/manual"),
                trimmed_current.to_string(),
            ));
        }
        options
    }

    pub(crate) fn selected_provider_preset_validation_request(
        &self,
    ) -> Result<ProviderPresetValidationRequest, MicroClawError> {
        let Some(page) = self.provider_preset_page.as_ref() else {
            return Err(MicroClawError::Config(
                "No provider profile is currently selected".into(),
            ));
        };
        let Some(entry) = page.entries.get(page.selected) else {
            return Err(MicroClawError::Config(
                "No provider profile is currently selected".into(),
            ));
        };

        let provider = entry.provider.trim().to_ascii_lowercase();
        if provider.is_empty() {
            return Err(MicroClawError::Config(
                "Provider profile must set a provider before testing".into(),
            ));
        }

        let configured_api_key = entry.api_key.trim().to_string();
        let (api_key, codex_account_id) = if is_openai_codex_provider(&provider) {
            let auth = resolve_openai_codex_auth(&configured_api_key)?;
            (auth.bearer_token, auth.account_id)
        } else if provider.eq_ignore_ascii_case("qwen-portal") && configured_api_key.is_empty() {
            let auth = resolve_qwen_portal_auth("")?;
            (auth.bearer_token, None)
        } else {
            (configured_api_key, None)
        };

        let base_url = entry.base_url.trim().to_string();
        let user_agent = entry.user_agent.trim().to_string();
        let model = if entry.default_model.trim().is_empty() {
            default_model_for_provider(&provider).to_string()
        } else {
            entry.default_model.trim().to_string()
        };

        Ok(ProviderPresetValidationRequest {
            profile_id: entry.id.clone(),
            provider,
            api_key,
            base_url,
            user_agent,
            model,
            codex_account_id,
        })
    }

    pub(crate) fn validate_selected_provider_preset_online(
        &self,
    ) -> Result<(String, Vec<String>), MicroClawError> {
        let request = self.selected_provider_preset_validation_request()?;
        let profile_id = request.profile_id.clone();
        let checks = std::thread::spawn(move || {
            perform_online_validation(
                false,
                false,
                "",
                "",
                &request.provider,
                &request.api_key,
                &request.base_url,
                &request.user_agent,
                &request.model,
                request.codex_account_id.as_deref(),
            )
        })
        .join()
        .map_err(|_| MicroClawError::Config("Validation thread panicked".into()))??;
        Ok((profile_id, checks))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use crate::setup::test_prelude::*;

    #[test]
    fn test_normalize_setup_provider_id_collapses_custom_suffixes() {
        assert_eq!(normalize_setup_provider_id("custom18"), "custom");
        assert_eq!(normalize_setup_provider_id("CUSTOM42"), "custom");
        assert_eq!(normalize_setup_provider_id("anthropic"), "anthropic");
    }

    #[test]
    fn test_provider_preset_serialization_keeps_user_agent_and_show_thinking() {
        let json = SetupApp::serialize_provider_preset_drafts(&[ProviderPresetDraft {
            id: "provider1".into(),
            provider: "openai".into(),
            api_key: "sk-test".into(),
            base_url: "https://example.com/v1".into(),
            user_agent: "microclaw-test/1.0".into(),
            default_model: "gpt-5.2".into(),
            show_thinking: true,
        }])
        .unwrap();
        let presets =
            parse_provider_presets_json_value(&json, llm_provider_profiles_key()).unwrap();
        let preset = presets.get("provider1").unwrap();
        assert_eq!(preset.llm_user_agent.as_deref(), Some("microclaw-test/1.0"));
        assert_eq!(preset.show_thinking, Some(true));
    }

    #[test]
    fn test_clone_selected_provider_preset_creates_dash_suffix_copy_and_focuses_model() {
        let mut app = SetupApp::new();
        app.provider_preset_page = Some(ProviderPresetPage {
            entries: vec![ProviderPresetDraft {
                id: "provider1".into(),
                provider: "anthropic".into(),
                api_key: "sk-test".into(),
                base_url: "https://example.com/v1".into(),
                user_agent: "microclaw-test/1.0".into(),
                default_model: "claude-sonnet-4-5-20250929".into(),
                show_thinking: true,
            }],
            selected: 0,
            mode: ProviderPresetPageMode::List,
            field_selected: 0,
            editing: false,
            picker: None,
        });

        let cloned_id = app.clone_selected_provider_preset().unwrap().unwrap();

        assert_eq!(cloned_id, "provider1-2");
        let page = app.provider_preset_page.as_ref().unwrap();
        assert_eq!(page.entries.len(), 2);
        assert_eq!(page.selected, 1);
        assert!(matches!(page.mode, ProviderPresetPageMode::Edit));
        assert_eq!(page.field_selected, 3);
        assert!(!page.editing);
        assert_eq!(page.entries[1].id, "provider1-2");
        assert_eq!(page.entries[1].provider, "anthropic");
        assert_eq!(page.entries[1].default_model, "claude-sonnet-4-5-20250929");
        assert!(page.entries[1].show_thinking);
    }

    #[test]
    fn test_selected_provider_preset_validation_request_uses_current_entry_values() {
        let mut app = SetupApp::new();
        app.provider_preset_page = Some(ProviderPresetPage {
            entries: vec![ProviderPresetDraft {
                id: "provider1".into(),
                provider: "anthropic".into(),
                api_key: "sk-test".into(),
                base_url: "https://example.com/v1".into(),
                user_agent: "microclaw-test/1.0".into(),
                default_model: String::new(),
                show_thinking: false,
            }],
            selected: 0,
            mode: ProviderPresetPageMode::Edit,
            field_selected: 0,
            editing: false,
            picker: None,
        });

        let request = app.selected_provider_preset_validation_request().unwrap();

        assert_eq!(request.profile_id, "provider1");
        assert_eq!(request.provider, "anthropic");
        assert_eq!(request.api_key, "sk-test");
        assert_eq!(request.base_url, "https://example.com/v1");
        assert_eq!(request.user_agent, "microclaw-test/1.0");
        assert_eq!(request.model, "claude-fable-5");
        assert_eq!(request.codex_account_id, None);
    }

    #[test]
    fn test_clear_selected_provider_preset_field_clears_without_edit_mode() {
        let mut app = SetupApp::new();
        app.provider_preset_page = Some(ProviderPresetPage {
            entries: vec![ProviderPresetDraft {
                id: "provider1".into(),
                provider: "google".into(),
                api_key: "secret".into(),
                base_url: "https://example.com/v1".into(),
                user_agent: "ua".into(),
                default_model: "gemini-2.5-pro".into(),
                show_thinking: false,
            }],
            selected: 0,
            mode: ProviderPresetPageMode::Edit,
            field_selected: 2,
            editing: false,
            picker: None,
        });

        app.clear_selected_provider_preset_field();

        let page = app.provider_preset_page.as_ref().unwrap();
        assert_eq!(page.entries[0].api_key, "");
    }

    #[test]
    fn test_restore_selected_provider_preset_field_default_restores_provider_base_url() {
        let mut app = SetupApp::new();
        app.provider_preset_page = Some(ProviderPresetPage {
            entries: vec![ProviderPresetDraft {
                id: "provider1".into(),
                provider: "openai".into(),
                api_key: String::new(),
                base_url: "https://integrate.api.nvidia.com/v1".into(),
                user_agent: String::new(),
                default_model: "meta/llama-3.3-70b-instruct".into(),
                show_thinking: false,
            }],
            selected: 0,
            mode: ProviderPresetPageMode::Edit,
            field_selected: 4,
            editing: false,
            picker: None,
        });

        let restored = app
            .restore_selected_provider_preset_field_default()
            .unwrap();

        assert_eq!(restored, "https://api.openai.com/v1");
        let page = app.provider_preset_page.as_ref().unwrap();
        assert_eq!(page.entries[0].base_url, "https://api.openai.com/v1");
    }

    #[test]
    fn test_switching_provider_updates_default_base_url_and_model_when_still_on_old_defaults() {
        let mut app = SetupApp::new();
        app.provider_preset_page = Some(ProviderPresetPage {
            entries: vec![ProviderPresetDraft {
                id: "provider1".into(),
                provider: "nvidia".into(),
                api_key: String::new(),
                base_url: "https://integrate.api.nvidia.com/v1".into(),
                user_agent: String::new(),
                default_model: "meta/llama-3.3-70b-instruct".into(),
                show_thinking: false,
            }],
            selected: 0,
            mode: ProviderPresetPageMode::Edit,
            field_selected: 1,
            editing: false,
            picker: Some(LlmOverridePicker {
                title: "Select Provider".into(),
                target_key: "provider".into(),
                options: vec![("openai".into(), "openai".into())],
                selected: 0,
            }),
        });

        app.apply_provider_preset_picker_selection();

        let page = app.provider_preset_page.as_ref().unwrap();
        assert_eq!(page.entries[0].provider, "openai");
        assert_eq!(page.entries[0].base_url, "https://api.openai.com/v1");
        assert_eq!(page.entries[0].default_model, "gpt-5.6-sol");
    }

    #[test]
    fn test_provider_preset_enter_on_default_model_opens_model_picker() {
        let mut app = SetupApp::new();
        app.provider_preset_page = Some(ProviderPresetPage {
            entries: vec![ProviderPresetDraft {
                id: "provider1".into(),
                provider: "openai".into(),
                api_key: String::new(),
                base_url: "https://api.openai.com/v1".into(),
                user_agent: String::new(),
                default_model: "gpt-5.2".into(),
                show_thinking: false,
            }],
            selected: 0,
            mode: ProviderPresetPageMode::Edit,
            field_selected: 3,
            editing: false,
            picker: None,
        });

        app.handle_provider_preset_enter();

        let page = app.provider_preset_page.as_ref().unwrap();
        let picker = page.picker.as_ref().unwrap();
        assert_eq!(picker.target_key, "default_model");
        assert!(picker.title.contains("openai"));
        assert!(!page.editing);
    }

    #[test]
    fn test_provider_preset_enter_on_base_url_starts_text_editing() {
        let mut app = SetupApp::new();
        app.provider_preset_page = Some(ProviderPresetPage {
            entries: vec![ProviderPresetDraft {
                id: "provider1".into(),
                provider: "openai".into(),
                api_key: String::new(),
                base_url: "https://api.openai.com/v1".into(),
                user_agent: String::new(),
                default_model: "gpt-5.2".into(),
                show_thinking: false,
            }],
            selected: 0,
            mode: ProviderPresetPageMode::Edit,
            field_selected: 4,
            editing: false,
            picker: None,
        });

        app.handle_provider_preset_enter();

        let page = app.provider_preset_page.as_ref().unwrap();
        assert!(page.editing);
        assert!(page.picker.is_none());
        assert_eq!(app.status, "Editing provider profile field");
    }

    #[test]
    fn test_custom_provider_model_picker_hides_placeholder_model() {
        let mut app = SetupApp::new();
        app.provider_preset_page = Some(ProviderPresetPage {
            entries: vec![ProviderPresetDraft {
                id: "provider1".into(),
                provider: "custom".into(),
                api_key: String::new(),
                base_url: "https://example.com/v1".into(),
                user_agent: String::new(),
                default_model: "custom-model".into(),
                show_thinking: false,
            }],
            selected: 0,
            mode: ProviderPresetPageMode::Edit,
            field_selected: 3,
            editing: false,
            picker: None,
        });

        app.open_provider_preset_model_picker();

        let page = app.provider_preset_page.as_ref().unwrap();
        let picker = page.picker.as_ref().unwrap();
        assert_eq!(picker.target_key, "default_model");
        assert_eq!(picker.options.len(), 1);
        assert_eq!(picker.options[0].0, MODEL_PICKER_MANUAL_INPUT);
        assert_eq!(picker.options[0].1, MODEL_PICKER_MANUAL_INPUT);
    }

    #[test]
    fn test_resolve_openai_compat_validation_base_keeps_non_v1_prefix() {
        let preset = find_provider_preset("zhipu");
        let base = resolve_openai_compat_validation_base("zhipu", "", preset);
        assert_eq!(base, "https://open.bigmodel.cn/api/paas/v4");
    }

    #[test]
    fn test_default_model_for_minimax_is_m3() {
        assert_eq!(default_model_for_provider("minimax"), "MiniMax-M3");
    }

    #[test]
    fn test_default_model_for_xiaomi_is_mimo_v2_5_pro() {
        assert_eq!(default_model_for_provider("xiaomi"), "mimo-v2.5-pro");
    }

    #[test]
    fn test_provider_presets_are_sorted_alphabetically() {
        // Invariant: PROVIDER_PRESETS is sorted A→Z by id. The setup
        // wizard's preset picker and the generated provider matrix both
        // assume this ordering. If you add a new provider, place it in
        // the right alphabetical slot.
        let ids: Vec<&str> = PROVIDER_PRESETS.iter().map(|p| p.id).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(
            ids, sorted,
            "PROVIDER_PRESETS must stay sorted A→Z; out of order entries above"
        );
    }

    #[test]
    fn test_provider_presets_include_synthetic_chutes_and_qwen_code() {
        assert!(find_provider_preset("synthetic").is_some());
        assert!(find_provider_preset("chutes").is_some());
        assert!(find_provider_preset("qwen-portal").is_some());
        assert!(find_provider_preset("aliyun-bailian").is_some());
        assert!(find_provider_preset("nvidia").is_some());
    }
}
