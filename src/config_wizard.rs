use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde::Deserialize;

use crate::config::{Config, WorkingDirIsolation};
use crate::error::MicroClawError;

#[derive(Clone, Copy)]
struct ProviderPreset {
    id: &'static str,
    label: &'static str,
    default_base_url: &'static str,
    models: &'static [&'static str],
}

const PROVIDER_PRESETS: &[ProviderPreset] = &[
    ProviderPreset {
        id: "openai",
        label: "OpenAI",
        default_base_url: "https://api.openai.com/v1",
        models: &["gpt-5.2", "gpt-5", "gpt-5-mini"],
    },
    ProviderPreset {
        id: "openrouter",
        label: "OpenRouter",
        default_base_url: "https://openrouter.ai/api/v1",
        models: &[
            "openrouter/auto",
            "anthropic/claude-sonnet-4.5",
            "openai/gpt-5.2",
        ],
    },
    ProviderPreset {
        id: "anthropic",
        label: "Anthropic",
        default_base_url: "",
        models: &["claude-sonnet-4-5-20250929", "claude-opus-4-6-20260205"],
    },
    ProviderPreset {
        id: "ollama",
        label: "Ollama (local)",
        default_base_url: "http://127.0.0.1:11434/v1",
        models: &["llama3.2", "qwen2.5-coder:7b", "mistral"],
    },
    ProviderPreset {
        id: "google",
        label: "Google DeepMind",
        default_base_url: "https://generativelanguage.googleapis.com/v1beta/openai",
        models: &["gemini-2.5-pro", "gemini-2.5-flash"],
    },
    ProviderPreset {
        id: "alibaba",
        label: "Alibaba Cloud (Qwen / DashScope)",
        default_base_url: "https://dashscope.aliyuncs.com/compatible-mode/v1",
        models: &["qwen3-max", "qwen-max-latest"],
    },
    ProviderPreset {
        id: "deepseek",
        label: "DeepSeek",
        default_base_url: "https://api.deepseek.com/v1",
        models: &["deepseek-chat", "deepseek-reasoner"],
    },
    ProviderPreset {
        id: "moonshot",
        label: "Moonshot AI (Kimi)",
        default_base_url: "https://api.moonshot.cn/v1",
        models: &["kimi-k2.5", "kimi-k2"],
    },
    ProviderPreset {
        id: "mistral",
        label: "Mistral AI",
        default_base_url: "https://api.mistral.ai/v1",
        models: &["mistral-large-latest", "ministral-8b-latest"],
    },
    ProviderPreset {
        id: "azure",
        label: "Microsoft Azure AI",
        default_base_url:
            "https://YOUR-RESOURCE.openai.azure.com/openai/deployments/YOUR-DEPLOYMENT",
        models: &["gpt-5.2", "gpt-5"],
    },
    ProviderPreset {
        id: "bedrock",
        label: "Amazon AWS Bedrock",
        default_base_url: "https://bedrock-runtime.YOUR-REGION.amazonaws.com/openai/v1",
        models: &[
            "anthropic.claude-opus-4-6-v1",
            "anthropic.claude-sonnet-4-5-v2",
        ],
    },
    ProviderPreset {
        id: "zhipu",
        label: "Zhipu AI (GLM / Z.AI)",
        default_base_url: "https://open.bigmodel.cn/api/paas/v4",
        models: &["glm-4.7", "glm-4.7-flash"],
    },
    ProviderPreset {
        id: "minimax",
        label: "MiniMax",
        default_base_url: "https://api.minimax.io/v1",
        models: &["MiniMax-M2.1"],
    },
    ProviderPreset {
        id: "cohere",
        label: "Cohere",
        default_base_url: "https://api.cohere.ai/compatibility/v1",
        models: &["command-a-03-2025", "command-r-plus-08-2024"],
    },
    ProviderPreset {
        id: "tencent",
        label: "Tencent AI Lab",
        default_base_url: "https://api.hunyuan.cloud.tencent.com/v1",
        models: &["hunyuan-t1-latest", "hunyuan-turbos-latest"],
    },
    ProviderPreset {
        id: "xai",
        label: "xAI",
        default_base_url: "https://api.x.ai/v1",
        models: &["grok-4", "grok-3"],
    },
    ProviderPreset {
        id: "huggingface",
        label: "Hugging Face",
        default_base_url: "https://router.huggingface.co/v1",
        models: &["Qwen/Qwen3-Coder-Next", "meta-llama/Llama-3.3-70B-Instruct"],
    },
    ProviderPreset {
        id: "together",
        label: "Together AI",
        default_base_url: "https://api.together.xyz/v1",
        models: &[
            "deepseek-ai/DeepSeek-V3",
            "meta-llama/Llama-3.3-70B-Instruct-Turbo",
        ],
    },
    ProviderPreset {
        id: "custom",
        label: "Custom (manual config)",
        default_base_url: "",
        models: &["custom-model"],
    },
];

fn find_provider_preset(provider: &str) -> Option<&'static ProviderPreset> {
    PROVIDER_PRESETS
        .iter()
        .find(|p| p.id.eq_ignore_ascii_case(provider))
}

fn resolve_config_path() -> PathBuf {
    if let Ok(custom) = std::env::var("MICROCLAW_CONFIG") {
        return PathBuf::from(custom);
    }
    if Path::new("./microclaw.config.yaml").exists() {
        PathBuf::from("./microclaw.config.yaml")
    } else if Path::new("./microclaw.config.yml").exists() {
        PathBuf::from("./microclaw.config.yml")
    } else {
        PathBuf::from("./microclaw.config.yaml")
    }
}

fn load_existing_config(path: &Path) -> Option<Config> {
    let content = fs::read_to_string(path).ok()?;
    serde_yaml::from_str::<Config>(&content).ok()
}

fn prompt_line(
    prompt: &str,
    default: Option<&str>,
    required: bool,
) -> Result<Option<String>, MicroClawError> {
    loop {
        let suffix = match default {
            Some(d) if !d.is_empty() => format!(" [{d}]"),
            _ => String::new(),
        };
        print!("{prompt}{suffix}: ");
        io::stdout().flush()?;

        let mut buf = String::new();
        io::stdin().read_line(&mut buf)?;
        let trimmed = buf.trim();

        if trimmed.eq_ignore_ascii_case("q") || trimmed.eq_ignore_ascii_case("quit") {
            return Ok(None);
        }
        if trimmed.is_empty() {
            if let Some(d) = default {
                return Ok(Some(d.to_string()));
            }
            if !required {
                return Ok(Some(String::new()));
            }
            println!("This field is required. Enter a value or type 'q' to cancel.");
            continue;
        }
        return Ok(Some(trimmed.to_string()));
    }
}

fn prompt_provider(default_provider: &str) -> Result<Option<String>, MicroClawError> {
    println!();
    println!("Select LLM provider (press Enter for default):");
    let default_idx = PROVIDER_PRESETS
        .iter()
        .position(|p| p.id.eq_ignore_ascii_case(default_provider))
        .unwrap_or(0);
    for (i, preset) in PROVIDER_PRESETS.iter().enumerate() {
        let mark = if i == default_idx { "*" } else { " " };
        println!("  {mark} {}. {} ({})", i + 1, preset.id, preset.label);
    }

    loop {
        print!("Provider number [{}]: ", default_idx + 1);
        io::stdout().flush()?;
        let mut buf = String::new();
        io::stdin().read_line(&mut buf)?;
        let trimmed = buf.trim();

        if trimmed.eq_ignore_ascii_case("q") || trimmed.eq_ignore_ascii_case("quit") {
            return Ok(None);
        }
        if trimmed.is_empty() {
            return Ok(Some(PROVIDER_PRESETS[default_idx].id.to_string()));
        }
        if let Ok(n) = trimmed.parse::<usize>() {
            if (1..=PROVIDER_PRESETS.len()).contains(&n) {
                return Ok(Some(PROVIDER_PRESETS[n - 1].id.to_string()));
            }
        }
        if let Some(p) = find_provider_preset(trimmed) {
            return Ok(Some(p.id.to_string()));
        }
        println!("Invalid provider. Enter a number, provider id, or 'q' to cancel.");
    }
}

#[derive(Debug, Deserialize)]
struct OllamaTagsResponse {
    models: Vec<OllamaModel>,
}

#[derive(Debug, Deserialize)]
struct OllamaModel {
    name: String,
}

fn ollama_tags_url(base_url: &str) -> String {
    let mut base = base_url.trim().trim_end_matches('/').to_string();
    if base.ends_with("/v1") {
        base = base.trim_end_matches("/v1").to_string();
    }
    if base.is_empty() {
        base = "http://127.0.0.1:11434".to_string();
    }
    format!("{base}/api/tags")
}

fn detect_ollama_models(base_url: &str) -> Vec<String> {
    let tags_url = ollama_tags_url(base_url);
    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
    {
        Ok(c) => c,
        Err(_) => return vec![],
    };
    let resp = match client.get(tags_url).send() {
        Ok(r) => r,
        Err(_) => return vec![],
    };
    let parsed = match resp.json::<OllamaTagsResponse>() {
        Ok(p) => p,
        Err(_) => return vec![],
    };
    parsed.models.into_iter().map(|m| m.name).collect()
}

fn prompt_model(
    provider: &str,
    default_model: &str,
    base_url: &str,
) -> Result<Option<String>, MicroClawError> {
    let mut options: Vec<String> = find_provider_preset(provider)
        .map(|p| p.models.iter().map(|m| m.to_string()).collect())
        .unwrap_or_else(|| vec![default_model.to_string()]);

    if provider.eq_ignore_ascii_case("ollama") {
        let installed = detect_ollama_models(base_url);
        if !installed.is_empty() {
            println!("Detected Ollama local models:");
            for m in &installed {
                println!("  - {m}");
            }
            options = installed;
        } else {
            println!("No local Ollama models detected (or Ollama not reachable).");
            println!("Tip: run `ollama pull llama3.2` then re-run `microclaw config`.");
        }
    }

    if !options.iter().any(|m| m == default_model) {
        options.insert(0, default_model.to_string());
    }

    println!();
    println!("Select model (number) or type a custom model id:");
    for (i, model) in options.iter().enumerate() {
        let mark = if model == default_model { "*" } else { " " };
        println!("  {mark} {}. {model}", i + 1);
    }

    print!("Model [{}]: ", default_model);
    io::stdout().flush()?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    let trimmed = buf.trim();

    if trimmed.eq_ignore_ascii_case("q") || trimmed.eq_ignore_ascii_case("quit") {
        return Ok(None);
    }
    if trimmed.is_empty() {
        return Ok(Some(default_model.to_string()));
    }
    if let Ok(n) = trimmed.parse::<usize>() {
        if (1..=options.len()).contains(&n) {
            return Ok(Some(options[n - 1].clone()));
        }
    }
    Ok(Some(trimmed.to_string()))
}

fn save_config_yaml(path: &Path, config: &Config) -> Result<Option<PathBuf>, MicroClawError> {
    let mut backup = None;
    if path.exists() {
        let ts = Utc::now().format("%Y%m%d%H%M%S");
        let backup_path = path.with_extension(format!(
            "{}.bak.{ts}",
            path.extension().and_then(|s| s.to_str()).unwrap_or("yaml")
        ));
        fs::copy(path, &backup_path)?;
        backup = Some(backup_path);
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let content = serde_yaml::to_string(config)
        .map_err(|e| MicroClawError::Config(format!("Failed to serialize config: {e}")))?;
    fs::write(path, content)?;
    Ok(backup)
}

fn default_config() -> Config {
    Config {
        telegram_bot_token: String::new(),
        bot_username: String::new(),
        llm_provider: "anthropic".into(),
        api_key: String::new(),
        model: "claude-sonnet-4-5-20250929".into(),
        llm_base_url: None,
        max_tokens: 8192,
        max_tool_iterations: 100,
        max_history_messages: 50,
        max_document_size_mb: 100,
        data_dir: "./microclaw.data".into(),
        working_dir: "./tmp".into(),
        working_dir_isolation: WorkingDirIsolation::Chat,
        openai_api_key: None,
        timezone: "UTC".into(),
        allowed_groups: vec![],
        control_chat_ids: vec![],
        max_session_messages: 40,
        compact_keep_recent: 20,
        whatsapp_access_token: None,
        whatsapp_phone_number_id: None,
        whatsapp_verify_token: None,
        whatsapp_webhook_port: 8080,
        discord_bot_token: None,
        discord_allowed_channels: vec![],
        show_thinking: false,
        web_enabled: true,
        web_host: "127.0.0.1".into(),
        web_port: 10961,
        web_auth_token: None,
        web_max_inflight_per_session: 2,
        web_max_requests_per_window: 8,
        web_rate_window_seconds: 10,
        web_run_history_limit: 512,
        web_session_idle_ttl_seconds: 300,
    }
}

pub fn run_config_wizard() -> Result<bool, MicroClawError> {
    let config_path = resolve_config_path();
    let existing = load_existing_config(&config_path).unwrap_or_else(default_config);

    println!("MicroClaw interactive config");
    println!("Press Enter to accept default values. Type 'q' to cancel.");
    println!("Config path: {}", config_path.display());

    let telegram_bot_token = match prompt_line(
        "Telegram bot token",
        Some(&existing.telegram_bot_token),
        true,
    )? {
        Some(v) => v,
        None => return Ok(false),
    };
    let bot_username = match prompt_line(
        "Bot username (without @)",
        Some(&existing.bot_username),
        true,
    )? {
        Some(v) => v.trim_start_matches('@').to_string(),
        None => return Ok(false),
    };

    let provider = match prompt_provider(&existing.llm_provider)? {
        Some(v) => v,
        None => return Ok(false),
    };
    let preset = find_provider_preset(&provider);

    let provider_changed = !provider.eq_ignore_ascii_case(&existing.llm_provider);
    let default_base_url = if provider_changed {
        preset
            .map(|p| p.default_base_url.to_string())
            .unwrap_or_default()
    } else {
        existing.llm_base_url.clone().unwrap_or_else(|| {
            preset
                .map(|p| p.default_base_url.to_string())
                .unwrap_or_default()
        })
    };
    let llm_base_url = match prompt_line("LLM base URL (optional)", Some(&default_base_url), false)?
    {
        Some(v) => {
            let t = v.trim().to_string();
            if t.is_empty() {
                None
            } else {
                Some(t)
            }
        }
        None => return Ok(false),
    };

    let api_default = existing.api_key.clone();
    let api_prompt = if provider.eq_ignore_ascii_case("ollama") {
        "LLM API key (optional for ollama)"
    } else {
        "LLM API key"
    };
    let api_key = match prompt_line(
        api_prompt,
        Some(&api_default),
        !provider.eq_ignore_ascii_case("ollama"),
    )? {
        Some(v) => v,
        None => return Ok(false),
    };

    let default_model = if provider_changed || existing.model.trim().is_empty() {
        preset
            .and_then(|p| p.models.first().copied())
            .unwrap_or("gpt-5.2")
            .to_string()
    } else {
        existing.model.clone()
    };
    let model = match prompt_model(
        &provider,
        &default_model,
        llm_base_url
            .as_deref()
            .unwrap_or(preset.map(|p| p.default_base_url).unwrap_or("")),
    )? {
        Some(v) => v,
        None => return Ok(false),
    };

    let data_dir = match prompt_line("Data directory", Some(&existing.data_dir), false)? {
        Some(v) => {
            if v.trim().is_empty() {
                "./microclaw.data".to_string()
            } else {
                v
            }
        }
        None => return Ok(false),
    };
    let working_dir = match prompt_line("Working directory", Some(&existing.working_dir), false)? {
        Some(v) => {
            if v.trim().is_empty() {
                "./tmp".to_string()
            } else {
                v
            }
        }
        None => return Ok(false),
    };
    let timezone = match prompt_line("Timezone (IANA)", Some(&existing.timezone), false)? {
        Some(v) => {
            if v.trim().is_empty() {
                "UTC".to_string()
            } else {
                v
            }
        }
        None => return Ok(false),
    };

    let mut out = existing.clone();
    out.telegram_bot_token = telegram_bot_token;
    out.bot_username = bot_username;
    out.llm_provider = provider;
    out.api_key = api_key;
    out.model = model;
    out.llm_base_url = llm_base_url;
    out.data_dir = data_dir;
    out.working_dir = working_dir;
    out.timezone = timezone;
    out.post_deserialize()?;

    fs::create_dir_all(&out.data_dir)?;
    fs::create_dir_all(&out.working_dir)?;

    let backup = save_config_yaml(&config_path, &out)?;
    println!();
    println!("Saved config to {}", config_path.display());
    if let Some(b) = backup {
        println!("Backup created at {}", b.display());
    }
    Ok(true)
}
