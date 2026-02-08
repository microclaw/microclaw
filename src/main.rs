mod builtin_skills;
mod claude;
mod config;
mod db;
mod discord;
mod error;
mod llm;
mod mcp;
mod memory;
mod scheduler;
mod setup;
mod skills;
mod telegram;
mod tools;
mod transcribe;
mod whatsapp;

use config::Config;
use error::MicroClawError;
use std::path::Path;
use tracing::info;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_help() {
    println!(
        r#"MicroClaw v{VERSION} — Agentic AI assistant for Telegram, WhatsApp & Discord

USAGE:
    microclaw <COMMAND>

COMMANDS:
    start       Start the bot (Telegram + optional WhatsApp/Discord)
    setup       Run interactive setup wizard
    version     Show version information
    help        Show this help message

FEATURES:
    - Agentic tool use (bash, files, search, memory)
    - Web search and page fetching
    - Image/photo understanding (Claude Vision)
    - Voice message transcription (OpenAI Whisper)
    - Scheduled/recurring tasks with timezone support
    - Task execution history/run logs
    - Chat export to markdown
    - Mid-conversation message sending
    - Group chat catch-up (reads all messages since last reply)
    - Group allowlist (restrict which groups can use the bot)
    - Continuous typing indicator
    - MCP (Model Context Protocol) server integration
    - WhatsApp Cloud API support
    - Discord bot support
    - Sensitive path blacklisting for file tools

SETUP:
    1. Run: microclaw setup
       (or run microclaw start and follow auto-setup on first launch)
    2. Edit microclaw.config.yaml with required values:

       telegram_bot_token    Bot token from @BotFather
       api_key               LLM API key
       bot_username          Your bot's username (without @)

    3. Run: microclaw start

CONFIG FILE (microclaw.config.yaml):
    MicroClaw reads configuration from microclaw.config.yaml (or microclaw.config.yml).
    Override the path with MICROCLAW_CONFIG env var.
    See config.example.yaml for all available fields.

    Core fields:
      telegram_bot_token     Telegram bot token from @BotFather
      bot_username           Bot username without @
      llm_provider           Provider preset (default: anthropic)
      api_key                LLM API key
      model                  Model name (auto-detected from provider if empty)
      llm_base_url           Custom base URL (optional)

    Runtime:
      data_dir               Data root (runtime in ./microclaw.data/runtime, skills in ./microclaw.data/skills)
      max_tokens             Max tokens per response (default: 8192)
      max_tool_iterations    Max tool loop iterations (default: 25)
      max_history_messages   Chat history context size (default: 50)
      openai_api_key         OpenAI key for voice transcription (optional)
      timezone               IANA timezone for scheduling (default: UTC)
      allowed_groups         List of chat IDs to allow (empty = all)

    WhatsApp (optional):
      whatsapp_access_token       Meta API access token
      whatsapp_phone_number_id    Phone number ID from Meta dashboard
      whatsapp_verify_token       Webhook verification token
      whatsapp_webhook_port       Webhook server port (default: 8080)

    Discord (optional):
      discord_bot_token           Discord bot token from Discord Developer Portal
      discord_allowed_channels    List of channel IDs to respond in (empty = all)

MCP (optional):
    Place a mcp.json file in data_dir to connect MCP servers.
    See https://modelcontextprotocol.io for details.

EXAMPLES:
    microclaw start          Start the bot
    microclaw setup          Run interactive setup wizard
    microclaw version        Show version
    microclaw help           Show this message

ABOUT:
    https://microclaw.ai"#
    );
}

fn print_version() {
    println!("microclaw {VERSION}");
}

fn move_path(src: &Path, dst: &Path) -> std::io::Result<()> {
    if std::fs::rename(src, dst).is_ok() {
        return Ok(());
    }

    if src.is_dir() {
        std::fs::create_dir_all(dst)?;
        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            let child_src = entry.path();
            let child_dst = dst.join(entry.file_name());
            move_path(&child_src, &child_dst)?;
        }
        std::fs::remove_dir_all(src)?;
    } else {
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(src, dst)?;
        std::fs::remove_file(src)?;
    }

    Ok(())
}

fn migrate_legacy_runtime_layout(data_root: &Path, runtime_dir: &Path) {
    if std::fs::create_dir_all(runtime_dir).is_err() {
        return;
    }

    let entries = match std::fs::read_dir(data_root) {
        Ok(entries) => entries,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if name_str == "skills" || name_str == "runtime" || name_str == "mcp.json" {
            continue;
        }
        let src = entry.path();
        let dst = runtime_dir.join(name_str);
        if dst.exists() {
            continue;
        }
        if let Err(e) = move_path(&src, &dst) {
            tracing::warn!(
                "Failed to migrate legacy data '{}' -> '{}': {}",
                src.display(),
                dst.display(),
                e
            );
        } else {
            tracing::info!(
                "Migrated legacy runtime data '{}' -> '{}'",
                src.display(),
                dst.display()
            );
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let command = args.get(1).map(|s| s.as_str());

    match command {
        Some("start") => {}
        Some("setup") => {
            let saved = setup::run_setup_wizard()?;
            if saved {
                println!("Setup saved to microclaw.config.yaml");
            } else {
                println!("Setup canceled");
            }
            return Ok(());
        }
        Some("version" | "--version" | "-V") => {
            print_version();
            return Ok(());
        }
        Some("help" | "--help" | "-h") | None => {
            print_help();
            return Ok(());
        }
        Some(unknown) => {
            eprintln!("Unknown command: {unknown}\n");
            print_help();
            std::process::exit(1);
        }
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let config = match Config::load() {
        Ok(c) => c,
        Err(MicroClawError::Config(e)) => {
            eprintln!("Config missing/invalid: {e}");
            eprintln!("Launching setup wizard...");
            let saved = setup::run_setup_wizard()?;
            if !saved {
                return Err(anyhow::anyhow!(
                    "setup canceled and config is still incomplete"
                ));
            }
            Config::load()?
        }
        Err(e) => return Err(e.into()),
    };
    info!("Starting MicroClaw bot...");

    let data_root_dir = config.data_root_dir();
    let runtime_data_dir = config.runtime_data_dir();
    let skills_data_dir = config.skills_data_dir();
    migrate_legacy_runtime_layout(&data_root_dir, Path::new(&runtime_data_dir));
    builtin_skills::ensure_builtin_skills(&data_root_dir)?;

    let db = db::Database::new(&runtime_data_dir)?;
    info!("Database initialized");

    let memory_manager = memory::MemoryManager::new(&runtime_data_dir);
    info!("Memory manager initialized");

    let skill_manager = skills::SkillManager::from_skills_dir(&skills_data_dir);
    let discovered = skill_manager.discover_skills();
    info!(
        "Skill manager initialized ({} skills discovered)",
        discovered.len()
    );

    // Initialize MCP servers (optional, configured via <data_root>/mcp.json)
    let mcp_config_path = data_root_dir.join("mcp.json").to_string_lossy().to_string();
    let mcp_manager = mcp::McpManager::from_config_file(&mcp_config_path).await;
    let mcp_tool_count: usize = mcp_manager.all_tools().len();
    if mcp_tool_count > 0 {
        info!("MCP initialized: {} tools available", mcp_tool_count);
    }

    let mut runtime_config = config.clone();
    runtime_config.data_dir = runtime_data_dir;

    telegram::run_bot(
        runtime_config,
        db,
        memory_manager,
        skill_manager,
        mcp_manager,
    )
    .await?;

    Ok(())
}
