use microclaw::claude::{Message, MessageContent};
use microclaw::config::Config;
use microclaw::error::MicroClawError;
use microclaw::{
    builtin_skills, config_wizard, db, doctor, gateway, logging, mcp, memory, setup, skills,
    telegram,
};
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
    gateway     Manage gateway service (install/uninstall/start/stop/status/logs)
    config      Run interactive Q&A config flow (recommended)
    doctor      Run preflight diagnostics (cross-platform)
    test-llm [--with-tools]   Test LLM connection (use --with-tools to send tools like Telegram)
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
    1. Run: microclaw config
       (or run microclaw start and follow auto-config on first launch)
    2. Edit microclaw.config.yaml with required values:

       api_key               LLM API key (optional when llm_provider=ollama)
       At least one channel token must be set (Telegram or Discord)

    3. Run: microclaw start

CONFIG FILE (microclaw.config.yaml):
    MicroClaw reads configuration from microclaw.config.yaml (or microclaw.config.yml).
    Override the path with MICROCLAW_CONFIG env var.
    See microclaw.config.example.yaml for all available fields.

    Core fields:
      llm_provider           Provider preset (default: anthropic)
      api_key                LLM API key (optional when llm_provider=ollama)
      model                  Model name (auto-detected from provider if empty)
      llm_base_url           Custom base URL (optional)

    Runtime:
      workspace_dir          Workspace root (default: ./workspace). Layout: runtime/, skills/, shared/ under this path. Copy to migrate.
      max_tokens             Max tokens per response (default: 8192)
      max_tool_iterations    Max tool loop iterations (default: 100)
      max_history_messages   Chat history context size (default: 50)
      openai_api_key         OpenAI key for voice transcription (optional)
      timezone               IANA timezone for scheduling (default: UTC)

    Telegram (optional):
      telegram_bot_token         Telegram bot token from @BotFather
      bot_username               Telegram mention username (without @)
      allowed_groups             Group allowlist by chat ID (empty = all groups)

    WhatsApp (optional):
      whatsapp_access_token       Meta API access token
      whatsapp_phone_number_id    Phone number ID from Meta dashboard
      whatsapp_verify_token       Webhook verification token
      whatsapp_webhook_port       Webhook server port (default: 8080)

    Discord (optional):
      discord_bot_token           Discord bot token from Discord Developer Portal
      discord_allowed_channels    List of channel IDs to respond in (empty = all)

MCP (optional):
    Place a mcp.json file in workspace_dir to connect MCP servers.
    See https://modelcontextprotocol.io for details.

EXAMPLES:
    microclaw start               Start the bot
    microclaw gateway install     Install and enable gateway service
    microclaw gateway status      Show gateway service status
    microclaw gateway logs 100    Show last 100 lines of gateway logs
    microclaw config              Run interactive Q&A config flow
    microclaw doctor              Run preflight diagnostics
    microclaw doctor --json       Output diagnostics as JSON
    microclaw test-llm            Test LLM API connection (no tools)
    microclaw test-llm --with-tools   Test LLM with full tool list (like Telegram)
    microclaw setup               Run full-screen setup wizard
    microclaw version             Show version
    microclaw help                Show this message

ABOUT:
    https://microclaw.ai"#
    );
}

fn print_version() {
    println!("microclaw {VERSION}");
}

async fn run_test_llm(with_tools: bool) -> anyhow::Result<()> {
    let config = match Config::load() {
        Ok(c) => c,
        Err(MicroClawError::Config(e)) => {
            eprintln!("Config error: {e}");
            eprintln!("Set MICROCLAW_CONFIG or create microclaw.config.yaml");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Failed to load config: {e}");
            std::process::exit(1);
        }
    };
    let provider = microclaw::llm::create_provider(&config);
    let messages = vec![Message {
        role: "user".into(),
        content: MessageContent::Text("Reply with exactly: OK".into()),
    }];
    let tools_arg = if with_tools {
        let runtime_data_dir = config.runtime_data_dir();
        let db = match db::Database::new(&runtime_data_dir) {
            Ok(d) => std::sync::Arc::new(d),
            Err(e) => {
                eprintln!("Database init failed (needed for --with-tools): {e}");
                std::process::exit(1);
            }
        };
        let token = if config.telegram_bot_token.is_empty() {
            "dummy"
        } else {
            &config.telegram_bot_token
        };
        let bot = teloxide::Bot::new(token);
        let tools = microclaw::tools::ToolRegistry::new(&config, bot, db.clone());
        let defs = tools.definitions();
        println!("Testing with {} tools (same as Telegram).", defs.len());
        Some(defs)
    } else {
        None
    };
    println!(
        "Testing LLM: provider={} model={} base={}{}",
        config.llm_provider,
        config.model,
        config.llm_base_url.as_deref().unwrap_or("(default)"),
        if with_tools { " (with tools)" } else { "" }
    );
    match provider
        .send_message("You are a test assistant.", messages, tools_arg)
        .await
    {
        Ok(resp) => {
            let text = resp
                .content
                .iter()
                .filter_map(|b| match b {
                    microclaw::claude::ResponseContentBlock::Text { text } => Some(text.as_str()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("");
            let usage = resp.usage.as_ref().map(|u| format!(" (input: {} output: {} tokens)", u.input_tokens, u.output_tokens)).unwrap_or_default();
            println!("LLM OK. Response: {}{}", text.trim(), usage);
        }
        Err(e) => {
            eprintln!("LLM error: {e}");
            std::process::exit(1);
        }
    }
    Ok(())
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

/// Ensure workspace shared directory exists under the data root (for unified layout).
fn ensure_workspace_shared_dir(data_root: &Path) {
    let shared = data_root.join("shared");
    if std::fs::create_dir_all(&shared).is_err() {
        tracing::warn!("Failed to create workspace shared dir: {}", shared.display());
    }
}

/// If repo-root shared/ exists, copy its contents into workspace shared dir so the canonical workspace has all shared content. Does not overwrite existing files.
fn migrate_repo_shared_into_workspace(working_dir: &Path) {
    let workspace_shared = working_dir.join("shared");
    if std::fs::create_dir_all(&workspace_shared).is_err() {
        return;
    }
    let Ok(cwd) = std::env::current_dir() else {
        return;
    };
    let repo_shared = cwd.join("shared");
    if !repo_shared.is_dir() {
        return;
    }
    let entries = match std::fs::read_dir(&repo_shared) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        let src = entry.path();
        let dst = workspace_shared.join(name_str);
        if dst.exists() {
            continue;
        }
        if src.is_dir() {
            if copy_dir_all(&src, &dst).is_err() {
                tracing::warn!(
                    "Failed to copy repo shared dir '{}' -> '{}'",
                    src.display(),
                    dst.display()
                );
            } else {
                tracing::info!(
                    "Migrated repo shared '{}' -> '{}'",
                    src.display(),
                    dst.display()
                );
            }
        } else if std::fs::copy(&src, &dst).is_err() {
            tracing::warn!(
                "Failed to copy repo shared file '{}' -> '{}'",
                src.display(),
                dst.display()
            );
        } else {
            tracing::info!(
                "Migrated repo shared '{}' -> '{}'",
                src.display(),
                dst.display()
            );
        }
    }
}

fn copy_dir_all(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let child_src = entry.path();
        let child_dst = dst.join(entry.file_name());
        if child_src.is_dir() {
            copy_dir_all(&child_src, &child_dst)?;
        } else {
            std::fs::copy(&child_src, &child_dst)?;
        }
    }
    Ok(())
}

fn migrate_legacy_runtime_layout(data_root: &Path, runtime_dir: &Path) {
    if std::fs::create_dir_all(runtime_dir).is_err() {
        return;
    }
    ensure_workspace_shared_dir(data_root);

    let entries = match std::fs::read_dir(data_root) {
        Ok(entries) => entries,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if name_str == "skills" || name_str == "runtime" || name_str == "shared" || name_str == "mcp.json" {
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
        Some("gateway") => {
            gateway::handle_gateway_cli(&args[2..])?;
            return Ok(());
        }
        Some("setup") => {
            let saved = setup::run_setup_wizard()?;
            if saved {
                println!("Setup saved to microclaw.config.yaml");
            } else {
                println!("Setup canceled");
            }
            return Ok(());
        }
        Some("config") => {
            let saved = config_wizard::run_config_wizard()?;
            if saved {
                println!("Config saved");
            } else {
                println!("Config canceled");
            }
            return Ok(());
        }
        Some("doctor") => {
            doctor::run_cli(&args[2..])?;
            return Ok(());
        }
        Some("test-llm") => {
            let with_tools = args.get(2).map(|s| s.as_str()) == Some("--with-tools");
            run_test_llm(with_tools).await?;
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

    let config = match Config::load() {
        Ok(c) => c,
        Err(MicroClawError::Config(e)) => {
            eprintln!("Config missing/invalid: {e}");
            eprintln!("Launching interactive config...");
            let saved = config_wizard::run_config_wizard()?;
            if !saved {
                return Err(anyhow::anyhow!(
                    "config canceled and config is still incomplete"
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
    migrate_repo_shared_into_workspace(Path::new(config.working_dir()));
    builtin_skills::ensure_builtin_skills(&data_root_dir)?;

    if std::env::var("MICROCLAW_GATEWAY").is_ok() {
        logging::init_logging(&runtime_data_dir)?;
    } else {
        logging::init_console_logging();
    }

    let db = db::Database::new(&runtime_data_dir)?;
    info!("Database initialized");

    let memory_manager = memory::MemoryManager::new(&runtime_data_dir, config.working_dir());
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

    telegram::run_bot(
        config,
        db,
        memory_manager,
        skill_manager,
        mcp_manager,
    )
    .await?;

    Ok(())
}
