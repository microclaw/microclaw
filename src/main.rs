use microclaw::config::Config;
use microclaw::error::MicroClawError;
use microclaw::{
    builtin_skills, db, doctor, gateway, hooks, logging, mcp, memory, runtime, setup, skills,
};
use std::path::Path;
use tracing::info;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_help() {
    println!(
        r#"MicroClaw v{VERSION}

Usage:
  microclaw <command>

Commands:
  start      Start runtime (enabled channels)
  setup      Full-screen setup wizard
  doctor     Preflight diagnostics
  hooks      Manage runtime hooks (list/info/enable/disable)
  gateway    Manage service (install/start/stop/status/logs)
  version    Show version
  help       Show this help

Quick Start:
  1) microclaw setup
  2) microclaw doctor
  3) microclaw start

Channel requirement:
  Enable at least one channel: Telegram / Discord / Web UI.

More:
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

fn migrate_legacy_skills_dir(legacy_dir: &Path, preferred_dir: &Path) {
    if legacy_dir == preferred_dir || !legacy_dir.exists() {
        return;
    }
    if std::fs::create_dir_all(preferred_dir).is_err() {
        return;
    }
    let entries = match std::fs::read_dir(legacy_dir) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let src = entry.path();
        let dst = preferred_dir.join(entry.file_name());
        if dst.exists() {
            continue;
        }
        if let Err(e) = move_path(&src, &dst) {
            tracing::warn!(
                "Failed to migrate legacy skills '{}' -> '{}': {}",
                src.display(),
                dst.display(),
                e
            );
        } else {
            tracing::info!(
                "Migrated legacy skill '{}' -> '{}'",
                src.display(),
                dst.display()
            );
        }
    }
}

async fn reembed_memories() -> anyhow::Result<()> {
    let config = Config::load()?;

    #[cfg(not(feature = "sqlite-vec"))]
    {
        let _ = config;
        anyhow::bail!(
            "sqlite-vec feature not enabled. Rebuild with: cargo build --release --features sqlite-vec"
        );
    }

    #[cfg(feature = "sqlite-vec")]
    {
        use microclaw::embedding;
        let runtime_data_dir = config.runtime_data_dir();
        let db = db::Database::new(&runtime_data_dir)?;

        let provider = embedding::create_provider(&config);
        let provider = match provider {
            Some(p) => p,
            None => {
                eprintln!("No embedding provider configured. Check embedding_provider in config.");
                std::process::exit(1);
            }
        };

        let dim = provider.dimension();
        db.prepare_vector_index(dim)?;
        println!("Embedding provider: {} ({}D)", provider.model(), dim);

        let memories = db.get_all_active_memories()?;
        println!("Re-embedding {} active memories...", memories.len());

        let mut success = 0usize;
        let mut failed = 0usize;
        for (i, (id, content)) in memories.iter().enumerate() {
            match provider.embed(content).await {
                Ok(embedding) => {
                    if let Err(e) = db.upsert_memory_vec(*id, &embedding) {
                        eprintln!("  [{}] DB error: {}", id, e);
                        failed += 1;
                    } else {
                        let _ = db.update_memory_embedding_model(*id, provider.model());
                        success += 1;
                    }
                }
                Err(e) => {
                    eprintln!("  [{}] Embed error: {}", id, e);
                    failed += 1;
                }
            }
            if (i + 1) % 20 == 0 {
                println!(
                    "  Progress: {}/{} (ok={}, fail={})",
                    i + 1,
                    memories.len(),
                    success,
                    failed
                );
            }
        }

        println!("Done! {} embedded, {} failed", success, failed);
        Ok(())
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
        Some("doctor") => {
            doctor::run_cli(&args[2..])?;
            return Ok(());
        }
        Some("skill") => {
            let config = Config::load()?;
            microclaw::clawhub::cli::handle_skill_cli(&args[2..], &config)?;
            return Ok(());
        }
        Some("hooks") => {
            hooks::handle_hooks_cli(&args[2..]).await?;
            return Ok(());
        }
        Some("reembed") => {
            return reembed_memories().await;
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
    let legacy_skills_dir = data_root_dir.join("skills");
    let skills_root_dir = std::path::PathBuf::from(&skills_data_dir)
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| data_root_dir.clone());
    migrate_legacy_runtime_layout(&data_root_dir, Path::new(&runtime_data_dir));
    migrate_legacy_skills_dir(&legacy_skills_dir, Path::new(&skills_data_dir));
    builtin_skills::ensure_builtin_skills(&skills_root_dir)?;

    if std::env::var("MICROCLAW_GATEWAY").is_ok() {
        logging::init_logging(&runtime_data_dir)?;
    } else {
        logging::init_console_logging();
    }

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

    runtime::run(
        runtime_config,
        db,
        memory_manager,
        skill_manager,
        mcp_manager,
    )
    .await?;

    Ok(())
}
