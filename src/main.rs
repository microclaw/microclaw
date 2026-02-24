use argon2::password_hash::{rand_core::OsRng, PasswordHashString, SaltString};
use argon2::{Argon2, PasswordHasher};
use clap::{Args, CommandFactory, Parser, Subcommand};
use microclaw::config::Config;
use microclaw::error::MicroClawError;
use microclaw::{
    builtin_skills, db, doctor, gateway, hooks, logging, mcp, memory, runtime, setup, skills,
};
use std::path::{Path, PathBuf};
use tracing::info;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const LONG_ABOUT: &str = concat!(
    "\x1b[1mMicroClaw v",
    env!("CARGO_PKG_VERSION"),
    "\x1b[22m\n",
    "\x1b[1mWebsite:\x1b[22m https://microclaw.ai\n",
    "\x1b[1mGitHub:\x1b[22m https://github.com/microclaw/microclaw\n",
    "\x1b[1mDiscord:\x1b[22m https://discord.gg/pvmezwkAk5\n",
    "\n",
    "\x1b[1mQuick Start:\x1b[22m\n",
    "  1) microclaw setup\n",
    "  2) microclaw doctor\n",
    "  3) microclaw start",
);

#[derive(Debug, Parser)]
#[command(
    name = "microclaw",
    version = VERSION,
    about = LONG_ABOUT
)]
struct Cli {
    #[command(subcommand)]
    command: Option<MainCommand>,
}

#[derive(Debug, Subcommand)]
enum MainCommand {
    /// Start runtime (enabled channels)
    Start,
    /// Full-screen setup wizard (or `setup --enable-sandbox`)
    Setup(SetupCommand),
    /// Preflight diagnostics
    Doctor {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Manage service (install/start/stop/status/logs)
    Gateway {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Manage ClawHub skills (search/install/list/inspect)
    Skill {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Manage runtime hooks (list/info/enable/disable)
    Hooks {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Manage Web UI configurations
    Web(WebCommand),
    /// Re-embed active memories (requires `sqlite-vec` feature)
    Reembed,
    /// Show version
    Version,
}

#[derive(Debug, Args)]
struct SetupCommand {
    /// Enable sandbox mode in config
    #[arg(long)]
    enable_sandbox: bool,
    /// Assume yes for follow-up prompts
    #[arg(short = 'y', long)]
    yes: bool,
    /// Suppress follow-up tips
    #[arg(long)]
    quiet: bool,
}

#[derive(Debug, Args)]
struct WebCommand {
    #[command(subcommand)]
    action: Option<WebAction>,
}

#[derive(Debug, Subcommand)]
enum WebAction {
    /// Set the exact new password (min 8 chars)
    Password { value: String },
    /// Generate and set a random password
    PasswordGenerate,
    /// Clear password hash and revoke sessions (test/reset)
    PasswordClear,
}

fn print_version() {
    println!("microclaw {VERSION}");
}

fn print_web_help() {
    println!(
        r#"Manage Web UI Configurations

Usage:
  microclaw web [password <value> | password-generate | password-clear]

Options:
  password <value>      Set the exact new password (min 8 chars)
  password-generate     Generate a random password
  password-clear        Clear password hash and revoke sessions (test/reset)

Notes:
  - Existing Web login sessions are revoked automatically.
  - Restart is not required."#
    );
}

fn make_password_hash(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash: PasswordHashString = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("password hashing failed: {e}"))?
        .serialize();
    Ok(hash.to_string())
}

fn generate_password() -> String {
    let rand = uuid::Uuid::new_v4().simple().to_string();
    format!("mc-{}-{}!", &rand[..6], &rand[6..12])
}

fn handle_web_cli(action: Option<WebAction>) -> anyhow::Result<()> {
    if action.is_none() {
        print_web_help();
        return Ok(());
    }

    if matches!(action, Some(WebAction::PasswordClear)) {
        let config = Config::load()?;
        let runtime_data_dir = config.runtime_data_dir();
        let database = db::Database::new(&runtime_data_dir)?;
        database.clear_auth_password_hash()?;
        let revoked = database.revoke_all_auth_sessions()?;
        println!("Web password cleared.");
        println!("Revoked web sessions: {revoked}");
        println!(
            "State is now uninitialized. On next `microclaw start`, default password bootstrap policy will apply."
        );
        return Ok(());
    }

    let (password, generated) = match action {
        Some(WebAction::PasswordGenerate) => (generate_password(), true),
        Some(WebAction::Password { value }) => (value, false),
        Some(WebAction::PasswordClear) => unreachable!("handled above"),
        None => unreachable!("handled above"),
    };
    let normalized = password.trim().to_string();
    if normalized.len() < 8 {
        anyhow::bail!("password must be at least 8 chars");
    }

    let config = Config::load()?;
    let runtime_data_dir = config.runtime_data_dir();
    let database = db::Database::new(&runtime_data_dir)?;
    let hash = make_password_hash(&normalized)?;
    database.upsert_auth_password_hash(&hash)?;
    let revoked = database.revoke_all_auth_sessions()?;

    println!("Web password reset successfully.");
    println!("Revoked web sessions: {revoked}");
    if generated {
        println!("Generated password: {normalized}");
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

fn migrate_legacy_runtime_layout(data_root: &Path, runtime_dir: &Path) {
    let entries = match std::fs::read_dir(data_root) {
        Ok(entries) => entries,
        Err(_) => return,
    };

    let mut runtime_dir_ready = false;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if name_str == "skills"
            || name_str == "runtime"
            || name_str == "mcp.json"
            || name_str == "working_dir"
        {
            continue;
        }
        let src = entry.path();
        let dst = runtime_dir.join(name_str);
        if dst.exists() {
            continue;
        }
        if !runtime_dir_ready {
            if std::fs::create_dir_all(runtime_dir).is_err() {
                return;
            }
            runtime_dir_ready = true;
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

fn collect_mcp_config_paths(data_root: &Path) -> Vec<PathBuf> {
    let mut paths = vec![data_root.join("mcp.json")];
    let mcp_dir = data_root.join("mcp.d");
    let mut fragments = match std::fs::read_dir(&mcp_dir) {
        Ok(entries) => entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|s| s.to_str()) == Some("json"))
            .collect::<Vec<_>>(),
        Err(_) => Vec::new(),
    };
    fragments.sort();
    paths.extend(fragments);
    paths
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
    let cli = Cli::parse();

    match cli.command {
        Some(MainCommand::Start) => {}
        Some(MainCommand::Gateway { args }) => {
            gateway::handle_gateway_cli(&args)?;
            return Ok(());
        }
        Some(MainCommand::Setup(setup_args)) => {
            if setup_args.enable_sandbox {
                let path = setup::enable_sandbox_in_config()?;
                println!("Sandbox enabled in {path}");
                if !setup_args.yes && !setup_args.quiet {
                    println!(
                        "Tip: run `microclaw doctor sandbox` to verify docker runtime and image readiness."
                    );
                }
            } else {
                let saved = setup::run_setup_wizard()?;
                if saved {
                    println!("Setup saved to microclaw.config.yaml");
                } else {
                    println!("Setup canceled");
                }
            }
            return Ok(());
        }
        Some(MainCommand::Doctor { args }) => {
            doctor::run_cli(&args)?;
            return Ok(());
        }
        Some(MainCommand::Web(web)) => {
            handle_web_cli(web.action)?;
            return Ok(());
        }
        Some(MainCommand::Skill { args }) => {
            let config = Config::load()?;
            microclaw::clawhub::cli::handle_skill_cli(&args, &config).await?;
            return Ok(());
        }
        Some(MainCommand::Hooks { args }) => {
            hooks::handle_hooks_cli(&args).await?;
            return Ok(());
        }
        Some(MainCommand::Reembed) => {
            return reembed_memories().await;
        }
        Some(MainCommand::Version) => {
            print_version();
            return Ok(());
        }
        None => {
            let mut cmd = Cli::command();
            cmd.print_help()?;
            println!();
            return Ok(());
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
    migrate_legacy_runtime_layout(&data_root_dir, Path::new(&runtime_data_dir));
    migrate_legacy_skills_dir(&legacy_skills_dir, Path::new(&skills_data_dir));
    builtin_skills::ensure_builtin_skills(Path::new(&skills_data_dir))?;

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

    // Initialize MCP servers (optional, configured via <data_root>/mcp.json and <data_root>/mcp.d/*.json)
    let mcp_config_paths = collect_mcp_config_paths(&data_root_dir);
    let mcp_manager =
        mcp::McpManager::from_config_paths(&mcp_config_paths, config.mcp_request_timeout_secs())
            .await;
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

#[cfg(test)]
mod tests {
    use super::migrate_legacy_runtime_layout;
    use std::path::Path;

    fn unique_temp_dir() -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("microclaw-main-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("create temp test dir");
        dir
    }

    #[test]
    fn migrate_legacy_runtime_layout_keeps_working_dir_at_data_root() {
        let root = unique_temp_dir();
        let runtime_dir = root.join("runtime");
        let working_dir = root.join("working_dir");
        std::fs::create_dir_all(&working_dir).expect("create working_dir");

        migrate_legacy_runtime_layout(&root, Path::new(&runtime_dir));

        assert!(working_dir.exists());
        assert!(!runtime_dir.join("working_dir").exists());
        assert!(!runtime_dir.exists());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn migrate_legacy_runtime_layout_does_not_create_runtime_dir_when_no_entries() {
        let root = unique_temp_dir();
        let runtime_dir = root.join("runtime");

        migrate_legacy_runtime_layout(&root, Path::new(&runtime_dir));

        assert!(!runtime_dir.exists());
        let _ = std::fs::remove_dir_all(root);
    }
}
