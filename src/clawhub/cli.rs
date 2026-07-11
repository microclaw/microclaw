use crate::clawhub::service::{ClawHubGateway, RegistryClawHubGateway};
use crate::config::Config;
use crate::error::MicroClawError;
use crate::skills::SkillManager;
use clap::{Parser, Subcommand};
use microclaw_clawhub::install::InstallOptions;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::time::{sleep, Duration};

/// Retry an async operation up to 3 times with brief delays
async fn retry_with_backoff<T, F, Fut>(mut operation: F) -> Result<T, MicroClawError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, MicroClawError>>,
{
    let mut last_error = None;
    for attempt in 1..=3 {
        match operation().await {
            Ok(result) => return Ok(result),
            Err(e) => {
                last_error = Some(e);
                if attempt < 3 {
                    sleep(Duration::from_millis(500)).await;
                }
            }
        }
    }
    Err(last_error
        .unwrap_or_else(|| MicroClawError::Config("Unexpected error during retry".to_string())))
}

pub async fn handle_skill_cli(args: &[String], config: &Config) -> Result<(), MicroClawError> {
    let cli = match SkillCli::try_parse_from(
        std::iter::once("skill").chain(args.iter().map(std::string::String::as_str)),
    ) {
        Ok(cli) => cli,
        Err(err)
            if matches!(
                err.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) =>
        {
            err.print()
                .map_err(|e| MicroClawError::Config(e.to_string()))?;
            return Ok(());
        }
        Err(err) => return Err(MicroClawError::Config(err.to_string())),
    };
    let subcommand = cli.command;

    let gateway: Arc<dyn ClawHubGateway> = Arc::new(RegistryClawHubGateway::from_config(config));

    match subcommand {
        Some(SkillCommand::Search { query }) => {
            let gateway = gateway.clone();
            let results = retry_with_backoff(|| {
                let gateway = gateway.clone();
                let query = query.clone();
                async move { gateway.search(&query, 10, "trending").await }
            })
            .await;
            match results {
                Ok(results) => {
                    println!("Found {} skills:\n", results.len());
                    for r in results {
                        println!("  {} - {}", r.slug, r.name);
                        println!("    {}", r.description);
                        println!("    {} installs", r.install_count);
                        if let Some(vt) = r.virustotal {
                            println!("    VirusTotal: {} ({})", vt.status, vt.report_count);
                        }
                        println!();
                    }
                }
                Err(e) => eprintln!("Search failed: {}", e),
            }
            Ok(())
        }
        Some(SkillCommand::Install { slug, force }) => {
            let skills_dir = PathBuf::from(config.skills_data_dir());
            let lockfile_path = config.clawhub_lockfile_path();

            let gateway = gateway.clone();
            let options = InstallOptions {
                force,
                skip_gates: false,
                skip_security: config.clawhub.skip_security_warnings,
            };
            let result = retry_with_backoff(|| {
                let gateway = gateway.clone();
                let skills_dir = skills_dir.clone();
                let lockfile_path = lockfile_path.clone();
                let options = options.clone();
                let slug = slug.clone();
                async move {
                    gateway
                        .install(&slug, None, &skills_dir, &lockfile_path, &options)
                        .await
                }
            })
            .await;
            match result {
                Ok(result) => {
                    println!("{}", result.message);
                    for w in &result.warnings {
                        println!("  ⚠ {}", w);
                    }
                    if result.requires_restart {
                        println!("Restart MicroClaw or run /reload-skills to activate.");
                    }
                }
                Err(e) => eprintln!("Install failed: {}", e),
            }
            Ok(())
        }
        Some(SkillCommand::List) => {
            let lockfile_path = config.clawhub_lockfile_path();
            let lock = gateway.read_lockfile(&lockfile_path)?;
            if lock.skills.is_empty() {
                println!("No ClawHub skills installed.");
            } else {
                println!("Installed ClawHub skills:\n");
                for (slug, entry) in &lock.skills {
                    println!(
                        "  {} - v{} (installed: {})",
                        slug, entry.installed_version, entry.installed_at
                    );
                }
            }
            Ok(())
        }
        Some(SkillCommand::Verify) => {
            let lockfile_path = config.clawhub_lockfile_path();
            let lock = gateway.read_lockfile(&lockfile_path)?;
            if lock.skills.is_empty() {
                println!("No ClawHub skills installed.");
                return Ok(());
            }
            let skills_dir = PathBuf::from(config.skills_data_dir());
            let mut bad = 0usize;
            for (slug, entry) in &lock.skills {
                use microclaw_clawhub::install::TreeVerification;
                match microclaw_clawhub::install::verify_tree(entry, &skills_dir) {
                    TreeVerification::Ok => println!("  ✓ {slug} — tree matches lockfile"),
                    TreeVerification::Unpinned => println!(
                        "  - {slug} — no tree hash recorded (installed before pinning; reinstall to pin)"
                    ),
                    TreeVerification::Missing => {
                        bad += 1;
                        println!("  ✗ {slug} — installed directory missing or unreadable");
                    }
                    TreeVerification::Modified { expected, actual } => {
                        bad += 1;
                        println!(
                            "  ✗ {slug} — tree MODIFIED since install
      expected {expected}
      actual   {actual}"
                        );
                    }
                }
            }
            if bad > 0 {
                return Err(MicroClawError::Config(format!(
                    "{bad} ClawHub skill(s) failed verification — inspect or reinstall them"
                )));
            }
            Ok(())
        }
        Some(SkillCommand::Available { all }) => {
            let manager = SkillManager::from_skills_and_runtime(
                &config.skills_data_dir(),
                &config.runtime_data_dir(),
            );
            if all {
                println!("{}", manager.list_skills_formatted_all());
            } else {
                println!("{}", manager.list_skills_formatted());
            }
            Ok(())
        }
        Some(SkillCommand::Inspect { slug }) => {
            let gateway = gateway.clone();
            let meta = retry_with_backoff(|| {
                let gateway = gateway.clone();
                let slug = slug.clone();
                async move { gateway.get_skill(&slug).await }
            })
            .await;
            match meta {
                Ok(meta) => {
                    println!("Skill: {} ({})", meta.name, meta.slug);
                    println!("{}", meta.description);
                    println!("\nVersions:");
                    for v in &meta.versions {
                        let marker = if v.latest { " (latest)" } else { "" };
                        println!("  v{}{}", v.version, marker);
                    }
                    if let Some(vt) = meta.virustotal {
                        println!("\nVirusTotal: {} ({} reports)", vt.status, vt.report_count);
                    }
                }
                Err(e) => eprintln!("Inspect failed: {}", e),
            }
            Ok(())
        }
        Some(SkillCommand::Audit {
            path,
            similarity,
            stale_days,
            min_body_chars,
            json,
            strict,
        }) => {
            let cfg = crate::skill_audit::AuditConfig {
                similarity,
                stale_days,
                min_body_chars,
                ..crate::skill_audit::AuditConfig::default()
            };
            let dir = path.unwrap_or_else(|| config.skills_data_dir());
            let code = crate::skill_audit::run_audit(&dir, &cfg, json, strict);
            std::process::exit(code);
        }
        None => {
            println!("Usage: microclaw skill <command>");
            println!("\nCommands:");
            println!("  search <query>   Search for skills");
            println!("  install <slug>    Install a skill");
            println!("  list              List installed skills");
            println!("  available [--all] List local skills (with diagnostics when --all)");
            println!("  inspect <slug>    Show skill details");
            println!("  audit [--json] [--strict]  Audit local skills for curation actions");
            Ok(())
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "microclaw skill",
    about = "Manage ClawHub skills",
    disable_help_subcommand = true
)]
struct SkillCli {
    #[command(subcommand)]
    command: Option<SkillCommand>,
}

#[derive(Debug, Subcommand)]
enum SkillCommand {
    /// Search for skills
    Search { query: String },
    /// Install a skill
    Install {
        slug: String,
        #[arg(long)]
        force: bool,
    },
    /// List installed skills
    List,
    /// List local skills (with diagnostics when --all)
    Available {
        #[arg(long)]
        all: bool,
    },
    /// Show skill details
    Inspect { slug: String },
    /// Verify installed ClawHub skills against their lockfile tree hashes
    /// (detects post-install modification). Exits non-zero on any mismatch.
    Verify,
    /// Audit the local skill corpus for curation actions (duplicates, stale,
    /// thin, cap headroom). Read-only and deterministic.
    Audit {
        /// Skills directory to audit (defaults to the configured skills dir)
        path: Option<String>,
        /// Token-Jaccard threshold for near-duplicate detection (0.0-1.0)
        #[arg(long, default_value_t = 0.5)]
        similarity: f64,
        /// Days since last update before an agent-created skill is stale
        #[arg(long, default_value_t = 30)]
        stale_days: i64,
        /// Minimum body chars before an agent-created skill is "thin"
        #[arg(long, default_value_t = 80)]
        min_body_chars: usize,
        /// Emit a JSON report instead of human-readable text
        #[arg(long)]
        json: bool,
        /// Exit non-zero when the audit finds anything actionable
        #[arg(long)]
        strict: bool,
    },
}
