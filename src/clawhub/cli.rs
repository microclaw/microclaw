use crate::clawhub::client::ClawHubClient;
use crate::clawhub::install::install_skill;
use crate::clawhub::lockfile::read_lockfile;
use crate::config::Config;
use crate::error::MicroClawError;
use std::path::PathBuf;
use tokio::runtime::Runtime;

pub fn handle_skill_cli(args: &[String], config: &Config) -> Result<(), MicroClawError> {
    let subcommand = args.first().map(|s| s.as_str()).unwrap_or("help");

    let registry = &config.clawhub_registry;
    let token = config.clawhub_token.clone();

    let rt = Runtime::new().map_err(|e| MicroClawError::Config(e.to_string()))?;

    match subcommand {
        "search" => {
            let empty_query = "".to_string();
            let query = args.get(1).map(|s| s.as_str()).unwrap_or(&empty_query);
            if query.is_empty() {
                eprintln!("Usage: microclaw skill search <query>");
                return Ok(());
            }
            rt.block_on(async {
                let client = ClawHubClient::new(registry, token);
                match client.search(query, 10, "trending").await {
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
            })
        }
        "install" => {
            let empty_slug = "".to_string();
            let slug = args.get(1).map(|s| s.as_str()).unwrap_or(&empty_slug);
            if slug.is_empty() {
                eprintln!("Usage: microclaw skill install <slug>");
                return Ok(());
            }
            let skills_dir = PathBuf::from(config.skills_data_dir());
            let lockfile_path = config.data_root_dir().join("clawhub.lock.json");

            rt.block_on(async {
                let client = ClawHubClient::new(registry, token);
                let options = crate::clawhub::install::InstallOptions {
                    force: args.contains(&"--force".to_string()),
                    skip_gates: false,
                    skip_security: config.clawhub_skip_security_warnings,
                };
                match install_skill(&client, slug, None, &skills_dir, &lockfile_path, &options)
                    .await
                {
                    Ok(result) => {
                        println!("{}", result.message);
                        if result.requires_restart {
                            println!("Restart MicroClaw or run /reload-skills to activate.");
                        }
                    }
                    Err(e) => eprintln!("Install failed: {}", e),
                }
                Ok(())
            })
        }
        "list" => {
            let lockfile_path = config.data_root_dir().join("clawhub.lock.json");
            let lock = read_lockfile(&lockfile_path)?;
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
        "inspect" => {
            let empty_slug = "".to_string();
            let slug = args.get(1).map(|s| s.as_str()).unwrap_or(&empty_slug);
            if slug.is_empty() {
                eprintln!("Usage: microclaw skill inspect <slug>");
                return Ok(());
            }
            rt.block_on(async {
                let client = ClawHubClient::new(registry, token);
                match client.get_skill(slug).await {
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
            })
        }
        _ => {
            println!("Usage: microclaw skill <command>");
            println!("\nCommands:");
            println!("  search <query>   Search for skills");
            println!("  install <slug>    Install a skill");
            println!("  list              List installed skills");
            println!("  inspect <slug>    Show skill details");
            Ok(())
        }
    }
}
