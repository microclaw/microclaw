//! `mccode plugin add | list | remove | update | enable | disable`.

use std::io::{BufRead, IsTerminal, Write};
use std::process::ExitCode;

use clap::Subcommand;
use microclaw_code_core::plugins::{self, Plugin, PluginScope, Registry};
use microclaw_code_core::project::Project;

#[derive(Debug, Subcommand)]
pub enum PluginAction {
    /// Install a plugin (Claude Code layout) from a git repository
    /// (`owner/repo`, a URL) or a local directory.
    Add {
        source: String,
        /// Which plugin of a marketplace repository to install.
        #[arg(long)]
        plugin: Option<String>,
        /// Install into `.microclaw/plugins/` (shared through the
        /// repository; loaded only when the project is trusted).
        #[arg(long)]
        project: bool,
        /// Enable without asking, even when it runs commands.
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// List installed plugins and what they bring.
    List,
    /// Remove a plugin.
    Remove {
        name: String,
        #[arg(long)]
        project: bool,
    },
    /// Fetch a plugin again from its source (all plugins without a name).
    Update {
        name: Option<String>,
        #[arg(long)]
        project: bool,
        /// Accept new hooks and MCP servers without asking.
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Turn an installed user plugin on.
    Enable { name: String },
    /// Turn an installed user plugin off (it stays installed).
    Disable { name: String },
}

fn registry(project: &Project, in_project: bool) -> Registry {
    if in_project {
        Registry::load(&plugins::project_dir(&project.root), PluginScope::Project)
    } else {
        Registry::load(&plugins::user_dir(), PluginScope::User)
    }
}

fn confirm(question: &str) -> bool {
    eprint!("{question} [y/N] ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim(), "y" | "Y" | "yes" | "Yes")
}

/// Ask before enabling something that runs commands. Without a terminal
/// only `--yes` enables it.
fn approve(plugin: &Plugin, yes: bool, what: &str) -> anyhow::Result<()> {
    if yes || !plugin.runs_commands() {
        return Ok(());
    }
    if !std::io::stdin().is_terminal() {
        anyhow::bail!(
            "`{}` runs commands on this machine ({what}); pass --yes to accept them",
            plugin.name
        );
    }
    if !confirm(&format!(
        "`{}` runs the commands listed above on this machine. Enable it?",
        plugin.name
    )) {
        anyhow::bail!("not installed");
    }
    Ok(())
}

pub fn run(action: &PluginAction, project: &Project) -> anyhow::Result<ExitCode> {
    match action {
        PluginAction::Add {
            source,
            plugin,
            project: in_project,
            yes,
        } => {
            let staged = plugins::stage(source, plugin.as_deref())?;
            for line in staged.plugin.describe() {
                println!("{line}");
            }
            let mut registry = registry(project, *in_project);
            if registry.plugin_dir(&staged.plugin.name).exists() {
                println!(
                    "note    replaces the installed `{}` ({})",
                    staged.plugin.name,
                    registry.dir.display()
                );
            }
            approve(&staged.plugin, *yes, "hooks or MCP servers")?;
            let (installed, skipped) = plugins::install(&staged, &mut registry)?;
            for s in skipped {
                println!("skipped {s}");
            }
            println!(
                "Installed `{}` in {}.",
                installed.name,
                installed.root.display()
            );
            if *in_project && !project.trusted {
                println!(
                    "This project is not trusted, so project plugins are not loaded until you run `mccode trust`."
                );
            }
        }
        PluginAction::List => {
            let mut any = false;
            for (scope, in_project) in [("user", false), ("project", true)] {
                let registry = registry(project, in_project);
                let mut dirs = registry.enabled_dirs();
                for entry in registry.entries.iter().filter(|e| !e.enabled) {
                    dirs.push(registry.plugin_dir(&entry.name));
                }
                for dir in dirs {
                    any = true;
                    let name = dir
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or_default()
                        .to_string();
                    let entry = registry.get(&name);
                    let state = match entry {
                        Some(e) if !e.enabled => "disabled",
                        _ if in_project && !project.trusted => "not loaded (untrusted project)",
                        _ => "enabled",
                    };
                    let source = entry
                        .map(|e| {
                            format!(
                                " from {}{}",
                                e.source,
                                e.subdir
                                    .as_deref()
                                    .map(|s| format!(" ({s})"))
                                    .unwrap_or_default()
                            )
                        })
                        .unwrap_or_default();
                    println!("{name} [{scope}, {state}]{source}");
                    match Plugin::load(&dir, registry.scope) {
                        Ok(plugin) => {
                            for line in plugin.describe().into_iter().skip(1) {
                                println!("  {line}");
                            }
                        }
                        Err(e) => println!("  error   {e:#}"),
                    }
                }
            }
            if !any {
                println!(
                    "No plugins. Install one with `mccode plugin add <owner/repo | url | path>`."
                );
            }
        }
        PluginAction::Remove {
            name,
            project: in_project,
        } => {
            let mut registry = registry(project, *in_project);
            if !plugins::remove(name, &mut registry)? {
                anyhow::bail!("no plugin `{name}` in {}", registry.dir.display());
            }
            println!("Removed `{name}`.");
        }
        PluginAction::Update {
            name,
            project: in_project,
            yes,
        } => {
            let mut registry = registry(project, *in_project);
            let names: Vec<String> = match name {
                Some(name) => vec![name.clone()],
                None => registry.entries.iter().map(|e| e.name.clone()).collect(),
            };
            if names.is_empty() {
                println!("No plugins to update.");
            }
            for name in names {
                let Some(entry) = registry.get(&name).cloned() else {
                    anyhow::bail!(
                        "`{name}` was not installed with `mccode plugin add`; add it again instead"
                    );
                };
                let staged = plugins::stage_at(
                    &entry.source,
                    entry.subdir.as_deref(),
                    entry.git_ref.as_deref(),
                )?;
                if staged.plugin.name != name {
                    anyhow::bail!(
                        "{} now holds the plugin `{}`, not `{name}`",
                        entry.source,
                        staged.plugin.name
                    );
                }
                if staged.commit.is_some() && staged.commit == entry.commit {
                    println!("`{name}` is up to date.");
                    continue;
                }
                let old = Plugin::load(&registry.plugin_dir(&name), registry.scope).ok();
                let added = plugins::new_commands(old.as_ref(), &staged.plugin);
                if !added.is_empty() {
                    println!("`{name}` now also runs:");
                    for line in &added {
                        println!("  {line}");
                    }
                    if !*yes {
                        if !std::io::stdin().is_terminal() {
                            anyhow::bail!("`{name}` adds commands; pass --yes to accept them");
                        }
                        if !confirm(&format!("Update `{name}`?")) {
                            println!("Kept the installed `{name}`.");
                            continue;
                        }
                    }
                }
                plugins::install(&staged, &mut registry)?;
                println!(
                    "Updated `{name}`{}.",
                    staged
                        .commit
                        .as_deref()
                        .map(|c| format!(" to {}", &c[..c.len().min(12)]))
                        .unwrap_or_default()
                );
            }
        }
        PluginAction::Enable { name } | PluginAction::Disable { name } => {
            let enable = matches!(action, PluginAction::Enable { .. });
            let mut registry = registry(project, false);
            let Some(entry) = registry.entries.iter_mut().find(|e| &e.name == name) else {
                anyhow::bail!("no user plugin `{name}`");
            };
            entry.enabled = enable;
            registry.save()?;
            println!("{} `{name}`.", if enable { "Enabled" } else { "Disabled" });
        }
    }
    Ok(ExitCode::SUCCESS)
}
