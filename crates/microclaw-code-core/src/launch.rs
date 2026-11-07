//! Building the Agent Engine for a project, shared by every front end (TUI,
//! `-p`, ACP, MCP server).
//!
//! The model comes from a settings profile (`model.default`) unless a
//! configuration file is named with `--config`; otherwise from
//! `MCCODE_CONFIG` or `~/.mccode/config.yaml` ([`crate::home::resolve_config`]).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use microclaw_sdk::{MicroClaw, MicroClawBuilder, ShellSandbox};

use crate::driver::RoleModels;
use crate::gate::{CodeToolGate, GateEvent};
use crate::project::Project;
use crate::rules::{Effect, PermissionRules};
use crate::settings::{self as code_settings, CodeSettings, NetworkMode, ResolvedModel};
use crate::trust::TrustStore;
use crate::user_hooks::UserHooks;

/// Where the session's model is configured.
#[derive(Debug, Clone)]
pub enum ModelSource {
    /// A `model.profiles` entry in settings.
    Profile(ResolvedModel),
    /// A MicroClaw configuration file.
    ConfigFile(PathBuf),
}

impl ModelSource {
    /// The profile name when the model comes from settings.
    pub fn profile(&self) -> Option<&str> {
        match self {
            Self::Profile(m) => Some(m.profile.as_str()),
            Self::ConfigFile(_) => None,
        }
    }

    /// A builder for this model source.
    pub fn builder(&self) -> MicroClawBuilder {
        match self {
            Self::Profile(m) => {
                let mut runtime =
                    microclaw_sdk::FullRuntimeConfig::new(&m.provider, &m.model, &m.api_key);
                if let Some(url) = &m.base_url {
                    runtime = runtime.base_url(url);
                }
                MicroClaw::configure(runtime)
            }
            Self::ConfigFile(path) => MicroClaw::builder(path),
        }
    }
}

/// The model source for `settings`: a profile unless `explicit_config` is
/// given, else the configuration file. The error says how to set one up.
pub fn model_source(
    settings: &CodeSettings,
    explicit_config: Option<&Path>,
) -> anyhow::Result<ModelSource> {
    if explicit_config.is_none()
        && let Some(model) = code_settings::resolve_model(settings, None)
    {
        return Ok(ModelSource::Profile(model));
    }
    let (path, _) = crate::home::resolve_config(explicit_config)?;
    Ok(ModelSource::ConfigFile(path))
}

/// Permission rules and hooks for the tool gate from merged settings.
pub fn gate_parts(
    root: &Path,
    settings: &CodeSettings,
    session_id: &str,
) -> (PermissionRules, Arc<UserHooks>) {
    let network_default = match settings.sandbox.network {
        Some(NetworkMode::Ask) => Some(Effect::Ask),
        Some(NetworkMode::Off) => Some(Effect::Deny),
        _ => None,
    };
    let rules = PermissionRules::from_config(&settings.permissions, root)
        .with_network(network_default, &settings.sandbox.allow_domains);
    let hooks = Arc::new(UserHooks::new(
        settings.hooks.clone(),
        root.to_path_buf(),
        session_id.to_string(),
    ));
    (rules, hooks)
}

/// The tool gate for `root`, optionally reporting its decisions.
pub fn tool_gate(
    root: &Path,
    settings: &CodeSettings,
    session_id: &str,
    events: Option<tokio::sync::mpsc::UnboundedSender<GateEvent>>,
) -> CodeToolGate {
    let (rules, hooks) = gate_parts(root, settings, session_id);
    let gate = CodeToolGate::new(rules, hooks, root.to_path_buf());
    match events {
        Some(tx) => gate.with_events(tx),
        None => gate,
    }
}

/// Per-role models resolved for a session on `active_profile` (`None`: the
/// MicroClaw configuration file).
#[derive(Debug, Clone, Default)]
pub struct RoleSetup {
    pub roles: RoleModels,
    pub summary: Option<String>,
    pub warnings: Vec<String>,
}

pub fn role_setup(settings: &CodeSettings, active_profile: Option<&str>) -> RoleSetup {
    let mut warnings = Vec::new();
    let mut get = |role: &str| {
        code_settings::role_model_for(settings, role, active_profile).unwrap_or_else(|e| {
            warnings.push(e);
            None
        })
    };
    let roles = RoleModels {
        plan: get("plan"),
        review: get("review"),
    };
    let summary = get("summary");
    RoleSetup {
        roles,
        summary,
        warnings,
    }
}

/// The project at `root` with the user's trust decision applied.
pub fn trusted_project(root: &Path) -> anyhow::Result<Project> {
    let trust = TrustStore::load(TrustStore::default_path());
    Project::discover(root, |r, hash| trust.is_trusted(r, hash))
}

/// Settings for a project root, honouring the project layer only when the
/// project is trusted.
pub fn project_settings(root: &Path) -> code_settings::LoadedSettings {
    let trusted = trusted_project(root).map(|p| p.trusted).unwrap_or(false);
    code_settings::load(root, trusted)
}

/// How a long-lived front end (ACP, MCP server) builds one engine per
/// project.
#[derive(Debug, Clone)]
pub struct EngineOptions {
    /// `--config` from the command line.
    pub explicit_config: Option<PathBuf>,
    pub sandbox: ShellSandbox,
    pub review_commands: bool,
    pub max_concurrent_runs: usize,
}

/// An engine with everything a session on it needs.
pub struct ProjectEngine {
    pub engine: MicroClaw,
    pub settings: CodeSettings,
    pub gate: CodeToolGate,
    pub roles: RoleModels,
    pub model: ModelSource,
    /// Settings and role problems worth showing once.
    pub warnings: Vec<String>,
}

/// Builds the engine serving `root` from its merged settings.
pub async fn project_engine(
    root: &Path,
    options: &EngineOptions,
    hook_session_id: &str,
) -> anyhow::Result<ProjectEngine> {
    let loaded = project_settings(root);
    let settings = loaded.settings;
    let mut warnings = loaded.warnings;
    let model = model_source(&settings, options.explicit_config.as_deref())?;
    let roles = role_setup(&settings, model.profile());
    warnings.extend(roles.warnings.iter().cloned());
    let gate = tool_gate(root, &settings, hook_session_id, None);
    let project = trusted_project(root).ok();
    let mut builder = model
        .builder()
        .tool_gate(Arc::new(gate.clone()))
        .summary_model(roles.summary.clone())
        .caller_channel(crate::driver::CALLER_CHANNEL)
        .workspace(root)
        .data_dir(crate::home::data_dir())
        .max_concurrent_runs(options.max_concurrent_runs)
        .shell_sandbox(options.sandbox.clone());
    if let Some(project) = &project {
        builder = builder
            .project_agents_dir(project.agents_dir())
            .compact_instructions(project.config.compact_instructions.clone())
            .context_tools(project.config.context_tools == Some(true));
    }
    if options.review_commands {
        builder = builder.command_reviewer(None);
    }
    let engine = builder.build().await.map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(ProjectEngine {
        engine,
        settings,
        gate,
        roles: roles.roles,
        model,
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_wins_unless_a_config_file_is_named() {
        let settings: CodeSettings = serde_yaml::from_str(
            "version: 1\nmodel:\n  default: ds/deepseek-v4-pro\n  profiles:\n    ds:\n      type: openai\n      api_key: k\n",
        )
        .unwrap();
        let source = model_source(&settings, None).unwrap();
        assert_eq!(source.profile(), Some("ds"));
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("config.yaml");
        std::fs::write(&file, "llm_provider: openai\n").unwrap();
        match model_source(&settings, Some(&file)).unwrap() {
            ModelSource::ConfigFile(path) => assert_eq!(path, file),
            other => panic!("expected the config file, got {other:?}"),
        }
    }
}
