//! UI-independent application service for running MicroClaw Work tasks.
//!
//! This crate owns the foreground worker lifecycle and bridges the shared
//! Agent Engine to versioned runtime events. UI packages consume this port;
//! they do not create Tokio runtimes or call the Agent Engine directly.

use microclaw::config::Config;
#[cfg(test)]
use microclaw::config::WorkingDirIsolation;
use microclaw::headless::{HeadlessRunRequest, HeadlessRuntime};
use microclaw::llm::create_provider;
use microclaw::storage::db::Database;
use microclaw_core::llm_types::{Message, MessageContent, ResponseContentBlock};
use microclaw_core::run_protocol::{RunId, RunRequest, SessionId};
use microclaw_core::runtime_event::RuntimeEventEnvelope;
use microclaw_engine as microclaw;
use microclaw_sdk::MicroClaw;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{fs, io};

static NEXT_RUN_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_DIAGNOSTIC_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone)]
pub struct WorkRunRequest {
    pub task: String,
    pub workspace: String,
    pub session: String,
}

#[derive(Debug, Clone)]
pub struct RuntimeConfigSummary {
    pub ready: bool,
    pub provider: String,
    pub model: String,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticStatus {
    Pass,
    Warning,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticCheck {
    pub id: &'static str,
    pub label: &'static str,
    pub status: DiagnosticStatus,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkDiagnosticsReport {
    pub ready: bool,
    pub checks: Vec<DiagnosticCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderConnectionReport {
    pub provider: String,
    pub model: String,
    pub latency_ms: u64,
    pub response_preview: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirstResponseReport {
    pub provider: String,
    pub model: String,
    pub latency_ms: u64,
    pub run_id: String,
    pub event_count: usize,
    pub response_preview: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelSettings {
    pub provider: String,
    pub model: String,
    pub base_url: String,
    pub has_api_key: bool,
    pub recovery_backup: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelSettingsDraft {
    pub provider: String,
    pub model: String,
    pub base_url: String,
    /// `None` preserves an existing key. `Some` replaces it.
    pub api_key: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModelProviderPreset {
    pub id: &'static str,
    pub label: &'static str,
    pub default_base_url: &'static str,
    pub models: &'static [&'static str],
}

pub fn popular_model_provider_presets() -> Vec<ModelProviderPreset> {
    const POPULAR: &[&str] = &[
        "openai",
        "openai-codex",
        "anthropic",
        "google",
        "deepseek",
        "moonshot",
        "alibaba",
        "minimax",
        "openrouter",
        "ollama",
        "xai",
        "zhipu",
    ];
    let catalog = microclaw::setup::provider_catalog().collect::<Vec<_>>();
    POPULAR
        .iter()
        .filter_map(|id| catalog.iter().find(|entry| entry.id == *id))
        .map(|entry| ModelProviderPreset {
            id: entry.id,
            label: entry.label,
            default_base_url: entry.default_base_url,
            models: entry.models,
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentSettings {
    pub soul_path: String,
    pub soul_content: String,
    pub context_dir: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentSettingsDraft {
    pub soul_path: String,
    pub soul_content: String,
    pub context_dir: String,
}

/// UI-safe projection of one locally installed Agent Skill.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkSkill {
    pub name: String,
    pub description: String,
    pub source: String,
    pub version: Option<String>,
    pub enabled: bool,
    pub available: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillInstallResult {
    pub message: String,
    pub warnings: Vec<String>,
    pub skills: Vec<WorkSkill>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillRemovalResult {
    pub name: String,
    pub archived_to: String,
    pub skills: Vec<WorkSkill>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkSubagent {
    pub run_id: String,
    pub label: String,
    pub task: String,
    pub status: String,
    pub progress: Option<String>,
    pub result: Option<String>,
    pub error: Option<String>,
    pub created_at: String,
    pub finished_at: Option<String>,
    pub elapsed_seconds: u64,
    pub cancel_requested: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ModelSettingsError {
    #[error("provider is required")]
    MissingProvider,
    #[error("model is required")]
    MissingModel,
    #[error("an API key is required for provider {provider}")]
    MissingApiKey { provider: String },
    #[error("base URL is invalid: {0}")]
    InvalidBaseUrl(String),
    #[error("configuration error: {0}")]
    Config(String),
    #[error("configuration I/O error: {0}")]
    Io(#[from] io::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum AgentSettingsError {
    #[error("SOUL.md path is required")]
    MissingSoulPath,
    #[error("SOUL.md must be a local file")]
    RemoteSoulPath,
    #[error("configuration error: {0}")]
    Config(String),
    #[error("configuration I/O error: {0}")]
    Io(#[from] io::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum SkillSettingsError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("skill error: {0}")]
    Skill(String),
    #[error("skills I/O error: {0}")]
    Io(#[from] io::Error),
}

const DEFAULT_WORK_SOUL: &str = r#"# MicroClaw Work Soul

## Identity

You are a capable, dependable work partner. Be direct, calm, and practical.

## Working style

- Lead with the result or the next concrete action.
- Use tools carefully and explain consequential changes.
- Prefer concise answers unless detail materially helps the work.
- Preserve user intent, local context, and existing project conventions.
"#;

fn editable_soul_path(config: &Config) -> PathBuf {
    let Some(configured) = config
        .soul_path
        .as_deref()
        .map(str::trim)
        .filter(|path| !path.is_empty())
    else {
        return config.data_root_dir().join("SOUL.md");
    };
    let configured = PathBuf::from(configured);
    if configured.is_absolute() || configured.exists() {
        return configured;
    }
    if configured.components().count() == 1 {
        let in_souls_dir = PathBuf::from(config.souls_data_dir()).join(&configured);
        if in_souls_dir.exists() {
            return in_souls_dir;
        }
    }
    let in_data_dir = config.data_root_dir().join(&configured);
    if in_data_dir.exists() {
        return in_data_dir;
    }
    if configured.components().count() == 1 {
        PathBuf::from(config.souls_data_dir()).join(configured)
    } else {
        in_data_dir
    }
}

fn load_runtime_config_summary(path: &Path) -> RuntimeConfigSummary {
    match Config::load_from_path_for_headless(path) {
        Ok(config) => RuntimeConfigSummary {
            ready: true,
            provider: config.llm_provider,
            model: config.model,
            detail: path.display().to_string(),
        },
        Err(error) => RuntimeConfigSummary {
            ready: false,
            provider: "Not configured".into(),
            model: "—".into(),
            detail: format!("{error} Open Model Settings to configure Work."),
        },
    }
}

#[derive(Debug)]
pub enum WorkRuntimeMessage {
    Envelope(RuntimeEventEnvelope),
    SteeringResult {
        run_id: String,
        accepted: bool,
        message: String,
    },
    Completed {
        run_id: String,
    },
    Failed {
        run_id: String,
        message: String,
    },
}

pub struct WorkRunHandle {
    pub messages: Receiver<WorkRuntimeMessage>,
    pub cancellation: WorkRunCancellation,
    pub steering: WorkRunSteering,
}

#[derive(Clone)]
pub struct WorkRunCancellation {
    cancel_tx: tokio::sync::mpsc::UnboundedSender<()>,
}

impl WorkRunCancellation {
    pub fn cancel(&self) -> Result<(), &'static str> {
        self.cancel_tx
            .send(())
            .map_err(|_| "The runtime has already exited; the stop request was not sent.")
    }
}

#[derive(Clone)]
pub struct WorkRunSteering {
    steer_tx: tokio::sync::mpsc::UnboundedSender<String>,
}

impl WorkRunSteering {
    pub fn steer(&self, message: &str) -> Result<(), &'static str> {
        let message = message.trim();
        if message.is_empty() {
            return Err("Describe the update before sending it.");
        }
        self.steer_tx
            .send(message.to_string())
            .map_err(|_| "The runtime has already exited; the update was not sent.")
    }
}

#[derive(Debug, Clone)]
pub struct WorkRuntimeService {
    config_path: PathBuf,
    config_ownership: WorkConfigOwnership,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkConfigOwnership {
    WorkOwned,
    External,
}

impl WorkRuntimeService {
    /// Use an explicitly configured/shared Server config when one is present,
    /// otherwise fall back to Work's platform-local config path.
    pub fn discover(fallback_path: impl Into<PathBuf>) -> Self {
        let fallback_path = fallback_path.into();
        if let Some(config_path) = std::env::var_os("MICROCLAW_WORK_CONFIG").map(PathBuf::from) {
            return Self {
                config_path,
                config_ownership: WorkConfigOwnership::External,
            };
        }
        if let Some(config_path) = Config::resolve_config_path().ok().flatten() {
            return Self {
                config_path,
                config_ownership: WorkConfigOwnership::External,
            };
        }
        Self {
            config_path: fallback_path,
            config_ownership: WorkConfigOwnership::WorkOwned,
        }
    }

    pub fn new(config_path: impl Into<PathBuf>) -> Self {
        Self {
            config_path: config_path.into(),
            config_ownership: WorkConfigOwnership::External,
        }
    }

    pub fn new_work_owned(config_path: impl Into<PathBuf>) -> Self {
        Self {
            config_path: config_path.into(),
            config_ownership: WorkConfigOwnership::WorkOwned,
        }
    }

    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    pub fn config_summary(&self) -> RuntimeConfigSummary {
        load_runtime_config_summary(&self.config_path)
    }

    /// Inspect the local prerequisites for starting a Work conversation.
    /// This is deliberately offline: provider reachability remains an explicit
    /// user-triggered connection test and credentials never enter the report.
    pub fn local_diagnostics(
        &self,
        workspace: &Path,
        session_root: &Path,
    ) -> WorkDiagnosticsReport {
        let mut checks = Vec::new();
        match Config::load_from_path_for_headless(&self.config_path) {
            Ok(config) => checks.push(DiagnosticCheck {
                id: "model-config",
                label: "Model configuration",
                status: DiagnosticStatus::Pass,
                detail: format!("{} / {}", config.llm_provider, config.model),
            }),
            Err(error) => checks.push(DiagnosticCheck {
                id: "model-config",
                label: "Model configuration",
                status: DiagnosticStatus::Fail,
                detail: microclaw_core::redact::redact_secrets(&error.to_string()),
            }),
        }

        checks.push(directory_diagnostic(
            "workspace",
            "Active workspace",
            workspace,
        ));
        checks.push(directory_diagnostic(
            "session-store",
            "Conversation storage",
            session_root,
        ));
        checks.push(config_permissions_diagnostic(&self.config_path));

        WorkDiagnosticsReport {
            ready: checks
                .iter()
                .all(|check| check.status != DiagnosticStatus::Fail),
            checks,
        }
    }

    /// Sends a minimal provider request on a background thread. This validates
    /// endpoint, authentication, model routing, and response decoding without
    /// starting an Agent Engine session or exposing the saved credential.
    pub fn test_provider_connection(&self) -> Receiver<Result<ProviderConnectionReport, String>> {
        let (result_tx, result_rx) = mpsc::channel();
        let config_path = self.config_path.clone();
        let worker_tx = result_tx.clone();
        let spawn = std::thread::Builder::new()
            .name("microclaw-work-provider-test".into())
            .spawn(move || {
                let result = (|| -> Result<ProviderConnectionReport, String> {
                    let config = Config::load_from_path_for_headless(&config_path)
                        .map_err(|error| error.to_string())?;
                    let provider_name = config.llm_provider.clone();
                    let model = config.model.clone();
                    let runtime = tokio::runtime::Runtime::new()
                        .map_err(|error| format!("could not create diagnostic runtime: {error}"))?;
                    let started = std::time::Instant::now();
                    let response = runtime.block_on(async {
                        let provider = create_provider(&config);
                        tokio::time::timeout(
                            Duration::from_secs(20),
                            provider.send_message(
                                "Reply with exactly: connection ok",
                                vec![Message {
                                    role: "user".into(),
                                    content: MessageContent::Text(
                                        "MicroClaw Work connection test".into(),
                                    ),
                                }],
                                None,
                            ),
                        )
                        .await
                        .map_err(|_| "provider connection timed out after 20 seconds".to_string())?
                        .map_err(|error| {
                            let error = error.to_string();
                            if config.api_key.is_empty() {
                                error
                            } else {
                                error.replace(&config.api_key, "<redacted>")
                            }
                        })
                    })?;
                    let response_preview = response
                        .content
                        .iter()
                        .find_map(|block| match block {
                            ResponseContentBlock::Text { text } => Some(text.as_str()),
                            _ => None,
                        })
                        .unwrap_or("Provider returned no visible text");
                    Ok(ProviderConnectionReport {
                        provider: provider_name,
                        model,
                        latency_ms: u64::try_from(started.elapsed().as_millis())
                            .unwrap_or(u64::MAX),
                        response_preview: microclaw_core::redact::redact_secrets(
                            &response_preview.chars().take(240).collect::<String>(),
                        ),
                    })
                })()
                .map_err(|error| microclaw_core::redact::redact_secrets(&error));
                let _ = worker_tx.send(result);
            });
        if let Err(error) = spawn {
            let _ = result_tx.send(Err(format!("could not start provider diagnostic: {error}")));
        }
        result_rx
    }

    /// Execute a minimal, tool-free-intent prompt through the shared Agent
    /// Engine and consume its versioned Work event stream. This is the explicit
    /// end-to-end first-response proof; unlike `test_provider_connection`, it
    /// validates runtime assembly, persistence, event bridging, and completion.
    pub fn test_first_response(
        &self,
        workspace: PathBuf,
    ) -> Receiver<Result<FirstResponseReport, String>> {
        let (result_tx, result_rx) = mpsc::channel();
        let config_path = self.config_path.clone();
        let worker_tx = result_tx.clone();
        let spawn = std::thread::Builder::new()
            .name("microclaw-work-first-response".into())
            .spawn(move || {
                let result = (|| -> Result<FirstResponseReport, String> {
                    let mut config = Config::load_from_path_for_headless(&config_path)
                        .map_err(|error| error.to_string())?;
                    let workspace = workspace
                        .canonicalize()
                        .map_err(|error| format!("workspace is unavailable: {error}"))?;
                    config.working_dir = workspace.display().to_string();
                    config.checkpoints_enabled = false;
                    let provider = config.llm_provider.clone();
                    let model = config.model.clone();
                    let api_key = config.api_key.clone();
                    let runtime = tokio::runtime::Runtime::new()
                        .map_err(|error| format!("could not create diagnostic runtime: {error}"))?;
                    let started = std::time::Instant::now();
                    runtime.block_on(async {
                        let runtime = HeadlessRuntime::load(config)
                            .await
                            .map_err(|error| redact_runtime_error(&error.to_string(), &api_key))?;
                        let run_id = next_diagnostic_run_id();
                        let session = format!("diagnostic-{run_id}");
                        let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel();
                        let events = tokio::spawn(async move {
                            let mut count = 0usize;
                            while event_rx.recv().await.is_some() {
                                count = count.saturating_add(1);
                            }
                            count
                        });
                        let result = tokio::time::timeout(
                            Duration::from_secs(60),
                            runtime.run(
                                HeadlessRunRequest::work(
                                    "Reply with exactly: first response ok".into(),
                                    Some(session),
                                    run_id.clone(),
                                ),
                                Some(event_tx),
                            ),
                        )
                        .await
                        .map_err(|_| "first response timed out after 60 seconds".to_string())?
                        .map_err(|error| redact_runtime_error(&error.to_string(), &api_key))?;
                        let event_count = tokio::time::timeout(Duration::from_secs(5), events)
                            .await
                            .map_err(|_| "runtime event stream did not close".to_string())?
                            .map_err(|error| error.to_string())?;
                        if event_count == 0 {
                            return Err("Agent Engine completed without Work runtime events".into());
                        }
                        let response = result.response.trim();
                        if response.is_empty() {
                            return Err("Agent Engine completed without a visible response".into());
                        }
                        if response.starts_with("I couldn't produce a visible reply")
                            || response.starts_with("I reached the model output limit")
                        {
                            return Err(format!(
                                "Agent Engine returned its completion fallback: {response}"
                            ));
                        }
                        Ok(FirstResponseReport {
                            provider,
                            model,
                            latency_ms: u64::try_from(started.elapsed().as_millis())
                                .unwrap_or(u64::MAX),
                            run_id: result.run_id,
                            event_count,
                            response_preview: microclaw_core::redact::redact_secrets(
                                &result.response.chars().take(240).collect::<String>(),
                            ),
                        })
                    })
                })()
                .map_err(|error| microclaw_core::redact::redact_secrets(&error));
                let _ = worker_tx.send(result);
            });
        if let Err(error) = spawn {
            let _ = result_tx.send(Err(format!(
                "could not start first-response diagnostic: {error}"
            )));
        }
        result_rx
    }

    pub fn model_settings(&self) -> Result<ModelSettings, ModelSettingsError> {
        let config = Config::load_from_path_for_headless(&self.config_path)
            .map_err(|error| ModelSettingsError::Config(error.to_string()))?;
        Ok(ModelSettings {
            provider: config.llm_provider,
            model: config.model,
            base_url: config.llm_base_url.unwrap_or_default(),
            has_api_key: !config.api_key.trim().is_empty(),
            recovery_backup: None,
        })
    }

    pub fn agent_settings(&self) -> Result<AgentSettings, AgentSettingsError> {
        let config = Config::load_from_path_for_headless(&self.config_path)
            .map_err(|error| AgentSettingsError::Config(error.to_string()))?;
        let soul_path = editable_soul_path(&config);
        let soul_content =
            fs::read_to_string(&soul_path).unwrap_or_else(|_| DEFAULT_WORK_SOUL.into());
        let context_dir = config
            .context_dir
            .clone()
            .filter(|path| !path.trim().is_empty())
            .unwrap_or_else(|| config.data_root_dir().join("context").display().to_string());
        Ok(AgentSettings {
            soul_path: soul_path.display().to_string(),
            soul_content,
            context_dir,
        })
    }

    /// List the skills visible to Work using the exact same config, runtime
    /// state, compatibility checks, and ClawHub verification as Agent Engine.
    pub fn skills(&self) -> Result<Vec<WorkSkill>, SkillSettingsError> {
        let config = Config::load_from_path_for_headless(&self.config_path)
            .map_err(|error| SkillSettingsError::Config(error.to_string()))?;
        let skills_dir = config.skills_data_dir();
        microclaw::builtin_skills::ensure_builtin_skills(Path::new(&skills_dir))?;
        let manager = microclaw::skills::SkillManager::from_skills_and_runtime(
            &skills_dir,
            &config.runtime_data_dir(),
        )
        .with_config_verification(&config);

        Ok(manager
            .discover_skills_with_status(true)
            .into_iter()
            .map(|skill| {
                let user_disabled =
                    skill.reason.as_deref() == Some("Skill is disabled for this runtime.");
                WorkSkill {
                    name: skill.meta.name,
                    description: skill.meta.description,
                    source: skill.meta.source,
                    version: skill.meta.version,
                    enabled: !user_disabled,
                    available: skill.available,
                    reason: skill.reason,
                }
            })
            .collect())
    }

    /// Change only Work's runtime-scoped enablement state. Skill files are
    /// never rewritten or removed by this operation.
    pub fn set_skill_enabled(
        &self,
        name: &str,
        enabled: bool,
    ) -> Result<Vec<WorkSkill>, SkillSettingsError> {
        let config = Config::load_from_path_for_headless(&self.config_path)
            .map_err(|error| SkillSettingsError::Config(error.to_string()))?;
        let manager = microclaw::skills::SkillManager::from_skills_and_runtime(
            &config.skills_data_dir(),
            &config.runtime_data_dir(),
        )
        .with_config_verification(&config);
        manager
            .set_enabled(name, enabled)
            .map_err(SkillSettingsError::Skill)?;
        self.skills()
    }

    /// Install or update a Skill from a local directory, GitHub reference, or
    /// ClawHub slug. The source is intentionally inferred so Work needs one
    /// compact import control rather than three package-manager screens.
    pub fn install_skill(&self, reference: &str) -> Result<SkillInstallResult, SkillSettingsError> {
        let reference = reference.trim();
        if reference.is_empty() {
            return Err(SkillSettingsError::Skill("skill source is required".into()));
        }
        let config = Config::load_from_path_for_headless(&self.config_path)
            .map_err(|error| SkillSettingsError::Config(error.to_string()))?;
        let skills_dir = PathBuf::from(config.skills_data_dir());
        fs::create_dir_all(&skills_dir)?;
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|error| SkillSettingsError::Skill(error.to_string()))?;

        let manager = microclaw::skills::SkillManager::from_skills_and_runtime(
            &config.skills_data_dir(),
            &config.runtime_data_dir(),
        )
        .with_config_verification(&config);
        let outcome = runtime
            .block_on(microclaw::skill_management::install_skill(
                &config, &manager, reference,
            ))
            .map_err(SkillSettingsError::Skill)?;
        Ok(SkillInstallResult {
            message: outcome.message,
            warnings: outcome.warnings,
            skills: self.skills()?,
        })
    }

    pub fn install_skill_background(
        &self,
        reference: String,
    ) -> Receiver<Result<SkillInstallResult, SkillSettingsError>> {
        let (tx, rx) = mpsc::channel();
        let service = self.clone();
        std::thread::Builder::new()
            .name("microclaw-skill-import".into())
            .spawn(move || {
                let _ = tx.send(service.install_skill(&reference));
            })
            .expect("failed to start skill import worker");
        rx
    }

    /// Recoverably remove a Skill by moving its directory below `.archived`.
    pub fn remove_skill(&self, name: &str) -> Result<SkillRemovalResult, SkillSettingsError> {
        let config = Config::load_from_path_for_headless(&self.config_path)
            .map_err(|error| SkillSettingsError::Config(error.to_string()))?;
        let manager = microclaw::skills::SkillManager::from_skills_and_runtime(
            &config.skills_data_dir(),
            &config.runtime_data_dir(),
        )
        .with_config_verification(&config);
        let archived_to = microclaw::skill_management::archive_skill(&manager, name)
            .map_err(SkillSettingsError::Skill)?;
        Ok(SkillRemovalResult {
            name: name.to_string(),
            archived_to: archived_to.display().to_string(),
            skills: self.skills()?,
        })
    }

    pub fn subagents(&self, session: &str) -> Result<Vec<WorkSubagent>, SkillSettingsError> {
        let config = Config::load_from_path_for_headless(&self.config_path)
            .map_err(|error| SkillSettingsError::Config(error.to_string()))?;
        let db = Database::new(&config.runtime_data_dir())
            .map_err(|error| SkillSettingsError::Skill(error.to_string()))?;
        let Some(chat_id) = find_work_session_chat_id(&db, session)? else {
            return Ok(Vec::new());
        };
        db.list_subagent_runs(chat_id, 100)
            .map_err(|error| SkillSettingsError::Skill(error.to_string()))
            .map(|rows| {
                rows.into_iter()
                    .map(|row| {
                        let elapsed_seconds =
                            subagent_elapsed_seconds(&row.created_at, row.finished_at.as_deref());
                        WorkSubagent {
                            run_id: row.run_id,
                            label: row.label.unwrap_or_else(|| "Subagent".into()),
                            task: row.task,
                            status: row.status,
                            progress: row.progress_text,
                            result: row.result_text,
                            error: row.error_text,
                            created_at: row.created_at,
                            finished_at: row.finished_at,
                            elapsed_seconds,
                            cancel_requested: row.cancel_requested,
                        }
                    })
                    .collect()
            })
    }

    pub fn cancel_subagent(&self, session: &str, run_id: &str) -> Result<bool, SkillSettingsError> {
        let config = Config::load_from_path_for_headless(&self.config_path)
            .map_err(|error| SkillSettingsError::Config(error.to_string()))?;
        let db = Database::new(&config.runtime_data_dir())
            .map_err(|error| SkillSettingsError::Skill(error.to_string()))?;
        let Some(chat_id) = find_work_session_chat_id(&db, session)? else {
            return Ok(false);
        };
        microclaw::tools::subagents::request_subagent_cancel(&config, &db, chat_id, run_id)
            .map_err(|error| SkillSettingsError::Skill(error.to_string()))
    }

    pub fn save_agent_settings(
        &self,
        draft: AgentSettingsDraft,
    ) -> Result<AgentSettings, AgentSettingsError> {
        let soul_path = draft.soul_path.trim();
        if soul_path.is_empty() {
            return Err(AgentSettingsError::MissingSoulPath);
        }
        if url::Url::parse(soul_path).is_ok() {
            return Err(AgentSettingsError::RemoteSoulPath);
        }
        let soul_path = PathBuf::from(soul_path);
        if let Some(parent) = soul_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)?;
        }
        fs::write(&soul_path, draft.soul_content.trim_end())?;

        let mut config = Config::load_from_path_for_headless(&self.config_path)
            .map_err(|error| AgentSettingsError::Config(error.to_string()))?;
        let before = config.clone();
        config.soul_path = Some(soul_path.display().to_string());
        config.context_dir =
            (!draft.context_dir.trim().is_empty()).then(|| draft.context_dir.trim().to_string());
        microclaw::config_persistence::save_config_delta_preserving_comments(
            &self.config_path,
            &before,
            &config,
        )
        .map_err(|error| AgentSettingsError::Config(error.to_string()))?;
        self.agent_settings()
    }

    pub fn codex_account_available(&self) -> bool {
        codex_account_available_at(
            dirs::home_dir().as_deref(),
            std::env::var_os("OPENAI_CODEX_ACCESS_TOKEN").is_some(),
        )
    }

    pub fn codex_default_model(&self) -> String {
        codex_model_from_config(&microclaw::codex_auth::default_codex_config_path())
            .or_else(|| {
                popular_model_provider_presets()
                    .into_iter()
                    .find(|preset| preset.id == "openai-codex")
                    .and_then(|preset| preset.models.first().copied())
                    .map(str::to_string)
            })
            .unwrap_or_else(|| {
                microclaw::config::default_model_for_provider_name("openai-codex").to_string()
            })
    }

    pub fn save_model_settings(
        &self,
        draft: ModelSettingsDraft,
    ) -> Result<ModelSettings, ModelSettingsError> {
        let provider = draft.provider.trim().to_ascii_lowercase();
        if provider.is_empty() {
            return Err(ModelSettingsError::MissingProvider);
        }
        let model = draft.model.trim().to_string();
        if model.is_empty() {
            return Err(ModelSettingsError::MissingModel);
        }
        let base_url = draft.base_url.trim().to_string();
        if !base_url.is_empty() {
            let parsed = url::Url::parse(&base_url)
                .map_err(|_| ModelSettingsError::InvalidBaseUrl(base_url.clone()))?;
            if !matches!(parsed.scheme(), "http" | "https") {
                return Err(ModelSettingsError::InvalidBaseUrl(base_url));
            }
        }

        let (existing, recovery_backup) = match Config::load_from_path_for_headless(
            &self.config_path,
        ) {
            Ok(config) => (Some(config), None),
            Err(_) if !self.config_path.exists() => (None, None),
            Err(_) if self.config_ownership == WorkConfigOwnership::WorkOwned => {
                let backup = quarantine_config_file(&self.config_path)?;
                (None, Some(backup.display().to_string()))
            }
            Err(error) => {
                return Err(ModelSettingsError::Config(format!(
                    "{error}; this configuration is shared or explicitly selected and was not replaced"
                )));
            }
        };
        let api_key = draft
            .api_key
            .map(|key| key.trim().to_string())
            .unwrap_or_else(|| {
                existing
                    .as_ref()
                    .map_or(String::new(), |config| config.api_key.clone())
            });
        if api_key.is_empty() && !provider_allows_keyless(&provider) {
            return Err(ModelSettingsError::MissingApiKey {
                provider: provider.clone(),
            });
        }

        if let Some(mut config) = existing {
            let before = config.clone();
            config.llm_provider = provider;
            config.model = model;
            config.api_key = api_key;
            config.llm_base_url = (!base_url.is_empty()).then_some(base_url);
            microclaw::config_persistence::save_config_delta_preserving_comments(
                &self.config_path,
                &before,
                &config,
            )
            .map_err(|error| ModelSettingsError::Config(error.to_string()))?;
        } else {
            write_new_config(&self.config_path, &provider, &model, &api_key, &base_url)?;
        }
        let mut settings = self.model_settings()?;
        settings.recovery_backup = recovery_backup;
        Ok(settings)
    }

    pub fn start(&self, request: WorkRunRequest) -> WorkRunHandle {
        let (message_tx, message_rx) = mpsc::channel();
        let (cancel_tx, cancel_rx) = tokio::sync::mpsc::unbounded_channel();
        let (steer_tx, steer_rx) = tokio::sync::mpsc::unbounded_channel();
        let run_id = next_run_id();
        let thread_name = format!("microclaw-work-{run_id}");
        let worker_run_id = run_id.clone();
        let worker_message_tx = message_tx.clone();
        let spawn_result = std::thread::Builder::new().name(thread_name).spawn({
            let config_path = self.config_path.clone();
            move || {
                run_worker(
                    config_path,
                    request,
                    worker_run_id,
                    worker_message_tx,
                    cancel_rx,
                    steer_rx,
                )
            }
        });
        if let Err(error) = spawn_result {
            let _ = message_tx.send(WorkRuntimeMessage::Failed {
                run_id,
                message: format!("Could not start the runtime worker thread: {error}"),
            });
        }
        WorkRunHandle {
            messages: message_rx,
            cancellation: WorkRunCancellation { cancel_tx },
            steering: WorkRunSteering { steer_tx },
        }
    }

    /// Restore a completed Work task's pre-run checkpoint on a background
    /// thread. The returned channel resolves once filesystem restoration has
    /// succeeded or failed.
    pub fn restore_workspace(
        &self,
        workspace: PathBuf,
        commit: String,
    ) -> Receiver<Result<(), String>> {
        let (result_tx, result_rx) = mpsc::channel();
        let config_path = self.config_path.clone();
        let spawn = std::thread::Builder::new()
            .name("microclaw-work-restore".into())
            .spawn(move || {
                let result = (|| -> Result<(), String> {
                    let config = Config::load_from_path_for_headless(&config_path)
                        .map_err(|error| error.to_string())?;
                    let workspace = workspace
                        .canonicalize()
                        .map_err(|error| format!("workspace is unavailable: {error}"))?;
                    let shadow_root = PathBuf::from(config.runtime_data_dir()).join("checkpoints");
                    let shadow_repo =
                        microclaw::checkpoint::shadow_repo_path(&shadow_root, &workspace);
                    let runtime = tokio::runtime::Runtime::new()
                        .map_err(|error| format!("could not create restore runtime: {error}"))?;
                    runtime.block_on(microclaw::checkpoint::restore(
                        &shadow_repo,
                        &workspace,
                        &commit,
                    ))
                })();
                let _ = result_tx.send(result);
            });
        if let Err(error) = spawn {
            let (fallback_tx, fallback_rx) = mpsc::channel();
            let _ = fallback_tx.send(Err(format!("could not start restore worker: {error}")));
            return fallback_rx;
        }
        result_rx
    }
}

fn directory_diagnostic(id: &'static str, label: &'static str, path: &Path) -> DiagnosticCheck {
    let result = (|| -> io::Result<PathBuf> {
        if path.as_os_str().is_empty() {
            return Err(io::Error::other("path is not configured"));
        }
        fs::create_dir_all(path)?;
        let canonical = path.canonicalize()?;
        if !canonical.is_dir() {
            return Err(io::Error::other("path is not a directory"));
        }
        let probe = canonical.join(format!(
            ".microclaw-work-write-test-{}-{}",
            std::process::id(),
            NEXT_DIAGNOSTIC_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::write(&probe, b"ok")?;
        fs::remove_file(probe)?;
        Ok(canonical)
    })();
    match result {
        Ok(path) => DiagnosticCheck {
            id,
            label,
            status: DiagnosticStatus::Pass,
            detail: path.display().to_string(),
        },
        Err(error) => DiagnosticCheck {
            id,
            label,
            status: DiagnosticStatus::Fail,
            detail: format!("{}: {error}", path.display()),
        },
    }
}

fn config_permissions_diagnostic(path: &Path) -> DiagnosticCheck {
    if !path.is_file() {
        return DiagnosticCheck {
            id: "config-permissions",
            label: "Credential file permissions",
            status: DiagnosticStatus::Warning,
            detail: "Configuration file has not been created yet.".into(),
        };
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match fs::metadata(path) {
            Ok(metadata) if metadata.permissions().mode() & 0o077 == 0 => DiagnosticCheck {
                id: "config-permissions",
                label: "Credential file permissions",
                status: DiagnosticStatus::Pass,
                detail: "Only the current OS user can read the configuration file.".into(),
            },
            Ok(metadata) => DiagnosticCheck {
                id: "config-permissions",
                label: "Credential file permissions",
                status: DiagnosticStatus::Warning,
                detail: format!(
                    "Configuration mode {:o} is broader than recommended 600.",
                    metadata.permissions().mode() & 0o777
                ),
            },
            Err(error) => DiagnosticCheck {
                id: "config-permissions",
                label: "Credential file permissions",
                status: DiagnosticStatus::Fail,
                detail: error.to_string(),
            },
        }
    }
    #[cfg(not(unix))]
    {
        DiagnosticCheck {
            id: "config-permissions",
            label: "Credential file permissions",
            status: DiagnosticStatus::Warning,
            detail: "Configuration access is managed by the operating system ACL and was not inspected by this preview build.".into(),
        }
    }
}

fn run_worker(
    config_path: PathBuf,
    request: WorkRunRequest,
    run_id: String,
    message_tx: Sender<WorkRuntimeMessage>,
    mut cancel_rx: tokio::sync::mpsc::UnboundedReceiver<()>,
    mut steer_rx: tokio::sync::mpsc::UnboundedReceiver<String>,
) {
    let tokio_runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(error) => {
            send_failure(
                &message_tx,
                &run_id,
                format!("Could not create the Tokio runtime: {error}"),
            );
            return;
        }
    };

    let result = tokio_runtime.block_on(async {
        let embedded_runtime = MicroClaw::builder(config_path)
            .caller_channel("work")
            .workspace(request.workspace)
            .max_concurrent_runs(1)
            .build()
            .await?;

        let mut runtime_request = RunRequest::new(request.task);
        runtime_request.run_id = Some(RunId::new(run_id.clone()));
        runtime_request.session_id = Some(SessionId::new(request.session));
        let agent = embedded_runtime.agent("MicroClaw Work").build()?;
        let mut run = agent.run_request(runtime_request);
        let controller = run.controller();
        'run_loop: loop {
            tokio::select! {
                event = run.next_event() => {
                    match event {
                        Some(envelope) => {
                            if message_tx.send(WorkRuntimeMessage::Envelope(envelope)).is_err() {
                                break run.result().await.map_err(anyhow::Error::from);
                            }
                        }
                        None => break run.result().await.map_err(anyhow::Error::from),
                    }
                }
                signal = cancel_rx.recv() => {
                    if signal.is_some() && controller.cancel_confirmed().await.is_ok() {
                        while let Some(envelope) = run.next_event().await {
                            let _ = message_tx.send(WorkRuntimeMessage::Envelope(envelope));
                        }
                        break 'run_loop run.result().await.map_err(anyhow::Error::from);
                    }
                }
                update = steer_rx.recv() => {
                    if let Some(update) = update {
                        let (accepted, message) = match controller.steer_confirmed(&update).await {
                            Ok(()) => (true, update),
                            Err(error) => (false, error.to_string()),
                        };
                        let _ = message_tx.send(WorkRuntimeMessage::SteeringResult {
                            run_id: run_id.clone(),
                            accepted,
                            message,
                        });
                    }
                }
            }
        }
    });

    match result {
        Ok(result) => {
            let _ = message_tx.send(WorkRuntimeMessage::Completed {
                run_id: result.run_id.to_string(),
            });
        }
        Err(error) => send_failure(&message_tx, &run_id, error.to_string()),
    }
}

#[cfg(test)]
fn configure_work_runtime(mut config: Config, workspace: String) -> Config {
    config.working_dir = workspace;
    // Work is an explicit foreground project session. Its tools must operate
    // from the folder the user selected, while Server keeps its configured
    // per-chat isolation behavior.
    config.working_dir_isolation = WorkingDirIsolation::Direct;
    config.checkpoints_enabled = true;
    config
}

#[cfg(test)]
fn work_session_chat_id(db: &Database, session: &str) -> Result<i64, SkillSettingsError> {
    let session = session.trim();
    if session.is_empty() {
        return Err(SkillSettingsError::Skill("Work session is required".into()));
    }
    db.resolve_or_create_chat_id(
        "headless",
        &format!("headless:{session}"),
        Some(&format!("headless-{session}")),
        "headless",
    )
    .map_err(|error| SkillSettingsError::Skill(error.to_string()))
}

fn find_work_session_chat_id(
    db: &Database,
    session: &str,
) -> Result<Option<i64>, SkillSettingsError> {
    let session = session.trim();
    if session.is_empty() {
        return Err(SkillSettingsError::Skill("Work session is required".into()));
    }
    db.find_chat_id("headless", &format!("headless:{session}"))
        .map_err(|error| SkillSettingsError::Skill(error.to_string()))
}

fn subagent_elapsed_seconds(created_at: &str, finished_at: Option<&str>) -> u64 {
    let Ok(created) = chrono::DateTime::parse_from_rfc3339(created_at) else {
        return 0;
    };
    let finished = finished_at
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .unwrap_or_else(|| chrono::Utc::now().fixed_offset());
    finished.signed_duration_since(created).num_seconds().max(0) as u64
}

fn codex_account_available_at(home: Option<&Path>, access_token_present: bool) -> bool {
    access_token_present || home.is_some_and(|home| home.join(".codex").join("auth.json").is_file())
}

fn codex_model_from_config(path: &Path) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct CodexPreferences {
        model: Option<String>,
    }
    let content = fs::read_to_string(path).ok()?;
    let preferences: CodexPreferences = toml::from_str(&content).ok()?;
    preferences.model.filter(|model| !model.trim().is_empty())
}

fn provider_allows_keyless(provider: &str) -> bool {
    matches!(provider, "ollama" | "openai-codex" | "qwen-portal")
}

fn write_new_config(
    path: &Path,
    provider: &str,
    model: &str,
    api_key: &str,
    base_url: &str,
) -> Result<(), ModelSettingsError> {
    #[derive(serde::Serialize)]
    struct MinimalConfig<'a> {
        llm_provider: &'a str,
        api_key: &'a str,
        model: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        llm_base_url: Option<&'a str>,
        web_enabled: bool,
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_yaml::to_string(&MinimalConfig {
        llm_provider: provider,
        api_key,
        model,
        llm_base_url: (!base_url.is_empty()).then_some(base_url),
        web_enabled: false,
    })
    .map_err(|error| ModelSettingsError::Config(error.to_string()))?;
    let temporary = path.with_extension("yaml.tmp");
    fs::write(&temporary, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))?;
    }
    fs::rename(&temporary, path)?;
    Ok(())
}

fn quarantine_config_file(path: &Path) -> io::Result<PathBuf> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("microclaw.config.yaml");
    for attempt in 0..100_u8 {
        let backup = path.with_file_name(format!("{file_name}.corrupt-{timestamp}-{attempt}"));
        if !backup.exists() {
            fs::rename(path, &backup)?;
            return Ok(backup);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a configuration recovery backup path",
    ))
}

fn send_failure(message_tx: &Sender<WorkRuntimeMessage>, run_id: &str, message: String) {
    let _ = message_tx.send(WorkRuntimeMessage::Failed {
        run_id: run_id.to_string(),
        message,
    });
}

fn redact_runtime_error(error: &str, api_key: &str) -> String {
    let error = if api_key.is_empty() {
        error.to_string()
    } else {
        error.replace(api_key, "<redacted>")
    };
    microclaw_core::redact::redact_secrets(&error)
}

fn next_diagnostic_run_id() -> String {
    let counter = NEXT_DIAGNOSTIC_ID.fetch_add(1, Ordering::Relaxed);
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis());
    format!("work-diagnostic-{millis}-{counter}")
}

fn next_run_id() -> String {
    let counter = NEXT_RUN_ID.fetch_add(1, Ordering::Relaxed);
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis());
    format!("work-{millis}-{counter}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn provider_fixture(status: &str, body: &'static str) -> (String, Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (request_tx, request_rx) = mpsc::channel();
        let status = status.to_string();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut bytes = vec![0; 16 * 1024];
            let count = stream.read(&mut bytes).unwrap_or(0);
            let request = String::from_utf8_lossy(&bytes[..count]).to_string();
            let _ = request_tx.send(request);
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.flush().unwrap();
        });
        (format!("http://{address}/v1"), request_rx)
    }

    fn repeating_provider_fixture(status: &str, body: &'static str) -> (String, Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (request_tx, request_rx) = mpsc::channel();
        let status = status.to_string();
        std::thread::spawn(move || {
            while let Ok((mut stream, _)) = listener.accept() {
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut bytes = vec![0; 64 * 1024];
                let count = stream.read(&mut bytes).unwrap_or(0);
                let request = String::from_utf8_lossy(&bytes[..count]).to_string();
                if request_tx.send(request).is_err() {
                    break;
                }
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).unwrap();
                stream.flush().unwrap();
            }
        });
        (format!("http://{address}/v1"), request_rx)
    }

    #[test]
    fn generated_run_ids_are_unique() {
        assert_ne!(next_run_id(), next_run_id());
    }

    #[test]
    fn detects_codex_account_without_reading_credentials() {
        let directory = tempfile::tempdir().unwrap();
        assert!(!codex_account_available_at(Some(directory.path()), false));
        assert!(codex_account_available_at(Some(directory.path()), true));

        let codex_dir = directory.path().join(".codex");
        fs::create_dir_all(&codex_dir).unwrap();
        fs::write(codex_dir.join("auth.json"), b"not inspected").unwrap();
        assert!(codex_account_available_at(Some(directory.path()), false));
    }

    #[test]
    fn uses_the_model_selected_by_the_local_codex_client() {
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("config.toml");
        fs::write(
            &config,
            "model = \"gpt-account-model\"\nmodel_reasoning_effort = \"high\"\n",
        )
        .unwrap();
        assert_eq!(
            codex_model_from_config(&config).as_deref(),
            Some("gpt-account-model")
        );

        fs::write(&config, "model = \"\"\n").unwrap();
        assert_eq!(codex_model_from_config(&config), None);
    }

    #[test]
    fn popular_provider_catalog_has_current_models_and_endpoints() {
        let presets = popular_model_provider_presets();
        assert_eq!(presets.len(), 12);
        assert_eq!(presets[0].id, "openai");
        assert_eq!(presets[0].models[0], "gpt-5.6-sol");
        assert!(
            presets
                .iter()
                .find(|preset| preset.id == "anthropic")
                .unwrap()
                .models
                .contains(&"claude-opus-5")
        );
        assert_eq!(
            presets
                .iter()
                .find(|preset| preset.id == "moonshot")
                .unwrap()
                .models[0],
            "kimi-k3"
        );
        assert!(presets.iter().all(|preset| !preset.models.is_empty()));
    }

    #[test]
    fn cancellation_signal_is_runtime_independent() {
        let (cancel_tx, mut cancel_rx) = tokio::sync::mpsc::unbounded_channel();
        let cancellation = WorkRunCancellation { cancel_tx };

        cancellation.cancel().unwrap();
        assert_eq!(cancel_rx.try_recv(), Ok(()));
    }

    #[test]
    fn work_runtime_uses_selected_workspace_without_server_chat_isolation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.yaml");
        fs::write(
            &path,
            "llm_provider: ollama\napi_key: ''\nmodel: local\nweb_enabled: false\n",
        )
        .unwrap();
        let mut config = Config::load_from_path_for_headless(&path).unwrap();
        config.working_dir = "/server/default".into();
        config.working_dir_isolation = WorkingDirIsolation::Chat;
        config.checkpoints_enabled = false;

        let configured = configure_work_runtime(config, "/project/selected".into());

        assert_eq!(configured.working_dir, "/project/selected");
        assert_eq!(
            configured.working_dir_isolation,
            WorkingDirIsolation::Direct
        );
        assert!(configured.checkpoints_enabled);
    }

    #[test]
    fn steering_signal_is_runtime_independent_and_validated() {
        let (steer_tx, mut steer_rx) = tokio::sync::mpsc::unbounded_channel();
        let steering = WorkRunSteering { steer_tx };

        assert!(steering.steer("  ").is_err());
        steering.steer("Focus on tests").unwrap();
        assert_eq!(steer_rx.try_recv(), Ok("Focus on tests".into()));
    }

    #[test]
    fn creates_and_loads_minimal_work_configuration() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("microclaw.config.yaml");
        let service = WorkRuntimeService::new(&path);

        let saved = service
            .save_model_settings(ModelSettingsDraft {
                provider: " openai ".into(),
                model: " gpt-5 ".into(),
                base_url: "https://api.openai.com/v1".into(),
                api_key: Some("secret-key".into()),
            })
            .unwrap();

        assert_eq!(saved.provider, "openai");
        assert_eq!(saved.model, "gpt-5");
        assert!(saved.has_api_key);
        assert!(service.config_summary().ready);
        let raw = fs::read_to_string(path).unwrap();
        assert!(raw.contains("web_enabled: false"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(service.config_path())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn diagnostics_report_missing_model_but_prepare_local_directories() {
        let directory = tempfile::tempdir().unwrap();
        let service = WorkRuntimeService::new(directory.path().join("config.yaml"));
        let workspace = directory.path().join("workspace");
        let sessions = directory.path().join("sessions");

        let report = service.local_diagnostics(&workspace, &sessions);

        assert!(!report.ready);
        assert!(workspace.is_dir());
        assert!(sessions.is_dir());
        assert_eq!(
            report
                .checks
                .iter()
                .find(|check| check.id == "model-config")
                .unwrap()
                .status,
            DiagnosticStatus::Fail
        );
        assert_eq!(
            report
                .checks
                .iter()
                .find(|check| check.id == "config-permissions")
                .unwrap()
                .status,
            DiagnosticStatus::Warning
        );
    }

    #[test]
    fn diagnostics_report_ready_after_model_and_storage_are_configured() {
        let directory = tempfile::tempdir().unwrap();
        let service = WorkRuntimeService::new(directory.path().join("config.yaml"));
        service
            .save_model_settings(ModelSettingsDraft {
                provider: "openai".into(),
                model: "gpt-5".into(),
                base_url: "".into(),
                api_key: Some("secret-key".into()),
            })
            .unwrap();

        let report = service.local_diagnostics(
            &directory.path().join("workspace"),
            &directory.path().join("sessions"),
        );

        assert!(report.ready);
        assert_eq!(report.checks.len(), 4);
        assert!(
            report
                .checks
                .iter()
                .all(|check| check.status != DiagnosticStatus::Fail)
        );
        assert!(
            report
                .checks
                .iter()
                .all(|check| !check.detail.contains("secret-key"))
        );
    }

    #[test]
    fn preserves_existing_key_and_comments_when_updating_model() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("microclaw.config.yaml");
        fs::write(
            &path,
            "# keep this comment\nllm_provider: openai\napi_key: existing-secret\nmodel: gpt-5\nweb_enabled: false\n",
        )
        .unwrap();
        let service = WorkRuntimeService::new(&path);

        service
            .save_model_settings(ModelSettingsDraft {
                provider: "openai".into(),
                model: "gpt-5-mini".into(),
                base_url: "".into(),
                api_key: None,
            })
            .unwrap();

        let raw = fs::read_to_string(path).unwrap();
        assert!(raw.contains("# keep this comment"));
        assert!(raw.contains("existing-secret"));
        assert!(raw.contains("gpt-5-mini"));
    }

    #[test]
    fn work_owned_invalid_config_is_preserved_before_model_recovery() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("microclaw.config.yaml");
        fs::write(&path, "not: [valid yaml").unwrap();
        let service = WorkRuntimeService::new_work_owned(&path);

        let settings = service
            .save_model_settings(ModelSettingsDraft {
                provider: "ollama".into(),
                model: "qwen3:8b".into(),
                base_url: "".into(),
                api_key: None,
            })
            .unwrap();

        let backup = PathBuf::from(settings.recovery_backup.unwrap());
        assert!(backup.is_file());
        assert_eq!(fs::read_to_string(backup).unwrap(), "not: [valid yaml");
        assert_eq!(service.model_settings().unwrap().model, "qwen3:8b");
    }

    #[test]
    fn external_invalid_config_is_never_replaced_by_work() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("server.config.yaml");
        fs::write(&path, "not: [valid yaml").unwrap();
        let service = WorkRuntimeService::new(&path);

        let error = service
            .save_model_settings(ModelSettingsDraft {
                provider: "ollama".into(),
                model: "qwen3:8b".into(),
                base_url: "".into(),
                api_key: None,
            })
            .unwrap_err();

        assert!(error.to_string().contains("was not replaced"));
        assert_eq!(fs::read_to_string(path).unwrap(), "not: [valid yaml");
    }

    #[test]
    fn saves_agent_identity_and_project_context_without_rewriting_config() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("microclaw.config.yaml");
        fs::write(
            &path,
            "# keep this comment\nllm_provider: ollama\napi_key: ''\nmodel: local\nweb_enabled: false\n",
        )
        .unwrap();
        let soul_path = directory.path().join("identity").join("SOUL.md");
        let context_dir = directory.path().join("context");
        let service = WorkRuntimeService::new(&path);

        let saved = service
            .save_agent_settings(AgentSettingsDraft {
                soul_path: soul_path.display().to_string(),
                soul_content: "# My Soul\n\nBe thoughtful.\n".into(),
                context_dir: context_dir.display().to_string(),
            })
            .unwrap();

        assert_eq!(saved.soul_path, soul_path.display().to_string());
        assert_eq!(saved.soul_content, "# My Soul\n\nBe thoughtful.");
        assert_eq!(saved.context_dir, context_dir.display().to_string());
        assert_eq!(fs::read_to_string(soul_path).unwrap(), saved.soul_content);
        let raw = fs::read_to_string(path).unwrap();
        assert!(raw.contains("# keep this comment"));
        assert!(raw.contains("soul_path:"));
        assert!(raw.contains("context_dir:"));
    }

    #[test]
    fn agent_settings_reject_remote_soul_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("microclaw.config.yaml");
        fs::write(
            &path,
            "llm_provider: ollama\napi_key: ''\nmodel: local\nweb_enabled: false\n",
        )
        .unwrap();
        let service = WorkRuntimeService::new(path);

        let error = service
            .save_agent_settings(AgentSettingsDraft {
                soul_path: "https://example.com/SOUL.md".into(),
                soul_content: "remote".into(),
                context_dir: String::new(),
            })
            .unwrap_err();

        assert!(matches!(error, AgentSettingsError::RemoteSoulPath));
    }

    #[test]
    fn agent_settings_resolve_named_soul_from_souls_directory() {
        let directory = tempfile::tempdir().unwrap();
        let souls_dir = directory.path().join("souls");
        fs::create_dir_all(&souls_dir).unwrap();
        fs::write(souls_dir.join("focused.md"), "# Focused\n").unwrap();
        let path = directory.path().join("microclaw.config.yaml");
        fs::write(
            &path,
            format!(
                "llm_provider: ollama\napi_key: ''\nmodel: local\nweb_enabled: false\ndata_dir: {}\nsouls_dir: {}\nsoul_path: focused.md\n",
                directory.path().display(),
                souls_dir.display()
            ),
        )
        .unwrap();

        let settings = WorkRuntimeService::new(path).agent_settings().unwrap();

        assert_eq!(
            settings.soul_path,
            souls_dir.join("focused.md").display().to_string()
        );
        assert_eq!(settings.soul_content, "# Focused\n");
    }

    #[test]
    fn validates_required_credentials_and_base_url() {
        let directory = tempfile::tempdir().unwrap();
        let service = WorkRuntimeService::new(directory.path().join("config.yaml"));
        let error = service
            .save_model_settings(ModelSettingsDraft {
                provider: "anthropic".into(),
                model: "claude-sonnet-4-5-20250929".into(),
                base_url: "file:///tmp/provider".into(),
                api_key: Some("key".into()),
            })
            .unwrap_err();
        assert!(matches!(error, ModelSettingsError::InvalidBaseUrl(_)));

        let error = service
            .save_model_settings(ModelSettingsDraft {
                provider: "anthropic".into(),
                model: "claude-sonnet-4-5-20250929".into(),
                base_url: "".into(),
                api_key: Some(String::new()),
            })
            .unwrap_err();
        assert!(matches!(error, ModelSettingsError::MissingApiKey { .. }));
    }

    #[test]
    fn provider_connection_test_exercises_endpoint_auth_model_and_response() {
        let (base_url, request_rx) = repeating_provider_fixture(
            "200 OK",
            r#"{"choices":[{"message":{"content":"connection ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":2,"total_tokens":3}}"#,
        );
        let directory = tempfile::tempdir().unwrap();
        let service = WorkRuntimeService::new(directory.path().join("config.yaml"));
        service
            .save_model_settings(ModelSettingsDraft {
                provider: "openai".into(),
                model: "fixture-model".into(),
                base_url,
                api_key: Some("fixture-secret".into()),
            })
            .unwrap();

        let report = service
            .test_provider_connection()
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap();
        let request = request_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(request.starts_with("POST /v1/chat/completions "));
        assert!(
            request
                .to_ascii_lowercase()
                .contains("authorization: bearer fixture-secret")
        );
        assert!(request.contains("fixture-model"));
        assert!(request.contains("MicroClaw Work connection test"));
        assert_eq!(report.provider, "openai");
        assert_eq!(report.model, "fixture-model");
        assert_eq!(report.response_preview, "connection ok");
    }

    #[test]
    fn first_response_proof_runs_shared_agent_engine_and_event_stream() {
        let (base_url, request_rx) = repeating_provider_fixture(
            "200 OK",
            "data: {\"choices\":[{\"delta\":{\"content\":\"first response ok\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n",
        );
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("config.yaml");
        let service = WorkRuntimeService::new(&config_path);
        service
            .save_model_settings(ModelSettingsDraft {
                provider: "openai".into(),
                model: "fixture-model".into(),
                base_url,
                api_key: Some("fixture-secret".into()),
            })
            .unwrap();
        let mut config = fs::read_to_string(&config_path).unwrap();
        config.push_str(&format!(
            "data_dir: {}\n",
            directory.path().join("runtime-data").display()
        ));
        fs::write(&config_path, config).unwrap();
        let workspace = directory.path().join("workspace");
        fs::create_dir(&workspace).unwrap();

        let report = service
            .test_first_response(workspace)
            .recv_timeout(Duration::from_secs(10))
            .unwrap()
            .unwrap();

        assert_eq!(report.provider, "openai");
        assert_eq!(report.model, "fixture-model");
        assert!(report.run_id.starts_with("work-diagnostic-"));
        assert!(report.event_count > 0);
        assert_eq!(report.response_preview, "first response ok");
        let request = request_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(request.contains("first response ok"));
        assert!(request.contains("fixture-model"));
        assert!(!report.response_preview.contains("fixture-secret"));
    }

    #[test]
    fn provider_connection_test_returns_redacted_provider_errors() {
        let (base_url, _) = provider_fixture(
            "401 Unauthorized",
            r#"{"error":{"message":"bad credential fixture-secret"}}"#,
        );
        let directory = tempfile::tempdir().unwrap();
        let service = WorkRuntimeService::new(directory.path().join("config.yaml"));
        service
            .save_model_settings(ModelSettingsDraft {
                provider: "openai".into(),
                model: "fixture-model".into(),
                base_url,
                api_key: Some("fixture-secret".into()),
            })
            .unwrap();

        let error = service
            .test_provider_connection()
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap_err();
        assert!(!error.contains("fixture-secret"));
        assert!(
            error.contains("LLM API error"),
            "unexpected provider error: {error}"
        );
        assert!(error.contains("<redacted>"));
    }

    #[test]
    fn restore_port_restores_modified_and_removes_created_files() {
        let directory = tempfile::tempdir().unwrap();
        let workspace = directory.path().join("workspace");
        let data_dir = directory.path().join("data");
        fs::create_dir_all(&workspace).unwrap();
        fs::write(workspace.join("tracked.txt"), "before").unwrap();
        let config_path = directory.path().join("microclaw.config.yaml");
        fs::write(
            &config_path,
            format!(
                "llm_provider: ollama\napi_key: ''\nmodel: local\nweb_enabled: false\ndata_dir: '{}'\n",
                data_dir.display()
            ),
        )
        .unwrap();
        let config = Config::load_from_path_for_headless(&config_path).unwrap();
        let shadow_root = PathBuf::from(config.runtime_data_dir()).join("checkpoints");
        let shadow_repo = microclaw::checkpoint::shadow_repo_path(&shadow_root, &workspace);
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let commit = runtime
            .block_on(microclaw::checkpoint::snapshot(
                &shadow_repo,
                &workspace,
                "before task",
            ))
            .unwrap()
            .unwrap();
        fs::write(workspace.join("tracked.txt"), "after").unwrap();
        fs::write(workspace.join("created.txt"), "created").unwrap();

        let service = WorkRuntimeService::new(&config_path);
        service
            .restore_workspace(workspace.clone(), commit)
            .recv_timeout(Duration::from_secs(10))
            .unwrap()
            .unwrap();

        assert_eq!(
            fs::read_to_string(workspace.join("tracked.txt")).unwrap(),
            "before"
        );
        assert!(!workspace.join("created.txt").exists());
    }

    #[test]
    fn work_skills_list_and_toggle_runtime_state() {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().join("data");
        let skills_dir = directory.path().join("skills");
        let config_path = directory.path().join("microclaw.config.yaml");
        fs::create_dir_all(skills_dir.join("fixture-skill")).unwrap();
        fs::write(
            skills_dir.join("fixture-skill/SKILL.md"),
            "---\nname: fixture-skill\ndescription: Work skill fixture\nsource: local\n---\nUse the fixture.\n",
        )
        .unwrap();
        fs::write(
            &config_path,
            format!(
                "llm_provider: ollama\napi_key: ''\nmodel: local\nweb_enabled: false\ndata_dir: '{}'\nskills_dir: '{}'\n",
                data_dir.display(),
                skills_dir.display()
            ),
        )
        .unwrap();
        let service = WorkRuntimeService::new(config_path);

        let listed = service.skills().unwrap();
        let fixture = listed
            .iter()
            .find(|skill| skill.name == "fixture-skill")
            .unwrap();
        assert!(fixture.enabled);
        assert!(fixture.available);

        let disabled = service.set_skill_enabled("fixture-skill", false).unwrap();
        let fixture = disabled
            .iter()
            .find(|skill| skill.name == "fixture-skill")
            .unwrap();
        assert!(!fixture.enabled);
        assert!(!fixture.available);
        assert_eq!(
            fixture.reason.as_deref(),
            Some("Skill is disabled for this runtime.")
        );

        let state = fs::read_to_string(data_dir.join("runtime/skills_state.json")).unwrap();
        assert!(state.contains("fixture-skill"));

        let enabled = service.set_skill_enabled("fixture-skill", true).unwrap();
        let fixture = enabled
            .iter()
            .find(|skill| skill.name == "fixture-skill")
            .unwrap();
        assert!(fixture.enabled);
        assert!(fixture.available);
    }

    #[test]
    fn work_imports_and_updates_local_skill_trees() {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().join("data");
        let skills_dir = directory.path().join("skills");
        let source = directory.path().join("local-skill");
        let config_path = directory.path().join("microclaw.config.yaml");
        fs::create_dir_all(source.join("scripts")).unwrap();
        fs::write(
            source.join("SKILL.md"),
            "---\nname: local-skill\ndescription: Local fixture\nsource: local\n---\nUse it.\n",
        )
        .unwrap();
        fs::write(source.join("scripts/helper.txt"), "v1").unwrap();
        fs::write(
            &config_path,
            format!(
                "llm_provider: ollama\napi_key: ''\nmodel: local\nweb_enabled: false\ndata_dir: '{}'\nskills_dir: '{}'\n",
                data_dir.display(),
                skills_dir.display()
            ),
        )
        .unwrap();
        let service = WorkRuntimeService::new(config_path);

        let result = service.install_skill(source.to_str().unwrap()).unwrap();
        assert!(
            result
                .skills
                .iter()
                .any(|skill| skill.name == "local-skill")
        );
        assert_eq!(
            fs::read_to_string(skills_dir.join("local-skill/scripts/helper.txt")).unwrap(),
            "v1"
        );

        fs::write(source.join("scripts/helper.txt"), "v2").unwrap();
        service.install_skill(source.to_str().unwrap()).unwrap();
        assert_eq!(
            fs::read_to_string(skills_dir.join("local-skill/scripts/helper.txt")).unwrap(),
            "v2"
        );
        assert!(!skills_dir.join(".local-skill.work-backup").exists());
        assert!(!skills_dir.join(".local-skill.work-import").exists());

        let removed = service.remove_skill("local-skill").unwrap();
        assert_eq!(removed.name, "local-skill");
        assert!(
            removed
                .skills
                .iter()
                .all(|skill| skill.name != "local-skill")
        );
        assert!(!skills_dir.join("local-skill").exists());
        assert!(Path::new(&removed.archived_to).join("SKILL.md").exists());
    }

    #[test]
    fn work_lists_and_cancels_durable_subagents() {
        use microclaw::storage::db::subagents::CreateSubagentRunParams;

        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().join("data");
        let config_path = directory.path().join("config.yaml");
        fs::write(
            &config_path,
            format!(
                "llm_provider: ollama\napi_key: ''\nmodel: local\nweb_enabled: false\ndata_dir: '{}'\n",
                data_dir.display()
            ),
        )
        .unwrap();
        let service = WorkRuntimeService::new(config_path);
        let config = Config::load_from_path_for_headless(service.config_path()).unwrap();
        let db = Database::new(&config.runtime_data_dir()).unwrap();
        let chat_id = work_session_chat_id(&db, "session-1").unwrap();
        db.create_subagent_run(CreateSubagentRunParams {
            run_id: "subrun-fixture",
            parent_run_id: None,
            depth: 1,
            token_budget: 1000,
            chat_id,
            caller_channel: "work",
            task: "inspect the project",
            context: "",
            provider: "ollama",
            model: "local",
            label: Some("Inspector"),
        })
        .unwrap();

        let runs = service.subagents("session-1").unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].label, "Inspector");
        assert_eq!(runs[0].status, "accepted");
        assert!(
            service
                .cancel_subagent("session-1", "subrun-fixture")
                .unwrap()
        );
        assert!(service.subagents("session-1").unwrap()[0].cancel_requested);
    }

    #[test]
    #[ignore = "requires OPENAI_APIKEY and live network access"]
    fn live_openai_work_first_response() {
        let api_key = std::env::var("OPENAI_APIKEY")
            .or_else(|_| std::env::var("OPENAI_API_KEY"))
            .expect("set OPENAI_APIKEY or OPENAI_API_KEY");
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("config.yaml");
        let service = WorkRuntimeService::new(&config_path);
        service
            .save_model_settings(ModelSettingsDraft {
                provider: "openai".into(),
                model: "gpt-5-mini".into(),
                base_url: String::new(),
                api_key: Some(api_key),
            })
            .unwrap();
        let mut config = fs::read_to_string(&config_path).unwrap();
        config.push_str(&format!(
            "data_dir: {}\n",
            directory.path().join("runtime-data").display()
        ));
        fs::write(&config_path, config).unwrap();
        let workspace = directory.path().join("workspace");
        fs::create_dir(&workspace).unwrap();

        let report = service
            .test_first_response(workspace)
            .recv_timeout(Duration::from_secs(90))
            .unwrap()
            .unwrap();
        assert_eq!(report.provider, "openai");
        assert_eq!(report.model, "gpt-5-mini");
        assert!(report.event_count > 0);
        assert!(report.response_preview.contains("first response ok"));
    }

    #[test]
    #[ignore = "requires live GitHub and ClawHub network access"]
    fn live_remote_skill_imports() {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().join("data");
        let skills_dir = directory.path().join("skills");
        let config_path = directory.path().join("config.yaml");
        fs::write(
            &config_path,
            format!(
                "llm_provider: ollama\napi_key: ''\nmodel: local\nweb_enabled: false\ndata_dir: '{}'\nskills_dir: '{}'\n",
                data_dir.display(),
                skills_dir.display()
            ),
        )
        .unwrap();
        let service = WorkRuntimeService::new(&config_path);

        let github = service
            .install_skill("https://github.com/vercel-labs/skills/tree/main/skills/find-skills")
            .unwrap();
        assert!(
            github
                .skills
                .iter()
                .any(|skill| skill.name == "find-skills")
        );

        let clawhub = service.install_skill("skills-weather").unwrap();
        assert!(
            clawhub
                .skills
                .iter()
                .any(|skill| skill.name == "skills-weather")
        );
        assert!(
            config_path
                .parent()
                .unwrap()
                .join("data/clawhub.lock.json")
                .is_file()
        );
    }
}
