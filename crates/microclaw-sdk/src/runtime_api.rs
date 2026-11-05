use serde_json::Value;
use std::sync::{Arc, RwLock};

#[cfg(feature = "full")]
use std::path::{Path, PathBuf};

use crate::{AgentId, AgentProfile, RunRequest, ToolPolicy};
pub use microclaw_engine::{
    AgentHandle, ControlRequest, ExecutionContext, ExecutionResult, LocalWorker, RemoteWorker,
    RemoteWorkerOptions, RunController, RunExecutor, RunHandle, Runtime, RuntimeBuildError,
    RuntimeBuilder, RuntimeStats, Worker, WorkerConnection, WorkerTransport,
};

#[cfg(feature = "remote-worker")]
pub use microclaw_engine::{WebSocketWorkerTransport, WorkerHost};

/// `RunRequest::metadata` key. Set it to `true` and a tool call that needs a
/// human pauses the run: the Agent Engine emits `ApprovalRequired` and waits
/// for `RunController::resolve_approval_confirmed(approval_id, "1" | "2" | "3")`
/// (approve once, always allow the tool in this session, deny) instead of
/// ending the run with a text prompt that the next message answers.
pub const INTERACTIVE_APPROVALS: &str = microclaw_engine::headless::INTERACTIVE_APPROVALS_KEY;

/// A workspace checkpoint (see `MicroClaw::checkpoint`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    /// Abbreviated commit id; pass it to `restore_checkpoint`.
    pub commit: String,
    pub label: String,
    /// RFC 3339.
    pub timestamp: String,
}

#[cfg(feature = "full")]
impl From<microclaw_engine::headless::HeadlessCheckpoint> for Checkpoint {
    fn from(c: microclaw_engine::headless::HeadlessCheckpoint) -> Self {
        Self {
            commit: c.commit,
            label: c.label,
            timestamp: c.timestamp,
        }
    }
}

/// Token usage of one session.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionUsage {
    pub requests: i64,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub by_model: Vec<ModelUsage>,
}

/// Result of compacting a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionCompaction {
    pub messages_before: usize,
    pub messages_after: usize,
    pub tokens_before: usize,
    pub tokens_after: usize,
    /// `none`, `pruned`, `summarized` or `fallback`.
    pub method: String,
}

/// How full a session's context is (estimates; see `MicroClaw::context_usage`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextUsage {
    pub model: String,
    /// The model's context window (tokens).
    pub window: usize,
    /// Tokens kept free for the reply.
    pub reserved_output: usize,
    /// Tokens at which automatic compaction starts (0: disabled).
    pub auto_compact_threshold: usize,
    /// Tokens the next request carries (measured when available).
    pub used_tokens: usize,
    /// Input tokens of the last request, as reported by the provider.
    pub last_request_tokens: Option<usize>,
    pub summary_tokens: usize,
    pub user_tokens: usize,
    pub assistant_tokens: usize,
    pub tool_call_tokens: usize,
    pub tool_result_tokens: usize,
    pub image_tokens: usize,
    pub messages: usize,
}

impl ContextUsage {
    /// Share of the usable window (window minus the output reserve) in use.
    pub fn percent_used(&self) -> u8 {
        let usable = self.window.saturating_sub(self.reserved_output).max(1);
        ((self.used_tokens * 100) / usable).min(100) as u8
    }
}

/// Token usage of one model within a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelUsage {
    pub model: String,
    pub requests: i64,
    pub input_tokens: i64,
    pub output_tokens: i64,
}

/// Who wrote a [`SessionMessage`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionMessageRole {
    User,
    Agent,
}

/// One stored message of a named session (see `MicroClaw::session_messages`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionMessage {
    pub role: SessionMessageRole,
    pub content: String,
    /// RFC 3339.
    pub timestamp: String,
}

/// An SDK-level error that does not expose Server or Agent Engine implementation types.
#[derive(Debug, thiserror::Error)]
pub enum SdkError {
    #[error("invalid SDK configuration: {0}")]
    Configuration(String),
    #[error("could not initialize the Agent Engine: {0}")]
    Initialization(String),
    #[error("could not build the runtime: {0}")]
    Runtime(String),
    #[error("agent name must not be empty")]
    EmptyAgentName,
    #[error("Skill '{0}' is not available in this runtime")]
    SkillUnavailable(String),
    #[error("could not manage Skill state: {0}")]
    SkillManagement(String),
}

impl From<RuntimeBuildError> for SdkError {
    fn from(error: RuntimeBuildError) -> Self {
        Self::Runtime(error.to_string())
    }
}

/// Stable category for handling SDK failures without parsing display strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SdkErrorCode {
    Configuration,
    Initialization,
    Runtime,
    InvalidAgent,
    SkillUnavailable,
    SkillManagement,
}

impl SdkError {
    pub fn code(&self) -> SdkErrorCode {
        match self {
            Self::Configuration(_) => SdkErrorCode::Configuration,
            Self::Initialization(_) => SdkErrorCode::Initialization,
            Self::Runtime(_) => SdkErrorCode::Runtime,
            Self::EmptyAgentName => SdkErrorCode::InvalidAgent,
            Self::SkillUnavailable(_) => SdkErrorCode::SkillUnavailable,
            Self::SkillManagement(_) => SdkErrorCode::SkillManagement,
        }
    }

    pub fn retryable(&self) -> bool {
        matches!(self, Self::Initialization(_))
    }
}

/// Stable, UI-neutral metadata for one discovered Skill.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillSummary {
    pub name: String,
    pub description: String,
    pub source: String,
    pub version: Option<String>,
    pub enabled: bool,
    pub available: bool,
    pub unavailable_reason: Option<String>,
}

/// A snapshot of Skills discovered while the SDK runtime was initialized.
#[derive(Debug, Clone, Default)]
pub struct SkillCatalog {
    skills: Vec<SkillSummary>,
}

/// Stable SDK projection of a durable task delegated by the Main Agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegatedTask {
    pub run_id: String,
    pub parent_run_id: Option<String>,
    pub depth: u32,
    pub label: Option<String>,
    pub task: String,
    pub status: DelegatedTaskStatus,
    pub progress: Option<String>,
    pub result: Option<String>,
    pub error: Option<String>,
    pub created_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub cancel_requested: bool,
}

/// Lifecycle state for a task delegated by the Main Agent.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DelegatedTaskStatus {
    Accepted,
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
    BudgetExceeded,
    Unknown(String),
}

impl DelegatedTaskStatus {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Accepted => "accepted",
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::BudgetExceeded => "budget_exceeded",
            Self::Unknown(status) => status,
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::Cancelled | Self::BudgetExceeded
        )
    }
}

impl From<String> for DelegatedTaskStatus {
    fn from(status: String) -> Self {
        match status.as_str() {
            "accepted" => Self::Accepted,
            "queued" => Self::Queued,
            "running" => Self::Running,
            "completed" => Self::Completed,
            "failed" => Self::Failed,
            "cancelled" | "canceled" => Self::Cancelled,
            "budget_exceeded" => Self::BudgetExceeded,
            _ => Self::Unknown(status),
        }
    }
}

/// Result of installing or updating a Skill package.
#[cfg(feature = "full")]
#[derive(Debug, Clone)]
pub struct SkillInstallResult {
    pub message: String,
    pub warnings: Vec<String>,
    pub skills: SkillCatalog,
}

/// Result of recoverably removing a Skill package.
#[cfg(feature = "full")]
#[derive(Debug, Clone)]
pub struct SkillRemovalResult {
    pub archived_at: PathBuf,
    pub skills: SkillCatalog,
}

impl SkillCatalog {
    pub fn new(skills: impl IntoIterator<Item = SkillSummary>) -> Self {
        Self {
            skills: skills.into_iter().collect(),
        }
    }

    pub fn all(&self) -> &[SkillSummary] {
        &self.skills
    }

    pub fn available(&self) -> impl Iterator<Item = &SkillSummary> {
        self.skills.iter().filter(|skill| skill.available)
    }

    pub fn find(&self, name: &str) -> Option<&SkillSummary> {
        self.skills.iter().find(|skill| skill.name == name)
    }
}

#[cfg(feature = "full")]
fn skill_catalog(skills: Vec<microclaw_engine::skills::SkillAvailability>) -> SkillCatalog {
    SkillCatalog::new(skills.into_iter().map(|skill| {
        let enabled = skill.reason.as_deref() != Some("Skill is disabled for this runtime.");
        SkillSummary {
            name: skill.meta.name,
            description: skill.meta.description,
            source: skill.meta.source,
            version: skill.meta.version,
            enabled,
            available: skill.available,
            unavailable_reason: skill.reason,
        }
    }))
}

/// A configured, embeddable MicroClaw runtime.
#[derive(Clone)]
pub struct MicroClaw {
    runtime: Runtime,
    skills: Arc<RwLock<SkillCatalog>>,
    #[cfg(feature = "full")]
    engine: Option<microclaw_engine::headless::HeadlessRuntime>,
    /// Caller channel of the engine runtime (policy and override scope).
    #[cfg(feature = "full")]
    caller_channel: String,
}

impl MicroClaw {
    /// Wrap an application-provided Runtime. This is the main entry point for `minimal` and
    /// `standard` consumers that implement their own [`RunExecutor`].
    pub fn from_runtime(runtime: Runtime) -> Self {
        Self {
            runtime,
            skills: Arc::new(RwLock::new(SkillCatalog::default())),
            #[cfg(feature = "full")]
            engine: None,
            #[cfg(feature = "full")]
            caller_channel: String::new(),
        }
    }

    /// Attach a host-provided Skill catalog to a custom Runtime.
    pub fn with_skill_catalog(mut self, skills: SkillCatalog) -> Self {
        self.skills = Arc::new(RwLock::new(skills));
        self
    }

    /// Start configuring a full Agent Engine from a MicroClaw YAML file.
    #[cfg(feature = "full")]
    pub fn builder(config_path: impl Into<PathBuf>) -> MicroClawBuilder {
        MicroClawBuilder::from_config_file(config_path)
    }

    /// Start configuring a full Agent Engine using MicroClaw's normal configuration discovery.
    #[cfg(feature = "full")]
    pub fn builder_from_environment() -> MicroClawBuilder {
        MicroClawBuilder::from_environment()
    }

    /// Configure an embedded Agent Engine entirely in Rust, without a Server YAML file.
    #[cfg(feature = "full")]
    pub fn configure(config: FullRuntimeConfig) -> MicroClawBuilder {
        MicroClawBuilder::from_runtime_config(config)
    }

    pub fn runtime(&self) -> &Runtime {
        &self.runtime
    }

    pub fn skills(&self) -> SkillCatalog {
        self.skills
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }

    /// Reload Skills from disk and return the current catalog.
    #[cfg(feature = "full")]
    pub fn reload_skills(&self) -> Result<SkillCatalog, SdkError> {
        let engine = self.engine.as_ref().ok_or_else(|| {
            SdkError::SkillManagement("this Runtime has no configured Agent Engine".into())
        })?;
        let catalog = skill_catalog(engine.reload_skill_catalog(true));
        *self
            .skills
            .write()
            .unwrap_or_else(|error| error.into_inner()) = catalog.clone();
        Ok(catalog)
    }

    /// Enable or disable one installed Skill for this Runtime.
    #[cfg(feature = "full")]
    pub fn set_skill_enabled(
        &self,
        name: impl AsRef<str>,
        enabled: bool,
    ) -> Result<SkillCatalog, SdkError> {
        let engine = self.engine.as_ref().ok_or_else(|| {
            SdkError::SkillManagement("this Runtime has no configured Agent Engine".into())
        })?;
        engine
            .set_skill_enabled(name.as_ref(), enabled)
            .map_err(SdkError::SkillManagement)?;
        self.reload_skills()
    }

    /// Install or update a local, GitHub, or ClawHub Skill and refresh the catalog.
    #[cfg(feature = "full")]
    pub async fn install_skill(
        &self,
        reference: impl AsRef<str>,
    ) -> Result<SkillInstallResult, SdkError> {
        let engine = self.engine.as_ref().ok_or_else(|| {
            SdkError::SkillManagement("this Runtime has no configured Agent Engine".into())
        })?;
        let outcome = engine
            .install_skill(reference.as_ref())
            .await
            .map_err(SdkError::SkillManagement)?;
        Ok(SkillInstallResult {
            message: outcome.message,
            warnings: outcome.warnings,
            skills: self.reload_skills()?,
        })
    }

    /// Import a Skill from a local directory containing `SKILL.md`.
    #[cfg(feature = "full")]
    pub async fn install_local_skill(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<SkillInstallResult, SdkError> {
        let reference = path.as_ref().to_string_lossy().into_owned();
        self.install_skill(reference).await
    }

    /// Recoverably remove one Skill by moving it into the managed archive directory.
    #[cfg(feature = "full")]
    pub fn remove_skill(&self, name: impl AsRef<str>) -> Result<SkillRemovalResult, SdkError> {
        let engine = self.engine.as_ref().ok_or_else(|| {
            SdkError::SkillManagement("this Runtime has no configured Agent Engine".into())
        })?;
        let archived_at = engine
            .archive_skill(name.as_ref())
            .map_err(SdkError::SkillManagement)?;
        Ok(SkillRemovalResult {
            archived_at,
            skills: self.reload_skills()?,
        })
    }

    /// List Subagent tasks delegated by the Main Agent in one session.
    #[cfg(feature = "full")]
    pub fn delegated_tasks(
        &self,
        session: impl AsRef<str>,
        limit: usize,
    ) -> Result<Vec<DelegatedTask>, SdkError> {
        let engine = self.engine.as_ref().ok_or_else(|| {
            SdkError::Runtime("this Runtime has no configured Agent Engine".into())
        })?;
        engine
            .subagent_runs(session.as_ref(), limit)
            .map(|runs| {
                runs.into_iter()
                    .map(|run| DelegatedTask {
                        run_id: run.run_id,
                        parent_run_id: run.parent_run_id,
                        depth: run.depth,
                        label: run.label,
                        task: run.task,
                        status: run.status.into(),
                        progress: run.progress,
                        result: run.result,
                        error: run.error,
                        created_at: run.created_at,
                        started_at: run.started_at,
                        finished_at: run.finished_at,
                        cancel_requested: run.cancel_requested,
                    })
                    .collect()
            })
            .map_err(|error| SdkError::Runtime(error.to_string()))
    }

    /// The most recent `limit` messages of a named session, oldest first:
    /// user prompts (including steering) and the agent's final replies. Use
    /// it to show history when resuming a session. Empty when the session
    /// never ran.
    #[cfg(feature = "full")]
    pub fn session_messages(
        &self,
        session: impl AsRef<str>,
        limit: usize,
    ) -> Result<Vec<SessionMessage>, SdkError> {
        let engine = self.engine.as_ref().ok_or_else(|| {
            SdkError::Runtime("this Runtime has no configured Agent Engine".into())
        })?;
        engine
            .session_messages(session.as_ref(), limit)
            .map(|messages| {
                messages
                    .into_iter()
                    .map(|message| SessionMessage {
                        role: if message.from_agent {
                            SessionMessageRole::Agent
                        } else {
                            SessionMessageRole::User
                        },
                        content: message.content,
                        timestamp: message.timestamp,
                    })
                    .collect()
            })
            .map_err(|error| SdkError::Runtime(error.to_string()))
    }

    #[cfg(feature = "full")]
    fn engine(&self) -> Result<&microclaw_engine::headless::HeadlessRuntime, SdkError> {
        self.engine
            .as_ref()
            .ok_or_else(|| SdkError::Runtime("this Runtime has no configured Agent Engine".into()))
    }

    /// Snapshot the session's workspace now (requires a `workspace`) and
    /// return the checkpoint holding its current state.
    #[cfg(feature = "full")]
    pub async fn checkpoint(
        &self,
        session: impl AsRef<str>,
        label: impl AsRef<str>,
    ) -> Result<Option<Checkpoint>, SdkError> {
        self.engine()?
            .checkpoint_session(&self.caller_channel, session.as_ref(), label.as_ref())
            .await
            .map(|c| c.map(Checkpoint::from))
            .map_err(|error| SdkError::Runtime(error.to_string()))
    }

    /// Recent workspace checkpoints of a session, newest first.
    #[cfg(feature = "full")]
    pub async fn checkpoints(
        &self,
        session: impl AsRef<str>,
        limit: usize,
    ) -> Result<Vec<Checkpoint>, SdkError> {
        self.engine()?
            .session_checkpoints(&self.caller_channel, session.as_ref(), limit)
            .await
            .map(|list| list.into_iter().map(Checkpoint::from).collect())
            .map_err(|error| SdkError::Runtime(error.to_string()))
    }

    /// Restore the workspace to a checkpoint. The current state is
    /// checkpointed first and returned, so the restore can be undone.
    #[cfg(feature = "full")]
    pub async fn restore_checkpoint(
        &self,
        session: impl AsRef<str>,
        commit: impl AsRef<str>,
    ) -> Result<Option<Checkpoint>, SdkError> {
        self.engine()?
            .restore_session_checkpoint(&self.caller_channel, session.as_ref(), commit.as_ref())
            .await
            .map(|c| c.map(Checkpoint::from))
            .map_err(|error| SdkError::Runtime(error.to_string()))
    }

    /// Token usage recorded for a session.
    #[cfg(feature = "full")]
    pub async fn session_usage(&self, session: impl AsRef<str>) -> Result<SessionUsage, SdkError> {
        self.engine()?
            .session_usage(session.as_ref())
            .await
            .map(|usage| SessionUsage {
                requests: usage.requests,
                input_tokens: usage.input_tokens,
                output_tokens: usage.output_tokens,
                by_model: usage
                    .by_model
                    .into_iter()
                    .map(
                        |(model, requests, input_tokens, output_tokens)| ModelUsage {
                            model,
                            requests,
                            input_tokens,
                            output_tokens,
                        },
                    )
                    .collect(),
            })
            .map_err(|error| SdkError::Runtime(error.to_string()))
    }

    /// The model the next run of a session uses.
    #[cfg(feature = "full")]
    pub async fn session_model(&self, session: impl AsRef<str>) -> Result<String, SdkError> {
        self.engine()?
            .session_model(&self.caller_channel, session.as_ref())
            .await
            .map_err(|error| SdkError::Runtime(error.to_string()))
    }

    /// Use another model for one session (`None` returns to the configured
    /// one). Lives as long as this runtime. Returns the effective model.
    #[cfg(feature = "full")]
    pub async fn set_session_model(
        &self,
        session: impl AsRef<str>,
        model: Option<&str>,
    ) -> Result<String, SdkError> {
        self.engine()?
            .set_session_model(&self.caller_channel, session.as_ref(), model)
            .await
            .map_err(|error| SdkError::Runtime(error.to_string()))
    }

    /// Summarize a session's older messages now, keeping the last
    /// `keep_recent` verbatim. Returns `(messages_before, messages_after)`.
    #[cfg(feature = "full")]
    pub async fn compact_session(
        &self,
        session: impl AsRef<str>,
        keep_recent: usize,
    ) -> Result<(usize, usize), SdkError> {
        self.compact_session_with(session, keep_recent, None)
            .await
            .map(|c| (c.messages_before, c.messages_after))
    }

    /// Summarize a session's older messages now; `focus` tells the
    /// summarizer what to keep (for example "the parser refactor").
    #[cfg(feature = "full")]
    pub async fn compact_session_with(
        &self,
        session: impl AsRef<str>,
        keep_recent: usize,
        focus: Option<&str>,
    ) -> Result<SessionCompaction, SdkError> {
        self.engine()?
            .compact_session(&self.caller_channel, session.as_ref(), keep_recent, focus)
            .await
            .map(|c| SessionCompaction {
                messages_before: c.messages_before,
                messages_after: c.messages_after,
                tokens_before: c.tokens_before,
                tokens_after: c.tokens_after,
                method: c.method,
            })
            .map_err(|error| SdkError::Runtime(error.to_string()))
    }

    /// How full a session's context is.
    #[cfg(feature = "full")]
    pub async fn context_usage(&self, session: impl AsRef<str>) -> Result<ContextUsage, SdkError> {
        self.engine()?
            .context_usage(&self.caller_channel, session.as_ref())
            .await
            .map(|u| ContextUsage {
                used_tokens: u.used(),
                model: u.model,
                window: u.window,
                reserved_output: u.reserved_output,
                auto_compact_threshold: u.auto_compact_threshold,
                last_request_tokens: u.last_request_tokens,
                summary_tokens: u.conversation.summary,
                user_tokens: u.conversation.user_text,
                assistant_tokens: u.conversation.assistant_text,
                tool_call_tokens: u.conversation.tool_calls,
                tool_result_tokens: u.conversation.tool_results,
                image_tokens: u.conversation.images,
                messages: u.conversation.messages,
            })
            .map_err(|error| SdkError::Runtime(error.to_string()))
    }

    /// Copy a session's conversation into a new session `to`.
    #[cfg(feature = "full")]
    pub async fn fork_session(
        &self,
        from: impl AsRef<str>,
        to: impl AsRef<str>,
    ) -> Result<(), SdkError> {
        self.engine()?
            .fork_session(from.as_ref(), to.as_ref())
            .await
            .map_err(|error| SdkError::Runtime(error.to_string()))
    }

    /// Cancel one active Subagent task owned by the named session.
    #[cfg(feature = "full")]
    pub fn cancel_delegated_task(
        &self,
        session: impl AsRef<str>,
        run_id: impl AsRef<str>,
    ) -> Result<bool, SdkError> {
        let engine = self.engine.as_ref().ok_or_else(|| {
            SdkError::Runtime("this Runtime has no configured Agent Engine".into())
        })?;
        engine
            .cancel_subagent(session.as_ref(), run_id.as_ref())
            .map_err(|error| SdkError::Runtime(error.to_string()))
    }

    pub fn agent(&self, name: impl Into<String>) -> AgentBuilder<'_> {
        AgentBuilder {
            microclaw: self,
            profile: AgentProfile {
                name: name.into(),
                ..AgentProfile::default()
            },
        }
    }
}

/// A model provider the Agent Engine can be configured for, with its default
/// endpoint and suggested models (used by setup flows).
#[cfg(feature = "full")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelProvider {
    pub id: &'static str,
    pub label: &'static str,
    pub default_base_url: &'static str,
    pub models: &'static [&'static str],
}

/// The model providers known to this Agent Engine.
#[cfg(feature = "full")]
pub fn model_providers() -> Vec<ModelProvider> {
    microclaw_engine::setup::provider_catalog()
        .map(|entry| ModelProvider {
            id: entry.id,
            label: entry.label,
            default_base_url: entry.default_base_url,
            models: entry.models,
        })
        .collect()
}

/// Validate a MicroClaw configuration file for a channel-free embedded
/// runtime without starting the Agent Engine.
#[cfg(feature = "full")]
pub fn validate_config_file(path: impl AsRef<Path>) -> Result<(), SdkError> {
    microclaw_engine::config::Config::load_from_path_for_headless(path.as_ref())
        .map(|_| ())
        .map_err(|error| SdkError::Configuration(error.to_string()))
}

/// How shell commands are confined (see `MicroClawBuilder::shell_sandbox`).
#[cfg(feature = "full")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellSandbox {
    /// Run commands directly on the host.
    Off,
    /// Commands may read the machine (except credential directories such as
    /// `~/.ssh`, `~/.aws`, `~/.microclaw`) but write only the workspace, the
    /// temp directory, common tool caches and `writable_roots`.
    WorkspaceWrite {
        network: bool,
        writable_roots: Vec<PathBuf>,
    },
}

/// The OS sandbox available on this machine: `"bubblewrap"` (Linux) or
/// `"seatbelt"` (macOS), or `None`.
#[cfg(feature = "full")]
pub fn local_sandbox() -> Option<&'static str> {
    microclaw_engine::tool_runtime::local_sandbox::detect().map(|kind| kind.name())
}

/// Context settings for a coding workspace, applied where the configuration
/// still has the chat-oriented defaults: compaction by tokens instead of
/// message count, a larger verbatim tail, and whole source files in tool
/// results (old outputs are pruned instead of truncated up front).
#[cfg(feature = "full")]
fn apply_workspace_context_defaults(config: &mut microclaw_engine::config::Config) {
    if config.max_session_messages == 40 {
        config.max_session_messages = 0;
    }
    if config.compact_keep_recent_tokens == 0 {
        config.compact_keep_recent_tokens = 24_000;
    }
    if config.tool_result_truncation_threshold_chars == 4_000 {
        config.tool_result_truncation_threshold_chars = 60_000;
        config.tool_result_truncation_head_chars = 40_000;
        config.tool_result_truncation_tail_chars = 10_000;
    }
}

/// Minimal provider configuration for a full embedded Agent Engine.
#[cfg(feature = "full")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullRuntimeConfig {
    pub provider: String,
    pub model: String,
    pub api_key: String,
    pub base_url: Option<String>,
}

#[cfg(feature = "full")]
impl FullRuntimeConfig {
    pub fn new(
        provider: impl Into<String>,
        model: impl Into<String>,
        api_key: impl Into<String>,
    ) -> Self {
        Self {
            provider: provider.into(),
            model: model.into(),
            api_key: api_key.into(),
            base_url: None,
        }
    }

    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = Some(url.into());
        self
    }
}

/// Builder for the configured Agent Engine exposed by the `full` SDK preset.
#[cfg(feature = "full")]
pub struct MicroClawBuilder {
    config_path: Option<PathBuf>,
    runtime_config: Option<FullRuntimeConfig>,
    data_dir: Option<PathBuf>,
    skills_dir: Option<PathBuf>,
    workspace: Option<PathBuf>,
    caller_channel: String,
    max_concurrent_runs: usize,
    shell_sandbox: Option<ShellSandbox>,
    command_reviewer: Option<Option<String>>,
    compact_instructions: Option<String>,
    context_window: Option<usize>,
}

#[cfg(feature = "full")]
impl MicroClawBuilder {
    pub fn from_config_file(path: impl Into<PathBuf>) -> Self {
        Self {
            config_path: Some(path.into()),
            runtime_config: None,
            data_dir: None,
            skills_dir: None,
            workspace: None,
            caller_channel: "embedded-app".into(),
            max_concurrent_runs: 4,
            shell_sandbox: None,
            command_reviewer: None,
            compact_instructions: None,
            context_window: None,
        }
    }

    pub fn from_environment() -> Self {
        Self {
            config_path: None,
            runtime_config: None,
            data_dir: None,
            skills_dir: None,
            workspace: None,
            caller_channel: "embedded-app".into(),
            max_concurrent_runs: 4,
            shell_sandbox: None,
            command_reviewer: None,
            compact_instructions: None,
            context_window: None,
        }
    }

    pub fn from_runtime_config(config: FullRuntimeConfig) -> Self {
        Self {
            config_path: None,
            runtime_config: Some(config),
            data_dir: None,
            skills_dir: None,
            workspace: None,
            caller_channel: "embedded-app".into(),
            max_concurrent_runs: 4,
            shell_sandbox: None,
            command_reviewer: None,
            compact_instructions: None,
            context_window: None,
        }
    }

    pub fn data_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.data_dir = Some(path.into());
        self
    }

    pub fn skills_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.skills_dir = Some(path.into());
        self
    }

    /// Select the direct working directory for an embedded foreground Agent.
    ///
    /// This enables checkpoints and keeps file tools rooted in the selected workspace.
    pub fn workspace(mut self, path: impl Into<PathBuf>) -> Self {
        self.workspace = Some(path.into());
        self
    }

    pub fn caller_channel(mut self, channel: impl Into<String>) -> Self {
        self.caller_channel = channel.into();
        self
    }

    pub fn max_concurrent_runs(mut self, max: usize) -> Self {
        self.max_concurrent_runs = max;
        self
    }

    /// Run shell commands under the operating system's sandbox (overrides
    /// the configuration's `sandbox` section). When this machine has no
    /// working OS sandbox (see [`local_sandbox`]) commands run unsandboxed.
    pub fn shell_sandbox(mut self, sandbox: ShellSandbox) -> Self {
        self.shell_sandbox = Some(sandbox);
        self
    }

    /// Have a model annotate every approval request with a one-line verdict
    /// (`SAFE` / `CAUTION` / `DANGEROUS …`, the `advisory` of
    /// `ApprovalRequired`). `None` uses the configured main model.
    pub fn command_reviewer(mut self, model: Option<String>) -> Self {
        self.command_reviewer = Some(model);
        self
    }

    /// Extra instructions for compaction summaries: what a summary of this
    /// workspace's sessions must keep.
    pub fn compact_instructions(mut self, instructions: Option<String>) -> Self {
        self.compact_instructions = instructions.filter(|i| !i.trim().is_empty());
        self
    }

    /// Treat the model's context window as this many tokens (overrides the
    /// configured and built-in sizes; `None` keeps them).
    pub fn context_window(mut self, tokens: Option<usize>) -> Self {
        self.context_window = tokens.filter(|t| *t > 0);
        self
    }

    pub async fn build(self) -> Result<MicroClaw, SdkError> {
        use microclaw_engine::config::Config;
        use microclaw_engine::headless::HeadlessRuntime;

        let mut config = match (self.runtime_config, self.config_path) {
            (Some(config), _) => Config::for_embedded(
                config.provider,
                config.model,
                config.api_key,
                config.base_url,
            ),
            (None, Some(path)) => Config::load_from_path_for_headless(Path::new(&path)),
            (None, None) => Config::load(),
        }
        .map_err(|error| SdkError::Configuration(error.to_string()))?;
        if let Some(path) = self.data_dir {
            config.data_dir = path.to_string_lossy().into_owned();
        }
        if let Some(path) = self.skills_dir {
            config.skills_dir = Some(path.to_string_lossy().into_owned());
        }
        if let Some(path) = self.workspace {
            config.working_dir = path.to_string_lossy().into_owned();
            config.working_dir_isolation = microclaw_engine::config::WorkingDirIsolation::Direct;
            config.checkpoints_enabled = true;
            apply_workspace_context_defaults(&mut config);
        }
        if self.compact_instructions.is_some() {
            config.compact_instructions = self.compact_instructions;
        }
        if let Some(window) = self.context_window {
            config.model_context_window = window;
            let model = config.model.clone();
            config.model_context_windows.insert(model, window);
        }
        if let Some(model) = self.command_reviewer {
            config.aux_models.approval_reviewer = Some(
                model
                    .filter(|m| !m.trim().is_empty())
                    .unwrap_or_else(|| config.model.clone()),
            );
        }
        match self.shell_sandbox {
            Some(ShellSandbox::Off) => {
                config.sandbox.mode = microclaw_engine::config::SandboxMode::Off;
            }
            Some(ShellSandbox::WorkspaceWrite {
                network,
                writable_roots,
            }) if local_sandbox().is_some() => {
                config.sandbox.mode = microclaw_engine::config::SandboxMode::All;
                config.sandbox.backend = microclaw_engine::config::SandboxBackend::Local;
                config.sandbox.no_network = !network;
                config.sandbox.require_runtime = false;
                config.sandbox.writable_roots = writable_roots
                    .into_iter()
                    .map(|p| p.to_string_lossy().into_owned())
                    .collect();
            }
            Some(ShellSandbox::WorkspaceWrite { .. }) => {
                config.sandbox.mode = microclaw_engine::config::SandboxMode::Off;
            }
            None => {}
        }
        let engine = HeadlessRuntime::load(config)
            .await
            .map_err(|error| SdkError::Initialization(error.to_string()))?;
        let skills = skill_catalog(engine.skill_catalog(true));
        let runtime = engine
            .clone()
            .into_embedded_runtime(self.caller_channel.clone(), self.max_concurrent_runs)?;
        Ok(MicroClaw {
            runtime,
            skills: Arc::new(RwLock::new(skills)),
            engine: Some(engine),
            caller_channel: self.caller_channel,
        })
    }
}

/// Builder for an Agent identity and its selected Skills.
pub struct AgentBuilder<'a> {
    microclaw: &'a MicroClaw,
    profile: AgentProfile,
}

impl AgentBuilder<'_> {
    pub fn id(mut self, id: impl Into<AgentId>) -> Self {
        self.profile.id = Some(id.into());
        self
    }

    pub fn system_prompt(mut self, prompt: impl Into<String>) -> Self {
        self.profile.system_prompt = Some(prompt.into());
        self
    }

    pub fn skill(mut self, name: impl Into<String>) -> Self {
        self.profile.skills.push(name.into());
        self
    }

    pub fn skills<I, S>(mut self, names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.profile
            .skills
            .extend(names.into_iter().map(Into::into));
        self
    }

    pub fn tool_policy(mut self, policy: ToolPolicy) -> Self {
        self.profile.tool_policy = policy;
        self
    }

    pub fn metadata(mut self, key: impl Into<String>, value: Value) -> Self {
        self.profile.metadata.insert(key.into(), value);
        self
    }

    pub fn build(mut self) -> Result<Agent, SdkError> {
        self.profile.name = self.profile.name.trim().to_owned();
        if self.profile.name.is_empty() {
            return Err(SdkError::EmptyAgentName);
        }
        self.profile.skills.sort();
        self.profile.skills.dedup();
        for name in &self.profile.skills {
            let available = self
                .microclaw
                .skills()
                .find(name)
                .is_some_and(|skill| skill.available);
            if !available {
                return Err(SdkError::SkillUnavailable(name.clone()));
            }
        }
        Ok(Agent {
            handle: self.microclaw.runtime.agent(self.profile),
        })
    }
}

/// A reusable Agent handle with a fixed identity, prompt, Skills, and tool policy.
#[derive(Clone)]
pub struct Agent {
    handle: AgentHandle,
}

impl Agent {
    pub fn profile(&self) -> &AgentProfile {
        self.handle.profile()
    }

    pub fn run(&self, prompt: impl Into<String>) -> RunHandle {
        self.handle.run(RunRequest::new(prompt))
    }

    pub fn run_request(&self, request: RunRequest) -> RunHandle {
        self.handle.run(request)
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;

    use super::*;
    use crate::RuntimeError;

    struct Echo;

    #[async_trait]
    impl RunExecutor for Echo {
        async fn execute(
            &self,
            _profile: AgentProfile,
            request: RunRequest,
            _context: ExecutionContext,
        ) -> Result<ExecutionResult, RuntimeError> {
            Ok(ExecutionResult::new("sdk-test", request.prompt))
        }
    }

    fn test_sdk(skills: Vec<SkillSummary>) -> MicroClaw {
        MicroClaw::from_runtime(Runtime::builder().executor(Echo).build().unwrap())
            .with_skill_catalog(SkillCatalog::new(skills))
    }

    #[tokio::test]
    async fn agent_builder_creates_a_reusable_agent() {
        let sdk = test_sdk(vec![SkillSummary {
            name: "review".into(),
            description: "Review code".into(),
            source: "test".into(),
            version: Some("1".into()),
            enabled: true,
            available: true,
            unavailable_reason: None,
        }]);
        let agent = sdk
            .agent(" reviewer ")
            .id("agent-1")
            .skill("review")
            .skill("review")
            .build()
            .unwrap();

        assert_eq!(agent.profile().name, "reviewer");
        assert_eq!(agent.profile().skills, vec!["review"]);
        assert_eq!(
            agent.run("hello").result().await.unwrap().final_text,
            "hello"
        );
    }

    #[test]
    fn agent_builder_rejects_unknown_or_unavailable_skills() {
        let sdk = test_sdk(Vec::new());
        let error = match sdk.agent("reviewer").skill("missing").build() {
            Ok(_) => panic!("unknown Skill should be rejected"),
            Err(error) => error,
        };
        assert!(matches!(error, SdkError::SkillUnavailable(name) if name == "missing"));
    }

    #[test]
    fn sdk_errors_have_stable_codes() {
        let error = SdkError::EmptyAgentName;
        assert_eq!(error.code(), SdkErrorCode::InvalidAgent);
        assert!(!error.retryable());
    }

    #[test]
    fn delegated_task_status_is_typed_and_forward_compatible() {
        assert!(DelegatedTaskStatus::from("completed".to_string()).is_terminal());
        assert!(!DelegatedTaskStatus::from("running".to_string()).is_terminal());
        assert_eq!(
            DelegatedTaskStatus::from("future_state".to_string()).as_str(),
            "future_state"
        );
    }

    #[cfg(feature = "full")]
    #[tokio::test]
    async fn full_runtime_reloads_and_toggles_skills_without_restart() {
        let directory = tempfile::tempdir().unwrap();
        let skills_dir = directory.path().join("skills");
        let first = skills_dir.join("sdk-first");
        std::fs::create_dir_all(&first).unwrap();
        std::fs::write(
            first.join("SKILL.md"),
            "---\nname: sdk-first\ndescription: first SDK skill\n---\nUse the first skill.\n",
        )
        .unwrap();

        let sdk = MicroClaw::configure(FullRuntimeConfig::new("ollama", "local", ""))
            .data_dir(directory.path().join("data"))
            .skills_dir(&skills_dir)
            .build()
            .await
            .unwrap();
        assert!(sdk.skills().find("sdk-first").unwrap().enabled);

        let disabled = sdk.set_skill_enabled("sdk-first", false).unwrap();
        let first = disabled.find("sdk-first").unwrap();
        assert!(!first.enabled);
        assert!(!first.available);

        let second = directory.path().join("sdk-second");
        std::fs::create_dir_all(&second).unwrap();
        std::fs::write(
            second.join("SKILL.md"),
            "---\nname: sdk-second\ndescription: second SDK skill\n---\nUse the second skill.\n",
        )
        .unwrap();
        assert!(sdk.skills().find("sdk-second").is_none());
        let installed = sdk.install_local_skill(&second).await.unwrap();
        assert!(installed.skills.find("sdk-second").is_some());
        let removed = sdk.remove_skill("sdk-second").unwrap();
        assert!(removed.archived_at.join("SKILL.md").is_file());
        assert!(removed.skills.find("sdk-second").is_none());
    }

    #[cfg(feature = "full")]
    #[test]
    fn exposes_provider_catalog_and_config_validation() {
        let providers = model_providers();
        assert!(providers.iter().any(|p| p.id == "anthropic"));
        assert!(providers.iter().any(|p| p.id == "openai"));

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.yaml");
        std::fs::write(&path, "llm_provider: ollama\nmodel: local\napi_key: \"\"\n").unwrap();
        validate_config_file(&path).unwrap();
        std::fs::write(&path, "llm_provider: [not, a, string]\n").unwrap();
        assert_eq!(
            validate_config_file(&path).unwrap_err().code(),
            SdkErrorCode::Configuration
        );
    }
}
