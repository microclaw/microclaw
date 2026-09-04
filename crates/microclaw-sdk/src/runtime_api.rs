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
    pub status: String,
    pub progress: Option<String>,
    pub result: Option<String>,
    pub error: Option<String>,
    pub created_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub cancel_requested: bool,
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
                        status: run.status,
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
        }
        let engine = HeadlessRuntime::load(config)
            .await
            .map_err(|error| SdkError::Initialization(error.to_string()))?;
        let skills = skill_catalog(engine.skill_catalog(true));
        let runtime = engine
            .clone()
            .into_embedded_runtime(self.caller_channel, self.max_concurrent_runs)?;
        Ok(MicroClaw {
            runtime,
            skills: Arc::new(RwLock::new(skills)),
            engine: Some(engine),
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
}
