//! Stable facade for embedding MicroClaw in Rust applications.
//!
//! Most applications should import contracts and runtime handles from this crate instead of
//! depending on MicroClaw's internal capability crates individually.

use serde_json::Value;

#[cfg(feature = "full")]
use std::path::{Path, PathBuf};

pub use microclaw_core::run_protocol::{
    validate_worker_protocol_version, AgentId, AgentProfile, CallerContext, RunId, RunRequest,
    RunResult, RunStatus, RuntimeCapabilities, RuntimeControl, RuntimeError, RuntimeErrorCode,
    SessionId, ToolPolicy, WorkerCommand, WorkerDescriptor, WorkerFrame, WorkerHealth,
    WorkerHealthStatus, WorkerId, WORKER_PROTOCOL_VERSION,
};
pub use microclaw_core::runtime_event::{
    RuntimeApprovalDecision, RuntimeApprovalOption, RuntimeApprovalOptionKind, RuntimeEvent,
    RuntimeEventEnvelope, RuntimePlanStep, RuntimePlanStepStatus, RuntimeProcessKind,
};
pub use microclaw_runtime::{
    AgentHandle, ControlRequest, ExecutionContext, ExecutionResult, LocalWorker, RemoteWorker,
    RunController, RunExecutor, RunHandle, Runtime, RuntimeBuildError, RuntimeBuilder,
    RuntimeStats, Worker, WorkerConnection, WorkerTransport,
};

/// An SDK-level error that does not expose Server or Agent Engine implementation types.
#[derive(Debug, thiserror::Error)]
pub enum SdkError {
    #[error("invalid SDK configuration: {0}")]
    Configuration(String),
    #[error("could not initialize the Agent Engine: {0}")]
    Initialization(String),
    #[error("could not build the runtime: {0}")]
    Runtime(#[from] RuntimeBuildError),
    #[error("agent name must not be empty")]
    EmptyAgentName,
    #[error("Skill '{0}' is not available in this runtime")]
    SkillUnavailable(String),
}

/// Stable, UI-neutral metadata for one discovered Skill.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillSummary {
    pub name: String,
    pub description: String,
    pub source: String,
    pub version: Option<String>,
    pub available: bool,
    pub unavailable_reason: Option<String>,
}

/// A snapshot of Skills discovered while the SDK runtime was initialized.
#[derive(Debug, Clone, Default)]
pub struct SkillCatalog {
    skills: Vec<SkillSummary>,
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

/// A configured, embeddable MicroClaw runtime.
#[derive(Clone)]
pub struct MicroClaw {
    runtime: Runtime,
    skills: SkillCatalog,
}

impl MicroClaw {
    /// Wrap an application-provided Runtime. This is the main entry point for `minimal` and
    /// `standard` consumers that implement their own [`RunExecutor`].
    pub fn from_runtime(runtime: Runtime) -> Self {
        Self {
            runtime,
            skills: SkillCatalog::default(),
        }
    }

    /// Attach a host-provided Skill catalog to a custom Runtime.
    pub fn with_skill_catalog(mut self, skills: SkillCatalog) -> Self {
        self.skills = skills;
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

    pub fn runtime(&self) -> &Runtime {
        &self.runtime
    }

    pub fn skills(&self) -> &SkillCatalog {
        &self.skills
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

/// Builder for the configured Agent Engine exposed by the `full` SDK preset.
#[cfg(feature = "full")]
pub struct MicroClawBuilder {
    config_path: Option<PathBuf>,
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

        let mut config = match self.config_path {
            Some(path) => Config::load_from_path_for_headless(Path::new(&path)),
            None => Config::load(),
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
        let skills =
            SkillCatalog::new(
                engine
                    .skill_catalog(true)
                    .into_iter()
                    .map(|skill| SkillSummary {
                        name: skill.meta.name,
                        description: skill.meta.description,
                        source: skill.meta.source,
                        version: skill.meta.version,
                        available: skill.available,
                        unavailable_reason: skill.reason,
                    }),
            );
        let runtime =
            engine.into_embedded_runtime(self.caller_channel, self.max_concurrent_runs)?;
        Ok(MicroClaw { runtime, skills })
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
                .skills
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

/// Lower-level contracts for applications that need the complete foundational API.
pub mod core {
    pub use microclaw_core::*;
}

/// Transitional access to Agent Engine internals for first-party consumers.
///
/// Third-party applications should use [`MicroClaw`] and the stable types at this crate root.
#[doc(hidden)]
#[cfg(feature = "full")]
pub mod engine {
    pub use microclaw_engine::*;
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;

    use super::*;

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
}
