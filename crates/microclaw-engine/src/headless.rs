//! Headless one-shot mode: `microclaw run -p "<prompt>"`.
//!
//! Runs a single prompt through the shared agent loop without starting any
//! channel, prints the final reply to stdout, and exits non-zero on failure
//! — the scripting/CI entry point (grok-build's headless mode equivalent).
//! Runs share the `headless` channel; `--session <name>` selects a named
//! chat so consecutive runs can keep conversation context.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use tokio::sync::{mpsc, RwLock};

use crate::agent_engine::{
    process_with_agent_profile_guarded_mode, AgentEvent, AgentRequestContext,
};
use crate::chat_turn_queue::PendingMessage;
use crate::config::Config;
use crate::hooks::HookManager;
use crate::internal::channels::channel_adapter::ChannelRegistry;
use crate::internal::runtime::{ExecutionContext, ExecutionResult, RunExecutor};
use crate::internal::storage::db::{call_blocking, Database, StoredMessage};
use crate::memory::MemoryManager;
use crate::memory_backend::{MemoryBackend, MemoryMcpClient};
use crate::runtime::AppState;
use crate::skill_management::{archive_skill, install_skill, SkillInstallOutcome};
use crate::skills::{SkillAvailability, SkillManager};
use crate::tools::ToolRegistry;
use crate::{embedding, llm};
use microclaw_core::run_protocol::{
    AgentProfile, RunRequest, RuntimeCapabilities, RuntimeControl, RuntimeError, RuntimeErrorCode,
    SessionId,
};
use microclaw_core::runtime_event::RuntimeEventEnvelope;

pub const HEADLESS_CHANNEL: &str = "headless";
pub const WORK_CHANNEL: &str = "work";

#[derive(Debug, Clone)]
pub struct HeadlessRunRequest {
    pub prompt: String,
    pub session: Option<String>,
    pub sender_name: String,
    pub run_id: Option<String>,
    pub caller_channel: String,
}

impl HeadlessRunRequest {
    pub fn cli(prompt: String, session: Option<String>) -> Self {
        Self {
            prompt,
            session,
            sender_name: "cli".into(),
            run_id: None,
            caller_channel: HEADLESS_CHANNEL.into(),
        }
    }

    pub fn work(prompt: String, session: Option<String>, run_id: String) -> Self {
        Self {
            prompt,
            session,
            sender_name: "work".into(),
            run_id: Some(run_id),
            caller_channel: WORK_CHANNEL.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HeadlessRunResult {
    pub run_id: String,
    pub chat_id: i64,
    pub response: String,
}

/// UI-neutral projection of one durable Subagent run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadlessSubagentRun {
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

/// Reusable application service for one-shot tasks.
///
/// It owns the existing provider-neutral Agent Engine state but starts no
/// channel, Web server, or scheduler. Both the CLI and Work adapters call this
/// service instead of assembling or copying an Agent Loop.
#[derive(Clone)]
pub struct HeadlessRuntime {
    state: Arc<AppState>,
}

/// Adapter from the existing shared Agent Engine to the embeddable Runtime contract.
///
/// This is intentionally channel-free: the caller selects the logical channel used for policy,
/// persistence, cancellation, and steering. Product UIs consume `microclaw-engine` rather than
/// calling the Agent Engine directly.
pub struct HeadlessRunExecutor {
    runtime: HeadlessRuntime,
    caller_channel: String,
}

impl HeadlessRunExecutor {
    pub fn new(runtime: HeadlessRuntime, caller_channel: impl Into<String>) -> Self {
        Self {
            runtime,
            caller_channel: caller_channel.into(),
        }
    }
}

#[async_trait::async_trait]
impl RunExecutor for HeadlessRunExecutor {
    async fn execute(
        &self,
        profile: AgentProfile,
        request: RunRequest,
        mut context: ExecutionContext,
    ) -> Result<ExecutionResult, RuntimeError> {
        let session = request
            .session_id
            .clone()
            .unwrap_or_else(|| SessionId::new("default"));
        let (legacy_event_tx, mut legacy_event_rx) = mpsc::unbounded_channel();
        let run = self.runtime.run_with_profile(
            HeadlessRunRequest {
                prompt: request.prompt,
                session: Some(session.to_string()),
                sender_name: self.caller_channel.clone(),
                run_id: Some(context.run_id().to_string()),
                caller_channel: self.caller_channel.clone(),
            },
            profile,
            Some(legacy_event_tx),
        );
        tokio::pin!(run);

        let result = loop {
            tokio::select! {
                result = &mut run => break result,
                event = legacy_event_rx.recv() => {
                    if let Some(envelope) = event {
                        forward_runtime_event(&context, envelope.event)?;
                    }
                }
                control = context.next_control_request() => {
                    if let Some(control) = control {
                        match control.control().clone() {
                        RuntimeControl::Cancel { .. } => {
                            let cancelled = self.runtime
                                .cancel_session_for_channel(&self.caller_channel, session.as_str())
                                .await
                                .map_err(runtime_internal_error)?;
                            if cancelled > 0 {
                                control.accept();
                            } else {
                                control.reject(RuntimeError {
                                    code: RuntimeErrorCode::Unavailable,
                                    message: "the run finished before cancellation was accepted".into(),
                                    retryable: false,
                                });
                            }
                        }
                        RuntimeControl::Steer { message, .. } => {
                            let accepted = self.runtime
                                .steer_session_for_channel(
                                    &self.caller_channel,
                                    session.as_str(),
                                    &message,
                                )
                                .await
                                .map_err(runtime_internal_error)?;
                            if accepted {
                                control.accept();
                            } else {
                                control.reject(RuntimeError {
                                    code: RuntimeErrorCode::Unavailable,
                                    message: "the run finished before the update could be queued".into(),
                                    retryable: false,
                                });
                            }
                        }
                        RuntimeControl::ResolveApproval { .. } => {
                            control.reject(RuntimeError {
                                code: RuntimeErrorCode::Unavailable,
                                message: "the current Agent Engine approval bridge is unavailable"
                                    .into(),
                                retryable: false,
                            });
                        }
                        }
                    }
                }
            }
        }
        .map_err(runtime_internal_error)?;

        while let Ok(envelope) = legacy_event_rx.try_recv() {
            forward_runtime_event(&context, envelope.event)?;
        }

        let mut output = ExecutionResult::new(session, result.response);
        output.metadata.insert(
            "chat_id".into(),
            serde_json::Value::Number(result.chat_id.into()),
        );
        Ok(output)
    }

    fn capabilities(&self) -> RuntimeCapabilities {
        RuntimeCapabilities {
            streaming: true,
            cancellation: true,
            steering: true,
            approvals: false,
            skills: true,
            subagents: true,
            remote_workers: false,
        }
    }
}

fn forward_runtime_event(
    context: &ExecutionContext,
    event: microclaw_core::runtime_event::RuntimeEvent,
) -> Result<(), RuntimeError> {
    if matches!(
        event,
        microclaw_core::runtime_event::RuntimeEvent::FinalResponse { .. }
            | microclaw_core::runtime_event::RuntimeEvent::Cancelled { .. }
    ) {
        return Ok(());
    }
    context.emit(event)
}

fn runtime_internal_error(error: impl std::fmt::Display) -> RuntimeError {
    RuntimeError {
        code: RuntimeErrorCode::Internal,
        message: error.to_string(),
        retryable: false,
    }
}

impl HeadlessRuntime {
    /// Return the Skills visible to this runtime, including availability diagnostics when
    /// requested. Embedding facades use this to present a catalog without exposing runtime state.
    pub fn skill_catalog(&self, include_unavailable: bool) -> Vec<SkillAvailability> {
        self.state
            .skills
            .discover_skills_with_status(include_unavailable)
    }

    /// Invalidate cached integrity verdicts and rebuild the runtime's Skill catalog.
    pub fn reload_skill_catalog(&self, include_unavailable: bool) -> Vec<SkillAvailability> {
        self.state.skills.reload();
        self.skill_catalog(include_unavailable)
    }

    /// Change runtime-scoped Skill enablement without rewriting the Skill package.
    pub fn set_skill_enabled(&self, name: &str, enabled: bool) -> Result<(), String> {
        self.state.skills.set_enabled(name, enabled)?;
        self.state.skills.reload();
        Ok(())
    }

    /// Install or update a Skill through the shared governed package path.
    pub async fn install_skill(&self, reference: &str) -> Result<SkillInstallOutcome, String> {
        install_skill(&self.state.config, &self.state.skills, reference).await
    }

    /// Recoverably remove a Skill and return its archive location.
    pub fn archive_skill(&self, name: &str) -> Result<std::path::PathBuf, String> {
        archive_skill(&self.state.skills, name)
    }

    /// List durable Subagent runs belonging to a named embedded session.
    pub fn subagent_runs(
        &self,
        session: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<HeadlessSubagentRun>> {
        let external_chat_id = format!("headless:{}", session.trim());
        let Some(chat_id) = self
            .state
            .db
            .find_chat_id(HEADLESS_CHANNEL, &external_chat_id)?
        else {
            return Ok(Vec::new());
        };
        Ok(self
            .state
            .db
            .list_subagent_runs(chat_id, limit.clamp(1, 1_000))?
            .into_iter()
            .map(|run| HeadlessSubagentRun {
                run_id: run.run_id,
                parent_run_id: run.parent_run_id,
                depth: run.depth.max(0) as u32,
                label: run.label,
                task: run.task,
                status: run.status,
                progress: run.progress_text,
                result: run.result_text,
                error: run.error_text,
                created_at: run.created_at,
                started_at: run.started_at,
                finished_at: run.finished_at,
                cancel_requested: run.cancel_requested,
            })
            .collect())
    }

    /// Persist and promptly signal cancellation for one Subagent owned by the session.
    pub fn cancel_subagent(&self, session: &str, run_id: &str) -> anyhow::Result<bool> {
        let external_chat_id = format!("headless:{}", session.trim());
        let Some(chat_id) = self
            .state
            .db
            .find_chat_id(HEADLESS_CHANNEL, &external_chat_id)?
        else {
            return Ok(false);
        };
        Ok(crate::tools::subagents::request_subagent_cancel(
            &self.state.config,
            &self.state.db,
            chat_id,
            run_id,
        )?)
    }

    /// Build a standalone runtime from a loaded product config.
    ///
    /// This is the Work/headless bootstrap path. It intentionally initializes
    /// no chat adapters, Web routes, scheduler, or gateway.
    pub async fn load(mut config: Config) -> anyhow::Result<Self> {
        let data_root = config.data_root_dir();
        let runtime_data_dir = config.runtime_data_dir();
        let skills_data_dir = config.skills_data_dir();
        crate::builtin_skills::ensure_builtin_skills(Path::new(&skills_data_dir))?;

        let db = Database::new(&runtime_data_dir)?;
        let memory = MemoryManager::new(&runtime_data_dir);
        let skills = SkillManager::from_skills_and_runtime(&skills_data_dir, &runtime_data_dir)
            .with_config_verification(&config);
        let mcp_manager = crate::mcp::McpManager::from_config_paths(
            &crate::mcp::collect_config_paths(&data_root),
            config.mcp_request_timeout_secs(),
        )
        .await;

        config.data_dir = runtime_data_dir;
        config.skills_dir = Some(skills_data_dir);
        Ok(Self::new(config, db, memory, skills, mcp_manager))
    }

    pub fn new(
        config: Config,
        db: Database,
        memory: MemoryManager,
        skills: SkillManager,
        mcp_manager: crate::mcp::McpManager,
    ) -> Self {
        let db = Arc::new(db);
        let llm = llm::create_provider(&config);
        let embedding = embedding::create_provider(&config);
        let channel_registry = Arc::new(ChannelRegistry::new());

        let memory_backend = Arc::new(MemoryBackend::new(
            db.clone(),
            MemoryMcpClient::discover(&mcp_manager),
            &config.data_dir,
        ));
        let mut tools = ToolRegistry::new(
            &config,
            channel_registry.clone(),
            db.clone(),
            memory_backend.clone(),
        );
        tools.register_mcp_tools(&mcp_manager);

        let chat_turn_queue = Arc::new(crate::chat_turn_queue::ChatTurnQueue::new(
            config.chat_turn_queue_max_pending,
        ));
        let (skill_review_queue, _skill_review_worker) =
            crate::skill_review::build_skill_review_channel();
        let state = Arc::new(AppState {
            config: config.clone(),
            channel_registry,
            db: db.clone(),
            memory: Arc::new(memory),
            skills: Arc::new(skills),
            hooks: Arc::new(HookManager::from_config(&config).with_db(db.clone())),
            llm: Arc::from(llm),
            llm_provider_overrides: Arc::new(RwLock::new(HashMap::new())),
            llm_model_overrides: Arc::new(RwLock::new(HashMap::new())),
            embedding,
            memory_backend,
            tools: Arc::new(tools),
            chat_turn_queue,
            skill_review_queue,
            metric_exporter: None,
            trace_exporter: None,
            log_exporter: None,
        });
        Self { state }
    }

    /// Build the public embeddable Runtime over this configured Agent Engine.
    pub fn into_embedded_runtime(
        self,
        caller_channel: impl Into<String>,
        max_concurrent_runs: usize,
    ) -> Result<crate::internal::runtime::Runtime, crate::internal::runtime::RuntimeBuildError>
    {
        crate::internal::runtime::Runtime::builder()
            .executor(HeadlessRunExecutor::new(self, caller_channel))
            .max_concurrent_runs(max_concurrent_runs)
            .build()
    }

    pub async fn run(
        &self,
        request: HeadlessRunRequest,
        event_tx: Option<mpsc::UnboundedSender<RuntimeEventEnvelope>>,
    ) -> anyhow::Result<HeadlessRunResult> {
        self.run_with_profile(request, AgentProfile::default(), event_tx)
            .await
    }

    pub async fn run_with_profile(
        &self,
        request: HeadlessRunRequest,
        profile: AgentProfile,
        event_tx: Option<mpsc::UnboundedSender<RuntimeEventEnvelope>>,
    ) -> anyhow::Result<HeadlessRunResult> {
        let session_name = request
            .session
            .clone()
            .unwrap_or_else(|| "default".to_string());
        let chat_id = self.resolve_session_chat_id(&session_name).await?;
        let caller_channel = request.caller_channel;

        let stored = StoredMessage {
            id: uuid::Uuid::new_v4().to_string(),
            chat_id,
            sender_name: request.sender_name,
            content: request.prompt,
            is_from_bot: false,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        let _ = call_blocking(self.state.db.clone(), move |db| db.store_message(&stored)).await;

        let run_id = request
            .run_id
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let (raw_event_tx, bridge) = match event_tx {
            Some(envelope_tx) => {
                let (raw_tx, raw_rx) = mpsc::unbounded_channel();
                let bridge = spawn_event_envelope_bridge(run_id.clone(), raw_rx, envelope_tx);
                (Some(raw_tx), Some(bridge))
            }
            None => (None, None),
        };
        let response = process_with_agent_profile_guarded_mode(
            &self.state,
            AgentRequestContext {
                caller_channel: &caller_channel,
                chat_id,
                chat_type: "private",
            },
            None,
            None,
            raw_event_tx.as_ref(),
            None,
            false,
            None,
            profile,
        )
        .await;
        drop(raw_event_tx);
        if let Some(bridge) = bridge {
            bridge.await?;
        }
        let response = response?;

        let bot_msg = StoredMessage {
            id: uuid::Uuid::new_v4().to_string(),
            chat_id,
            sender_name: "microclaw".to_string(),
            content: response.clone(),
            is_from_bot: true,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        let _ = call_blocking(self.state.db.clone(), move |db| db.store_message(&bot_msg)).await;

        Ok(HeadlessRunResult {
            run_id,
            chat_id,
            response,
        })
    }

    /// Cancel active work for a named headless session.
    ///
    /// This delegates to the same run-control registry used by chat, Web, and
    /// scheduler adapters, so callers stop the real Agent Engine rather than
    /// merely hiding its output.
    pub async fn cancel_session(&self, session: &str) -> anyhow::Result<usize> {
        self.cancel_session_for_channel(HEADLESS_CHANNEL, session)
            .await
    }

    pub async fn cancel_work_session(&self, session: &str) -> anyhow::Result<usize> {
        self.cancel_session_for_channel(WORK_CHANNEL, session).await
    }

    async fn cancel_session_for_channel(
        &self,
        channel: &str,
        session: &str,
    ) -> anyhow::Result<usize> {
        let chat_id = self.resolve_session_chat_id(session).await?;
        Ok(crate::run_control::abort_runs(channel, chat_id).await)
    }

    /// Add a user update to an active named session.
    ///
    /// The shared Agent Engine drains this queue at its normal tool/end-turn
    /// breakpoints. Returning `false` means the run ended before the update
    /// could be queued; callers must not report it as accepted.
    pub async fn steer_session(&self, session: &str, content: &str) -> anyhow::Result<bool> {
        self.steer_session_for_channel(HEADLESS_CHANNEL, session, content)
            .await
    }

    pub async fn steer_work_session(&self, session: &str, content: &str) -> anyhow::Result<bool> {
        self.steer_session_for_channel(WORK_CHANNEL, session, content)
            .await
    }

    async fn steer_session_for_channel(
        &self,
        channel: &str,
        session: &str,
        content: &str,
    ) -> anyhow::Result<bool> {
        let content = content.trim();
        if content.is_empty() {
            anyhow::bail!("steering update must not be empty");
        }
        let chat_id = self.resolve_session_chat_id(session).await?;
        let message_id = uuid::Uuid::new_v4().to_string();
        let timestamp = chrono::Utc::now().to_rfc3339();
        let pending = PendingMessage {
            sender_name: "work".into(),
            content: content.to_string(),
            message_id: message_id.clone(),
            timestamp: timestamp.clone(),
        };
        if !self
            .state
            .chat_turn_queue
            .enqueue_if_busy(channel, chat_id, pending)
            .await
        {
            return Ok(false);
        }

        let stored = StoredMessage {
            id: message_id,
            chat_id,
            sender_name: "work".into(),
            content: content.to_string(),
            is_from_bot: false,
            timestamp,
        };
        call_blocking(self.state.db.clone(), move |db| db.store_message(&stored)).await?;
        Ok(true)
    }

    async fn resolve_session_chat_id(&self, session: &str) -> anyhow::Result<i64> {
        let external_chat_id = format!("headless:{session}");
        let title = format!("headless-{session}");
        Ok(call_blocking(self.state.db.clone(), move |db| {
            db.resolve_or_create_chat_id(
                HEADLESS_CHANNEL,
                &external_chat_id,
                Some(&title),
                "headless",
            )
        })
        .await?)
    }
}

fn spawn_event_envelope_bridge(
    run_id: String,
    mut raw_rx: mpsc::UnboundedReceiver<AgentEvent>,
    envelope_tx: mpsc::UnboundedSender<RuntimeEventEnvelope>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut sequence = 0_u64;
        while let Some(event) = raw_rx.recv().await {
            sequence = sequence.saturating_add(1);
            if envelope_tx
                .send(RuntimeEventEnvelope::new(&run_id, sequence, event))
                .is_err()
            {
                break;
            }
        }
    })
}

#[allow(clippy::too_many_arguments)]
pub async fn run_once(
    config: Config,
    db: Database,
    memory: MemoryManager,
    skills: SkillManager,
    mcp_manager: crate::mcp::McpManager,
    prompt: String,
    session: Option<String>,
    json: bool,
) -> anyhow::Result<i32> {
    let runtime = HeadlessRuntime::new(config, db, memory, skills, mcp_manager)
        .into_embedded_runtime(HEADLESS_CHANNEL, 1)?;
    let mut request = RunRequest::new(prompt);
    request.session_id = session.map(SessionId::new);
    let result = runtime
        .agent(AgentProfile {
            name: "MicroClaw CLI".into(),
            ..AgentProfile::default()
        })
        .run(request)
        .result()
        .await;

    match result {
        Ok(result) => {
            let chat_id = result
                .metadata
                .get("chat_id")
                .and_then(serde_json::Value::as_i64);
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "ok": true,
                        "response": result.final_text,
                        "chat_id": chat_id,
                        "run_id": result.run_id.to_string(),
                    })
                );
            } else {
                println!("{}", result.final_text);
            }
            Ok(0)
        }
        Err(e) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({"ok": false, "error": e.to_string()})
                );
            } else {
                eprintln!("Error: {e}");
            }
            Ok(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WorkingDirIsolation;
    use crate::llm::LlmProvider;
    use microclaw_core::error::MicroClawError;
    use microclaw_core::llm_types::{
        Message, MessagesResponse, ResponseContentBlock, ToolDefinition,
    };
    use microclaw_core::runtime_event::RuntimeEvent;

    static RUNTIME_TEST_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
        std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

    struct FakeLlm;

    struct SlowLlm;

    struct CapturingLlm {
        system_prompt: Arc<std::sync::Mutex<String>>,
    }

    struct ToolCapturingLlm {
        tools: Arc<std::sync::Mutex<Vec<String>>>,
    }

    struct SteeringLlm {
        calls: Arc<std::sync::atomic::AtomicUsize>,
        first_call_started: Arc<tokio::sync::Notify>,
        saw_update: Arc<std::sync::atomic::AtomicBool>,
    }

    #[async_trait::async_trait]
    impl LlmProvider for FakeLlm {
        async fn send_message(
            &self,
            _system: &str,
            _messages: Vec<Message>,
            _tools: Option<Vec<ToolDefinition>>,
        ) -> Result<MessagesResponse, MicroClawError> {
            Ok(MessagesResponse {
                content: vec![ResponseContentBlock::Text {
                    text: "real agent loop response".into(),
                }],
                stop_reason: Some("end_turn".into()),
                usage: None,
            })
        }
    }

    #[async_trait::async_trait]
    impl LlmProvider for SlowLlm {
        async fn send_message(
            &self,
            _system: &str,
            _messages: Vec<Message>,
            _tools: Option<Vec<ToolDefinition>>,
        ) -> Result<MessagesResponse, MicroClawError> {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            unreachable!("the cancellation test must stop the pending model call")
        }
    }

    #[async_trait::async_trait]
    impl LlmProvider for CapturingLlm {
        async fn send_message(
            &self,
            system: &str,
            _messages: Vec<Message>,
            _tools: Option<Vec<ToolDefinition>>,
        ) -> Result<MessagesResponse, MicroClawError> {
            *self.system_prompt.lock().unwrap() = system.to_string();
            Ok(MessagesResponse {
                content: vec![ResponseContentBlock::Text {
                    text: "profile applied".into(),
                }],
                stop_reason: Some("end_turn".into()),
                usage: None,
            })
        }
    }

    #[async_trait::async_trait]
    impl LlmProvider for ToolCapturingLlm {
        async fn send_message(
            &self,
            _system: &str,
            _messages: Vec<Message>,
            tools: Option<Vec<ToolDefinition>>,
        ) -> Result<MessagesResponse, MicroClawError> {
            *self.tools.lock().unwrap() = tools
                .unwrap_or_default()
                .into_iter()
                .map(|tool| tool.name)
                .collect();
            Ok(MessagesResponse {
                content: vec![ResponseContentBlock::Text {
                    text: "policy applied".into(),
                }],
                stop_reason: Some("end_turn".into()),
                usage: None,
            })
        }
    }

    #[async_trait::async_trait]
    impl LlmProvider for SteeringLlm {
        async fn send_message(
            &self,
            _system: &str,
            messages: Vec<Message>,
            _tools: Option<Vec<ToolDefinition>>,
        ) -> Result<MessagesResponse, MicroClawError> {
            let call = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if call == 0 {
                self.first_call_started.notify_one();
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                return Ok(MessagesResponse {
                    content: vec![ResponseContentBlock::ToolUse {
                        id: "todo-read-1".into(),
                        name: "todo_read".into(),
                        input: serde_json::json!({}),
                        thought_signature: None,
                    }],
                    stop_reason: Some("tool_use".into()),
                    usage: None,
                });
            }
            let rendered = format!("{messages:?}");
            self.saw_update.store(
                rendered.contains("Focus on the parser first"),
                std::sync::atomic::Ordering::SeqCst,
            );
            Ok(MessagesResponse {
                content: vec![ResponseContentBlock::Text {
                    text: "steering applied".into(),
                }],
                stop_reason: Some("end_turn".into()),
                usage: None,
            })
        }
    }

    fn runtime_with_fake_llm(base: &Path) -> HeadlessRuntime {
        runtime_with_llm(base, Box::new(FakeLlm))
    }

    fn runtime_with_llm(base: &Path, llm: Box<dyn LlmProvider>) -> HeadlessRuntime {
        let runtime_dir = base.join("runtime");
        std::fs::create_dir_all(&runtime_dir).unwrap();
        let mut config = Config::test_defaults();
        config.data_dir = runtime_dir.display().to_string();
        config.working_dir = base.display().to_string();
        config.working_dir_isolation = WorkingDirIsolation::Shared;
        let runtime_dir = runtime_dir.display().to_string();
        let db = Arc::new(Database::new(&runtime_dir).unwrap());
        let memory_backend = Arc::new(MemoryBackend::local_only(db.clone()));
        let channel_registry = Arc::new(ChannelRegistry::new());
        HeadlessRuntime {
            state: Arc::new(AppState {
                config: config.clone(),
                channel_registry: channel_registry.clone(),
                db: db.clone(),
                memory: Arc::new(MemoryManager::new(&runtime_dir)),
                skills: Arc::new(SkillManager::from_skills_dir(&config.skills_data_dir())),
                hooks: Arc::new(HookManager::from_config(&config)),
                llm: Arc::from(llm),
                llm_provider_overrides: Arc::new(RwLock::new(HashMap::new())),
                llm_model_overrides: Arc::new(RwLock::new(HashMap::new())),
                embedding: None,
                memory_backend: memory_backend.clone(),
                tools: Arc::new(ToolRegistry::new(
                    &config,
                    channel_registry,
                    db,
                    memory_backend,
                )),
                chat_turn_queue: Arc::new(crate::chat_turn_queue::ChatTurnQueue::new(20)),
                skill_review_queue: crate::skill_review::build_skill_review_channel().0,
                metric_exporter: None,
                trace_exporter: None,
                log_exporter: None,
            }),
        }
    }

    #[tokio::test]
    async fn event_bridge_adds_stable_run_id_and_monotonic_sequence() {
        let (raw_tx, raw_rx) = mpsc::unbounded_channel();
        let (envelope_tx, mut envelope_rx) = mpsc::unbounded_channel();
        let bridge = spawn_event_envelope_bridge("work-run-1".into(), raw_rx, envelope_tx);

        raw_tx
            .send(RuntimeEvent::Iteration { iteration: 1 })
            .unwrap();
        raw_tx
            .send(RuntimeEvent::FinalResponse {
                text: "done".into(),
            })
            .unwrap();
        drop(raw_tx);
        bridge.await.unwrap();

        let first = envelope_rx.recv().await.unwrap();
        let second = envelope_rx.recv().await.unwrap();
        assert_eq!(first.run_id, "work-run-1");
        assert_eq!(first.sequence, 1);
        assert_eq!(second.run_id, "work-run-1");
        assert_eq!(second.sequence, 2);
        assert!(envelope_rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn reusable_runtime_executes_real_agent_loop_and_emits_envelopes() {
        let _guard = RUNTIME_TEST_LOCK.lock().await;
        let directory = tempfile::tempdir().unwrap();
        let runtime = runtime_with_fake_llm(directory.path());
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();

        let result = runtime
            .run(
                HeadlessRunRequest::work(
                    "answer through the shared loop".into(),
                    Some("work-test".into()),
                    "work-run-test".into(),
                ),
                Some(event_tx),
            )
            .await
            .unwrap();
        let mut events = Vec::new();
        while let Some(event) = event_rx.recv().await {
            events.push(event);
        }

        assert_eq!(result.run_id, "work-run-test");
        assert_eq!(result.response, "real agent loop response");
        assert!(!events.is_empty());
        assert!(events.iter().enumerate().all(|(index, envelope)| {
            envelope.run_id == "work-run-test" && envelope.sequence == index as u64 + 1
        }));
        assert!(events.iter().any(|envelope| matches!(
            envelope.event,
            RuntimeEvent::FinalResponse { ref text } if text == "real agent loop response"
        )));
    }

    #[tokio::test]
    async fn durable_subagents_are_observable_and_cancellable_through_headless_runtime() {
        use crate::storage::db::subagents::CreateSubagentRunParams;

        let _guard = RUNTIME_TEST_LOCK.lock().await;
        let directory = tempfile::tempdir().unwrap();
        let runtime = runtime_with_fake_llm(directory.path());
        let chat_id = runtime
            .resolve_session_chat_id("sdk-session")
            .await
            .unwrap();
        runtime
            .state
            .db
            .create_subagent_run(CreateSubagentRunParams {
                run_id: "delegated-1",
                parent_run_id: Some("main-1"),
                depth: 1,
                token_budget: 10_000,
                chat_id,
                caller_channel: HEADLESS_CHANNEL,
                task: "inspect the parser",
                context: "",
                provider: "test",
                model: "test",
                label: Some("parser review"),
            })
            .unwrap();

        let tasks = runtime.subagent_runs("sdk-session", 20).unwrap();
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].parent_run_id.as_deref(), Some("main-1"));
        assert_eq!(tasks[0].depth, 1);
        assert_eq!(tasks[0].label.as_deref(), Some("parser review"));
        assert!(runtime
            .cancel_subagent("sdk-session", "delegated-1")
            .unwrap());
        assert!(runtime.subagent_runs("sdk-session", 20).unwrap()[0].cancel_requested);
    }

    #[tokio::test]
    async fn embedded_agent_profile_applies_prompt_and_selected_skills() {
        let _guard = RUNTIME_TEST_LOCK.lock().await;
        let directory = tempfile::tempdir().unwrap();
        let captured = Arc::new(std::sync::Mutex::new(String::new()));
        let headless = runtime_with_llm(
            directory.path(),
            Box::new(CapturingLlm {
                system_prompt: captured.clone(),
            }),
        );
        let skill_dir = headless.state.skills.skills_dir().join("rust-review");
        std::fs::create_dir_all(&skill_dir).unwrap();
        std::fs::write(
            skill_dir.join("SKILL.md"),
            "---\nname: rust-review\ndescription: Review Rust\n---\nCHECK_AGENT_SKILL_BODY\n",
        )
        .unwrap();
        let runtime = headless.into_embedded_runtime(WORK_CHANNEL, 1).unwrap();
        let profile = AgentProfile {
            name: "reviewer".into(),
            system_prompt: Some("CHECK_AGENT_PROFILE_PROMPT".into()),
            skills: vec!["rust-review".into()],
            ..AgentProfile::default()
        };

        let result = runtime
            .agent(profile)
            .run(RunRequest::new("review this crate"))
            .result()
            .await
            .unwrap();

        assert_eq!(result.final_text, "profile applied");
        let system = captured.lock().unwrap();
        assert!(system.contains("CHECK_AGENT_PROFILE_PROMPT"), "{system}");
        assert!(system.contains("CHECK_AGENT_SKILL_BODY"), "{system}");
    }

    #[tokio::test]
    async fn embedded_read_only_profile_hides_mutating_tools() {
        let _guard = RUNTIME_TEST_LOCK.lock().await;
        let directory = tempfile::tempdir().unwrap();
        let captured = Arc::new(std::sync::Mutex::new(Vec::new()));
        let runtime = runtime_with_llm(
            directory.path(),
            Box::new(ToolCapturingLlm {
                tools: captured.clone(),
            }),
        )
        .into_embedded_runtime(WORK_CHANNEL, 1)
        .unwrap();
        let profile = AgentProfile {
            name: "reviewer".into(),
            tool_policy: microclaw_core::run_protocol::ToolPolicy::ReadOnly,
            ..AgentProfile::default()
        };

        runtime
            .agent(profile)
            .run(RunRequest::new("inspect this project"))
            .result()
            .await
            .unwrap();

        let tools = captured.lock().unwrap();
        assert!(tools.iter().any(|name| name == "read_file"), "{tools:?}");
        assert!(!tools.iter().any(|name| name == "write_file"), "{tools:?}");
        assert!(!tools.iter().any(|name| name == "bash"), "{tools:?}");
    }

    #[tokio::test]
    async fn cancelling_a_headless_session_stops_the_real_agent_loop() {
        let _guard = RUNTIME_TEST_LOCK.lock().await;
        let directory = tempfile::tempdir().unwrap();
        let runtime = Arc::new(runtime_with_llm(directory.path(), Box::new(SlowLlm)));
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let running_runtime = runtime.clone();
        let run = tokio::spawn(async move {
            running_runtime
                .run(
                    HeadlessRunRequest::work(
                        "wait for cancellation".into(),
                        Some("cancel-test".into()),
                        "cancel-run-test".into(),
                    ),
                    Some(event_tx),
                )
                .await
        });

        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if runtime.cancel_work_session("cancel-test").await.unwrap() > 0 {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("run should register for cancellation");

        let result = tokio::time::timeout(std::time::Duration::from_secs(5), run)
            .await
            .expect("cancelled run should finish promptly")
            .unwrap()
            .unwrap();
        assert_eq!(result.response, crate::run_control::STOPPED_TEXT);

        let mut cancelled = false;
        while let Some(envelope) = event_rx.recv().await {
            cancelled |= matches!(envelope.event, RuntimeEvent::Cancelled { .. });
        }
        assert!(cancelled);
    }

    #[tokio::test]
    async fn steering_uses_the_active_agent_turn_queue() {
        let _guard = RUNTIME_TEST_LOCK.lock().await;
        let directory = tempfile::tempdir().unwrap();
        let runtime = runtime_with_fake_llm(directory.path());
        let chat_id = runtime.resolve_session_chat_id("steer-test").await.unwrap();
        let turn = runtime
            .state
            .chat_turn_queue
            .acquire(HEADLESS_CHANNEL, chat_id)
            .await
            .unwrap();

        assert!(runtime
            .steer_session("steer-test", "Focus on the parser first")
            .await
            .unwrap());
        let pending = runtime
            .state
            .chat_turn_queue
            .drain_pending(HEADLESS_CHANNEL, chat_id)
            .await;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].sender_name, "work");
        assert_eq!(pending[0].content, "Focus on the parser first");
        drop(turn);

        assert!(!runtime
            .steer_session("steer-test", "This run is already idle")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn steering_reaches_the_real_agent_loop_after_a_tool_breakpoint() {
        let _guard = RUNTIME_TEST_LOCK.lock().await;
        let directory = tempfile::tempdir().unwrap();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let first_call_started = Arc::new(tokio::sync::Notify::new());
        let saw_update = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let runtime = Arc::new(runtime_with_llm(
            directory.path(),
            Box::new(SteeringLlm {
                calls: calls.clone(),
                first_call_started: first_call_started.clone(),
                saw_update: saw_update.clone(),
            }),
        ));
        let running_runtime = runtime.clone();
        let run = tokio::spawn(async move {
            running_runtime
                .run(
                    HeadlessRunRequest::work(
                        "Start with the whole task".into(),
                        Some("live-steer".into()),
                        "live-steer-run".into(),
                    ),
                    None,
                )
                .await
        });

        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            first_call_started.notified(),
        )
        .await
        .expect("first model call should start");
        assert!(runtime
            .steer_work_session("live-steer", "Focus on the parser first")
            .await
            .unwrap());
        let result = run.await.unwrap().unwrap();

        assert_eq!(result.response, "steering applied");
        assert!(calls.load(std::sync::atomic::Ordering::SeqCst) >= 2);
        assert!(saw_update.load(std::sync::atomic::Ordering::SeqCst));
    }
}
