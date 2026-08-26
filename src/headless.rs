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

use crate::agent_engine::{process_with_agent_with_events, AgentEvent, AgentRequestContext};
use crate::chat_turn_queue::PendingMessage;
use crate::config::Config;
use crate::hooks::HookManager;
use crate::memory::MemoryManager;
use crate::memory_backend::{MemoryBackend, MemoryMcpClient};
use crate::runtime::AppState;
use crate::skills::SkillManager;
use crate::tools::ToolRegistry;
use crate::{embedding, llm};
use microclaw_channels::channel_adapter::ChannelRegistry;
use microclaw_core::runtime_event::RuntimeEventEnvelope;
use microclaw_storage::db::{call_blocking, Database, StoredMessage};

pub const HEADLESS_CHANNEL: &str = "headless";

#[derive(Debug, Clone)]
pub struct HeadlessRunRequest {
    pub prompt: String,
    pub session: Option<String>,
    pub sender_name: String,
    pub run_id: Option<String>,
}

impl HeadlessRunRequest {
    pub fn cli(prompt: String, session: Option<String>) -> Self {
        Self {
            prompt,
            session,
            sender_name: "cli".into(),
            run_id: None,
        }
    }

    pub fn work(prompt: String, session: Option<String>, run_id: String) -> Self {
        Self {
            prompt,
            session,
            sender_name: "work".into(),
            run_id: Some(run_id),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HeadlessRunResult {
    pub run_id: String,
    pub chat_id: i64,
    pub response: String,
}

/// Reusable application service for one-shot tasks.
///
/// It owns the existing provider-neutral Agent Engine state but starts no
/// channel, Web server, or scheduler. Both the CLI and Work adapters call this
/// service instead of assembling or copying an Agent Loop.
pub struct HeadlessRuntime {
    state: Arc<AppState>,
}

impl HeadlessRuntime {
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
            memory,
            skills,
            hooks: Arc::new(HookManager::from_config(&config).with_db(db.clone())),
            llm,
            llm_provider_overrides: Arc::new(RwLock::new(HashMap::new())),
            llm_model_overrides: Arc::new(RwLock::new(HashMap::new())),
            embedding,
            memory_backend,
            tools,
            chat_turn_queue,
            skill_review_queue,
            metric_exporter: None,
            trace_exporter: None,
            log_exporter: None,
        });
        Self { state }
    }

    pub async fn run(
        &self,
        request: HeadlessRunRequest,
        event_tx: Option<mpsc::UnboundedSender<RuntimeEventEnvelope>>,
    ) -> anyhow::Result<HeadlessRunResult> {
        let session_name = request
            .session
            .clone()
            .unwrap_or_else(|| "default".to_string());
        let chat_id = self.resolve_session_chat_id(&session_name).await?;

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
        let response = process_with_agent_with_events(
            &self.state,
            AgentRequestContext {
                caller_channel: HEADLESS_CHANNEL,
                chat_id,
                chat_type: "private",
            },
            None,
            None,
            raw_event_tx.as_ref(),
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
        let chat_id = self.resolve_session_chat_id(session).await?;
        Ok(crate::run_control::abort_runs(HEADLESS_CHANNEL, chat_id).await)
    }

    /// Add a user update to an active named session.
    ///
    /// The shared Agent Engine drains this queue at its normal tool/end-turn
    /// breakpoints. Returning `false` means the run ended before the update
    /// could be queued; callers must not report it as accepted.
    pub async fn steer_session(&self, session: &str, content: &str) -> anyhow::Result<bool> {
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
            .enqueue_if_busy(HEADLESS_CHANNEL, chat_id, pending)
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
    let runtime = HeadlessRuntime::new(config, db, memory, skills, mcp_manager);
    let result = runtime
        .run(HeadlessRunRequest::cli(prompt, session), None)
        .await;

    match result {
        Ok(result) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "ok": true,
                        "response": result.response,
                        "chat_id": result.chat_id,
                        "run_id": result.run_id,
                    })
                );
            } else {
                println!("{}", result.response);
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
                memory: MemoryManager::new(&runtime_dir),
                skills: SkillManager::from_skills_dir(&config.skills_data_dir()),
                hooks: Arc::new(HookManager::from_config(&config)),
                llm,
                llm_provider_overrides: Arc::new(RwLock::new(HashMap::new())),
                llm_model_overrides: Arc::new(RwLock::new(HashMap::new())),
                embedding: None,
                memory_backend: memory_backend.clone(),
                tools: ToolRegistry::new(&config, channel_registry, db, memory_backend),
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
                if runtime.cancel_session("cancel-test").await.unwrap() > 0 {
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
            .steer_session("live-steer", "Focus on the parser first")
            .await
            .unwrap());
        let result = run.await.unwrap().unwrap();

        assert_eq!(result.response, "steering applied");
        assert!(calls.load(std::sync::atomic::Ordering::SeqCst) >= 2);
        assert!(saw_update.load(std::sync::atomic::Ordering::SeqCst));
    }
}
