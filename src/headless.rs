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
        let external_chat_id = format!("headless:{session_name}");
        let title = format!("headless-{session_name}");
        let chat_id = call_blocking(self.state.db.clone(), {
            let external_chat_id = external_chat_id.clone();
            move |db| {
                db.resolve_or_create_chat_id(
                    HEADLESS_CHANNEL,
                    &external_chat_id,
                    Some(&title),
                    "headless",
                )
            }
        })
        .await?;

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

    struct FakeLlm;

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

    fn runtime_with_fake_llm(base: &Path) -> HeadlessRuntime {
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
                llm: Box::new(FakeLlm),
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
}
