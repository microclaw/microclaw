//! Headless one-shot mode: `microclaw run -p "<prompt>"`.
//!
//! Runs a single prompt through the shared agent loop without starting any
//! channel, prints the final reply to stdout, and exits non-zero on failure
//! — the scripting/CI entry point (grok-build's headless mode equivalent).
//! Runs share the `headless` channel; `--session <name>` selects a named
//! chat so consecutive runs can keep conversation context.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::agent_engine::{process_with_agent, AgentRequestContext};
use crate::config::Config;
use crate::hooks::HookManager;
use crate::memory::MemoryManager;
use crate::memory_backend::{MemoryBackend, MemoryMcpClient};
use crate::runtime::AppState;
use crate::skills::SkillManager;
use crate::tools::ToolRegistry;
use crate::{embedding, llm};
use microclaw_channels::channel_adapter::ChannelRegistry;
use microclaw_storage::db::{call_blocking, Database, StoredMessage};

pub const HEADLESS_CHANNEL: &str = "headless";

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

    let session_name = session.unwrap_or_else(|| "default".to_string());
    let external_chat_id = format!("headless:{session_name}");
    let title = format!("headless-{session_name}");
    let chat_id = call_blocking(state.db.clone(), {
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
        sender_name: "cli".to_string(),
        content: prompt,
        is_from_bot: false,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };
    let _ = call_blocking(state.db.clone(), move |db| db.store_message(&stored)).await;

    let result = process_with_agent(
        &state,
        AgentRequestContext {
            caller_channel: HEADLESS_CHANNEL,
            chat_id,
            chat_type: "private",
        },
        None,
        None,
    )
    .await;

    match result {
        Ok(response) => {
            let bot_msg = StoredMessage {
                id: uuid::Uuid::new_v4().to_string(),
                chat_id,
                sender_name: "microclaw".to_string(),
                content: response.clone(),
                is_from_bot: true,
                timestamp: chrono::Utc::now().to_rfc3339(),
            };
            let _ = call_blocking(state.db.clone(), move |db| db.store_message(&bot_msg)).await;
            if json {
                println!(
                    "{}",
                    serde_json::json!({"ok": true, "response": response, "chat_id": chat_id})
                );
            } else {
                println!("{response}");
            }
            Ok(0)
        }
        Err(e) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({"ok": false, "error": e.to_string(), "chat_id": chat_id})
                );
            } else {
                eprintln!("Error: {e}");
            }
            Ok(1)
        }
    }
}
