pub mod acp;
pub mod canary;
pub mod channels;
pub mod doctor;
pub mod eval;
pub mod gateway;
pub mod outbox;
pub mod runtime;
pub mod scheduler;
pub mod setup;
pub mod tls;
pub mod web;

pub use microclaw_engine::{
    a2a, acp_subagent, agent_engine, alerts, chat_commands, chat_turn_queue, checkpoint, clawhub,
    codex_auth, completion_contract, config, config_persistence, context_references, embedding,
    headless, hooks, http_client, learning_foundry, llm, mcp, memory_backend, memory_service,
    messages, mood, plugins, prompt_cache, relationship, run_control, schedule_lifecycle,
    setup_def, skill_audit, skill_review, skills, subdirectory_hints, supervision, title_generator,
    tool_executor, tool_guardrails, tools, trust_report, turn_recovery, voice,
};

/// Whether this build embeds the React operator console. Server builds enable
/// it by default; native Work builds deliberately disable it.
pub const EMBEDDED_WEB_UI_ENABLED: bool = cfg!(feature = "embedded-web-ui");

pub use channels::discord;
pub use channels::telegram;
pub use microclaw_core::error;
pub use microclaw_core::llm_types;
pub use microclaw_core::text;
pub use microclaw_engine::builtin_skills;
pub use microclaw_engine::channel;
pub use microclaw_engine::channel_adapter;
pub use microclaw_engine::logging;
pub use microclaw_engine::storage::db;
pub use microclaw_engine::storage::memory;
pub use microclaw_engine::storage::memory_quality;
pub use microclaw_engine::tool_runtime::sandbox;
pub use microclaw_engine::transcribe;

#[cfg(test)]
pub mod test_support {
    use std::sync::{Mutex, MutexGuard, OnceLock};

    pub fn env_lock() -> MutexGuard<'static, ()> {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env lock poisoned")
    }
}
