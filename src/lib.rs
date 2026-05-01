pub mod a2a;
pub mod acp;
pub mod acp_subagent;
pub mod agent_engine;
pub mod channels;
pub mod chat_commands;
pub mod chat_turn_queue;
pub mod checkpoint;
pub mod clawhub;
pub mod codex_auth;
pub mod config;
pub mod config_persistence;
pub mod context_references;
pub mod doctor;
pub mod embedding;
pub mod gateway;
pub mod hooks;
pub mod http_client;
pub mod llm;
pub mod mcp;
pub mod memory_backend;
pub mod memory_service;
pub mod plugins;
pub mod prompt_cache;
pub(crate) mod run_control;
pub mod runtime;
pub mod scheduler;
pub mod setup;
pub mod setup_def;
pub mod skill_review;
pub mod skills;
pub mod subdirectory_hints;
pub mod title_generator;
pub mod tls;
pub mod tool_executor;
pub mod tool_guardrails;
pub mod tools;
pub mod voice;
pub mod web;

pub use channels::discord;
pub use channels::telegram;
pub use microclaw_app::builtin_skills;
pub use microclaw_app::logging;
pub use microclaw_app::transcribe;
pub use microclaw_channels::channel;
pub use microclaw_channels::channel_adapter;
pub use microclaw_core::error;
pub use microclaw_core::llm_types;
pub use microclaw_core::text;
pub use microclaw_storage::db;
pub use microclaw_storage::memory;
pub use microclaw_storage::memory_quality;
pub use microclaw_tools::sandbox;

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
