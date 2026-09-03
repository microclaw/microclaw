//! Concrete, channel-independent MicroClaw Agent Engine services.
//!
//! This crate is the physical extraction boundary for the provider-neutral loop and its default
//! services. Product crates translate input/output at their edge and consume this library.

// Some public helpers are consumed only by product crates, so they are intentionally not all
// reachable from this crate's own entry points.
#![allow(dead_code)]

pub mod a2a;
pub mod acp_subagent;
pub mod agent_engine;
pub mod alerts;
pub mod chat_commands;
pub mod chat_turn_queue;
pub mod checkpoint;
pub mod clawhub;
pub mod codex_auth;
pub mod completion_contract;
pub mod config;
pub mod config_persistence;
pub mod context_references;
pub mod embedding;
pub mod headless;
pub mod hooks;
pub mod http_client;
pub mod learning_foundry;
pub mod llm;
pub mod mcp;
pub mod memory_backend;
pub mod memory_service;
pub mod messages;
pub mod mood;
pub mod plugins;
pub mod prompt_cache;
pub mod relationship;
pub mod run_control;
pub mod schedule_lifecycle;
pub mod setup;
pub mod setup_def;
pub mod skill_audit;
pub mod skill_review;
pub mod skills;
pub mod subdirectory_hints;
pub mod supervision;
pub mod title_generator;
pub mod tool_executor;
pub mod tool_guardrails;
pub mod tools;
pub mod trust_report;
pub mod turn_recovery;
pub mod voice;

pub mod channels;
pub mod runtime;

pub use microclaw_app::builtin_skills;
pub use microclaw_app::logging;
pub use microclaw_app::transcribe;
pub use microclaw_core::error;
pub use microclaw_core::llm_types;
pub use microclaw_storage::memory;

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
