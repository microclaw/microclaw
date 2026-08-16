use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use include_dir::{include_dir, Dir};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::{broadcast, Mutex};
use tracing::{error, info, warn};

use crate::agent_engine::{process_with_agent_with_events, AgentEvent, AgentRequestContext};
use crate::chat_commands::handle_chat_command;
use crate::config::{Config, WorkingDirIsolation};
use crate::runtime::AppState;
use microclaw_channels::channel::ConversationKind;
use microclaw_channels::channel::{
    deliver_and_store_bot_message, get_chat_routing, session_source_for_chat,
};
use microclaw_channels::channel_adapter::{ChannelAdapter, ChannelRegistry};
use microclaw_observability::metrics::{OtlpMetricExporter, OtlpMetricSnapshot};
use microclaw_storage::db::{call_blocking, ChatSummary, MetricsHistoryPoint, StoredMessage};
use microclaw_storage::usage::build_usage_report;

use middleware::*;

include!(concat!(env!("OUT_DIR"), "/web_assets.rs"));

mod a2a;
mod auth;
mod chat_abort;
mod config;
mod governance;
mod metrics;
mod middleware;
mod sessions;
mod skills;
mod stream;
mod tasks;
mod ws;

pub mod api_chat;
pub mod api_hooks;
pub mod api_learning;
pub mod api_observability;
pub mod config_yaml;
pub mod dto;
pub mod metrics_sink;
pub mod server;
pub mod state;
#[cfg(test)]
pub(crate) mod test_prelude;

pub(crate) use self::api_chat::*;
pub(crate) use self::api_hooks::*;
pub(crate) use self::api_learning::*;
pub(crate) use self::api_observability::*;
pub(crate) use self::config_yaml::*;
pub(crate) use self::dto::*;
pub(crate) use self::metrics_sink::*;
pub(crate) use self::server::*;
pub(crate) use self::state::*;

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use crate::web::test_prelude::*;

    #[tokio::test]
    async fn test_db_paths_use_call_blocking_in_web_flow() {
        let state = test_state(Box::new(DummyLlm));
        let chat_id = 12345_i64;
        let message_count = call_blocking(state.db.clone(), move |db| db.get_all_messages(chat_id))
            .await
            .unwrap()
            .len();
        assert_eq!(message_count, 0);
    }

    #[test]
    fn test_client_key_ignores_xff_by_default() {
        let cfg = test_config_template();
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.10".parse().unwrap());
        let key = client_key_from_headers_with_config(&headers, &cfg);
        assert_eq!(key, "global");
    }

    #[test]
    fn test_client_key_uses_xff_when_trusted() {
        let mut cfg = test_config_template();
        cfg.channels.insert(
            "web".to_string(),
            serde_yaml::to_value(json!({"trust_x_forwarded_for": true})).unwrap(),
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "203.0.113.10, 198.51.100.2".parse().unwrap(),
        );
        let key = client_key_from_headers_with_config(&headers, &cfg);
        assert_eq!(key, "203.0.113.10");
    }
}
