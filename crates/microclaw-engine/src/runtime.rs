use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::config::Config;
use crate::embedding::EmbeddingProvider;
use crate::hooks::HookManager;
use crate::internal::channels::channel_adapter::ChannelRegistry;
use crate::internal::observability::logs::OtlpLogExporter;
use crate::internal::observability::metrics::OtlpMetricExporter;
use crate::internal::observability::traces::OtlpTraceExporter;
use crate::internal::storage::db::Database;
use crate::llm::LlmProvider;
use crate::memory::MemoryManager;
use crate::memory_backend::MemoryBackend;
use crate::skills::SkillManager;
use crate::tools::ToolRegistry;

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub channel_registry: Arc<ChannelRegistry>,
    pub db: Arc<Database>,
    pub memory: Arc<MemoryManager>,
    pub skills: Arc<SkillManager>,
    pub hooks: Arc<HookManager>,
    pub llm: Arc<dyn LlmProvider>,
    pub llm_provider_overrides: Arc<RwLock<HashMap<String, String>>>,
    pub llm_model_overrides: Arc<RwLock<HashMap<String, String>>>,
    pub embedding: Option<Arc<dyn EmbeddingProvider>>,
    pub memory_backend: Arc<MemoryBackend>,
    pub tools: Arc<ToolRegistry>,
    pub chat_turn_queue: Arc<crate::chat_turn_queue::ChatTurnQueue>,
    pub skill_review_queue: crate::skill_review::SkillReviewQueue,
    pub metric_exporter: Option<Arc<OtlpMetricExporter>>,
    pub trace_exporter: Option<Arc<OtlpTraceExporter>>,
    pub log_exporter: Option<Arc<OtlpLogExporter>>,
}
