use async_trait::async_trait;
use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;

use tracing::{info, warn};

use crate::mcp::{McpManager, McpServer, McpToolInfo};
use microclaw_core::error::MicroClawError;
use microclaw_storage::db::{call_blocking, Database, Memory};

#[derive(Clone)]
pub struct MemoryMcpClient {
    server: Arc<McpServer>,
    query_tool: String,
    upsert_tool: String,
}

impl MemoryMcpClient {
    pub fn discover(manager: &McpManager) -> Option<Self> {
        let tools = manager.all_tools();
        let mut grouped: HashMap<String, (Option<Arc<McpServer>>, bool, bool)> = HashMap::new();
        for (server, tool) in tools {
            let entry =
                grouped
                    .entry(tool.server_name.clone())
                    .or_insert((Some(server), false, false));
            if tool.name == "memory_query" {
                entry.1 = true;
            }
            if tool.name == "memory_upsert" {
                entry.2 = true;
            }
        }

        for (name, (server_opt, has_query, has_upsert)) in grouped {
            if has_query && has_upsert {
                if let Some(server) = server_opt {
                    info!("Memory MCP backend enabled via server '{name}'");
                    return Some(Self {
                        server,
                        query_tool: "memory_query".to_string(),
                        upsert_tool: "memory_upsert".to_string(),
                    });
                }
            }
        }
        None
    }

    async fn call_query(&self, payload: serde_json::Value) -> Result<serde_json::Value, String> {
        let text = self.server.call_tool(&self.query_tool, payload).await?;
        parse_json_loose(&text)
    }

    async fn call_upsert(&self, payload: serde_json::Value) -> Result<serde_json::Value, String> {
        let text = self.server.call_tool(&self.upsert_tool, payload).await?;
        parse_json_loose(&text)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MemoryProviderErrorKind {
    InvalidPayload,
    Timeout,
    Transport,
    UnsupportedOperation,
}

impl MemoryProviderErrorKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::InvalidPayload => "invalid_payload",
            Self::Timeout => "timeout",
            Self::Transport => "transport",
            Self::UnsupportedOperation => "unsupported_operation",
        }
    }
}

#[derive(Debug, Clone)]
struct MemoryProviderFailure {
    op: String,
    kind: MemoryProviderErrorKind,
    detail: String,
}

impl MemoryProviderFailure {
    fn timeout(op: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            op: op.into(),
            kind: MemoryProviderErrorKind::Timeout,
            detail: detail.into(),
        }
    }

    fn invalid_payload(op: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            op: op.into(),
            kind: MemoryProviderErrorKind::InvalidPayload,
            detail: detail.into(),
        }
    }

    fn transport(op: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            op: op.into(),
            kind: MemoryProviderErrorKind::Transport,
            detail: detail.into(),
        }
    }

    fn unsupported_operation(op: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            op: op.into(),
            kind: MemoryProviderErrorKind::UnsupportedOperation,
            detail: detail.into(),
        }
    }

    fn classify(op: impl Into<String>, detail: impl Into<String>) -> Self {
        let op = op.into();
        let detail = detail.into();
        let lower = detail.to_ascii_lowercase();
        if lower.contains("tool not found")
            || lower.contains("unknown tool")
            || lower.contains("not implemented")
            || lower.contains("unsupported op")
            || lower.contains("unsupported operation")
        {
            return Self::unsupported_operation(op, detail);
        }
        if lower.contains("timed out")
            || lower.contains("timeout")
            || lower.contains("deadline exceeded")
        {
            return Self::timeout(op, detail);
        }
        Self::transport(op, detail)
    }

    fn fallback_reason(&self) -> String {
        format!("{}:{}", self.op, self.kind.as_str())
    }

    fn into_error(self) -> MicroClawError {
        MicroClawError::ToolExecution(self.to_string())
    }
}

impl fmt::Display for MemoryProviderFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} [{}]: {}", self.op, self.kind.as_str(), self.detail)
    }
}

fn classify_memory_error(op: impl Into<String>, err: String) -> MicroClawError {
    MemoryProviderFailure::classify(op, err).into_error()
}

fn invalid_memory_payload(op: impl Into<String>, detail: impl Into<String>) -> MicroClawError {
    MemoryProviderFailure::invalid_payload(op, detail).into_error()
}

/// Append a write-ahead log entry for memory operations (for auditing and poisoning detection).
/// Spawns a background task — never blocks the write path.
fn audit_memory_write(data_dir: &str, entry: serde_json::Value) {
    let data_dir = data_dir.to_string();
    tokio::spawn(async move {
        let result = tokio::task::spawn_blocking(move || {
            use std::io::Write;
            let wal_dir = std::path::Path::new(&data_dir).join("runtime").join("wal");
            std::fs::create_dir_all(&wal_dir)?;
            let path = wal_dir.join("memory_writes.jsonl");
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)?;
            let mut line = serde_json::to_string(&entry).unwrap_or_default();
            line.push('\n');
            file.write_all(line.as_bytes())
        })
        .await;
        if let Err(e) = result {
            tracing::debug!("Memory WAL write failed (non-critical): {e}");
        }
    });
}

pub struct MemoryBackend {
    provider: Arc<dyn MemoryProvider>,
    stats: Arc<MemoryBackendStats>,
    primary_provider: Option<Arc<dyn MemoryProvider>>,
    primary_provider_name: Option<String>,
    data_dir: String,
}

type ProviderBundle = (
    Arc<dyn MemoryProvider>,
    Option<Arc<dyn MemoryProvider>>,
    Option<String>,
);

impl MemoryBackend {
    pub fn new(db: Arc<Database>, mcp: Option<MemoryMcpClient>, data_dir: &str) -> Self {
        let stats = Arc::new(MemoryBackendStats::new());
        let sqlite: Arc<dyn MemoryProvider> = Arc::new(SqliteMemoryProvider::new(db.clone()));
        let (provider, primary_provider, primary_provider_name): ProviderBundle = match mcp {
            Some(mcp_client) => {
                let primary: Arc<dyn MemoryProvider> = Arc::new(McpMemoryProvider::new(mcp_client));
                (
                    Arc::new(FallbackMemoryProvider::new(
                        primary.clone(),
                        sqlite,
                        stats.clone(),
                        "mcp".to_string(),
                    )),
                    Some(primary),
                    Some("mcp".to_string()),
                )
            }
            None => (sqlite, None, None),
        };
        Self {
            provider,
            stats,
            primary_provider,
            primary_provider_name,
            data_dir: data_dir.to_string(),
        }
    }

    pub fn local_only(db: Arc<Database>) -> Self {
        Self {
            provider: Arc::new(SqliteMemoryProvider::new(db)),
            stats: Arc::new(MemoryBackendStats::new()),
            primary_provider: None,
            primary_provider_name: None,
            data_dir: String::new(),
        }
    }

    #[cfg(test)]
    fn from_provider(provider: Arc<dyn MemoryProvider>) -> Self {
        Self {
            provider,
            stats: Arc::new(MemoryBackendStats::new()),
            primary_provider: None,
            primary_provider_name: None,
            data_dir: String::new(),
        }
    }

    #[cfg(test)]
    fn from_provider_with_stats(
        provider: Arc<dyn MemoryProvider>,
        stats: Arc<MemoryBackendStats>,
        primary_provider_name: Option<String>,
    ) -> Self {
        Self {
            provider,
            stats,
            primary_provider: None,
            primary_provider_name,
            data_dir: String::new(),
        }
    }

    pub fn supports_local_semantic_ranking(&self) -> bool {
        self.provider.supports_local_semantic_ranking()
    }

    pub fn provider_health_snapshot(&self) -> MemoryBackendHealthSnapshot {
        self.stats.snapshot(self.primary_provider_name.clone())
    }

    pub fn should_pause_reflector_writes(&self) -> bool {
        let snapshot = self.provider_health_snapshot();
        snapshot.external_provider_enabled
            && (!snapshot.startup_probe_ok.unwrap_or(true)
                || snapshot.consecutive_primary_failures >= 3)
    }

    pub async fn run_startup_health_check(&self) -> Result<(), MicroClawError> {
        let Some(primary) = &self.primary_provider else {
            return Ok(());
        };
        match primary.get_all_memories_for_chat(None).await {
            Ok(_) => {
                self.stats.record_primary_success();
                self.stats.startup_probe_ok.store(true, Ordering::SeqCst);
                self.stats
                    .startup_probe_message
                    .store_string(Some("ok".to_string()));
                Ok(())
            }
            Err(err) => {
                self.stats.record_primary_failure();
                self.stats.startup_probe_ok.store(false, Ordering::SeqCst);
                self.stats
                    .startup_probe_message
                    .store_string(Some(err.to_string()));
                Err(err)
            }
        }
    }

    pub async fn get_all_memories_for_chat(
        &self,
        chat_id: Option<i64>,
    ) -> Result<Vec<Memory>, MicroClawError> {
        self.provider.get_all_memories_for_chat(chat_id).await
    }

    pub async fn get_memories_for_context(
        &self,
        chat_id: i64,
        limit: usize,
    ) -> Result<Vec<Memory>, MicroClawError> {
        self.provider.get_memories_for_context(chat_id, limit).await
    }

    pub async fn search_memories_with_options(
        &self,
        chat_id: i64,
        query: &str,
        limit: usize,
        include_archived: bool,
        broad_recall: bool,
    ) -> Result<Vec<Memory>, MicroClawError> {
        self.provider
            .search_memories_with_options(chat_id, query, limit, include_archived, broad_recall)
            .await
    }

    pub async fn get_memory_by_id(&self, id: i64) -> Result<Option<Memory>, MicroClawError> {
        self.provider.get_memory_by_id(id).await
    }

    pub async fn insert_memory_with_metadata(
        &self,
        chat_id: Option<i64>,
        content: &str,
        category: &str,
        source: &str,
        confidence: f64,
    ) -> Result<i64, MicroClawError> {
        if !self.data_dir.is_empty() {
            audit_memory_write(
                &self.data_dir,
                serde_json::json!({
                    "op": "insert",
                    "chat_id": chat_id,
                    "category": category,
                    "source": source,
                    "confidence": confidence,
                    "content_len": content.len(),
                    "content_preview": &content[..content.len().min(100)],
                    "ts": chrono::Utc::now().to_rfc3339(),
                }),
            );
        }
        self.provider
            .insert_memory_with_metadata(chat_id, content, category, source, confidence)
            .await
    }

    pub async fn update_memory_with_metadata(
        &self,
        id: i64,
        content: &str,
        category: &str,
        confidence: f64,
        source: &str,
    ) -> Result<bool, MicroClawError> {
        self.provider
            .update_memory_with_metadata(id, content, category, confidence, source)
            .await
    }

    pub async fn update_memory_content(
        &self,
        id: i64,
        content: &str,
        category: &str,
    ) -> Result<bool, MicroClawError> {
        self.update_memory_with_metadata(id, content, category, 0.8, "tool")
            .await
    }

    pub async fn archive_memory(&self, id: i64) -> Result<bool, MicroClawError> {
        self.provider.archive_memory(id).await
    }

    pub async fn supersede_memory(
        &self,
        from_memory_id: i64,
        new_content: &str,
        category: &str,
        source: &str,
        confidence: f64,
        reason: Option<&str>,
    ) -> Result<i64, MicroClawError> {
        self.provider
            .supersede_memory(
                from_memory_id,
                new_content,
                category,
                source,
                confidence,
                reason,
            )
            .await
    }

    pub async fn touch_memory_last_seen(
        &self,
        id: i64,
        confidence_floor: Option<f64>,
    ) -> Result<bool, MicroClawError> {
        self.provider
            .touch_memory_last_seen(id, confidence_floor)
            .await
    }
}

#[async_trait]
pub trait MemoryProvider: Send + Sync {
    fn supports_local_semantic_ranking(&self) -> bool {
        true
    }

    async fn get_all_memories_for_chat(
        &self,
        chat_id: Option<i64>,
    ) -> Result<Vec<Memory>, MicroClawError>;

    async fn get_memories_for_context(
        &self,
        chat_id: i64,
        limit: usize,
    ) -> Result<Vec<Memory>, MicroClawError>;

    async fn search_memories_with_options(
        &self,
        chat_id: i64,
        query: &str,
        limit: usize,
        include_archived: bool,
        broad_recall: bool,
    ) -> Result<Vec<Memory>, MicroClawError>;

    async fn get_memory_by_id(&self, id: i64) -> Result<Option<Memory>, MicroClawError>;

    async fn insert_memory_with_metadata(
        &self,
        chat_id: Option<i64>,
        content: &str,
        category: &str,
        source: &str,
        confidence: f64,
    ) -> Result<i64, MicroClawError>;

    async fn update_memory_with_metadata(
        &self,
        id: i64,
        content: &str,
        category: &str,
        confidence: f64,
        source: &str,
    ) -> Result<bool, MicroClawError>;

    async fn archive_memory(&self, id: i64) -> Result<bool, MicroClawError>;

    async fn supersede_memory(
        &self,
        from_memory_id: i64,
        new_content: &str,
        category: &str,
        source: &str,
        confidence: f64,
        reason: Option<&str>,
    ) -> Result<i64, MicroClawError>;

    async fn touch_memory_last_seen(
        &self,
        id: i64,
        confidence_floor: Option<f64>,
    ) -> Result<bool, MicroClawError>;
}

#[derive(Debug, Clone)]
pub struct MemoryBackendHealthSnapshot {
    pub external_provider_enabled: bool,
    pub primary_provider_name: Option<String>,
    pub startup_probe_ok: Option<bool>,
    pub startup_probe_message: Option<String>,
    pub consecutive_primary_failures: u64,
    pub total_fallbacks: u64,
    pub last_primary_success_ts: Option<i64>,
    pub last_primary_failure_ts: Option<i64>,
    pub last_fallback_reason: Option<String>,
}

struct MemoryBackendStats {
    startup_probe_ran: AtomicBool,
    startup_probe_ok: AtomicBool,
    consecutive_primary_failures: AtomicU64,
    total_fallbacks: AtomicU64,
    last_primary_success_ts: AtomicI64,
    last_primary_failure_ts: AtomicI64,
    startup_probe_message: AtomicStringCell,
    last_fallback_reason: AtomicStringCell,
}

impl MemoryBackendStats {
    fn new() -> Self {
        Self {
            startup_probe_ran: AtomicBool::new(false),
            startup_probe_ok: AtomicBool::new(false),
            consecutive_primary_failures: AtomicU64::new(0),
            total_fallbacks: AtomicU64::new(0),
            last_primary_success_ts: AtomicI64::new(0),
            last_primary_failure_ts: AtomicI64::new(0),
            startup_probe_message: AtomicStringCell::default(),
            last_fallback_reason: AtomicStringCell::default(),
        }
    }

    fn now_ts() -> i64 {
        chrono::Utc::now().timestamp()
    }

    fn record_primary_success(&self) {
        self.startup_probe_ran.store(true, Ordering::SeqCst);
        self.consecutive_primary_failures.store(0, Ordering::SeqCst);
        self.last_primary_success_ts
            .store(Self::now_ts(), Ordering::SeqCst);
    }

    fn record_primary_failure(&self) {
        self.startup_probe_ran.store(true, Ordering::SeqCst);
        self.consecutive_primary_failures
            .fetch_add(1, Ordering::SeqCst);
        self.last_primary_failure_ts
            .store(Self::now_ts(), Ordering::SeqCst);
    }

    fn record_fallback(&self, reason: String) {
        self.total_fallbacks.fetch_add(1, Ordering::SeqCst);
        self.last_fallback_reason.store_string(Some(reason));
    }

    fn snapshot(&self, primary_provider_name: Option<String>) -> MemoryBackendHealthSnapshot {
        MemoryBackendHealthSnapshot {
            external_provider_enabled: primary_provider_name.is_some(),
            primary_provider_name,
            startup_probe_ok: self
                .startup_probe_ran
                .load(Ordering::SeqCst)
                .then(|| self.startup_probe_ok.load(Ordering::SeqCst)),
            startup_probe_message: self.startup_probe_message.load_string(),
            consecutive_primary_failures: self.consecutive_primary_failures.load(Ordering::SeqCst),
            total_fallbacks: self.total_fallbacks.load(Ordering::SeqCst),
            last_primary_success_ts: nonzero_i64(
                self.last_primary_success_ts.load(Ordering::SeqCst),
            ),
            last_primary_failure_ts: nonzero_i64(
                self.last_primary_failure_ts.load(Ordering::SeqCst),
            ),
            last_fallback_reason: self.last_fallback_reason.load_string(),
        }
    }
}

#[derive(Default)]
struct AtomicStringCell(std::sync::Mutex<Option<String>>);

impl AtomicStringCell {
    fn store_string(&self, value: Option<String>) {
        *self.0.lock().expect("atomic string cell poisoned") = value;
    }

    fn load_string(&self) -> Option<String> {
        self.0.lock().expect("atomic string cell poisoned").clone()
    }
}

fn nonzero_i64(value: i64) -> Option<i64> {
    (value != 0).then_some(value)
}

struct SqliteMemoryProvider {
    db: Arc<Database>,
}

impl SqliteMemoryProvider {
    fn new(db: Arc<Database>) -> Self {
        Self { db }
    }
}

#[async_trait]
impl MemoryProvider for SqliteMemoryProvider {
    async fn get_all_memories_for_chat(
        &self,
        chat_id: Option<i64>,
    ) -> Result<Vec<Memory>, MicroClawError> {
        let chat = chat_id;
        call_blocking(self.db.clone(), move |db| {
            db.get_all_memories_for_chat(chat)
        })
        .await
    }

    async fn get_memories_for_context(
        &self,
        chat_id: i64,
        limit: usize,
    ) -> Result<Vec<Memory>, MicroClawError> {
        call_blocking(self.db.clone(), move |db| {
            db.get_memories_for_context(chat_id, limit)
        })
        .await
    }

    async fn search_memories_with_options(
        &self,
        chat_id: i64,
        query: &str,
        limit: usize,
        include_archived: bool,
        broad_recall: bool,
    ) -> Result<Vec<Memory>, MicroClawError> {
        let q = query.to_string();
        call_blocking(self.db.clone(), move |db| {
            db.search_memories_with_options(chat_id, &q, limit, include_archived, broad_recall)
        })
        .await
    }

    async fn get_memory_by_id(&self, id: i64) -> Result<Option<Memory>, MicroClawError> {
        call_blocking(self.db.clone(), move |db| db.get_memory_by_id(id)).await
    }

    async fn insert_memory_with_metadata(
        &self,
        chat_id: Option<i64>,
        content: &str,
        category: &str,
        source: &str,
        confidence: f64,
    ) -> Result<i64, MicroClawError> {
        let text = content.to_string();
        let cat = category.to_string();
        let src = source.to_string();
        call_blocking(self.db.clone(), move |db| {
            db.insert_memory_with_metadata(chat_id, &text, &cat, &src, confidence)
        })
        .await
    }

    async fn update_memory_with_metadata(
        &self,
        id: i64,
        content: &str,
        category: &str,
        confidence: f64,
        source: &str,
    ) -> Result<bool, MicroClawError> {
        let text = content.to_string();
        let cat = category.to_string();
        let src = source.to_string();
        call_blocking(self.db.clone(), move |db| {
            db.update_memory_with_metadata(id, &text, &cat, confidence, &src)
        })
        .await
    }

    async fn archive_memory(&self, id: i64) -> Result<bool, MicroClawError> {
        call_blocking(self.db.clone(), move |db| db.archive_memory(id)).await
    }

    async fn supersede_memory(
        &self,
        from_memory_id: i64,
        new_content: &str,
        category: &str,
        source: &str,
        confidence: f64,
        reason: Option<&str>,
    ) -> Result<i64, MicroClawError> {
        let text = new_content.to_string();
        let cat = category.to_string();
        let src = source.to_string();
        let why = reason.map(|value| value.to_string());
        call_blocking(self.db.clone(), move |db| {
            db.supersede_memory(
                from_memory_id,
                &text,
                &cat,
                &src,
                confidence,
                why.as_deref(),
            )
        })
        .await
    }

    async fn touch_memory_last_seen(
        &self,
        id: i64,
        confidence_floor: Option<f64>,
    ) -> Result<bool, MicroClawError> {
        call_blocking(self.db.clone(), move |db| {
            db.touch_memory_last_seen(id, confidence_floor)
        })
        .await
    }
}

struct McpMemoryProvider {
    client: MemoryMcpClient,
}

impl McpMemoryProvider {
    fn new(client: MemoryMcpClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl MemoryProvider for McpMemoryProvider {
    fn supports_local_semantic_ranking(&self) -> bool {
        false
    }

    async fn get_all_memories_for_chat(
        &self,
        chat_id: Option<i64>,
    ) -> Result<Vec<Memory>, MicroClawError> {
        let op = "memory_query(list)";
        let payload = serde_json::json!({
            "op": "list",
            "chat_id": chat_id,
        });
        let value = self
            .client
            .call_query(payload)
            .await
            .map_err(|err| classify_memory_error(op, err))?;
        parse_memory_list_strict(&value).map_err(|err| invalid_memory_payload(op, err))
    }

    async fn get_memories_for_context(
        &self,
        chat_id: i64,
        limit: usize,
    ) -> Result<Vec<Memory>, MicroClawError> {
        let op = "memory_query(context)";
        let payload = serde_json::json!({
            "op": "context",
            "chat_id": chat_id,
            "limit": limit,
        });
        let value = self
            .client
            .call_query(payload)
            .await
            .map_err(|err| classify_memory_error(op, err))?;
        parse_memory_list_strict(&value).map_err(|err| invalid_memory_payload(op, err))
    }

    async fn search_memories_with_options(
        &self,
        chat_id: i64,
        query: &str,
        limit: usize,
        include_archived: bool,
        broad_recall: bool,
    ) -> Result<Vec<Memory>, MicroClawError> {
        let op = "memory_query(search)";
        let payload = serde_json::json!({
            "op": "search",
            "chat_id": chat_id,
            "query": query,
            "limit": limit,
            "include_archived": include_archived,
            "broad_recall": broad_recall,
        });
        let value = self
            .client
            .call_query(payload)
            .await
            .map_err(|err| classify_memory_error(op, err))?;
        parse_memory_list_strict(&value).map_err(|err| invalid_memory_payload(op, err))
    }

    async fn get_memory_by_id(&self, id: i64) -> Result<Option<Memory>, MicroClawError> {
        let op = "memory_query(get)";
        let payload = serde_json::json!({
            "op": "get",
            "id": id,
        });
        let value = self
            .client
            .call_query(payload)
            .await
            .map_err(|err| classify_memory_error(op, err))?;
        if let Ok(memories) = parse_memory_list_strict(&value) {
            return Ok(memories.into_iter().next());
        }
        if let Ok(memory) = parse_single_memory_strict(&value) {
            return Ok(Some(memory));
        }
        Err(invalid_memory_payload(
            op,
            "expected single memory object or list response",
        ))
    }

    async fn insert_memory_with_metadata(
        &self,
        chat_id: Option<i64>,
        content: &str,
        category: &str,
        source: &str,
        confidence: f64,
    ) -> Result<i64, MicroClawError> {
        let op = "memory_upsert(insert)";
        let payload = serde_json::json!({
            "op": "insert",
            "chat_id": chat_id,
            "content": content,
            "category": category,
            "source": source,
            "confidence": confidence,
        });
        let value = self
            .client
            .call_upsert(payload)
            .await
            .map_err(|err| classify_memory_error(op, err))?;
        extract_id(&value).ok_or_else(|| invalid_memory_payload(op, "expected `id`/`memory_id`"))
    }

    async fn update_memory_with_metadata(
        &self,
        id: i64,
        content: &str,
        category: &str,
        confidence: f64,
        source: &str,
    ) -> Result<bool, MicroClawError> {
        let op = "memory_upsert(update)";
        let payload = serde_json::json!({
            "op": "update",
            "id": id,
            "content": content,
            "category": category,
            "source": source,
            "confidence": confidence,
        });
        let value = self
            .client
            .call_upsert(payload)
            .await
            .map_err(|err| classify_memory_error(op, err))?;
        extract_bool_flag(&value)
            .ok_or_else(|| invalid_memory_payload(op, "expected `updated`/`ok`/`success`"))
    }

    async fn archive_memory(&self, id: i64) -> Result<bool, MicroClawError> {
        let op = "memory_upsert(archive)";
        let payload = serde_json::json!({
            "op": "archive",
            "id": id,
        });
        let value = self
            .client
            .call_upsert(payload)
            .await
            .map_err(|err| classify_memory_error(op, err))?;
        extract_bool_flag(&value)
            .ok_or_else(|| invalid_memory_payload(op, "expected `updated`/`ok`/`success`"))
    }

    async fn supersede_memory(
        &self,
        from_memory_id: i64,
        new_content: &str,
        category: &str,
        source: &str,
        confidence: f64,
        reason: Option<&str>,
    ) -> Result<i64, MicroClawError> {
        let op = "memory_upsert(supersede)";
        let payload = serde_json::json!({
            "op": "supersede",
            "from_memory_id": from_memory_id,
            "content": new_content,
            "category": category,
            "source": source,
            "confidence": confidence,
            "reason": reason,
        });
        let value = self
            .client
            .call_upsert(payload)
            .await
            .map_err(|err| classify_memory_error(op, err))?;
        extract_id(&value).ok_or_else(|| invalid_memory_payload(op, "expected `id`/`memory_id`"))
    }

    async fn touch_memory_last_seen(
        &self,
        id: i64,
        confidence_floor: Option<f64>,
    ) -> Result<bool, MicroClawError> {
        let op = "memory_upsert(touch)";
        let payload = serde_json::json!({
            "op": "touch",
            "id": id,
            "confidence_floor": confidence_floor,
        });
        let value = self
            .client
            .call_upsert(payload)
            .await
            .map_err(|err| classify_memory_error(op, err))?;
        extract_bool_flag(&value)
            .ok_or_else(|| invalid_memory_payload(op, "expected `updated`/`ok`/`success`"))
    }
}

struct FallbackMemoryProvider {
    primary: Arc<dyn MemoryProvider>,
    fallback: Arc<dyn MemoryProvider>,
    stats: Arc<MemoryBackendStats>,
    primary_name: String,
}

impl FallbackMemoryProvider {
    fn new(
        primary: Arc<dyn MemoryProvider>,
        fallback: Arc<dyn MemoryProvider>,
        stats: Arc<MemoryBackendStats>,
        primary_name: String,
    ) -> Self {
        Self {
            primary,
            fallback,
            stats,
            primary_name,
        }
    }

    async fn fallback_on_err<T, FutPrimary, FutFallback>(
        &self,
        op_name: &str,
        primary: FutPrimary,
        fallback: FutFallback,
    ) -> Result<T, MicroClawError>
    where
        FutPrimary: std::future::Future<Output = Result<T, MicroClawError>>,
        FutFallback: std::future::Future<Output = Result<T, MicroClawError>>,
    {
        match primary.await {
            Ok(value) => {
                self.stats.record_primary_success();
                Ok(value)
            }
            Err(err) => {
                self.stats.record_primary_failure();
                let reason = fallback_reason_for_error(op_name, &err);
                self.stats.record_fallback(reason.clone());
                warn!(
                    "{op_name} failed via primary memory provider '{}' ({reason}; {err}); falling back",
                    self.primary_name,
                );
                fallback.await
            }
        }
    }
}

#[async_trait]
impl MemoryProvider for FallbackMemoryProvider {
    fn supports_local_semantic_ranking(&self) -> bool {
        self.primary.supports_local_semantic_ranking()
    }

    async fn get_all_memories_for_chat(
        &self,
        chat_id: Option<i64>,
    ) -> Result<Vec<Memory>, MicroClawError> {
        self.fallback_on_err(
            "memory_query(list)",
            self.primary.get_all_memories_for_chat(chat_id),
            self.fallback.get_all_memories_for_chat(chat_id),
        )
        .await
    }

    async fn get_memories_for_context(
        &self,
        chat_id: i64,
        limit: usize,
    ) -> Result<Vec<Memory>, MicroClawError> {
        self.fallback_on_err(
            "memory_query(context)",
            self.primary.get_memories_for_context(chat_id, limit),
            self.fallback.get_memories_for_context(chat_id, limit),
        )
        .await
    }

    async fn search_memories_with_options(
        &self,
        chat_id: i64,
        query: &str,
        limit: usize,
        include_archived: bool,
        broad_recall: bool,
    ) -> Result<Vec<Memory>, MicroClawError> {
        self.fallback_on_err(
            "memory_query(search)",
            self.primary.search_memories_with_options(
                chat_id,
                query,
                limit,
                include_archived,
                broad_recall,
            ),
            self.fallback.search_memories_with_options(
                chat_id,
                query,
                limit,
                include_archived,
                broad_recall,
            ),
        )
        .await
    }

    async fn get_memory_by_id(&self, id: i64) -> Result<Option<Memory>, MicroClawError> {
        self.fallback_on_err(
            "memory_query(get)",
            self.primary.get_memory_by_id(id),
            self.fallback.get_memory_by_id(id),
        )
        .await
    }

    async fn insert_memory_with_metadata(
        &self,
        chat_id: Option<i64>,
        content: &str,
        category: &str,
        source: &str,
        confidence: f64,
    ) -> Result<i64, MicroClawError> {
        self.fallback_on_err(
            "memory_upsert(insert)",
            self.primary
                .insert_memory_with_metadata(chat_id, content, category, source, confidence),
            self.fallback
                .insert_memory_with_metadata(chat_id, content, category, source, confidence),
        )
        .await
    }

    async fn update_memory_with_metadata(
        &self,
        id: i64,
        content: &str,
        category: &str,
        confidence: f64,
        source: &str,
    ) -> Result<bool, MicroClawError> {
        self.fallback_on_err(
            "memory_upsert(update)",
            self.primary
                .update_memory_with_metadata(id, content, category, confidence, source),
            self.fallback
                .update_memory_with_metadata(id, content, category, confidence, source),
        )
        .await
    }

    async fn archive_memory(&self, id: i64) -> Result<bool, MicroClawError> {
        self.fallback_on_err(
            "memory_upsert(archive)",
            self.primary.archive_memory(id),
            self.fallback.archive_memory(id),
        )
        .await
    }

    async fn supersede_memory(
        &self,
        from_memory_id: i64,
        new_content: &str,
        category: &str,
        source: &str,
        confidence: f64,
        reason: Option<&str>,
    ) -> Result<i64, MicroClawError> {
        self.fallback_on_err(
            "memory_upsert(supersede)",
            self.primary.supersede_memory(
                from_memory_id,
                new_content,
                category,
                source,
                confidence,
                reason,
            ),
            self.fallback.supersede_memory(
                from_memory_id,
                new_content,
                category,
                source,
                confidence,
                reason,
            ),
        )
        .await
    }

    async fn touch_memory_last_seen(
        &self,
        id: i64,
        confidence_floor: Option<f64>,
    ) -> Result<bool, MicroClawError> {
        self.fallback_on_err(
            "memory_upsert(touch)",
            self.primary.touch_memory_last_seen(id, confidence_floor),
            self.fallback.touch_memory_last_seen(id, confidence_floor),
        )
        .await
    }
}

fn parse_json_loose(text: &str) -> Result<serde_json::Value, String> {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
        return Ok(v);
    }
    for (open, close) in [(b'[', b']'), (b'{', b'}')] {
        if let Some(start) = text.as_bytes().iter().position(|b| *b == open) {
            if let Some(end) = text.as_bytes().iter().rposition(|b| *b == close) {
                if start < end {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text[start..=end]) {
                        return Ok(v);
                    }
                }
            }
        }
    }
    Err("MCP memory response is not valid JSON".to_string())
}

fn fallback_reason_for_error(op_name: &str, err: &MicroClawError) -> String {
    let structured = match err {
        MicroClawError::ToolExecution(message) => Some(message.as_str()),
        _ => None,
    };
    if let Some(message) = structured.filter(|message| message.starts_with(op_name)) {
        if let Some((_, rest)) = message.split_once('[') {
            if let Some((kind, _)) = rest.split_once(']') {
                let normalized = kind.trim().to_ascii_lowercase().replace(' ', "_");
                if !normalized.is_empty() {
                    return format!("{op_name}:{normalized}");
                }
            }
        }
    }
    let err_text = err.to_string();
    MemoryProviderFailure::classify(op_name.to_string(), err_text).fallback_reason()
}

fn parse_memory_list_strict(value: &serde_json::Value) -> Result<Vec<Memory>, String> {
    let arr = if let Some(arr) = value.as_array() {
        arr
    } else if let Some(obj) = value.as_object() {
        if let Some(arr) = obj.get("memories").and_then(|v| v.as_array()) {
            arr
        } else if let Some(arr) = obj.get("items").and_then(|v| v.as_array()) {
            arr
        } else {
            return Err(
                "memory payload must be an array or an object with `memories`/`items`".to_string(),
            );
        }
    } else {
        return Err("memory payload must be JSON array/object".to_string());
    };

    let mut out = Vec::with_capacity(arr.len());
    for (idx, item) in arr.iter().enumerate() {
        out.push(
            parse_single_memory_strict(item)
                .map_err(|err| format!("invalid memory at index {idx}: {err}"))?,
        );
    }
    Ok(out)
}

fn parse_single_memory_strict(value: &serde_json::Value) -> Result<Memory, String> {
    let obj = value
        .as_object()
        .ok_or_else(|| "memory item must be an object".to_string())?;
    let id = obj
        .get("id")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| "missing numeric `id`".to_string())?;
    let content = obj
        .get("content")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| "missing non-empty `content`".to_string())?
        .to_string();
    let category = obj
        .get("category")
        .and_then(|v| v.as_str())
        .unwrap_or("KNOWLEDGE")
        .to_string();
    let now = chrono::Utc::now().to_rfc3339();
    Ok(Memory {
        id,
        chat_id: obj.get("chat_id").and_then(|v| v.as_i64()),
        content,
        category,
        created_at: obj
            .get("created_at")
            .and_then(|v| v.as_str())
            .unwrap_or(&now)
            .to_string(),
        updated_at: obj
            .get("updated_at")
            .and_then(|v| v.as_str())
            .unwrap_or(&now)
            .to_string(),
        embedding_model: obj
            .get("embedding_model")
            .and_then(|v| v.as_str())
            .map(|v| v.to_string()),
        confidence: obj
            .get("confidence")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.8),
        source: obj
            .get("source")
            .and_then(|v| v.as_str())
            .unwrap_or("mcp_memory")
            .to_string(),
        last_seen_at: obj
            .get("last_seen_at")
            .and_then(|v| v.as_str())
            .unwrap_or(&now)
            .to_string(),
        is_archived: obj
            .get("is_archived")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        archived_at: obj
            .get("archived_at")
            .and_then(|v| v.as_str())
            .map(|v| v.to_string()),
        expires_at: obj
            .get("expires_at")
            .and_then(|v| v.as_str())
            .map(|v| v.to_string()),
    })
}

fn extract_id(value: &serde_json::Value) -> Option<i64> {
    value
        .get("id")
        .and_then(|v| v.as_i64())
        .or_else(|| value.get("memory_id").and_then(|v| v.as_i64()))
        .or_else(|| {
            value
                .get("memory")
                .and_then(|v| v.get("id"))
                .and_then(|v| v.as_i64())
        })
}

fn extract_bool_flag(value: &serde_json::Value) -> Option<bool> {
    value
        .get("updated")
        .and_then(|v| v.as_bool())
        .or_else(|| value.get("ok").and_then(|v| v.as_bool()))
        .or_else(|| value.get("success").and_then(|v| v.as_bool()))
}

#[allow(dead_code)]
fn _extract_tool_info(tools: &[McpToolInfo]) -> Vec<String> {
    tools.iter().map(|t| t.name.clone()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn sample_memory(id: i64, content: &str) -> Memory {
        Memory {
            id,
            chat_id: Some(42),
            content: content.to_string(),
            category: "KNOWLEDGE".to_string(),
            created_at: "2026-03-10T00:00:00Z".to_string(),
            updated_at: "2026-03-10T00:00:00Z".to_string(),
            embedding_model: None,
            confidence: 0.9,
            source: "test".to_string(),
            last_seen_at: "2026-03-10T00:00:00Z".to_string(),
            is_archived: false,
            archived_at: None,
            expires_at: None,
        }
    }

    struct FakeProvider {
        supports_local_semantic_ranking: bool,
        get_context_memories: Vec<Memory>,
        get_context_error: Option<String>,
        get_context_calls: AtomicUsize,
    }

    impl FakeProvider {
        fn success(memories: Vec<Memory>, supports_local_semantic_ranking: bool) -> Self {
            Self {
                supports_local_semantic_ranking,
                get_context_memories: memories,
                get_context_error: None,
                get_context_calls: AtomicUsize::new(0),
            }
        }

        fn failure(message: &str, supports_local_semantic_ranking: bool) -> Self {
            Self {
                supports_local_semantic_ranking,
                get_context_memories: Vec::new(),
                get_context_error: Some(message.to_string()),
                get_context_calls: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl MemoryProvider for FakeProvider {
        fn supports_local_semantic_ranking(&self) -> bool {
            self.supports_local_semantic_ranking
        }

        async fn get_all_memories_for_chat(
            &self,
            _chat_id: Option<i64>,
        ) -> Result<Vec<Memory>, MicroClawError> {
            Ok(vec![sample_memory(1, "all")])
        }

        async fn get_memories_for_context(
            &self,
            _chat_id: i64,
            _limit: usize,
        ) -> Result<Vec<Memory>, MicroClawError> {
            self.get_context_calls.fetch_add(1, Ordering::SeqCst);
            match &self.get_context_error {
                Some(message) => Err(MicroClawError::ToolExecution(message.clone())),
                None => Ok(self.get_context_memories.clone()),
            }
        }

        async fn search_memories_with_options(
            &self,
            _chat_id: i64,
            _query: &str,
            _limit: usize,
            _include_archived: bool,
            _broad_recall: bool,
        ) -> Result<Vec<Memory>, MicroClawError> {
            Ok(vec![sample_memory(2, "search")])
        }

        async fn get_memory_by_id(&self, id: i64) -> Result<Option<Memory>, MicroClawError> {
            Ok(Some(sample_memory(id, "by-id")))
        }

        async fn insert_memory_with_metadata(
            &self,
            _chat_id: Option<i64>,
            _content: &str,
            _category: &str,
            _source: &str,
            _confidence: f64,
        ) -> Result<i64, MicroClawError> {
            Ok(10)
        }

        async fn update_memory_with_metadata(
            &self,
            _id: i64,
            _content: &str,
            _category: &str,
            _confidence: f64,
            _source: &str,
        ) -> Result<bool, MicroClawError> {
            Ok(true)
        }

        async fn archive_memory(&self, _id: i64) -> Result<bool, MicroClawError> {
            Ok(true)
        }

        async fn supersede_memory(
            &self,
            _from_memory_id: i64,
            _new_content: &str,
            _category: &str,
            _source: &str,
            _confidence: f64,
            _reason: Option<&str>,
        ) -> Result<i64, MicroClawError> {
            Ok(11)
        }

        async fn touch_memory_last_seen(
            &self,
            _id: i64,
            _confidence_floor: Option<f64>,
        ) -> Result<bool, MicroClawError> {
            Ok(true)
        }
    }

    #[tokio::test]
    async fn test_backend_capability_reflects_provider() {
        let backend = MemoryBackend::from_provider(Arc::new(FakeProvider::success(
            vec![sample_memory(1, "x")],
            false,
        )));
        assert!(!backend.supports_local_semantic_ranking());
    }

    #[tokio::test]
    async fn test_fallback_provider_uses_fallback_on_error() {
        let primary = Arc::new(FakeProvider::failure("boom", false));
        let fallback = Arc::new(FakeProvider::success(
            vec![sample_memory(7, "from fallback")],
            true,
        ));
        let stats = Arc::new(MemoryBackendStats::new());
        let backend = MemoryBackend::from_provider_with_stats(
            Arc::new(FallbackMemoryProvider::new(
                primary.clone(),
                fallback.clone(),
                stats.clone(),
                "fake-primary".to_string(),
            )),
            stats,
            Some("fake-primary".to_string()),
        );

        let memories = backend.get_memories_for_context(42, 10).await.unwrap();
        let snapshot = backend.provider_health_snapshot();
        assert_eq!(memories.len(), 1);
        assert_eq!(memories[0].content, "from fallback");
        assert_eq!(primary.get_context_calls.load(Ordering::SeqCst), 1);
        assert_eq!(fallback.get_context_calls.load(Ordering::SeqCst), 1);
        assert_eq!(snapshot.total_fallbacks, 1);
        assert_eq!(snapshot.consecutive_primary_failures, 1);
        assert_eq!(
            snapshot.last_fallback_reason.as_deref(),
            Some("memory_query(context):transport")
        );
        assert!(!backend.supports_local_semantic_ranking());
    }

    #[test]
    fn test_memory_provider_failure_classifies_timeout() {
        let failure = MemoryProviderFailure::classify(
            "memory_query(context)",
            "MCP tool call timed out for 'memory' after 60s",
        );
        assert_eq!(failure.kind, MemoryProviderErrorKind::Timeout);
        assert_eq!(failure.fallback_reason(), "memory_query(context):timeout");
    }

    #[test]
    fn test_memory_provider_failure_classifies_unsupported_operation() {
        let failure = MemoryProviderFailure::classify(
            "memory_upsert(insert)",
            "tool not found: memory_upsert",
        );
        assert_eq!(failure.kind, MemoryProviderErrorKind::UnsupportedOperation);
        assert_eq!(
            failure.fallback_reason(),
            "memory_upsert(insert):unsupported_operation"
        );
    }

    #[test]
    fn test_invalid_memory_payload_uses_stable_category() {
        let err = invalid_memory_payload("memory_query(get)", "expected single memory object");
        let reason = fallback_reason_for_error("memory_query(get)", &err);
        assert_eq!(reason, "memory_query(get):invalid_payload");
        assert!(err
            .to_string()
            .contains("memory_query(get) [invalid_payload]"));
    }

    #[test]
    fn test_parse_memory_list_strict_rejects_invalid_item() {
        let payload = serde_json::json!({
            "memories": [
                {"id": 1, "content": "ok"},
                {"id": 2}
            ]
        });
        let err = parse_memory_list_strict(&payload).unwrap_err();
        assert!(err.contains("invalid memory at index 1"));
    }

    #[test]
    fn test_parse_memory_list_strict_accepts_empty_array() {
        let payload = serde_json::json!([]);
        let memories = parse_memory_list_strict(&payload).unwrap();
        assert!(memories.is_empty());
    }

    #[test]
    fn test_parse_single_memory_strict_rejects_blank_content() {
        let payload = serde_json::json!({"id": 1, "content": "   "});
        let err = parse_single_memory_strict(&payload).unwrap_err();
        assert!(err.contains("missing non-empty `content`"));
    }
}
