#![allow(unused_imports)]

use super::*;

pub(crate) use crate::config::{Config, LlmProviderProfile, WorkingDirIsolation};

pub(crate) use crate::llm::LlmProvider;

pub(crate) use crate::{
    db::Database, memory::MemoryManager, skills::SkillManager, tools::ToolRegistry,
};

pub(crate) use crate::{error::MicroClawError, llm_types::ResponseContentBlock};

pub(crate) use axum::body::Body;

pub(crate) use axum::http::{Request, StatusCode};

pub(crate) use futures_util::{SinkExt, StreamExt};

pub(crate) use microclaw_channels::channel_adapter::ChannelRegistry;

pub(crate) use microclaw_storage::db::call_blocking;

pub(crate) use serde_json::json;

pub(crate) use std::sync::atomic::{AtomicUsize, Ordering};

pub(crate) use tower::ServiceExt;

pub(crate) struct DummyLlm;

#[async_trait::async_trait]
impl LlmProvider for DummyLlm {
    async fn send_message(
        &self,
        _system: &str,
        _messages: Vec<microclaw_core::llm_types::Message>,
        _tools: Option<Vec<microclaw_core::llm_types::ToolDefinition>>,
    ) -> Result<microclaw_core::llm_types::MessagesResponse, microclaw_core::error::MicroClawError>
    {
        Ok(microclaw_core::llm_types::MessagesResponse {
            content: vec![microclaw_core::llm_types::ResponseContentBlock::Text {
                text: "hello from llm".into(),
            }],
            stop_reason: Some("end_turn".into()),
            usage: None,
        })
    }

    async fn send_message_stream(
        &self,
        _system: &str,
        _messages: Vec<microclaw_core::llm_types::Message>,
        _tools: Option<Vec<microclaw_core::llm_types::ToolDefinition>>,
        text_tx: Option<&tokio::sync::mpsc::UnboundedSender<String>>,
    ) -> Result<microclaw_core::llm_types::MessagesResponse, microclaw_core::error::MicroClawError>
    {
        if let Some(tx) = text_tx {
            let _ = tx.send("hello ".into());
            let _ = tx.send("from llm".into());
        }
        self.send_message("", vec![], None).await
    }
}

pub(crate) struct SlowLlm {
    pub(crate) sleep_ms: u64,
}

#[async_trait::async_trait]
impl LlmProvider for SlowLlm {
    async fn send_message(
        &self,
        _system: &str,
        _messages: Vec<microclaw_core::llm_types::Message>,
        _tools: Option<Vec<microclaw_core::llm_types::ToolDefinition>>,
    ) -> Result<microclaw_core::llm_types::MessagesResponse, MicroClawError> {
        tokio::time::sleep(Duration::from_millis(self.sleep_ms)).await;
        Ok(microclaw_core::llm_types::MessagesResponse {
            content: vec![ResponseContentBlock::Text {
                text: "slow".into(),
            }],
            stop_reason: Some("end_turn".into()),
            usage: None,
        })
    }
}

pub(crate) struct ThinkingLlm;

#[async_trait::async_trait]
impl LlmProvider for ThinkingLlm {
    async fn send_message(
        &self,
        _system: &str,
        _messages: Vec<microclaw_core::llm_types::Message>,
        _tools: Option<Vec<microclaw_core::llm_types::ToolDefinition>>,
    ) -> Result<microclaw_core::llm_types::MessagesResponse, MicroClawError> {
        Ok(microclaw_core::llm_types::MessagesResponse {
            content: vec![ResponseContentBlock::Text {
                text: "<thinking>internal</thinking>Visible".into(),
            }],
            stop_reason: Some("end_turn".into()),
            usage: None,
        })
    }
}

pub(crate) struct ToolFlowLlm {
    pub(crate) calls: AtomicUsize,
}

#[async_trait::async_trait]
impl LlmProvider for ToolFlowLlm {
    async fn send_message(
        &self,
        _system: &str,
        _messages: Vec<microclaw_core::llm_types::Message>,
        _tools: Option<Vec<microclaw_core::llm_types::ToolDefinition>>,
    ) -> Result<microclaw_core::llm_types::MessagesResponse, MicroClawError> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        if n == 0 {
            return Ok(microclaw_core::llm_types::MessagesResponse {
                content: vec![ResponseContentBlock::ToolUse {
                    id: "tool_1".into(),
                    name: "glob".into(),
                    input: json!({"pattern": "*.rs", "path": "."}),
                    thought_signature: None,
                }],
                stop_reason: Some("tool_use".into()),
                usage: None,
            });
        }
        Ok(microclaw_core::llm_types::MessagesResponse {
            content: vec![ResponseContentBlock::Text {
                text: "after tool".into(),
            }],
            stop_reason: Some("end_turn".into()),
            usage: None,
        })
    }
}

pub(crate) struct SendMessageThenAnswerLlm {
    pub(crate) calls: AtomicUsize,
}

#[async_trait::async_trait]
impl LlmProvider for SendMessageThenAnswerLlm {
    async fn send_message(
        &self,
        _system: &str,
        _messages: Vec<microclaw_core::llm_types::Message>,
        _tools: Option<Vec<microclaw_core::llm_types::ToolDefinition>>,
    ) -> Result<microclaw_core::llm_types::MessagesResponse, MicroClawError> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        if n == 0 {
            return Ok(microclaw_core::llm_types::MessagesResponse {
                content: vec![ResponseContentBlock::ToolUse {
                    id: "tool_send_1".into(),
                    name: "send_message".into(),
                    input: json!({"text": "tool reply"}),
                    thought_signature: None,
                }],
                stop_reason: Some("tool_use".into()),
                usage: None,
            });
        }
        Ok(microclaw_core::llm_types::MessagesResponse {
            content: vec![ResponseContentBlock::Text {
                text: "final reply".into(),
            }],
            stop_reason: Some("end_turn".into()),
            usage: None,
        })
    }
}

pub(crate) fn test_config_template() -> Config {
    let mut cfg = Config::test_defaults();
    cfg.working_dir_isolation = WorkingDirIsolation::Shared;
    cfg.web_port = 3900;
    cfg
}

pub(crate) fn with_hooks_token(mut cfg: Config, token: &str) -> Config {
    let mut web = serde_yaml::Mapping::new();
    web.insert(
        serde_yaml::Value::String("hooks_token".to_string()),
        serde_yaml::Value::String(token.to_string()),
    );
    cfg.channels
        .insert("web".to_string(), serde_yaml::Value::Mapping(web));
    cfg
}

pub(crate) fn with_hooks_session_key_policy(
    mut cfg: Config,
    allow_request: bool,
    prefixes: &[&str],
) -> Config {
    let mut web = cfg
        .channels
        .get("web")
        .and_then(|v| v.as_mapping())
        .cloned()
        .unwrap_or_default();
    web.insert(
        serde_yaml::Value::String("hooks_allow_request_session_key".to_string()),
        serde_yaml::Value::Bool(allow_request),
    );
    if !prefixes.is_empty() {
        web.insert(
            serde_yaml::Value::String("hooks_allowed_session_key_prefixes".to_string()),
            serde_yaml::Value::Sequence(
                prefixes
                    .iter()
                    .map(|p| serde_yaml::Value::String((*p).to_string()))
                    .collect(),
            ),
        );
    }
    cfg.channels
        .insert("web".to_string(), serde_yaml::Value::Mapping(web));
    cfg
}

pub(crate) fn test_state_with_config(llm: Box<dyn LlmProvider>, mut cfg: Config) -> Arc<AppState> {
    let dir = std::env::temp_dir().join(format!("microclaw_webtest_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    cfg.data_dir = dir.to_string_lossy().to_string();
    cfg.working_dir = dir.join("tmp").to_string_lossy().to_string();
    let runtime_dir = cfg.runtime_data_dir();
    std::fs::create_dir_all(&runtime_dir).unwrap();
    let db = Arc::new(Database::new(&runtime_dir).unwrap());
    let memory_backend = Arc::new(crate::memory_backend::MemoryBackend::local_only(db.clone()));
    let mut registry = ChannelRegistry::new();
    registry.register(Arc::new(WebAdapter));
    let channel_registry = Arc::new(registry);
    let state = AppState {
        config: cfg.clone(),
        channel_registry: channel_registry.clone(),
        db: db.clone(),
        memory: Arc::new(MemoryManager::new(&runtime_dir)),
        skills: Arc::new(SkillManager::from_skills_dir(&cfg.skills_data_dir())),
        hooks: Arc::new(crate::hooks::HookManager::for_tests()),
        llm: Arc::from(llm),
        llm_provider_overrides: Arc::new(
            tokio::sync::RwLock::new(std::collections::HashMap::new()),
        ),
        llm_model_overrides: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
        embedding: None,
        memory_backend: memory_backend.clone(),
        tools: Arc::new(ToolRegistry::new(
            &cfg,
            channel_registry,
            db,
            memory_backend,
        )),
        chat_turn_queue: Arc::new(crate::chat_turn_queue::ChatTurnQueue::new(20)),
        skill_review_queue: crate::skill_review::build_skill_review_channel().0,
        metric_exporter: None,
        trace_exporter: None,
        log_exporter: None,
    };
    Arc::new(state)
}

pub(crate) fn test_state(llm: Box<dyn LlmProvider>) -> Arc<AppState> {
    test_state_with_config(llm, test_config_template())
}

pub(crate) fn test_web_state_from_app_state(state: Arc<AppState>, limits: WebLimits) -> WebState {
    WebState {
        app_state: state,
        bootstrap_token: Arc::new(Mutex::new(None)),
        run_hub: RunHub::default(),
        session_hub: SessionHub::default(),
        request_hub: RequestHub::default(),
        auth_hub: AuthHub::default(),
        metrics: Arc::new(Mutex::new(WebMetrics::default())),
        otlp: None,
        limits,
    }
}

pub(crate) fn test_web_state(llm: Box<dyn LlmProvider>, limits: WebLimits) -> WebState {
    test_web_state_from_app_state(test_state(llm), limits)
}

pub(crate) async fn seed_test_api_key(state: &WebState, secret: &str) {
    seed_test_api_key_with_scopes(
        state,
        secret,
        &[
            "operator.read".to_string(),
            "operator.write".to_string(),
            "operator.admin".to_string(),
        ],
    )
    .await;
}

pub(crate) async fn seed_test_api_key_with_scopes(
    state: &WebState,
    secret: &str,
    scopes: &[String],
) {
    let secret_owned = secret.to_string();
    let key_hash = sha256_hex(&secret_owned);
    let safe_end = microclaw_core::text::floor_char_boundary(&secret_owned, 6);
    let prefix = secret_owned[..safe_end].to_string();
    let scopes = scopes.to_vec();
    call_blocking(state.app_state.db.clone(), move |db| {
        db.upsert_auth_password_hash(&make_password_hash("passw0rd!"))?;
        db.create_api_key("ws-test", &key_hash, &prefix, &scopes, None, None)?;
        Ok(())
    })
    .await
    .unwrap();
}

pub(crate) async fn spawn_test_server(
    app: Router,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, handle)
}

pub(crate) async fn recv_ws_json(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> serde_json::Value {
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(10), ws.next())
            .await
            .expect("ws timeout")
            .expect("ws closed")
            .expect("ws message");
        if let tokio_tungstenite::tungstenite::Message::Text(text) = msg {
            return serde_json::from_str(&text).unwrap();
        }
    }
}

pub(crate) fn unique_test_chat_id() -> i64 {
    static NEXT_TEST_CHAT_ID: AtomicUsize = AtomicUsize::new(10_000);
    NEXT_TEST_CHAT_ID.fetch_add(1, Ordering::Relaxed) as i64
}
