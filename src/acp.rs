use crate::agent_engine::{process_with_agent_with_events, AgentEvent, AgentRequestContext};
use crate::chat_commands::handle_chat_command;
use crate::config::Config;
use crate::embedding;
use crate::hooks::HookManager;
use crate::llm;
use crate::memory::MemoryManager;
use crate::memory_backend::{MemoryBackend, MemoryMcpClient};
use crate::runtime::AppState;
use crate::skills::SkillManager;
use crate::tools::ToolRegistry;
use agent_client_protocol::{
    Agent, AgentCapabilities, AgentSideConnection, AuthenticateRequest, AuthenticateResponse,
    AvailableCommand, AvailableCommandsUpdate, CancelNotification, Client, ContentBlock,
    ContentChunk, CurrentModeUpdate, Error, Implementation, InitializeRequest, InitializeResponse,
    LoadSessionRequest, LoadSessionResponse, McpCapabilities, NewSessionRequest,
    NewSessionResponse, PromptCapabilities, PromptRequest, PromptResponse, Result as AcpResult,
    SessionId, SessionMode, SessionModeState, SessionUpdate, SetSessionModeRequest,
    SetSessionModeResponse, StopReason,
};
use microclaw_channels::channel::ConversationKind;
use microclaw_channels::channel_adapter::{ChannelAdapter, ChannelRegistry};
use microclaw_storage::db::{call_blocking, Database, StoredMessage};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
use tracing::warn;

const ACP_CHANNEL: &str = "acp";
const ACP_CHAT_TYPE: &str = "acp";
const ACP_MODE_ID: &str = "chat";

pub async fn serve(
    config: Config,
    db: Database,
    memory: MemoryManager,
    skills: SkillManager,
    mcp_manager: crate::mcp::McpManager,
) -> anyhow::Result<()> {
    let db = Arc::new(db);
    let llm = llm::create_provider(&config);
    let embedding = embedding::create_provider(&config);
    let mut registry = ChannelRegistry::new();
    registry.register(Arc::new(AcpAdapter));
    let channel_registry = Arc::new(registry);

    let memory_backend = Arc::new(MemoryBackend::new(
        db.clone(),
        MemoryMcpClient::discover(&mcp_manager),
    ));
    let mut tools = ToolRegistry::new(
        &config,
        channel_registry.clone(),
        db.clone(),
        memory_backend.clone(),
    );
    for (server, tool_info) in mcp_manager.all_tools() {
        tools.add_tool(Box::new(crate::tools::mcp::McpTool::new(server, tool_info)));
    }

    let app_state = Arc::new(AppState {
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
    });

    crate::scheduler::spawn_scheduler(app_state.clone());
    crate::scheduler::spawn_reflector(app_state.clone());

    let local = tokio::task::LocalSet::new();
    local
        .run_until(async move {
            let stdin = tokio::io::stdin().compat();
            let stdout = tokio::io::stdout().compat_write();
            let (outbound_tx, mut outbound_rx) = mpsc::unbounded_channel::<OutboundNotification>();
            let agent = MicroClawAcpAgent::new(app_state, outbound_tx);
            let (client, io) = AgentSideConnection::new(agent, stdout, stdin, |fut| {
                tokio::task::spawn_local(fut);
            });

            let notify_task = tokio::task::spawn_local(async move {
                while let Some(notification) = outbound_rx.recv().await {
                    if let Err(err) = client.session_notification(notification.into()).await {
                        warn!("ACP session update failed: {err}");
                        break;
                    }
                }
            });

            let io_result = io.await;
            notify_task.abort();
            io_result.map_err(|err| anyhow::anyhow!("ACP transport failed: {err}"))
        })
        .await
}

#[derive(Clone)]
struct MicroClawAcpAgent {
    app_state: Arc<AppState>,
    outbound_tx: mpsc::UnboundedSender<OutboundNotification>,
    sessions: Arc<RwLock<HashMap<String, SessionState>>>,
}

impl MicroClawAcpAgent {
    fn new(
        app_state: Arc<AppState>,
        outbound_tx: mpsc::UnboundedSender<OutboundNotification>,
    ) -> Self {
        Self {
            app_state,
            outbound_tx,
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn ensure_session(
        &self,
        session_id: &SessionId,
        cwd: PathBuf,
    ) -> anyhow::Result<(i64, SessionState)> {
        let session_key = session_id.0.to_string();
        let session_key_for_db = session_key.clone();
        let chat_id = call_blocking(self.app_state.db.clone(), move |db| {
            db.resolve_or_create_chat_id(
                ACP_CHANNEL,
                &session_key_for_db,
                Some(&session_key_for_db),
                ACP_CHAT_TYPE,
            )
        })
        .await?;

        let mut sessions = self.sessions.write().await;
        let entry = sessions
            .entry(session_key)
            .and_modify(|state| {
                state.cwd = cwd.clone();
            })
            .or_insert_with(|| SessionState { cwd });
        Ok((chat_id, entry.clone()))
    }

    async fn load_history(&self, session_id: &SessionId, chat_id: i64) -> anyhow::Result<()> {
        let messages = call_blocking(self.app_state.db.clone(), move |db| {
            db.get_all_messages(chat_id)
        })
        .await?;
        for message in messages {
            let update = if message.is_from_bot {
                SessionUpdate::AgentMessageChunk(ContentChunk::new(message.content.into()))
            } else {
                SessionUpdate::UserMessageChunk(ContentChunk::new(message.content.into()))
            };
            self.send_update(session_id.clone(), update)?;
        }
        Ok(())
    }

    fn send_update(&self, session_id: SessionId, update: SessionUpdate) -> AcpResult<()> {
        self.outbound_tx
            .send(OutboundNotification { session_id, update })
            .map_err(|_| Error::internal_error())
    }

    async fn store_message(
        &self,
        chat_id: i64,
        sender_name: &str,
        content: String,
        is_from_bot: bool,
    ) -> anyhow::Result<()> {
        let message = StoredMessage {
            id: uuid::Uuid::new_v4().to_string(),
            chat_id,
            sender_name: sender_name.to_string(),
            content,
            is_from_bot,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        call_blocking(self.app_state.db.clone(), move |db| {
            db.store_message(&message)
        })
        .await?;
        Ok(())
    }
}

#[async_trait::async_trait(?Send)]
impl Agent for MicroClawAcpAgent {
    async fn initialize(&self, args: InitializeRequest) -> AcpResult<InitializeResponse> {
        Ok(InitializeResponse::new(args.protocol_version)
            .agent_info(
                Implementation::new("microclaw", env!("CARGO_PKG_VERSION")).title("MicroClaw"),
            )
            .agent_capabilities(
                AgentCapabilities::new()
                    .load_session(true)
                    .prompt_capabilities(PromptCapabilities::new().embedded_context(true))
                    .mcp_capabilities(McpCapabilities::new()),
            ))
    }

    async fn authenticate(&self, _args: AuthenticateRequest) -> AcpResult<AuthenticateResponse> {
        Ok(AuthenticateResponse::new())
    }

    async fn new_session(&self, args: NewSessionRequest) -> AcpResult<NewSessionResponse> {
        let session_id = SessionId::new(uuid::Uuid::new_v4().to_string());
        self.ensure_session(&session_id, args.cwd)
            .await
            .map_err(to_acp_error)?;
        self.send_update(
            session_id.clone(),
            SessionUpdate::AvailableCommandsUpdate(AvailableCommandsUpdate::new(
                available_commands(),
            )),
        )?;
        Ok(NewSessionResponse::new(session_id).modes(default_mode_state()))
    }

    async fn load_session(&self, args: LoadSessionRequest) -> AcpResult<LoadSessionResponse> {
        let (chat_id, _) = self
            .ensure_session(&args.session_id, args.cwd)
            .await
            .map_err(to_acp_error)?;
        self.send_update(
            args.session_id.clone(),
            SessionUpdate::AvailableCommandsUpdate(AvailableCommandsUpdate::new(
                available_commands(),
            )),
        )?;
        self.load_history(&args.session_id, chat_id)
            .await
            .map_err(to_acp_error)?;
        Ok(LoadSessionResponse::new().modes(default_mode_state()))
    }

    async fn set_session_mode(
        &self,
        args: SetSessionModeRequest,
    ) -> AcpResult<SetSessionModeResponse> {
        self.send_update(
            args.session_id,
            SessionUpdate::CurrentModeUpdate(CurrentModeUpdate::new(args.mode_id)),
        )?;
        Ok(SetSessionModeResponse::new())
    }

    async fn prompt(&self, args: PromptRequest) -> AcpResult<PromptResponse> {
        let (chat_id, _) = self
            .ensure_session(&args.session_id, current_or_default_cwd())
            .await
            .map_err(to_acp_error)?;
        let prompt_text = flatten_prompt(&args.prompt);
        if prompt_text.trim().is_empty() {
            return Err(Error::invalid_params());
        }

        self.store_message(chat_id, "acp-user", prompt_text.clone(), false)
            .await
            .map_err(to_acp_error)?;

        if let Some(command_reply) =
            handle_chat_command(&self.app_state, chat_id, ACP_CHANNEL, &prompt_text, None).await
        {
            self.send_update(
                args.session_id.clone(),
                SessionUpdate::AgentMessageChunk(ContentChunk::new(command_reply.clone().into())),
            )?;
            self.store_message(chat_id, "microclaw", command_reply, true)
                .await
                .map_err(to_acp_error)?;
            return Ok(PromptResponse::new(StopReason::EndTurn));
        }

        let (event_tx, mut event_rx) = mpsc::unbounded_channel::<AgentEvent>();
        let outbound_tx = self.outbound_tx.clone();
        let session_id = args.session_id.clone();
        let forward_task = tokio::spawn(async move {
            while let Some(event) = event_rx.recv().await {
                if let AgentEvent::TextDelta { delta } = event {
                    let _ = outbound_tx.send(OutboundNotification {
                        session_id: session_id.clone(),
                        update: SessionUpdate::AgentMessageChunk(ContentChunk::new(delta.into())),
                    });
                }
            }
        });

        let request_ctx = AgentRequestContext {
            caller_channel: ACP_CHANNEL,
            chat_id,
            chat_type: ACP_CHAT_TYPE,
        };
        let result = process_with_agent_with_events(
            &self.app_state,
            request_ctx,
            None,
            None,
            Some(&event_tx),
        )
        .await;
        drop(event_tx);
        let _ = forward_task.await;

        let response = result.map_err(to_acp_error)?;
        self.store_message(chat_id, "microclaw", response, true)
            .await
            .map_err(to_acp_error)?;
        Ok(PromptResponse::new(StopReason::EndTurn))
    }

    async fn cancel(&self, args: CancelNotification) -> AcpResult<()> {
        let session_key = args.session_id.0.to_string();
        let maybe_chat_id = call_blocking(self.app_state.db.clone(), move |db| {
            db.get_chat_id_by_channel_and_title(ACP_CHANNEL, &session_key)
        })
        .await
        .map_err(to_acp_error)?;

        if let Some(chat_id) = maybe_chat_id {
            crate::run_control::abort_runs(ACP_CHANNEL, chat_id).await;
        }
        Ok(())
    }
}

#[derive(Clone)]
struct SessionState {
    cwd: PathBuf,
}

struct OutboundNotification {
    session_id: SessionId,
    update: SessionUpdate,
}

impl From<OutboundNotification> for agent_client_protocol::SessionNotification {
    fn from(value: OutboundNotification) -> Self {
        agent_client_protocol::SessionNotification::new(value.session_id, value.update)
    }
}

struct AcpAdapter;

#[async_trait::async_trait]
impl ChannelAdapter for AcpAdapter {
    fn name(&self) -> &str {
        ACP_CHANNEL
    }

    fn chat_type_routes(&self) -> Vec<(&str, ConversationKind)> {
        vec![(ACP_CHAT_TYPE, ConversationKind::Private)]
    }

    fn is_local_only(&self) -> bool {
        true
    }

    fn allows_cross_chat(&self) -> bool {
        false
    }

    async fn send_text(&self, _external_chat_id: &str, _text: &str) -> Result<(), String> {
        Ok(())
    }
}

fn current_or_default_cwd() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn default_mode_state() -> SessionModeState {
    SessionModeState::new(
        ACP_MODE_ID,
        vec![SessionMode::new(ACP_MODE_ID, "Chat")
            .description("General-purpose MicroClaw chat mode.")],
    )
}

fn available_commands() -> Vec<AvailableCommand> {
    vec![
        AvailableCommand::new("/status", "Show current provider and model status."),
        AvailableCommand::new("/usage", "Show token usage for this session."),
        AvailableCommand::new("/skills", "List installed skills."),
        AvailableCommand::new("/reload-skills", "Reload skills from disk."),
        AvailableCommand::new("/archive", "Archive the current session transcript."),
        AvailableCommand::new("/reset", "Clear session state and chat history."),
        AvailableCommand::new("/clear", "Clear session state but keep scheduled tasks."),
        AvailableCommand::new("/stop", "Cancel the active run for this ACP session."),
        AvailableCommand::new("/providers", "List configured providers."),
        AvailableCommand::new("/provider", "Inspect or switch provider overrides."),
        AvailableCommand::new("/models", "List configured models."),
        AvailableCommand::new("/model", "Inspect or switch the active model."),
    ]
}

fn flatten_prompt(blocks: &[ContentBlock]) -> String {
    let mut parts = Vec::new();
    for block in blocks {
        match block {
            ContentBlock::Text(text) => parts.push(text.text.clone()),
            ContentBlock::ResourceLink(link) => {
                parts.push(format!("Resource: {} ({})", link.name, link.uri));
            }
            ContentBlock::Resource(resource) => match &resource.resource {
                agent_client_protocol::EmbeddedResourceResource::TextResourceContents(text) => {
                    parts.push(format!("Embedded resource {}:\n{}", text.uri, text.text));
                }
                agent_client_protocol::EmbeddedResourceResource::BlobResourceContents(blob) => {
                    parts.push(format!(
                        "Embedded resource {} ({} bytes, binary content omitted)",
                        blob.uri,
                        blob.blob.len()
                    ));
                }
                _ => {}
            },
            ContentBlock::Image(image) => {
                parts.push(format!("Image attachment ({})", image.mime_type));
            }
            ContentBlock::Audio(audio) => {
                parts.push(format!("Audio attachment ({})", audio.mime_type));
            }
            _ => {}
        }
    }
    parts.join("\n\n")
}

fn to_acp_error(err: impl std::fmt::Display) -> Error {
    let mut error = Error::internal_error();
    error.message = err.to_string();
    error
}

#[cfg(test)]
mod tests {
    use super::flatten_prompt;
    use agent_client_protocol::{
        BlobResourceContents, ContentBlock, EmbeddedResource, EmbeddedResourceResource,
        ResourceLink, TextResourceContents,
    };

    #[test]
    fn flatten_prompt_keeps_text_and_resource_context() {
        let blocks = vec![
            ContentBlock::from("hello"),
            ContentBlock::ResourceLink(ResourceLink::new("README", "file:///tmp/README.md")),
            ContentBlock::Resource(EmbeddedResource::new(
                EmbeddedResourceResource::TextResourceContents(TextResourceContents::new(
                    "body",
                    "file:///tmp/note.txt",
                )),
            )),
            ContentBlock::Resource(EmbeddedResource::new(
                EmbeddedResourceResource::BlobResourceContents(BlobResourceContents::new(
                    "YWJj",
                    "file:///tmp/blob.bin",
                )),
            )),
        ];

        let text = flatten_prompt(&blocks);
        assert!(text.contains("hello"));
        assert!(text.contains("README"));
        assert!(text.contains("body"));
        assert!(text.contains("binary content omitted"));
    }
}
