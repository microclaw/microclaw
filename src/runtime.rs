use std::sync::Arc;

use anyhow::anyhow;
use tracing::info;
#[cfg(feature = "sqlite-vec")]
use tracing::warn;

use crate::channels::discord::{build_discord_runtime_contexts, DiscordRuntimeContext};
use crate::channels::feishu::{build_feishu_runtime_contexts, FeishuRuntimeContext};
use crate::channels::matrix::{build_matrix_runtime_contexts, MatrixRuntimeContext};
use crate::channels::slack::{build_slack_runtime_contexts, SlackRuntimeContext};
use crate::channels::telegram::{
    build_telegram_runtime_contexts, TelegramChannelConfig, TelegramRuntimeContext,
};
use crate::channels::{
    DiscordAdapter, FeishuAdapter, IrcAdapter, MatrixAdapter, SlackAdapter, TelegramAdapter,
};
use crate::config::Config;
use crate::embedding::EmbeddingProvider;
use crate::hooks::HookManager;
use crate::llm::LlmProvider;
use crate::memory::MemoryManager;
use crate::memory_backend::MemoryBackend;
use crate::skills::SkillManager;
use crate::tools::ToolRegistry;
use crate::web::WebAdapter;
use microclaw_channels::channel_adapter::ChannelRegistry;
use microclaw_storage::db::Database;

pub struct AppState {
    pub config: Config,
    pub channel_registry: Arc<ChannelRegistry>,
    pub db: Arc<Database>,
    pub memory: MemoryManager,
    pub skills: SkillManager,
    pub hooks: Arc<HookManager>,
    pub llm: Box<dyn LlmProvider>,
    pub embedding: Option<Arc<dyn EmbeddingProvider>>,
    pub memory_backend: Arc<MemoryBackend>,
    pub tools: ToolRegistry,
}

pub async fn run(
    config: Config,
    db: Database,
    memory: MemoryManager,
    skills: SkillManager,
    mcp_manager: crate::mcp::McpManager,
) -> anyhow::Result<()> {
    let db = Arc::new(db);
    let llm = crate::llm::create_provider(&config);
    let embedding = crate::embedding::create_provider(&config);
    #[cfg(feature = "sqlite-vec")]
    {
        let dim = embedding
            .as_ref()
            .map(|e| e.dimension())
            .or(config.embedding_dim)
            .unwrap_or(1536);
        if let Err(e) = db.prepare_vector_index(dim) {
            warn!("Failed to initialize sqlite-vec index: {e}");
        }
    }

    // Build channel registry from config
    let mut registry = ChannelRegistry::new();
    let mut telegram_runtimes: Vec<(teloxide::Bot, TelegramRuntimeContext)> = Vec::new();
    let mut discord_runtimes: Vec<(String, DiscordRuntimeContext)> = Vec::new();
    let mut slack_runtimes: Vec<SlackRuntimeContext> = Vec::new();
    let mut feishu_runtimes: Vec<FeishuRuntimeContext> = Vec::new();
    let mut matrix_runtimes: Vec<MatrixRuntimeContext> = Vec::new();
    let mut has_irc = false;
    let mut has_web = false;

    if config.channel_enabled("telegram") {
        if let Some(tg_cfg) = config.channel_config::<TelegramChannelConfig>("telegram") {
            for (token, runtime_ctx) in build_telegram_runtime_contexts(&config) {
                let bot = teloxide::Bot::new(&token);
                registry.register(Arc::new(TelegramAdapter::new(
                    runtime_ctx.channel_name.clone(),
                    bot.clone(),
                    tg_cfg.clone(),
                )));
                telegram_runtimes.push((bot, runtime_ctx));
            }
        }
    }

    if config.channel_enabled("discord") {
        discord_runtimes = build_discord_runtime_contexts(&config);
        for (token, runtime_ctx) in &discord_runtimes {
            registry.register(Arc::new(DiscordAdapter::new(
                runtime_ctx.channel_name.clone(),
                token.clone(),
            )));
        }
    }

    if config.channel_enabled("slack") {
        slack_runtimes = build_slack_runtime_contexts(&config);
        for runtime_ctx in &slack_runtimes {
            registry.register(Arc::new(SlackAdapter::new(
                runtime_ctx.channel_name.clone(),
                runtime_ctx.bot_token.clone(),
            )));
        }
    }

    if config.channel_enabled("feishu") {
        feishu_runtimes = build_feishu_runtime_contexts(&config);
        for runtime_ctx in &feishu_runtimes {
            registry.register(Arc::new(FeishuAdapter::new(
                runtime_ctx.channel_name.clone(),
                runtime_ctx.config.app_id.clone(),
                runtime_ctx.config.app_secret.clone(),
                runtime_ctx.config.domain.clone(),
            )));
        }
    }

    if config.channel_enabled("matrix") {
        matrix_runtimes = build_matrix_runtime_contexts(&config);
        for runtime_ctx in &matrix_runtimes {
            registry.register(Arc::new(MatrixAdapter::new(
                runtime_ctx.channel_name.clone(),
                runtime_ctx.homeserver_url.clone(),
                runtime_ctx.access_token.clone(),
            )));
        }
    }

    let mut irc_adapter: Option<Arc<IrcAdapter>> = None;
    if config.channel_enabled("irc") {
        if let Some(irc_cfg) =
            config.channel_config::<crate::channels::irc::IrcChannelConfig>("irc")
        {
            if !irc_cfg.server.trim().is_empty() && !irc_cfg.nick.trim().is_empty() {
                has_irc = true;
                let adapter = Arc::new(IrcAdapter::new(380));
                registry.register(adapter.clone());
                irc_adapter = Some(adapter);
            }
        }
    }

    if config.channel_enabled("web") {
        has_web = true;
        registry.register(Arc::new(WebAdapter));
    }

    let channel_registry = Arc::new(registry);

    let memory_backend = Arc::new(MemoryBackend::new(
        db.clone(),
        crate::memory_backend::MemoryMcpClient::discover(&mcp_manager),
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

    let hooks = Arc::new(HookManager::from_config(&config).with_db(db.clone()));

    let state = Arc::new(AppState {
        config,
        channel_registry,
        db,
        memory,
        skills,
        hooks,
        llm,
        embedding,
        memory_backend,
        tools,
    });

    crate::scheduler::spawn_scheduler(state.clone());
    crate::scheduler::spawn_reflector(state.clone());

    let has_discord = !discord_runtimes.is_empty();
    if has_discord {
        for (token, runtime_ctx) in discord_runtimes {
            let discord_state = state.clone();
            info!(
                "Starting Discord bot adapter '{}' as @{}",
                runtime_ctx.channel_name, runtime_ctx.bot_username
            );
            tokio::spawn(async move {
                crate::discord::start_discord_bot(discord_state, runtime_ctx, &token).await;
            });
        }
    }

    let has_slack = !slack_runtimes.is_empty();
    if has_slack {
        for runtime_ctx in slack_runtimes {
            let slack_state = state.clone();
            info!(
                "Starting Slack bot adapter '{}' as @{} (Socket Mode)",
                runtime_ctx.channel_name, runtime_ctx.bot_username
            );
            tokio::spawn(async move {
                crate::channels::slack::start_slack_bot(slack_state, runtime_ctx).await;
            });
        }
    }

    let has_feishu = !feishu_runtimes.is_empty();
    if has_feishu {
        for runtime_ctx in feishu_runtimes {
            let feishu_state = state.clone();
            info!(
                "Starting Feishu bot adapter '{}' as @{}",
                runtime_ctx.channel_name, runtime_ctx.bot_username
            );
            tokio::spawn(async move {
                crate::channels::feishu::start_feishu_bot(feishu_state, runtime_ctx).await;
            });
        }
    }

    let has_matrix = !matrix_runtimes.is_empty();
    if has_matrix {
        for runtime_ctx in matrix_runtimes {
            let matrix_state = state.clone();
            info!(
                "Starting Matrix bot adapter '{}' as {}",
                runtime_ctx.channel_name, runtime_ctx.bot_user_id
            );
            tokio::spawn(async move {
                crate::channels::matrix::start_matrix_bot(matrix_state, runtime_ctx).await;
            });
        }
    }

    if has_web {
        let web_state = state.clone();
        info!(
            "Starting Web UI server on {}:{}",
            state.config.web_host, state.config.web_port
        );
        tokio::spawn(async move {
            crate::web::start_web_server(web_state).await;
        });
    }

    let has_telegram = !telegram_runtimes.is_empty();
    if has_telegram {
        for (bot, tg_ctx) in telegram_runtimes {
            let telegram_state = state.clone();
            info!(
                "Starting Telegram bot adapter '{}' as @{}",
                tg_ctx.channel_name, tg_ctx.bot_username
            );
            tokio::spawn(async move {
                let _ = crate::telegram::start_telegram_bot(telegram_state, bot, tg_ctx).await;
            });
        }
    }

    if has_irc {
        let irc_state = state.clone();
        let Some(irc_adapter) = irc_adapter else {
            return Err(anyhow!("IRC adapter state is missing"));
        };
        info!("Starting IRC bot");
        tokio::spawn(async move {
            crate::channels::irc::start_irc_bot(irc_state, irc_adapter).await;
        });
    }

    if has_telegram || has_web || has_discord || has_slack || has_feishu || has_matrix || has_irc {
        info!("Runtime active; waiting for Ctrl-C");
        tokio::signal::ctrl_c()
            .await
            .map_err(|e| anyhow!("Failed to listen for Ctrl-C: {e}"))?;
        Ok(())
    } else {
        Err(anyhow!(
            "No channel is enabled. Configure channels.<name>.enabled (or legacy channel settings) for Telegram, Discord, Slack, Feishu, Matrix, IRC, or web."
        ))
    }
}
