use std::sync::Arc;

use anyhow::anyhow;
use tracing::info;
#[cfg(feature = "sqlite-vec")]
use tracing::warn;

use crate::channels::telegram::TelegramChannelConfig;
use crate::channels::{DiscordAdapter, FeishuAdapter, SlackAdapter, TelegramAdapter};
use crate::config::Config;
use crate::embedding::EmbeddingProvider;
use crate::hooks::HookManager;
use crate::llm::LlmProvider;
use crate::memory::MemoryManager;
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
    let mut telegram_bot: Option<teloxide::Bot> = None;
    let mut discord_token: Option<String> = None;
    let mut has_slack = false;
    let mut has_web = false;

    if config.channel_enabled("telegram") {
        if let Some(tg_cfg) = config.channel_config::<TelegramChannelConfig>("telegram") {
            if !tg_cfg.bot_token.trim().is_empty() {
                let bot = teloxide::Bot::new(&tg_cfg.bot_token);
                telegram_bot = Some(bot.clone());
                registry.register(Arc::new(TelegramAdapter::new(bot, tg_cfg)));
            }
        }
    }

    if config.channel_enabled("discord") {
        if let Some(dc_cfg) =
            config.channel_config::<crate::channels::discord::DiscordChannelConfig>("discord")
        {
            if !dc_cfg.bot_token.trim().is_empty() {
                discord_token = Some(dc_cfg.bot_token.clone());
                registry.register(Arc::new(DiscordAdapter::new(dc_cfg.bot_token)));
            }
        }
    }

    if config.channel_enabled("slack") {
        if let Some(slack_cfg) =
            config.channel_config::<crate::channels::slack::SlackChannelConfig>("slack")
        {
            if !slack_cfg.bot_token.trim().is_empty() && !slack_cfg.app_token.trim().is_empty() {
                has_slack = true;
                registry.register(Arc::new(SlackAdapter::new(slack_cfg.bot_token)));
            }
        }
    }

    let mut has_feishu = false;
    if config.channel_enabled("feishu") {
        if let Some(feishu_cfg) =
            config.channel_config::<crate::channels::feishu::FeishuChannelConfig>("feishu")
        {
            if !feishu_cfg.app_id.trim().is_empty() && !feishu_cfg.app_secret.trim().is_empty() {
                has_feishu = true;
                registry.register(Arc::new(FeishuAdapter::new(
                    feishu_cfg.app_id.clone(),
                    feishu_cfg.app_secret.clone(),
                    feishu_cfg.domain.clone(),
                )));
            }
        }
    }

    if config.channel_enabled("web") {
        has_web = true;
        registry.register(Arc::new(WebAdapter));
    }

    let channel_registry = Arc::new(registry);

    let mut tools = ToolRegistry::new(&config, channel_registry.clone(), db.clone());

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
        tools,
    });

    crate::scheduler::spawn_scheduler(state.clone());
    crate::scheduler::spawn_reflector(state.clone());

    if let Some(ref token) = discord_token {
        let discord_state = state.clone();
        let token = token.clone();
        info!("Starting Discord bot");
        tokio::spawn(async move {
            crate::discord::start_discord_bot(discord_state, &token).await;
        });
    }

    if has_slack {
        let slack_state = state.clone();
        info!("Starting Slack bot (Socket Mode)");
        tokio::spawn(async move {
            crate::channels::slack::start_slack_bot(slack_state).await;
        });
    }

    if has_feishu {
        let feishu_state = state.clone();
        info!("Starting Feishu bot");
        tokio::spawn(async move {
            crate::channels::feishu::start_feishu_bot(feishu_state).await;
        });
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

    if let Some(bot) = telegram_bot {
        crate::telegram::start_telegram_bot(state, bot).await
    } else if has_web || discord_token.is_some() || has_slack || has_feishu {
        info!("Running without Telegram adapter; waiting for other channels");
        tokio::signal::ctrl_c()
            .await
            .map_err(|e| anyhow!("Failed to listen for Ctrl-C: {e}"))?;
        Ok(())
    } else {
        Err(anyhow!(
            "No channel is enabled. Configure channels.<name>.enabled (or legacy channel settings) for Telegram, Discord, Slack, Feishu, or web."
        ))
    }
}
