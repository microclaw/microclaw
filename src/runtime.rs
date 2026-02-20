use std::sync::Arc;

use anyhow::anyhow;
use tracing::info;
#[cfg(feature = "sqlite-vec")]
use tracing::warn;

use crate::channels::telegram::{TelegramChannelConfig, TelegramRuntimeContext};
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
    let mut telegram_runtimes: Vec<(teloxide::Bot, TelegramRuntimeContext)> = Vec::new();
    let mut discord_token: Option<String> = None;
    let mut has_slack = false;
    let mut has_web = false;

    if config.channel_enabled("telegram") {
        if let Some(tg_cfg) = config.channel_config::<TelegramChannelConfig>("telegram") {
            let mut account_ids: Vec<String> = tg_cfg.accounts.keys().cloned().collect();
            account_ids.sort();
            let default_account = tg_cfg
                .default_account
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(ToOwned::to_owned)
                .or_else(|| {
                    if tg_cfg.accounts.contains_key("default") {
                        Some("default".to_string())
                    } else {
                        account_ids.first().cloned()
                    }
                });

            for account_id in account_ids {
                let Some(account_cfg) = tg_cfg.accounts.get(&account_id) else {
                    continue;
                };
                if !account_cfg.enabled || account_cfg.bot_token.trim().is_empty() {
                    continue;
                }
                let is_default = default_account
                    .as_deref()
                    .map(|v| v == account_id.as_str())
                    .unwrap_or(false);
                let channel_name = if is_default {
                    "telegram".to_string()
                } else {
                    format!("telegram.{account_id}")
                };
                let bot = teloxide::Bot::new(&account_cfg.bot_token);
                registry.register(Arc::new(TelegramAdapter::new(
                    channel_name.clone(),
                    bot.clone(),
                    tg_cfg.clone(),
                )));
                let bot_username = if account_cfg.bot_username.trim().is_empty() {
                    config.bot_username_for_channel("telegram")
                } else {
                    account_cfg.bot_username.trim().to_string()
                };
                let allowed_groups = if account_cfg.allowed_groups.is_empty() {
                    tg_cfg.allowed_groups.clone()
                } else {
                    account_cfg.allowed_groups.clone()
                };
                telegram_runtimes.push((
                    bot,
                    TelegramRuntimeContext {
                        channel_name,
                        bot_username,
                        allowed_groups,
                    },
                ));
            }

            if telegram_runtimes.is_empty() && !tg_cfg.bot_token.trim().is_empty() {
                let bot = teloxide::Bot::new(&tg_cfg.bot_token);
                registry.register(Arc::new(TelegramAdapter::new(
                    "telegram".to_string(),
                    bot.clone(),
                    tg_cfg.clone(),
                )));
                telegram_runtimes.push((
                    bot,
                    TelegramRuntimeContext {
                        channel_name: "telegram".to_string(),
                        bot_username: if tg_cfg.bot_username.trim().is_empty() {
                            config.bot_username_for_channel("telegram")
                        } else {
                            tg_cfg.bot_username.trim().to_string()
                        },
                        allowed_groups: tg_cfg.allowed_groups.clone(),
                    },
                ));
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

    if has_telegram || has_web || discord_token.is_some() || has_slack || has_feishu {
        info!("Runtime active; waiting for Ctrl-C");
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
