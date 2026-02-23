use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;

use anyhow::anyhow;
use tokio::sync::RwLock;
use tracing::info;
#[cfg(feature = "sqlite-vec")]
use tracing::warn;

use crate::channels::dingtalk::{build_dingtalk_runtime_contexts, DingTalkRuntimeContext};
use crate::channels::discord::{build_discord_runtime_contexts, DiscordRuntimeContext};
use crate::channels::email::{build_email_runtime_contexts, EmailRuntimeContext};
use crate::channels::feishu::{build_feishu_runtime_contexts, FeishuRuntimeContext};
use crate::channels::imessage::{build_imessage_runtime_contexts, IMessageRuntimeContext};
use crate::channels::matrix::{build_matrix_runtime_contexts, MatrixRuntimeContext};
use crate::channels::nostr::{build_nostr_runtime_contexts, NostrRuntimeContext};
use crate::channels::qq::{build_qq_runtime_contexts, QQRuntimeContext};
use crate::channels::signal::{build_signal_runtime_contexts, SignalRuntimeContext};
use crate::channels::slack::{build_slack_runtime_contexts, SlackRuntimeContext};
use crate::channels::telegram::{
    build_telegram_runtime_contexts, TelegramChannelConfig, TelegramRuntimeContext,
};
use crate::channels::whatsapp::{build_whatsapp_runtime_contexts, WhatsAppRuntimeContext};
use crate::channels::{
    DingTalkAdapter, DiscordAdapter, EmailAdapter, FeishuAdapter, IMessageAdapter, IrcAdapter,
    MatrixAdapter, NostrAdapter, QQAdapter, SignalAdapter, SlackAdapter, TelegramAdapter,
    WhatsAppAdapter,
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
    pub llm_provider_overrides: Arc<RwLock<HashMap<String, String>>>,
    pub llm_model_overrides: Arc<RwLock<HashMap<String, String>>>,
    pub embedding: Option<Arc<dyn EmbeddingProvider>>,
    pub memory_backend: Arc<MemoryBackend>,
    pub tools: ToolRegistry,
}

fn prepare_channel_runtimes<T, Build, Register, ModelOverride>(
    config: &Config,
    channel_key: &str,
    registry: &mut ChannelRegistry,
    llm_model_overrides: &mut HashMap<String, String>,
    build: Build,
    register: Register,
    model_override: ModelOverride,
) -> Vec<T>
where
    Build: Fn(&Config) -> Vec<T>,
    Register: Fn(&T, &mut ChannelRegistry),
    ModelOverride: Fn(&T) -> Option<(String, String)>,
{
    if !config.channel_enabled(channel_key) {
        return Vec::new();
    }

    let runtimes = build(config);
    for runtime in &runtimes {
        if let Some((channel_name, model)) = model_override(runtime) {
            llm_model_overrides.insert(channel_name, model);
        }
        register(runtime, registry);
    }
    runtimes
}

fn spawn_channel_runtimes<T, StartFn, Fut>(state: Arc<AppState>, runtimes: Vec<T>, start: StartFn)
where
    T: Send + 'static,
    StartFn: Fn(Arc<AppState>, T) -> Fut + Copy + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    for runtime_ctx in runtimes {
        let channel_state = state.clone();
        tokio::spawn(start(channel_state, runtime_ctx));
    }
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
    let mut llm_model_overrides: HashMap<String, String> = HashMap::new();
    let discord_runtimes: Vec<(String, DiscordRuntimeContext)> = prepare_channel_runtimes(
        &config,
        "discord",
        &mut registry,
        &mut llm_model_overrides,
        build_discord_runtime_contexts,
        |runtime, reg| {
            reg.register(Arc::new(DiscordAdapter::new(
                runtime.1.channel_name.clone(),
                runtime.0.clone(),
            )));
        },
        |runtime| {
            runtime
                .1
                .model
                .clone()
                .map(|model| (runtime.1.channel_name.clone(), model))
        },
    );
    let slack_runtimes: Vec<SlackRuntimeContext> = prepare_channel_runtimes(
        &config,
        "slack",
        &mut registry,
        &mut llm_model_overrides,
        build_slack_runtime_contexts,
        |runtime, reg| {
            reg.register(Arc::new(SlackAdapter::new(
                runtime.channel_name.clone(),
                runtime.bot_token.clone(),
            )));
        },
        |runtime| {
            runtime
                .model
                .clone()
                .map(|model| (runtime.channel_name.clone(), model))
        },
    );
    let feishu_runtimes: Vec<FeishuRuntimeContext> = prepare_channel_runtimes(
        &config,
        "feishu",
        &mut registry,
        &mut llm_model_overrides,
        build_feishu_runtime_contexts,
        |runtime, reg| {
            reg.register(Arc::new(FeishuAdapter::new(
                runtime.channel_name.clone(),
                runtime.config.app_id.clone(),
                runtime.config.app_secret.clone(),
                runtime.config.domain.clone(),
            )));
        },
        |runtime| {
            runtime
                .model
                .clone()
                .map(|model| (runtime.channel_name.clone(), model))
        },
    );
    let matrix_runtimes: Vec<MatrixRuntimeContext> = prepare_channel_runtimes(
        &config,
        "matrix",
        &mut registry,
        &mut llm_model_overrides,
        build_matrix_runtime_contexts,
        |runtime, reg| {
            reg.register(Arc::new(MatrixAdapter::new(
                runtime.channel_name.clone(),
                runtime.homeserver_url.clone(),
                runtime.access_token.clone(),
            )));
        },
        |_| None,
    );
    let whatsapp_runtimes: Vec<WhatsAppRuntimeContext> = prepare_channel_runtimes(
        &config,
        "whatsapp",
        &mut registry,
        &mut llm_model_overrides,
        build_whatsapp_runtime_contexts,
        |runtime, reg| {
            reg.register(Arc::new(WhatsAppAdapter::new(
                runtime.channel_name.clone(),
                runtime.access_token.clone(),
                runtime.phone_number_id.clone(),
                runtime.api_version.clone(),
            )));
        },
        |runtime| {
            runtime
                .model
                .clone()
                .map(|model| (runtime.channel_name.clone(), model))
        },
    );
    let imessage_runtimes: Vec<IMessageRuntimeContext> = prepare_channel_runtimes(
        &config,
        "imessage",
        &mut registry,
        &mut llm_model_overrides,
        build_imessage_runtime_contexts,
        |runtime, reg| {
            reg.register(Arc::new(IMessageAdapter::new(
                runtime.channel_name.clone(),
                runtime.service.clone(),
            )));
        },
        |runtime| {
            runtime
                .model
                .clone()
                .map(|model| (runtime.channel_name.clone(), model))
        },
    );
    let email_runtimes: Vec<EmailRuntimeContext> = prepare_channel_runtimes(
        &config,
        "email",
        &mut registry,
        &mut llm_model_overrides,
        build_email_runtime_contexts,
        |runtime, reg| {
            reg.register(Arc::new(EmailAdapter::new(
                runtime.channel_name.clone(),
                runtime.from_address.clone(),
                runtime.sendmail_path.clone(),
            )));
        },
        |runtime| {
            runtime
                .model
                .clone()
                .map(|model| (runtime.channel_name.clone(), model))
        },
    );
    let nostr_runtimes: Vec<NostrRuntimeContext> = prepare_channel_runtimes(
        &config,
        "nostr",
        &mut registry,
        &mut llm_model_overrides,
        build_nostr_runtime_contexts,
        |runtime, reg| {
            reg.register(Arc::new(NostrAdapter::new(
                runtime.channel_name.clone(),
                runtime.publish_command.clone(),
            )));
        },
        |runtime| {
            runtime
                .model
                .clone()
                .map(|model| (runtime.channel_name.clone(), model))
        },
    );
    let signal_runtimes: Vec<SignalRuntimeContext> = prepare_channel_runtimes(
        &config,
        "signal",
        &mut registry,
        &mut llm_model_overrides,
        build_signal_runtime_contexts,
        |runtime, reg| {
            reg.register(Arc::new(SignalAdapter::new(
                runtime.channel_name.clone(),
                runtime.send_command.clone(),
            )));
        },
        |runtime| {
            runtime
                .model
                .clone()
                .map(|model| (runtime.channel_name.clone(), model))
        },
    );
    let dingtalk_runtimes: Vec<DingTalkRuntimeContext> = prepare_channel_runtimes(
        &config,
        "dingtalk",
        &mut registry,
        &mut llm_model_overrides,
        build_dingtalk_runtime_contexts,
        |runtime, reg| {
            reg.register(Arc::new(DingTalkAdapter::new(
                runtime.channel_name.clone(),
                runtime.robot_webhook_url.clone(),
            )));
        },
        |runtime| {
            runtime
                .model
                .clone()
                .map(|model| (runtime.channel_name.clone(), model))
        },
    );
    let qq_runtimes: Vec<QQRuntimeContext> = prepare_channel_runtimes(
        &config,
        "qq",
        &mut registry,
        &mut llm_model_overrides,
        build_qq_runtime_contexts,
        |runtime, reg| {
            reg.register(Arc::new(QQAdapter::new(
                runtime.channel_name.clone(),
                runtime.send_command.clone(),
            )));
        },
        |runtime| {
            runtime
                .model
                .clone()
                .map(|model| (runtime.channel_name.clone(), model))
        },
    );
    let mut has_irc = false;
    let mut has_web = false;

    if config.channel_enabled("telegram") {
        if let Some(tg_cfg) = config.channel_config::<TelegramChannelConfig>("telegram") {
            for (token, runtime_ctx) in build_telegram_runtime_contexts(&config) {
                if let Some(model) = runtime_ctx.model.clone() {
                    llm_model_overrides.insert(runtime_ctx.channel_name.clone(), model);
                }
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

    let mut irc_adapter: Option<Arc<IrcAdapter>> = None;
    if config.channel_enabled("irc") {
        if let Some(irc_cfg) =
            config.channel_config::<crate::channels::irc::IrcChannelConfig>("irc")
        {
            if !irc_cfg.server.trim().is_empty() && !irc_cfg.nick.trim().is_empty() {
                if let Some(model) = irc_cfg
                    .model
                    .as_deref()
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .map(ToOwned::to_owned)
                {
                    llm_model_overrides.insert("irc".to_string(), model);
                }
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
        llm_provider_overrides: Arc::new(RwLock::new(HashMap::new())),
        llm_model_overrides: Arc::new(RwLock::new(llm_model_overrides)),
        embedding,
        memory_backend,
        tools,
    });

    crate::scheduler::spawn_scheduler(state.clone());
    crate::scheduler::spawn_reflector(state.clone());

    let has_discord = !discord_runtimes.is_empty();
    if has_discord {
        spawn_channel_runtimes(
            state.clone(),
            discord_runtimes,
            |channel_state, (token, runtime_ctx)| async move {
                info!(
                    "Starting Discord bot adapter '{}' as @{}",
                    runtime_ctx.channel_name, runtime_ctx.bot_username
                );
                crate::discord::start_discord_bot(channel_state, runtime_ctx, &token).await;
            },
        );
    }

    let has_slack = !slack_runtimes.is_empty();
    if has_slack {
        spawn_channel_runtimes(
            state.clone(),
            slack_runtimes,
            |channel_state, runtime_ctx| async move {
                info!(
                    "Starting Slack bot adapter '{}' as @{} (Socket Mode)",
                    runtime_ctx.channel_name, runtime_ctx.bot_username
                );
                crate::channels::slack::start_slack_bot(channel_state, runtime_ctx).await;
            },
        );
    }

    let has_feishu = !feishu_runtimes.is_empty();
    if has_feishu {
        spawn_channel_runtimes(
            state.clone(),
            feishu_runtimes,
            |channel_state, runtime_ctx| async move {
                info!(
                    "Starting Feishu bot adapter '{}' as @{}",
                    runtime_ctx.channel_name, runtime_ctx.bot_username
                );
                crate::channels::feishu::start_feishu_bot(channel_state, runtime_ctx).await;
            },
        );
    }

    let has_matrix = !matrix_runtimes.is_empty();
    if has_matrix {
        spawn_channel_runtimes(
            state.clone(),
            matrix_runtimes,
            |channel_state, runtime_ctx| async move {
                info!(
                    "Starting Matrix bot adapter '{}' as {}",
                    runtime_ctx.channel_name, runtime_ctx.bot_user_id
                );
                crate::channels::matrix::start_matrix_bot(channel_state, runtime_ctx).await;
            },
        );
    }

    let has_whatsapp = !whatsapp_runtimes.is_empty();
    if has_whatsapp {
        spawn_channel_runtimes(
            state.clone(),
            whatsapp_runtimes,
            |channel_state, runtime_ctx| async move {
                info!(
                    "Starting WhatsApp adapter '{}' (webhook mode, phone_number_id={})",
                    runtime_ctx.channel_name, runtime_ctx.phone_number_id
                );
                crate::channels::whatsapp::start_whatsapp_bot(channel_state, runtime_ctx).await;
            },
        );
    }

    let has_imessage = !imessage_runtimes.is_empty();
    if has_imessage {
        spawn_channel_runtimes(
            state.clone(),
            imessage_runtimes,
            |channel_state, runtime_ctx| async move {
                info!(
                    "Starting iMessage adapter '{}' (service={})",
                    runtime_ctx.channel_name, runtime_ctx.service
                );
                crate::channels::imessage::start_imessage_bot(channel_state, runtime_ctx).await;
            },
        );
    }

    let has_email = !email_runtimes.is_empty();
    if has_email {
        spawn_channel_runtimes(
            state.clone(),
            email_runtimes,
            |channel_state, runtime_ctx| async move {
                info!(
                    "Starting Email adapter '{}' (from={})",
                    runtime_ctx.channel_name, runtime_ctx.from_address
                );
                crate::channels::email::start_email_bot(channel_state, runtime_ctx).await;
            },
        );
    }

    let has_nostr = !nostr_runtimes.is_empty();
    if has_nostr {
        spawn_channel_runtimes(
            state.clone(),
            nostr_runtimes,
            |channel_state, runtime_ctx| async move {
                info!("Starting Nostr adapter '{}'", runtime_ctx.channel_name);
                crate::channels::nostr::start_nostr_bot(channel_state, runtime_ctx).await;
            },
        );
    }

    let has_signal = !signal_runtimes.is_empty();
    if has_signal {
        spawn_channel_runtimes(
            state.clone(),
            signal_runtimes,
            |channel_state, runtime_ctx| async move {
                info!("Starting Signal adapter '{}'", runtime_ctx.channel_name);
                crate::channels::signal::start_signal_bot(channel_state, runtime_ctx).await;
            },
        );
    }

    let has_dingtalk = !dingtalk_runtimes.is_empty();
    if has_dingtalk {
        spawn_channel_runtimes(
            state.clone(),
            dingtalk_runtimes,
            |channel_state, runtime_ctx| async move {
                info!("Starting DingTalk adapter '{}'", runtime_ctx.channel_name);
                crate::channels::dingtalk::start_dingtalk_bot(channel_state, runtime_ctx).await;
            },
        );
    }

    let has_qq = !qq_runtimes.is_empty();
    if has_qq {
        spawn_channel_runtimes(
            state.clone(),
            qq_runtimes,
            |channel_state, runtime_ctx| async move {
                info!("Starting QQ adapter '{}'", runtime_ctx.channel_name);
                crate::channels::qq::start_qq_bot(channel_state, runtime_ctx).await;
            },
        );
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

    let has_active_channels = [
        has_telegram,
        has_web,
        has_discord,
        has_slack,
        has_feishu,
        has_matrix,
        has_irc,
        has_whatsapp,
        has_imessage,
        has_email,
        has_nostr,
        has_signal,
        has_dingtalk,
        has_qq,
    ]
    .into_iter()
    .any(|v| v);

    if has_active_channels {
        info!("Runtime active; waiting for Ctrl-C");
        tokio::signal::ctrl_c()
            .await
            .map_err(|e| anyhow!("Failed to listen for Ctrl-C: {e}"))?;
        Ok(())
    } else {
        Err(anyhow!(
            "No channel is enabled. Configure channels.<name>.enabled (or legacy channel settings) for Telegram, Discord, Slack, Feishu, Matrix, WhatsApp, iMessage, Email, Nostr, Signal, DingTalk, QQ, IRC, or web."
        ))
    }
}
