use std::collections::HashMap;
use std::process::Command;
use std::sync::Arc;

use serde::Deserialize;
use tracing::{error, info};

use crate::runtime::AppState;
use crate::setup_def::{ChannelFieldDef, DynamicChannelDef};
use microclaw_core::text::split_text;
use microclaw_engine::channel::ConversationKind;
use microclaw_engine::channel_adapter::ChannelAdapter;

pub const SETUP_DEF: DynamicChannelDef = DynamicChannelDef {
    name: "imessage",
    presence_keys: &["service"],
    fields: &[
        ChannelFieldDef {
            yaml_key: "service",
            label: "iMessage service type (default iMessage)",
            default: "iMessage",
            secret: false,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "bot_username",
            label: "iMessage bot username override (optional)",
            default: "",
            secret: false,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "model",
            label: "iMessage bot model override (optional)",
            default: "",
            secret: false,
            required: false,
        },
    ],
};

fn default_enabled() -> bool {
    true
}

fn default_service() -> String {
    "iMessage".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct IMessageAccountConfig {
    #[serde(default = "default_service")]
    pub service: String,
    #[serde(default)]
    pub bot_username: String,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IMessageChannelConfig {
    #[serde(default = "default_service")]
    pub service: String,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub accounts: HashMap<String, IMessageAccountConfig>,
    #[serde(default)]
    pub default_account: Option<String>,
}

#[derive(Debug, Clone)]
pub struct IMessageRuntimeContext {
    pub channel_name: String,
    pub service: String,
    pub bot_username: String,
    pub model: Option<String>,
}

fn pick_default_account_id(
    configured: Option<&str>,
    accounts: &HashMap<String, IMessageAccountConfig>,
) -> Option<String> {
    let explicit = configured
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned);
    if explicit.is_some() {
        return explicit;
    }
    if accounts.contains_key("default") {
        return Some("default".to_string());
    }
    let mut keys: Vec<String> = accounts.keys().cloned().collect();
    keys.sort();
    keys.first().cloned()
}

pub fn build_imessage_runtime_contexts(
    config: &crate::config::Config,
) -> Vec<IMessageRuntimeContext> {
    let Some(im_cfg) = config.channel_config::<IMessageChannelConfig>("imessage") else {
        return Vec::new();
    };

    let mut runtimes = Vec::new();
    let default_account =
        pick_default_account_id(im_cfg.default_account.as_deref(), &im_cfg.accounts);
    let mut account_ids: Vec<String> = im_cfg.accounts.keys().cloned().collect();
    account_ids.sort();

    for account_id in account_ids {
        let Some(account_cfg) = im_cfg.accounts.get(&account_id) else {
            continue;
        };
        if !account_cfg.enabled {
            continue;
        }
        let is_default = default_account
            .as_deref()
            .map(|v| v == account_id.as_str())
            .unwrap_or(false);
        let channel_name = if is_default {
            "imessage".to_string()
        } else {
            format!("imessage.{account_id}")
        };
        let service = if account_cfg.service.trim().is_empty() {
            im_cfg.service.trim().to_string()
        } else {
            account_cfg.service.trim().to_string()
        };
        let service = if service.is_empty() {
            default_service()
        } else {
            service
        };
        let bot_username = if account_cfg.bot_username.trim().is_empty() {
            config.bot_username_for_channel(&channel_name)
        } else {
            account_cfg.bot_username.trim().to_string()
        };
        let model = account_cfg
            .model
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(ToOwned::to_owned);
        runtimes.push(IMessageRuntimeContext {
            channel_name,
            service,
            bot_username,
            model,
        });
    }

    if runtimes.is_empty() {
        runtimes.push(IMessageRuntimeContext {
            channel_name: "imessage".to_string(),
            service: if im_cfg.service.trim().is_empty() {
                default_service()
            } else {
                im_cfg.service.trim().to_string()
            },
            bot_username: config.bot_username_for_channel("imessage"),
            model: im_cfg
                .model
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(ToOwned::to_owned),
        });
    }

    runtimes
}

pub struct IMessageAdapter {
    name: String,
    service: String,
}

impl IMessageAdapter {
    pub fn new(name: String, service: String) -> Self {
        Self { name, service }
    }
}

#[async_trait::async_trait]
impl ChannelAdapter for IMessageAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn chat_type_routes(&self) -> Vec<(&str, ConversationKind)> {
        vec![("imessage_dm", ConversationKind::Private)]
    }

    async fn send_text(&self, external_chat_id: &str, text: &str) -> Result<(), String> {
        let target = external_chat_id.trim();
        if target.is_empty() {
            return Err("iMessage target is empty".to_string());
        }

        for chunk in split_text(text, 1500) {
            let script = r#"on run argv
set targetBuddy to item 1 of argv
set targetMessage to item 2 of argv
set targetServiceType to item 3 of argv
tell application "Messages"
    set targetService to 1st service whose service type = targetServiceType
    set targetBuddyHandle to buddy targetBuddy of targetService
    send targetMessage to targetBuddyHandle
end tell
end run"#;
            let output = Command::new("osascript")
                .arg("-e")
                .arg(script)
                .arg(target)
                .arg(&chunk)
                .arg(&self.service)
                .output()
                .map_err(|e| format!("Failed to run osascript for iMessage: {e}"))?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(format!("osascript iMessage send failed: {stderr}"));
            }
        }
        Ok(())
    }
}

pub async fn start_imessage_bot(_app_state: Arc<AppState>, runtime: IMessageRuntimeContext) {
    info!(
        "iMessage adapter '{}' is ready (outbound via osascript, service={})",
        runtime.channel_name, runtime.service
    );
    if std::env::consts::OS != "macos" {
        error!("iMessage channel is enabled but current OS is not macOS; outbound will fail");
    }
}
