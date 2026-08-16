use std::collections::HashMap;
use std::fs;
use std::hash::{Hash, Hasher};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;
use std::{cell::Cell, cell::RefCell};

use chrono::Utc;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::layout::{Constraint, Direction, Layout, Margin, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::DefaultTerminal;

use crate::codex_auth::{
    codex_config_default_openai_base_url, is_openai_codex_provider, provider_allows_empty_api_key,
    qwen_oauth_file_has_access_token, resolve_openai_codex_auth, resolve_qwen_portal_auth,
};
use crate::config::{Config, LlmProviderProfile, SandboxBackend, SandboxMode};
use crate::http_client::llm_user_agent;
use microclaw_core::error::MicroClawError;
use microclaw_core::text::floor_char_boundary;

#[cfg(feature = "channel-matrix")]
use crate::channels::matrix;
use crate::channels::{
    dingtalk, email, feishu, imessage, irc, nostr, qq, signal, slack, weixin, whatsapp,
};
use crate::setup_def::{ChannelFieldDef, DynamicChannelDef};

pub mod app;
pub mod fields;
pub mod keys;
pub mod overrides;
pub mod pickers;
pub mod presets;
pub mod save;
#[cfg(test)]
pub(crate) mod test_prelude;
pub mod ui;
pub mod validate;
pub mod values;
pub mod wizard;

pub(crate) use self::app::*;
pub(crate) use self::keys::*;
pub(crate) use self::overrides::*;
pub(crate) use self::pickers::*;
pub use self::presets::*;
pub(crate) use self::save::*;
pub(crate) use self::ui::*;
pub(crate) use self::validate::*;
pub(crate) use self::values::*;
pub use self::wizard::*;
