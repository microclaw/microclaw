use std::path::Path;
use std::sync::Arc;

use native_tls::TlsConnector as NativeTlsConnector;
use serde::Deserialize;
use tokio::io::{split, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, RwLock};
use tokio_native_tls::TlsConnector as TokioTlsConnector;
use tracing::{error, info, warn};

use crate::agent_engine::process_with_agent_with_events;
use crate::agent_engine::AgentEvent;
use crate::agent_engine::AgentRequestContext;
use crate::chat_commands::handle_chat_command;
use crate::chat_commands::maybe_handle_plugin_command;
use crate::runtime::AppState;
use crate::setup_def::{ChannelFieldDef, DynamicChannelDef};
use microclaw_channels::channel::ConversationKind;
use microclaw_channels::channel_adapter::ChannelAdapter;
use microclaw_core::text::floor_char_boundary;
use microclaw_storage::db::call_blocking;
use microclaw_storage::db::StoredMessage;

pub const SETUP_DEF: DynamicChannelDef = DynamicChannelDef {
    name: "irc",
    presence_keys: &["server", "nick", "channels"],
    fields: &[
        ChannelFieldDef {
            yaml_key: "server",
            label: "IRC server (host or IP)",
            default: "",
            secret: false,
            required: true,
        },
        ChannelFieldDef {
            yaml_key: "port",
            label: "IRC port (default 6667)",
            default: "6667",
            secret: false,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "nick",
            label: "IRC bot nick",
            default: "",
            secret: false,
            required: true,
        },
        ChannelFieldDef {
            yaml_key: "username",
            label: "IRC username (optional)",
            default: "",
            secret: false,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "real_name",
            label: "IRC real name (optional)",
            default: "MicroClaw",
            secret: false,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "channels",
            label: "IRC channels csv (e.g. #general,#ops)",
            default: "",
            secret: false,
            required: true,
        },
        ChannelFieldDef {
            yaml_key: "password",
            label: "IRC server password (optional)",
            default: "",
            secret: true,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "mention_required",
            label: "IRC mention required in channels (true/false)",
            default: "true",
            secret: false,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "tls",
            label: "IRC TLS enabled (true/false)",
            default: "false",
            secret: false,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "tls_server_name",
            label: "IRC TLS server name (optional)",
            default: "",
            secret: false,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "tls_danger_accept_invalid_certs",
            label: "IRC TLS accept invalid certs (true/false)",
            default: "false",
            secret: false,
            required: false,
        },
        ChannelFieldDef {
            yaml_key: "model",
            label: "IRC bot model override (optional)",
            default: "",
            secret: false,
            required: false,
        },
    ],
};

fn default_irc_port() -> String {
    "6667".into()
}

fn default_irc_mention_required() -> String {
    "true".into()
}
fn default_irc_tls() -> String {
    "false".into()
}
fn default_irc_tls_danger_accept_invalid_certs() -> String {
    "false".into()
}

#[derive(Debug, Clone, Deserialize)]
pub struct IrcChannelConfig {
    pub server: String,
    #[serde(default = "default_irc_port")]
    pub port: String,
    pub nick: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub real_name: String,
    #[serde(default)]
    pub channels: String,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default = "default_irc_mention_required")]
    pub mention_required: String,
    #[serde(default = "default_irc_tls")]
    pub tls: String,
    #[serde(default)]
    pub tls_server_name: String,
    #[serde(default = "default_irc_tls_danger_accept_invalid_certs")]
    pub tls_danger_accept_invalid_certs: String,
}

impl IrcChannelConfig {
    fn port_u16(&self) -> u16 {
        self.port.trim().parse::<u16>().unwrap_or(6667)
    }

    fn username_or_nick(&self) -> String {
        let username = self.username.trim();
        if username.is_empty() {
            self.nick.trim().to_string()
        } else {
            username.to_string()
        }
    }

    fn real_name_or_default(&self) -> String {
        let real_name = self.real_name.trim();
        if real_name.is_empty() {
            "MicroClaw".to_string()
        } else {
            real_name.to_string()
        }
    }

    fn channel_list(&self) -> Vec<String> {
        self.channels
            .split(',')
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(ToString::to_string)
            .collect()
    }

    fn mention_required_bool(&self) -> bool {
        parse_bool_str(&self.mention_required, true)
    }

    fn tls_enabled(&self) -> bool {
        parse_bool_str(&self.tls, false)
    }

    fn tls_server_name_or_server(&self) -> String {
        let name = self.tls_server_name.trim();
        if name.is_empty() {
            self.server.trim().to_string()
        } else {
            name.to_string()
        }
    }

    fn tls_danger_accept_invalid_certs_bool(&self) -> bool {
        parse_bool_str(&self.tls_danger_accept_invalid_certs, false)
    }
}

pub struct IrcAdapter {
    command_tx: Arc<RwLock<Option<mpsc::UnboundedSender<String>>>>,
    message_max_len: usize,
}

impl IrcAdapter {
    pub fn new(message_max_len: usize) -> Self {
        Self {
            command_tx: Arc::new(RwLock::new(None)),
            message_max_len,
        }
    }

    async fn set_command_tx(&self, tx: mpsc::UnboundedSender<String>) {
        *self.command_tx.write().await = Some(tx);
    }

    async fn clear_command_tx(&self) {
        *self.command_tx.write().await = None;
    }

    async fn send_raw(&self, line: String) -> Result<(), String> {
        let tx = self.command_tx.read().await.clone();
        let Some(tx) = tx else {
            return Err("IRC adapter is not connected".to_string());
        };
        tx.send(line)
            .map_err(|_| "IRC connection writer is not available".to_string())
    }
}

#[async_trait::async_trait]
impl ChannelAdapter for IrcAdapter {
    fn name(&self) -> &str {
        "irc"
    }

    fn chat_type_routes(&self) -> Vec<(&str, ConversationKind)> {
        vec![
            ("irc_group", ConversationKind::Group),
            ("irc_dm", ConversationKind::Private),
        ]
    }

    async fn send_text(&self, external_chat_id: &str, text: &str) -> Result<(), String> {
        let sanitized = sanitize_irc_text(text);
        for chunk in split_irc_text(&sanitized, self.message_max_len.max(32)) {
            self.send_raw(format!("PRIVMSG {} :{}", external_chat_id, chunk))
                .await?;
        }
        Ok(())
    }

    async fn send_attachment(
        &self,
        _external_chat_id: &str,
        _file_path: &Path,
        _caption: Option<&str>,
    ) -> Result<String, String> {
        Err("attachments not supported for irc".to_string())
    }
}

pub async fn start_irc_bot(app_state: Arc<AppState>, adapter: Arc<IrcAdapter>) {
    let cfg: IrcChannelConfig = match app_state.config.channel_config("irc") {
        Some(c) => c,
        None => {
            error!("IRC channel not configured");
            return;
        }
    };

    let server = cfg.server.trim().to_string();
    let nick = cfg.nick.trim().to_string();
    if server.is_empty() || nick.is_empty() {
        error!("IRC channel requires non-empty server and nick");
        return;
    }

    let reconnect_delay = std::time::Duration::from_secs(5);
    loop {
        if let Err(e) = run_irc_connection(app_state.clone(), adapter.clone(), cfg.clone()).await {
            warn!("IRC connection ended: {e}");
        }
        adapter.clear_command_tx().await;
        tokio::time::sleep(reconnect_delay).await;
    }
}

async fn run_irc_connection(
    app_state: Arc<AppState>,
    adapter: Arc<IrcAdapter>,
    cfg: IrcChannelConfig,
) -> Result<(), String> {
    let addr = format!("{}:{}", cfg.server.trim(), cfg.port_u16());
    info!(
        "IRC: connecting to {} ({})",
        addr,
        if cfg.tls_enabled() { "tls" } else { "plain" }
    );
    let tcp_stream = TcpStream::connect(&addr)
        .await
        .map_err(|e| format!("IRC connect failed for {addr}: {e}"))?;

    let stream: BoxedIo = if cfg.tls_enabled() {
        let mut builder = NativeTlsConnector::builder();
        builder.danger_accept_invalid_certs(cfg.tls_danger_accept_invalid_certs_bool());
        let connector = builder
            .build()
            .map_err(|e| format!("IRC TLS connector init failed: {e}"))?;
        let connector = TokioTlsConnector::from(connector);
        let server_name = cfg.tls_server_name_or_server();
        let tls_stream = connector
            .connect(&server_name, tcp_stream)
            .await
            .map_err(|e| format!("IRC TLS handshake failed: {e}"))?;
        Box::new(tls_stream)
    } else {
        Box::new(tcp_stream)
    };

    let (read_half, mut write_half) = split(stream);
    let mut lines = BufReader::new(read_half).lines();

    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    adapter.set_command_tx(tx.clone()).await;

    let writer = tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            write_half
                .write_all(line.as_bytes())
                .await
                .map_err(|e| format!("IRC write failed: {e}"))?;
            write_half
                .write_all(b"\r\n")
                .await
                .map_err(|e| format!("IRC write failed: {e}"))?;
        }
        Ok::<(), String>(())
    });

    if let Some(pass) = cfg
        .password
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        let _ = tx.send(format!("PASS {pass}"));
    }
    let _ = tx.send(format!("NICK {}", cfg.nick.trim()));
    let _ = tx.send(format!(
        "USER {} 0 * :{}",
        cfg.username_or_nick(),
        sanitize_irc_text(&cfg.real_name_or_default())
    ));

    let mut joined_channels = false;
    while let Some(line) = lines.next_line().await.map_err(|e| e.to_string())? {
        let line = line.trim_end_matches('\r').to_string();

        if let Some(payload) = line.strip_prefix("PING ") {
            let _ = tx.send(format!("PONG {payload}"));
            continue;
        }

        let Some(msg) = parse_irc_line(&line) else {
            continue;
        };

        if msg.command == "001" && !joined_channels {
            joined_channels = true;
            for channel in cfg.channel_list() {
                let _ = tx.send(format!("JOIN {channel}"));
            }
            continue;
        }

        if msg.command == "433" {
            return Err("IRC nick already in use".to_string());
        }

        if msg.command != "PRIVMSG" {
            continue;
        }

        let Some(prefix) = msg.prefix else {
            continue;
        };
        let Some(sender_nick) = nick_from_prefix(prefix) else {
            continue;
        };
        if sender_nick.eq_ignore_ascii_case(cfg.nick.trim()) {
            continue;
        }

        let Some(target) = msg.params.first().copied() else {
            continue;
        };
        let text = msg.trailing.unwrap_or("").trim().to_string();
        if text.is_empty() {
            continue;
        }

        let state = app_state.clone();
        let adapter = adapter.clone();
        let cfg = cfg.clone();
        let sender = sender_nick.to_string();
        let target = target.to_string();

        tokio::spawn(async move {
            handle_irc_message(state, adapter, cfg, sender, target, text).await;
        });
    }

    drop(tx);
    match writer.await {
        Ok(Ok(())) => Err("IRC read stream ended".to_string()),
        Ok(Err(e)) => Err(e),
        Err(e) => Err(format!("IRC writer join error: {e}")),
    }
}

type BoxedIo = Box<dyn AsyncReadWrite + Unpin + Send>;
trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> AsyncReadWrite for T {}

async fn handle_irc_message(
    app_state: Arc<AppState>,
    adapter: Arc<IrcAdapter>,
    cfg: IrcChannelConfig,
    sender_nick: String,
    target: String,
    text: String,
) {
    let is_group = is_irc_channel_target(&target);
    let response_target = if is_group {
        target.clone()
    } else {
        sender_nick.clone()
    };
    let external_chat_id = response_target.clone();
    let db_chat_type = if is_group { "irc_group" } else { "irc_dm" };
    let runtime_chat_type = if is_group { "group" } else { "private" };
    let title = format!("irc-{external_chat_id}");

    let chat_id = call_blocking(app_state.db.clone(), {
        let external_chat_id = external_chat_id.clone();
        let title = title.clone();
        let db_chat_type = db_chat_type.to_string();
        move |db| {
            db.resolve_or_create_chat_id("irc", &external_chat_id, Some(&title), &db_chat_type)
        }
    })
    .await
    .unwrap_or(0);

    if chat_id == 0 {
        error!(
            "IRC: failed to resolve chat ID for target {}",
            response_target
        );
        return;
    }

    let stored = StoredMessage {
        id: uuid::Uuid::new_v4().to_string(),
        chat_id,
        sender_name: sender_nick.clone(),
        content: text.clone(),
        is_from_bot: false,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };
    let _ = call_blocking(app_state.db.clone(), move |db| db.store_message(&stored)).await;

    let trimmed = text.trim();
    if trimmed.starts_with('/') {
        if let Some(reply) = handle_chat_command(&app_state, chat_id, "irc", trimmed).await {
            let _ = adapter.send_text(&response_target, &reply).await;
            return;
        }
    }
    if let Some(plugin_response) =
        maybe_plugin_slash_response(&app_state.config, trimmed, chat_id, "irc").await
    {
        let _ = adapter.send_text(&response_target, &plugin_response).await;
        return;
    }

    if is_group && cfg.mention_required_bool() && !is_irc_mention(&text, cfg.nick.trim()) {
        return;
    }

    info!(
        "IRC message from {} in {}: {}",
        sender_nick,
        response_target,
        text.chars().take(100).collect::<String>()
    );

    let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel::<AgentEvent>();

    match process_with_agent_with_events(
        &app_state,
        AgentRequestContext {
            caller_channel: "irc",
            chat_id,
            chat_type: runtime_chat_type,
        },
        None,
        None,
        Some(&event_tx),
    )
    .await
    {
        Ok(response) => {
            drop(event_tx);
            let mut used_send_message_tool = false;
            while let Some(event) = event_rx.recv().await {
                if let AgentEvent::ToolStart { name } = event {
                    if name == "send_message" {
                        used_send_message_tool = true;
                    }
                }
            }

            if !response.is_empty() {
                if let Err(e) = adapter.send_text(&response_target, &response).await {
                    error!("IRC: failed to send response: {e}");
                }
                let bot_msg = StoredMessage {
                    id: uuid::Uuid::new_v4().to_string(),
                    chat_id,
                    sender_name: app_state.config.bot_username_for_channel("irc"),
                    content: response,
                    is_from_bot: true,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                };
                let _ =
                    call_blocking(app_state.db.clone(), move |db| db.store_message(&bot_msg)).await;
            } else if !used_send_message_tool {
                let fallback =
                    "I couldn't produce a visible reply after an automatic retry. Please try again.";
                let _ = adapter.send_text(&response_target, fallback).await;
                let bot_msg = StoredMessage {
                    id: uuid::Uuid::new_v4().to_string(),
                    chat_id,
                    sender_name: app_state.config.bot_username_for_channel("irc"),
                    content: fallback.to_string(),
                    is_from_bot: true,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                };
                let _ =
                    call_blocking(app_state.db.clone(), move |db| db.store_message(&bot_msg)).await;
            }
        }
        Err(e) => {
            error!("Error processing IRC message: {e}");
            let _ = adapter
                .send_text(&response_target, &format!("Error: {e}"))
                .await;
        }
    }
}

fn parse_bool_str(raw: &str, default_value: bool) -> bool {
    match raw.trim().to_ascii_lowercase().as_str() {
        "" => default_value,
        "1" | "true" | "yes" | "on" => true,
        "0" | "false" | "no" | "off" => false,
        _ => default_value,
    }
}

fn sanitize_irc_text(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '\r' | '\n' | '\0' => ' ',
            _ => c,
        })
        .collect()
}

fn split_irc_text(text: &str, max_len: usize) -> Vec<String> {
    if text.len() <= max_len {
        return vec![text.to_string()];
    }

    let mut chunks = Vec::new();
    let mut remaining = text;
    while !remaining.is_empty() {
        if remaining.len() <= max_len {
            chunks.push(remaining.to_string());
            break;
        }

        let boundary = floor_char_boundary(remaining, max_len.min(remaining.len()));
        let candidate = &remaining[..boundary];
        let split_at = candidate
            .rfind('\n')
            .or_else(|| candidate.rfind(char::is_whitespace))
            .filter(|idx| *idx > 0)
            .unwrap_or(boundary);

        let chunk = remaining[..split_at]
            .trim_end_matches(char::is_whitespace)
            .to_string();
        if !chunk.is_empty() {
            chunks.push(chunk);
        }

        remaining = remaining[split_at..].trim_start_matches(char::is_whitespace);
    }

    chunks
}

fn is_irc_channel_target(target: &str) -> bool {
    target.starts_with(['#', '&', '+', '!'])
}

fn is_irc_mention(text: &str, nick: &str) -> bool {
    let n = nick.trim().to_ascii_lowercase();
    if n.is_empty() {
        return false;
    }
    let t = text.trim().to_ascii_lowercase();
    t.starts_with(&format!("{n}:"))
        || t.starts_with(&format!("{n},"))
        || t == n
        || t.contains(&format!("@{n}"))
        || t.contains(&n)
}

struct ParsedIrcMessage<'a> {
    prefix: Option<&'a str>,
    command: &'a str,
    params: Vec<&'a str>,
    trailing: Option<&'a str>,
}

fn parse_irc_line(line: &str) -> Option<ParsedIrcMessage<'_>> {
    let mut rest = line.trim();
    if rest.is_empty() {
        return None;
    }

    let mut prefix = None;
    if let Some(body) = rest.strip_prefix(':') {
        let space = body.find(' ')?;
        prefix = Some(&body[..space]);
        rest = body[space + 1..].trim_start();
    }

    let (head, trailing) = if let Some(idx) = rest.find(" :") {
        (&rest[..idx], Some(&rest[idx + 2..]))
    } else {
        (rest, None)
    };

    let mut it = head.split_whitespace();
    let command = it.next()?;
    let params = it.collect::<Vec<_>>();

    Some(ParsedIrcMessage {
        prefix,
        command,
        params,
        trailing,
    })
}

fn nick_from_prefix(prefix: &str) -> Option<&str> {
    let nick = prefix.split('!').next().unwrap_or(prefix).trim();
    if nick.is_empty() {
        None
    } else {
        Some(nick)
    }
}

async fn maybe_plugin_slash_response(
    config: &crate::config::Config,
    text: &str,
    chat_id: i64,
    channel_name: &str,
) -> Option<String> {
    maybe_handle_plugin_command(config, text, chat_id, channel_name).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_irc_line_privmsg() {
        let parsed = parse_irc_line(":alice!u@h PRIVMSG #room :hello world").unwrap();
        assert_eq!(parsed.command, "PRIVMSG");
        assert_eq!(parsed.params, vec!["#room"]);
        assert_eq!(parsed.trailing, Some("hello world"));
        assert_eq!(parsed.prefix, Some("alice!u@h"));
    }

    #[test]
    fn test_nick_from_prefix() {
        assert_eq!(nick_from_prefix("alice!u@h"), Some("alice"));
        assert_eq!(nick_from_prefix("server"), Some("server"));
    }

    #[test]
    fn test_split_irc_text_prefers_word_boundary() {
        let input = "alpha beta gamma delta epsilon";
        let chunks = split_irc_text(input, 12);
        assert_eq!(chunks, vec!["alpha beta", "gamma delta", "epsilon"]);
    }

    #[test]
    fn test_split_irc_text_falls_back_to_hard_split_for_long_word() {
        let input = "supercalifragilisticexpialidocious";
        let chunks = split_irc_text(input, 8);
        assert_eq!(
            chunks,
            vec!["supercal", "ifragili", "sticexpi", "alidocio", "us"]
        );
    }

    #[tokio::test]
    async fn test_irc_plugin_slash_dispatch_helper() {
        let root = std::env::temp_dir().join(format!("mc_irc_plugin_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("plugin.yaml"),
            r#"
name: ircplug
enabled: true
commands:
  - command: /ircplug
    response: "irc-ok"
"#,
        )
        .unwrap();

        let mut cfg = crate::config::Config::test_defaults();
        cfg.plugins.enabled = true;
        cfg.plugins.dir = Some(root.to_string_lossy().to_string());

        let out = maybe_plugin_slash_response(&cfg, "/ircplug", 1, "irc").await;
        assert_eq!(out.as_deref(), Some("irc-ok"));
        let _ = std::fs::remove_dir_all(root);
    }
}
