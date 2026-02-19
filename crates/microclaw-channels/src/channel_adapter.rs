use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;

use crate::channel::ConversationKind;

#[async_trait]
pub trait ChannelAdapter: Send + Sync {
    /// Unique name: "telegram", "discord", "slack", "web"
    fn name(&self) -> &str;

    /// DB chat_type strings this adapter handles + whether each is private/group.
    fn chat_type_routes(&self) -> Vec<(&str, ConversationKind)>;

    /// Whether this channel stores messages only (no external delivery). Web = true.
    fn is_local_only(&self) -> bool {
        false
    }

    /// Whether chats on this channel can operate on other chats. Web = false.
    fn allows_cross_chat(&self) -> bool {
        true
    }

    /// Send text to external chat. Called by deliver_and_store_bot_message.
    async fn send_text(&self, external_chat_id: &str, text: &str) -> Result<(), String>;

    /// Send file attachment. Default: not supported.
    async fn send_attachment(
        &self,
        _external_chat_id: &str,
        _file_path: &Path,
        _caption: Option<&str>,
    ) -> Result<String, String> {
        Err(format!("attachments not supported for {}", self.name()))
    }
}

#[derive(Default)]
pub struct ChannelRegistry {
    adapters: HashMap<String, Arc<dyn ChannelAdapter>>,
    /// "slack_dm" -> "slack", "telegram_private" -> "telegram", etc.
    type_to_channel: HashMap<String, String>,
    /// "slack_dm" -> Private, "group" -> Group, etc.
    type_to_conversation: HashMap<String, ConversationKind>,
}

impl ChannelRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, adapter: Arc<dyn ChannelAdapter>) {
        let name = adapter.name().to_string();
        for (chat_type, kind) in adapter.chat_type_routes() {
            self.type_to_channel
                .insert(chat_type.to_string(), name.clone());
            self.type_to_conversation
                .insert(chat_type.to_string(), kind);
        }
        self.adapters.insert(name, adapter);
    }

    pub fn get(&self, name: &str) -> Option<&Arc<dyn ChannelAdapter>> {
        self.adapters.get(name)
    }

    /// Resolve a DB chat_type string to the adapter and conversation kind.
    pub fn resolve(
        &self,
        db_chat_type: &str,
    ) -> Option<(&Arc<dyn ChannelAdapter>, ConversationKind)> {
        let channel_name = self.type_to_channel.get(db_chat_type)?;
        let adapter = self.adapters.get(channel_name)?;
        let kind = self.type_to_conversation.get(db_chat_type)?;
        Some((adapter, *kind))
    }

    /// Resolve only the channel name and conversation kind (without needing the adapter).
    pub fn resolve_routing(&self, db_chat_type: &str) -> Option<(&str, ConversationKind)> {
        let channel_name = self.type_to_channel.get(db_chat_type)?;
        let kind = self.type_to_conversation.get(db_chat_type)?;
        Some((channel_name.as_str(), *kind))
    }

    pub fn has_any(&self) -> bool {
        !self.adapters.is_empty()
    }
}
