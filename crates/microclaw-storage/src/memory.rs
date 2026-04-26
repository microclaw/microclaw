use std::path::{Path, PathBuf};

use microclaw_core::redact;

pub struct MemoryManager {
    data_dir: PathBuf,
}

impl MemoryManager {
    pub fn new(data_dir: &str) -> Self {
        MemoryManager {
            data_dir: PathBuf::from(data_dir).join("groups"),
        }
    }

    fn global_memory_path(&self) -> PathBuf {
        self.data_dir.join("AGENTS.md")
    }

    fn chat_memory_path(&self, channel: &str, chat_id: i64) -> PathBuf {
        self.data_dir
            .join(channel.trim())
            .join(chat_id.to_string())
            .join("AGENTS.md")
    }

    fn bot_memory_path(&self, channel: &str) -> PathBuf {
        self.data_dir.join(channel.trim()).join("AGENTS.md")
    }

    /// Per-chat user-model file. Mirrors Hermes' USER.md split from
    /// MEMORY.md: a single curated narrative about who the user is, kept
    /// separate from atomic memories so it can be loaded as one coherent
    /// block at the top of the system prompt.
    fn chat_user_model_path(&self, channel: &str, chat_id: i64) -> PathBuf {
        self.data_dir
            .join(channel.trim())
            .join(chat_id.to_string())
            .join("USER.md")
    }

    pub fn read_global_memory(&self) -> Option<String> {
        let path = self.global_memory_path();
        std::fs::read_to_string(path).ok()
    }

    pub fn read_chat_user_model(&self, channel: &str, chat_id: i64) -> Option<String> {
        let path = self.chat_user_model_path(channel, chat_id);
        std::fs::read_to_string(path).ok()
    }

    pub fn write_chat_user_model(
        &self,
        channel: &str,
        chat_id: i64,
        content: &str,
    ) -> std::io::Result<()> {
        let path = self.chat_user_model_path(channel, chat_id);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Redact PII / credentials before USER.md hits disk. The reflector
        // LLM was asked to never invent facts, but raw conversation excerpts
        // include things like API keys and emails the model might have
        // verbatim-quoted into the narrative.
        std::fs::write(path, redact::redact(content))
    }

    pub fn read_chat_memory(&self, channel: &str, chat_id: i64) -> Option<String> {
        let path = self.chat_memory_path(channel, chat_id);
        std::fs::read_to_string(path).ok()
    }

    pub fn read_bot_memory(&self, channel: &str) -> Option<String> {
        let path = self.bot_memory_path(channel);
        std::fs::read_to_string(path).ok()
    }

    #[allow(dead_code)]
    pub fn write_global_memory(&self, content: &str) -> std::io::Result<()> {
        let path = self.global_memory_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, redact::redact(content))
    }

    #[allow(dead_code)]
    pub fn write_chat_memory(
        &self,
        channel: &str,
        chat_id: i64,
        content: &str,
    ) -> std::io::Result<()> {
        let path = self.chat_memory_path(channel, chat_id);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, redact::redact(content))
    }

    #[allow(dead_code)]
    pub fn write_bot_memory(&self, channel: &str, content: &str) -> std::io::Result<()> {
        let path = self.bot_memory_path(channel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, redact::redact(content))
    }

    pub fn build_memory_context(&self, channel: &str, chat_id: i64) -> String {
        let mut context = String::new();

        if let Some(global) = self.read_global_memory() {
            if !global.trim().is_empty() {
                context.push_str("<global_memory>\n");
                context.push_str(&global);
                context.push_str("\n</global_memory>\n\n");
            }
        }

        if let Some(bot) = self.read_bot_memory(channel) {
            if !bot.trim().is_empty() {
                context.push_str("<bot_memory>\n");
                context.push_str(&bot);
                context.push_str("\n</bot_memory>\n\n");
            }
        }

        if let Some(chat) = self.read_chat_memory(channel, chat_id) {
            if !chat.trim().is_empty() {
                context.push_str("<chat_memory>\n");
                context.push_str(&chat);
                context.push_str("\n</chat_memory>\n\n");
            }
        }

        context
    }

    #[allow(dead_code)]
    pub fn groups_dir(&self) -> &Path {
        &self.data_dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_memory_manager() -> (MemoryManager, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("microclaw_mem_test_{}", uuid::Uuid::new_v4()));
        let mm = MemoryManager::new(dir.to_str().unwrap());
        (mm, dir)
    }

    fn cleanup(dir: &std::path::Path) {
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn test_global_memory_path() {
        let (mm, dir) = test_memory_manager();
        let path = mm.global_memory_path();
        assert!(path.ends_with("groups/AGENTS.md"));
        cleanup(&dir);
    }

    #[test]
    fn test_chat_memory_path() {
        let (mm, dir) = test_memory_manager();
        let path = mm.chat_memory_path("telegram", 12345);
        assert!(path.ends_with(
            std::path::Path::new("groups")
                .join("telegram")
                .join("12345")
                .join("AGENTS.md")
        ));
        cleanup(&dir);
    }

    #[test]
    fn test_bot_memory_path() {
        let (mm, dir) = test_memory_manager();
        let path = mm.bot_memory_path("feishu.ops");
        assert!(path.ends_with(
            std::path::Path::new("groups")
                .join("feishu.ops")
                .join("AGENTS.md")
        ));
        cleanup(&dir);
    }

    #[test]
    fn test_writes_redact_credentials_before_persist() {
        let (mm, dir) = test_memory_manager();
        // USER.md path: secrets get masked before hitting disk.
        mm.write_chat_user_model(
            "telegram",
            7,
            "User shared sk-proj-ABCDEFGHIJKLMNOP1234567890 and email a@b.com",
        )
        .expect("write");
        let stored = mm.read_chat_user_model("telegram", 7).expect("read");
        assert!(!stored.contains("sk-proj-ABCDEFGHIJKLMNOP"));
        assert!(stored.contains("sk-<redacted>"));
        assert!(!stored.contains("a@b.com"));
        assert!(stored.contains("<redacted>@b.com"));

        // Same guarantee for chat AGENTS.md.
        mm.write_chat_memory("telegram", 7, "ghp_abcdefghij1234567890ABCDE leaked")
            .expect("write");
        let mem = mm.read_chat_memory("telegram", 7).expect("read");
        assert!(!mem.contains("ghp_abcdefghij"));
        assert!(mem.contains("gh<redacted>"));

        cleanup(&dir);
    }

    #[test]
    fn test_chat_user_model_path_and_round_trip() {
        let (mm, dir) = test_memory_manager();
        let path = mm.chat_user_model_path("telegram", 42);
        assert!(path.ends_with(
            std::path::Path::new("groups")
                .join("telegram")
                .join("42")
                .join("USER.md")
        ));
        // Empty round-trip: read returns None when file does not exist.
        assert!(mm.read_chat_user_model("telegram", 42).is_none());
        // Write then read back.
        mm.write_chat_user_model("telegram", 42, "Senior Rust engineer.")
            .expect("write");
        let got = mm
            .read_chat_user_model("telegram", 42)
            .expect("read after write");
        assert_eq!(got, "Senior Rust engineer.");
        cleanup(&dir);
    }

    #[test]
    fn test_read_nonexistent_memory() {
        let (mm, dir) = test_memory_manager();
        assert!(mm.read_global_memory().is_none());
        assert!(mm.read_chat_memory("telegram", 100).is_none());
        cleanup(&dir);
    }

    #[test]
    fn test_write_and_read_global_memory() {
        let (mm, dir) = test_memory_manager();
        mm.write_global_memory("global notes").unwrap();
        let content = mm.read_global_memory().unwrap();
        assert_eq!(content, "global notes");
        cleanup(&dir);
    }

    #[test]
    fn test_write_and_read_chat_memory() {
        let (mm, dir) = test_memory_manager();
        mm.write_chat_memory("telegram", 42, "chat 42 notes")
            .unwrap();
        let content = mm.read_chat_memory("telegram", 42).unwrap();
        assert_eq!(content, "chat 42 notes");

        // Different chat should be empty
        assert!(mm.read_chat_memory("telegram", 99).is_none());
        cleanup(&dir);
    }

    #[test]
    fn test_write_and_read_bot_memory() {
        let (mm, dir) = test_memory_manager();
        mm.write_bot_memory("feishu", "bot notes").unwrap();
        let content = mm.read_bot_memory("feishu").unwrap();
        assert_eq!(content, "bot notes");
        cleanup(&dir);
    }

    #[test]
    fn test_build_memory_context_empty() {
        let (mm, dir) = test_memory_manager();
        let ctx = mm.build_memory_context("telegram", 100);
        assert!(ctx.is_empty());
        cleanup(&dir);
    }

    #[test]
    fn test_build_memory_context_with_global_only() {
        let (mm, dir) = test_memory_manager();
        mm.write_global_memory("I am global memory").unwrap();
        let ctx = mm.build_memory_context("telegram", 100);
        assert!(ctx.contains("<global_memory>"));
        assert!(ctx.contains("I am global memory"));
        assert!(ctx.contains("</global_memory>"));
        assert!(!ctx.contains("<chat_memory>"));
        cleanup(&dir);
    }

    #[test]
    fn test_build_memory_context_with_both() {
        let (mm, dir) = test_memory_manager();
        mm.write_global_memory("global stuff").unwrap();
        mm.write_bot_memory("telegram", "bot stuff").unwrap();
        mm.write_chat_memory("telegram", 100, "chat stuff").unwrap();
        let ctx = mm.build_memory_context("telegram", 100);
        assert!(ctx.contains("<global_memory>"));
        assert!(ctx.contains("global stuff"));
        assert!(ctx.contains("<bot_memory>"));
        assert!(ctx.contains("bot stuff"));
        assert!(ctx.contains("<chat_memory>"));
        assert!(ctx.contains("chat stuff"));
        cleanup(&dir);
    }

    #[test]
    fn test_build_memory_context_ignores_whitespace_only() {
        let (mm, dir) = test_memory_manager();
        mm.write_global_memory("   \n  ").unwrap();
        let ctx = mm.build_memory_context("telegram", 100);
        // Whitespace-only content should be ignored
        assert!(ctx.is_empty());
        cleanup(&dir);
    }

    #[test]
    fn test_groups_dir() {
        let (mm, dir) = test_memory_manager();
        assert!(mm.groups_dir().ends_with("groups"));
        cleanup(&dir);
    }
}
