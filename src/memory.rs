use std::path::{Path, PathBuf};

use chrono::Utc;

pub struct MemoryManager {
    /// Directory containing groups/ (for per-chat memory and daily logs).
    data_dir: PathBuf,
    /// Global AGENTS.md is read/written from workspace root shared/AGENTS.md (single source of truth).
    working_dir: PathBuf,
}

impl MemoryManager {
    pub fn new(data_dir: &str, working_dir: &str) -> Self {
        MemoryManager {
            data_dir: PathBuf::from(data_dir).join("groups"),
            working_dir: PathBuf::from(working_dir),
        }
    }

    /// Path for global principles/memory: workspace root shared/AGENTS.md (single source of truth).
    fn global_memory_path(&self) -> PathBuf {
        self.working_dir.join("shared").join("AGENTS.md")
    }

    fn chat_memory_path(&self, chat_id: i64) -> PathBuf {
        self.data_dir.join(chat_id.to_string()).join("AGENTS.md")
    }

    /// Path for shared principles for all chats/personas: workspace_dir/AGENTS.md (at workspace root).
    fn groups_root_memory_path(&self) -> PathBuf {
        self.working_dir.join("AGENTS.md")
    }

    /// Path string for AGENTS.md (principles, for display in system prompt).
    pub fn groups_root_memory_path_display(&self) -> String {
        self.groups_root_memory_path().to_string_lossy().to_string()
    }

    /// Path for per-persona tiered memory: groups/{chat_id}/{persona_id}/MEMORY.md.
    pub fn persona_memory_path(&self, chat_id: i64, persona_id: i64) -> PathBuf {
        self.data_dir
            .join(chat_id.to_string())
            .join(persona_id.to_string())
            .join("MEMORY.md")
    }

    /// Path for per-persona daily log: `groups/{chat_id}/{persona_id}/memory/YYYY-MM-DD.md`
    fn daily_log_path(&self, chat_id: i64, persona_id: i64, date: &str) -> PathBuf {
        self.data_dir
            .join(chat_id.to_string())
            .join(persona_id.to_string())
            .join("memory")
            .join(format!("{date}.md"))
    }

    pub fn read_global_memory(&self) -> Option<String> {
        let path = self.global_memory_path();
        std::fs::read_to_string(path).ok()
    }

    /// Read shared AGENTS.md at workspace root. Used as principles for all personas.
    pub fn read_groups_root_memory(&self) -> Option<String> {
        let path = self.groups_root_memory_path();
        std::fs::read_to_string(path).ok()
    }

    pub fn read_chat_memory(&self, chat_id: i64) -> Option<String> {
        let path = self.chat_memory_path(chat_id);
        std::fs::read_to_string(path).ok()
    }

    /// Read per-persona tiered memory from groups/{chat_id}/{persona_id}/MEMORY.md.
    pub fn read_persona_memory(&self, chat_id: i64, persona_id: i64) -> Option<String> {
        let path = self.persona_memory_path(chat_id, persona_id);
        std::fs::read_to_string(path).ok()
    }

    /// Read a single daily log file if it exists. `date` must be "YYYY-MM-DD".
    pub fn read_daily_log(&self, chat_id: i64, persona_id: i64, date: &str) -> Option<String> {
        let path = self.daily_log_path(chat_id, persona_id, date);
        std::fs::read_to_string(path).ok()
    }

    /// Read today's and yesterday's daily logs and return combined content for injection.
    /// Returns empty string if neither file exists.
    pub fn read_daily_logs_today_yesterday(&self, chat_id: i64, persona_id: i64) -> String {
        let today = Utc::now().format("%Y-%m-%d").to_string();
        let yesterday = (Utc::now() - chrono::Duration::days(1)).format("%Y-%m-%d").to_string();
        let mut out = String::new();
        if let Some(content) = self.read_daily_log(chat_id, persona_id, &yesterday) {
            if !content.trim().is_empty() {
                out.push_str(&format!("## {yesterday}\n{content}\n\n"));
            }
        }
        if let Some(content) = self.read_daily_log(chat_id, persona_id, &today) {
            if !content.trim().is_empty() {
                out.push_str(&format!("## {today}\n{content}\n\n"));
            }
        }
        out.trim().to_string()
    }

    /// Append content to the daily log for the given date. Creates file and parent dir if needed.
    /// `date` must be "YYYY-MM-DD".
    pub fn append_daily_log(&self, chat_id: i64, persona_id: i64, date: &str, content: &str) -> std::io::Result<()> {
        let path = self.daily_log_path(chat_id, persona_id, date);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        if !content.ends_with('\n') {
            f.write_all(b"\n")?;
        }
        f.write_all(content.as_bytes())?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn write_global_memory(&self, content: &str) -> std::io::Result<()> {
        let path = self.global_memory_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, content)
    }

    #[allow(dead_code)]
    pub fn write_chat_memory(&self, chat_id: i64, content: &str) -> std::io::Result<()> {
        let path = self.chat_memory_path(chat_id);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, content)
    }

    /// Build memory context for the system prompt: per-persona MEMORY.md and daily logs.
    /// Principles (workspace_dir/AGENTS.md) are loaded separately and injected as the "Principles" section.
    pub fn build_memory_context(&self, chat_id: i64, persona_id: i64) -> String {
        let mut context = String::new();

        if let Some(persona_mem) = self.read_persona_memory(chat_id, persona_id) {
            if !persona_mem.trim().is_empty() {
                context.push_str("<memory_this_persona>\n");
                context.push_str(&persona_mem);
                context.push_str("\n</memory_this_persona>\n\n");
            }
        }

        let daily = self.read_daily_logs_today_yesterday(chat_id, persona_id);
        if !daily.is_empty() {
            context.push_str("<recent_daily_log>\n");
            context.push_str(&daily);
            context.push_str("\n</recent_daily_log>\n");
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
        let dir_str = dir.to_str().unwrap();
        let mm = MemoryManager::new(dir_str, dir_str);
        (mm, dir)
    }

    fn cleanup(dir: &std::path::Path) {
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn test_global_memory_path() {
        let (mm, dir) = test_memory_manager();
        let path = mm.global_memory_path();
        assert!(path.ends_with("shared/AGENTS.md"), "path = {}", path.display());
        cleanup(&dir);
    }

    #[test]
    fn test_chat_memory_path() {
        let (mm, dir) = test_memory_manager();
        let path = mm.chat_memory_path(12345);
        assert!(path.to_str().unwrap().contains("groups/12345/AGENTS.md"));
        cleanup(&dir);
    }

    #[test]
    fn test_persona_memory_path() {
        let (mm, dir) = test_memory_manager();
        let path = mm.persona_memory_path(997894126, 1);
        assert!(path.to_str().unwrap().contains("997894126/1/MEMORY.md"));
        cleanup(&dir);
    }

    #[test]
    fn test_groups_root_memory_path_display() {
        let (mm, dir) = test_memory_manager();
        let s = mm.groups_root_memory_path_display();
        assert!(s.contains("AGENTS.md"));
        cleanup(&dir);
    }

    #[test]
    fn test_groups_root_memory_path() {
        let (mm, dir) = test_memory_manager();
        let path = mm.groups_root_memory_path();
        assert!(path.ends_with("AGENTS.md"));
        cleanup(&dir);
    }

    #[test]
    fn test_read_nonexistent_memory() {
        let (mm, dir) = test_memory_manager();
        assert!(mm.read_global_memory().is_none());
        assert!(mm.read_chat_memory(100).is_none());
        assert!(mm.read_persona_memory(100, 1).is_none());
        cleanup(&dir);
    }

    #[test]
    fn test_read_persona_memory() {
        let (mm, dir) = test_memory_manager();
        let path = mm.persona_memory_path(42, 2);
        if let Some(p) = path.parent() {
            let _ = std::fs::create_dir_all(p);
        }
        std::fs::write(&path, "persona 42/2 memory").unwrap();
        let content = mm.read_persona_memory(42, 2).unwrap();
        assert_eq!(content, "persona 42/2 memory");
        assert!(mm.read_persona_memory(42, 3).is_none());
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
        mm.write_chat_memory(42, "chat 42 notes").unwrap();
        let content = mm.read_chat_memory(42).unwrap();
        assert_eq!(content, "chat 42 notes");

        // Different chat should be empty
        assert!(mm.read_chat_memory(99).is_none());
        cleanup(&dir);
    }

    #[test]
    fn test_build_memory_context_empty() {
        let (mm, dir) = test_memory_manager();
        let ctx = mm.build_memory_context(100, 1);
        assert!(ctx.is_empty());
        cleanup(&dir);
    }

    #[test]
    fn test_build_memory_context_with_global_only() {
        let (mm, dir) = test_memory_manager();
        mm.write_global_memory("I am global memory").unwrap();
        let ctx = mm.build_memory_context(100, 1);
        // Global AGENTS.md is not part of memory_context; it is loaded separately as principles
        assert!(ctx.is_empty());
        cleanup(&dir);
    }

    #[test]
    fn test_build_memory_context_persona_and_daily_only() {
        let (mm, dir) = test_memory_manager();
        mm.write_global_memory("global stuff").unwrap();
        let persona_path = mm.persona_memory_path(100, 1);
        if let Some(p) = persona_path.parent() {
            let _ = std::fs::create_dir_all(p);
        }
        std::fs::write(&persona_path, "persona memory").unwrap();
        let ctx = mm.build_memory_context(100, 1);
        assert!(ctx.contains("<memory_this_persona>"));
        assert!(ctx.contains("persona memory"));
        assert!(!ctx.contains("global stuff"));
        cleanup(&dir);
    }

    #[test]
    fn test_build_memory_context_ignores_whitespace_only_persona() {
        let (mm, dir) = test_memory_manager();
        let persona_path = mm.persona_memory_path(100, 1);
        if let Some(p) = persona_path.parent() {
            let _ = std::fs::create_dir_all(p);
        }
        std::fs::write(&persona_path, "   \n  ").unwrap();
        let ctx = mm.build_memory_context(100, 1);
        // Whitespace-only persona memory is not included
        assert!(ctx.is_empty());
        cleanup(&dir);
    }

    #[test]
    fn test_groups_dir() {
        let (mm, dir) = test_memory_manager();
        assert!(mm.groups_dir().ends_with("groups"));
        cleanup(&dir);
    }

    #[test]
    fn test_daily_log_append_and_read() {
        let (mm, dir) = test_memory_manager();
        mm.append_daily_log(100, 1, "2025-01-15", "Note from day one.\n").unwrap();
        mm.append_daily_log(100, 1, "2025-01-15", "Second line.").unwrap();
        let content = mm.read_daily_log(100, 1, "2025-01-15").unwrap();
        assert!(content.contains("Note from day one."));
        assert!(content.contains("Second line."));
        assert!(mm.read_daily_log(100, 1, "2025-01-14").is_none());
        cleanup(&dir);
    }

}
