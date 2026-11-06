//! Multi-line input box: cursor movement, persistent per-project history,
//! collapsed large pastes and reverse history search.

use std::path::{Path, PathBuf};

use unicode_width::UnicodeWidthChar;

/// Pastes longer than this many lines (or characters) are shown as a chip.
const PASTE_LINES: usize = 8;
const PASTE_CHARS: usize = 800;
/// History entries kept per project.
const HISTORY_KEEP: usize = 500;

#[derive(Debug, Default)]
pub struct InputBox {
    chars: Vec<char>,
    cursor: usize,
    history: Vec<String>,
    /// Position while browsing history (`None` = editing a new entry).
    history_pos: Option<usize>,
    draft: String,
    /// Collapsed pastes: the chip text and the pasted content.
    pastes: Vec<(String, String)>,
    /// Where history is persisted (`None`: memory only).
    history_file: Option<PathBuf>,
    project_key: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct HistoryLine {
    project: String,
    text: String,
}

impl InputBox {
    /// Load this project's history from `file` and append new entries to it.
    pub fn with_history_file(file: PathBuf, project_root: &Path) -> Self {
        let project_key = project_root.display().to_string();
        let history = std::fs::read_to_string(&file)
            .map(|text| {
                let mut entries: Vec<String> = text
                    .lines()
                    .filter_map(|l| serde_json::from_str::<HistoryLine>(l).ok())
                    .filter(|h| h.project == project_key)
                    .map(|h| h.text)
                    .collect();
                entries.dedup();
                let skip = entries.len().saturating_sub(HISTORY_KEEP);
                entries.split_off(skip)
            })
            .unwrap_or_default();
        Self {
            history,
            history_file: Some(file),
            project_key,
            ..Self::default()
        }
    }

    pub fn text(&self) -> String {
        self.chars.iter().collect()
    }

    /// The text with collapsed pastes expanded.
    pub fn expanded_text(&self) -> String {
        expand_pastes(&self.text(), &self.pastes)
    }

    pub fn is_empty(&self) -> bool {
        self.chars.is_empty()
    }

    pub fn set_text(&mut self, text: &str) {
        self.chars = text.chars().collect();
        self.cursor = self.chars.len();
    }

    pub fn clear(&mut self) {
        self.chars.clear();
        self.cursor = 0;
        self.history_pos = None;
        self.pastes.clear();
    }

    /// Take the text for submission (pastes expanded) and record it in
    /// history.
    pub fn submit(&mut self) -> String {
        let shown = self.text();
        let text = self.expanded_text();
        if !shown.trim().is_empty() && self.history.last() != Some(&text) {
            self.history.push(text.clone());
            self.persist(&text);
        }
        self.clear();
        text
    }

    fn persist(&self, text: &str) {
        let Some(file) = &self.history_file else {
            return;
        };
        if text.len() > 20_000 {
            return;
        }
        if let Some(parent) = file.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let line = serde_json::to_string(&HistoryLine {
            project: self.project_key.clone(),
            text: text.to_string(),
        })
        .unwrap_or_default();
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(file)
        {
            let _ = writeln!(f, "{line}");
        }
    }

    #[cfg(test)]
    pub fn history(&self) -> &[String] {
        &self.history
    }

    pub fn insert(&mut self, ch: char) {
        self.chars.insert(self.cursor, ch);
        self.cursor += 1;
        self.history_pos = None;
    }

    pub fn insert_str(&mut self, text: &str) {
        for ch in text.chars() {
            self.insert(ch);
        }
    }

    /// Insert pasted text; large pastes become a `[Pasted #N +L lines]` chip
    /// that is expanded on submit.
    pub fn paste(&mut self, text: &str) {
        let text = text.replace("\r\n", "\n").replace('\r', "\n");
        let lines = text.lines().count();
        if lines > PASTE_LINES || text.chars().count() > PASTE_CHARS {
            let n = self.pastes.len() + 1;
            let chip = if lines > 1 {
                format!("[Pasted #{n} +{lines} lines]")
            } else {
                format!("[Pasted #{n} {} chars]", text.chars().count())
            };
            self.insert_str(&chip);
            self.pastes.push((chip, text));
        } else {
            self.insert_str(&text);
        }
    }

    pub fn backspace(&mut self) {
        if self.cursor == 0 {
            return;
        }
        // Delete a whole paste chip when the cursor sits right after it.
        let before: String = self.chars[..self.cursor].iter().collect();
        if let Some(pos) = self
            .pastes
            .iter()
            .position(|(chip, _)| before.ends_with(chip))
        {
            let len = self.pastes[pos].0.chars().count();
            for _ in 0..len {
                self.cursor -= 1;
                self.chars.remove(self.cursor);
            }
            self.pastes.remove(pos);
            return;
        }
        self.cursor -= 1;
        self.chars.remove(self.cursor);
    }

    pub fn delete(&mut self) {
        if self.cursor < self.chars.len() {
            self.chars.remove(self.cursor);
        }
    }

    /// Delete the word before the cursor.
    pub fn delete_word(&mut self) {
        while self.cursor > 0 && self.chars[self.cursor - 1].is_whitespace() {
            self.cursor -= 1;
            self.chars.remove(self.cursor);
        }
        while self.cursor > 0 && !self.chars[self.cursor - 1].is_whitespace() {
            self.cursor -= 1;
            self.chars.remove(self.cursor);
        }
    }

    pub fn left(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    pub fn right(&mut self) {
        self.cursor = (self.cursor + 1).min(self.chars.len());
    }

    pub fn word_left(&mut self) {
        while self.cursor > 0 && self.chars[self.cursor - 1].is_whitespace() {
            self.cursor -= 1;
        }
        while self.cursor > 0 && !self.chars[self.cursor - 1].is_whitespace() {
            self.cursor -= 1;
        }
    }

    pub fn word_right(&mut self) {
        let n = self.chars.len();
        while self.cursor < n && self.chars[self.cursor].is_whitespace() {
            self.cursor += 1;
        }
        while self.cursor < n && !self.chars[self.cursor].is_whitespace() {
            self.cursor += 1;
        }
    }

    pub fn home(&mut self) {
        while self.cursor > 0 && self.chars[self.cursor - 1] != '\n' {
            self.cursor -= 1;
        }
    }

    pub fn end(&mut self) {
        while self.cursor < self.chars.len() && self.chars[self.cursor] != '\n' {
            self.cursor += 1;
        }
    }

    /// Delete from the cursor to the end of the line.
    pub fn kill_line(&mut self) {
        while self.cursor < self.chars.len() && self.chars[self.cursor] != '\n' {
            self.chars.remove(self.cursor);
        }
    }

    pub fn is_multiline(&self) -> bool {
        self.chars.contains(&'\n')
    }

    /// Cursor is on the first / last visual line of a multi-line text.
    pub fn on_first_line(&self) -> bool {
        !self.chars[..self.cursor].contains(&'\n')
    }

    pub fn on_last_line(&self) -> bool {
        !self.chars[self.cursor..].contains(&'\n')
    }

    /// Move the cursor up / down one line in multi-line text.
    pub fn line_up(&mut self) {
        let col = self.column();
        self.home();
        if self.cursor == 0 {
            return;
        }
        self.cursor -= 1;
        self.home();
        let start = self.cursor;
        self.end();
        self.cursor = (start + col).min(self.cursor);
    }

    pub fn line_down(&mut self) {
        let col = self.column();
        self.end();
        if self.cursor >= self.chars.len() {
            return;
        }
        self.cursor += 1;
        let start = self.cursor;
        self.end();
        self.cursor = (start + col).min(self.cursor);
    }

    fn column(&self) -> usize {
        let mut i = self.cursor;
        while i > 0 && self.chars[i - 1] != '\n' {
            i -= 1;
        }
        self.cursor - i
    }

    /// Browse to the previous history entry.
    pub fn history_prev(&mut self) {
        if self.history.is_empty() {
            return;
        }
        let pos = match self.history_pos {
            None => {
                self.draft = self.text();
                self.history.len() - 1
            }
            Some(0) => 0,
            Some(p) => p - 1,
        };
        self.history_pos = Some(pos);
        let entry = self.history[pos].clone();
        self.chars = entry.chars().collect();
        self.cursor = self.chars.len();
    }

    /// Browse to the next history entry (or back to the draft).
    pub fn history_next(&mut self) {
        let Some(pos) = self.history_pos else {
            return;
        };
        let text = if pos + 1 < self.history.len() {
            self.history_pos = Some(pos + 1);
            self.history[pos + 1].clone()
        } else {
            self.history_pos = None;
            std::mem::take(&mut self.draft)
        };
        self.chars = text.chars().collect();
        self.cursor = self.chars.len();
    }

    /// History entries containing `query` (case-insensitive), newest first.
    pub fn search_history(&self, query: &str) -> Vec<String> {
        let q = query.to_lowercase();
        let mut seen = std::collections::HashSet::new();
        self.history
            .iter()
            .rev()
            .filter(|h| q.is_empty() || h.to_lowercase().contains(&q))
            .filter(|h| seen.insert(h.as_str()))
            .take(50)
            .cloned()
            .collect()
    }

    /// The whitespace-delimited word ending at the cursor.
    pub fn current_word(&self) -> String {
        let mut start = self.cursor;
        while start > 0 && !self.chars[start - 1].is_whitespace() {
            start -= 1;
        }
        self.chars[start..self.cursor].iter().collect()
    }

    /// Replace the word ending at the cursor.
    pub fn replace_current_word(&mut self, replacement: &str) {
        let word_len = self.current_word().chars().count();
        for _ in 0..word_len {
            self.cursor -= 1;
            self.chars.remove(self.cursor);
        }
        self.insert_str(replacement);
    }

    /// Wrap the text to `width` columns; returns the lines and the cursor's
    /// (row, column).
    pub fn layout(&self, width: usize) -> (Vec<String>, (usize, usize)) {
        let width = width.max(2);
        let mut lines = vec![String::new()];
        let mut col = 0usize;
        let mut cursor = (0, 0);
        for (i, ch) in self.chars.iter().enumerate() {
            if i == self.cursor {
                cursor = (lines.len() - 1, col);
            }
            if *ch == '\n' {
                lines.push(String::new());
                col = 0;
                continue;
            }
            let w = ch.width().unwrap_or(0);
            if col + w > width {
                lines.push(String::new());
                col = 0;
                if i == self.cursor {
                    cursor = (lines.len() - 1, 0);
                }
            }
            lines.last_mut().unwrap().push(*ch);
            col += w;
        }
        if self.cursor >= self.chars.len() {
            if col >= width {
                lines.push(String::new());
                col = 0;
            }
            cursor = (lines.len() - 1, col);
        }
        (lines, cursor)
    }
}

fn expand_pastes(text: &str, pastes: &[(String, String)]) -> String {
    let mut out = text.to_string();
    for (chip, content) in pastes {
        out = out.replacen(chip, content, 1);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edits_history_and_words() {
        let mut input = InputBox::default();
        input.insert_str("fix the bug");
        input.delete_word();
        assert_eq!(input.text(), "fix the ");
        input.insert_str("@src/ma");
        assert_eq!(input.current_word(), "@src/ma");
        input.replace_current_word("@src/main.rs");
        assert_eq!(input.text(), "fix the @src/main.rs");
        assert_eq!(input.submit(), "fix the @src/main.rs");
        assert!(input.is_empty());

        input.insert_str("draft");
        input.history_prev();
        assert_eq!(input.text(), "fix the @src/main.rs");
        input.history_next();
        assert_eq!(input.text(), "draft");
    }

    #[test]
    fn layout_wraps_and_tracks_the_cursor() {
        let mut input = InputBox::default();
        input.insert_str("abcdef\nxy");
        let (lines, cursor) = input.layout(4);
        assert_eq!(lines, vec!["abcd", "ef", "xy"]);
        assert_eq!(cursor, (2, 2));
        input.home();
        assert_eq!(input.layout(4).1, (2, 0));
    }

    #[test]
    fn large_pastes_collapse_and_expand_on_submit() {
        let mut input = InputBox::default();
        input.insert_str("look: ");
        let big = (1..=20)
            .map(|i| format!("line {i}"))
            .collect::<Vec<_>>()
            .join("\n");
        input.paste(&big);
        assert_eq!(input.text(), "look: [Pasted #1 +20 lines]");
        assert!(input.expanded_text().contains("line 20"));
        input.backspace();
        assert_eq!(input.text(), "look: ");
        input.paste(&big);
        assert_eq!(input.submit(), format!("look: {big}"));
        input.paste("small");
        assert_eq!(input.text(), "small");
    }

    #[test]
    fn history_persists_per_project_and_searches() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("history.jsonl");
        let mut a = InputBox::with_history_file(file.clone(), Path::new("/repo/a"));
        a.insert_str("run the tests");
        a.submit();
        a.insert_str("fix lint");
        a.submit();
        let mut b = InputBox::with_history_file(file.clone(), Path::new("/repo/b"));
        b.insert_str("other project");
        b.submit();
        let a2 = InputBox::with_history_file(file, Path::new("/repo/a"));
        assert_eq!(a2.history(), ["run the tests", "fix lint"]);
        assert_eq!(a2.search_history("TEST"), vec!["run the tests".to_string()]);
    }

    #[test]
    fn moves_between_lines() {
        let mut input = InputBox::default();
        input.insert_str("abc\ndefgh");
        input.line_up();
        assert!(input.on_first_line());
        input.line_down();
        assert!(input.on_last_line());
    }
}
