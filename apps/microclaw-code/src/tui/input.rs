//! Multi-line input box with history and cursor movement.

use unicode_width::UnicodeWidthChar;

#[derive(Debug, Default)]
pub struct InputBox {
    chars: Vec<char>,
    cursor: usize,
    history: Vec<String>,
    /// Position while browsing history (`None` = editing a new entry).
    history_pos: Option<usize>,
    draft: String,
}

impl InputBox {
    pub fn text(&self) -> String {
        self.chars.iter().collect()
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
    }

    /// Take the text for submission and record it in history.
    pub fn submit(&mut self) -> String {
        let text = self.text();
        if !text.trim().is_empty() && self.history.last() != Some(&text) {
            self.history.push(text.clone());
        }
        self.clear();
        text
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

    pub fn backspace(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
            self.chars.remove(self.cursor);
        }
    }

    pub fn delete(&mut self) {
        if self.cursor < self.chars.len() {
            self.chars.remove(self.cursor);
        }
    }

    /// Delete the word before the cursor.
    pub fn delete_word(&mut self) {
        while self.cursor > 0 && self.chars[self.cursor - 1].is_whitespace() {
            self.backspace();
        }
        while self.cursor > 0 && !self.chars[self.cursor - 1].is_whitespace() {
            self.backspace();
        }
    }

    pub fn left(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    pub fn right(&mut self) {
        self.cursor = (self.cursor + 1).min(self.chars.len());
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

    pub fn is_multiline(&self) -> bool {
        self.chars.contains(&'\n')
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
            self.backspace();
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
}
