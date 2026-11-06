//! Ctrl+T: the whole transcript, expanded, in a read-only pager with search.

use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

use crate::ui::theme::Theme;

#[derive(Debug, Clone)]
pub struct Pager {
    pub lines: Vec<Line<'static>>,
    plain: Vec<String>,
    /// First visible line.
    pub top: usize,
    pub query: String,
    /// Typing a search query.
    pub searching: bool,
    pub matches: Vec<usize>,
    pub current: usize,
}

pub enum PagerKey {
    Up(usize),
    Down(usize),
    Top,
    Bottom,
    StartSearch,
    Char(char),
    Backspace,
    Enter,
    Next,
    Prev,
    Close,
}

impl Pager {
    pub fn new(lines: Vec<Line<'static>>, height: usize) -> Self {
        let plain = lines
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>();
        let top = lines.len().saturating_sub(height);
        Self {
            lines,
            plain,
            top,
            query: String::new(),
            searching: false,
            matches: Vec::new(),
            current: 0,
        }
    }

    /// Plain text of the transcript (for `$EDITOR`).
    pub fn text(&self) -> String {
        self.plain.join("\n")
    }

    fn run_search(&mut self) {
        let q = self.query.to_lowercase();
        self.matches = if q.is_empty() {
            Vec::new()
        } else {
            self.plain
                .iter()
                .enumerate()
                .filter(|(_, l)| l.to_lowercase().contains(&q))
                .map(|(i, _)| i)
                .collect()
        };
        // Start from the first match at or below the current position.
        self.current = self
            .matches
            .iter()
            .position(|m| *m >= self.top)
            .unwrap_or(0);
    }

    fn jump(&mut self, height: usize) {
        if let Some(&line) = self.matches.get(self.current) {
            self.top = line.saturating_sub(height / 3);
        }
    }

    /// Returns `false` when the pager closes.
    pub fn key(&mut self, key: PagerKey, height: usize) -> bool {
        let max_top = self.lines.len().saturating_sub(height);
        if self.searching {
            match key {
                PagerKey::Char(c) => {
                    self.query.push(c);
                    self.run_search();
                    self.jump(height);
                }
                PagerKey::Backspace => {
                    self.query.pop();
                    self.run_search();
                    self.jump(height);
                }
                PagerKey::Enter => self.searching = false,
                PagerKey::Close => {
                    self.searching = false;
                    self.query.clear();
                    self.matches.clear();
                }
                _ => {}
            }
            return true;
        }
        match key {
            PagerKey::Up(n) => self.top = self.top.saturating_sub(n),
            PagerKey::Down(n) => self.top = (self.top + n).min(max_top),
            PagerKey::Top => self.top = 0,
            PagerKey::Bottom => self.top = max_top,
            PagerKey::StartSearch => {
                self.searching = true;
                self.query.clear();
            }
            PagerKey::Next if !self.matches.is_empty() => {
                self.current = (self.current + 1) % self.matches.len();
                self.jump(height);
            }
            PagerKey::Prev if !self.matches.is_empty() => {
                self.current = (self.current + self.matches.len() - 1) % self.matches.len();
                self.jump(height);
            }
            PagerKey::Close => return false,
            _ => {}
        }
        self.top = self.top.min(max_top);
        true
    }

    pub fn render(&self, width: u16, height: usize, theme: &Theme) -> Vec<Line<'static>> {
        let body = height.saturating_sub(1);
        let mut out: Vec<Line<'static>> = Vec::with_capacity(height);
        let current = self.matches.get(self.current).copied();
        for (i, line) in self.lines.iter().enumerate().skip(self.top).take(body) {
            if self.matches.binary_search(&i).is_ok() {
                let bg = if Some(i) == current {
                    theme.warning
                } else {
                    theme.border
                };
                let mut l = line.clone();
                l.spans
                    .insert(0, Span::styled("▌", Style::default().fg(bg)));
                out.push(l);
            } else {
                out.push(line.clone());
            }
        }
        while out.len() < body {
            out.push(Line::default());
        }
        let status = if self.searching {
            format!(" /{}▌  {} matches", self.query, self.matches.len())
        } else {
            let pct = if self.lines.len() <= body {
                100
            } else {
                (self.top + body) * 100 / self.lines.len()
            };
            format!(
                " transcript · {}%{} · / search · n/N next/prev · g/G top/bottom · v editor · q close",
                pct.min(100),
                if self.matches.is_empty() {
                    String::new()
                } else {
                    format!(" · match {}/{}", self.current + 1, self.matches.len())
                }
            )
        };
        let mut status_line = Line::from(Span::styled(
            status,
            Style::default().fg(theme.text).add_modifier(Modifier::BOLD),
        ));
        if let Some(bg) = theme.background_panel {
            status_line = status_line.style(Style::default().bg(bg));
        }
        let _ = width;
        out.push(status_line);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn searches_and_jumps() {
        let lines: Vec<Line<'static>> = (0..100)
            .map(|i| {
                Line::raw(if i % 30 == 0 {
                    format!("needle {i}")
                } else {
                    format!("hay {i}")
                })
            })
            .collect();
        let mut p = Pager::new(lines, 10);
        assert_eq!(p.top, 90);
        p.key(PagerKey::Top, 10);
        p.key(PagerKey::StartSearch, 10);
        for c in "needle".chars() {
            p.key(PagerKey::Char(c), 10);
        }
        p.key(PagerKey::Enter, 10);
        assert_eq!(p.matches, vec![0, 30, 60, 90]);
        p.key(PagerKey::Next, 10);
        assert_eq!(p.current, 1);
        assert!(p.top <= 30 && p.top + 10 > 30);
        assert!(!p.key(PagerKey::Close, 10));
    }
}
