//! Completion popups above the input box (`/` commands, `@` files, Ctrl+R
//! history search) and a small fuzzy matcher shared with the pickers.

/// One selectable entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// What the list shows (and what is matched).
    pub label: String,
    /// Dimmed text after the label.
    pub detail: String,
    /// Text inserted on accept.
    pub insert: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PopupKind {
    Slash,
    File,
    History,
}

#[derive(Debug, Clone)]
pub struct Popup {
    pub kind: PopupKind,
    /// The text being matched (without the `/` or `@` sigil for files).
    pub query: String,
    pub entries: Vec<Entry>,
    pub selected: usize,
}

impl Popup {
    pub fn new(kind: PopupKind, query: String, candidates: &[Entry]) -> Self {
        let entries = filter(candidates, &query, 50);
        Self {
            kind,
            query,
            entries,
            selected: 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn up(&mut self) {
        if !self.entries.is_empty() {
            self.selected = (self.selected + self.entries.len() - 1) % self.entries.len();
        }
    }

    pub fn down(&mut self) {
        if !self.entries.is_empty() {
            self.selected = (self.selected + 1) % self.entries.len();
        }
    }

    pub fn current(&self) -> Option<&Entry> {
        self.entries.get(self.selected)
    }
}

/// Entries matching `query` best first (fuzzy subsequence match, prefix
/// and word-start matches score higher).
pub fn filter(candidates: &[Entry], query: &str, limit: usize) -> Vec<Entry> {
    let mut scored: Vec<(i64, usize, &Entry)> = candidates
        .iter()
        .enumerate()
        .filter_map(|(i, e)| score(&e.label, query).map(|s| (s, i, e)))
        .collect();
    scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    scored
        .into_iter()
        .take(limit)
        .map(|(_, _, e)| e.clone())
        .collect()
}

/// Fuzzy score of `text` for `query` (`None`: no match).
pub fn score(text: &str, query: &str) -> Option<i64> {
    if query.is_empty() {
        return Some(0);
    }
    let t: Vec<char> = text.to_lowercase().chars().collect();
    let q: Vec<char> = query.to_lowercase().chars().collect();
    let lower = text.to_lowercase();
    let lq = query.to_lowercase();
    if lower.starts_with(&lq) {
        return Some(10_000 - t.len() as i64);
    }
    if let Some(pos) = lower.find(&lq) {
        let boundary = pos == 0
            || lower[..pos]
                .chars()
                .last()
                .is_some_and(|c| matches!(c, '/' | '_' | '-' | '.' | ' '));
        return Some(if boundary { 6_000 } else { 4_000 } - pos as i64 - t.len() as i64);
    }
    // Subsequence.
    let mut qi = 0;
    let mut last = None;
    let mut gaps = 0i64;
    for (i, c) in t.iter().enumerate() {
        if qi < q.len() && *c == q[qi] {
            if let Some(l) = last {
                gaps += (i - l - 1) as i64;
            }
            last = Some(i);
            qi += 1;
        }
    }
    (qi == q.len()).then(|| 1_000 - gaps * 10 - t.len() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(label: &str) -> Entry {
        Entry {
            label: label.into(),
            detail: String::new(),
            insert: label.into(),
        }
    }

    #[test]
    fn prefix_beats_substring_beats_subsequence() {
        let items = [
            e("src/tui/view.rs"),
            e("src/main.rs"),
            e("docs/main-notes.md"),
            e("mod_also_in.rs"),
        ];
        let out = filter(&items, "main", 10);
        assert_eq!(out[0].label, "src/main.rs");
        assert_eq!(out.len(), 3);
        assert!(
            filter(&items, "stv", 10)
                .iter()
                .any(|e| e.label == "src/tui/view.rs")
        );
        assert!(filter(&items, "zzz", 10).is_empty());
    }

    #[test]
    fn popup_selection_wraps() {
        let items = [e("/help"), e("/hooks")];
        let mut p = Popup::new(PopupKind::Slash, "/h".into(), &items);
        assert_eq!(p.current().unwrap().label, "/help");
        p.up();
        assert_eq!(p.current().unwrap().label, "/hooks");
        p.down();
        assert_eq!(p.current().unwrap().label, "/help");
    }
}
