//! Modal dialogs: approvals, trust, plan execution, searchable pickers
//! (command palette, model, theme, sessions, timeline), the hunk review and
//! the transcript pager.

use microclaw_code_core::driver::PendingApproval;
use microclaw_sdk::RuntimeApprovalDecision;

use super::pager::Pager;
use super::popup::{self, Entry};
use super::review::ReviewState;

pub enum Dialog {
    Approval(ApprovalDialog),
    Trust {
        root: String,
        has_config: bool,
        changed: bool,
    },
    ExecutePlan,
    Picker(Picker),
    Review(ReviewState),
    Pager(Pager),
    /// `/configure` proposal waiting for y / n.
    Configure {
        explanation: String,
        changes: Vec<super::configure::Change>,
    },
}

/// An approval card with keyboard selection and an optional reason for a
/// denial (sent to the agent).
pub struct ApprovalDialog {
    pub approval: PendingApproval,
    pub selected: usize,
    /// Typing "no, and tell the agent why".
    pub reason: Option<String>,
    /// Remote approval id when the card was also sent to a chat.
    pub remote: Option<String>,
}

impl ApprovalDialog {
    pub fn new(approval: PendingApproval) -> Self {
        Self {
            approval,
            selected: 0,
            reason: None,
            remote: None,
        }
    }

    pub fn deny_value(&self) -> String {
        self.approval
            .options
            .iter()
            .find(|o| o.decision == RuntimeApprovalDecision::Deny)
            .map(|o| o.value.clone())
            .unwrap_or_else(|| "3".into())
    }

    /// Option rows: the approval's options plus "no, and say why".
    pub fn rows(&self) -> Vec<(String, String)> {
        let mut rows: Vec<(String, String)> = self
            .approval
            .options
            .iter()
            .map(|o| (o.value.clone(), o.label.clone()))
            .collect();
        rows.push((
            "r".into(),
            "No, and tell the agent what to do instead".into(),
        ));
        rows
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PickerKind {
    Palette,
    Model,
    Theme,
    Session,
    Timeline,
}

pub struct Picker {
    pub kind: PickerKind,
    pub title: String,
    pub filter: String,
    all: Vec<Entry>,
    pub shown: Vec<Entry>,
    pub selected: usize,
    /// Value active when the picker opened (theme preview restore).
    pub original: Option<String>,
}

impl Picker {
    pub fn new(kind: PickerKind, title: impl Into<String>, entries: Vec<Entry>) -> Self {
        let shown = entries.clone();
        Self {
            kind,
            title: title.into(),
            filter: String::new(),
            all: entries,
            shown,
            selected: 0,
            original: None,
        }
    }

    pub fn select_value(&mut self, value: &str) {
        if let Some(i) = self.shown.iter().position(|e| e.insert == value) {
            self.selected = i;
        }
    }

    pub fn type_char(&mut self, c: char) {
        self.filter.push(c);
        self.refilter();
    }

    pub fn backspace(&mut self) {
        self.filter.pop();
        self.refilter();
    }

    fn refilter(&mut self) {
        self.shown = if self.filter.is_empty() {
            self.all.clone()
        } else {
            popup::filter(&self.all, &self.filter, 200)
        };
        self.selected = 0;
    }

    pub fn up(&mut self) {
        if !self.shown.is_empty() {
            self.selected = (self.selected + self.shown.len() - 1) % self.shown.len();
        }
    }

    pub fn down(&mut self) {
        if !self.shown.is_empty() {
            self.selected = (self.selected + 1) % self.shown.len();
        }
    }

    pub fn current(&self) -> Option<&Entry> {
        self.shown.get(self.selected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(label: &str) -> Entry {
        Entry {
            label: label.into(),
            detail: String::new(),
            insert: label.into(),
        }
    }

    #[test]
    fn picker_filters_and_selects() {
        let mut p = Picker::new(
            PickerKind::Theme,
            "Theme",
            vec![entry("dark"), entry("light"), entry("tokyonight")],
        );
        p.select_value("light");
        assert_eq!(p.current().unwrap().label, "light");
        p.type_char('t');
        p.type_char('o');
        assert_eq!(p.current().unwrap().label, "tokyonight");
        p.backspace();
        p.backspace();
        assert_eq!(p.shown.len(), 3);
    }
}
