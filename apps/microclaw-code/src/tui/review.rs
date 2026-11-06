//! Hunk-by-hunk review of the working tree (`/changes`, F2): browse the
//! uncommitted changes file by file, revert single hunks, mark files as
//! reviewed and leave comments that become a prompt for the agent.
//!
//! Reverting writes the reverse patch to `.git/microclaw/reverted/` first,
//! so `git apply <file>` brings a hunk back.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

use crate::ui::theme::Theme;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hunk {
    /// `@@ -a,b +c,d @@ …`
    pub header: String,
    /// Body lines with their `+`/`-`/` ` prefix.
    pub lines: Vec<String>,
    /// First line number on the new side.
    pub new_start: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileChange {
    pub path: String,
    /// `diff --git …` through `+++ …` header lines.
    pub header: Vec<String>,
    pub hunks: Vec<Hunk>,
    /// Untracked file (reverting deletes it).
    pub untracked: bool,
    pub reviewed: bool,
}

impl FileChange {
    pub fn stats(&self) -> (usize, usize) {
        let mut added = 0;
        let mut removed = 0;
        for h in &self.hunks {
            for l in &h.lines {
                if l.starts_with('+') {
                    added += 1;
                } else if l.starts_with('-') {
                    removed += 1;
                }
            }
        }
        (added, removed)
    }

    /// The file's diff as text (for the renderer).
    pub fn diff_text(&self) -> String {
        let mut text = self.header.join("\n");
        for h in &self.hunks {
            text.push('\n');
            text.push_str(&h.header);
            for l in &h.lines {
                text.push('\n');
                text.push_str(l);
            }
        }
        text.push('\n');
        text
    }
}

/// Parse `git diff` output.
pub fn parse_diff(text: &str) -> Vec<FileChange> {
    let mut files: Vec<FileChange> = Vec::new();
    for line in text.lines() {
        if line.starts_with("diff --git ") {
            let path = line
                .rsplit_once(" b/")
                .map(|(_, p)| p.to_string())
                .unwrap_or_default();
            files.push(FileChange {
                path,
                header: vec![line.to_string()],
                hunks: Vec::new(),
                untracked: false,
                reviewed: false,
            });
            continue;
        }
        let Some(file) = files.last_mut() else {
            continue;
        };
        if line.starts_with("@@") {
            let new_start = line
                .split_whitespace()
                .find(|p| p.starts_with('+'))
                .and_then(|p| p[1..].split(',').next())
                .and_then(|n| n.parse().ok())
                .unwrap_or(1);
            file.hunks.push(Hunk {
                header: line.to_string(),
                lines: Vec::new(),
                new_start,
            });
        } else if let Some(hunk) = file.hunks.last_mut() {
            hunk.lines.push(line.to_string());
        } else {
            if let Some(p) = line.strip_prefix("+++ b/") {
                file.path = p.to_string();
            }
            file.header.push(line.to_string());
        }
    }
    files.retain(|f| !f.hunks.is_empty());
    files
}

/// Uncommitted changes against HEAD plus untracked files.
pub fn load_changes(root: &Path) -> anyhow::Result<Vec<FileChange>> {
    let out = Command::new("git")
        .current_dir(root)
        .args([
            "--no-pager",
            "diff",
            "HEAD",
            "--no-color",
            "--no-ext-diff",
            "-U3",
        ])
        .output()?;
    anyhow::ensure!(
        out.status.success(),
        "git diff failed: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    );
    let mut files = parse_diff(&String::from_utf8_lossy(&out.stdout));
    let untracked = Command::new("git")
        .current_dir(root)
        .args(["ls-files", "--others", "--exclude-standard"])
        .output()?;
    for path in String::from_utf8_lossy(&untracked.stdout).lines().take(200) {
        let full = root.join(path);
        let Ok(content) = std::fs::read_to_string(&full) else {
            continue; // binary or unreadable
        };
        let lines: Vec<String> = content.lines().map(|l| format!("+{l}")).collect();
        if lines.len() > 5_000 {
            continue;
        }
        files.push(FileChange {
            path: path.to_string(),
            header: vec![
                format!("diff --git a/{path} b/{path}"),
                "new file".into(),
                "--- /dev/null".into(),
                format!("+++ b/{path}"),
            ],
            hunks: vec![Hunk {
                header: format!("@@ -0,0 +1,{} @@", lines.len()),
                lines,
                new_start: 1,
            }],
            untracked: true,
            reviewed: false,
        });
    }
    Ok(files)
}

/// Revert one hunk; returns the backup patch path.
pub fn revert_hunk(root: &Path, file: &FileChange, hunk: usize) -> anyhow::Result<PathBuf> {
    let h = file
        .hunks
        .get(hunk)
        .ok_or_else(|| anyhow::anyhow!("no such hunk"))?;
    let dir = root.join(".git").join("microclaw").join("reverted");
    std::fs::create_dir_all(&dir)?;
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%S%3f");
    let safe = file.path.replace(['/', '\\'], "_");
    let backup = dir.join(format!("{stamp}-{safe}.patch"));
    if file.untracked {
        let full = root.join(&file.path);
        std::fs::copy(&full, backup.with_extension("orig"))?;
        std::fs::remove_file(&full)?;
        return Ok(backup.with_extension("orig"));
    }
    let mut patch = String::new();
    for l in &file.header {
        if l.starts_with("diff --git") || l.starts_with("--- ") || l.starts_with("+++ ") {
            patch.push_str(l);
            patch.push('\n');
        }
    }
    patch.push_str(&h.header);
    patch.push('\n');
    for l in &h.lines {
        patch.push_str(l);
        patch.push('\n');
    }
    std::fs::write(&backup, &patch)?;
    let mut child = Command::new("git")
        .current_dir(root)
        .args(["apply", "-R", "--recount", "--whitespace=nowarn", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        stdin.write_all(patch.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    anyhow::ensure!(
        out.status.success(),
        "git apply -R failed: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    );
    Ok(backup)
}

/// Review dialog state.
#[derive(Debug, Clone)]
pub struct ReviewState {
    pub root: PathBuf,
    pub files: Vec<FileChange>,
    pub file: usize,
    pub hunk: usize,
    /// `(path:line, comment)` notes for the agent.
    pub comments: Vec<(String, String)>,
    /// Comment being typed for the current hunk.
    pub composing: Option<String>,
    /// Waiting for `y` to revert the current hunk.
    pub confirm_revert: bool,
    pub message: Option<String>,
    /// Scroll offset of the hunk view.
    pub scroll: usize,
}

pub enum ReviewKey {
    Up,
    Down,
    NextFile,
    PrevFile,
    Revert,
    Confirm,
    Cancel,
    Comment,
    Reviewed,
    Char(char),
    Backspace,
    Enter,
    Close,
}

/// What the app should do after a key.
pub enum ReviewOutcome {
    Stay,
    /// Close; the prompt (from comments) goes into the input box.
    Close(Option<String>),
}

impl ReviewState {
    pub fn new(root: PathBuf, files: Vec<FileChange>) -> Self {
        Self {
            root,
            files,
            file: 0,
            hunk: 0,
            comments: Vec::new(),
            composing: None,
            confirm_revert: false,
            message: None,
            scroll: 0,
        }
    }

    fn current(&self) -> Option<&FileChange> {
        self.files.get(self.file)
    }

    pub fn key(&mut self, key: ReviewKey) -> ReviewOutcome {
        if let Some(text) = &mut self.composing {
            match key {
                ReviewKey::Char(c) => text.push(c),
                ReviewKey::Backspace => {
                    text.pop();
                }
                ReviewKey::Enter => {
                    let text = std::mem::take(text);
                    self.composing = None;
                    if let Some(f) = self.current()
                        && !text.trim().is_empty()
                    {
                        let line = f.hunks.get(self.hunk).map(|h| h.new_start).unwrap_or(1);
                        self.comments
                            .push((format!("{}:{line}", f.path), text.trim().to_string()));
                        self.message = Some(format!("{} comment(s)", self.comments.len()));
                    }
                }
                ReviewKey::Cancel | ReviewKey::Close => self.composing = None,
                _ => {}
            }
            return ReviewOutcome::Stay;
        }
        if self.confirm_revert {
            self.confirm_revert = false;
            if matches!(key, ReviewKey::Confirm) {
                self.revert_current();
            } else {
                self.message = Some("kept".into());
            }
            return ReviewOutcome::Stay;
        }
        self.message = None;
        let hunks = self.current().map(|f| f.hunks.len()).unwrap_or(0);
        match key {
            ReviewKey::Down => {
                if self.hunk + 1 < hunks {
                    self.hunk += 1;
                } else if self.file + 1 < self.files.len() {
                    self.file += 1;
                    self.hunk = 0;
                }
                self.scroll = 0;
            }
            ReviewKey::Up => {
                if self.hunk > 0 {
                    self.hunk -= 1;
                } else if self.file > 0 {
                    self.file -= 1;
                    self.hunk = self
                        .current()
                        .map(|f| f.hunks.len().saturating_sub(1))
                        .unwrap_or(0);
                }
                self.scroll = 0;
            }
            ReviewKey::NextFile => {
                if self.file + 1 < self.files.len() {
                    self.file += 1;
                    self.hunk = 0;
                }
            }
            ReviewKey::PrevFile => {
                if self.file > 0 {
                    self.file -= 1;
                    self.hunk = 0;
                }
            }
            ReviewKey::Revert if hunks > 0 => {
                self.confirm_revert = true;
                self.message = Some("revert this hunk? y / n".into());
            }
            ReviewKey::Comment if hunks > 0 => self.composing = Some(String::new()),
            ReviewKey::Reviewed => {
                if let Some(f) = self.files.get_mut(self.file) {
                    f.reviewed = !f.reviewed;
                }
            }
            ReviewKey::Close | ReviewKey::Cancel => return ReviewOutcome::Close(self.prompt()),
            _ => {}
        }
        ReviewOutcome::Stay
    }

    fn revert_current(&mut self) {
        let Some(file) = self.files.get(self.file).cloned() else {
            return;
        };
        match revert_hunk(&self.root, &file, self.hunk) {
            Ok(backup) => {
                self.message = Some(format!(
                    "reverted; backup {}",
                    backup.strip_prefix(&self.root).unwrap_or(&backup).display()
                ));
                match load_changes(&self.root) {
                    Ok(files) => {
                        let reviewed: Vec<String> = self
                            .files
                            .iter()
                            .filter(|f| f.reviewed)
                            .map(|f| f.path.clone())
                            .collect();
                        self.files = files;
                        for f in &mut self.files {
                            f.reviewed = reviewed.contains(&f.path);
                        }
                        self.file = self.file.min(self.files.len().saturating_sub(1));
                        let hunks = self.current().map(|f| f.hunks.len()).unwrap_or(0);
                        self.hunk = self.hunk.min(hunks.saturating_sub(1));
                    }
                    Err(e) => self.message = Some(format!("reload failed: {e}")),
                }
            }
            Err(e) => self.message = Some(format!("revert failed: {e}")),
        }
    }

    /// A prompt for the agent from the comments.
    pub fn prompt(&self) -> Option<String> {
        if self.comments.is_empty() {
            return None;
        }
        let mut text = String::from("Review comments on your changes; please address each:\n");
        for (loc, c) in &self.comments {
            text.push_str(&format!("- {loc}: {c}\n"));
        }
        Some(text.trim_end().to_string())
    }

    /// Render the review screen into lines for `width` x `height`.
    pub fn render(
        &self,
        width: u16,
        height: u16,
        theme: &Theme,
        layout_setting: microclaw_code_core::settings::DiffStyle,
    ) -> Vec<Line<'static>> {
        let muted = Style::default().fg(theme.text_muted);
        let mut out = Vec::new();
        let total_hunks: usize = self.files.iter().map(|f| f.hunks.len()).sum();
        out.push(Line::from(vec![
            Span::styled(
                " Changes ",
                Style::default()
                    .fg(theme.accent)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(
                    "{} files · {} hunks · {} reviewed",
                    self.files.len(),
                    total_hunks,
                    self.files.iter().filter(|f| f.reviewed).count()
                ),
                muted,
            ),
        ]));
        if self.files.is_empty() {
            out.push(Line::from(Span::styled(" no uncommitted changes", muted)));
            return out;
        }
        // File list (compact, up to a third of the height).
        let list_rows = (height as usize / 3).clamp(3, 12).min(self.files.len());
        let first = self.file.saturating_sub(list_rows.saturating_sub(1));
        for (i, f) in self.files.iter().enumerate().skip(first).take(list_rows) {
            let (a, r) = f.stats();
            let selected = i == self.file;
            let base = if selected {
                Style::default().fg(theme.text).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(theme.text)
            };
            out.push(Line::from(vec![
                Span::styled(
                    if selected { " ▶ " } else { "   " },
                    Style::default().fg(theme.accent),
                ),
                Span::styled(
                    if f.reviewed { "✓ " } else { "  " },
                    Style::default().fg(theme.success),
                ),
                Span::styled(f.path.clone(), base),
                Span::styled(format!("  +{a}"), Style::default().fg(theme.diff_added)),
                Span::styled(format!(" −{r}"), Style::default().fg(theme.diff_removed)),
                Span::styled(if f.untracked { "  new" } else { "" }, muted),
            ]));
        }
        out.push(Line::from(Span::styled(
            "─".repeat(width as usize),
            Style::default().fg(theme.border),
        )));
        // Current hunk.
        if let Some(f) = self.current()
            && let Some(h) = f.hunks.get(self.hunk)
        {
            out.push(Line::from(vec![
                Span::styled(
                    format!(" {} ", f.path),
                    Style::default().fg(theme.text).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!(
                        "hunk {}/{} · line {}",
                        self.hunk + 1,
                        f.hunks.len(),
                        h.new_start
                    ),
                    muted,
                ),
            ]));
            let one = FileChange {
                hunks: vec![h.clone()],
                ..f.clone()
            };
            let layout = crate::ui::diff::choose_layout(layout_setting, width.saturating_sub(2));
            let body = crate::ui::diff::render(
                &one.diff_text(),
                &f.path,
                width.saturating_sub(2),
                theme,
                layout,
                None,
            );
            let room = (height as usize).saturating_sub(out.len() + 3);
            for line in body.into_iter().skip(self.scroll).take(room) {
                let mut spans = vec![Span::raw(" ")];
                spans.extend(line.spans);
                out.push(Line::from(spans));
            }
        }
        // Footer.
        while out.len() + 2 < height as usize {
            out.push(Line::default());
        }
        if let Some(text) = &self.composing {
            out.push(Line::from(vec![
                Span::styled(
                    " comment › ",
                    Style::default()
                        .fg(theme.accent)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!("{text}▌"), Style::default().fg(theme.text)),
            ]));
        } else {
            out.push(Line::from(Span::styled(
                self.message.clone().unwrap_or_default(),
                Style::default().fg(theme.warning),
            )));
        }
        out.push(Line::from(Span::styled(
            format!(
                " ↑↓ hunk · Tab file · r revert hunk · c comment · v reviewed · q close{}",
                if self.comments.is_empty() {
                    String::new()
                } else {
                    format!(" (sends {} comment(s) to the prompt)", self.comments.len())
                }
            ),
            muted,
        )));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIFF: &str = "diff --git a/src/a.rs b/src/a.rs
index 1..2 100644
--- a/src/a.rs
+++ b/src/a.rs
@@ -1,3 +1,3 @@
 one
-two
+TWO
 three
@@ -10,2 +10,3 @@ fn x()
 ten
+ten and a half
 eleven
";

    #[test]
    fn parses_files_and_hunks() {
        let files = parse_diff(DIFF);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "src/a.rs");
        assert_eq!(files[0].hunks.len(), 2);
        assert_eq!(files[0].hunks[1].new_start, 10);
        assert_eq!(files[0].stats(), (2, 1));
    }

    #[test]
    fn reverts_one_hunk_in_a_repo() {
        if Command::new("git").arg("--version").output().is_err() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let git = |args: &[&str]| {
            Command::new("git")
                .current_dir(root)
                .args(args)
                .output()
                .unwrap()
        };
        git(&["init", "-q"]);
        git(&["config", "user.email", "t@t"]);
        git(&["config", "user.name", "t"]);
        let original: String = (1..=30).map(|i| format!("line {i}\n")).collect();
        std::fs::write(root.join("f.txt"), &original).unwrap();
        git(&["add", "."]);
        git(&["commit", "-qm", "init"]);
        let changed = original
            .replace("line 2\n", "line two\n")
            .replace("line 25\n", "line twenty-five\n");
        std::fs::write(root.join("f.txt"), &changed).unwrap();
        std::fs::write(root.join("new.txt"), "fresh\n").unwrap();
        let files = load_changes(root).unwrap();
        assert_eq!(files.len(), 2);
        let f = files.iter().find(|f| f.path == "f.txt").unwrap();
        assert_eq!(f.hunks.len(), 2);
        revert_hunk(root, f, 0).unwrap();
        let now = std::fs::read_to_string(root.join("f.txt")).unwrap();
        assert!(now.contains("line 2\n") && now.contains("line twenty-five"));
        let n = files.iter().find(|f| f.untracked).unwrap();
        revert_hunk(root, n, 0).unwrap();
        assert!(!root.join("new.txt").exists());

        let mut state = ReviewState::new(root.to_path_buf(), load_changes(root).unwrap());
        state.key(ReviewKey::Comment);
        for c in "use a constant".chars() {
            state.key(ReviewKey::Char(c));
        }
        state.key(ReviewKey::Enter);
        match state.key(ReviewKey::Close) {
            ReviewOutcome::Close(Some(prompt)) => assert!(prompt.contains("f.txt:")),
            _ => panic!("expected a prompt"),
        }
    }
}
