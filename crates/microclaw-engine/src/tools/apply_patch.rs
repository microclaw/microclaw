//! `apply_patch`: add, delete, move and edit several files in one call.
//!
//! The patch uses the plain-text envelope coding models are trained on:
//!
//! ```text
//! *** Begin Patch
//! *** Add File: src/new.rs
//! +fn main() {}
//! *** Update File: src/lib.rs
//! *** Move to: src/core.rs
//! @@ fn parse
//!  context line
//! -removed line
//! +added line
//! *** Delete File: old.txt
//! *** End Patch
//! ```
//!
//! Every operation is checked (paths, the stale-read guard, hunk matching)
//! before anything is written, so a patch applies completely or not at all.
//! Hunks are located after the previous hunk of the same file, first by
//! exact lines, then ignoring trailing whitespace, then ignoring surrounding
//! whitespace; an `@@ <text>` header first moves past the line containing
//! `<text>`.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use serde_json::json;

use crate::config::WorkingDirIsolation;
use microclaw_core::llm_types::ToolDefinition;

use super::{schema_object, Tool, ToolResult};

pub struct ApplyPatchTool {
    working_dir: PathBuf,
    working_dir_isolation: WorkingDirIsolation,
    diff_max_lines: usize,
    governance_guard: crate::internal::tool_runtime::path_guard::GovernanceGuard,
    file_state: std::sync::Arc<super::file_state::FileStateTable>,
}

impl ApplyPatchTool {
    pub fn new_with_isolation(
        working_dir: &str,
        working_dir_isolation: WorkingDirIsolation,
    ) -> Self {
        Self {
            working_dir: PathBuf::from(working_dir),
            working_dir_isolation,
            diff_max_lines: microclaw_core::diff::DEFAULT_DIFF_MAX_LINES,
            governance_guard: Default::default(),
            file_state: Default::default(),
        }
    }

    pub fn with_file_state(
        mut self,
        file_state: std::sync::Arc<super::file_state::FileStateTable>,
    ) -> Self {
        self.file_state = file_state;
        self
    }

    pub fn with_diff_max_lines(mut self, max_lines: usize) -> Self {
        self.diff_max_lines = max_lines;
        self
    }

    pub fn with_governance_guard(
        mut self,
        guard: crate::internal::tool_runtime::path_guard::GovernanceGuard,
    ) -> Self {
        self.governance_guard = guard;
        self
    }
}

/// One parsed file operation.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Op {
    Add {
        path: String,
        content: String,
    },
    Delete {
        path: String,
    },
    Update {
        path: String,
        move_to: Option<String>,
        hunks: Vec<Hunk>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct Hunk {
    /// Text after `@@`, used to locate the hunk.
    anchor: Option<String>,
    old: Vec<String>,
    new: Vec<String>,
    /// `*** End of File`: the hunk must match at the end of the file.
    at_eof: bool,
}

const BEGIN: &str = "*** Begin Patch";
const END: &str = "*** End Patch";
const ADD: &str = "*** Add File: ";
const DELETE: &str = "*** Delete File: ";
const UPDATE: &str = "*** Update File: ";
const MOVE: &str = "*** Move to: ";
const EOF_MARKER: &str = "*** End of File";

fn parse_patch(text: &str) -> Result<Vec<Op>, String> {
    let lines: Vec<&str> = text.trim().lines().collect();
    let (first, last) = (lines.first().copied(), lines.last().copied());
    if first.map(str::trim) != Some(BEGIN) {
        return Err(format!("The patch must start with `{BEGIN}`"));
    }
    if last.map(str::trim) != Some(END) {
        return Err(format!("The patch must end with `{END}`"));
    }
    let body = &lines[1..lines.len() - 1];
    let mut ops = Vec::new();
    let mut i = 0;
    while i < body.len() {
        let line = body[i];
        if let Some(path) = line.strip_prefix(ADD) {
            i += 1;
            let mut content = String::new();
            while i < body.len() && !body[i].starts_with("*** ") {
                let Some(added) = body[i].strip_prefix('+') else {
                    return Err(format!(
                        "Line {}: every line of an added file must start with `+`",
                        i + 2
                    ));
                };
                content.push_str(added);
                content.push('\n');
                i += 1;
            }
            ops.push(Op::Add {
                path: path.trim().to_string(),
                content,
            });
        } else if let Some(path) = line.strip_prefix(DELETE) {
            ops.push(Op::Delete {
                path: path.trim().to_string(),
            });
            i += 1;
        } else if let Some(path) = line.strip_prefix(UPDATE) {
            i += 1;
            let mut move_to = None;
            if let Some(target) = body.get(i).and_then(|l| l.strip_prefix(MOVE)) {
                move_to = Some(target.trim().to_string());
                i += 1;
            }
            let mut hunks: Vec<Hunk> = Vec::new();
            let mut current: Option<Hunk> = None;
            while i < body.len() {
                let line = body[i];
                if line.trim() == EOF_MARKER {
                    current.get_or_insert_with(Hunk::default).at_eof = true;
                    i += 1;
                    continue;
                }
                if line.starts_with("*** ") {
                    break;
                }
                if let Some(anchor) = line.strip_prefix("@@") {
                    if let Some(hunk) = current.take() {
                        hunks.push(hunk);
                    }
                    let anchor = anchor.trim();
                    current = Some(Hunk {
                        anchor: (!anchor.is_empty()).then(|| anchor.to_string()),
                        ..Hunk::default()
                    });
                    i += 1;
                    continue;
                }
                let hunk = current.get_or_insert_with(Hunk::default);
                match line.chars().next() {
                    Some('+') => hunk.new.push(line[1..].to_string()),
                    Some('-') => hunk.old.push(line[1..].to_string()),
                    Some(' ') => {
                        hunk.old.push(line[1..].to_string());
                        hunk.new.push(line[1..].to_string());
                    }
                    // A bare empty line inside a hunk is an empty context line.
                    None => {
                        hunk.old.push(String::new());
                        hunk.new.push(String::new());
                    }
                    Some(_) => {
                        return Err(format!(
                            "Line {}: hunk lines must start with ` `, `-` or `+` (got {line:?})",
                            i + 2
                        ))
                    }
                }
                i += 1;
            }
            if let Some(hunk) = current.take() {
                hunks.push(hunk);
            }
            hunks.retain(|h| !(h.old.is_empty() && h.new.is_empty()));
            if hunks.is_empty() && move_to.is_none() {
                return Err(format!("`{UPDATE}{}` has no changes", path.trim()));
            }
            ops.push(Op::Update {
                path: path.trim().to_string(),
                move_to,
                hunks,
            });
        } else if line.trim().is_empty() {
            i += 1;
        } else {
            return Err(format!(
                "Line {}: expected `{ADD}`, `{DELETE}` or `{UPDATE}`, got {line:?}",
                i + 2
            ));
        }
    }
    if ops.is_empty() {
        return Err("The patch contains no file operations".into());
    }
    for op in &ops {
        let path = match op {
            Op::Add { path, .. } | Op::Delete { path } | Op::Update { path, .. } => path,
        };
        if path.is_empty() {
            return Err("A file operation is missing its path".into());
        }
    }
    Ok(ops)
}

/// Find `needle` in `lines` at or after `from`. Tries exact, then
/// trailing-whitespace-insensitive, then whitespace-insensitive matching.
fn find_lines(lines: &[String], needle: &[String], from: usize, at_eof: bool) -> Option<usize> {
    if needle.is_empty() {
        return Some(lines.len());
    }
    if needle.len() > lines.len() {
        return None;
    }
    let last_start = lines.len() - needle.len();
    let candidates: Vec<usize> = if at_eof {
        vec![last_start]
    } else {
        (from.min(last_start + 1)..=last_start).collect()
    };
    let normalizers: [fn(&str) -> &str; 3] = [|s| s, str::trim_end, str::trim];
    for normalize in normalizers {
        for &start in &candidates {
            if lines[start..start + needle.len()]
                .iter()
                .zip(needle)
                .all(|(a, b)| normalize(a) == normalize(b))
            {
                return Some(start);
            }
        }
    }
    None
}

fn apply_hunks(path: &str, content: &str, hunks: &[Hunk]) -> Result<String, String> {
    let had_trailing_newline = content.ends_with('\n') || content.is_empty();
    let mut lines: Vec<String> = content.lines().map(str::to_string).collect();
    let mut cursor = 0;
    for (index, hunk) in hunks.iter().enumerate() {
        if let Some(anchor) = &hunk.anchor {
            match lines[cursor.min(lines.len())..]
                .iter()
                .position(|l| l.contains(anchor.as_str()))
            {
                Some(offset) => {
                    // Context lines may include the anchor line itself.
                    cursor += offset;
                    if hunk
                        .old
                        .first()
                        .is_none_or(|first| first.trim() != anchor.trim())
                    {
                        cursor += 1;
                    }
                }
                None => {
                    return Err(format!(
                        "{path}: hunk {} anchor `@@ {anchor}` was not found",
                        index + 1
                    ))
                }
            }
        }
        let Some(start) = find_lines(&lines, &hunk.old, cursor, hunk.at_eof) else {
            let preview: Vec<&str> = hunk.old.iter().take(3).map(String::as_str).collect();
            return Err(format!(
                "{path}: hunk {} does not match the file (looking for {:?}{}). Read the file again and resend the patch with exact context lines.",
                index + 1,
                preview,
                if hunk.old.len() > 3 { ", …" } else { "" }
            ));
        };
        lines.splice(start..start + hunk.old.len(), hunk.new.iter().cloned());
        cursor = start + hunk.new.len();
    }
    let mut out = lines.join("\n");
    if had_trailing_newline && !out.is_empty() {
        out.push('\n');
    }
    Ok(out)
}

/// A fully checked change to one path.
struct Planned {
    /// Path as written in the patch (for diffs and messages).
    display: String,
    target: PathBuf,
    /// `None` = delete the target.
    new_content: Option<String>,
    old_content: String,
    /// Also remove this path (the source of a move).
    remove_source: Option<PathBuf>,
    verb: &'static str,
}

impl ApplyPatchTool {
    fn resolve(&self, working_dir: &Path, path: &str) -> Result<PathBuf, String> {
        let resolved = super::resolve_tool_path(working_dir, path);
        crate::internal::tool_runtime::path_guard::check_path(&resolved.to_string_lossy())?;
        self.governance_guard.check_write(&resolved)?;
        Ok(resolved)
    }

    async fn read_fresh(&self, path: &Path, display: &str) -> Result<String, String> {
        let content = tokio::fs::read_to_string(path)
            .await
            .map_err(|e| format!("{display}: cannot read the file: {e}"))?;
        self.file_state.check_fresh(path, content.as_bytes())?;
        Ok(content)
    }

    async fn plan(&self, working_dir: &Path, ops: Vec<Op>) -> Result<Vec<Planned>, String> {
        let mut planned: Vec<Planned> = Vec::new();
        let mut touched: Vec<PathBuf> = Vec::new();
        let mut claim = |path: &PathBuf, display: &str| {
            if touched.contains(path) {
                Err(format!(
                    "{display}: the patch changes this file more than once"
                ))
            } else {
                touched.push(path.clone());
                Ok(())
            }
        };
        for op in ops {
            match op {
                Op::Add { path, content } => {
                    let target = self.resolve(working_dir, &path)?;
                    claim(&target, &path)?;
                    if tokio::fs::try_exists(&target).await.unwrap_or(false) {
                        return Err(format!(
                            "{path}: already exists; use `{UPDATE}{path}` to change it"
                        ));
                    }
                    planned.push(Planned {
                        display: path,
                        target,
                        new_content: Some(content),
                        old_content: String::new(),
                        remove_source: None,
                        verb: "added",
                    });
                }
                Op::Delete { path } => {
                    let target = self.resolve(working_dir, &path)?;
                    claim(&target, &path)?;
                    let old_content = self.read_fresh(&target, &path).await?;
                    planned.push(Planned {
                        display: path,
                        target,
                        new_content: None,
                        old_content,
                        remove_source: None,
                        verb: "deleted",
                    });
                }
                Op::Update {
                    path,
                    move_to,
                    hunks,
                } => {
                    let source = self.resolve(working_dir, &path)?;
                    claim(&source, &path)?;
                    let old_content = self.read_fresh(&source, &path).await?;
                    let new_content = apply_hunks(&path, &old_content, &hunks)?;
                    let (display, target, remove_source) = match move_to {
                        Some(dest) => {
                            let target = self.resolve(working_dir, &dest)?;
                            claim(&target, &dest)?;
                            if tokio::fs::try_exists(&target).await.unwrap_or(false) {
                                return Err(format!("{dest}: move target already exists"));
                            }
                            (dest, target, Some(source))
                        }
                        None => (path, source, None),
                    };
                    let verb = if remove_source.is_some() {
                        "moved"
                    } else {
                        "updated"
                    };
                    planned.push(Planned {
                        display,
                        target,
                        new_content: Some(new_content),
                        old_content,
                        remove_source,
                        verb,
                    });
                }
            }
        }
        Ok(planned)
    }
}

#[async_trait]
impl Tool for ApplyPatchTool {
    fn name(&self) -> &str {
        "apply_patch"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "apply_patch".into(),
            description: "Add, delete, move and edit files in one atomic call. Use it for changes that span several files or several places in a file. The patch format:\n\n*** Begin Patch\n*** Add File: path/new.txt\n+every line of the new file starts with +\n*** Update File: path/existing.rs\n*** Move to: path/renamed.rs   (optional)\n@@ optional line that appears just before the change, e.g. a function signature\n unchanged context line (leading space)\n-removed line\n+added line\n*** Delete File: path/obsolete.txt\n*** End Patch\n\nGive 1-3 context lines around each change so it can be located; hunks of one file apply in order. All operations are checked before anything is written: if one fails, nothing changes. Edits are refused when a file changed on disk after you last read it. Paths are relative to the working directory.".into(),
            input_schema: schema_object(
                json!({
                    "patch": {
                        "type": "string",
                        "description": "The full patch text, from `*** Begin Patch` to `*** End Patch`"
                    }
                }),
                &["patch"],
            ),
        }
    }

    async fn execute(&self, input: serde_json::Value) -> ToolResult {
        let Some(patch) = input
            .get("patch")
            .or_else(|| input.get("input"))
            .and_then(|v| v.as_str())
        else {
            return ToolResult::error("Missing 'patch' parameter".into());
        };
        let ops = match parse_patch(patch) {
            Ok(ops) => ops,
            Err(msg) => return ToolResult::error(format!("Invalid patch: {msg}")),
        };
        let working_dir =
            super::resolve_tool_working_dir(&self.working_dir, self.working_dir_isolation, &input);
        let planned = match self.plan(&working_dir, ops).await {
            Ok(planned) => planned,
            Err(msg) if msg.contains("modified on disk") => {
                return ToolResult::error(format!("{msg} No files were changed."))
                    .with_error_type("stale_read")
            }
            Err(msg) => {
                return ToolResult::error(format!(
                    "{}. No files were changed.",
                    msg.trim_end_matches('.')
                ))
            }
        };

        let mut summary = Vec::new();
        let mut diffs = Vec::new();
        for change in &planned {
            let outcome = match &change.new_content {
                Some(content) => {
                    if let Some(parent) = change.target.parent() {
                        if let Err(e) = tokio::fs::create_dir_all(parent).await {
                            return ToolResult::error(format!(
                                "{}: cannot create its directory: {e}",
                                change.display
                            ));
                        }
                    }
                    tokio::fs::write(&change.target, content).await
                }
                None => tokio::fs::remove_file(&change.target).await,
            };
            if let Err(e) = outcome {
                return ToolResult::error(format!(
                    "{}: write failed: {e}. Earlier operations of this patch were already applied: {}",
                    change.display,
                    if summary.is_empty() { "none".to_string() } else { summary.join(", ") }
                ));
            }
            if let Some(source) = &change.remove_source {
                let _ = tokio::fs::remove_file(source).await;
            }
            match &change.new_content {
                Some(content) => self.file_state.record(&change.target, content.as_bytes()),
                None => self.file_state.record(&change.target, b""),
            }
            let new = change.new_content.as_deref().unwrap_or("");
            let verb = change.verb;
            let diff =
                microclaw_core::diff::unified_diff(&change.old_content, new, self.diff_max_lines);
            summary.push(match &diff {
                Some(d) => format!("{verb} {} ({})", change.display, d.stats()),
                None => format!("{verb} {}", change.display),
            });
            if let Some(d) = diff {
                diffs.push((change.display.clone(), d));
            }
        }
        let mut result = ToolResult::success(format!("Applied patch: {}", summary.join(", ")));
        if !diffs.is_empty() {
            result = result.with_metadata(microclaw_core::diff::file_diffs_metadata(&diffs));
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool(dir: &Path) -> ApplyPatchTool {
        ApplyPatchTool::new_with_isolation(dir.to_str().unwrap(), WorkingDirIsolation::Direct)
    }

    async fn run(dir: &Path, patch: &str) -> ToolResult {
        tool(dir).execute(json!({ "patch": patch })).await
    }

    #[tokio::test]
    async fn adds_updates_moves_and_deletes_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lib.rs"),
            "fn a() {\n    1\n}\n\nfn b() {\n    2\n}\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("old.txt"), "bye\n").unwrap();
        std::fs::write(dir.path().join("name.txt"), "x\ny\n").unwrap();
        let result = run(
            dir.path(),
            "*** Begin Patch
*** Add File: src/new.rs
+fn main() {}
*** Update File: lib.rs
@@ fn b() {
-    2
+    20
*** Update File: name.txt
*** Move to: renamed.txt
 x
-y
+z
*** Delete File: old.txt
*** End Patch",
        )
        .await;
        assert!(!result.is_error, "{}", result.content);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("src/new.rs")).unwrap(),
            "fn main() {}\n"
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("lib.rs")).unwrap(),
            "fn a() {\n    1\n}\n\nfn b() {\n    20\n}\n"
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("renamed.txt")).unwrap(),
            "x\nz\n"
        );
        assert!(!dir.path().join("name.txt").exists());
        assert!(!dir.path().join("old.txt").exists());
        let diffs = result
            .metadata
            .as_ref()
            .and_then(|m| m.get(microclaw_core::diff::FILE_DIFFS_METADATA_KEY))
            .and_then(|v| v.as_array())
            .unwrap();
        assert_eq!(diffs.len(), 4);
    }

    #[tokio::test]
    async fn a_failing_hunk_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "one\ntwo\n").unwrap();
        let result = run(
            dir.path(),
            "*** Begin Patch
*** Add File: b.txt
+new
*** Update File: a.txt
-three
+four
*** End Patch",
        )
        .await;
        assert!(result.is_error);
        assert!(
            result.content.contains("does not match"),
            "{}",
            result.content
        );
        assert!(result.content.contains("No files were changed"));
        assert!(!dir.path().join("b.txt").exists());
        assert_eq!(
            std::fs::read_to_string(dir.path().join("a.txt")).unwrap(),
            "one\ntwo\n"
        );
    }

    #[tokio::test]
    async fn whitespace_tolerant_matching_and_ordered_hunks() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("a.py"),
            "x = 1  \ny = 2\nz = 1\ny = 2\nz = 1\n",
        )
        .unwrap();
        let result = run(
            dir.path(),
            "*** Begin Patch
*** Update File: a.py
-x = 1
+x = 10
@@ z = 1
 y = 2
-z = 1
+z = 30
*** End Patch",
        )
        .await;
        assert!(!result.is_error, "{}", result.content);
        // The trailing-space line matched loosely; the anchor skipped the
        // first `z = 1`, so the second hunk changed the later one.
        assert_eq!(
            std::fs::read_to_string(dir.path().join("a.py")).unwrap(),
            "x = 10\ny = 2\nz = 1\ny = 2\nz = 30\n"
        );
    }

    #[tokio::test]
    async fn refuses_stale_files_and_existing_add_targets() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "one\n").unwrap();
        let tool = tool(dir.path());
        tool.file_state.record(&dir.path().join("a.txt"), b"older");
        let stale = tool
            .execute(json!({"patch": "*** Begin Patch\n*** Update File: a.txt\n-one\n+two\n*** End Patch"}))
            .await;
        assert!(stale.is_error);
        assert_eq!(stale.error_type.as_deref(), Some("stale_read"));
        let exists = tool
            .execute(json!({"patch": "*** Begin Patch\n*** Add File: a.txt\n+x\n*** End Patch"}))
            .await;
        assert!(exists.is_error);
        assert!(exists.content.contains("already exists"));
    }

    #[test]
    fn rejects_malformed_patches() {
        assert!(parse_patch("*** Update File: a\n-x\n+y").is_err());
        assert!(parse_patch("*** Begin Patch\n*** End Patch").is_err());
        assert!(parse_patch("*** Begin Patch\n*** Add File: a\nno plus\n*** End Patch").is_err());
        assert!(parse_patch("*** Begin Patch\n*** Update File: a\n*** End Patch").is_err());
        assert!(parse_patch("*** Begin Patch\nhello\n*** End Patch").is_err());
    }

    #[test]
    fn end_of_file_hunks_match_at_the_end() {
        let out = apply_hunks(
            "a",
            "x\nend\nx\nend\n",
            &[Hunk {
                anchor: None,
                old: vec!["end".into()],
                new: vec!["END".into()],
                at_eof: true,
            }],
        )
        .unwrap();
        assert_eq!(out, "x\nend\nx\nEND\n");
    }
}
