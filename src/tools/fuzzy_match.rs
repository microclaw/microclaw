//! Multi-strategy fuzzy matching for `edit_file`.
//!
//! LLMs frequently produce `old_string` arguments that don't byte-exactly match
//! the file contents — wrong indentation, smart quotes pasted from a doc,
//! collapsed whitespace, literal `\n` instead of newlines, etc. This module
//! tries an ordered chain of increasingly-fuzzy strategies, returning the
//! first that matches uniquely. The caller learns which strategy fired so it
//! can surface that to the model (and the user).
//!
//! Hermes reference: `tools/fuzzy_match.py` (originally from OpenCode).
//! Strategies (in order):
//!  1. exact
//!  2. line_trimmed     — strip leading/trailing ws per line
//!  3. whitespace_normalized — collapse runs of spaces/tabs
//!  4. indentation_flexible — lstrip per line (the most common LLM mistake)
//!  5. escape_normalized — `\n`/`\t`/`\r` escape sequences → real chars
//!  6. trimmed_boundary  — trim only first and last lines
//!  7. unicode_normalized — smart quotes, em/en-dash, ellipsis, NBSP
//!  8. block_anchor      — first+last line anchor + middle similarity
//!
//! `context_aware` (50% line similarity) is intentionally NOT ported — it's
//! too loose and produces dangerous false positives.

use std::collections::HashMap;

/// Result of a fuzzy find/replace attempt.
#[derive(Debug)]
pub struct FuzzyMatch {
    pub new_content: String,
    pub strategy: &'static str,
    pub match_count: usize,
}

/// Try the strategy chain. Returns Ok if exactly one match was found via some
/// strategy. Returns Err with a human-readable explanation on no match,
/// multi-match, or escape-drift.
pub fn fuzzy_find_and_replace(
    content: &str,
    old_string: &str,
    new_string: &str,
) -> Result<FuzzyMatch, String> {
    if old_string.is_empty() {
        return Err("old_string cannot be empty".into());
    }
    if old_string == new_string {
        return Err("old_string and new_string are identical".into());
    }

    type StrategyFn = fn(&str, &str) -> Vec<(usize, usize)>;
    let strategies: &[(&str, StrategyFn)] = &[
        ("exact", strategy_exact),
        ("line_trimmed", strategy_line_trimmed),
        ("whitespace_normalized", strategy_whitespace_normalized),
        ("indentation_flexible", strategy_indentation_flexible),
        ("escape_normalized", strategy_escape_normalized),
        ("trimmed_boundary", strategy_trimmed_boundary),
        ("unicode_normalized", strategy_unicode_normalized),
        ("block_anchor", strategy_block_anchor),
    ];

    for (name, f) in strategies {
        let matches = f(content, old_string);
        if matches.is_empty() {
            continue;
        }

        if matches.len() > 1 {
            return Err(format!(
                "Found {} matches for old_string (matched via `{}` strategy). \
                 Provide more context to make it unique.",
                matches.len(),
                name
            ));
        }

        // Escape-drift guard: when not the exact strategy, check for
        // tool-call serialization drift (\\' or \\" copied as literal
        // backslash-escapes the file doesn't contain).
        if *name != "exact" {
            if let Some(err) = detect_escape_drift(content, &matches, old_string, new_string) {
                return Err(err);
            }
        }

        let new_content = apply_replacements(content, &matches, new_string);
        return Ok(FuzzyMatch {
            new_content,
            strategy: name,
            match_count: matches.len(),
        });
    }

    Err(
        "Could not find a match for old_string in the file (tried 8 strategies including \
         indentation-flexible, whitespace-normalized, and unicode-normalized matching). \
         Re-read the file with read_file to see the exact bytes."
            .into(),
    )
}

fn detect_escape_drift(
    content: &str,
    matches: &[(usize, usize)],
    old_string: &str,
    new_string: &str,
) -> Option<String> {
    if !new_string.contains("\\'") && !new_string.contains("\\\"") {
        return None;
    }
    let matched: String = matches
        .iter()
        .map(|(s, e)| &content[*s..*e])
        .collect::<Vec<_>>()
        .join("");

    for suspect in &["\\'", "\\\""] {
        if new_string.contains(suspect)
            && old_string.contains(suspect)
            && !matched.contains(suspect)
        {
            let plain = &suspect[1..];
            return Some(format!(
                "Escape-drift detected: old_string and new_string contain the literal sequence \
                 `{suspect}` but the matched region of the file does not. This is almost \
                 always a tool-call serialization artifact where an apostrophe or quote got \
                 prefixed with a spurious backslash. Re-read the file with read_file and pass \
                 old_string/new_string without backslash-escaping `{plain}` characters."
            ));
        }
    }
    None
}

fn apply_replacements(content: &str, matches: &[(usize, usize)], new_string: &str) -> String {
    let mut sorted: Vec<(usize, usize)> = matches.to_vec();
    sorted.sort_by(|a, b| b.0.cmp(&a.0));
    let mut result = content.to_string();
    for (start, end) in sorted {
        result.replace_range(start..end, new_string);
    }
    result
}

// =============================================================================
// Strategies
// =============================================================================

/// 1. Exact match — multiple non-overlapping occurrences.
fn strategy_exact(content: &str, pattern: &str) -> Vec<(usize, usize)> {
    if pattern.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut start = 0;
    while let Some(pos) = content[start..].find(pattern) {
        let abs = start + pos;
        out.push((abs, abs + pattern.len()));
        start = abs + 1;
    }
    out
}

/// 2. Trim each line of leading/trailing whitespace before matching.
fn strategy_line_trimmed(content: &str, pattern: &str) -> Vec<(usize, usize)> {
    let normalized_pattern = pattern
        .split('\n')
        .map(|l| l.trim())
        .collect::<Vec<_>>()
        .join("\n");
    line_block_match(
        content,
        pattern,
        |line| line.trim().to_string(),
        &normalized_pattern,
    )
}

/// 3. Collapse runs of spaces/tabs to a single space (preserve newlines).
fn strategy_whitespace_normalized(content: &str, pattern: &str) -> Vec<(usize, usize)> {
    let normalized_content = collapse_horizontal_ws(content);
    let normalized_pattern = collapse_horizontal_ws(pattern);
    if normalized_content == content && normalized_pattern == pattern {
        return Vec::new();
    }
    let norm_matches = strategy_exact(&normalized_content, &normalized_pattern);
    if norm_matches.is_empty() {
        return Vec::new();
    }
    map_collapsed_positions(content, &normalized_content, &norm_matches)
}

fn collapse_horizontal_ws(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_was_h_ws = false;
    for ch in s.chars() {
        if ch == ' ' || ch == '\t' {
            if !prev_was_h_ws {
                out.push(' ');
                prev_was_h_ws = true;
            }
        } else {
            out.push(ch);
            prev_was_h_ws = false;
        }
    }
    out
}

/// Build a map from byte index in normalised string back to byte index in
/// original when normalisation only DELETES bytes (i.e. it never inserts or
/// substitutes — ws collapse can do both, but we approximate by walking).
fn map_collapsed_positions(
    original: &str,
    normalized: &str,
    norm_matches: &[(usize, usize)],
) -> Vec<(usize, usize)> {
    // Build byte-position correspondence.
    let mut orig_to_norm: Vec<usize> = Vec::with_capacity(original.len() + 1);
    let mut norm_pos = 0;
    let mut prev_was_h_ws = false;
    for (i, ch) in original.char_indices() {
        orig_to_norm.push(norm_pos);
        if ch == ' ' || ch == '\t' {
            if !prev_was_h_ws {
                norm_pos += 1;
                prev_was_h_ws = true;
            }
        } else {
            norm_pos += ch.len_utf8();
            prev_was_h_ws = false;
        }
        let _ = i;
    }
    orig_to_norm.push(norm_pos);

    // Sentinel safety: if our reconstruction differs in length, bail.
    if norm_pos != normalized.len() {
        return Vec::new();
    }

    let mut out = Vec::new();
    for &(ns, ne) in norm_matches {
        let mut start_orig = None;
        let mut end_orig = None;
        for (orig_pos, &mapped) in orig_to_norm.iter().enumerate() {
            if start_orig.is_none() && mapped >= ns {
                start_orig = Some(orig_pos);
            }
            if mapped >= ne {
                end_orig = Some(orig_pos);
                break;
            }
        }
        if let (Some(s), Some(e)) = (start_orig, end_orig) {
            // Snap to char boundaries.
            let s = floor_char_boundary(original, s);
            let e = floor_char_boundary(original, e);
            if e > s {
                out.push((s, e));
            }
        }
    }
    out
}

fn floor_char_boundary(s: &str, mut idx: usize) -> usize {
    if idx >= s.len() {
        return s.len();
    }
    while !s.is_char_boundary(idx) && idx > 0 {
        idx -= 1;
    }
    idx
}

/// 4. Strip leading whitespace from every line — handles indent drift.
fn strategy_indentation_flexible(content: &str, pattern: &str) -> Vec<(usize, usize)> {
    let normalized_pattern = pattern
        .split('\n')
        .map(|l| l.trim_start())
        .collect::<Vec<_>>()
        .join("\n");
    line_block_match(
        content,
        pattern,
        |line| line.trim_start().to_string(),
        &normalized_pattern,
    )
}

/// 5. Convert `\\n`, `\\t`, `\\r` escape sequences to real chars.
fn strategy_escape_normalized(content: &str, pattern: &str) -> Vec<(usize, usize)> {
    let unescaped = pattern
        .replace("\\n", "\n")
        .replace("\\t", "\t")
        .replace("\\r", "\r");
    if unescaped == pattern {
        return Vec::new();
    }
    strategy_exact(content, &unescaped)
}

/// 6. Trim whitespace from first and last lines only.
fn strategy_trimmed_boundary(content: &str, pattern: &str) -> Vec<(usize, usize)> {
    let mut pat_lines: Vec<String> = pattern.split('\n').map(|s| s.to_string()).collect();
    if pat_lines.is_empty() {
        return Vec::new();
    }
    pat_lines[0] = pat_lines[0].trim().to_string();
    let n = pat_lines.len();
    if n > 1 {
        pat_lines[n - 1] = pat_lines[n - 1].trim().to_string();
    }
    let modified_pattern = pat_lines.join("\n");

    let content_lines: Vec<&str> = content.split('\n').collect();
    let mut out = Vec::new();
    let pat_count = pat_lines.len();
    if pat_count == 0 || content_lines.len() < pat_count {
        return out;
    }

    for i in 0..=content_lines.len() - pat_count {
        let mut block: Vec<String> = content_lines[i..i + pat_count]
            .iter()
            .map(|s| s.to_string())
            .collect();
        block[0] = block[0].trim().to_string();
        if pat_count > 1 {
            block[pat_count - 1] = block[pat_count - 1].trim().to_string();
        }
        if block.join("\n") == modified_pattern {
            if let Some((s, e)) =
                line_range_to_byte_range(content, &content_lines, i, i + pat_count)
            {
                out.push((s, e));
            }
        }
    }
    out
}

/// 7. Unicode-normalise smart quotes, em/en-dashes, ellipsis, NBSP.
fn strategy_unicode_normalized(content: &str, pattern: &str) -> Vec<(usize, usize)> {
    let norm_content = unicode_normalize(content);
    let norm_pattern = unicode_normalize(pattern);
    if norm_content == content && norm_pattern == pattern {
        return Vec::new();
    }
    let norm_matches = strategy_exact(&norm_content, &norm_pattern);
    let norm_matches = if norm_matches.is_empty() {
        let mp = norm_pattern
            .split('\n')
            .map(|l| l.trim())
            .collect::<Vec<_>>()
            .join("\n");
        line_block_match(&norm_content, &norm_pattern, |l| l.trim().to_string(), &mp)
    } else {
        norm_matches
    };
    if norm_matches.is_empty() {
        return Vec::new();
    }

    let orig_to_norm = build_orig_to_norm_map(content);
    map_norm_to_orig(content, &orig_to_norm, &norm_matches)
}

fn unicode_normalize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\u{201C}' | '\u{201D}' => out.push('"'),
            '\u{2018}' | '\u{2019}' => out.push('\''),
            '\u{2014}' => out.push_str("--"),
            '\u{2013}' => out.push('-'),
            '\u{2026}' => out.push_str("..."),
            '\u{00A0}' => out.push(' '),
            other => out.push(other),
        }
    }
    out
}

/// For each char in `original` (by byte index), record the byte offset in the
/// unicode-normalised string. Length = original.len() + 1; final entry is the
/// total normalised byte length.
fn build_orig_to_norm_map(original: &str) -> Vec<usize> {
    let mut map = Vec::with_capacity(original.len() + 1);
    let mut np = 0usize;
    for (idx, ch) in original.char_indices() {
        // Pad bytes inside a multibyte char with the same starting np.
        while map.len() < idx {
            map.push(np);
        }
        map.push(np);
        let replaced_len = match ch {
            '\u{201C}' | '\u{201D}' | '\u{2018}' | '\u{2019}' | '\u{00A0}' => 1,
            '\u{2014}' => 2,
            '\u{2013}' => 1,
            '\u{2026}' => 3,
            other => other.len_utf8(),
        };
        np += replaced_len;
    }
    while map.len() < original.len() {
        map.push(np);
    }
    map.push(np);
    map
}

fn map_norm_to_orig(
    original: &str,
    orig_to_norm: &[usize],
    norm_matches: &[(usize, usize)],
) -> Vec<(usize, usize)> {
    // Invert: norm_pos -> first orig_pos that maps to it.
    let mut norm_to_orig: HashMap<usize, usize> = HashMap::new();
    for (orig_pos, &mapped) in orig_to_norm.iter().enumerate().take(orig_to_norm.len() - 1) {
        norm_to_orig.entry(mapped).or_insert(orig_pos);
    }
    let orig_len = orig_to_norm.len() - 1;
    let mut out = Vec::new();
    for &(ns, ne) in norm_matches {
        let Some(&start) = norm_to_orig.get(&ns) else {
            continue;
        };
        let mut end = start;
        while end < orig_len && orig_to_norm[end] < ne {
            end += 1;
        }
        let start = floor_char_boundary(original, start);
        let end = floor_char_boundary(original, end);
        if end > start {
            out.push((start, end));
        }
    }
    out
}

/// 8. Anchor on first/last line + similarity on the middle. Threshold 0.50
///    when there's exactly one anchor match, 0.70 otherwise.
fn strategy_block_anchor(content: &str, pattern: &str) -> Vec<(usize, usize)> {
    let norm_content = unicode_normalize(content);
    let norm_pattern = unicode_normalize(pattern);
    let pat_lines: Vec<&str> = norm_pattern.split('\n').collect();
    if pat_lines.len() < 2 {
        return Vec::new();
    }
    let first = pat_lines[0].trim();
    let last = pat_lines[pat_lines.len() - 1].trim();

    let norm_lines: Vec<&str> = norm_content.split('\n').collect();
    let orig_lines: Vec<&str> = content.split('\n').collect();
    let pat_count = pat_lines.len();
    if norm_lines.len() < pat_count {
        return Vec::new();
    }

    let mut potential = Vec::new();
    for i in 0..=norm_lines.len() - pat_count {
        if norm_lines[i].trim() == first && norm_lines[i + pat_count - 1].trim() == last {
            potential.push(i);
        }
    }

    let threshold = if potential.len() == 1 { 0.50 } else { 0.70 };
    let mut out = Vec::new();
    for i in potential {
        let similarity = if pat_count <= 2 {
            1.0
        } else {
            let content_middle = norm_lines[i + 1..i + pat_count - 1].join("\n");
            let pattern_middle = pat_lines[1..pat_count - 1].join("\n");
            sequence_ratio(&content_middle, &pattern_middle)
        };
        if similarity >= threshold {
            if let Some((s, e)) = line_range_to_byte_range(content, &orig_lines, i, i + pat_count) {
                out.push((s, e));
            }
        }
    }
    out
}

// =============================================================================
// Helpers shared across strategies
// =============================================================================

/// Generic line-block scanner: normalise each line via `norm_line`, look for
/// `normalized_pattern` as a contiguous slice of normalised lines, and report
/// byte ranges in `content`.
fn line_block_match<F>(
    content: &str,
    pattern: &str,
    norm_line: F,
    normalized_pattern: &str,
) -> Vec<(usize, usize)>
where
    F: Fn(&str) -> String,
{
    let pat_lines: Vec<String> = normalized_pattern
        .split('\n')
        .map(|s| s.to_string())
        .collect();
    let pat_count = pat_lines.len();
    if pat_count == 0 {
        return Vec::new();
    }
    let content_lines: Vec<&str> = content.split('\n').collect();
    if content_lines.len() < pat_count {
        return Vec::new();
    }
    let normalized_lines: Vec<String> = content_lines.iter().map(|l| norm_line(l)).collect();
    let _ = pattern;

    let mut out = Vec::new();
    for i in 0..=content_lines.len() - pat_count {
        let block: &[String] = &normalized_lines[i..i + pat_count];
        if block == pat_lines.as_slice() {
            if let Some((s, e)) =
                line_range_to_byte_range(content, &content_lines, i, i + pat_count)
            {
                out.push((s, e));
            }
        }
    }
    out
}

/// Convert (start_line, end_line_exclusive) into a byte range over `content`.
/// The range covers [start_of_line(start), end_of_line(end-1)) — i.e. it does
/// NOT include the trailing newline of the last line, which matches Hermes's
/// `_calculate_line_positions` behavior.
fn line_range_to_byte_range(
    content: &str,
    content_lines: &[&str],
    start_line: usize,
    end_line: usize,
) -> Option<(usize, usize)> {
    if start_line >= content_lines.len() || end_line == 0 {
        return None;
    }
    // Compute byte offset to start of `start_line`.
    let mut offset = 0usize;
    for (i, line) in content_lines.iter().enumerate() {
        if i == start_line {
            break;
        }
        offset += line.len() + 1; // +1 for the '\n' separator
    }
    let start_byte = offset;

    // Walk to end_line.
    let mut end_byte = offset;
    for (idx, line) in content_lines.iter().enumerate().skip(start_line) {
        if idx >= end_line {
            break;
        }
        end_byte += line.len();
        // Add the trailing newline EXCEPT for the last line of the block.
        if idx < end_line - 1 {
            end_byte += 1;
        }
    }
    // Don't run past content (empty trailing lines from split).
    if end_byte > content.len() {
        end_byte = content.len();
    }
    Some((start_byte, end_byte))
}

/// difflib.SequenceMatcher.ratio() approximation: 2 * matches / (len(a) + len(b)).
/// "matches" computed via LCS over the chars of both strings. O(n*m) memory —
/// fine for typical edit_file payloads which are small.
fn sequence_ratio(a: &str, b: &str) -> f64 {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let total = a.len() + b.len();
    if total == 0 {
        return 1.0;
    }
    // Cap to avoid pathological mem use.
    if a.len() > 4096 || b.len() > 4096 {
        // Fall back to length-based heuristic.
        let common = a.iter().zip(b.iter()).filter(|(x, y)| x == y).count();
        return 2.0 * common as f64 / total as f64;
    }
    let mut prev = vec![0usize; b.len() + 1];
    let mut curr = vec![0usize; b.len() + 1];
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            if a[i - 1] == b[j - 1] {
                curr[j] = prev[j - 1] + 1;
            } else {
                curr[j] = prev[j].max(curr[j - 1]);
            }
        }
        std::mem::swap(&mut prev, &mut curr);
        for v in curr.iter_mut() {
            *v = 0;
        }
    }
    let matches = prev[b.len()];
    2.0 * matches as f64 / total as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match_passes_through() {
        let r = fuzzy_find_and_replace("hello world", "world", "rust").unwrap();
        assert_eq!(r.new_content, "hello rust");
        assert_eq!(r.strategy, "exact");
    }

    #[test]
    fn empty_old_string_errors() {
        assert!(fuzzy_find_and_replace("x", "", "y").is_err());
    }

    #[test]
    fn identical_strings_error() {
        assert!(fuzzy_find_and_replace("x", "y", "y").is_err());
    }

    #[test]
    fn line_trimmed_recovers_from_trailing_ws() {
        let content = "fn foo() {  \n    bar();\n}";
        let pattern = "fn foo() {\n    bar();\n}";
        let r = fuzzy_find_and_replace(content, pattern, "fn baz() {\n    qux();\n}").unwrap();
        assert_eq!(r.strategy, "line_trimmed");
        assert!(r.new_content.contains("baz"));
    }

    #[test]
    fn indentation_flexible_recovers_wrong_indent() {
        let content = "        if x:\n            return 1\n";
        let pattern = "if x:\n    return 1";
        let r = fuzzy_find_and_replace(content, pattern, "if y:\n    return 2").unwrap();
        // line_trimmed is more permissive than indentation_flexible and may
        // win first; we only require that SOME normalising strategy succeeds.
        assert!(
            matches!(r.strategy, "line_trimmed" | "indentation_flexible"),
            "got strategy={}",
            r.strategy
        );
        assert!(r.new_content.contains("if y"));
    }

    #[test]
    fn escape_normalized_handles_literal_backslash_n() {
        let content = "alpha\nbeta\ngamma";
        let pattern = "alpha\\nbeta";
        let r = fuzzy_find_and_replace(content, pattern, "ALPHA\nBETA").unwrap();
        assert_eq!(r.strategy, "escape_normalized");
        assert!(r.new_content.starts_with("ALPHA\nBETA"));
    }

    #[test]
    fn unicode_normalized_smart_quotes() {
        let content = "let s = \"hi\";";
        // smart double quotes
        let pattern = "let s = \u{201C}hi\u{201D};";
        let r = fuzzy_find_and_replace(content, pattern, "let s = \"bye\";").unwrap();
        assert_eq!(r.strategy, "unicode_normalized");
        assert!(r.new_content.contains("bye"));
    }

    #[test]
    fn whitespace_normalized_collapses_runs() {
        let content = "foo   bar    baz";
        let pattern = "foo bar baz";
        let r = fuzzy_find_and_replace(content, pattern, "FOO BAR BAZ").unwrap();
        assert_eq!(r.strategy, "whitespace_normalized");
        // After replace, original spans (foo...baz) become FOO BAR BAZ.
        assert!(r.new_content.contains("FOO BAR BAZ"));
    }

    #[test]
    fn block_anchor_with_similar_middle() {
        let content = "fn foo() {\n    let x = 1;\n    let y = 2;\n    let z = 3;\n}\n";
        // Same anchor lines, slightly different middle (one renamed var).
        let pattern = "fn foo() {\n    let x = 1;\n    let y = 22;\n    let z = 3;\n}";
        let r = fuzzy_find_and_replace(content, pattern, "fn bar() {}").unwrap();
        assert_eq!(r.strategy, "block_anchor");
        assert!(r.new_content.contains("fn bar"));
    }

    #[test]
    fn multi_match_errors_with_strategy_name() {
        let content = "aaa bbb aaa";
        let err = fuzzy_find_and_replace(content, "aaa", "ccc").unwrap_err();
        assert!(err.contains("2 matches"));
        assert!(err.contains("exact"));
    }

    #[test]
    fn no_match_error_mentions_strategies() {
        let err = fuzzy_find_and_replace("hello", "completely different", "x").unwrap_err();
        assert!(err.contains("8 strategies"));
    }

    #[test]
    fn escape_drift_blocked() {
        // Drift only fires when SOME non-exact strategy matched and the
        // matched region of the file lacks the suspect escape. Use
        // block_anchor: matching first/last line + similar middle.
        let content = "fn foo() {\n    println!('hi');\n}\n";
        let pattern = "fn foo() {\n    println!(\\'hi\\');\n}";
        let new_str = "fn bar() {\n    println!(\\'bye\\');\n}";
        let err = fuzzy_find_and_replace(content, pattern, new_str).unwrap_err();
        assert!(err.contains("Escape-drift detected"), "got: {err}");
    }

    #[test]
    fn trimmed_boundary_recovers_first_line_ws() {
        let content = "    fn foo() {\n    pass\n    }\n";
        let pattern = "fn foo() {\n    pass\n}";
        let r = fuzzy_find_and_replace(content, pattern, "fn bar() {\n    pass\n}").unwrap();
        // line_trimmed already covers strict per-line strip; we just want SOME
        // strategy to succeed.
        assert!(r.strategy == "line_trimmed" || r.strategy == "trimmed_boundary");
        assert!(r.new_content.contains("fn bar"));
    }

    #[test]
    fn sequence_ratio_basic() {
        assert!((sequence_ratio("abc", "abc") - 1.0).abs() < 1e-9);
        assert!((sequence_ratio("abc", "xyz") - 0.0).abs() < 1e-9);
        assert!(sequence_ratio("abcd", "abce") > 0.5);
    }
}
