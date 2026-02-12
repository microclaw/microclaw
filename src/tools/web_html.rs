use crate::text::floor_char_boundary;
use std::borrow::Cow;

#[derive(Debug, Clone)]
pub struct SearchItem {
    pub title: String,
    pub url: String,
    pub snippet: String,
}

fn strip_block(mut html: String, tag: &str) -> String {
    let open = format!("<{}", tag);
    let close = format!("</{}>", tag);
    loop {
        let Some(start) = find_case_insensitive(&html, &open, 0) else {
            break;
        };
        let Some(end) = find_case_insensitive(&html, &close, start) else {
            html.truncate(start);
            break;
        };
        let remove_to = end + close.len();
        html.replace_range(start..remove_to, " ");
    }
    html
}

fn find_case_insensitive(haystack: &str, needle: &str, from: usize) -> Option<usize> {
    if from >= haystack.len() {
        return None;
    }

    // Callers may pass byte offsets derived from external data; coerce to a valid
    // UTF-8 boundary to avoid panics when slicing.
    let from = crate::text::floor_char_boundary(haystack, from);
    let h = haystack[from..].to_ascii_lowercase();
    let n = needle.to_ascii_lowercase();
    h.find(&n).map(|idx| from + idx)
}

pub fn decode_html_entities(input: &str) -> Cow<'_, str> {
    if !input.contains('&') {
        return Cow::Borrowed(input);
    }

    let mut out = input.to_string();
    let replacements = [
        ("&nbsp;", " "),
        ("&amp;", "&"),
        ("&lt;", "<"),
        ("&gt;", ">"),
        ("&quot;", "\""),
        ("&#39;", "'"),
    ];
    for (from, to) in replacements {
        out = out.replace(from, to);
    }
    Cow::Owned(out)
}

pub fn html_to_text(html: &str) -> String {
    let html = strip_block(strip_block(html.to_string(), "script"), "style");

    let mut text = String::with_capacity(html.len());
    let mut in_tag = false;
    for ch in html.chars() {
        match ch {
            '<' => {
                in_tag = true;
                text.push(' ');
            }
            '>' => {
                in_tag = false;
            }
            _ if !in_tag => text.push(ch),
            _ => {}
        }
    }

    collapse_whitespace(&decode_html_entities(&text))
}

pub fn collapse_whitespace(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut last_ws = false;
    for ch in input.chars() {
        if ch.is_whitespace() {
            if !last_ws {
                out.push(' ');
                last_ws = true;
            }
        } else {
            out.push(ch);
            last_ws = false;
        }
    }

    let mut compact = String::with_capacity(out.len());
    let punctuation = ['.', ',', ':', ';', '!', '?'];
    for ch in out.trim().chars() {
        if punctuation.contains(&ch) && compact.ends_with(' ') {
            compact.pop();
        }
        compact.push(ch);
    }

    compact
}

fn extract_attr(tag: &str, attr: &str) -> Option<String> {
    let lower_tag = tag.to_ascii_lowercase();
    let needle = format!("{}=", attr.to_ascii_lowercase());
    let idx = lower_tag.find(&needle)?;
    let raw = &tag[idx + needle.len()..];
    let raw = raw.trim_start();
    if raw.is_empty() {
        return None;
    }

    let first = raw.chars().next()?;
    if first == '"' || first == '\'' {
        let quote = first;
        let rest = &raw[1..];
        let end = rest.find(quote)?;
        return Some(rest[..end].to_string());
    }

    let end = raw
        .find(|c: char| c.is_whitespace() || c == '>')
        .unwrap_or(raw.len());
    Some(raw[..end].to_string())
}

fn extract_snippet_near(html: &str, from: usize) -> String {
    let from = floor_char_boundary(html, from.min(html.len()));
    let window_end = floor_char_boundary(html, from.saturating_add(4000).min(html.len()));
    let segment = &html[from..window_end];
    let Some(class_idx) = find_case_insensitive(segment, "result__snippet", 0) else {
        return String::new();
    };

    let tag_start = segment[..class_idx].rfind('<').unwrap_or(0);
    let Some(tag_end_rel) = segment[tag_start..].find('>') else {
        return String::new();
    };
    let tag_end = tag_start + tag_end_rel;

    let closing = if segment[tag_start..].starts_with("<a") {
        "</a>"
    } else {
        "</div>"
    };

    let Some(close_rel) = find_case_insensitive(segment, closing, tag_end) else {
        return String::new();
    };

    let inner = &segment[tag_end + 1..close_rel];
    html_to_text(inner)
}

pub fn extract_ddg_results(html: &str, max_results: usize) -> Vec<SearchItem> {
    let mut results = Vec::new();
    let mut pos = 0usize;

    while results.len() < max_results {
        let Some(a_start) = find_case_insensitive(html, "<a", pos) else {
            break;
        };
        let Some(a_tag_end_rel) = html[a_start..].find('>') else {
            break;
        };
        let a_tag_end = a_start + a_tag_end_rel;
        let a_tag = &html[a_start..=a_tag_end];

        let class = extract_attr(a_tag, "class").unwrap_or_default();
        if !class.split_whitespace().any(|c| c == "result__a") {
            pos = a_tag_end + 1;
            continue;
        }

        let Some(close_rel) = find_case_insensitive(html, "</a>", a_tag_end + 1) else {
            break;
        };

        let href = extract_attr(a_tag, "href")
            .map(|h| decode_html_entities(&h).into_owned())
            .unwrap_or_default();
        let title_html = &html[a_tag_end + 1..close_rel];
        let title = html_to_text(title_html);
        let snippet = extract_snippet_near(html, close_rel + 4);

        if !href.is_empty() && !title.is_empty() {
            results.push(SearchItem {
                title,
                url: href,
                snippet,
            });
        }

        pos = close_rel + 4;
    }

    results
}

pub fn extract_primary_html(html: &str) -> &str {
    let candidates = ["main", "article", "body"];
    for tag in candidates {
        let open = format!("<{tag}");
        let close = format!("</{tag}>");
        if let Some(start) = find_case_insensitive(html, &open, 0) {
            if let Some(open_end_rel) = html[start..].find('>') {
                let content_start = start + open_end_rel + 1;
                if let Some(end) = find_case_insensitive(html, &close, content_start) {
                    return &html[content_start..end];
                }
            }
        }
    }
    html
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_html_to_text() {
        let html = "<html><body><h1>Hello&nbsp;World</h1><script>x=1;</script></body></html>";
        assert_eq!(html_to_text(html), "Hello World");
    }

    #[test]
    fn test_extract_ddg_results() {
        let html = r#"
<div>
  <a class="result__a" href="https://example.com">Example <b>Title</b></a>
  <a class="result__snippet">This is <b>snippet</b>.</a>
</div>
"#;
        let items = extract_ddg_results(html, 8);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].title, "Example Title");
        assert_eq!(items[0].url, "https://example.com");
        assert_eq!(items[0].snippet, "This is snippet.");
    }

    #[test]
    fn test_extract_primary_html_prefers_main() {
        let html = "<body>body</body><main>main section</main>";
        assert_eq!(extract_primary_html(html), "main section");
    }

    #[test]
    fn test_find_case_insensitive_non_char_boundary_input() {
        let s = "abc只def";
        // byte 4 is inside the multi-byte '只'
        assert_eq!(find_case_insensitive(s, "def", 4), Some(6));
    }
}
