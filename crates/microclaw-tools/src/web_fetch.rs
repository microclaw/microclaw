use std::sync::OnceLock;

use microclaw_core::text::floor_char_boundary;

use crate::web_html::{extract_primary_html, html_to_text};

fn http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::limited(5))
            .user_agent("MicroClaw/1.0")
            .build()
            .expect("failed to build HTTP client")
    })
}

pub async fn fetch_url(url: &str) -> Result<String, String> {
    let resp = http_client()
        .get(url)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }

    let body = resp.text().await.map_err(|e| e.to_string())?;
    let primary = extract_primary_html(&body);
    let text = html_to_text(primary);

    const MAX_BYTES: usize = 20_000;
    if text.len() > MAX_BYTES {
        let truncated = &text[..floor_char_boundary(&text, MAX_BYTES)];
        Ok(format!("{truncated}\n\n[Truncated at 20KB]"))
    } else {
        Ok(text)
    }
}
