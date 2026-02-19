use std::sync::OnceLock;

use crate::web_html::extract_ddg_results;

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

pub async fn search_ddg(query: &str) -> Result<String, String> {
    let encoded = urlencoding::encode(query);
    let url = format!("https://html.duckduckgo.com/html/?q={encoded}");

    let resp = http_client()
        .get(&url)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }

    let body = resp.text().await.map_err(|e| e.to_string())?;
    let items = extract_ddg_results(&body, 8);

    let mut output = String::new();
    for (i, item) in items.iter().enumerate() {
        output.push_str(&format!(
            "{}. {}\n   {}\n   {}\n\n",
            i + 1,
            item.title,
            item.url,
            item.snippet
        ));
    }

    Ok(output)
}
