use crate::internal::clawhub::types::*;
use microclaw_core::error::MicroClawError;

pub struct ClawHubClient {
    base_url: String,
    token: Option<String>,
    client: reqwest::Client,
}

impl ClawHubClient {
    pub fn new(base_url: &str, token: Option<String>) -> Self {
        Self {
            base_url: base_url.to_string(),
            token,
            client: reqwest::Client::new(),
        }
    }

    /// Search skills by query
    pub async fn search(
        &self,
        query: &str,
        limit: usize,
        _sort: &str,
    ) -> Result<Vec<SearchResult>, MicroClawError> {
        // Use the dedicated search endpoint that actually filters by query
        let url = format!(
            "{}/api/v1/search?q={}&limit={}",
            self.base_url, query, limit
        );
        let mut req = self.client.get(&url);
        if let Some(ref token) = self.token {
            req = req.header("Authorization", format!("Bearer {}", token));
        }
        let resp = req
            .send()
            .await
            .map_err(|e| MicroClawError::Config(format!("ClawHub request failed: {}", e)))?;
        let search_response: ApiSearchResponse = resp.json().await.map_err(|e| {
            MicroClawError::Config(format!("Failed to parse search results: {}", e))
        })?;
        // Convert API response items to internal SearchResult type
        Ok(search_response
            .results
            .into_iter()
            .take(limit)
            .map(SearchResult::from)
            .collect())
    }

    /// Get skill metadata by slug
    pub async fn get_skill(&self, slug: &str) -> Result<SkillMeta, MicroClawError> {
        let url = format!("{}/api/v1/skills/{}", self.base_url, slug);
        let mut req = self.client.get(&url);
        if let Some(ref token) = self.token {
            req = req.header("Authorization", format!("Bearer {}", token));
        }
        let resp = req
            .send()
            .await
            .map_err(|e| MicroClawError::Config(format!("ClawHub request failed: {}", e)))?;
        let get_response: GetSkillResponse = resp.json().await.map_err(|e| {
            MicroClawError::Config(format!("Failed to parse skill metadata: {}", e))
        })?;
        // Convert API response to internal SkillMeta type
        Ok(SkillMeta::from(get_response))
    }

    /// Download skill as ZIP bytes
    pub async fn download_skill(
        &self,
        slug: &str,
        version: &str,
    ) -> Result<Vec<u8>, MicroClawError> {
        // Prefer the configured registry domain first.
        let mut candidate_urls = vec![
            format!(
                "{}/api/v1/download?slug={}&version={}",
                self.base_url, slug, version
            ),
            format!(
                "{}/api/v1/skills/{}/download?version={}",
                self.base_url, slug, version
            ),
        ];

        // Backward-compatible fallback used by the hosted registry.
        if self.base_url.contains("clawhub.ai") {
            candidate_urls.push(format!(
                "https://wry-manatee-359.convex.site/api/v1/download?slug={}&version={}",
                slug, version
            ));
        }

        let mut last_error: Option<MicroClawError> = None;
        for url in candidate_urls {
            let mut req = self.client.get(&url);
            if let Some(ref token) = self.token {
                req = req.header("Authorization", format!("Bearer {}", token));
            }

            let resp = match req.send().await {
                Ok(resp) => resp,
                Err(e) => {
                    last_error = Some(MicroClawError::Config(format!(
                        "ClawHub download failed at {}: {}",
                        url, e
                    )));
                    continue;
                }
            };

            let resp = match resp.error_for_status() {
                Ok(resp) => resp,
                Err(e) => {
                    last_error = Some(MicroClawError::Config(format!(
                        "ClawHub download HTTP error at {}: {}",
                        url, e
                    )));
                    continue;
                }
            };

            let bytes = resp.bytes().await.map_err(|e| {
                MicroClawError::Config(format!("Failed to read download from {}: {}", url, e))
            })?;
            return Ok(bytes.to_vec());
        }

        Err(last_error.unwrap_or_else(|| {
            MicroClawError::Config("ClawHub download failed: no usable endpoint".into())
        }))
    }

    /// List versions for a skill
    pub async fn get_versions(&self, slug: &str) -> Result<Vec<SkillVersion>, MicroClawError> {
        let url = format!("{}/api/v1/skills/{}/versions", self.base_url, slug);
        let mut req = self.client.get(&url);
        if let Some(ref token) = self.token {
            req = req.header("Authorization", format!("Bearer {}", token));
        }
        let resp = req
            .send()
            .await
            .map_err(|e| MicroClawError::Config(format!("ClawHub request failed: {}", e)))?;
        let versions: Vec<SkillVersion> = resp
            .json()
            .await
            .map_err(|e| MicroClawError::Config(format!("Failed to parse versions: {}", e)))?;
        Ok(versions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_construction() {
        let client = ClawHubClient::new("https://clawhub.ai", None);
        assert_eq!(client.base_url, "https://clawhub.ai");
        assert!(client.token.is_none());
    }

    #[test]
    fn test_client_with_token() {
        let client = ClawHubClient::new("https://clawhub.ai", Some("test-token".into()));
        assert!(client.token.is_some());
    }
}
