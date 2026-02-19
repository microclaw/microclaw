use crate::error::MicroClawError;
use crate::clawhub::types::*;

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
    pub async fn search(&self, query: &str, limit: usize, sort: &str) -> Result<Vec<SearchResult>, MicroClawError> {
        let url = format!(
            "{}/api/v1/skills?q={}&limit={}&sort={}",
            self.base_url, query, limit, sort
        );
        let mut req = self.client.get(&url);
        if let Some(ref token) = self.token {
            req = req.header("Authorization", format!("Bearer {}", token));
        }
        let resp = req.send().await
            .map_err(|e| MicroClawError::Config(format!("ClawHub request failed: {}", e)))?;
        let results: Vec<SearchResult> = resp.json().await
            .map_err(|e| MicroClawError::Config(format!("Failed to parse search results: {}", e)))?;
        Ok(results)
    }

    /// Get skill metadata by slug
    pub async fn get_skill(&self, slug: &str) -> Result<SkillMeta, MicroClawError> {
        let url = format!("{}/api/v1/skills/{}", self.base_url, slug);
        let mut req = self.client.get(&url);
        if let Some(ref token) = self.token {
            req = req.header("Authorization", format!("Bearer {}", token));
        }
        let resp = req.send().await
            .map_err(|e| MicroClawError::Config(format!("ClawHub request failed: {}", e)))?;
        let meta: SkillMeta = resp.json().await
            .map_err(|e| MicroClawError::Config(format!("Failed to parse skill metadata: {}", e)))?;
        Ok(meta)
    }

    /// Download skill as ZIP bytes
    pub async fn download_skill(&self, slug: &str, version: &str) -> Result<Vec<u8>, MicroClawError> {
        let url = format!("{}/api/v1/skills/{}/download?version={}", self.base_url, slug, version);
        let mut req = self.client.get(&url);
        if let Some(ref token) = self.token {
            req = req.header("Authorization", format!("Bearer {}", token));
        }
        let resp = req.send().await
            .map_err(|e| MicroClawError::Config(format!("ClawHub download failed: {}", e)))?;
        let bytes = resp.bytes().await
            .map_err(|e| MicroClawError::Config(format!("Failed to read download: {}", e)))?;
        Ok(bytes.to_vec())
    }

    /// List versions for a skill
    pub async fn get_versions(&self, slug: &str) -> Result<Vec<SkillVersion>, MicroClawError> {
        let url = format!("{}/api/v1/skills/{}/versions", self.base_url, slug);
        let mut req = self.client.get(&url);
        if let Some(ref token) = self.token {
            req = req.header("Authorization", format!("Bearer {}", token));
        }
        let resp = req.send().await
            .map_err(|e| MicroClawError::Config(format!("ClawHub request failed: {}", e)))?;
        let versions: Vec<SkillVersion> = resp.json().await
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
