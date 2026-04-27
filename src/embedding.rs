use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::config::Config;

#[async_trait]
pub trait EmbeddingProvider: Send + Sync {
    async fn embed(&self, text: &str) -> Result<Vec<f32>>;
    fn model(&self) -> &str;
    fn dimension(&self) -> usize;
}

pub struct OpenAIEmbeddingProvider {
    client: reqwest::Client,
    base_url: String,
    api_key: String,
    model: String,
    dim: usize,
}

pub struct OllamaEmbeddingProvider {
    client: reqwest::Client,
    base_url: String,
    model: String,
    dim: usize,
}

#[derive(Debug, Serialize)]
struct OpenAIEmbeddingRequest<'a> {
    model: &'a str,
    input: &'a str,
}

#[derive(Debug, Deserialize)]
struct OpenAIEmbeddingResponse {
    data: Vec<OpenAIEmbeddingData>,
}

#[derive(Debug, Deserialize)]
struct OpenAIEmbeddingData {
    embedding: Vec<f32>,
}

#[derive(Debug, Serialize)]
struct OllamaEmbeddingRequest<'a> {
    model: &'a str,
    prompt: &'a str,
}

#[derive(Debug, Deserialize)]
struct OllamaEmbeddingResponse {
    embedding: Vec<f32>,
}

#[cfg(feature = "sqlite-vec")]
fn infer_default_dim(provider: &str, model: &str) -> usize {
    match provider {
        "openai" => {
            if model.contains("3-large") {
                3072
            } else {
                1536
            }
        }
        "ollama" => 1024,
        _ => 1536,
    }
}

#[async_trait]
impl EmbeddingProvider for OpenAIEmbeddingProvider {
    async fn embed(&self, text: &str) -> Result<Vec<f32>> {
        let url = format!("{}/embeddings", self.base_url.trim_end_matches('/'));
        let response = self
            .client
            .post(url)
            .bearer_auth(&self.api_key)
            .json(&OpenAIEmbeddingRequest {
                model: &self.model,
                input: text,
            })
            .send()
            .await?;

        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("embedding request failed: {}", body));
        }

        let body: OpenAIEmbeddingResponse = response.json().await?;
        let embedding = body
            .data
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("empty embedding response"))?
            .embedding;
        Ok(embedding)
    }

    fn model(&self) -> &str {
        &self.model
    }

    fn dimension(&self) -> usize {
        self.dim
    }
}

#[async_trait]
impl EmbeddingProvider for OllamaEmbeddingProvider {
    async fn embed(&self, text: &str) -> Result<Vec<f32>> {
        let url = format!("{}/api/embeddings", self.base_url.trim_end_matches('/'));
        let response = self
            .client
            .post(url)
            .json(&OllamaEmbeddingRequest {
                model: &self.model,
                prompt: text,
            })
            .send()
            .await?;

        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("embedding request failed: {}", body));
        }

        let body: OllamaEmbeddingResponse = response.json().await?;
        Ok(body.embedding)
    }

    fn model(&self) -> &str {
        &self.model
    }

    fn dimension(&self) -> usize {
        self.dim
    }
}

pub fn create_provider(config: &Config) -> Option<Arc<dyn EmbeddingProvider>> {
    #[cfg(not(feature = "sqlite-vec"))]
    {
        let _ = config;
        None
    }

    #[cfg(feature = "sqlite-vec")]
    {
        let provider = config
            .embedding_provider
            .as_deref()
            .unwrap_or("")
            .trim()
            .to_lowercase();
        if provider.is_empty() {
            return None;
        }

        let model = config
            .embedding_model
            .clone()
            .unwrap_or_else(|| match provider.as_str() {
                "openai" => "text-embedding-3-small".to_string(),
                "ollama" => "nomic-embed-text".to_string(),
                _ => "text-embedding-3-small".to_string(),
            });
        let dim = config
            .embedding_dim
            .unwrap_or_else(|| infer_default_dim(&provider, &model));
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(300))
            .build()
            .unwrap_or_default();

        match provider.as_str() {
            "openai" => {
                let api_key = config.embedding_api_key.clone().unwrap_or_default();
                if api_key.trim().is_empty() {
                    return None;
                }
                let base_url = config
                    .embedding_base_url
                    .clone()
                    .unwrap_or_else(|| "https://api.openai.com/v1".to_string());
                Some(Arc::new(OpenAIEmbeddingProvider {
                    client,
                    base_url,
                    api_key,
                    model,
                    dim,
                }))
            }
            "ollama" => {
                let base_url = config
                    .embedding_base_url
                    .clone()
                    .unwrap_or_else(|| "http://127.0.0.1:11434".to_string());
                Some(Arc::new(OllamaEmbeddingProvider {
                    client,
                    base_url,
                    model,
                    dim,
                }))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, WorkingDirIsolation};

    fn base_config() -> Config {
        let mut cfg = Config::test_defaults();
        cfg.working_dir_isolation = WorkingDirIsolation::Chat;
        cfg
    }

    #[test]
    fn test_create_provider_without_config_returns_none() {
        let cfg = base_config();
        assert!(create_provider(&cfg).is_none());
    }

    #[cfg(feature = "sqlite-vec")]
    #[test]
    fn test_create_provider_openai_when_configured() {
        let mut cfg = base_config();
        cfg.embedding_provider = Some("openai".into());
        cfg.embedding_api_key = Some("sk-test".into());
        cfg.embedding_model = Some("text-embedding-3-small".into());
        cfg.embedding_dim = Some(1536);

        let provider = create_provider(&cfg);
        assert!(provider.is_some());
        assert_eq!(
            provider.as_ref().map(|p| p.model()),
            Some("text-embedding-3-small")
        );
    }
}
