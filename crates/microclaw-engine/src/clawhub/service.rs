use std::path::Path;

use crate::internal::clawhub::client::ClawHubClient;
use crate::internal::clawhub::install::{install_skill, InstallOptions, InstallResult};
use crate::internal::clawhub::lockfile::read_lockfile;
use crate::internal::clawhub::types::{LockFile, SearchResult, SkillMeta};
use async_trait::async_trait;

use crate::config::Config;
use crate::error::MicroClawError;

#[async_trait]
pub trait ClawHubGateway: Send + Sync {
    async fn search(
        &self,
        query: &str,
        limit: usize,
        sort: &str,
    ) -> Result<Vec<SearchResult>, MicroClawError>;
    async fn get_skill(&self, slug: &str) -> Result<SkillMeta, MicroClawError>;
    async fn install(
        &self,
        slug: &str,
        version: Option<&str>,
        skills_dir: &Path,
        lockfile_path: &Path,
        options: &InstallOptions,
    ) -> Result<InstallResult, MicroClawError>;
    fn read_lockfile(&self, path: &Path) -> Result<LockFile, MicroClawError>;
}

pub struct RegistryClawHubGateway {
    client: ClawHubClient,
}

impl RegistryClawHubGateway {
    pub fn from_config(config: &Config) -> Self {
        let client = ClawHubClient::new(&config.clawhub.registry, config.clawhub.token.clone());
        Self { client }
    }
}

#[async_trait]
impl ClawHubGateway for RegistryClawHubGateway {
    async fn search(
        &self,
        query: &str,
        limit: usize,
        sort: &str,
    ) -> Result<Vec<SearchResult>, MicroClawError> {
        self.client.search(query, limit, sort).await
    }

    async fn get_skill(&self, slug: &str) -> Result<SkillMeta, MicroClawError> {
        self.client.get_skill(slug).await
    }

    async fn install(
        &self,
        slug: &str,
        version: Option<&str>,
        skills_dir: &Path,
        lockfile_path: &Path,
        options: &InstallOptions,
    ) -> Result<InstallResult, MicroClawError> {
        install_skill(
            &self.client,
            slug,
            version,
            skills_dir,
            lockfile_path,
            options,
        )
        .await
    }

    fn read_lockfile(&self, path: &Path) -> Result<LockFile, MicroClawError> {
        read_lockfile(path)
    }
}
