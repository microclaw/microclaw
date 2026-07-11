use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// =============================================================================
// API Response Types - These match the actual ClawHub API responses
// =============================================================================

/// Dedicated search API response (the one that actually filters by query)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiSearchResponse {
    pub results: Vec<ApiSearchResult>,
}

/// Search result from dedicated search API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiSearchResult {
    pub score: f64,
    pub slug: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    pub summary: String,
    pub version: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: i64,
}

impl From<ApiSearchResult> for SearchResult {
    fn from(item: ApiSearchResult) -> Self {
        Self {
            slug: item.slug,
            name: item.display_name,
            description: item.summary,
            install_count: 0, // Not available in search response
            virustotal: None,
        }
    }
}

/// Search API response wrapper (list endpoint, doesn't filter by query)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResponse {
    pub items: Vec<SearchItem>,
    #[serde(rename = "nextCursor")]
    pub next_cursor: Option<String>,
}

/// Search result item from API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchItem {
    pub slug: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    pub summary: String,
    pub tags: HashMap<String, String>,
    pub stats: SkillStats,
    #[serde(rename = "createdAt")]
    pub created_at: i64,
    #[serde(rename = "updatedAt")]
    pub updated_at: i64,
    #[serde(rename = "latestVersion")]
    pub latest_version: Option<VersionItem>,
}

/// Skill statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillStats {
    pub comments: i32,
    pub downloads: i32,
    #[serde(rename = "installsAllTime")]
    pub installs_all_time: i32,
    #[serde(rename = "installsCurrent")]
    pub installs_current: i32,
    pub stars: i32,
    pub versions: i32,
}

/// Version item from API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionItem {
    pub version: String,
    #[serde(rename = "createdAt")]
    pub created_at: i64,
    pub changelog: String,
}

/// Get skill API response wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetSkillResponse {
    pub skill: SkillItem,
    #[serde(rename = "latestVersion")]
    pub latest_version: VersionItem,
    pub owner: Owner,
    pub moderation: Option<serde_json::Value>,
}

/// Skill item from get skill API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillItem {
    pub slug: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    pub summary: String,
    pub tags: HashMap<String, String>,
    pub stats: SkillStats,
    #[serde(rename = "createdAt")]
    pub created_at: i64,
    #[serde(rename = "updatedAt")]
    pub updated_at: i64,
}

/// Owner information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Owner {
    pub handle: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    pub image: String,
}

// =============================================================================
// Internal Types - These are what the rest of the app uses
// =============================================================================

/// Lockfile format for tracking ClawHub-installed skills
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockFile {
    pub version: u32,
    pub skills: HashMap<String, LockEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockEntry {
    pub slug: String,
    #[serde(rename = "installedVersion")]
    pub installed_version: String,
    #[serde(rename = "installedAt")]
    pub installed_at: String,
    #[serde(rename = "contentHash")]
    pub content_hash: String,
    /// sha256 over the EXTRACTED tree (sorted rel-paths + per-file hashes).
    /// Verifiable against disk at any time, unlike contentHash which covers
    /// the downloaded archive bytes. Absent on entries installed before this
    /// field existed.
    #[serde(
        rename = "treeHash",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub tree_hash: Option<String>,
    #[serde(rename = "localPath")]
    pub local_path: String,
}

/// Skill metadata from ClawHub API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillMeta {
    pub slug: String,
    pub name: String,
    pub description: String,
    pub versions: Vec<SkillVersion>,
    #[serde(default)]
    pub virustotal: Option<VirusTotal>,
    #[serde(default)]
    pub metadata: SkillMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillVersion {
    pub version: String,
    #[serde(default)]
    pub latest: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirusTotal {
    #[serde(rename = "reportCount")]
    pub report_count: i32,
    #[serde(rename = "pendingScan")]
    pub pending_scan: bool,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SkillMetadata {
    #[serde(default)]
    pub openclaw: Option<OpenClawMeta>,
    #[serde(default)]
    pub clawdbot: Option<ClawdbotMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OpenClawMeta {
    #[serde(default)]
    pub requires: Option<Requires>,
    #[serde(default)]
    pub os: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClawdbotMeta {
    #[serde(default)]
    pub requires: Option<Requires>,
    #[serde(default)]
    pub os: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Requires {
    #[serde(default)]
    pub bins: Vec<String>,
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default, rename = "anyBins")]
    pub any_bins: Vec<String>,
}

/// Search result item (internal representation)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub slug: String,
    pub name: String,
    pub description: String,
    #[serde(rename = "installCount")]
    pub install_count: i32,
    #[serde(default)]
    pub virustotal: Option<VirusTotal>,
}

impl From<SearchItem> for SearchResult {
    fn from(item: SearchItem) -> Self {
        Self {
            slug: item.slug,
            name: item.display_name,
            description: item.summary,
            install_count: item.stats.installs_current,
            virustotal: None, // Not available in search response
        }
    }
}

impl From<GetSkillResponse> for SkillMeta {
    fn from(resp: GetSkillResponse) -> Self {
        Self {
            slug: resp.skill.slug,
            name: resp.skill.display_name,
            description: resp.skill.summary,
            versions: vec![SkillVersion {
                version: resp.latest_version.version,
                latest: true,
            }],
            virustotal: None, // Not available in this response
            metadata: SkillMetadata::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lockfile_serde() {
        let lock = LockFile {
            version: 1,
            skills: std::collections::HashMap::new(),
        };
        let json = serde_json::to_string(&lock).unwrap();
        assert!(json.contains(r#""version":1"#));
    }

    #[test]
    fn test_skill_meta_deserialize() {
        let json = r#"{
            "slug": "test-skill",
            "name": "Test Skill",
            "description": "A test skill",
            "versions": [{"version": "1.0.0", "latest": true}]
        }"#;
        let _meta: SkillMeta = serde_json::from_str(json).unwrap();
    }
}
