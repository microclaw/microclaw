use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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

/// Search result item
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
