use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Duration;

use microclaw_core::llm_types::ToolDefinition;

use super::{schema_object, Tool, ToolResult};

/// OSV (Open Source Vulnerabilities) query tool.
///
/// Queries `https://api.osv.dev/v1/query` for vulnerabilities affecting a
/// given package / ecosystem / version. Modeled after hermes-agent's
/// `tools/osv_check.py`, which narrows to MAL-* (malware) advisories; this
/// Rust port returns every advisory and lets the caller filter.
pub struct OsvCheckTool {
    endpoint: String,
    timeout_secs: u64,
}

impl OsvCheckTool {
    pub fn new(timeout_secs: u64) -> Self {
        Self {
            endpoint: "https://api.osv.dev/v1/query".to_string(),
            timeout_secs: timeout_secs.clamp(1, 30),
        }
    }

    /// Allow tests to override the endpoint.
    #[allow(dead_code)]
    pub fn with_endpoint(mut self, endpoint: String) -> Self {
        self.endpoint = endpoint;
        self
    }
}

#[derive(Serialize)]
struct OsvPackage<'a> {
    name: &'a str,
    ecosystem: &'a str,
}

#[derive(Serialize)]
struct OsvQuery<'a> {
    package: OsvPackage<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<&'a str>,
}

#[derive(Deserialize, Default)]
struct OsvResponse {
    #[serde(default)]
    vulns: Vec<OsvVuln>,
}

#[derive(Deserialize)]
struct OsvVuln {
    id: String,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
}

#[derive(Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    score: String,
}

fn is_supported_ecosystem(raw: &str) -> bool {
    matches!(
        raw.to_ascii_lowercase().as_str(),
        "npm"
            | "pypi"
            | "cargo"
            | "go"
            | "maven"
            | "rubygems"
            | "nuget"
            | "packagist"
            | "hex"
            | "pub"
            | "swifturl"
            | "crates.io"
    )
}

fn canonical_ecosystem(raw: &str) -> &str {
    // OSV accepts "PyPI", "npm", "crates.io" exactly. Normalize the common
    // variants the agent is likely to pass.
    match raw.to_ascii_lowercase().as_str() {
        "pypi" | "py" | "python" => "PyPI",
        "crates.io" | "cargo" | "rust" | "crates" => "crates.io",
        "npm" | "node" | "nodejs" => "npm",
        "rubygems" | "gem" | "ruby" => "RubyGems",
        "maven" | "java" => "Maven",
        "nuget" | "dotnet" | "csharp" => "NuGet",
        "packagist" | "composer" | "php" => "Packagist",
        "hex" | "elixir" => "Hex",
        "pub" | "dart" => "Pub",
        "go" | "golang" => "Go",
        _ => "", // unknown → caller-handled rejection
    }
}

#[async_trait]
impl Tool for OsvCheckTool {
    fn name(&self) -> &str {
        "osv_check"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: self.name().into(),
            description: "Query the OSV (Open Source Vulnerabilities) database at \
                api.osv.dev for advisories against a package. Supports PyPI, npm, \
                crates.io, RubyGems, Maven, NuGet, Packagist, Hex, Pub, and Go. \
                Use before recommending or installing a third-party dependency, \
                or when the user wants a quick security check."
                .into(),
            input_schema: schema_object(
                json!({
                    "package": {
                        "type": "string",
                        "description": "Package name (e.g. 'lodash', 'requests', 'serde_json')."
                    },
                    "ecosystem": {
                        "type": "string",
                        "description": "Ecosystem: npm, PyPI, crates.io, RubyGems, Maven, NuGet, Packagist, Hex, Pub, or Go."
                    },
                    "version": {
                        "type": "string",
                        "description": "Optional specific version. When omitted, returns all known advisories for the package."
                    }
                }),
                &["package", "ecosystem"],
            ),
        }
    }

    async fn execute(&self, input: serde_json::Value) -> ToolResult {
        let package = match input.get("package").and_then(|v| v.as_str()) {
            Some(v) if !v.trim().is_empty() => v.trim().to_string(),
            _ => return ToolResult::error("Missing required parameter: package".into()),
        };
        let ecosystem_raw = match input.get("ecosystem").and_then(|v| v.as_str()) {
            Some(v) if !v.trim().is_empty() => v.trim().to_string(),
            _ => return ToolResult::error("Missing required parameter: ecosystem".into()),
        };
        let version = input
            .get("version")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        if !is_supported_ecosystem(&ecosystem_raw) {
            return ToolResult::error(format!(
                "Unsupported ecosystem '{ecosystem_raw}'. Supported: npm, PyPI, \
                 crates.io, RubyGems, Maven, NuGet, Packagist, Hex, Pub, Go."
            ));
        }
        let ecosystem = canonical_ecosystem(&ecosystem_raw);
        if ecosystem.is_empty() {
            return ToolResult::error(format!("Unsupported ecosystem '{ecosystem_raw}'"));
        }

        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(self.timeout_secs))
            .user_agent("MicroClaw-osv-check/1.0")
            .build()
        {
            Ok(c) => c,
            Err(e) => return ToolResult::error(format!("failed to build HTTP client: {e}")),
        };

        let body = OsvQuery {
            package: OsvPackage {
                name: package.as_str(),
                ecosystem,
            },
            version: version.as_deref(),
        };

        let resp = match client.post(&self.endpoint).json(&body).send().await {
            Ok(r) => r,
            Err(e) => return ToolResult::error(format!("OSV request failed: {e}")),
        };
        if !resp.status().is_success() {
            return ToolResult::error(format!("OSV returned HTTP {}", resp.status()));
        }
        let parsed: OsvResponse = match resp.json().await {
            Ok(v) => v,
            Err(e) => return ToolResult::error(format!("invalid OSV JSON: {e}")),
        };

        if parsed.vulns.is_empty() {
            let ver = version.as_deref().unwrap_or("<all>");
            return ToolResult::success(format!(
                "No OSV advisories for {ecosystem}:{package} (version {ver})."
            ));
        }

        let mut lines = Vec::new();
        lines.push(format!(
            "{} OSV advisor(y/ies) for {ecosystem}:{package}{}",
            parsed.vulns.len(),
            version
                .as_deref()
                .map(|v| format!(" @ {v}"))
                .unwrap_or_default()
        ));
        for v in &parsed.vulns {
            let mut line = format!("- {}", v.id);
            if !v.aliases.is_empty() {
                line.push_str(" (aliases: ");
                line.push_str(&v.aliases.join(", "));
                line.push(')');
            }
            if let Some(sum) = v.summary.as_deref().filter(|s| !s.is_empty()) {
                line.push_str(" — ");
                line.push_str(sum);
            }
            if let Some(sev) = v
                .severity
                .iter()
                .find(|s| !s.kind.is_empty() && !s.score.is_empty())
            {
                line.push_str(&format!(" [severity {}: {}]", sev.kind, sev.score));
            }
            lines.push(line);
        }
        let malware_count = parsed
            .vulns
            .iter()
            .filter(|v| v.id.starts_with("MAL-"))
            .count();
        if malware_count > 0 {
            lines.push(format!(
                "WARNING: {malware_count} advisor(y/ies) are confirmed-malware (MAL-*)."
            ));
        }
        ToolResult::success(lines.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supports_common_ecosystems() {
        assert!(is_supported_ecosystem("npm"));
        assert!(is_supported_ecosystem("PyPI"));
        assert!(is_supported_ecosystem("crates.io"));
        assert!(!is_supported_ecosystem("homebrew"));
    }

    #[test]
    fn canonicalizes_aliases() {
        assert_eq!(canonical_ecosystem("python"), "PyPI");
        assert_eq!(canonical_ecosystem("rust"), "crates.io");
        assert_eq!(canonical_ecosystem("npm"), "npm");
        assert_eq!(canonical_ecosystem("go"), "Go");
        assert_eq!(canonical_ecosystem("unknown"), "");
    }
}
