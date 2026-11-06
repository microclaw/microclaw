//! MicroClaw Code's own home: configuration, engine data, sessions and trust
//! decisions live under `~/.mccode` (or `MCCODE_HOME`).
//!
//! MicroClaw Code is a separate product from the MicroClaw Server: it never
//! reads the Server's configuration, data directory or environment, and the
//! Server never reads Code's. Both can be installed, configured and removed
//! independently.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use serde::Serialize;

/// Environment variable overriding the Code home directory.
pub const HOME_ENV: &str = "MCCODE_HOME";
/// Environment variable naming an explicit configuration file.
pub const CONFIG_ENV: &str = "MCCODE_CONFIG";
/// A non-empty environment variable.
pub fn env_var(name: &str) -> Option<OsString> {
    std::env::var_os(name).filter(|v| !v.is_empty())
}

/// The Code home directory.
pub fn code_home() -> PathBuf {
    if let Some(dir) = env_var(HOME_ENV) {
        return PathBuf::from(dir);
    }
    dirs::home_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join(".mccode")
}

/// Engine data directory (SQLite, memory, checkpoints, MCP and skill state).
pub fn data_dir() -> PathBuf {
    code_home().join("data")
}

/// Code's own configuration file, written by `mccode setup`.
pub fn config_path() -> PathBuf {
    code_home().join("config.yaml")
}

/// Where the active configuration came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigSource {
    /// `--config <PATH>`.
    Explicit,
    /// `MCCODE_CONFIG`.
    Environment(&'static str),
    /// `~/.mccode/config.yaml`.
    CodeHome,
}

impl ConfigSource {
    pub fn describe(&self) -> String {
        match self {
            Self::Explicit => "--config".into(),
            Self::Environment(var) => (*var).into(),
            Self::CodeHome => "MicroClaw Code home".into(),
        }
    }
}

/// Locate the configuration with model credentials: `--config`,
/// `MCCODE_CONFIG`, then `~/.mccode/config.yaml`.
///
/// A configuration file inside the repository is deliberately never picked up
/// implicitly (a cloned project must not be able to choose the model endpoint
/// or tool policy), and neither is a MicroClaw Server configuration: the two
/// products do not share model settings.
pub fn resolve_config(explicit: Option<&Path>) -> anyhow::Result<(PathBuf, ConfigSource)> {
    resolve_config_in(explicit, &code_home(), env_var(CONFIG_ENV))
}

fn resolve_config_in(
    explicit: Option<&Path>,
    code_home: &Path,
    config_env: Option<OsString>,
) -> anyhow::Result<(PathBuf, ConfigSource)> {
    if let Some(path) = explicit {
        anyhow::ensure!(
            path.is_file(),
            "config file {} does not exist",
            path.display()
        );
        return Ok((path.to_path_buf(), ConfigSource::Explicit));
    }
    if let Some(value) = config_env {
        let path = PathBuf::from(value);
        anyhow::ensure!(
            path.is_file(),
            "{CONFIG_ENV} points to missing file {}",
            path.display()
        );
        return Ok((path, ConfigSource::Environment(CONFIG_ENV)));
    }
    let own = code_home.join("config.yaml");
    if own.is_file() {
        return Ok((own, ConfigSource::CodeHome));
    }
    anyhow::bail!(
        "no model configuration found. Run `mccode setup`, add a model profile to {}, or pass --config <PATH>.",
        code_home.join("settings.yaml").display()
    )
}

/// Model settings written by `mccode setup`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelSettings {
    pub provider: String,
    pub model: String,
    pub api_key: String,
    pub base_url: Option<String>,
}

/// Write a minimal channel-free configuration with owner-only permissions.
pub fn write_config(path: &Path, settings: &ModelSettings) -> std::io::Result<()> {
    #[derive(Serialize)]
    struct MinimalConfig<'a> {
        llm_provider: &'a str,
        model: &'a str,
        api_key: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        llm_base_url: Option<&'a str>,
        web_enabled: bool,
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let text = serde_yaml::to_string(&MinimalConfig {
        llm_provider: &settings.provider,
        model: &settings.model,
        api_key: &settings.api_key,
        llm_base_url: settings
            .base_url
            .as_deref()
            .filter(|u| !u.trim().is_empty()),
        web_enabled: false,
    })
    .map_err(std::io::Error::other)?;
    let temporary = path.with_extension("yaml.tmp");
    std::fs::write(&temporary, format!("# Written by `mccode setup`.\n{text}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&temporary, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolution_order_and_no_server_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let code_home = dir.path().join("code");
        // A MicroClaw Server configuration next door is never used.
        let user_home = dir.path().join("user");
        std::fs::create_dir_all(user_home.join(".microclaw")).unwrap();
        std::fs::write(user_home.join(".microclaw/microclaw.config.yaml"), "x").unwrap();
        assert!(resolve_config_in(None, &code_home, None).is_err());

        std::fs::create_dir_all(&code_home).unwrap();
        std::fs::write(code_home.join("config.yaml"), "x").unwrap();
        let (_, source) = resolve_config_in(None, &code_home, None).unwrap();
        assert_eq!(source, ConfigSource::CodeHome);

        let from_env = dir.path().join("env.yaml");
        std::fs::write(&from_env, "x").unwrap();
        let (path, source) =
            resolve_config_in(None, &code_home, Some(from_env.clone().into())).unwrap();
        assert_eq!(source, ConfigSource::Environment(CONFIG_ENV));
        assert_eq!(path, from_env);

        let explicit = dir.path().join("explicit.yaml");
        std::fs::write(&explicit, "x").unwrap();
        let (_, source) =
            resolve_config_in(Some(&explicit), &code_home, Some(from_env.into())).unwrap();
        assert_eq!(source, ConfigSource::Explicit);
    }

    #[test]
    fn missing_configuration_points_to_setup() {
        let dir = tempfile::tempdir().unwrap();
        let err = resolve_config_in(None, dir.path(), None).unwrap_err();
        assert!(err.to_string().contains("mccode setup"));
    }

    #[test]
    fn written_config_is_valid_and_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("code/config.yaml");
        write_config(
            &path,
            &ModelSettings {
                provider: "ollama".into(),
                model: "qwen".into(),
                api_key: String::new(),
                base_url: Some("http://127.0.0.1:11434/v1".into()),
            },
        )
        .unwrap();
        microclaw_sdk::validate_config_file(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}
