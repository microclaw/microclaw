use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;

use serde::{Deserialize, Serialize};
use crate::command_runner::{build_command, shell_command};

fn default_sandbox_mode() -> SandboxMode {
    SandboxMode::Off
}

fn default_sandbox_backend() -> SandboxBackend {
    SandboxBackend::Auto
}

fn default_sandbox_image() -> String {
    "ubuntu:25.10".to_string()
}

fn default_sandbox_container_prefix() -> String {
    "microclaw-sandbox".to_string()
}

fn default_sandbox_no_network() -> bool {
    true
}

fn default_sandbox_require_runtime() -> bool {
    false
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxMode {
    Off,
    All,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxBackend {
    Auto,
    Docker,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SandboxConfig {
    #[serde(default = "default_sandbox_mode")]
    pub mode: SandboxMode,
    #[serde(default = "default_sandbox_backend")]
    pub backend: SandboxBackend,
    #[serde(default = "default_sandbox_image")]
    pub image: String,
    #[serde(default = "default_sandbox_container_prefix")]
    pub container_prefix: String,
    #[serde(default = "default_sandbox_no_network")]
    pub no_network: bool,
    #[serde(default = "default_sandbox_require_runtime")]
    pub require_runtime: bool,
    #[serde(default)]
    pub memory_limit: Option<String>,
    #[serde(default)]
    pub cpu_quota: Option<f64>,
    #[serde(default)]
    pub pids_limit: Option<u32>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            mode: default_sandbox_mode(),
            backend: default_sandbox_backend(),
            image: default_sandbox_image(),
            container_prefix: default_sandbox_container_prefix(),
            no_network: default_sandbox_no_network(),
            require_runtime: default_sandbox_require_runtime(),
            memory_limit: None,
            cpu_quota: None,
            pids_limit: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SandboxExecOptions {
    pub timeout: Duration,
    pub working_dir: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct SandboxExecResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

#[async_trait]
pub trait Sandbox: Send + Sync {
    fn backend_name(&self) -> &'static str;
    fn is_real(&self) -> bool {
        true
    }
    async fn ensure_ready(&self, session_key: &str) -> Result<()>;
    async fn exec(
        &self,
        session_key: &str,
        command: &str,
        opts: &SandboxExecOptions,
    ) -> Result<SandboxExecResult>;
}

pub struct NoSandbox;

#[async_trait]
impl Sandbox for NoSandbox {
    fn backend_name(&self) -> &'static str {
        "none"
    }

    fn is_real(&self) -> bool {
        false
    }

    async fn ensure_ready(&self, _session_key: &str) -> Result<()> {
        Ok(())
    }

    async fn exec(
        &self,
        _session_key: &str,
        command: &str,
        opts: &SandboxExecOptions,
    ) -> Result<SandboxExecResult> {
        exec_host_command(command, opts).await
    }
}

pub struct DockerSandbox {
    config: SandboxConfig,
    mount_dir: PathBuf,
}

impl DockerSandbox {
    pub fn new(config: SandboxConfig, mount_dir: PathBuf) -> Self {
        Self { config, mount_dir }
    }

    fn container_name(&self, session_key: &str) -> String {
        format!(
            "{}-{}",
            self.config.container_prefix,
            sanitize_segment(session_key)
        )
    }

    fn resource_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        if let Some(mem) = &self.config.memory_limit {
            args.extend(["--memory".to_string(), mem.clone()]);
        }
        if let Some(cpu) = self.config.cpu_quota {
            args.extend(["--cpus".to_string(), cpu.to_string()]);
        }
        if let Some(pids) = self.config.pids_limit {
            args.extend(["--pids-limit".to_string(), pids.to_string()]);
        }
        args
    }
}

#[async_trait]
impl Sandbox for DockerSandbox {
    fn backend_name(&self) -> &'static str {
        "docker"
    }

    async fn ensure_ready(&self, session_key: &str) -> Result<()> {
        let name = self.container_name(session_key);
        let inspect = tokio::process::Command::new("docker")
            .args(["inspect", "--format", "{{.State.Running}}", &name])
            .output()
            .await;
        if let Ok(out) = inspect {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if out.status.success() && stdout.trim() == "true" {
                return Ok(());
            }
        }

        let mut args = vec![
            "run".to_string(),
            "-d".to_string(),
            "--name".to_string(),
            name.clone(),
            "--cap-drop".to_string(),
            "ALL".to_string(),
            "--security-opt".to_string(),
            "no-new-privileges".to_string(),
        ];
        if self.config.no_network {
            args.push("--network=none".to_string());
        }
        args.extend(self.resource_args());
        let mount = self.mount_dir.display().to_string();
        args.extend(["-v".to_string(), format!("{mount}:{mount}:rw")]);
        args.push(self.config.image.clone());
        args.extend(["sleep".to_string(), "infinity".to_string()]);

        let out = tokio::process::Command::new("docker")
            .args(&args)
            .output()
            .await
            .context("failed to run docker")?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            bail!("docker run failed: {}", stderr.trim());
        }
        Ok(())
    }

    async fn exec(
        &self,
        session_key: &str,
        command: &str,
        opts: &SandboxExecOptions,
    ) -> Result<SandboxExecResult> {
        let name = self.container_name(session_key);
        let mut args = vec!["exec".to_string()];
        if let Some(dir) = &opts.working_dir {
            args.extend(["-w".to_string(), dir.display().to_string()]);
        }
        args.push(name);
        args.extend(["sh".to_string(), "-c".to_string(), command.to_string()]);
        let child = tokio::process::Command::new("docker")
            .args(&args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .stdin(std::process::Stdio::null())
            .spawn()
            .context("failed to spawn docker exec")?;
        match tokio::time::timeout(opts.timeout, child.wait_with_output()).await {
            Ok(Ok(output)) => Ok(SandboxExecResult {
                stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
                exit_code: output.status.code().unwrap_or(-1),
            }),
            Ok(Err(e)) => bail!("docker exec failed: {e}"),
            Err(_) => bail!(
                "docker exec timed out after {} seconds",
                opts.timeout.as_secs()
            ),
        }
    }
}

pub struct SandboxRouter {
    config: SandboxConfig,
    backend: Arc<dyn Sandbox>,
    warned_missing_runtime: AtomicBool,
}

impl SandboxRouter {
    pub fn new(config: SandboxConfig, working_dir: &Path) -> Self {
        let mount_dir = resolve_mount_dir(working_dir);
        let backend: Arc<dyn Sandbox> = match config.backend {
            SandboxBackend::Auto | SandboxBackend::Docker => {
                if docker_available() {
                    Arc::new(DockerSandbox::new(config.clone(), mount_dir))
                } else {
                    Arc::new(NoSandbox)
                }
            }
        };
        Self {
            config,
            backend,
            warned_missing_runtime: AtomicBool::new(false),
        }
    }

    pub fn mode(&self) -> SandboxMode {
        self.config.mode
    }

    pub fn backend_name(&self) -> &'static str {
        self.backend.backend_name()
    }

    pub async fn exec(
        &self,
        session_key: &str,
        command: &str,
        opts: &SandboxExecOptions,
    ) -> Result<SandboxExecResult> {
        if self.config.mode == SandboxMode::Off {
            return exec_host_command(command, opts).await;
        }
        if !self.backend.is_real() {
            if self.config.require_runtime {
                bail!("sandbox is enabled but no docker runtime is available");
            }
            if !self.warned_missing_runtime.swap(true, Ordering::Relaxed) {
                tracing::warn!("sandbox enabled but docker unavailable, falling back to host");
            }
            return exec_host_command(command, opts).await;
        }
        self.backend.ensure_ready(session_key).await?;
        self.backend.exec(session_key, command, opts).await
    }
}

pub async fn exec_host_command(
    command: &str,
    opts: &SandboxExecOptions,
) -> Result<SandboxExecResult> {
    let spec = shell_command(command);
    let mut cmd = build_command(&spec, opts.working_dir.as_deref());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    cmd.stdin(std::process::Stdio::null());
    let child = cmd.spawn().context("failed to start shell command")?;
    match tokio::time::timeout(opts.timeout, child.wait_with_output()).await {
        Ok(Ok(output)) => Ok(SandboxExecResult {
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            exit_code: output.status.code().unwrap_or(-1),
        }),
        Ok(Err(e)) => bail!("failed to run command: {e}"),
        Err(_) => bail!("command timed out after {} seconds", opts.timeout.as_secs()),
    }
}

fn docker_available() -> bool {
    std::process::Command::new("docker")
        .args(["info", "--format", "{{.ServerVersion}}"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn resolve_mount_dir(working_dir: &Path) -> PathBuf {
    let _ = std::fs::create_dir_all(working_dir);
    std::fs::canonicalize(working_dir).unwrap_or_else(|_| working_dir.to_path_buf())
}

fn sanitize_segment(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
            out.push(c.to_ascii_lowercase());
        } else {
            out.push('-');
        }
    }
    if out.is_empty() {
        "default".into()
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_segment() {
        assert_eq!(sanitize_segment("Web:10001"), "web-10001");
    }

    #[test]
    fn test_router_default_backend_name() {
        let router = SandboxRouter::new(SandboxConfig::default(), Path::new("./tmp"));
        let name = router.backend_name();
        assert!(name == "docker" || name == "none");
    }
}
