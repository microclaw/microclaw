use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;

use crate::command_runner::{build_command, shell_command};
use serde::{Deserialize, Serialize};

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

fn default_sandbox_mount_allowlist_path() -> Option<String> {
    None
}

fn default_sandbox_security_profile() -> SecurityProfile {
    SecurityProfile::Hardened
}

fn default_sandbox_cap_add() -> Vec<String> {
    Vec::new()
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

/// Container security profile controlling Linux capabilities and privilege escalation.
///
/// - `Hardened`: `--cap-drop ALL --security-opt no-new-privileges` (most restrictive; apt/chown/su will fail)
/// - `Standard`: Docker default capabilities (apt/chown/su work normally)
/// - `Privileged`: `--privileged` flag (full host-level access; use for debugging only)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityProfile {
    Hardened,
    Standard,
    Privileged,
}

impl std::fmt::Display for SecurityProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecurityProfile::Hardened => write!(f, "hardened"),
            SecurityProfile::Standard => write!(f, "standard"),
            SecurityProfile::Privileged => write!(f, "privileged"),
        }
    }
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
    #[serde(default = "default_sandbox_mount_allowlist_path")]
    pub mount_allowlist_path: Option<String>,
    #[serde(default = "default_sandbox_security_profile")]
    pub security_profile: SecurityProfile,
    #[serde(default = "default_sandbox_cap_add")]
    pub cap_add: Vec<String>,
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
            mount_allowlist_path: default_sandbox_mount_allowlist_path(),
            security_profile: default_sandbox_security_profile(),
            cap_add: default_sandbox_cap_add(),
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

/// An additional bind mount to expose inside the sandbox container.
#[derive(Debug, Clone)]
pub struct ExtraMount {
    pub host_path: PathBuf,
    pub read_only: bool,
}

pub struct DockerSandbox {
    config: SandboxConfig,
    mount_dir: PathBuf,
    extra_mounts: Vec<ExtraMount>,
}

impl DockerSandbox {
    pub fn new(config: SandboxConfig, mount_dir: PathBuf, extra_mounts: Vec<ExtraMount>) -> Self {
        Self {
            config,
            mount_dir,
            extra_mounts,
        }
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

    fn security_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        match self.config.security_profile {
            SecurityProfile::Hardened => {
                args.extend([
                    "--cap-drop".to_string(),
                    "ALL".to_string(),
                    "--security-opt".to_string(),
                    "no-new-privileges".to_string(),
                ]);
                for cap in &self.config.cap_add {
                    args.extend(["--cap-add".to_string(), cap.clone()]);
                }
            }
            SecurityProfile::Standard => {
                for cap in &self.config.cap_add {
                    args.extend(["--cap-add".to_string(), cap.clone()]);
                }
            }
            SecurityProfile::Privileged => {
                args.push("--privileged".to_string());
            }
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
        ];
        args.extend(self.security_args());
        if self.config.no_network {
            args.push("--network=none".to_string());
        }
        args.extend(self.resource_args());
        let mount = self.mount_dir.display().to_string();
        args.extend(["-v".to_string(), format!("{mount}:{mount}:rw")]);
        for em in &self.extra_mounts {
            let p = em.host_path.display().to_string();
            let mode = if em.read_only { "ro" } else { "rw" };
            args.extend(["-v".to_string(), format!("{p}:{p}:{mode}")]);
        }
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
    pub fn new(config: SandboxConfig, working_dir: &Path, extra_mounts: Vec<ExtraMount>) -> Self {
        let mount_dir = resolve_mount_dir(working_dir, &config);
        let backend: Arc<dyn Sandbox> = match config.backend {
            SandboxBackend::Auto | SandboxBackend::Docker => {
                if docker_available() {
                    Arc::new(DockerSandbox::new(config.clone(), mount_dir, extra_mounts))
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

    #[cfg(test)]
    fn with_backend_for_tests(config: SandboxConfig, backend: Arc<dyn Sandbox>) -> Self {
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

    pub fn runtime_available(&self) -> bool {
        self.backend.is_real()
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

fn resolve_mount_dir(working_dir: &Path, config: &SandboxConfig) -> PathBuf {
    let _ = std::fs::create_dir_all(working_dir);
    let canonical =
        std::fs::canonicalize(working_dir).unwrap_or_else(|_| working_dir.to_path_buf());
    if let Err(err) = validate_mount_dir(&canonical, config) {
        tracing::warn!(
            path = %canonical.display(),
            error = %err,
            "sandbox mount dir failed validation; falling back to raw working dir"
        );
        working_dir.to_path_buf()
    } else {
        canonical
    }
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

const MOUNT_BLOCKED_COMPONENTS: &[&str] = &[
    ".ssh", ".gnupg", ".aws", ".azure", ".gcloud", ".kube", ".docker",
];

const MOUNT_BLOCKED_FILENAMES: &[&str] = &[
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    ".netrc",
    ".npmrc",
    "id_rsa",
    "id_ed25519",
    "credentials",
    "private_key",
];

fn validate_mount_dir(path: &Path, config: &SandboxConfig) -> Result<()> {
    if contains_symlink_component(path)? {
        bail!("mount path contains symlink component");
    }
    if has_sensitive_mount_component(path) {
        bail!("mount path contains sensitive component");
    }
    validate_mount_allowlist(path, config)
}

fn contains_symlink_component(path: &Path) -> Result<bool> {
    let mut cur = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::RootDir => {
                cur.push(Path::new("/"));
            }
            Component::Prefix(prefix) => cur.push(prefix.as_os_str()),
            Component::Normal(part) => {
                cur.push(part);
                let meta = std::fs::symlink_metadata(&cur)
                    .with_context(|| format!("failed to stat mount path '{}'", cur.display()))?;
                if meta.file_type().is_symlink() {
                    return Ok(true);
                }
            }
            Component::CurDir | Component::ParentDir => {}
        }
    }
    Ok(false)
}

fn has_sensitive_mount_component(path: &Path) -> bool {
    for component in path.components() {
        let Component::Normal(segment) = component else {
            continue;
        };
        let part = segment.to_string_lossy().to_string();
        if MOUNT_BLOCKED_COMPONENTS.contains(&part.as_str()) {
            return true;
        }
        if MOUNT_BLOCKED_FILENAMES.contains(&part.as_str()) {
            return true;
        }
    }
    false
}

fn default_allowlist_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from))?;
    Some(home.join(".microclaw/sandbox-mount-allowlist.txt"))
}

fn validate_mount_allowlist(path: &Path, config: &SandboxConfig) -> Result<()> {
    let allowlist_path = config
        .mount_allowlist_path
        .as_ref()
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("MICROCLAW_SANDBOX_MOUNT_ALLOWLIST").map(PathBuf::from))
        .or_else(default_allowlist_path);
    let Some(file_path) = allowlist_path else {
        return Ok(());
    };
    if !file_path.exists() {
        return Ok(());
    }
    let content = std::fs::read_to_string(&file_path)
        .with_context(|| format!("failed reading mount allowlist '{}'", file_path.display()))?;
    let mut allowed_roots = Vec::new();
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let candidate = PathBuf::from(line);
        let canonical = std::fs::canonicalize(&candidate).unwrap_or(candidate);
        allowed_roots.push(canonical);
    }
    if allowed_roots.is_empty() {
        // Keep compatibility: treat empty allowlist as disabled.
        return Ok(());
    }
    if allowed_roots.iter().any(|root| path.starts_with(root)) {
        Ok(())
    } else {
        bail!(
            "mount path '{}' is not allowed by '{}'",
            path.display(),
            file_path.display()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_sanitize_segment() {
        assert_eq!(sanitize_segment("Web:10001"), "web-10001");
    }

    #[test]
    fn test_router_default_backend_name() {
        let router = SandboxRouter::new(SandboxConfig::default(), Path::new("./tmp"), vec![]);
        let name = router.backend_name();
        assert!(name == "docker" || name == "none");
    }

    #[tokio::test]
    async fn test_router_falls_back_to_host_when_runtime_missing_and_not_required() {
        let cfg = SandboxConfig {
            mode: SandboxMode::All,
            backend: SandboxBackend::Auto,
            require_runtime: false,
            ..SandboxConfig::default()
        };
        let router = SandboxRouter::with_backend_for_tests(cfg, Arc::new(NoSandbox));
        let opts = SandboxExecOptions {
            timeout: Duration::from_secs(2),
            working_dir: None,
        };
        let out = router.exec("chat-1", "printf microclaw-smoke", &opts).await;
        let out = out.expect("expected host fallback execution");
        assert_eq!(out.exit_code, 0);
        assert_eq!(out.stdout, "microclaw-smoke");
    }

    #[tokio::test]
    async fn test_router_fails_closed_when_runtime_required_and_missing() {
        let cfg = SandboxConfig {
            mode: SandboxMode::All,
            backend: SandboxBackend::Auto,
            require_runtime: true,
            ..SandboxConfig::default()
        };
        let router = SandboxRouter::with_backend_for_tests(cfg, Arc::new(NoSandbox));
        let opts = SandboxExecOptions {
            timeout: Duration::from_secs(2),
            working_dir: None,
        };
        let err = router.exec("chat-1", "echo hi", &opts).await.unwrap_err();
        assert!(err
            .to_string()
            .contains("sandbox is enabled but no docker runtime is available"));
    }
}
