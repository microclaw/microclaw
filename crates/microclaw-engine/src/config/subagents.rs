use super::*;

pub(crate) fn default_subagent_max_concurrent() -> usize {
    4
}

pub(crate) fn default_subagent_max_active_per_chat() -> usize {
    5
}

pub(crate) fn default_subagent_run_timeout_secs() -> u64 {
    900
}

pub(crate) fn default_subagent_announce() -> bool {
    false
}

pub(crate) fn default_subagent_progress_min_interval_secs() -> u64 {
    45
}

pub(crate) fn default_subagent_max_spawn_depth() -> usize {
    1
}

pub(crate) fn default_subagent_max_children_per_run() -> usize {
    5
}

pub(crate) fn default_subagent_thread_bound_routing_enabled() -> bool {
    true
}

pub(crate) fn default_subagent_announce_relay_interval_secs() -> u64 {
    15
}

pub(crate) fn default_subagent_max_tokens_per_run() -> i64 {
    400_000
}

pub(crate) fn default_subagent_orchestrate_max_workers() -> usize {
    5
}

pub(crate) fn default_subagent_acp_auto_approve() -> bool {
    true
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubagentAcpTargetConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: HashMap<String, String>,
    #[serde(default = "default_subagent_acp_auto_approve")]
    pub auto_approve: bool,
}

impl Default for SubagentAcpTargetConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            command: String::new(),
            args: Vec::new(),
            env: HashMap::new(),
            auto_approve: default_subagent_acp_auto_approve(),
        }
    }
}

impl SubagentAcpTargetConfig {
    pub(crate) fn normalize(&mut self) {
        self.command = self.command.trim().to_string();
        self.args = self
            .args
            .drain(..)
            .map(|arg| arg.trim().to_string())
            .filter(|arg| !arg.is_empty())
            .collect();
        self.env = self
            .env
            .drain()
            .filter_map(|(key, value)| {
                let normalized = key.trim().to_string();
                if normalized.is_empty() {
                    None
                } else {
                    Some((normalized, value))
                }
            })
            .collect();
    }

    fn command_label(&self) -> String {
        if self.command.trim().is_empty() {
            "acp".to_string()
        } else {
            Path::new(&self.command)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("acp")
                .to_string()
        }
    }
}

#[derive(Clone, Debug)]
pub struct ResolvedSubagentAcpTargetConfig {
    pub name: Option<String>,
    pub command: String,
    pub args: Vec<String>,
    pub env: HashMap<String, String>,
    pub auto_approve: bool,
}

impl ResolvedSubagentAcpTargetConfig {
    pub fn model_label(&self) -> String {
        if let Some(name) = self.name.as_deref() {
            format!(
                "{name}/{}",
                SubagentAcpTargetConfig {
                    enabled: true,
                    command: self.command.clone(),
                    args: self.args.clone(),
                    env: self.env.clone(),
                    auto_approve: self.auto_approve,
                }
                .command_label()
            )
        } else {
            SubagentAcpTargetConfig {
                enabled: true,
                command: self.command.clone(),
                args: self.args.clone(),
                env: self.env.clone(),
                auto_approve: self.auto_approve,
            }
            .command_label()
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct SubagentAcpConfig {
    #[serde(flatten)]
    pub default_target: SubagentAcpTargetConfig,
    #[serde(default, rename = "default_target")]
    pub default_target_name: Option<String>,
    #[serde(default)]
    pub targets: HashMap<String, SubagentAcpTargetConfig>,
}

impl SubagentAcpConfig {
    pub(crate) fn normalize(&mut self) {
        self.default_target.normalize();
        self.default_target_name = self
            .default_target_name
            .take()
            .map(|name| name.trim().to_string())
            .filter(|name| !name.is_empty());
        self.targets = self
            .targets
            .drain()
            .filter_map(|(key, mut value)| {
                let normalized = key.trim().to_string();
                if normalized.is_empty() {
                    return None;
                }
                value.normalize();
                Some((normalized, value))
            })
            .collect();
    }

    pub fn resolve_target(
        &self,
        requested_target: Option<&str>,
    ) -> Result<ResolvedSubagentAcpTargetConfig, String> {
        let requested_target = requested_target
            .map(str::trim)
            .filter(|target| !target.is_empty());
        if let Some(name) = requested_target {
            return self.resolve_named_target(name);
        }
        if let Some(name) = self.default_target_name.as_deref() {
            return self.resolve_named_target(name);
        }
        if !self.default_target.command.trim().is_empty() {
            return Ok(ResolvedSubagentAcpTargetConfig {
                name: None,
                command: self.default_target.command.clone(),
                args: self.default_target.args.clone(),
                env: self.default_target.env.clone(),
                auto_approve: self.default_target.auto_approve,
            });
        }

        let mut enabled_targets = self
            .targets
            .iter()
            .filter(|(_, target)| target.enabled)
            .collect::<Vec<_>>();
        enabled_targets.sort_by_key(|(name, _)| *name);
        match enabled_targets.as_slice() {
            [] => Err(
                "ACP runtime is enabled but no command is configured. Set subagents.acp.command or add an enabled target under subagents.acp.targets."
                    .into(),
            ),
            [(name, _)] => self.resolve_named_target(name),
            _ => Err(
                "ACP runtime has multiple enabled named targets. Set runtime_target or subagents.acp.default_target."
                    .into(),
            ),
        }
    }

    fn resolve_named_target(
        &self,
        target_name: &str,
    ) -> Result<ResolvedSubagentAcpTargetConfig, String> {
        let target = self.targets.get(target_name).ok_or_else(|| {
            format!(
                "Unknown ACP runtime target '{target_name}'. Configure it under subagents.acp.targets."
            )
        })?;
        if !target.enabled {
            return Err(format!(
                "ACP runtime target '{target_name}' is disabled. Enable it under subagents.acp.targets.{target_name}.enabled."
            ));
        }
        if target.command.trim().is_empty() {
            return Err(format!(
                "ACP runtime target '{target_name}' is enabled but command is empty."
            ));
        }
        Ok(ResolvedSubagentAcpTargetConfig {
            name: Some(target_name.to_string()),
            command: target.command.clone(),
            args: target.args.clone(),
            env: target.env.clone(),
            auto_approve: target.auto_approve,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubagentConfig {
    #[serde(default = "default_subagent_max_concurrent")]
    pub max_concurrent: usize,
    #[serde(default = "default_subagent_max_active_per_chat")]
    pub max_active_per_chat: usize,
    #[serde(default = "default_subagent_run_timeout_secs")]
    pub run_timeout_secs: u64,
    #[serde(default = "default_subagent_announce")]
    pub announce_to_chat: bool,
    #[serde(default)]
    pub fan_in_summary: bool,
    #[serde(default)]
    pub progress_reports: bool,
    #[serde(default = "default_subagent_progress_min_interval_secs")]
    pub progress_min_interval_secs: u64,
    #[serde(default = "default_subagent_max_spawn_depth")]
    pub max_spawn_depth: usize,
    #[serde(default = "default_subagent_max_children_per_run")]
    pub max_children_per_run: usize,
    #[serde(default = "default_subagent_thread_bound_routing_enabled")]
    pub thread_bound_routing_enabled: bool,
    #[serde(default = "default_subagent_announce_relay_interval_secs")]
    pub announce_relay_interval_secs: u64,
    #[serde(default = "default_subagent_max_tokens_per_run")]
    pub max_tokens_per_run: i64,
    #[serde(default = "default_subagent_orchestrate_max_workers")]
    pub orchestrate_max_workers: usize,
    #[serde(default)]
    pub acp: SubagentAcpConfig,
    #[serde(default)]
    pub standup: SubagentStandupConfig,
}

impl Default for SubagentConfig {
    fn default() -> Self {
        Self {
            max_concurrent: default_subagent_max_concurrent(),
            max_active_per_chat: default_subagent_max_active_per_chat(),
            run_timeout_secs: default_subagent_run_timeout_secs(),
            announce_to_chat: default_subagent_announce(),
            fan_in_summary: false,
            progress_reports: false,
            progress_min_interval_secs: default_subagent_progress_min_interval_secs(),
            max_spawn_depth: default_subagent_max_spawn_depth(),
            max_children_per_run: default_subagent_max_children_per_run(),
            thread_bound_routing_enabled: default_subagent_thread_bound_routing_enabled(),
            announce_relay_interval_secs: default_subagent_announce_relay_interval_secs(),
            max_tokens_per_run: default_subagent_max_tokens_per_run(),
            orchestrate_max_workers: default_subagent_orchestrate_max_workers(),
            acp: SubagentAcpConfig::default(),
            standup: SubagentStandupConfig::default(),
        }
    }
}

pub(crate) fn default_subagent_standup_interval_secs() -> u64 {
    1800
}

/// Proactive task-standup: periodically post a one-line status for tasks that
/// have been running a while. Off by default — it sends unprompted messages.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubagentStandupConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_subagent_standup_interval_secs")]
    pub interval_secs: u64,
}

impl Default for SubagentStandupConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: default_subagent_standup_interval_secs(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use crate::config::test_prelude::*;

    #[test]
    fn test_subagent_acp_resolve_named_target() {
        let mut acp = SubagentAcpConfig::default();
        acp.default_target.enabled = true;
        acp.default_target.command = "codex".into();
        acp.targets.insert(
            "fast".into(),
            SubagentAcpTargetConfig {
                enabled: true,
                command: "claude-code".into(),
                args: vec!["--dangerously-skip-permissions".into()],
                env: HashMap::new(),
                auto_approve: false,
            },
        );
        acp.normalize();

        let resolved = acp.resolve_target(Some("fast")).unwrap();
        assert_eq!(resolved.name.as_deref(), Some("fast"));
        assert_eq!(resolved.command, "claude-code");
        assert_eq!(
            resolved.args,
            vec!["--dangerously-skip-permissions".to_string()]
        );
        assert!(!resolved.auto_approve);
    }

    #[test]
    fn test_subagent_acp_resolve_requires_target_when_multiple_named_workers() {
        let mut acp = SubagentAcpConfig::default();
        acp.default_target.command.clear();
        acp.targets.insert(
            "one".into(),
            SubagentAcpTargetConfig {
                enabled: true,
                command: "codex".into(),
                ..SubagentAcpTargetConfig::default()
            },
        );
        acp.targets.insert(
            "two".into(),
            SubagentAcpTargetConfig {
                enabled: true,
                command: "claude-code".into(),
                ..SubagentAcpTargetConfig::default()
            },
        );
        acp.normalize();

        let err = acp.resolve_target(None).unwrap_err();
        assert!(err.contains("multiple enabled named targets"));
    }
}
