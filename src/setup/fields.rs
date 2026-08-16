use super::*;

impl SetupApp {
    pub(crate) fn next(&mut self) {
        let visible = self.visible_field_indices();
        if visible.is_empty() {
            return;
        }
        if let Some(pos) = visible.iter().position(|idx| *idx == self.selected) {
            if pos + 1 < visible.len() {
                self.selected = visible[pos + 1];
            }
        } else {
            self.selected = visible[0];
        }
        self.adjust_field_scroll(self.field_window.max(1));
    }

    pub(crate) fn prev(&mut self) {
        let visible = self.visible_field_indices();
        if visible.is_empty() {
            return;
        }
        if let Some(pos) = visible.iter().position(|idx| *idx == self.selected) {
            if pos > 0 {
                self.selected = visible[pos - 1];
            }
        } else {
            self.selected = visible[0];
        }
        self.adjust_field_scroll(self.field_window.max(1));
    }

    pub(crate) fn selected_field_mut(&mut self) -> &mut Field {
        self.ensure_selected_visible();
        &mut self.fields[self.selected]
    }

    pub(crate) fn selected_field(&self) -> &Field {
        if self.selected < self.fields.len()
            && self.is_field_visible(&self.fields[self.selected].key)
        {
            return &self.fields[self.selected];
        }
        if let Some(first_visible) = self.visible_field_indices().first().copied() {
            return &self.fields[first_visible];
        }
        &self.fields[self.selected]
    }

    pub(crate) fn field_value(&self, key: &str) -> String {
        self.fields
            .iter()
            .find(|f| f.key == key)
            .map(|f| f.value.trim().to_string())
            .unwrap_or_default()
    }

    pub(crate) fn souls_dir_value(&self) -> String {
        let configured = self.field_value("SOULS_DIR");
        if !configured.is_empty() {
            return configured;
        }
        let data_dir = self.field_value("DATA_DIR");
        if data_dir.is_empty() {
            return default_souls_dir_for_setup();
        }
        Path::new(&data_dir)
            .join("souls")
            .to_string_lossy()
            .to_string()
    }

    pub(crate) fn normalize_soul_path_value(&self, raw: &str) -> String {
        normalize_soul_path_input(raw, &self.souls_dir_value())
    }

    pub(crate) fn set_field_value(&mut self, key: &str, value: String) {
        if let Some(field) = self.fields.iter_mut().find(|f| f.key == key) {
            field.value = if key == "LLM_PROVIDER" {
                normalize_setup_provider_id(&value)
            } else {
                value
            };
        }
    }

    pub(crate) fn is_field_visible(&self, key: &str) -> bool {
        match key {
            "WEB_HOOKS_TOKEN"
            | "WEB_HOOKS_DEFAULT_SESSION_KEY"
            | "WEB_HOOKS_ALLOW_REQUEST_SESSION_KEY"
            | "WEB_HOOKS_ALLOWED_SESSION_KEY_PREFIXES" => self.channel_enabled("web"),
            "A2A_ENABLED"
            | "A2A_PUBLIC_BASE_URL"
            | "A2A_AGENT_NAME"
            | "A2A_AGENT_DESCRIPTION"
            | "A2A_SHARED_TOKENS"
            | "A2A_PEERS_JSON" => true,
            "TELEGRAM_MODEL" | "TELEGRAM_ALLOWED_USER_IDS" | "TELEGRAM_TOPIC_ROUTING" => {
                self.channel_enabled("telegram")
            }
            "TELEGRAM_BOT_TOKEN" | "BOT_USERNAME" | "TELEGRAM_ACCOUNT_ID" => false,
            "TELEGRAM_LLM_PROVIDER" | "TELEGRAM_LLM_API_KEY" | "TELEGRAM_LLM_BASE_URL" => false,
            _ if key == telegram_bot_count_key() => self.channel_enabled("telegram"),
            _ if key.starts_with("TELEGRAM_BOT") => {
                if !self.channel_enabled("telegram") {
                    return false;
                }
                for slot in 1..=MAX_BOT_SLOTS {
                    if key == telegram_slot_id_key(slot)
                        || key == telegram_slot_enabled_key(slot)
                        || key == telegram_slot_token_key(slot)
                        || key == telegram_slot_username_key(slot)
                        || key == telegram_slot_model_key(slot)
                        || key == telegram_slot_soul_path_key(slot)
                        || key == telegram_slot_allowed_user_ids_key(slot)
                        || key == telegram_slot_topic_routing_key(slot)
                    {
                        return slot <= self.telegram_bot_count();
                    }
                }
                false
            }
            "DISCORD_BOT_TOKEN"
            | "DISCORD_ACCOUNT_ID"
            | "DISCORD_MODEL"
            | "DISCORD_ACCOUNTS_JSON" => self.channel_enabled("discord"),
            "DISCORD_LLM_PROVIDER" | "DISCORD_LLM_API_KEY" | "DISCORD_LLM_BASE_URL" => false,
            _ => {
                if let Some(ch) = Self::dynamic_field_channel(key) {
                    if !self.channel_enabled(ch) {
                        return false;
                    }
                    if dynamic_channel_uses_minimal_setup(ch) {
                        return false;
                    }
                    if key == dynamic_account_id_field_key(ch)
                        || key == dynamic_accounts_json_field_key(ch)
                    {
                        return false;
                    }
                    if key == dynamic_bot_count_field_key(ch) {
                        return true;
                    }
                    for slot in 1..=MAX_BOT_SLOTS {
                        if key == dynamic_slot_id_field_key(ch, slot)
                            || key == dynamic_slot_enabled_field_key(ch, slot)
                            || key == dynamic_slot_soul_path_field_key(ch, slot)
                        {
                            return slot <= self.dynamic_bot_count(ch);
                        }
                        if key == dynamic_slot_llm_provider_key(ch, slot)
                            || key == dynamic_slot_llm_api_key_key(ch, slot)
                            || key == dynamic_slot_llm_base_url_key(ch, slot)
                        {
                            return false;
                        }
                        for d in DYNAMIC_CHANNELS {
                            if d.name != ch {
                                continue;
                            }
                            for f in d.fields {
                                if key == dynamic_slot_field_key(ch, slot, f.yaml_key) {
                                    return slot <= self.dynamic_bot_count(ch);
                                }
                            }
                        }
                    }
                    // Hide legacy single-account dynamic keys in setup UI.
                    false
                } else {
                    true
                }
            }
        }
    }

    pub(crate) fn visible_field_indices(&self) -> Vec<usize> {
        let sig = self.visibility_signature();
        if self.visible_cache_sig.get() != sig {
            let indices = self
                .fields
                .iter()
                .enumerate()
                .filter_map(|(idx, field)| {
                    if self.is_field_visible(&field.key) {
                        Some(idx)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            *self.visible_cache_indices.borrow_mut() = indices;
            self.visible_cache_sig.set(sig);
        }
        self.visible_cache_indices.borrow().clone()
    }

    pub(crate) fn visibility_signature(&self) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        for field in &self.fields {
            let key = field.key.as_str();
            if key == "ENABLED_CHANNELS"
                || key == telegram_bot_count_key()
                || key.starts_with("DYN_") && key.ends_with("_BOT_COUNT")
            {
                key.hash(&mut hasher);
                field.value.hash(&mut hasher);
            }
        }
        hasher.finish()
    }

    pub(crate) fn ensure_selected_visible(&mut self) {
        let visible = self.visible_field_indices();
        if visible.is_empty() {
            return;
        }
        if self.selected >= self.fields.len() {
            self.selected = visible[0];
            return;
        }
        if self.is_field_visible(&self.fields[self.selected].key) {
            return;
        }
        if let Some(next_idx) = visible.iter().copied().find(|idx| *idx > self.selected) {
            self.selected = next_idx;
            return;
        }
        if let Some(last) = visible.last().copied() {
            self.selected = last;
        }
        self.adjust_field_scroll(self.field_window.max(1));
    }

    pub(crate) fn adjust_field_scroll(&mut self, window: usize) {
        let visible = self.visible_field_indices();
        if visible.is_empty() {
            self.field_scroll = 0;
            return;
        }
        let Some(sel_pos) = visible.iter().position(|idx| *idx == self.selected) else {
            self.field_scroll = 0;
            return;
        };
        if self.field_scroll >= visible.len() {
            self.field_scroll = visible.len().saturating_sub(1);
        }
        if sel_pos < self.field_scroll {
            self.field_scroll = sel_pos;
        }
        let window_lines = window.max(1);
        while self.field_scroll < sel_pos {
            let end = self.window_end_for_start_pos(&visible, self.field_scroll, window_lines);
            if sel_pos < end {
                break;
            }
            self.field_scroll += 1;
        }
    }

    pub(crate) fn page_down(&mut self, window: usize) {
        let visible = self.visible_field_indices();
        if visible.is_empty() {
            return;
        }
        let start = self.field_scroll.min(visible.len().saturating_sub(1));
        let end = self.window_end_for_start_pos(&visible, start, window.max(1));
        if end >= visible.len() {
            self.selected = visible[visible.len() - 1];
        } else {
            self.field_scroll = end;
            self.selected = visible[end];
        }
        self.adjust_field_scroll(window.max(1));
    }

    pub(crate) fn page_up(&mut self, window: usize) {
        let visible = self.visible_field_indices();
        if visible.is_empty() {
            return;
        }
        let step = window.max(1);
        self.field_scroll = self
            .field_scroll
            .saturating_sub(step)
            .min(visible.len() - 1);
        self.selected = visible[self.field_scroll];
        self.adjust_field_scroll(window.max(1));
    }

    pub(crate) fn jump_top(&mut self) {
        let visible = self.visible_field_indices();
        if visible.is_empty() {
            return;
        }
        self.field_scroll = 0;
        self.selected = visible[0];
        self.adjust_field_scroll(self.field_window.max(1));
    }

    pub(crate) fn jump_bottom(&mut self) {
        let visible = self.visible_field_indices();
        if visible.is_empty() {
            return;
        }
        self.selected = *visible.last().unwrap_or(&visible[0]);
        self.adjust_field_scroll(self.field_window.max(1));
    }

    pub(crate) fn window_end_for_start_pos(
        &self,
        visible: &[usize],
        start_pos: usize,
        window_lines: usize,
    ) -> usize {
        if visible.is_empty() || start_pos >= visible.len() {
            return visible.len();
        }
        let mut used_lines = 0usize;
        let mut last_section = "";
        let mut pos = start_pos;
        while pos < visible.len() {
            let section = Self::section_for_key(&self.fields[visible[pos]].key);
            let added = if section != last_section {
                if used_lines == 0 {
                    2
                } else {
                    3
                }
            } else {
                1
            };
            if used_lines + added > window_lines {
                if pos == start_pos {
                    return pos + 1;
                }
                break;
            }
            used_lines += added;
            last_section = section;
            pos += 1;
        }
        pos
    }

    pub(crate) fn selected_progress(&self) -> (usize, usize) {
        let visible = self.visible_field_indices();
        if visible.is_empty() {
            return (1, 1);
        }
        let current = visible
            .iter()
            .position(|idx| *idx == self.selected)
            .map(|v| v + 1)
            .unwrap_or(1);
        (current, visible.len())
    }

    pub(crate) fn is_field_required(&self, field: &Field) -> bool {
        if field.key == "LLM_API_KEY" {
            return !provider_allows_empty_api_key(&self.field_value("LLM_PROVIDER"));
        }
        field.required
    }

    pub(crate) fn key_display(key: &str) -> String {
        if key == llm_provider_profiles_key() {
            "LLM_PROVIDER_PROFILES".to_string()
        } else {
            key.to_string()
        }
    }

    pub(crate) fn default_value_for_field(&self, key: &str) -> String {
        let provider = self.field_value("LLM_PROVIDER");
        match key {
            "ENABLED_CHANNELS" => "web".into(),
            "TELEGRAM_ACCOUNT_ID" | "DISCORD_ACCOUNT_ID" => default_account_id().to_string(),
            "TELEGRAM_BOT_TOKEN"
            | "BOT_USERNAME"
            | "WEB_HOOKS_TOKEN"
            | "WEB_HOOKS_ALLOWED_SESSION_KEY_PREFIXES"
            | "A2A_PUBLIC_BASE_URL"
            | "A2A_AGENT_NAME"
            | "A2A_AGENT_DESCRIPTION"
            | "A2A_SHARED_TOKENS"
            | "A2A_PEERS_JSON"
            | "TELEGRAM_MODEL"
            | "TELEGRAM_ALLOWED_USER_IDS"
            | "TELEGRAM_TOPIC_ROUTING"
            | "TELEGRAM_LLM_PROVIDER"
            | "TELEGRAM_LLM_API_KEY"
            | "TELEGRAM_LLM_BASE_URL"
            | "DISCORD_BOT_TOKEN"
            | "DISCORD_MODEL"
            | "DISCORD_ACCOUNTS_JSON"
            | "LLM_API_KEY" => String::new(),
            "WEB_HOOKS_DEFAULT_SESSION_KEY" => "hook:ingress".into(),
            "WEB_HOOKS_ALLOW_REQUEST_SESSION_KEY" => "false".into(),
            "A2A_ENABLED" => "false".into(),
            "SUBAGENTS_MAX_CONCURRENT" => "4".into(),
            "SUBAGENTS_MAX_ACTIVE_PER_CHAT" => "5".into(),
            "SUBAGENTS_RUN_TIMEOUT_SECS" => "900".into(),
            "SUBAGENTS_ANNOUNCE_TO_CHAT" => "true".into(),
            "SUBAGENTS_MAX_SPAWN_DEPTH" => "1".into(),
            "SUBAGENTS_MAX_CHILDREN_PER_RUN" => "5".into(),
            "SUBAGENTS_THREAD_BOUND_ROUTING_ENABLED" => "true".into(),
            "SUBAGENTS_ANNOUNCE_RELAY_INTERVAL_SECS" => "15".into(),
            "SUBAGENTS_MAX_TOKENS_PER_RUN" => "400000".into(),
            "SUBAGENTS_ORCHESTRATE_MAX_WORKERS" => "5".into(),
            "SUBAGENTS_ACP_ENABLED" => "false".into(),
            "SUBAGENTS_ACP_AUTO_APPROVE" => "true".into(),
            _ if key == telegram_bot_count_key() => TELEGRAM_DEFAULT_BOT_COUNT.to_string(),
            _ if key.starts_with("TELEGRAM_BOT") => {
                if key.ends_with("_ENABLED") {
                    "true".into()
                } else {
                    String::new()
                }
            }
            "LLM_PROVIDER" => "anthropic".into(),
            "LLM_MODEL" => default_model_for_provider(&provider).into(),
            "LLM_BASE_URL" => find_provider_preset(&provider)
                .map(|p| p.default_base_url.to_string())
                .unwrap_or_default(),
            "LLM_USER_AGENT" => String::new(),
            _ if key == llm_provider_profiles_key() => String::new(),
            "SHOW_THINKING" => "false".into(),
            "DATA_DIR" => default_data_dir_for_setup(),
            "OVERRIDE_TIMEZONE" => String::new(),
            "WORKING_DIR" => default_working_dir_for_setup(),
            "SOULS_DIR" => default_souls_dir_for_setup(),
            "SANDBOX_ENABLED" => "false".into(),
            "HIGH_RISK_TOOL_USER_CONFIRMATION_REQUIRED" => "true".into(),
            "REFLECTOR_ENABLED" => "true".into(),
            "REFLECTOR_INTERVAL_MINS" => "15".into(),
            "MEMORY_TOKEN_BUDGET" => "1500".into(),
            "EMBEDDING_PROVIDER" | "EMBEDDING_API_KEY" | "EMBEDDING_BASE_URL"
            | "EMBEDDING_MODEL" | "EMBEDDING_DIM" => String::new(),
            _ => {
                for ch in DYNAMIC_CHANNELS {
                    if key == dynamic_bot_count_field_key(ch.name) {
                        return "1".into();
                    }
                    if key == dynamic_account_id_field_key(ch.name) {
                        return default_account_id().to_string();
                    }
                    if key == dynamic_accounts_json_field_key(ch.name) {
                        return String::new();
                    }
                    for slot in 1..=MAX_BOT_SLOTS {
                        if key == dynamic_slot_enabled_field_key(ch.name, slot) {
                            return "true".into();
                        }
                        if key == dynamic_slot_id_field_key(ch.name, slot) {
                            return default_slot_account_id(slot);
                        }
                        for f in ch.fields {
                            if key == dynamic_slot_field_key(ch.name, slot, f.yaml_key) {
                                return String::new();
                            }
                        }
                    }
                }
                String::new()
            }
        }
    }

    pub(crate) fn clear_selected_field(&mut self) {
        let key = self.selected_field().key.clone();
        if let Some(keys) = Self::llm_override_related_keys_for_model_field(&key) {
            for k in keys {
                self.set_field_value(&k, String::new());
            }
        } else {
            self.selected_field_mut().value.clear();
        }
        self.status = format!("Cleared {key}");
    }

    pub(crate) fn restore_selected_field_default(&mut self) {
        let key = self.selected_field().key.clone();
        let default = self.default_value_for_field(&key);
        if default.is_empty() {
            self.status = format!("{key} has no default");
        } else {
            self.selected_field_mut().value = default.clone();
            self.status = format!("Restored {key} to default: {default}");
        }
    }

    pub(crate) fn section_for_key(key: &str) -> &'static str {
        if key.starts_with("DYN_") {
            return "Channel";
        }
        match key {
            "DATA_DIR" | "OVERRIDE_TIMEZONE" | "WORKING_DIR" | "SOULS_DIR" => "App",
            "SANDBOX_ENABLED" | "HIGH_RISK_TOOL_USER_CONFIRMATION_REQUIRED" => "Sandbox",
            "REFLECTOR_ENABLED" | "REFLECTOR_INTERVAL_MINS" | "MEMORY_TOKEN_BUDGET" => "Memory",
            "LLM_PROVIDER" | "LLM_API_KEY" | "LLM_MODEL" | "LLM_BASE_URL" | "LLM_USER_AGENT"
            | "SHOW_THINKING" => "Model",
            _ if key == llm_provider_profiles_key() => "Model",
            "EMBEDDING_PROVIDER" | "EMBEDDING_API_KEY" | "EMBEDDING_BASE_URL"
            | "EMBEDDING_MODEL" | "EMBEDDING_DIM" => "Embedding",
            "A2A_ENABLED"
            | "A2A_PUBLIC_BASE_URL"
            | "A2A_AGENT_NAME"
            | "A2A_AGENT_DESCRIPTION"
            | "A2A_SHARED_TOKENS"
            | "A2A_PEERS_JSON" => "A2A",
            "SUBAGENTS_MAX_CONCURRENT"
            | "SUBAGENTS_MAX_ACTIVE_PER_CHAT"
            | "SUBAGENTS_RUN_TIMEOUT_SECS"
            | "SUBAGENTS_ANNOUNCE_TO_CHAT"
            | "SUBAGENTS_MAX_SPAWN_DEPTH"
            | "SUBAGENTS_MAX_CHILDREN_PER_RUN"
            | "SUBAGENTS_THREAD_BOUND_ROUTING_ENABLED"
            | "SUBAGENTS_ANNOUNCE_RELAY_INTERVAL_SECS"
            | "SUBAGENTS_MAX_TOKENS_PER_RUN"
            | "SUBAGENTS_ORCHESTRATE_MAX_WORKERS"
            | "SUBAGENTS_ACP_ENABLED"
            | "SUBAGENTS_ACP_COMMAND"
            | "SUBAGENTS_ACP_ARGS"
            | "SUBAGENTS_ACP_ENV_JSON"
            | "SUBAGENTS_ACP_AUTO_APPROVE"
            | "SUBAGENTS_ACP_DEFAULT_TARGET"
            | "SUBAGENTS_ACP_TARGETS_JSON" => "Sub-agents",
            "ENABLED_CHANNELS"
            | "WEB_HOOKS_TOKEN"
            | "WEB_HOOKS_DEFAULT_SESSION_KEY"
            | "WEB_HOOKS_ALLOW_REQUEST_SESSION_KEY"
            | "WEB_HOOKS_ALLOWED_SESSION_KEY_PREFIXES"
            | "TELEGRAM_BOT_TOKEN"
            | "BOT_USERNAME"
            | "TELEGRAM_ACCOUNT_ID"
            | "TELEGRAM_MODEL"
            | "TELEGRAM_ALLOWED_USER_IDS"
            | "TELEGRAM_TOPIC_ROUTING"
            | "TELEGRAM_LLM_PROVIDER"
            | "TELEGRAM_LLM_API_KEY"
            | "TELEGRAM_LLM_BASE_URL"
            | "DISCORD_BOT_TOKEN"
            | "DISCORD_ACCOUNT_ID"
            | "DISCORD_MODEL"
            | "DISCORD_LLM_PROVIDER"
            | "DISCORD_LLM_API_KEY"
            | "DISCORD_LLM_BASE_URL"
            | "DISCORD_ACCOUNTS_JSON" => "Channel",
            _ if key == telegram_bot_count_key() => "Channel",
            _ if key.starts_with("TELEGRAM_BOT") => "Channel",
            _ => "Setup",
        }
    }

    pub(crate) fn field_guidance(key: &str) -> (&'static str, &'static str) {
        match key {
            "LLM_PROVIDER" => (
                "Select the LLM backend. Presets auto-fill a sensible model/base URL. OpenRouter models: https://openrouter.ai/models . NVIDIA models: https://build.nvidia.com/models",
                "Example: openai, anthropic, openrouter, nvidia, custom",
            ),
            "LLM_API_KEY" => (
                "API key for the selected provider. Leave empty only for providers that allow it.",
                "Example: sk-xxxx",
            ),
            "LLM_MODEL" => (
                "Default model used when no per-channel override is set.",
                "Example: qwen3.5-plus",
            ),
            "LLM_BASE_URL" => (
                "Custom OpenAI-compatible endpoint root. Use provider default if empty.",
                "Example: https://dashscope.aliyuncs.com/compatible-mode/v1",
            ),
            "LLM_USER_AGENT" => (
                "HTTP User-Agent for LLM requests. Empty means automatic MicroClaw/<version>.",
                "Example: OpenClaw-Gateway/1.0",
            ),
            _ if key == llm_provider_profiles_key() => (
                "Reusable profile definitions keyed by profile id. Press Enter to open the profile editor.",
                "Example: create profile provider1 for OpenAI, then let channels/bots select provider1",
            ),
            "SHOW_THINKING" => (
                "Show model reasoning/thinking text in channel output when provider supports it.",
                "Example: true or false",
            ),
            "ENABLED_CHANNELS" => (
                "Comma-separated channel names to enable now. You can configure more later.",
                "Example: web,feishu,telegram",
            ),
            "WEB_HOOKS_TOKEN" => (
                "Bearer token used to authenticate /hooks/* and /api/hooks/* requests.",
                "Example: my-hooks-secret",
            ),
            "WEB_HOOKS_DEFAULT_SESSION_KEY" => (
                "Default session key used by hooks when request payload omits sessionKey.",
                "Example: hook:ingress",
            ),
            "WEB_HOOKS_ALLOW_REQUEST_SESSION_KEY" => (
                "Whether hook payload may override sessionKey. Keep false unless you trust callers.",
                "Example: true or false",
            ),
            "WEB_HOOKS_ALLOWED_SESSION_KEY_PREFIXES" => (
                "Allowlist of sessionKey prefixes when request override is enabled (csv/JSON array).",
                "Example: hook:,chat:",
            ),
            "A2A_ENABLED" => (
                "Enable agent-to-agent HTTP endpoints and outbound delegation tools.",
                "Example: true or false",
            ),
            "A2A_PUBLIC_BASE_URL" => (
                "Public base URL remote peers should use for agent-card discovery and message delivery.",
                "Example: https://planner.example.com",
            ),
            "A2A_AGENT_NAME" => (
                "Friendly name exposed in the A2A agent card and outbound calls.",
                "Example: Planner",
            ),
            "A2A_AGENT_DESCRIPTION" => (
                "Short description of this agent's role for other agents.",
                "Example: Routes work to specialized agents",
            ),
            "A2A_SHARED_TOKENS" => (
                "Inbound bearer tokens accepted by /api/a2a/message (csv/JSON array).",
                "Example: shared-a2a-token,backup-token",
            ),
            "A2A_PEERS_JSON" => (
                "JSON object of outbound peers keyed by name. Supports base_url, bearer_token, description, default_session_key, enabled.",
                "Example: {\"worker\":{\"base_url\":\"https://worker.example.com\",\"bearer_token\":\"shared-a2a-token\"}}",
            ),
            "SUBAGENTS_MAX_CONCURRENT" => (
                "Maximum number of subagent runs allowed to execute at the same time across the runtime.",
                "Example: 4",
            ),
            "SUBAGENTS_MAX_ACTIVE_PER_CHAT" => (
                "Maximum number of active subagent runs allowed in one chat.",
                "Example: 5",
            ),
            "SUBAGENTS_RUN_TIMEOUT_SECS" => (
                "Per-run timeout for one subagent before it is marked timed out.",
                "Example: 1800",
            ),
            "SUBAGENTS_ANNOUNCE_TO_CHAT" => (
                "Whether finished subagents post completion notices back to the parent chat.",
                "Example: true or false",
            ),
            "SUBAGENTS_MAX_SPAWN_DEPTH" => (
                "Maximum recursive subagent nesting depth.",
                "Example: 1",
            ),
            "SUBAGENTS_MAX_CHILDREN_PER_RUN" => (
                "Maximum active child runs that one parent run may create.",
                "Example: 5",
            ),
            "SUBAGENTS_THREAD_BOUND_ROUTING_ENABLED" => (
                "Route thread replies to the currently focused subagent when the channel supports it.",
                "Example: true or false",
            ),
            "SUBAGENTS_ANNOUNCE_RELAY_INTERVAL_SECS" => (
                "Polling interval for relaying pending subagent completion notices.",
                "Example: 15",
            ),
            "SUBAGENTS_MAX_TOKENS_PER_RUN" => (
                "Default token budget ceiling for sessions_spawn and subagents_orchestrate.",
                "Example: 240000",
            ),
            "SUBAGENTS_ORCHESTRATE_MAX_WORKERS" => (
                "Worker cap used by subagents_orchestrate fan-out.",
                "Example: 5",
            ),
            "SUBAGENTS_ACP_ENABLED" => (
                "Enable ACP-backed external subagent execution for sessions_spawn(runtime=\"acp\").",
                "Example: true or false",
            ),
            "SUBAGENTS_ACP_COMMAND" => (
                "Default ACP worker command used when no named target is selected.",
                "Example: codex",
            ),
            "SUBAGENTS_ACP_ARGS" => (
                "Default ACP worker args as csv or JSON array.",
                "Example: [\"--model\",\"gpt-5.4\"]",
            ),
            "SUBAGENTS_ACP_ENV_JSON" => (
                "Default ACP worker env vars as JSON object.",
                "Example: {\"OPENAI_API_KEY\":\"sk-...\"}",
            ),
            "SUBAGENTS_ACP_AUTO_APPROVE" => (
                "Whether the default ACP target auto-approves ACP permission requests.",
                "Example: true or false",
            ),
            "SUBAGENTS_ACP_DEFAULT_TARGET" => (
                "Named ACP target to use by default when runtime_target is omitted.",
                "Example: codex-fast",
            ),
            "SUBAGENTS_ACP_TARGETS_JSON" => (
                "Named ACP worker definitions as JSON object keyed by target name.",
                "Example: {\"codex-fast\":{\"enabled\":true,\"command\":\"codex\",\"args\":[\"--model\",\"gpt-5.4\"]}}",
            ),
            "DATA_DIR" => (
                "Root directory for runtime data (DB, sessions, memory, skills).",
                "Example: ./microclaw.data",
            ),
            "WORKING_DIR" => (
                "Filesystem base path for tools like read/write/bash/glob.",
                "Example: ./tmp",
            ),
            "OVERRIDE_TIMEZONE" => (
                "Optional IANA timezone override for scheduling. Empty uses system timezone.",
                "Example: Asia/Shanghai",
            ),
            "SOULS_DIR" => (
                "Directory storing SOUL.md personalities. Empty uses <data_dir>/souls.",
                "Example: ./microclaw.data/souls",
            ),
            "REFLECTOR_ENABLED" => (
                "Enable periodic memory reflection that extracts structured memories from chat.",
                "Example: true or false",
            ),
            "REFLECTOR_INTERVAL_MINS" => ("How often memory reflection runs.", "Example: 15"),
            "MEMORY_TOKEN_BUDGET" => (
                "Approximate token budget for injected memories in the system prompt.",
                "Example: 1500",
            ),
            "EMBEDDING_PROVIDER" => (
                "Provider for memory embeddings (semantic retrieval). Optional feature.",
                "Example: openai or ollama",
            ),
            "EMBEDDING_API_KEY" => (
                "API key for embedding provider, if required.",
                "Example: sk-xxxx",
            ),
            "EMBEDDING_BASE_URL" => (
                "Custom endpoint for embedding provider.",
                "Example: https://api.openai.com/v1",
            ),
            "EMBEDDING_MODEL" => (
                "Embedding model name for memory vectors.",
                "Example: text-embedding-3-small",
            ),
            "EMBEDDING_DIM" => ("Embedding vector dimension.", "Example: 1536"),
            "SANDBOX_ENABLED" => (
                "Enable sandbox mode for tool execution isolation.",
                "Example: true or false",
            ),
            "HIGH_RISK_TOOL_USER_CONFIRMATION_REQUIRED" => (
                "Require explicit confirmation before running high-risk tools.",
                "Example: true or false",
            ),
            _ if key.ends_with("_BOT_TOKEN") => (
                "Bot token for this channel account.",
                "Example: 123456:ABCDEF...",
            ),
            _ if key.ends_with("_MODEL") => (
                "Per-channel/per-account provider profile override entry point. Press Enter to choose profile; model follows the profile.",
                "Example: choose provider1 or leave empty for main",
            ),
            _ if key.ends_with("_LLM_PROVIDER") => (
                "Per-channel/per-account profile id override. Empty means use main/global default.",
                "Example: provider1",
            ),
            _ if key.ends_with("_LLM_API_KEY") => (
                "Per-channel/per-account API key override.",
                "Example: sk-xxxx",
            ),
            _ if key.ends_with("_LLM_BASE_URL") => (
                "Per-channel/per-account base URL override.",
                "Example: https://dashscope.aliyuncs.com/compatible-mode/v1",
            ),
            _ if key.ends_with("_ALLOWED_USER_IDS") => (
                "Allowed user IDs for this bot/account.",
                "Example: 12345,67890",
            ),
            _ if key.ends_with("_SOUL_PATH") => (
                "SOUL.md filename/path used by this bot/account.",
                "Example: souls/soul-zhang.md",
            ),
            _ if key.starts_with("DYN_") => (
                "Dynamic channel field loaded from channel setup definition.",
                "Example: fill with your channel-specific credential/config value",
            ),
            _ => ("Configuration value used by setup/runtime.", ""),
        }
    }

    pub(crate) fn field_display_order(key: &str) -> usize {
        const ORDER_MODEL_BASE: usize = 0;
        const ORDER_CHANNEL_BASE: usize = 100;
        const ORDER_APP_BASE: usize = 20_000;
        const ORDER_MEMORY_BASE: usize = 21_000;
        const ORDER_EMBED_BASE: usize = 22_000;
        const ORDER_SANDBOX_BASE: usize = 23_000;
        const ORDER_A2A_BASE: usize = 24_000;
        const ORDER_SUBAGENTS_BASE: usize = 25_000;

        if key.starts_with("DYN_") {
            for (ch_idx, ch) in DYNAMIC_CHANNELS.iter().enumerate() {
                let channel_base = ORDER_CHANNEL_BASE + 2_000 + ch_idx * 1_000;
                if key == dynamic_bot_count_field_key(ch.name) {
                    return channel_base;
                }
                for slot in 1..=MAX_BOT_SLOTS {
                    let slot_base = channel_base + slot * 50;
                    if key == dynamic_slot_id_field_key(ch.name, slot) {
                        return slot_base + 1;
                    }
                    if key == dynamic_slot_enabled_field_key(ch.name, slot) {
                        return slot_base + 2;
                    }
                    if key == dynamic_slot_soul_path_field_key(ch.name, slot) {
                        return slot_base + 3;
                    }
                    for (field_idx, f) in ch.fields.iter().enumerate() {
                        if key == dynamic_slot_field_key(ch.name, slot, f.yaml_key) {
                            return slot_base + 4 + field_idx;
                        }
                    }
                    if key == dynamic_slot_llm_provider_key(ch.name, slot) {
                        return slot_base + 30;
                    }
                    if key == dynamic_slot_llm_api_key_key(ch.name, slot) {
                        return slot_base + 31;
                    }
                    if key == dynamic_slot_llm_base_url_key(ch.name, slot) {
                        return slot_base + 32;
                    }
                }
                if key == dynamic_account_id_field_key(ch.name) {
                    return channel_base + 900;
                }
                if key == dynamic_accounts_json_field_key(ch.name) {
                    return channel_base + 901;
                }
                for (field_idx, f) in ch.fields.iter().enumerate() {
                    if key == dynamic_field_key(ch.name, f.yaml_key) {
                        return channel_base + 910 + field_idx;
                    }
                }
            }
            return usize::MAX;
        }
        match key {
            // 1) Model
            "LLM_PROVIDER" => ORDER_MODEL_BASE,
            "LLM_API_KEY" => ORDER_MODEL_BASE + 1,
            "LLM_MODEL" => ORDER_MODEL_BASE + 2,
            "LLM_BASE_URL" => ORDER_MODEL_BASE + 3,
            "LLM_USER_AGENT" => ORDER_MODEL_BASE + 4,
            "SHOW_THINKING" => ORDER_MODEL_BASE + 5,
            _ if key == llm_provider_profiles_key() => ORDER_MODEL_BASE + 6,
            // 2) Channel (dynamic channel fields are placed in the branch above)
            "ENABLED_CHANNELS" => ORDER_CHANNEL_BASE,
            "WEB_HOOKS_TOKEN" => ORDER_CHANNEL_BASE + 1,
            "WEB_HOOKS_DEFAULT_SESSION_KEY" => ORDER_CHANNEL_BASE + 2,
            "WEB_HOOKS_ALLOW_REQUEST_SESSION_KEY" => ORDER_CHANNEL_BASE + 3,
            "WEB_HOOKS_ALLOWED_SESSION_KEY_PREFIXES" => ORDER_CHANNEL_BASE + 4,
            "TELEGRAM_BOT_TOKEN" => ORDER_CHANNEL_BASE + 20,
            "BOT_USERNAME" => ORDER_CHANNEL_BASE + 21,
            "TELEGRAM_ACCOUNT_ID" => ORDER_CHANNEL_BASE + 22,
            _ if key == telegram_bot_count_key() => ORDER_CHANNEL_BASE + 23,
            "TELEGRAM_MODEL" => ORDER_CHANNEL_BASE + 24,
            "TELEGRAM_ALLOWED_USER_IDS" => ORDER_CHANNEL_BASE + 25,
            "TELEGRAM_TOPIC_ROUTING" => ORDER_CHANNEL_BASE + 26,
            "TELEGRAM_LLM_PROVIDER" => ORDER_CHANNEL_BASE + 27,
            "TELEGRAM_LLM_API_KEY" => ORDER_CHANNEL_BASE + 28,
            "TELEGRAM_LLM_BASE_URL" => ORDER_CHANNEL_BASE + 29,
            "DISCORD_BOT_TOKEN" => ORDER_CHANNEL_BASE + 900,
            "DISCORD_ACCOUNT_ID" => ORDER_CHANNEL_BASE + 901,
            "DISCORD_MODEL" => ORDER_CHANNEL_BASE + 902,
            "DISCORD_LLM_PROVIDER" => ORDER_CHANNEL_BASE + 903,
            "DISCORD_LLM_API_KEY" => ORDER_CHANNEL_BASE + 904,
            "DISCORD_LLM_BASE_URL" => ORDER_CHANNEL_BASE + 905,
            "DISCORD_ACCOUNTS_JSON" => ORDER_CHANNEL_BASE + 906,
            _ if key.starts_with("TELEGRAM_BOT") => {
                for slot in 1..=MAX_BOT_SLOTS {
                    let base = ORDER_CHANNEL_BASE + 100 + (slot * 10);
                    if key == telegram_slot_id_key(slot) {
                        return base + 1;
                    }
                    if key == telegram_slot_enabled_key(slot) {
                        return base + 2;
                    }
                    if key == telegram_slot_token_key(slot) {
                        return base + 3;
                    }
                    if key == telegram_slot_username_key(slot) {
                        return base + 4;
                    }
                    if key == telegram_slot_model_key(slot) {
                        return base + 5;
                    }
                    if key == telegram_slot_soul_path_key(slot) {
                        return base + 6;
                    }
                    if key == telegram_slot_allowed_user_ids_key(slot) {
                        return base + 7;
                    }
                    if key == telegram_slot_topic_routing_key(slot) {
                        return base + 8;
                    }
                }
                usize::MAX
            }
            // 3) App
            "DATA_DIR" => ORDER_APP_BASE,
            "WORKING_DIR" => ORDER_APP_BASE + 1,
            "OVERRIDE_TIMEZONE" => ORDER_APP_BASE + 2,
            "SOULS_DIR" => ORDER_APP_BASE + 3,
            // 4) Memory
            "REFLECTOR_ENABLED" => ORDER_MEMORY_BASE,
            "REFLECTOR_INTERVAL_MINS" => ORDER_MEMORY_BASE + 1,
            "MEMORY_TOKEN_BUDGET" => ORDER_MEMORY_BASE + 2,
            // 5) Embedding
            "EMBEDDING_PROVIDER" => ORDER_EMBED_BASE,
            "EMBEDDING_API_KEY" => ORDER_EMBED_BASE + 1,
            "EMBEDDING_BASE_URL" => ORDER_EMBED_BASE + 2,
            "EMBEDDING_MODEL" => ORDER_EMBED_BASE + 3,
            "EMBEDDING_DIM" => ORDER_EMBED_BASE + 4,
            // 6) Sandbox
            "SANDBOX_ENABLED" => ORDER_SANDBOX_BASE,
            "HIGH_RISK_TOOL_USER_CONFIRMATION_REQUIRED" => ORDER_SANDBOX_BASE + 1,
            // 7) A2A
            "A2A_ENABLED" => ORDER_A2A_BASE,
            "A2A_PUBLIC_BASE_URL" => ORDER_A2A_BASE + 1,
            "A2A_AGENT_NAME" => ORDER_A2A_BASE + 2,
            "A2A_AGENT_DESCRIPTION" => ORDER_A2A_BASE + 3,
            "A2A_SHARED_TOKENS" => ORDER_A2A_BASE + 4,
            "A2A_PEERS_JSON" => ORDER_A2A_BASE + 5,
            // 8) Sub-agents (last)
            "SUBAGENTS_MAX_CONCURRENT" => ORDER_SUBAGENTS_BASE,
            "SUBAGENTS_MAX_ACTIVE_PER_CHAT" => ORDER_SUBAGENTS_BASE + 1,
            "SUBAGENTS_RUN_TIMEOUT_SECS" => ORDER_SUBAGENTS_BASE + 2,
            "SUBAGENTS_ANNOUNCE_TO_CHAT" => ORDER_SUBAGENTS_BASE + 3,
            "SUBAGENTS_MAX_SPAWN_DEPTH" => ORDER_SUBAGENTS_BASE + 4,
            "SUBAGENTS_MAX_CHILDREN_PER_RUN" => ORDER_SUBAGENTS_BASE + 5,
            "SUBAGENTS_THREAD_BOUND_ROUTING_ENABLED" => ORDER_SUBAGENTS_BASE + 6,
            "SUBAGENTS_ANNOUNCE_RELAY_INTERVAL_SECS" => ORDER_SUBAGENTS_BASE + 7,
            "SUBAGENTS_MAX_TOKENS_PER_RUN" => ORDER_SUBAGENTS_BASE + 8,
            "SUBAGENTS_ORCHESTRATE_MAX_WORKERS" => ORDER_SUBAGENTS_BASE + 9,
            _ => usize::MAX,
        }
    }

    pub(crate) fn current_section(&self) -> &'static str {
        Self::section_for_key(&self.selected_field().key)
    }

    pub(crate) fn progress_bar(&self, width: usize) -> String {
        let (done, total) = self.selected_progress();
        let fill = (done * width) / total;
        let mut s = String::new();
        for i in 0..width {
            if i < fill {
                s.push('█');
            } else {
                s.push('░');
            }
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use crate::setup::test_prelude::*;

    #[test]
    fn test_picker_selecting_main_clears_channel_provider_preset() {
        let mut app = SetupApp::new();
        // Set up channel-level override
        app.set_field_value("TELEGRAM_MODEL", "googlegemini".into());
        app.set_field_value(telegram_llm_provider_key(), "googlegemini".into());

        // Simulate picker selecting "main" for channel-level field
        app.llm_override_picker = Some(LlmOverridePicker {
            title: "Select LLM Provider Profile".to_string(),
            target_key: "TELEGRAM_MODEL".to_string(),
            options: vec![
                ("main (global default)".to_string(), String::new()),
                (
                    "googlegemini - google / gemini-2.5-pro".to_string(),
                    "googlegemini".into(),
                ),
            ],
            selected: 0,
        });
        app.apply_llm_override_picker_selection();

        assert_eq!(
            app.field_value("TELEGRAM_MODEL"),
            "",
            "TELEGRAM_MODEL should be empty after selecting main"
        );
        assert_eq!(
            app.field_value(telegram_llm_provider_key()),
            "",
            "TELEGRAM_LLM_PROVIDER should also be cleared"
        );
    }

    #[test]
    fn test_picker_clearing_channel_also_clears_inherited_slot_values() {
        let mut app = SetupApp::new();
        // Simulate loading: channel has googlegemini, slot inherited the same
        app.set_field_value("TELEGRAM_MODEL", "googlegemini".into());
        app.set_field_value(telegram_llm_provider_key(), "googlegemini".into());
        app.set_field_value(&telegram_slot_model_key(1), "googlegemini".into());

        // User selects "main" on channel-level field
        app.llm_override_picker = Some(LlmOverridePicker {
            title: "Select LLM Provider Profile".to_string(),
            target_key: "TELEGRAM_MODEL".to_string(),
            options: vec![
                ("main (global default)".to_string(), String::new()),
                (
                    "googlegemini - google / gemini-2.5-pro".to_string(),
                    "googlegemini".into(),
                ),
            ],
            selected: 0,
        });
        app.apply_llm_override_picker_selection();

        assert_eq!(app.field_value("TELEGRAM_MODEL"), "");
        assert_eq!(app.field_value(telegram_llm_provider_key()), "");
        // Slot that inherited the same value should also be cleared
        assert_eq!(
            app.field_value(&telegram_slot_model_key(1)),
            "",
            "slot with inherited channel value should be cleared"
        );
    }
}
