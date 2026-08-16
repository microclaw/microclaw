use super::*;

#[derive(Clone)]
pub(crate) struct LlmOverridePage {
    pub(crate) title: String,
    pub(crate) provider_key: String,
    pub(crate) api_key_key: String,
    pub(crate) base_url_key: String,
    pub(crate) show_legacy_fields: bool,
    pub(crate) selected: usize,
    pub(crate) editing: bool,
}

#[derive(Clone)]
pub(crate) struct LlmOverridePicker {
    pub(crate) title: String,
    pub(crate) target_key: String,
    pub(crate) options: Vec<(String, String)>,
    pub(crate) selected: usize,
}

impl SetupApp {
    pub(crate) fn llm_override_uses_legacy_fields(
        &self,
        provider_key: &str,
        api_key_key: &str,
        base_url_key: &str,
    ) -> bool {
        let provider = self.field_value(provider_key);
        let api_key = self.field_value(api_key_key);
        let base_url = self.field_value(base_url_key);
        if !api_key.is_empty() || !base_url.is_empty() {
            return true;
        }
        let provider = provider.trim();
        if provider.is_empty() {
            return false;
        }
        !self
            .llm_provider_presets()
            .keys()
            .any(|preset| preset.eq_ignore_ascii_case(provider))
    }

    pub(crate) fn llm_override_label_for_key(key: &str) -> &'static str {
        match key {
            "TELEGRAM_LLM_PROVIDER" => "Preset ID (optional; main=global)",
            "TELEGRAM_LLM_API_KEY" => "API key (optional)",
            "TELEGRAM_LLM_BASE_URL" => "Base URL (optional)",
            "DISCORD_LLM_PROVIDER" => "Preset ID (optional; main=global)",
            "DISCORD_LLM_API_KEY" => "API key (optional)",
            "DISCORD_LLM_BASE_URL" => "Base URL (optional)",
            "TELEGRAM_MODEL" => "Preset ID (optional; main=global)",
            "DISCORD_MODEL" => "Preset ID (optional; main=global)",
            _ if key.ends_with("_LLM_PROVIDER") => "Preset ID (optional; main=global)",
            _ if key.ends_with("_LLM_API_KEY") => "API key (optional)",
            _ if key.ends_with("_LLM_BASE_URL") => "Base URL (optional)",
            _ if key.ends_with("_MODEL") => "Preset ID (optional; main=global)",
            _ => "Value",
        }
    }

    pub(crate) fn open_llm_override_page(
        &mut self,
        title: String,
        provider_key: String,
        api_key_key: String,
        base_url_key: String,
    ) {
        let show_legacy_fields =
            self.llm_override_uses_legacy_fields(&provider_key, &api_key_key, &base_url_key);
        if !show_legacy_fields {
            self.llm_override_page = None;
            self.open_llm_override_provider_picker_for_key(&provider_key);
            self.status = "Selecting LLM provider profile override".to_string();
            return;
        }
        self.llm_override_page = Some(LlmOverridePage {
            title,
            provider_key,
            api_key_key,
            base_url_key,
            show_legacy_fields,
            selected: 0,
            editing: false,
        });
        self.open_llm_override_provider_picker();
        self.status = "Selecting LLM provider profile override".to_string();
    }

    pub(crate) fn open_llm_override_provider_picker(&mut self) {
        let Some(provider_key) = self
            .llm_override_page
            .as_ref()
            .map(|page| page.provider_key.clone())
        else {
            return;
        };
        self.open_llm_override_provider_picker_for_key(&provider_key);
    }

    pub(crate) fn open_llm_override_provider_picker_for_key(&mut self, target_key: &str) {
        let current = self.field_value(target_key);
        let options = self.llm_provider_preset_choices(&current);
        let selected = options
            .iter()
            .position(|(_, value)| value.eq_ignore_ascii_case(&current))
            .unwrap_or(0);
        self.llm_override_picker = Some(LlmOverridePicker {
            title: "Select LLM Provider Profile".to_string(),
            target_key: target_key.to_string(),
            options,
            selected,
        });
    }

    pub(crate) fn apply_llm_override_picker_selection(&mut self) {
        let Some(picker) = self.llm_override_picker.take() else {
            return;
        };
        let Some((_, value)) = picker.options.get(picker.selected) else {
            return;
        };
        let old_value = self.field_value(&picker.target_key);
        self.set_field_value(&picker.target_key, value.clone());
        // Sync related legacy keys so save_config_yaml does not fall back to
        // a stale value.
        if let Some(related_keys) =
            Self::llm_override_related_keys_for_model_field(&picker.target_key)
        {
            for key in &related_keys {
                if key != &picker.target_key {
                    self.set_field_value(key, value.clone());
                }
            }
        }
        // When a channel-level override changes, also update any bot-slot
        // fields that still carry the old (inherited) value so that save does
        // not write the stale override back into the per-account config.
        if picker.target_key == "TELEGRAM_MODEL" {
            for slot in 1..=MAX_BOT_SLOTS {
                let key = telegram_slot_model_key(slot);
                if self.field_value(&key) == old_value {
                    self.set_field_value(&key, value.clone());
                }
            }
        } else if picker.target_key == "DISCORD_MODEL" {
            for slot in 1..=MAX_BOT_SLOTS {
                let key = dynamic_slot_field_key("discord", slot, "model");
                if self.field_value(&key) == old_value {
                    self.set_field_value(&key, value.clone());
                }
            }
        }
        let close_after_select = self
            .llm_override_page
            .as_ref()
            .map(|page| !page.show_legacy_fields)
            .unwrap_or(false);
        if close_after_select {
            self.llm_override_page = None;
        }
        self.status = if value.trim().is_empty() {
            "Selected main (global default)".to_string()
        } else {
            format!("Selected provider profile: {value}")
        };
    }

    pub(crate) fn llm_override_keys_for_page(page: &LlmOverridePage) -> Vec<&str> {
        let mut keys = vec![page.provider_key.as_str()];
        if page.show_legacy_fields {
            keys.push(page.api_key_key.as_str());
            keys.push(page.base_url_key.as_str());
        }
        keys
    }

    pub(crate) fn open_llm_override_page_for_field(&mut self, field_key: &str) -> bool {
        if field_key == "TELEGRAM_MODEL" {
            self.open_llm_override_page(
                "Telegram Channel LLM Override".to_string(),
                "TELEGRAM_MODEL".to_string(),
                telegram_llm_api_key_key().to_string(),
                telegram_llm_base_url_key().to_string(),
            );
            return true;
        }
        if field_key == "DISCORD_MODEL" {
            self.open_llm_override_page(
                "Discord Channel LLM Override".to_string(),
                "DISCORD_MODEL".to_string(),
                discord_llm_api_key_key().to_string(),
                discord_llm_base_url_key().to_string(),
            );
            return true;
        }
        for slot in 1..=MAX_BOT_SLOTS {
            if field_key == telegram_slot_model_key(slot) {
                self.open_llm_override_page(
                    format!("Telegram Bot #{slot} LLM Override"),
                    telegram_slot_model_key(slot),
                    dynamic_slot_llm_api_key_key("telegram", slot),
                    dynamic_slot_llm_base_url_key("telegram", slot),
                );
                return true;
            }
        }
        for ch in DYNAMIC_CHANNELS {
            for slot in 1..=MAX_BOT_SLOTS {
                let model_key = dynamic_slot_field_key(ch.name, slot, "model");
                if field_key == model_key {
                    self.open_llm_override_page(
                        format!("{} bot #{slot} LLM Override", ch.name),
                        model_key.clone(),
                        dynamic_slot_llm_api_key_key(ch.name, slot),
                        dynamic_slot_llm_base_url_key(ch.name, slot),
                    );
                    return true;
                }
            }
        }
        false
    }

    pub(crate) fn llm_provider_key_for_model_field(field_key: &str) -> Option<String> {
        if field_key == "TELEGRAM_MODEL" {
            return Some("TELEGRAM_MODEL".to_string());
        }
        if field_key == "DISCORD_MODEL" {
            return Some("DISCORD_MODEL".to_string());
        }
        for slot in 1..=MAX_BOT_SLOTS {
            if field_key == telegram_slot_model_key(slot) {
                return Some(telegram_slot_model_key(slot));
            }
        }
        for ch in DYNAMIC_CHANNELS {
            for slot in 1..=MAX_BOT_SLOTS {
                if field_key == dynamic_slot_field_key(ch.name, slot, "model") {
                    return Some(dynamic_slot_field_key(ch.name, slot, "model"));
                }
            }
        }
        None
    }

    pub(crate) fn llm_override_related_keys_for_model_field(
        field_key: &str,
    ) -> Option<Vec<String>> {
        if field_key == "TELEGRAM_MODEL" {
            return Some(vec![
                "TELEGRAM_MODEL".to_string(),
                telegram_llm_provider_key().to_string(),
                telegram_llm_api_key_key().to_string(),
                telegram_llm_base_url_key().to_string(),
            ]);
        }
        if field_key == "DISCORD_MODEL" {
            return Some(vec![
                "DISCORD_MODEL".to_string(),
                discord_llm_provider_key().to_string(),
                discord_llm_api_key_key().to_string(),
                discord_llm_base_url_key().to_string(),
            ]);
        }
        for slot in 1..=MAX_BOT_SLOTS {
            if field_key == telegram_slot_model_key(slot) {
                return Some(vec![
                    telegram_slot_model_key(slot),
                    dynamic_slot_llm_provider_key("telegram", slot),
                    dynamic_slot_llm_api_key_key("telegram", slot),
                    dynamic_slot_llm_base_url_key("telegram", slot),
                ]);
            }
        }
        for ch in DYNAMIC_CHANNELS {
            for slot in 1..=MAX_BOT_SLOTS {
                let model_key = dynamic_slot_field_key(ch.name, slot, "model");
                if field_key == model_key {
                    return Some(vec![
                        model_key.clone(),
                        dynamic_slot_llm_provider_key(ch.name, slot),
                        dynamic_slot_llm_api_key_key(ch.name, slot),
                        dynamic_slot_llm_base_url_key(ch.name, slot),
                    ]);
                }
            }
        }
        None
    }
}
