use super::*;

pub(crate) const MODEL_PICKER_MANUAL_INPUT: &str = "<Manual input...>";

pub(crate) const SOUL_PICKER_CLEAR: &str = "<None>";

pub(crate) const SOUL_PICKER_MANUAL_INPUT: &str = "<Manual input...>";

pub(crate) const TIMEZONE_PICKER_SYSTEM_DEFAULT: &str = "<Use system timezone (default)>";

pub(crate) const TIMEZONE_PICKER_MANUAL_INPUT: &str = "<Custom timezone (type IANA)...>";

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PickerKind {
    Provider,
    Model,
    Channels,
    SoulPath,
    Timezone,
}

#[derive(Clone)]
pub(crate) struct PickerState {
    pub(crate) kind: PickerKind,
    pub(crate) selected: usize,
    pub(crate) selected_multi: Vec<bool>,
}

impl SetupApp {
    pub(crate) fn set_provider(&mut self, provider: &str) {
        let old_provider = self.field_value("LLM_PROVIDER");
        let old_base_url = self.field_value("LLM_BASE_URL");
        let old_model = self.field_value("LLM_MODEL");

        if let Some(field) = self.fields.iter_mut().find(|f| f.key == "LLM_PROVIDER") {
            field.value = provider.to_string();
        }
        if let Some(base) = self.fields.iter_mut().find(|f| f.key == "LLM_BASE_URL") {
            let next_default = find_provider_preset(provider)
                .map(|p| p.default_base_url)
                .unwrap_or("");
            let old_default = find_provider_preset(&old_provider)
                .map(|p| p.default_base_url)
                .unwrap_or("");
            if old_base_url.trim().is_empty() || old_base_url == old_default {
                base.value = next_default.to_string();
            }
        }
        if let Some(model) = self.fields.iter_mut().find(|f| f.key == "LLM_MODEL") {
            let old_in_old_preset = find_provider_preset(&old_provider)
                .map(|p| p.models.iter().any(|m| *m == old_model))
                .unwrap_or(false);
            if old_model.trim().is_empty() || old_in_old_preset {
                model.value = default_model_for_provider(provider).to_string();
            }
        }
    }

    pub(crate) fn cycle_provider(&mut self, direction: i32) {
        let current = self.field_value("LLM_PROVIDER");
        let current_idx = PROVIDER_PRESETS
            .iter()
            .position(|p| p.id.eq_ignore_ascii_case(&current))
            .unwrap_or(PROVIDER_PRESETS.len() - 1);
        let next_idx = if direction < 0 {
            if current_idx == 0 {
                PROVIDER_PRESETS.len() - 1
            } else {
                current_idx - 1
            }
        } else {
            (current_idx + 1) % PROVIDER_PRESETS.len()
        };
        self.set_provider(PROVIDER_PRESETS[next_idx].id);
    }

    pub(crate) fn cycle_model(&mut self, direction: i32) {
        let provider = self.field_value("LLM_PROVIDER");
        let preset = match find_provider_preset(&provider) {
            Some(p) => p,
            None => return,
        };
        if preset.models.is_empty() {
            return;
        }
        let current = self.field_value("LLM_MODEL");
        let current_idx = preset
            .models
            .iter()
            .position(|m| *m == current)
            .unwrap_or(0);
        let next_idx = if direction < 0 {
            if current_idx == 0 {
                preset.models.len() - 1
            } else {
                current_idx - 1
            }
        } else {
            (current_idx + 1) % preset.models.len()
        };
        if let Some(model) = self.fields.iter_mut().find(|f| f.key == "LLM_MODEL") {
            model.value = preset.models[next_idx].to_string();
        }
    }

    pub(crate) fn provider_index(&self, provider: &str) -> usize {
        PROVIDER_PRESETS
            .iter()
            .position(|p| p.id.eq_ignore_ascii_case(provider))
            .unwrap_or(PROVIDER_PRESETS.len().saturating_sub(1))
    }

    pub(crate) fn model_options(&self) -> Vec<String> {
        let provider = self.field_value("LLM_PROVIDER");
        if let Some(preset) = find_provider_preset(&provider) {
            preset.models.iter().map(|m| (*m).to_string()).collect()
        } else {
            vec![self.field_value("LLM_MODEL")]
        }
    }

    pub(crate) fn model_picker_options(&self) -> Vec<String> {
        let mut options = self.model_options();
        options.push(MODEL_PICKER_MANUAL_INPUT.to_string());
        options
    }

    pub(crate) fn is_soul_field_key(key: &str) -> bool {
        if key.starts_with("TELEGRAM_BOT") && key.ends_with("_SOUL_PATH") {
            return true;
        }
        key.starts_with("DYN_") && key.ends_with("_SOUL_PATH")
    }

    pub(crate) fn soul_picker_options(&self) -> Vec<String> {
        let mut options = vec![
            SOUL_PICKER_CLEAR.to_string(),
            SOUL_PICKER_MANUAL_INPUT.to_string(),
        ];
        let data_dir = self.field_value("DATA_DIR");
        let souls_dir = self.souls_dir_value();
        options.extend(soul_picker_file_names(Some(&data_dir), Some(&souls_dir)));
        options
    }

    pub(crate) fn timezone_picker_options(&self) -> Vec<String> {
        vec![
            TIMEZONE_PICKER_SYSTEM_DEFAULT.to_string(),
            "UTC".to_string(),
            "America/Los_Angeles".to_string(),
            "America/New_York".to_string(),
            "America/Chicago".to_string(),
            "America/Denver".to_string(),
            "America/Phoenix".to_string(),
            "America/Toronto".to_string(),
            "America/Vancouver".to_string(),
            "America/Sao_Paulo".to_string(),
            "Europe/London".to_string(),
            "Europe/Berlin".to_string(),
            "Europe/Paris".to_string(),
            "Europe/Madrid".to_string(),
            "Europe/Rome".to_string(),
            "Europe/Amsterdam".to_string(),
            "Europe/Moscow".to_string(),
            "Asia/Shanghai".to_string(),
            "Asia/Tokyo".to_string(),
            "Asia/Singapore".to_string(),
            "Asia/Kolkata".to_string(),
            "Asia/Hong_Kong".to_string(),
            "Asia/Seoul".to_string(),
            "Asia/Dubai".to_string(),
            "Asia/Bangkok".to_string(),
            "Asia/Jakarta".to_string(),
            "Australia/Sydney".to_string(),
            "Australia/Melbourne".to_string(),
            "Pacific/Auckland".to_string(),
            "Africa/Johannesburg".to_string(),
            TIMEZONE_PICKER_MANUAL_INPUT.to_string(),
        ]
    }

    pub(crate) fn open_picker_for_selected(&mut self) -> bool {
        let selected_key = self.selected_field().key.clone();
        if Self::is_soul_field_key(&selected_key) {
            let options = self.soul_picker_options();
            let current = self.field_value(&selected_key);
            let current_name = Path::new(current.trim())
                .file_name()
                .and_then(|v| v.to_str())
                .unwrap_or("");
            let idx = if current.trim().is_empty() {
                0
            } else {
                options.iter().position(|v| v == current_name).unwrap_or(1)
            };
            self.picker = Some(PickerState {
                kind: PickerKind::SoulPath,
                selected: idx,
                selected_multi: Vec::new(),
            });
            return true;
        }
        match selected_key.as_str() {
            "LLM_PROVIDER" => {
                let idx = self.provider_index(&self.field_value("LLM_PROVIDER"));
                self.picker = Some(PickerState {
                    kind: PickerKind::Provider,
                    selected: idx,
                    selected_multi: Vec::new(),
                });
                true
            }
            "LLM_MODEL" => {
                let provider = self.field_value("LLM_PROVIDER");
                if provider.eq_ignore_ascii_case("custom") {
                    return false;
                }
                let options = self.model_picker_options();
                if options.is_empty() {
                    return false;
                }
                let current_model = self.field_value("LLM_MODEL");
                let idx = options
                    .iter()
                    .position(|m| *m == current_model)
                    .unwrap_or(options.len().saturating_sub(1));
                self.picker = Some(PickerState {
                    kind: PickerKind::Model,
                    selected: idx,
                    selected_multi: Vec::new(),
                });
                true
            }
            "ENABLED_CHANNELS" => {
                let selected_channels = self.enabled_channels();
                let mut selected_multi = Vec::new();
                for channel in Self::channel_options() {
                    selected_multi.push(selected_channels.iter().any(|c| c == channel));
                }
                self.picker = Some(PickerState {
                    kind: PickerKind::Channels,
                    selected: 0,
                    selected_multi,
                });
                true
            }
            _ if selected_key == llm_provider_profiles_key() => {
                self.open_provider_preset_page();
                true
            }
            "OVERRIDE_TIMEZONE" => {
                let options = self.timezone_picker_options();
                let current = {
                    let tz = self.field_value("OVERRIDE_TIMEZONE");
                    if tz.trim().is_empty() {
                        TIMEZONE_PICKER_SYSTEM_DEFAULT.to_string()
                    } else {
                        tz
                    }
                };
                let idx = options
                    .iter()
                    .position(|tz| tz.eq_ignore_ascii_case(&current))
                    .unwrap_or(options.len().saturating_sub(1));
                self.picker = Some(PickerState {
                    kind: PickerKind::Timezone,
                    selected: idx,
                    selected_multi: Vec::new(),
                });
                true
            }
            _ => false,
        }
    }

    pub(crate) fn move_picker(&mut self, direction: i32) {
        let Some(picker) = self.picker.as_ref() else {
            return;
        };
        let kind = picker.kind;
        let selected = picker.selected;
        let options_len = match kind {
            PickerKind::Provider => PROVIDER_PRESETS.len(),
            PickerKind::Model => self.model_picker_options().len(),
            PickerKind::Channels => Self::channel_options().len(),
            PickerKind::SoulPath => self.soul_picker_options().len(),
            PickerKind::Timezone => self.timezone_picker_options().len(),
        };
        if options_len == 0 {
            return;
        }
        let next = if direction < 0 {
            if selected == 0 {
                options_len - 1
            } else {
                selected - 1
            }
        } else {
            (selected + 1) % options_len
        };
        if let Some(picker_mut) = self.picker.as_mut() {
            picker_mut.selected = next;
        }
    }

    pub(crate) fn toggle_picker_multi(&mut self) {
        let Some(picker) = self.picker.as_mut() else {
            return;
        };
        if picker.kind != PickerKind::Channels {
            return;
        }
        if let Some(slot) = picker.selected_multi.get_mut(picker.selected) {
            *slot = !*slot;
        }
    }

    pub(crate) fn apply_picker_selection(&mut self) {
        let Some(picker) = self.picker.take() else {
            return;
        };
        match picker.kind {
            PickerKind::Provider => {
                if let Some(preset) = PROVIDER_PRESETS.get(picker.selected) {
                    self.set_provider(preset.id);
                    self.status = format!("Provider set to {}", preset.id);
                }
            }
            PickerKind::Model => {
                let options = self.model_picker_options();
                if let Some(chosen) = options.get(picker.selected) {
                    if chosen == MODEL_PICKER_MANUAL_INPUT {
                        self.editing = true;
                        self.status = "Editing LLM_MODEL (manual input)".to_string();
                    } else if let Some(model) =
                        self.fields.iter_mut().find(|f| f.key == "LLM_MODEL")
                    {
                        model.value = chosen.clone();
                        self.status = format!("Model set to {chosen}");
                    }
                }
            }
            PickerKind::Channels => {
                let mut enabled = Vec::new();
                for (idx, channel) in Self::channel_options().iter().enumerate() {
                    if picker.selected_multi.get(idx).copied().unwrap_or(false) {
                        enabled.push((*channel).to_string());
                    }
                }
                if let Some(field) = self.fields.iter_mut().find(|f| f.key == "ENABLED_CHANNELS") {
                    field.value = enabled.join(",");
                }
                if enabled.is_empty() {
                    self.status = "Channels set to setup later (web-only by default)".to_string();
                } else {
                    self.status = format!("Channels set to {}", enabled.join(","));
                }
            }
            PickerKind::SoulPath => {
                let options = self.soul_picker_options();
                let selected_key = self.selected_field().key.clone();
                let souls_dir = self.souls_dir_value();
                if let Some(chosen) = options.get(picker.selected) {
                    if chosen == SOUL_PICKER_MANUAL_INPUT {
                        self.editing = true;
                        self.status = format!("Editing {} (manual input)", selected_key);
                    } else if let Some(field) =
                        self.fields.iter_mut().find(|f| f.key == selected_key)
                    {
                        if chosen == SOUL_PICKER_CLEAR {
                            field.value.clear();
                            self.status = format!("Cleared {}", field.key);
                        } else {
                            let normalized = normalize_soul_path_input(chosen, &souls_dir);
                            field.value = normalized;
                            self.status = format!("{} set to {}", field.key, field.value);
                        }
                    }
                }
            }
            PickerKind::Timezone => {
                let options = self.timezone_picker_options();
                if let Some(chosen) = options.get(picker.selected) {
                    if chosen == TIMEZONE_PICKER_MANUAL_INPUT {
                        self.editing = true;
                        self.status = "Editing OVERRIDE_TIMEZONE (manual input)".to_string();
                    } else if let Some(field) = self
                        .fields
                        .iter_mut()
                        .find(|f| f.key == "OVERRIDE_TIMEZONE")
                    {
                        if chosen == TIMEZONE_PICKER_SYSTEM_DEFAULT {
                            field.value.clear();
                            self.status =
                                "Timezone override cleared (using system timezone)".to_string();
                        } else {
                            field.value = chosen.clone();
                            self.status = format!("Override timezone set to {chosen}");
                        }
                    }
                }
            }
        }
        self.ensure_selected_visible();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use crate::setup::test_prelude::*;

    #[test]
    fn test_model_picker_options_include_manual_input() {
        let app = SetupApp::new();
        let options = app.model_picker_options();
        assert_eq!(
            options.last().map(String::as_str),
            Some(MODEL_PICKER_MANUAL_INPUT)
        );
    }

    #[test]
    fn test_model_picker_manual_input_enters_edit_mode() {
        let mut app = SetupApp::new();
        app.set_provider("openai");
        let model_idx = app
            .fields
            .iter()
            .position(|f| f.key == "LLM_MODEL")
            .expect("LLM_MODEL field missing");
        app.selected = model_idx;
        assert!(app.open_picker_for_selected());
        let manual_idx = app.model_picker_options().len().saturating_sub(1);
        if let Some(picker) = app.picker.as_mut() {
            picker.selected = manual_idx;
        }
        app.apply_picker_selection();
        assert!(app.editing);
        assert!(app.status.contains("manual input"));
    }

    #[test]
    fn test_timezone_picker_options_include_system_default_and_manual_input() {
        let app = SetupApp::new();
        let options = app.timezone_picker_options();
        assert_eq!(
            options.first().map(String::as_str),
            Some(TIMEZONE_PICKER_SYSTEM_DEFAULT)
        );
        assert_eq!(
            options.last().map(String::as_str),
            Some(TIMEZONE_PICKER_MANUAL_INPUT)
        );
    }

    #[test]
    fn test_timezone_picker_manual_input_enters_edit_mode() {
        let mut app = SetupApp::new();
        let timezone_idx = app
            .fields
            .iter()
            .position(|f| f.key == "OVERRIDE_TIMEZONE")
            .expect("OVERRIDE_TIMEZONE field missing");
        app.selected = timezone_idx;
        assert!(app.open_picker_for_selected());
        let manual_idx = app.timezone_picker_options().len().saturating_sub(1);
        if let Some(picker) = app.picker.as_mut() {
            picker.selected = manual_idx;
        }
        app.apply_picker_selection();
        assert!(app.editing);
        assert!(app.status.contains("manual input"));
    }
}
