//! UI-independent application service for running MicroClaw Work tasks.
//!
//! This crate owns the foreground worker lifecycle and bridges the shared
//! Agent Engine to versioned runtime events. UI packages consume this port;
//! they do not create Tokio runtimes or call the Agent Engine directly.

use microclaw::config::Config;
use microclaw::headless::{HeadlessRunRequest, HeadlessRuntime};
use microclaw_core::runtime_event::RuntimeEventEnvelope;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;
use std::{fs, io};

static NEXT_RUN_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone)]
pub struct WorkRunRequest {
    pub task: String,
    pub workspace: String,
    pub session: String,
}

#[derive(Debug, Clone)]
pub struct RuntimeConfigSummary {
    pub ready: bool,
    pub provider: String,
    pub model: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelSettings {
    pub provider: String,
    pub model: String,
    pub base_url: String,
    pub has_api_key: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelSettingsDraft {
    pub provider: String,
    pub model: String,
    pub base_url: String,
    /// `None` preserves an existing key. `Some` replaces it.
    pub api_key: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ModelSettingsError {
    #[error("provider is required")]
    MissingProvider,
    #[error("model is required")]
    MissingModel,
    #[error("an API key is required for provider {provider}")]
    MissingApiKey { provider: String },
    #[error("base URL is invalid: {0}")]
    InvalidBaseUrl(String),
    #[error("configuration error: {0}")]
    Config(String),
    #[error("configuration I/O error: {0}")]
    Io(#[from] io::Error),
}

fn load_runtime_config_summary(path: &Path) -> RuntimeConfigSummary {
    match Config::load_from_path_for_headless(path) {
        Ok(config) => RuntimeConfigSummary {
            ready: true,
            provider: config.llm_provider,
            model: config.model,
            detail: path.display().to_string(),
        },
        Err(error) => RuntimeConfigSummary {
            ready: false,
            provider: "Not configured".into(),
            model: "—".into(),
            detail: format!("{error} Open Model Settings to configure Work."),
        },
    }
}

#[derive(Debug)]
pub enum WorkRuntimeMessage {
    Envelope(RuntimeEventEnvelope),
    Completed { run_id: String },
    Failed { run_id: String, message: String },
}

pub struct WorkRunHandle {
    pub messages: Receiver<WorkRuntimeMessage>,
    pub cancellation: WorkRunCancellation,
}

#[derive(Clone)]
pub struct WorkRunCancellation {
    cancel_tx: tokio::sync::mpsc::UnboundedSender<()>,
}

impl WorkRunCancellation {
    pub fn cancel(&self) -> Result<(), &'static str> {
        self.cancel_tx
            .send(())
            .map_err(|_| "The runtime has already exited; the stop request was not sent.")
    }
}

#[derive(Debug, Clone)]
pub struct WorkRuntimeService {
    config_path: PathBuf,
}

impl WorkRuntimeService {
    /// Use an explicitly configured/shared Server config when one is present,
    /// otherwise fall back to Work's platform-local config path.
    pub fn discover(fallback_path: impl Into<PathBuf>) -> Self {
        let config_path = std::env::var_os("MICROCLAW_WORK_CONFIG")
            .map(PathBuf::from)
            .or_else(|| Config::resolve_config_path().ok().flatten())
            .unwrap_or_else(|| fallback_path.into());
        Self { config_path }
    }

    pub fn new(config_path: impl Into<PathBuf>) -> Self {
        Self {
            config_path: config_path.into(),
        }
    }

    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    pub fn config_summary(&self) -> RuntimeConfigSummary {
        load_runtime_config_summary(&self.config_path)
    }

    pub fn model_settings(&self) -> Result<ModelSettings, ModelSettingsError> {
        let config = Config::load_from_path_for_headless(&self.config_path)
            .map_err(|error| ModelSettingsError::Config(error.to_string()))?;
        Ok(ModelSettings {
            provider: config.llm_provider,
            model: config.model,
            base_url: config.llm_base_url.unwrap_or_default(),
            has_api_key: !config.api_key.trim().is_empty(),
        })
    }

    pub fn save_model_settings(
        &self,
        draft: ModelSettingsDraft,
    ) -> Result<ModelSettings, ModelSettingsError> {
        let provider = draft.provider.trim().to_ascii_lowercase();
        if provider.is_empty() {
            return Err(ModelSettingsError::MissingProvider);
        }
        let model = draft.model.trim().to_string();
        if model.is_empty() {
            return Err(ModelSettingsError::MissingModel);
        }
        let base_url = draft.base_url.trim().to_string();
        if !base_url.is_empty() {
            let parsed = url::Url::parse(&base_url)
                .map_err(|_| ModelSettingsError::InvalidBaseUrl(base_url.clone()))?;
            if !matches!(parsed.scheme(), "http" | "https") {
                return Err(ModelSettingsError::InvalidBaseUrl(base_url));
            }
        }

        let existing = Config::load_from_path_for_headless(&self.config_path).ok();
        let api_key = draft
            .api_key
            .map(|key| key.trim().to_string())
            .unwrap_or_else(|| {
                existing
                    .as_ref()
                    .map_or(String::new(), |config| config.api_key.clone())
            });
        if api_key.is_empty() && !provider_allows_keyless(&provider) {
            return Err(ModelSettingsError::MissingApiKey {
                provider: provider.clone(),
            });
        }

        if let Some(mut config) = existing {
            let before = config.clone();
            config.llm_provider = provider;
            config.model = model;
            config.api_key = api_key;
            config.llm_base_url = (!base_url.is_empty()).then_some(base_url);
            microclaw::config_persistence::save_config_delta_preserving_comments(
                &self.config_path,
                &before,
                &config,
            )
            .map_err(|error| ModelSettingsError::Config(error.to_string()))?;
        } else {
            write_new_config(&self.config_path, &provider, &model, &api_key, &base_url)?;
        }
        self.model_settings()
    }

    pub fn start(&self, request: WorkRunRequest) -> WorkRunHandle {
        let (message_tx, message_rx) = mpsc::channel();
        let (cancel_tx, cancel_rx) = tokio::sync::mpsc::unbounded_channel();
        let run_id = next_run_id();
        let thread_name = format!("microclaw-work-{run_id}");
        let worker_run_id = run_id.clone();
        let worker_message_tx = message_tx.clone();
        let spawn_result = std::thread::Builder::new().name(thread_name).spawn({
            let config_path = self.config_path.clone();
            move || {
                run_worker(
                    config_path,
                    request,
                    worker_run_id,
                    worker_message_tx,
                    cancel_rx,
                )
            }
        });
        if let Err(error) = spawn_result {
            let _ = message_tx.send(WorkRuntimeMessage::Failed {
                run_id,
                message: format!("Could not start the runtime worker thread: {error}"),
            });
        }
        WorkRunHandle {
            messages: message_rx,
            cancellation: WorkRunCancellation { cancel_tx },
        }
    }
}

fn run_worker(
    config_path: PathBuf,
    request: WorkRunRequest,
    run_id: String,
    message_tx: Sender<WorkRuntimeMessage>,
    mut cancel_rx: tokio::sync::mpsc::UnboundedReceiver<()>,
) {
    let tokio_runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(error) => {
            send_failure(
                &message_tx,
                &run_id,
                format!("Could not create the Tokio runtime: {error}"),
            );
            return;
        }
    };

    let result = tokio_runtime.block_on(async {
        let mut config = Config::load_from_path_for_headless(&config_path)?;
        config.working_dir = request.workspace;
        let runtime = HeadlessRuntime::load(config).await?;
        let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel();
        let event_message_tx = message_tx.clone();
        let event_forwarder = tokio::spawn(async move {
            while let Some(envelope) = event_rx.recv().await {
                if event_message_tx
                    .send(WorkRuntimeMessage::Envelope(envelope))
                    .is_err()
                {
                    break;
                }
            }
        });

        let session = request.session.clone();
        let run = runtime.run(
            HeadlessRunRequest::work(request.task, Some(request.session), run_id.clone()),
            Some(event_tx),
        );
        tokio::pin!(run);
        let result = tokio::select! {
            result = &mut run => result,
            signal = cancel_rx.recv() => {
                if signal.is_some() {
                    let completed_while_waiting = loop {
                        let aborted = runtime.cancel_session(&session).await?;
                        if aborted > 0 {
                            break None;
                        }
                        tokio::select! {
                            result = &mut run => break Some(result),
                            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
                        }
                    };
                    match completed_while_waiting {
                        Some(result) => result,
                        None => run.await,
                    }
                } else {
                    run.await
                }
            }
        };
        event_forwarder.await?;
        result
    });

    match result {
        Ok(result) => {
            let _ = message_tx.send(WorkRuntimeMessage::Completed {
                run_id: result.run_id,
            });
        }
        Err(error) => send_failure(&message_tx, &run_id, error.to_string()),
    }
}

fn provider_allows_keyless(provider: &str) -> bool {
    matches!(provider, "ollama" | "openai-codex" | "qwen-portal")
}

fn write_new_config(
    path: &Path,
    provider: &str,
    model: &str,
    api_key: &str,
    base_url: &str,
) -> Result<(), ModelSettingsError> {
    #[derive(serde::Serialize)]
    struct MinimalConfig<'a> {
        llm_provider: &'a str,
        api_key: &'a str,
        model: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        llm_base_url: Option<&'a str>,
        web_enabled: bool,
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_yaml::to_string(&MinimalConfig {
        llm_provider: provider,
        api_key,
        model,
        llm_base_url: (!base_url.is_empty()).then_some(base_url),
        web_enabled: false,
    })
    .map_err(|error| ModelSettingsError::Config(error.to_string()))?;
    let temporary = path.with_extension("yaml.tmp");
    fs::write(&temporary, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))?;
    }
    fs::rename(&temporary, path)?;
    Ok(())
}

fn send_failure(message_tx: &Sender<WorkRuntimeMessage>, run_id: &str, message: String) {
    let _ = message_tx.send(WorkRuntimeMessage::Failed {
        run_id: run_id.to_string(),
        message,
    });
}

fn next_run_id() -> String {
    let counter = NEXT_RUN_ID.fetch_add(1, Ordering::Relaxed);
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis());
    format!("work-{millis}-{counter}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_run_ids_are_unique() {
        assert_ne!(next_run_id(), next_run_id());
    }

    #[test]
    fn cancellation_signal_is_runtime_independent() {
        let (cancel_tx, mut cancel_rx) = tokio::sync::mpsc::unbounded_channel();
        let cancellation = WorkRunCancellation { cancel_tx };

        cancellation.cancel().unwrap();
        assert_eq!(cancel_rx.try_recv(), Ok(()));
    }

    #[test]
    fn creates_and_loads_minimal_work_configuration() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("microclaw.config.yaml");
        let service = WorkRuntimeService::new(&path);

        let saved = service
            .save_model_settings(ModelSettingsDraft {
                provider: " openai ".into(),
                model: " gpt-5 ".into(),
                base_url: "https://api.openai.com/v1".into(),
                api_key: Some("secret-key".into()),
            })
            .unwrap();

        assert_eq!(saved.provider, "openai");
        assert_eq!(saved.model, "gpt-5");
        assert!(saved.has_api_key);
        assert!(service.config_summary().ready);
        let raw = fs::read_to_string(path).unwrap();
        assert!(raw.contains("web_enabled: false"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(service.config_path())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn preserves_existing_key_and_comments_when_updating_model() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("microclaw.config.yaml");
        fs::write(
            &path,
            "# keep this comment\nllm_provider: openai\napi_key: existing-secret\nmodel: gpt-5\nweb_enabled: false\n",
        )
        .unwrap();
        let service = WorkRuntimeService::new(&path);

        service
            .save_model_settings(ModelSettingsDraft {
                provider: "openai".into(),
                model: "gpt-5-mini".into(),
                base_url: "".into(),
                api_key: None,
            })
            .unwrap();

        let raw = fs::read_to_string(path).unwrap();
        assert!(raw.contains("# keep this comment"));
        assert!(raw.contains("existing-secret"));
        assert!(raw.contains("gpt-5-mini"));
    }

    #[test]
    fn validates_required_credentials_and_base_url() {
        let directory = tempfile::tempdir().unwrap();
        let service = WorkRuntimeService::new(directory.path().join("config.yaml"));
        let error = service
            .save_model_settings(ModelSettingsDraft {
                provider: "anthropic".into(),
                model: "claude-sonnet-4-5-20250929".into(),
                base_url: "file:///tmp/provider".into(),
                api_key: Some("key".into()),
            })
            .unwrap_err();
        assert!(matches!(error, ModelSettingsError::InvalidBaseUrl(_)));

        let error = service
            .save_model_settings(ModelSettingsDraft {
                provider: "anthropic".into(),
                model: "claude-sonnet-4-5-20250929".into(),
                base_url: "".into(),
                api_key: Some(String::new()),
            })
            .unwrap_err();
        assert!(matches!(error, ModelSettingsError::MissingApiKey { .. }));
    }
}
