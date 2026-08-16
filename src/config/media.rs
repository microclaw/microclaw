use super::*;

/// Configuration for multimedia tools (image generation, vision, TTS, STT).
///
/// All four tools are **disabled by default** — operators opt in per-tool.
/// Credential resolution order for each tool (first non-empty wins):
/// 1. `media.api_key` (plaintext in config; discouraged but supported)
/// 2. Environment variable `MICROCLAW_OPENAI_API_KEY`
/// 3. Environment variable `OPENAI_API_KEY`
/// 4. `config.openai_api_key` (existing top-level field; used by transcribe)
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct MediaConfig {
    /// Optional explicit API key. Prefer env vars (`MICROCLAW_OPENAI_API_KEY`
    /// or `OPENAI_API_KEY`) over plaintext here.
    #[serde(default)]
    pub api_key: Option<String>,
    /// Optional per-module base URL override. Falls back to `openai_base_url`
    /// then to `https://api.openai.com/v1`.
    #[serde(default)]
    pub base_url: Option<String>,
    /// Extra directories that `describe_image` / `transcribe_audio` may read
    /// from, beyond the working_dir default. Absolute paths only. Empty by
    /// default — matches the previous working-dir-only behavior.
    #[serde(default)]
    pub allowed_read_dirs: Vec<String>,
    #[serde(default)]
    pub image_gen: ImageGenConfig,
    #[serde(default)]
    pub vision: VisionConfig,
    #[serde(default)]
    pub tts: TtsConfig,
    #[serde(default)]
    pub stt: SttConfig,
    #[serde(default)]
    pub book: BookConfig,
    #[serde(default)]
    pub podcast: PodcastConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImageGenConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_image_model")]
    pub model: String,
    #[serde(default = "default_image_size")]
    pub default_size: String,
}

impl Default for ImageGenConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            model: default_image_model(),
            default_size: default_image_size(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VisionConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_vision_model")]
    pub model: String,
    #[serde(default = "default_vision_max_tokens")]
    pub max_tokens: u32,
}

impl Default for VisionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            model: default_vision_model(),
            max_tokens: default_vision_max_tokens(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TtsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_tts_model")]
    pub model: String,
    #[serde(default = "default_tts_voice")]
    pub default_voice: String,
    #[serde(default = "default_tts_format")]
    pub default_format: String,
    /// Optional TTS-specific endpoint override, e.g. a dedicated speech host.
    /// Falls back to `media.base_url`, then `openai_base_url`, then OpenAI.
    #[serde(default)]
    pub base_url: Option<String>,
    /// Optional TTS-specific API key. Falls back to `media.api_key`, then
    /// `MICROCLAW_OPENAI_API_KEY` / `OPENAI_API_KEY` / `openai_api_key`.
    #[serde(default)]
    pub api_key: Option<String>,
}

impl Default for TtsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            model: default_tts_model(),
            default_voice: default_tts_voice(),
            default_format: default_tts_format(),
            base_url: None,
            api_key: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SttConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_stt_model")]
    pub model: String,
    #[serde(default)]
    pub language: Option<String>,
}

impl Default for SttConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            model: default_stt_model(),
            language: None,
        }
    }
}

/// Configuration for the native `render_pdf` ("generate a book") tool.
///
/// Disabled by default — operators opt in via `media.book.enabled`. PDF
/// rendering is fully self-contained (pure-Rust `genpdf`), so no external
/// binaries are required.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BookConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Page size for rendered documents. Currently "A4" or "Letter".
    #[serde(default = "default_book_page_size")]
    pub page_size: String,
    /// Path to a single-face TrueType (`.ttf`) font used to render text.
    /// When unset, a usable system font is auto-detected (e.g. Arial Unicode
    /// on macOS, DejaVu/Liberation on Linux). For CJK output, point this at a
    /// CJK-capable TrueType font.
    #[serde(default)]
    pub font_path: Option<String>,
}

impl Default for BookConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            page_size: default_book_page_size(),
            font_path: None,
        }
    }
}

/// Configuration for the native `generate_podcast` tool.
///
/// Disabled by default — operators opt in via `media.podcast.enabled`.
/// Per-segment speech uses the OpenAI-compatible `/audio/speech` endpoint with
/// the `media.tts` model; credentials/endpoint default to `media.tts` then the
/// shared `media` settings, but can be overridden here. Segments are stitched
/// into a single file by shelling out to `ffmpeg`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PodcastConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Path to (or name of) the `ffmpeg` binary used to concatenate segments.
    #[serde(default = "default_ffmpeg_path")]
    pub ffmpeg_path: String,
    /// Default voice when a segment does not specify one.
    #[serde(default = "default_tts_voice")]
    pub default_voice: String,
    /// Silence inserted between segments, in milliseconds.
    #[serde(default = "default_segment_pause_ms")]
    pub segment_pause_ms: u32,
    /// Optional podcast-specific endpoint override. Falls back to
    /// `media.tts.base_url`, then `media.base_url`, then `openai_base_url`.
    #[serde(default)]
    pub base_url: Option<String>,
    /// Optional podcast-specific API key. Falls back to `media.tts.api_key`,
    /// then `media.api_key` / `MICROCLAW_OPENAI_API_KEY` / `OPENAI_API_KEY`.
    #[serde(default)]
    pub api_key: Option<String>,
}

impl Default for PodcastConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ffmpeg_path: default_ffmpeg_path(),
            default_voice: default_tts_voice(),
            segment_pause_ms: default_segment_pause_ms(),
            base_url: None,
            api_key: None,
        }
    }
}

pub(crate) fn default_image_model() -> String {
    "gpt-image-1".into()
}

pub(crate) fn default_image_size() -> String {
    "1024x1024".into()
}

pub(crate) fn default_vision_model() -> String {
    "gpt-4o-mini".into()
}

pub(crate) fn default_vision_max_tokens() -> u32 {
    1024
}

pub(crate) fn default_tts_model() -> String {
    "tts-1".into()
}

pub(crate) fn default_tts_voice() -> String {
    "alloy".into()
}

pub(crate) fn default_tts_format() -> String {
    "mp3".into()
}

pub(crate) fn default_stt_model() -> String {
    "whisper-1".into()
}

pub(crate) fn default_book_page_size() -> String {
    "A4".into()
}

pub(crate) fn default_ffmpeg_path() -> String {
    "ffmpeg".into()
}

pub(crate) fn default_segment_pause_ms() -> u32 {
    500
}

impl MediaConfig {
    /// Resolve the API key using the documented priority order. Returns
    /// `None` if no source is configured. Never logs the value.
    pub fn resolve_api_key(&self, fallback_openai_key: Option<&str>) -> Option<String> {
        if let Some(k) = self.api_key.as_deref().filter(|s| !s.trim().is_empty()) {
            return Some(k.to_string());
        }
        if let Ok(k) = std::env::var("MICROCLAW_OPENAI_API_KEY") {
            if !k.trim().is_empty() {
                return Some(k);
            }
        }
        if let Ok(k) = std::env::var("OPENAI_API_KEY") {
            if !k.trim().is_empty() {
                return Some(k);
            }
        }
        fallback_openai_key
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.to_string())
    }

    /// Resolve the base URL using the documented priority order. Always
    /// returns a non-empty value (defaults to OpenAI).
    pub fn resolve_base_url(&self, fallback: Option<&str>) -> String {
        if let Some(u) = self.base_url.as_deref().filter(|s| !s.trim().is_empty()) {
            return u.trim_end_matches('/').to_string();
        }
        if let Some(u) = fallback.filter(|s| !s.trim().is_empty()) {
            return u.trim_end_matches('/').to_string();
        }
        "https://api.openai.com/v1".to_string()
    }
}
