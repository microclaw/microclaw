use async_trait::async_trait;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use microclaw_channels::channel::deliver_and_store_bot_message;
use microclaw_channels::channel_adapter::ChannelRegistry;
use microclaw_core::llm_types::ToolDefinition;
use microclaw_storage::db::Database;
use microclaw_tools::media_client::{persist_output, MediaClient};
use microclaw_tools::runtime::auth_context_from_input;

use super::{schema_object, Tool, ToolResult};
use crate::config::{Config, MediaConfig, PodcastConfig, TtsConfig};

/// Voices accepted per segment — same set the standalone TTS tool exposes.
const ALLOWED_VOICES: &[&str] = &[
    "alloy", "ash", "ballad", "coral", "echo", "fable", "onyx", "nova", "sage", "shimmer", "verse",
];

const MAX_SEGMENTS: usize = 40;

/// Trim and reject blank optional strings (e.g. an explicitly-empty config key).
fn nonempty(s: Option<&str>) -> Option<String> {
    s.map(str::trim).filter(|s| !s.is_empty()).map(str::to_string)
}

/// Native "generate a podcast" tool.
///
/// Takes an ordered list of script segments (each with its own voice),
/// synthesizes every segment via an OpenAI-compatible `/audio/speech`
/// endpoint (reusing `media.tts` model/credentials), then stitches them into
/// a single mp3 — with short silences between segments — by shelling out to
/// `ffmpeg`. The finished episode is saved under the bot's data directory and,
/// when the active channel supports attachments, delivered inline.
///
/// Disabled by default; requires operator opt-in via `media.podcast.enabled`.
pub struct GeneratePodcastTool {
    data_dir: PathBuf,
    channels: Arc<ChannelRegistry>,
    db: Arc<Database>,
    cfg: PodcastConfig,
    tts: TtsConfig,
    media: MediaConfig,
    openai_api_key: Option<String>,
    openai_base_url: Option<String>,
    timeout_secs: u64,
}

impl GeneratePodcastTool {
    pub fn new(config: &Config, channels: Arc<ChannelRegistry>, db: Arc<Database>) -> Self {
        Self {
            data_dir: PathBuf::from(&config.data_dir),
            channels,
            db,
            cfg: config.media.podcast.clone(),
            tts: config.media.tts.clone(),
            media: config.media.clone(),
            openai_api_key: config.openai_api_key.clone(),
            openai_base_url: config.openai_base_url.clone(),
            timeout_secs: config.tool_timeout_secs("generate_podcast", 300),
        }
    }

    fn client(&self) -> Result<MediaClient, String> {
        // Resolution order: podcast-specific override, then the shared TTS
        // override, then the shared media credentials / env / top-level.
        let key = nonempty(self.cfg.api_key.as_deref())
            .or_else(|| nonempty(self.tts.api_key.as_deref()))
            .or_else(|| self.media.resolve_api_key(self.openai_api_key.as_deref()))
            .ok_or_else(|| {
                "generate_podcast requires an API key (media.podcast.api_key, \
                 media.tts.api_key, media.api_key, MICROCLAW_OPENAI_API_KEY, \
                 OPENAI_API_KEY, or top-level openai_api_key)."
                    .to_string()
            })?;
        let base = nonempty(self.cfg.base_url.as_deref())
            .or_else(|| nonempty(self.tts.base_url.as_deref()))
            .map(|s| s.trim_end_matches('/').to_string())
            .unwrap_or_else(|| self.media.resolve_base_url(self.openai_base_url.as_deref()));
        MediaClient::new(base, key, self.timeout_secs)
    }
}

/// One parsed script segment.
struct Segment {
    voice: String,
    text: String,
    pause_ms: u32,
}

#[async_trait]
impl Tool for GeneratePodcastTool {
    fn name(&self) -> &str {
        "generate_podcast"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: self.name().into(),
            description: "Produce a single podcast-episode audio file from a script. \
                Provide an ordered list of `segments`, each with its own `voice` and \
                `text`; every segment is synthesized via text-to-speech and the pieces \
                are concatenated (with short silences) into one mp3 that is saved under \
                the bot's data directory and — when the active channel supports \
                attachments — sent back inline. Use alternating voices for a two-host \
                show. Disabled by default; requires operator opt-in via \
                `media.podcast.enabled` (also needs `media.tts` credentials and an \
                `ffmpeg` binary)."
                .into(),
            input_schema: schema_object(
                json!({
                    "title": {
                        "type": "string",
                        "description": "Episode title (used as the attachment caption)."
                    },
                    "segments": {
                        "type": "array",
                        "description": "Ordered script segments, spoken back-to-back.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "voice": {
                                    "type": "string",
                                    "enum": ALLOWED_VOICES,
                                    "description": "Voice for this segment. Defaults to media.podcast.default_voice."
                                },
                                "text": {
                                    "type": "string",
                                    "description": "What this voice says (max ~4096 chars)."
                                },
                                "pause_ms": {
                                    "type": "integer",
                                    "description": "Silence to add after this segment, in ms. Defaults to media.podcast.segment_pause_ms."
                                }
                            },
                            "required": ["text"]
                        }
                    },
                    "deliver": {
                        "type": "boolean",
                        "description": "Whether to attempt channel delivery (default true)."
                    }
                }),
                &["title", "segments"],
            ),
        }
    }

    async fn execute(&self, input: Value) -> ToolResult {
        if !self.cfg.enabled {
            return ToolResult::error(
                "generate_podcast is disabled. Set media.podcast.enabled=true to enable.".into(),
            );
        }
        if !self.tts.enabled {
            return ToolResult::error(
                "generate_podcast needs text-to-speech. Set media.tts.enabled=true to enable."
                    .into(),
            );
        }

        let title = match input.get("title").and_then(|v| v.as_str()) {
            Some(t) if !t.trim().is_empty() => t.trim().to_string(),
            _ => return ToolResult::error("Missing parameter: title".into()),
        };

        let segments = match parse_segments(&input, &self.cfg) {
            Ok(s) => s,
            Err(e) => return ToolResult::error(e),
        };
        let deliver = input
            .get("deliver")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        // Fail fast with a clear message if ffmpeg is missing, rather than
        // synthesizing all the (paid) audio first and then dying at concat.
        if let Err(e) = ensure_ffmpeg(&self.cfg.ffmpeg_path).await {
            return ToolResult::error(e);
        }

        let client = match self.client() {
            Ok(c) => c,
            Err(e) => return ToolResult::error(e),
        };

        // Scratch directory for the per-segment files + concat list.
        let work = self
            .data_dir
            .join("media")
            .join("tmp")
            .join(uuid::Uuid::new_v4().to_string());
        if let Err(e) = std::fs::create_dir_all(&work) {
            return ToolResult::error(format!("failed to create work dir: {e}"));
        }

        let result = self
            .build_episode(&client, &work, &segments)
            .await;
        // Best-effort cleanup of scratch files regardless of outcome.
        let _ = std::fs::remove_dir_all(&work);

        let saved = match result {
            Ok(p) => p,
            Err(e) => return ToolResult::error(e),
        };

        let mut summary = format!(
            "podcast '{}' ({} segments) -> {}",
            title,
            segments.len(),
            saved.display()
        );
        if deliver {
            if let Some(auth) = auth_context_from_input(&input) {
                match deliver_attachment(
                    &self.channels,
                    self.db.clone(),
                    auth.caller_chat_id,
                    &saved,
                    &title,
                )
                .await
                {
                    Ok(msg) => summary.push_str(&format!("; {msg}")),
                    Err(e) => summary.push_str(&format!("; delivery skipped: {e}")),
                }
            }
        }
        ToolResult::success(summary).with_metadata(json!({
            "path": saved.to_string_lossy(),
            "segments": segments.len(),
            "title": title,
        }))
    }
}

impl GeneratePodcastTool {
    /// Synthesize each segment, render the inter-segment silences, concatenate
    /// everything with ffmpeg, and persist the finished episode.
    async fn build_episode(
        &self,
        client: &MediaClient,
        work: &Path,
        segments: &[Segment],
    ) -> Result<PathBuf, String> {
        let model = self.tts.model.clone();
        // Concat-demuxer list; entries are quoted absolute paths.
        let mut list = String::new();
        // Cache silence clips by duration so we only render each length once.
        let mut silence_paths: std::collections::HashMap<u32, PathBuf> =
            std::collections::HashMap::new();

        for (i, seg) in segments.iter().enumerate() {
            let body = json!({
                "model": model,
                "voice": seg.voice,
                "input": seg.text,
                "response_format": "mp3",
            });
            let resp = client
                .post_json("audio/speech")
                .json(&body)
                .send()
                .await
                .map_err(|e| format!("audio/speech request failed (segment {i}): {e}"))?;
            if !resp.status().is_success() {
                let status = resp.status();
                let txt = resp.text().await.unwrap_or_default();
                return Err(format!("audio/speech HTTP {status} (segment {i}): {txt}"));
            }
            let bytes = resp
                .bytes()
                .await
                .map_err(|e| format!("audio body read failed (segment {i}): {e}"))?;
            let seg_path = work.join(format!("seg_{i:03}.mp3"));
            std::fs::write(&seg_path, &bytes)
                .map_err(|e| format!("failed to write segment {i}: {e}"))?;
            list.push_str(&concat_entry(&seg_path));

            if seg.pause_ms > 0 && i + 1 < segments.len() {
                let silence = match silence_paths.get(&seg.pause_ms) {
                    Some(p) => p.clone(),
                    None => {
                        let p = work.join(format!("silence_{}.mp3", seg.pause_ms));
                        render_silence(&self.cfg.ffmpeg_path, &p, seg.pause_ms).await?;
                        silence_paths.insert(seg.pause_ms, p.clone());
                        p
                    }
                };
                list.push_str(&concat_entry(&silence));
            }
        }

        let list_path = work.join("concat.txt");
        std::fs::write(&list_path, &list).map_err(|e| format!("failed to write concat list: {e}"))?;
        let out_path = work.join("episode.mp3");

        // Re-encode (rather than `-c copy`) so segments + silence with slightly
        // different mp3 framing concatenate cleanly into one continuous file.
        let status = tokio::process::Command::new(&self.cfg.ffmpeg_path)
            .args([
                "-y",
                "-f",
                "concat",
                "-safe",
                "0",
                "-i",
                &list_path.to_string_lossy(),
                "-c:a",
                "libmp3lame",
                "-q:a",
                "4",
                &out_path.to_string_lossy(),
            ])
            .output()
            .await
            .map_err(|e| format!("ffmpeg concat failed to start: {e}"))?;
        if !status.status.success() {
            let err = String::from_utf8_lossy(&status.stderr);
            let tail: String = err.chars().rev().take(500).collect::<String>().chars().rev().collect();
            return Err(format!("ffmpeg concat failed: {tail}"));
        }

        let bytes = std::fs::read(&out_path)
            .map_err(|e| format!("failed to read concatenated episode: {e}"))?;
        persist_output(&self.data_dir, "audio", "mp3", &bytes)
            .map_err(|e| format!("failed to save episode: {e}"))
    }
}

fn parse_segments(input: &Value, cfg: &PodcastConfig) -> Result<Vec<Segment>, String> {
    let arr = input
        .get("segments")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "Missing or invalid parameter: segments (expected an array)".to_string())?;
    if arr.is_empty() {
        return Err("segments must contain at least one entry".into());
    }
    if arr.len() > MAX_SEGMENTS {
        return Err(format!(
            "too many segments ({}); max is {MAX_SEGMENTS}",
            arr.len()
        ));
    }
    let mut out = Vec::with_capacity(arr.len());
    for (i, seg) in arr.iter().enumerate() {
        let text = match seg.get("text").and_then(|v| v.as_str()) {
            Some(t) if !t.trim().is_empty() => t.trim().to_string(),
            _ => return Err(format!("segment {i}: missing or empty 'text'")),
        };
        if text.chars().count() > 4096 {
            return Err(format!(
                "segment {i}: text exceeds 4096 characters — split it into more segments"
            ));
        }
        let voice = seg
            .get("voice")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| cfg.default_voice.clone());
        if !ALLOWED_VOICES.iter().any(|v| v == &voice.as_str()) {
            return Err(format!(
                "segment {i}: invalid voice '{voice}'. Allowed: {}",
                ALLOWED_VOICES.join(", ")
            ));
        }
        let pause_ms = seg
            .get("pause_ms")
            .and_then(|v| v.as_u64())
            .map(|v| v.min(10_000) as u32)
            .unwrap_or(cfg.segment_pause_ms);
        out.push(Segment {
            voice,
            text,
            pause_ms,
        });
    }
    Ok(out)
}

/// A single `file '...'` line for ffmpeg's concat demuxer. Single quotes in the
/// path are escaped per the concat format's `'\''` convention.
fn concat_entry(path: &Path) -> String {
    let p = path.to_string_lossy().replace('\'', "'\\''");
    format!("file '{p}'\n")
}

/// Verify the ffmpeg binary is runnable; return a clear, actionable error if not.
async fn ensure_ffmpeg(ffmpeg_path: &str) -> Result<(), String> {
    match tokio::process::Command::new(ffmpeg_path)
        .arg("-version")
        .output()
        .await
    {
        Ok(o) if o.status.success() => Ok(()),
        Ok(_) => Err(format!(
            "ffmpeg at '{ffmpeg_path}' exited with an error. Install ffmpeg or set media.podcast.ffmpeg_path."
        )),
        Err(_) => Err(format!(
            "ffmpeg not found at '{ffmpeg_path}'. Install ffmpeg or set media.podcast.ffmpeg_path to its location."
        )),
    }
}

/// Render `pause_ms` of silence to `out` as mp3 via ffmpeg's anullsrc.
async fn render_silence(ffmpeg_path: &str, out: &Path, pause_ms: u32) -> Result<(), String> {
    let seconds = format!("{:.3}", pause_ms as f64 / 1000.0);
    let res = tokio::process::Command::new(ffmpeg_path)
        .args([
            "-y",
            "-f",
            "lavfi",
            "-i",
            "anullsrc=r=24000:cl=mono",
            "-t",
            &seconds,
            "-c:a",
            "libmp3lame",
            "-q:a",
            "9",
            &out.to_string_lossy(),
        ])
        .output()
        .await
        .map_err(|e| format!("ffmpeg silence render failed to start: {e}"))?;
    if !res.status.success() {
        let err = String::from_utf8_lossy(&res.stderr);
        let tail: String = err.chars().rev().take(300).collect::<String>().chars().rev().collect();
        return Err(format!("ffmpeg silence render failed: {tail}"));
    }
    Ok(())
}

async fn deliver_attachment(
    channels: &ChannelRegistry,
    db: Arc<Database>,
    chat_id: i64,
    file: &Path,
    caption: &str,
) -> Result<String, String> {
    let routing = microclaw_channels::channel::get_required_chat_routing(
        channels,
        db.clone(),
        chat_id,
    )
    .await?;
    let Some(adapter) = channels.get(&routing.channel_name) else {
        return Err(format!("no adapter for channel '{}'", routing.channel_name));
    };
    if adapter.is_local_only() {
        return Ok(format!(
            "channel '{}' is local-only, path retained at: {}",
            routing.channel_name,
            file.display()
        ));
    }
    let external_chat_id = microclaw_storage::db::call_blocking(db.clone(), move |d| {
        d.get_chat_external_id(chat_id)
    })
    .await
    .map_err(|e| e.to_string())?
    .unwrap_or_else(|| chat_id.to_string());
    let caption_short = caption.chars().take(120).collect::<String>();
    match adapter
        .send_attachment(&external_chat_id, file, Some(&caption_short))
        .await
    {
        Ok(_) => {
            let _ = deliver_and_store_bot_message(
                channels,
                db,
                "bot",
                chat_id,
                &format!("[podcast attached: {}]", file.display()),
            )
            .await;
            Ok(format!("delivered via channel '{}'", routing.channel_name))
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_segments() {
        let cfg = PodcastConfig::default();
        let input = json!({"title": "t", "segments": []});
        assert!(parse_segments(&input, &cfg).is_err());
    }

    #[test]
    fn defaults_voice_and_pause() {
        let cfg = PodcastConfig {
            default_voice: "nova".into(),
            segment_pause_ms: 750,
            ..Default::default()
        };
        let input = json!({"segments": [{"text": "hello"}]});
        let segs = parse_segments(&input, &cfg).unwrap();
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0].voice, "nova");
        assert_eq!(segs[0].pause_ms, 750);
    }

    #[test]
    fn rejects_bad_voice() {
        let cfg = PodcastConfig::default();
        let input = json!({"segments": [{"text": "hi", "voice": "bogus"}]});
        assert!(parse_segments(&input, &cfg).is_err());
    }

    #[test]
    fn nonempty_trims_and_rejects_blank() {
        assert_eq!(nonempty(Some("  k  ")), Some("k".to_string()));
        assert_eq!(nonempty(Some("   ")), None);
        assert_eq!(nonempty(Some("")), None);
        assert_eq!(nonempty(None), None);
    }

    #[test]
    fn concat_entry_escapes_quotes() {
        let p = Path::new("/tmp/a'b.mp3");
        assert_eq!(concat_entry(p), "file '/tmp/a'\\''b.mp3'\n");
    }

    // Live end-to-end test against a real OpenAI-compatible TTS endpoint.
    // #[ignore] — needs an API key + ffmpeg (costs ~a fraction of a cent).
    // Run with: OPENAI_API_KEY=... cargo test --lib live_generate_episode -- --ignored --nocapture
    #[tokio::test]
    #[ignore]
    async fn live_generate_episode() {
        use std::sync::Arc;
        // Standard credential env vars, same ones the tool itself resolves.
        let key = std::env::var("OPENAI_API_KEY")
            .or_else(|_| std::env::var("MICROCLAW_OPENAI_API_KEY"))
            .expect("set OPENAI_API_KEY (or MICROCLAW_OPENAI_API_KEY) to run this live test");

        let work = std::env::temp_dir().join(format!(
            "microclaw_podcast_live_{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&work).unwrap();

        let mut cfg = crate::config::Config::test_defaults();
        cfg.data_dir = work.to_string_lossy().into_owned();
        cfg.media.api_key = Some(key);
        cfg.media.tts.enabled = true;
        cfg.media.tts.model = "tts-1".into();
        cfg.media.podcast.enabled = true;
        if std::path::Path::new("/opt/homebrew/bin/ffmpeg").exists() {
            cfg.media.podcast.ffmpeg_path = "/opt/homebrew/bin/ffmpeg".into();
        }

        let db_dir = work.join("db");
        std::fs::create_dir_all(&db_dir).unwrap();
        let db = Arc::new(Database::new(db_dir.to_str().unwrap()).unwrap());
        let tool = GeneratePodcastTool::new(
            &cfg,
            Arc::new(ChannelRegistry::new()),
            db,
        );

        let input = json!({
            "title": "MicroClaw Live Test",
            "segments": [
                {"voice": "nova", "text": "Welcome to the MicroClaw test podcast."},
                {"voice": "onyx", "text": "This episode verifies text to speech and audio stitching from end to end."}
            ],
            "deliver": false
        });
        let res = tool.execute(input).await;
        assert!(!res.is_error, "tool errored: {}", res.content);

        let path = res
            .metadata
            .as_ref()
            .and_then(|m| m.get("path"))
            .and_then(|v| v.as_str())
            .expect("metadata.path missing");
        let bytes = std::fs::read(path).unwrap();
        assert!(bytes.len() > 5000, "episode too small: {} bytes", bytes.len());
        let is_mp3 =
            bytes.starts_with(b"ID3") || (bytes[0] == 0xFF && (bytes[1] & 0xE0) == 0xE0);
        assert!(
            is_mp3,
            "output is not mp3 (first bytes {:02X} {:02X})",
            bytes[0], bytes[1]
        );
        eprintln!("OK: {} bytes -> {}", bytes.len(), path);
    }
}
