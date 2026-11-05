//! Images mentioned in a prompt (`@screenshot.png`), sent to the model.

use std::path::{Path, PathBuf};

use base64::Engine;

/// Largest image file attached (bytes).
pub const MAX_IMAGE_BYTES: u64 = 5 * 1024 * 1024;

/// An image attached to a prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptImage {
    pub path: PathBuf,
    pub media_type: &'static str,
    pub base64: String,
}

pub fn media_type(path: &Path) -> Option<&'static str> {
    match path.extension()?.to_str()?.to_ascii_lowercase().as_str() {
        "png" => Some("image/png"),
        "jpg" | "jpeg" => Some("image/jpeg"),
        "gif" => Some("image/gif"),
        "webp" => Some("image/webp"),
        _ => None,
    }
}

fn resolve(root: &Path, mention: &str) -> PathBuf {
    let mention = mention.trim_matches(|c| c == '"' || c == '\'');
    if let Some(rest) = mention.strip_prefix("~/")
        && let Some(home) = dirs::home_dir()
    {
        return home.join(rest);
    }
    let path = Path::new(mention);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

/// The first `@path` in `prompt` that names an existing image file (relative
/// to `root`, absolute, or `~/…`). Errors describe an image that cannot be
/// attached (too large, unreadable).
pub fn first_image(root: &Path, prompt: &str) -> Result<Option<PromptImage>, String> {
    for token in prompt.split_whitespace() {
        let Some(mention) = token.strip_prefix('@') else {
            continue;
        };
        let mention = mention.trim_end_matches([',', '.', ';', ':', ')']);
        let path = resolve(root, mention);
        let Some(media_type) = media_type(&path) else {
            continue;
        };
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        if meta.len() > MAX_IMAGE_BYTES {
            return Err(format!(
                "{} is larger than {} MB; not attached",
                path.display(),
                MAX_IMAGE_BYTES / 1024 / 1024
            ));
        }
        let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        return Ok(Some(PromptImage {
            path,
            media_type,
            base64: base64::engine::general_purpose::STANDARD.encode(bytes),
        }));
    }
    Ok(None)
}

/// Save a base64 image (for example from an editor) under `dir` and return
/// its path, so it can be mentioned as `@path`.
pub fn save_base64(dir: &Path, media_type: &str, data: &str) -> Result<PathBuf, String> {
    let ext = match media_type {
        "image/png" => "png",
        "image/jpeg" => "jpg",
        "image/gif" => "gif",
        "image/webp" => "webp",
        other => return Err(format!("unsupported image type {other}")),
    };
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(data.trim())
        .map_err(|e| format!("invalid image data: {e}"))?;
    if bytes.len() as u64 > MAX_IMAGE_BYTES {
        return Err("image is larger than 5 MB".into());
    }
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = dir.join(format!("image-{stamp}.{ext}"));
    std::fs::write(&path, bytes).map_err(|e| e.to_string())?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_first_existing_image_mention() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("shot.png"), [137u8, 80, 78, 71]).unwrap();
        std::fs::write(dir.path().join("notes.txt"), "x").unwrap();
        let image = first_image(
            dir.path(),
            "see @notes.txt and @missing.png then @shot.png, please",
        )
        .unwrap()
        .unwrap();
        assert_eq!(image.media_type, "image/png");
        assert_eq!(image.base64, "iVBORw==");
        assert!(first_image(dir.path(), "no images here").unwrap().is_none());
    }

    #[test]
    fn saved_images_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = save_base64(dir.path(), "image/png", "iVBORw==").unwrap();
        let mention = format!("look @{}", path.display());
        let image = first_image(dir.path(), &mention).unwrap().unwrap();
        assert_eq!(image.base64, "iVBORw==");
        assert!(save_base64(dir.path(), "image/bmp", "AA==").is_err());
    }

    #[test]
    fn rejects_oversized_images() {
        let dir = tempfile::tempdir().unwrap();
        let file = std::fs::File::create(dir.path().join("big.jpg")).unwrap();
        file.set_len(MAX_IMAGE_BYTES + 1).unwrap();
        assert!(first_image(dir.path(), "@big.jpg").is_err());
    }
}
