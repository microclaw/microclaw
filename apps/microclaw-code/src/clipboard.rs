//! Clipboard images (Ctrl+V): read a PNG from the system clipboard with
//! the platform's own tools and save it under `~/.mccode/attachments`.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Save the clipboard image; `Ok(None)` when the clipboard holds no image.
pub fn save_image(_project_root: &Path) -> anyhow::Result<Option<PathBuf>> {
    let Some(png) = read_png()? else {
        return Ok(None);
    };
    let dir = microclaw_code_core::home::code_home().join("attachments");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!(
        "clip-{}.png",
        chrono::Local::now().format("%Y%m%d-%H%M%S")
    ));
    std::fs::write(&path, png)?;
    Ok(Some(path))
}

fn is_png(bytes: &[u8]) -> bool {
    bytes.starts_with(&[0x89, b'P', b'N', b'G'])
}

#[cfg(target_os = "macos")]
fn read_png() -> anyhow::Result<Option<Vec<u8>>> {
    // `«class PNGf»` is returned as `«data PNGf89504E47…»`.
    let out = Command::new("osascript")
        .args(["-e", "the clipboard as «class PNGf»"])
        .output()?;
    if !out.status.success() {
        return Ok(None);
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let Some(hex) = text
        .trim()
        .strip_prefix("«data PNGf")
        .and_then(|s| s.strip_suffix('»'))
    else {
        return Ok(None);
    };
    let bytes: Option<Vec<u8>> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok())
        .collect();
    Ok(bytes.filter(|b| is_png(b)))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn read_png() -> anyhow::Result<Option<Vec<u8>>> {
    let attempts: [(&str, &[&str]); 2] = [
        ("wl-paste", &["--no-newline", "--type", "image/png"]),
        (
            "xclip",
            &["-selection", "clipboard", "-t", "image/png", "-o"],
        ),
    ];
    let mut tried = Vec::new();
    for (program, args) in attempts {
        match Command::new(program).args(args).output() {
            Ok(out) if out.status.success() && is_png(&out.stdout) => return Ok(Some(out.stdout)),
            Ok(_) => return Ok(None),
            Err(_) => tried.push(program),
        }
    }
    anyhow::bail!("install wl-clipboard (Wayland) or xclip (X11) to paste images")
}

#[cfg(windows)]
fn read_png() -> anyhow::Result<Option<Vec<u8>>> {
    let tmp = std::env::temp_dir().join(format!("mccode-clip-{}.png", std::process::id()));
    let script = format!(
        "Add-Type -AssemblyName System.Windows.Forms; $i=[Windows.Forms.Clipboard]::GetImage(); if ($i) {{ $i.Save('{}', [System.Drawing.Imaging.ImageFormat]::Png) }}",
        tmp.display()
    );
    let _ = Command::new("powershell")
        .args(["-NoProfile", "-STA", "-Command", &script])
        .output()?;
    match std::fs::read(&tmp) {
        Ok(bytes) => {
            let _ = std::fs::remove_file(&tmp);
            Ok(Some(bytes).filter(|b| is_png(b)))
        }
        Err(_) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn recognizes_png_magic() {
        assert!(super::is_png(&[0x89, b'P', b'N', b'G', 0x0d]));
        assert!(!super::is_png(b"GIF89a"));
    }
}
