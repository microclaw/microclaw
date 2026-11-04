//! `mccode update`: replace this binary with the latest GitHub release.
//!
//! Releases ship `mccode` as its own `mccode-<version>-<target>` archive.
//! The archive is checked against the release's `SHA256SUMS.txt` before it is
//! unpacked (with the system `tar`, which also reads zip files on Windows),
//! and the running executable is swapped atomically (the old one is kept as
//! `mccode.old` until the next update). Homebrew installs are left to
//! `brew upgrade`.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

const REPO: &str = "microclaw/microclaw";

/// `(major, minor, patch, is_prerelease)` of a version or tag.
fn parse_version(raw: &str) -> Option<(u64, u64, u64, bool)> {
    let raw = raw.trim().trim_start_matches('v');
    let (core, pre) = match raw.split_once('-') {
        Some((core, _)) => (core, true),
        None => (raw, false),
    };
    let mut parts = core.split('.').map(|p| p.parse::<u64>().ok());
    Some((parts.next()??, parts.next()??, parts.next()??, pre))
}

/// Whether `candidate` is newer than `current`.
pub fn is_newer(candidate: &str, current: &str) -> bool {
    match (parse_version(candidate), parse_version(current)) {
        (Some((a, b, c, a_pre)), Some((x, y, z, x_pre))) => {
            (a, b, c) > (x, y, z) || ((a, b, c) == (x, y, z) && x_pre && !a_pre)
        }
        _ => false,
    }
}

/// The release target triple of this build, as used in asset names.
pub fn asset_triple() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Some("x86_64-linux-gnu"),
        ("linux", "aarch64") => Some("aarch64-linux-gnu"),
        ("macos", "x86_64") => Some("x86_64-apple-darwin"),
        ("macos", "aarch64") => Some("aarch64-apple-darwin"),
        ("windows", "x86_64") => Some("x86_64-windows-msvc"),
        _ => None,
    }
}

/// Archive name for `version` on this platform.
pub fn asset_name(version: &str, triple: &str) -> String {
    let ext = if triple.contains("windows") {
        "zip"
    } else {
        "tar.gz"
    };
    format!("mccode-{version}-{triple}.{ext}")
}

/// Look `name` up in a `shasum -a 256` listing.
pub fn expected_sha256<'a>(sums: &'a str, name: &str) -> Option<&'a str> {
    sums.lines().find_map(|line| {
        let mut parts = line.split_whitespace();
        let hash = parts.next()?;
        let file = parts.next()?.trim_start_matches('*');
        (file == name).then_some(hash)
    })
}

fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent(concat!("mccode/", env!("CARGO_PKG_VERSION")))
        .build()
        .unwrap_or_default()
}

async fn latest_tag() -> anyhow::Result<String> {
    let response = http()
        .get(format!(
            "https://api.github.com/repos/{REPO}/releases/latest"
        ))
        .header("accept", "application/vnd.github+json")
        .send()
        .await?;
    if !response.status().is_success() {
        anyhow::bail!("GitHub returned {}", response.status());
    }
    let body: serde_json::Value = response.json().await?;
    body.get("tag_name")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("the latest release has no tag"))
}

async fn download(url: &str) -> anyhow::Result<Vec<u8>> {
    let response = http().get(url).send().await?;
    if !response.status().is_success() {
        anyhow::bail!("download failed: {} ({url})", response.status());
    }
    Ok(response.bytes().await?.to_vec())
}

fn installed_by_homebrew(exe: &Path) -> bool {
    let path = exe.to_string_lossy();
    path.contains("/Cellar/") || path.contains("/homebrew/")
}

fn find_binary(dir: &Path, name: &str) -> Option<PathBuf> {
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if let Some(found) = find_binary(&path, name) {
                return Some(found);
            }
        } else if path.file_name().is_some_and(|n| n == name) {
            return Some(path);
        }
    }
    None
}

/// Check for, and unless `check_only`, install the latest release.
pub async fn run(check_only: bool) -> anyhow::Result<()> {
    let current = env!("CARGO_PKG_VERSION");
    let tag = latest_tag().await?;
    let version = tag.trim_start_matches('v').to_string();
    if !is_newer(&version, current) {
        println!("mccode {current} is up to date (latest release: {tag}).");
        return Ok(());
    }
    println!("A newer release is available: {tag} (you have {current}).");
    if check_only {
        return Ok(());
    }
    let exe = std::env::current_exe()?;
    if installed_by_homebrew(&exe) {
        println!("Installed with Homebrew: run `brew upgrade mccode`.");
        return Ok(());
    }
    let triple = asset_triple()
        .ok_or_else(|| anyhow::anyhow!("no release build for this platform; build from source"))?;
    let name = asset_name(&version, triple);
    let base = format!("https://github.com/{REPO}/releases/download/{tag}");
    let sums = String::from_utf8(download(&format!("{base}/SHA256SUMS.txt")).await?)?;
    let expected = expected_sha256(&sums, &name)
        .ok_or_else(|| anyhow::anyhow!("{name} is not listed in SHA256SUMS.txt"))?
        .to_ascii_lowercase();
    println!("Downloading {name}…");
    let archive = download(&format!("{base}/{name}")).await?;
    let actual: String = Sha256::digest(&archive)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if actual != expected {
        anyhow::bail!("checksum mismatch for {name}; not installing");
    }
    let work = std::env::temp_dir().join(format!("mccode-update-{}", std::process::id()));
    std::fs::create_dir_all(&work)?;
    let archive_path = work.join(&name);
    std::fs::write(&archive_path, &archive)?;
    let flag = if name.ends_with(".zip") {
        "-xf"
    } else {
        "-xzf"
    };
    let status = std::process::Command::new("tar")
        .arg(flag)
        .arg(&archive_path)
        .arg("-C")
        .arg(&work)
        .status()?;
    if !status.success() {
        anyhow::bail!("could not unpack {name} (tar exited with {status})");
    }
    let binary_name = if cfg!(windows) {
        "mccode.exe"
    } else {
        "mccode"
    };
    let new_binary = find_binary(&work, binary_name)
        .ok_or_else(|| anyhow::anyhow!("{name} does not contain {binary_name}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&new_binary, std::fs::Permissions::from_mode(0o755))?;
    }
    // Stage next to the executable, then swap with renames.
    let staged = exe.with_extension("new");
    std::fs::copy(&new_binary, &staged)?;
    let old = exe.with_extension("old");
    let _ = std::fs::remove_file(&old);
    std::fs::rename(&exe, &old)?;
    if let Err(e) = std::fs::rename(&staged, &exe) {
        let _ = std::fs::rename(&old, &exe);
        anyhow::bail!("could not install the new binary: {e}");
    }
    let _ = std::fs::remove_dir_all(&work);
    println!("Updated mccode to {tag} ({}).", exe.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_versions() {
        assert!(is_newer("0.12.0", "0.11.1"));
        assert!(is_newer("v1.0.0", "0.99.9"));
        assert!(is_newer("0.11.1", "0.11.1-rc.1"));
        assert!(!is_newer("0.11.1", "0.11.1"));
        assert!(!is_newer("0.11.0", "0.11.1"));
        assert!(!is_newer("0.12.0-rc.1", "0.12.0"));
        assert!(!is_newer("garbage", "0.11.1"));
    }

    #[test]
    fn asset_names_and_checksums() {
        assert_eq!(
            asset_name("0.12.0", "aarch64-apple-darwin"),
            "mccode-0.12.0-aarch64-apple-darwin.tar.gz"
        );
        assert_eq!(
            asset_name("0.12.0", "x86_64-windows-msvc"),
            "mccode-0.12.0-x86_64-windows-msvc.zip"
        );
        let sums = "abc123  mccode-0.12.0-x86_64-linux-gnu.tar.gz\nfff  microclaw-0.12.0-x86_64-linux-gnu.tar.gz\n";
        assert_eq!(
            expected_sha256(sums, "mccode-0.12.0-x86_64-linux-gnu.tar.gz"),
            Some("abc123")
        );
        assert_eq!(expected_sha256(sums, "missing.tar.gz"), None);
        assert!(installed_by_homebrew(Path::new(
            "/opt/homebrew/Cellar/microclaw/0.11.1/bin/mccode"
        )));
        assert!(!installed_by_homebrew(Path::new(
            "/home/me/.cargo/bin/mccode"
        )));
    }
}
