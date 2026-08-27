use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

fn main() {
    for path in [
        "web/index.html",
        "web/package.json",
        "web/package-lock.json",
        "web/tsconfig.json",
        "web/vite.config.ts",
        "web/public",
        "web/src",
    ] {
        println!("cargo:rerun-if-changed={path}");
    }
    println!("cargo:rerun-if-env-changed=MICROCLAW_SKIP_WEB_BUILD");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_EMBEDDED_WEB_UI");
    println!("cargo:rerun-if-env-changed=NPM");

    ensure_web_assets();

    // Keep builtin skills embedding in sync as well.
    println!("cargo:rerun-if-changed=skills/built-in");
}

fn ensure_web_assets() {
    if env::var_os("CARGO_FEATURE_EMBEDDED_WEB_UI").is_none() {
        write_embedded_web_assets(false, Path::new("web/dist"));
        return;
    }

    let source_dist = Path::new("web/dist");
    let skip_web_build = env::var_os("MICROCLAW_SKIP_WEB_BUILD").is_some();

    if skip_web_build {
        if !has_required_web_assets(source_dist) {
            panic!(
                "web assets are missing, but MICROCLAW_SKIP_WEB_BUILD is set; \
                 regenerate web/dist before building"
            );
        }
    } else if web_assets_need_rebuild(source_dist) {
        build_web_assets();
    }

    assert_web_assets_ready(source_dist);

    write_embedded_web_assets(true, source_dist);
}

fn write_embedded_web_assets(include_assets: bool, source_dist: &Path) {
    let output_root = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR not set"));
    let out_dist = output_root.join("web-dist");
    if out_dist.exists() {
        fs::remove_dir_all(&out_dist).unwrap_or_else(|err| {
            panic!(
                "failed to clear generated web asset directory {}: {err}",
                out_dist.display()
            )
        });
    }
    if include_assets {
        copy_dir_all(source_dist, &out_dist).unwrap_or_else(|err| {
            panic!(
                "failed to copy web assets from {} to {}: {err}",
                source_dist.display(),
                out_dist.display()
            )
        });
    } else {
        fs::create_dir_all(&out_dist).unwrap_or_else(|err| {
            panic!(
                "failed to create empty Web asset directory {}: {err}",
                out_dist.display()
            )
        });
    }

    let web_assets_rs = output_root.join("web_assets.rs");
    let web_assets_source = format!(
        "static WEB_ASSETS: Dir<'_> = include_dir!({:?});\n",
        out_dist.to_string_lossy()
    );
    fs::write(&web_assets_rs, web_assets_source).unwrap_or_else(|err| {
        panic!(
            "failed to write generated web asset source {}: {err}",
            web_assets_rs.display()
        )
    });
}

fn web_assets_need_rebuild(dist_dir: &Path) -> bool {
    if !has_required_web_assets(dist_dir) {
        return true;
    }

    let newest_source = newest_mtime(Path::new("web/src"))
        .into_iter()
        .chain(newest_mtime(Path::new("web/public")))
        .chain(single_file_mtime(Path::new("web/index.html")))
        .chain(single_file_mtime(Path::new("web/package.json")))
        .chain(single_file_mtime(Path::new("web/package-lock.json")))
        .chain(single_file_mtime(Path::new("web/tsconfig.json")))
        .chain(single_file_mtime(Path::new("web/vite.config.ts")))
        .max();

    let newest_dist = newest_mtime(dist_dir);
    newest_source.is_some() && newest_source > newest_dist
}

fn build_web_assets() {
    let npm = env::var_os("NPM").unwrap_or_else(default_npm_command);

    println!("cargo:warning=building web assets into web/dist");

    if !Path::new("web/node_modules").is_dir() {
        if Path::new("web/package-lock.json").is_file() {
            run_command(&npm, &["--prefix", "web", "ci"], "install web dependencies");
        } else {
            run_command(
                &npm,
                &["--prefix", "web", "install"],
                "install web dependencies",
            );
        }
    }

    run_command(
        &npm,
        &["--prefix", "web", "run", "build"],
        "build web assets",
    );
}

fn default_npm_command() -> OsString {
    if cfg!(windows) {
        OsString::from("npm.cmd")
    } else {
        OsString::from("npm")
    }
}

fn run_command(program: &OsStr, args: &[&str], action: &str) {
    let status = Command::new(program)
        .args(args)
        .status()
        .unwrap_or_else(|err| panic!("failed to {action}: could not start {:?}: {err}", program));

    if !status.success() {
        panic!(
            "failed to {action}: command {:?} {} exited with {status}",
            program,
            args.join(" ")
        );
    }
}

fn assert_web_assets_ready(dist_dir: &Path) {
    if has_required_web_assets(dist_dir) {
        return;
    }

    panic!(
        "web asset directory {} is incomplete; expected index.html, favicon.ico, icon.png, \
         and at least one JavaScript bundle in assets/",
        dist_dir.display()
    );
}

fn has_required_web_assets(dist_dir: &Path) -> bool {
    dist_dir.join("index.html").is_file()
        && dist_dir.join("favicon.ico").is_file()
        && dist_dir.join("icon.png").is_file()
        && has_js_bundle(&dist_dir.join("assets"))
}

fn has_js_bundle(assets_dir: &Path) -> bool {
    let Ok(entries) = fs::read_dir(assets_dir) else {
        return false;
    };

    entries
        .filter_map(Result::ok)
        .any(|entry| entry.path().extension() == Some(OsStr::new("js")))
}

fn newest_mtime(path: &Path) -> Option<SystemTime> {
    if !path.exists() {
        return None;
    }

    if path.is_file() {
        return single_file_mtime(path);
    }

    let mut newest = None;
    let entries = fs::read_dir(path).ok()?;
    for entry in entries.filter_map(Result::ok) {
        let child_newest = newest_mtime(&entry.path());
        newest = max_mtime(newest, child_newest);
    }
    newest
}

fn single_file_mtime(path: &Path) -> Option<SystemTime> {
    path.metadata().ok()?.modified().ok()
}

fn max_mtime(left: Option<SystemTime>, right: Option<SystemTime>) -> Option<SystemTime> {
    match (left, right) {
        (Some(left), Some(right)) => Some(if left >= right { left } else { right }),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }
}

fn copy_dir_all(src: &Path, dst: &Path) -> io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            copy_dir_all(&src_path, &dst_path)?;
        } else {
            fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}
