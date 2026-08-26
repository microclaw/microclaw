use std::{env, fs, path::PathBuf};

fn main() {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let icon = manifest_dir.join("../../packaging/microclaw-work/windows/MicroClawWork.ico");
    println!("cargo:rerun-if-changed={}", icon.display());

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let escaped_icon = icon
        .canonicalize()
        .expect("MicroClaw Work Windows icon must exist")
        .display()
        .to_string()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    let resource = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("microclaw-work.rc");
    fs::write(&resource, format!("1 ICON \"{escaped_icon}\"\n"))
        .expect("failed to write MicroClaw Work Windows resource");
    embed_resource::compile(&resource, std::iter::empty::<&str>())
        .manifest_required()
        .expect("failed to embed MicroClaw Work Windows resources");
}
