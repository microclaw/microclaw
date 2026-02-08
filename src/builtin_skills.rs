use include_dir::{include_dir, Dir, DirEntry};
use std::path::Path;

static BUILTIN_SKILLS_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/data/skills");

pub fn ensure_builtin_skills(data_root: &Path) -> std::io::Result<()> {
    let skills_root = data_root.join("skills");
    std::fs::create_dir_all(&skills_root)?;
    copy_missing_entries(&BUILTIN_SKILLS_DIR, &skills_root)
}

fn copy_missing_entries(embedded: &Dir<'_>, destination: &Path) -> std::io::Result<()> {
    for entry in embedded.entries() {
        match entry {
            DirEntry::Dir(dir) => {
                let Some(name) = dir.path().file_name() else {
                    continue;
                };
                let next_dest = destination.join(name);
                std::fs::create_dir_all(&next_dest)?;
                copy_missing_entries(dir, &next_dest)?;
            }
            DirEntry::File(file) => {
                let Some(name) = file.path().file_name() else {
                    continue;
                };
                let out_path = destination.join(name);
                if !out_path.exists() {
                    std::fs::write(out_path, file.contents())?;
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "microclaw_builtin_skills_test_{}",
            uuid::Uuid::new_v4()
        ))
    }

    fn cleanup(path: &Path) {
        let _ = std::fs::remove_dir_all(path);
    }

    #[test]
    fn test_ensure_builtin_skills_writes_missing_files() {
        let root = temp_root();
        ensure_builtin_skills(&root).unwrap();
        let sample = root.join("skills").join("pdf").join("SKILL.md");
        assert!(sample.exists());
        let content = std::fs::read_to_string(sample).unwrap();
        assert!(!content.trim().is_empty());
        cleanup(&root);
    }

    #[test]
    fn test_ensure_builtin_skills_does_not_overwrite_existing_file() {
        let root = temp_root();
        let custom_pdf = root.join("skills").join("pdf");
        std::fs::create_dir_all(&custom_pdf).unwrap();
        let custom_file = custom_pdf.join("SKILL.md");
        std::fs::write(&custom_file, "custom-content").unwrap();

        ensure_builtin_skills(&root).unwrap();
        let content = std::fs::read_to_string(custom_file).unwrap();
        assert_eq!(content, "custom-content");
        cleanup(&root);
    }
}
