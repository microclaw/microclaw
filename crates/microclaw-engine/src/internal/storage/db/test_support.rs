use super::*;

pub(crate) fn test_db() -> (Database, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("microclaw_test_{}", uuid::Uuid::new_v4()));
    let db = Database::new(dir.to_str().unwrap()).unwrap();
    (db, dir)
}

pub(crate) fn cleanup(dir: &std::path::Path) {
    let _ = std::fs::remove_dir_all(dir);
}
