use std::sync::Arc;

use crate::config::Config;
use crate::db::Database;

pub async fn build_usage_report(
    db: Arc<Database>,
    _config: &Config,
    chat_id: i64,
) -> Result<String, String> {
    microclaw_storage::usage::build_usage_report(db, chat_id).await
}
