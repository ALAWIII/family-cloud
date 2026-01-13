use axum::{Router, routing::get};

use crate::AppState;

//---------------------------------------storage usage information -------------------

async fn fetch_storage_info() {}
pub fn storage_status() -> Router<AppState> {
    Router::new().route("/api/storage/usage", get(fetch_storage_info))
}
