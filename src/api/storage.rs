use axum::{Router, routing::get};

//---------------------------------------storage usage information -------------------

async fn fetch_storage_info() {}
pub fn storage_status() -> Router {
    Router::new().route("/api/storage/usage", get(fetch_storage_info))
}
