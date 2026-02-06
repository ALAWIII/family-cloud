mod download;
mod stream;
use crate::AppState;
use axum::{
    Router,
    routing::{get, post},
};
pub use download::*;
pub use stream::*;

//--------------------------------------objects manipulation ----------------------
pub fn storage_objects() -> Router<AppState> {
    Router::new()
        .route("/api/objects", get(list_objects).post(upload_object))
        .route(
            "/api/objects/{id}",
            get(get_metadata)
                .put(replace_object)
                .patch(update_metadata)
                .delete(delete_object),
        )
        .route("/api/objects/{id}/download", get(download))
        .route("/api/stream", get(stream))
}

async fn list_objects() {}
async fn upload_object() {}
async fn get_metadata() {}
async fn replace_object() {}
async fn update_metadata() {}
async fn delete_object() {}
