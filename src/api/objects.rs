use axum::{Router, routing::get};

//--------------------------------------objects manipulation ----------------------

async fn list_objects_with_metadata() {}
async fn upload_object() {}
async fn download_object() {}
async fn fetch_metadata() {}
async fn replace_object() {}
async fn update_metadata() {}
async fn delete_object() {}
pub fn storage_objects() -> Router {
    Router::new()
        .route(
            "/api/objects",
            get(list_objects_with_metadata).post(upload_object),
        )
        .route(
            "/api/objects/{id}",
            get(download_object)
                .head(fetch_metadata)
                .put(replace_object)
                .patch(update_metadata)
                .delete(delete_object),
        )
}
