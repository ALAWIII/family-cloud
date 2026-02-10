mod download;
mod stream;
mod upload;
use crate::{AppState, validate_jwt_access_token};
use axum::{Router, middleware::from_fn_with_state, routing::get};
pub use download::*;
use secrecy::SecretString;
pub use stream::*;
pub use upload::*;

//--------------------------------------objects manipulation ----------------------
pub fn storage_objects(hmac: SecretString) -> Router<AppState> {
    Router::new()
        .route("/api/objects", get(list_objects).post(upload))
        .route(
            "/api/objects/{id}",
            get(get_metadata)
                .put(replace_object)
                .patch(update_metadata)
                .delete(delete_object),
        )
        .route("/api/objects/{id}/download", get(download))
        .layer(from_fn_with_state(hmac, validate_jwt_access_token))
        .route("/api/objects/stream", get(stream)) // no need for accepting jwt access token.
}

async fn list_objects() {}
async fn get_metadata() {}
async fn replace_object() {}
async fn update_metadata() {}
async fn delete_object() {}
