mod download;
mod stream;
mod upload;
use crate::{AppState, validate_jwt_access_token};
use axum::{
    Router,
    middleware::from_fn_with_state,
    routing::{get, post},
};
pub use download::*;
use secrecy::SecretString;
pub use stream::*;
pub use upload::*;
mod delete;
mod metadata;
pub use delete::*;
pub use metadata::*;
mod copy_obj;
mod move_obj;
pub use copy_obj::*;
pub use move_obj::*;

//--------------------------------------objects manipulation ----------------------
pub fn storage_objects(hmac: SecretString) -> Router<AppState> {
    Router::new()
        .route("/api/objects", get(list_objects).post(upload))
        .route(
            "/api/objects/{id}",
            get(get_metadata)
                .patch(update_metadata)
                .delete(delete_object),
        )
        .route("/api/objects/{id}/move", post(move_object))
        .route("/api/objects/{id}/copy", post(copy_object))
        .route("/api/objects/{id}/download", get(download))
        .layer(from_fn_with_state(hmac, validate_jwt_access_token))
        .route("/api/objects/stream", get(stream)) // no need for accepting jwt access token.
}
