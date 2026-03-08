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
mod copy;
mod move_obj;
pub use copy::*;
pub use move_obj::*;
mod shares;
pub use shares::*;

//--------------------------------------objects manipulation ----------------------
pub fn storage_objects(hmac: SecretString) -> Router<AppState> {
    Router::new()
        .route(
            "/api/objects",
            get(list_objects).post(upload).delete(delete),
        )
        .route(
            "/api/objects/{id}",
            get(get_metadata).patch(update_metadata),
        )
        .route("/api/objects/children/{id}", get(list_children))
        .route("/api/objects/move", post(move_object))
        .route("/api/objects/copy", post(copy))
        .route("/api/objects/{id}/download", get(download))
        .route("/api/objects/shares", post(create_link_share))
        .layer(from_fn_with_state(hmac, validate_jwt_access_token))
        .route("/api/objects/stream", get(stream)) // no need for accepting jwt access token.
}
