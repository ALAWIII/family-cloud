use axum::{
    Router,
    routing::{get, post},
};
//------------------------------------share objects links ----------------------------

async fn create_link_share() {}
async fn access_object() {}
pub fn sharing_object() -> Router {
    Router::new()
        .route("/api/objects/{id}/shares", post(create_link_share))
        .route("/api/shares/{token}", get(access_object))
}
