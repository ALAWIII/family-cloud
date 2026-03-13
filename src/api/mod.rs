mod auth;
mod objects;
mod users;
use crate::{AppState, validate_jwt_access_token};
use auth::*;
use axum::{
    Router,
    middleware::from_fn_with_state,
    routing::{get, post},
};
use objects::*;
use secrecy::SecretString;
use users::*;

pub fn app_router(hmac: SecretString) -> Router<AppState> {
    Router::new()
        .merge(public_routes())
        .merge(protected_routes(hmac))
}
fn public_routes() -> Router<AppState> {
    Router::new()
        // Shares
        .route("/api/shares/{token}", get(access_object))
        // Auth
        .route("/api/auth/signup", post(signup).get(verify_signup))
        .route("/api/auth/login", post(login))
        .route("/api/auth/logout", post(logout))
        .route("/api/auth/refresh", post(refresh_token))
        // Password reset
        .route(
            "/api/auth/password-reset",
            post(password_reset).get(verify_password_reset),
        )
        .route(
            "/api/auth/password-reset/confirm",
            post(confirm_password_reset),
        )
        // Email change (no auth — token in URL)
        .route("/api/auth/change-email/verify", get(verify_change_email))
        .route("/api/auth/change-email/cancel", get(cancel_change_email))
        // Streaming (no JWT)
        .route("/api/objects/stream", get(stream))
        .route("/api/objects/stream/share", get(stream_share))
}

fn protected_routes(hmac: SecretString) -> Router<AppState> {
    Router::new()
        // Users
        .route(
            "/api/users/me",
            get(user_profile)
                .patch(update_user_username)
                .delete(delete_account),
        )
        // Storage
        .route("/api/storage/usage", get(fetch_storage_info))
        // Objects
        .route(
            "/api/objects",
            get(list_objects).post(upload).delete(delete),
        )
        .route(
            "/api/objects/{id}",
            get(get_metadata).patch(update_metadata),
        )
        .route("/api/objects/{id}/download", get(download))
        .route("/api/objects/children/{id}", get(list_children))
        .route("/api/objects/move", post(move_object))
        .route("/api/objects/copy", post(copy))
        .route("/api/objects/shares", post(create_link_share))
        // Auth (protected)
        .route("/api/auth/change-email", post(change_email))
        .layer(from_fn_with_state(hmac, validate_jwt_access_token))
}
