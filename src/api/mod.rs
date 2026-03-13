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
pub fn sharing_object() -> Router<AppState> {
    Router::new().route("/api/shares/{token}", get(access_object))
}
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
        .route("/api/objects/stream/share", get(stream_share))
}

pub fn change_email_router(hmac: SecretString) -> Router<AppState> {
    Router::new()
        // body contains { access_token , new_email }
        .route("/api/auth/change-email", post(change_email))
        .layer(from_fn_with_state(hmac, validate_jwt_access_token))
        //the url must contain the verification token to be verified and accept new email then deleted from redis
        .route("/api/auth/change-email/verify", get(verify_change_email))
        //the url must contain the verification token to be deleted/revoked from redis
        .route("/api/auth/change-email/cancel", get(cancel_change_email))
}

pub fn pswd_router() -> Router<AppState> {
    Router::new()
        // body contains user `email`
        .route(
            "/api/auth/password-reset",
            post(password_reset)
                // url contains the generated verification token , response : password form
                .get(verify_password_reset),
        )
        // body contains (verification_token, new password,confirm password)
        .route(
            "/api/auth/password-reset/confirm",
            post(confirm_password_reset),
        )
}

pub fn authentication() -> Router<AppState> {
    Router::new()
        .route("/api/auth/signup", post(signup).get(verify_signup))
        .route("/api/auth/login", post(login))
        .route("/api/auth/logout", post(logout))
        .route("/api/auth/refresh", post(refresh_token))
}

pub fn user_management(hmac: SecretString) -> Router<AppState> {
    Router::new()
        .route(
            "/api/users/me",
            get(user_profile)
                .patch(update_user_username)
                .delete(delete_account),
        )
        .layer(from_fn_with_state(hmac, validate_jwt_access_token))
}

pub fn storage_status(hmac: SecretString) -> Router<AppState> {
    Router::new()
        .route("/api/storage/usage", get(fetch_storage_info))
        .layer(from_fn_with_state(hmac, validate_jwt_access_token))
}
