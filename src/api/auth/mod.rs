mod login;
mod logout;
mod refresh;
mod signup;

use login::*;
use logout::*;
use refresh::*;
use secrecy::SecretString;
use signup::*;

use axum::{
    Router,
    middleware::from_fn_with_state,
    routing::{get, post},
};

mod pswd_reset;
pub use pswd_reset::*;
mod email_change;
use crate::{AppState, validate_jwt_access_token};
pub use email_change::*;

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
