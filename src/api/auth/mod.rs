mod login;
mod logout;
mod refresh;
mod signup;
use login::*;
use logout::*;
use refresh::*;
use signup::*;
mod utils;
use axum::{Router, routing::post};
pub use utils::*;
mod models;
#[cfg(test)]
mod tests;
use crate::AppState;
pub use models::*;
pub fn authentication() -> Router<AppState> {
    Router::new()
        .route("/api/auth/signup", post(signup))
        .route("/api/auth/login", post(login))
        .route("/api/auth/logout", post(logout))
        .route("/api/auth/refresh", post(refresh_token))
}
