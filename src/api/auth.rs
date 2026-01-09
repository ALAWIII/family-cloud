use axum::{Router, routing::post};

//-----------------------------------authentication management-----

async fn login() {}
async fn logout() {}
async fn signup() {}
async fn refresh_token() {}
pub fn authentication() -> Router {
    Router::new()
        .route("/api/auth/signup", post(signup))
        .route("/api/auth/login", post(login))
        .route("/api/auth/logout", post(logout))
        .route("/api/auth/refresh", post(refresh_token))
}
