use axum::{Router, routing::get};

use crate::AppState;

//------------------------------------user management-------

async fn user_profile() {}
async fn update_user_profile_info() {}
pub fn user_management() -> Router<AppState> {
    Router::new().route(
        "/api/users/me",
        get(user_profile).patch(update_user_profile_info),
    )
}
