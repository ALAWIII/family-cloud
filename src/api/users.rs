use axum::{
    Router,
    routing::{get, put},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::AppState;

#[derive(Debug, Deserialize, Serialize)]
struct User {
    id: Uuid,
    username: String,
    email: String,
    password_hash: String,
    created_at: DateTime<Utc>,
    storage_quota_bytes: u64,
    storage_used_bytes: u64,
}
impl User {
    pub fn new(username: String, email: String, password_hash: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            username,
            email,
            password_hash,
            created_at: Utc::now(),
            storage_quota_bytes: 2147483648,
            storage_used_bytes: 0,
        }
    }
    pub fn set_storage_quota_bytes(&mut self, sqb: u64) {
        self.storage_quota_bytes = sqb;
    }
    pub fn set_storage_used_bytes(&mut self, sub: u64) {
        self.storage_used_bytes = sub;
    }
}
//------------------------------------user management-------

async fn user_profile() {}
async fn update_user_profile_info() {}
async fn change_password() {}
pub fn user_management() -> Router<AppState> {
    Router::new()
        .route(
            "/api/users/me",
            get(user_profile).patch(update_user_profile_info),
        )
        .route("/api/users/me/password", put(change_password))
}
