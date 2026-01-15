use axum::{
    Router,
    routing::{get, put},
};
use chrono::{NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::prelude::FromRow;
use uuid::Uuid;

use crate::AppState;

#[derive(Debug, Deserialize, Serialize, FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub created_at: NaiveDateTime,
    pub storage_quota_bytes: i64,
    pub storage_used_bytes: i64,
}
impl User {
    pub fn new(username: String, email: String, password_hash: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            username,
            email,
            password_hash,
            created_at: Utc::now().naive_utc(),
            storage_quota_bytes: 2147483648,
            storage_used_bytes: 0,
        }
    }

    pub fn set_storage_quota_bytes(&mut self, sqb: i64) {
        self.storage_quota_bytes = sqb;
    }
    pub fn set_storage_used_bytes(&mut self, sub: i64) {
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
