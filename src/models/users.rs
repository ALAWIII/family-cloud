use chrono::{NaiveDateTime, Utc};

use serde::{Deserialize, Serialize};

use sqlx::prelude::FromRow;

use uuid::Uuid;

#[derive(Debug, Deserialize, Serialize, FromRow, Clone)]
pub struct User {
    pub id: Uuid,
    pub root_folder: Option<Uuid>,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub created_at: NaiveDateTime,
    pub storage_quota_bytes: i64,
    pub storage_used_bytes: i64,
}

impl User {
    pub fn new(id: Uuid, username: String, email: String, password_hash: String) -> Self {
        Self {
            root_folder: None,
            id,
            username,
            email,
            password_hash,
            created_at: Utc::now().naive_utc(),
            storage_quota_bytes: 2147483648,
            storage_used_bytes: 0,
        }
    }
    pub fn set_root_folder(&mut self, f_id: Uuid) {
        self.root_folder = Some(f_id);
    }

    pub fn set_storage_quota_bytes(&mut self, sqb: i64) {
        self.storage_quota_bytes = sqb;
    }
    pub fn set_storage_used_bytes(&mut self, sub: i64) {
        self.storage_used_bytes = sub;
    }
}
#[derive(Serialize, Debug, Deserialize)]
pub struct UserProfile {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub root_folder: Option<Uuid>,
    pub created_at: NaiveDateTime,
    pub storage_quota_bytes: i64,
    pub storage_used_bytes: i64,
}
impl From<User> for UserProfile {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            username: user.username,
            email: user.email,
            root_folder: user.root_folder,
            created_at: user.created_at,
            storage_quota_bytes: user.storage_quota_bytes,
            storage_used_bytes: user.storage_used_bytes,
        }
    }
}
