use chrono::{NaiveDateTime, Utc};
use secrecy::SecretBox;
use serde::{Deserialize, Serialize};
use sqlx::prelude::FromRow;
use uuid::Uuid;

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

#[derive(Debug, Serialize, Deserialize)]
pub struct PasswordUserReset {
    pub id: Uuid,
    pub username: String,
    pub email: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PendingAccount {
    pub token_type: TokenType,
    pub username: String,
    pub email: String,
    pub password_hash: String, // store hashed, not plain
}
impl PendingAccount {
    pub fn new(username: &str, email: &str, hashed_password: String) -> Self {
        Self {
            token_type: TokenType::SignupVerification,
            username: username.into(),
            email: email.into(),
            password_hash: hashed_password,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct TokenPayload {
    pub user_id: Uuid,
}

#[derive(Deserialize)]
pub struct SignupRequest {
    pub username: String,
    pub email: String,
    pub password: SecretBox<String>, // Received as plain text
}

#[derive(Serialize)]
pub enum SignupPayload {
    Existing(TokenPayload),
    New(PendingAccount),
}
impl SignupPayload {
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        match self {
            Self::Existing(t) => serde_json::to_string(t),
            Self::New(p) => serde_json::to_string(p),
        }
    }
}
#[derive(Debug, Serialize, Deserialize)]
pub enum TokenType {
    SignupVerification,
    PasswordReset,
    EmailChange,
    Refresh,
    Access,
}

/// used only on login !!!
pub struct Credentials {
    pub email: String,
    pub password: SecretBox<String>,
}
#[derive(Debug, Deserialize)]
pub struct TokenQuery {
    pub token: String,
}
