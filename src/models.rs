use std::fmt::Display;

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
#[derive(Debug, Deserialize)]
pub struct PasswordRequestReset {
    pub email: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PasswordUserReset {
    pub id: Uuid,
    pub username: String,
    pub email: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PendingAccount {
    pub username: String,
    pub email: String,
    pub password_hash: String, // store hashed, not plain
}
impl PendingAccount {
    pub fn new(username: &str, email: &str, hashed_password: String) -> Self {
        Self {
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

/// used only on login !!!
pub struct Credentials {
    pub email: String,
    pub password: SecretBox<String>,
}
#[derive(Debug, Deserialize)]
pub struct TokenQuery {
    pub token: String,
}
#[derive(Debug, Clone, Copy)]
pub enum TokenType {
    Signup,
    PasswordReset,
    EmailChange,
}
impl Display for TokenType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::EmailChange => "email_change",
                Self::Signup => "signup",
                Self::PasswordReset => "password_reset",
            }
        )
    }
}
pub fn create_verification_key(hashed_token: &str, token_type: TokenType) -> String {
    format!("verify:{}:{}", token_type, hashed_token)
}
