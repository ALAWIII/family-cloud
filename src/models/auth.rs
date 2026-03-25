use chrono::Utc;

use secrecy::{ExposeSecret, SecretBox, SecretString};
use serde::{Deserialize, Serialize, Serializer};

use std::{fmt::Display, str::FromStr};

use uuid::Uuid;

use crate::UserProfile;
/// Login response returned by `/api/auth/login`, bundling a short‑lived
/// JWT access token, a long‑lived opaque refresh token, and the user’s
/// profile information.
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub user: UserProfile,
}
/// Simple input wrapper for endpoints that take an email address, such as
/// password reset and change‑email initiation.
#[derive(Debug, Deserialize)]
pub struct EmailInput {
    pub email: String,
}
/// Lightweight user identity used in verification flows (email change,
/// password reset) containing id, username, and email, serializable to and
/// from JSON.
#[derive(Debug, Serialize, Deserialize)]
pub struct UserVerification {
    pub id: Uuid,
    pub username: String,
    pub email: String,
}
impl UserVerification {
    pub fn new(id: Uuid, username: &str, email: &str) -> Self {
        Self {
            id,
            username: username.into(),
            email: email.into(),
        }
    }
}

impl FromStr for UserVerification {
    type Err = serde_json::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
    }
}
/// Pending signup state stored in Redis before a user confirms their email;
/// holds username, email, and a hashed password, but is not yet persisted
/// as a full user in Postgres.
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
/// Payload for signup requests, carrying plain‑text credentials in a
/// `SecretBox` that will be hashed before storage.
#[derive(Debug, Deserialize)]
pub struct SignupRequest {
    pub username: String,
    pub email: String,
    pub password: SecretBox<String>, // Received as plain text
}

/// Credentials used only for login, containing email and a secret‑boxed
/// plain‑text password.
#[derive(Debug, Deserialize)]
pub struct Credentials {
    pub email: String,
    pub password: SecretBox<String>,
}
/// Wrapper for any token string passed over the wire (e.g., refresh,
/// signup, reset), using `SecretString` internally and custom serialization
/// to avoid accidental logging of the token.
#[derive(Debug, Deserialize, Serialize)]
pub struct TokenPayload {
    #[serde(serialize_with = "serialize_token")]
    pub token: SecretString,
}
fn serialize_token<S>(token: &SecretString, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(token.expose_secret())
}
/// Enumerates all logical token namespaces (signup, password reset,
/// email‑change, refresh, download, shared) and provides lowercase string
/// names used when composing Redis keys.
#[derive(Debug, Clone, Copy)]
pub enum TokenType {
    Signup,
    PasswordReset,
    EmailChange,
    Refresh,
    Download,
    Shared,
}
impl Display for TokenType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Shared => "shared",
                Self::EmailChange => "email_change",
                Self::Signup => "signup",
                Self::PasswordReset => "password_reset",
                Self::Refresh => "refresh",
                Self::Download => "download",
            }
        )
    }
}
/// JWT claims used for access tokens, containing user id (`sub`),
/// username, issued‑at (`iat`), and expiration (`exp`) timestamps.
/// `new` defaults to a 15‑minute lifetime; `with_expiry` allows custom
/// durations.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: Uuid, // user ID
    pub username: String,
    pub iat: i64,
    pub exp: i64,
}
impl Claims {
    /// default exp = 900 seconds = 15 minutes
    pub fn new(sub: Uuid, username: String) -> Self {
        let now = Utc::now().timestamp();
        Self {
            sub,
            username,
            iat: now,
            exp: now + 900,
        }
    }
    pub fn with_expiry(mut self, seconds: i64) -> Self {
        self.exp = self.iat + seconds;
        self
    }
}
/// Minimal user payload embedded in refresh tokens and used to mint new
/// JWT access tokens, carrying only user id and username.
#[derive(Debug, Deserialize, Serialize)]
pub struct UserTokenPayload {
    pub id: Uuid,
    pub username: String,
}
impl UserTokenPayload {
    pub fn new(id: Uuid, username: &str) -> Self {
        Self {
            id,
            username: username.into(),
        }
    }
}
