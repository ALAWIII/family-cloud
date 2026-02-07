use std::ffi::OsStr;
use std::path::Path;
use std::{fmt::Display, str::FromStr};

use chrono::DateTime;
use chrono::{NaiveDateTime, Utc};
use secrecy::{ExposeSecret, SecretBox, SecretString};
use serde::{Deserialize, Serialize, Serializer};
use sqlx::prelude::FromRow;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::{decrement_concurrent_download, get_redis_con};

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
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub user: UserProfile,
}

#[derive(Serialize, Debug, Deserialize)]
pub struct UserProfile {
    pub id: Uuid,
    pub username: String,
    pub email: String,
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
            created_at: user.created_at,
            storage_quota_bytes: user.storage_quota_bytes,
            storage_used_bytes: user.storage_used_bytes,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct EmailInput {
    pub email: String,
}

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

#[derive(Debug, Deserialize)]
pub struct SignupRequest {
    pub username: String,
    pub email: String,
    pub password: SecretBox<String>, // Received as plain text
}

/// used only on login request !!!
#[derive(Debug, Deserialize)]
pub struct Credentials {
    pub email: String,
    pub password: SecretBox<String>,
}

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
#[derive(Debug, Clone, Copy)]
pub enum TokenType {
    Signup,
    PasswordReset,
    EmailChange,
    Refresh,
    Download,
    Access,
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
                Self::Refresh => "refresh",
                Self::Access => "access",
                Self::Download => "download",
            }
        )
    }
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectRecord {
    // ===== Identity (DB authority) =====
    pub id: Uuid,           // internal unique file_id
    pub user_id: Uuid,      // == bucket_name == bucket_id
    pub object_key: String, // actual key in RustFS (e.g. "/shawarma/potato.txt")

    // ===== RustFS technical metadata =====
    pub size: i64,                    // content_length
    pub etag: String,                 // e_tag
    pub mime_type: Option<String>,    // content_type (nullable)
    pub last_modified: DateTime<Utc>, // from RustFS

    // ===== System / business metadata =====
    pub created_at: DateTime<Utc>, // DB timestamp
    pub visibility: Visibility,    // public / private
    pub status: ObjectStatus,      // active / deleted / archived

    // ===== Optional / advanced =====
    pub checksum_sha256: String,
    pub custom_metadata: Option<serde_json::Value>, // copy of RustFS metadata
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Visibility {
    Public,
    Private,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "object_status")]
#[sqlx(rename_all = "lowercase")]
pub enum ObjectStatus {
    Active,
    Deleted,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct ObjectDownload {
    pub id: Uuid,
    pub user_id: Uuid,
    pub kind: ObjectKind,
    pub object_key: String,
    pub status: ObjectStatus,
    pub size: i64,
    pub etag: String,
    pub checksum_sha256: String,
}
impl ObjectDownload {
    pub fn object_name(&self) -> String {
        let path = Path::new(&self.object_key);
        path.file_name()
            .unwrap_or(OsStr::new("download"))
            .to_string_lossy()
            .to_string()
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DownloadTokenData {
    #[serde(flatten)]
    pub object_d: ObjectDownload,
    pub ip_address: Option<String>,
}
#[derive(Debug, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "object_kind_type", rename_all = "PascalCase")]
pub enum ObjectKind {
    File,
    Folder,
}

impl ObjectKind {
    pub fn is_folder(&self) -> bool {
        if let Self::Folder = self {
            return true;
        }
        false
    }
}
#[derive(Deserialize)]
pub struct StreamQuery {
    pub token: Uuid,
    pub download: Option<bool>, // Add this!
}

#[derive(Debug, Clone)]
pub struct CleanupGuard {
    redis_pool: deadpool_redis::Pool,
    token: Uuid,
    user_key: String,
}

impl CleanupGuard {
    pub fn new(redis_pool: deadpool_redis::Pool, token: Uuid, user_key: String) -> Self {
        Self {
            redis_pool,
            token,
            user_key,
        }
    }
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        let pool = self.redis_pool.clone();
        let token = self.token.to_string();
        let user_key = self.user_key.clone();

        // Spawn cleanup task (don't block Drop)
        tokio::spawn(async move {
            match get_redis_con(&pool).await {
                Ok(mut con) => {
                    match decrement_concurrent_download(&mut con, &token, &user_key).await {
                        Err(e) => warn!(error = %e, "Failed to cleanup download token"),
                        _ => info!(token = %token, "Download token cleaned up"),
                    }
                }
                Err(e) => error!(error = %e, "Failed to get redis connection for cleanup"),
            }
        });
    }
}
