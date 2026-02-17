use std::ffi::OsStr;
use std::path::Path;
use std::{fmt::Display, str::FromStr};

use chrono::DateTime;
use chrono::{NaiveDateTime, Utc};
use derivative::Derivative;
use secrecy::{ExposeSecret, SecretBox, SecretString};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;
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

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ObjectRecord {
    // ===== Identity (DB authority) =====
    pub id: Uuid,
    pub user_id: Uuid,
    pub object_key: String, // e.g. "/shawarma/potato.txt" or "/shawarma/folder/"

    // ===== RustFS technical metadata (OPTIONAL for folders) =====
    pub size: Option<i64>,                    // None for folders
    pub etag: Option<String>,                 // None for folders
    pub mime_type: Option<String>,            // None for folders
    pub last_modified: Option<DateTime<Utc>>, // None for folders

    // ===== System / business metadata =====
    pub created_at: DateTime<Utc>,
    pub visibility: Visibility,
    pub status: ObjectStatus,

    // ===== Optional / advanced (OPTIONAL for folders) =====
    pub checksum_sha256: Option<String>, // None for folders
    pub custom_metadata: Option<serde_json::Value>,

    // ===== NEW: Folder-specific =====
    pub is_folder: bool, // Distinguish file vs folder
}
impl ObjectRecord {
    pub fn new(user_id: Uuid, obj_key: &str, is_folder: bool) -> Self {
        Self {
            id: Uuid::new_v4(),
            user_id,
            object_key: obj_key.into(),
            is_folder,
            ..Default::default()
        }
    }
    pub fn bucket_name(&self) -> String {
        self.user_id.to_string()
    }
    pub fn size(&mut self, s: i64) {
        self.size = Some(s);
    }
    pub fn object_key(&mut self, key: impl Into<String>) {
        self.object_key = key.into();
    }
    pub fn etag(&mut self, e: impl Into<String>) {
        self.etag = Some(e.into());
    }
    pub fn mime_type(&mut self, m: impl Into<String>) {
        self.mime_type = Some(m.into())
    }
    pub fn last_modified(&mut self, ldate: DateTime<Utc>) {
        self.last_modified = Some(ldate);
    }
    pub fn created_at(&mut self, cat: DateTime<Utc>) {
        self.created_at = cat;
    }
    pub fn visibility(&mut self, v: Visibility) {
        self.visibility = v;
    }
    pub fn checksum_sha256(&mut self, c: impl Into<String>) {
        self.checksum_sha256 = Some(c.into());
    }
    pub fn status(&mut self, s: ObjectStatus) {
        self.status = s;
    }
    pub fn is_folder(&mut self, b: bool) {
        self.is_folder = b;
    }
    pub fn add_metadata(&mut self, m: Value) -> bool {
        if let Some(v) = self.custom_metadata.as_mut() {
            return v.as_array_mut().is_some_and(|a| {
                a.push(m);
                true
            });
        }
        self.custom_metadata = Some(serde_json::Value::from([m]));
        true
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type, Default, PartialEq, Eq)]
#[sqlx(type_name = "visibility")]
#[sqlx(rename_all = "lowercase")]
pub enum Visibility {
    Public,
    #[default]
    Private,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type, Default, PartialEq, Eq)]
#[sqlx(type_name = "object_status")]
#[sqlx(rename_all = "lowercase")]
pub enum ObjectStatus {
    #[default]
    Active,
    Deleted,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct ObjectDownload {
    pub id: Uuid,
    pub user_id: Uuid,
    pub is_folder: bool,
    pub object_key: String,
    pub status: ObjectStatus,
    pub size: Option<i64>,
    pub etag: Option<String>,
    pub checksum_sha256: Option<String>,
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
impl Display for ObjectKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::File => "file",
                Self::Folder => "folder",
            }
        )
    }
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
#[derive(Debug, Serialize, Deserialize, Derivative, Clone)]
#[derivative(Hash, PartialEq, Eq)]
pub struct ObjDelete {
    #[derivative(Hash, PartialEq)]
    pub id: Uuid,
    pub object_key: String,
    pub is_folder: bool,
}
