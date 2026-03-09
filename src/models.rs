use axum::Json;
use axum::response::IntoResponse;
use chrono::DateTime;
use chrono::SubsecRound;
use chrono::{NaiveDateTime, Utc};
use deadpool_redis::redis;
use deadpool_redis::redis::AsyncTypedCommands;
use derivative::Derivative;
use secrecy::{ExposeSecret, SecretBox, SecretString};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;
use sqlx::prelude::FromRow;
use std::{fmt::Display, str::FromStr};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::CRedisError;
use crate::{decrement_concurrent_download, get_redis_con};

#[derive(Debug, Deserialize, Serialize, FromRow)]
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
//-------------------------------------------- objects (files,folders) models.---

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
    Deleting,
    Deleted,
    Uploading,
    Copying,
}
impl Display for ObjectStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let v = match self {
            Self::Active => "active",
            Self::Deleting => "deleting",
            Self::Deleted => "deleted",
            Self::Copying => "copying",
            Self::Uploading => "uploading",
        };
        write!(f, "{}", v)
    }
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum FileSystemObject {
    Folder(FolderRecord),
    File(FileRecord),
}
impl FileSystemObject {
    pub fn is_folder(&self) -> bool {
        matches!(self, Self::Folder(_))
    }

    pub fn get_folder(&self) -> Option<&FolderRecord> {
        match self {
            Self::Folder(f) => Some(f),
            _ => None,
        }
    }

    pub fn get_file(&self) -> Option<&FileRecord> {
        match self {
            Self::File(f) => Some(f),
            _ => None,
        }
    }
    pub fn owner_id(&self) -> Uuid {
        match self {
            Self::Folder(f) => f.owner_id,
            Self::File(f) => f.owner_id,
        }
    }

    pub fn id(&self) -> Uuid {
        match self {
            Self::Folder(f) => f.id,
            Self::File(f) => f.id,
        }
    }
    pub fn key(&self) -> String {
        self.id().to_string()
    }
    pub fn name(&self) -> &str {
        match self {
            Self::Folder(f) => &f.name,
            Self::File(f) => &f.name,
        }
    }

    pub fn created_at(&self) -> DateTime<Utc> {
        match self {
            Self::Folder(f) => f.created_at,
            Self::File(f) => f.created_at,
        }
    }

    pub fn visibility(&self) -> &Visibility {
        match self {
            Self::Folder(f) => &f.visibility,
            Self::File(f) => &f.visibility,
        }
    }

    pub fn status(&self) -> &ObjectStatus {
        match self {
            Self::Folder(f) => &f.status,
            Self::File(f) => &f.status,
        }
    }

    pub fn bucket_name(&self) -> String {
        match self {
            Self::Folder(f) => f.bucket_name(),
            Self::File(f) => f.bucket_name(),
        }
    }
}
impl From<FolderRecord> for FileSystemObject {
    fn from(value: FolderRecord) -> Self {
        Self::Folder(value)
    }
}
impl From<FileRecord> for FileSystemObject {
    fn from(value: FileRecord) -> Self {
        Self::File(value)
    }
}
#[derive(Debug, Deserialize, Serialize)]
pub struct DownloadTokenData {
    #[serde(flatten)]
    pub object_d: FileSystemObject,
    pub ip_address: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, sqlx::Type, Hash)]
#[serde(rename_all = "lowercase")]
#[sqlx(type_name = "text", rename_all = "lowercase")]
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
pub enum CleanupStrategy {
    Hash { token: String }, // HDEL user_key token
    Counter,                // DECR ip_key
}

#[derive(Debug, Clone)]
pub struct CleanupGuard {
    redis_pool: deadpool_redis::Pool,
    user_key: String,
    strategy: CleanupStrategy,
}

impl CleanupGuard {
    pub fn hash(pool: deadpool_redis::Pool, token: Uuid, user_key: String) -> Self {
        Self {
            redis_pool: pool,
            user_key,
            strategy: CleanupStrategy::Hash {
                token: token.to_string(),
            },
        }
    }

    pub fn counter(pool: deadpool_redis::Pool, ip_key: String) -> Self {
        Self {
            redis_pool: pool,
            user_key: ip_key,
            strategy: CleanupStrategy::Counter,
        }
    }
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        let pool = self.redis_pool.clone();
        let user_key = self.user_key.clone();
        let strategy = self.strategy.clone();

        tokio::spawn(async move {
            match get_redis_con(&pool).await {
                Ok(mut con) => {
                    let result = match &strategy {
                        CleanupStrategy::Hash { token } => con
                            .hdel(&user_key, token)
                            .await
                            .map_err(CRedisError::Connection),
                        CleanupStrategy::Counter => {
                            // floor at 0 to avoid negative counts
                            redis::Script::new(
                                r#"
                                local v = redis.call('GET', KEYS[1])
                                if v and tonumber(v) > 0 then
                                    redis.call('DECR', KEYS[1])
                                end
                                return 1
                            "#,
                            )
                            .key(&user_key)
                            .invoke_async(&mut con)
                            .await
                            .map_err(CRedisError::Connection)
                        }
                    };
                    match result {
                        Err(e) => warn!(error = %e, "Failed to cleanup download token"),
                        _ => info!(key = %user_key, "Download token cleaned up"),
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
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq, FromRow)]
pub struct FileRecord {
    pub id: Uuid,
    pub parent_id: Uuid,
    pub owner_id: Uuid,
    pub name: String,
    pub size: i64,
    pub etag: String,
    pub mime_type: String,
    pub last_modified: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub metadata: Option<serde_json::Value>,
    pub status: ObjectStatus,
    pub visibility: Visibility,
    pub checksum: Option<String>,
}

impl FileRecord {
    pub fn new(owner_id: Uuid, parent_id: Uuid, name: String) -> Self {
        let date = Utc::now();
        Self {
            id: Uuid::new_v4(),
            owner_id,
            parent_id,
            name,
            created_at: date,
            last_modified: date,
            ..Default::default()
        }
    }
    pub fn normalize_dates(&mut self) {
        self.last_modified = self.last_modified.trunc_subsecs(6);
        self.created_at = self.created_at.trunc_subsecs(6);
        self.deleted_at = self.deleted_at.map(|t| t.trunc_subsecs(6));
    }
    pub fn key(&self) -> String {
        self.id.to_string()
    }
    pub fn bucket_name(&self) -> String {
        self.owner_id.to_string()
    }
    pub fn size(&mut self, s: i64) {
        self.size = s;
    }
    pub fn name(&mut self, name: impl Into<String>) {
        self.name = name.into();
    }
    pub fn etag(&mut self, e: impl Into<String>) {
        self.etag = e.into();
    }
    pub fn mime_type(&mut self, m: impl Into<String>) {
        self.mime_type = m.into();
    }
    pub fn last_modified(&mut self, ldate: DateTime<Utc>) {
        self.last_modified = ldate;
    }
    pub fn created_at(&mut self, cat: DateTime<Utc>) {
        self.created_at = cat;
    }
    pub fn visibility(&mut self, v: Visibility) {
        self.visibility = v;
    }

    pub fn status(&mut self, s: ObjectStatus) {
        self.status = s;
    }
    pub fn checksum(&mut self, c: &str) {
        self.checksum = Some(c.into());
    }
    pub fn add_metadata(&mut self, m: Value) -> bool {
        if let Some(v) = self.metadata.as_mut() {
            return v.as_array_mut().is_some_and(|a| {
                a.push(m);
                true
            });
        }
        self.metadata = Some(serde_json::Value::from([m]));
        true
    }
}
impl IntoResponse for FileRecord {
    fn into_response(self) -> axum::response::Response {
        Json(self).into_response()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq, FromRow)]
pub struct FolderRecord {
    pub id: Uuid,
    pub parent_id: Option<Uuid>, // folder
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub owner_id: Uuid,
    pub copying_children_count: i32,
    pub deleted_at: Option<DateTime<Utc>>,
    pub status: ObjectStatus,
    pub visibility: Visibility,
}
impl FolderRecord {
    pub fn new(owner_id: Uuid, parent_id: Option<Uuid>, name: String) -> Self {
        let date = Utc::now();
        let f_id = Uuid::new_v4();
        Self {
            id: f_id,
            owner_id,
            parent_id,
            name,
            created_at: date,
            ..Default::default()
        }
    }
    pub fn normalize_dates(&mut self) {
        self.created_at = self.created_at.trunc_subsecs(6);
        self.deleted_at = self.deleted_at.map(|t| t.trunc_subsecs(6));
    }
    pub fn bucket_name(&self) -> String {
        self.owner_id.to_string()
    }

    pub fn name(&mut self, name: impl Into<String>) {
        self.name = name.into();
    }

    pub fn created_at(&mut self, cat: DateTime<Utc>) {
        self.created_at = cat;
    }
    pub fn visibility(&mut self, v: Visibility) {
        self.visibility = v;
    }

    pub fn status(&mut self, s: ObjectStatus) {
        self.status = s;
    }
}
impl IntoResponse for FolderRecord {
    fn into_response(self) -> axum::response::Response {
        Json(self).into_response()
    }
}

#[derive(Debug, Deserialize)]
pub struct ObjectKindQuery {
    pub kind: ObjectKind,
}
#[derive(Debug, Deserialize, FromRow)]
pub struct FileDownload {
    pub file_id: Uuid,
    pub zip_path: String,
}
impl FileDownload {
    pub fn key(&self) -> String {
        self.file_id.to_string()
    }
    pub fn zip_path_ref(&self) -> &str {
        &self.zip_path
    }
}
#[derive(Debug, sqlx::FromRow, Derivative, Serialize, Deserialize)]
#[derivative(Hash, PartialEq, Eq)]
pub struct FolderChild {
    #[derivative(Hash, PartialEq)]
    pub id: Uuid,
    pub kind: ObjectKind,
}
#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct FolderShared {
    pub id: Uuid,
    pub parent_id: Option<Uuid>, // folder
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub children: sqlx::types::Json<Vec<FolderChild>>,
}
impl From<&FolderRecord> for FolderShared {
    fn from(value: &FolderRecord) -> Self {
        Self {
            id: value.id,
            parent_id: value.parent_id,
            name: value.name.to_string(),
            created_at: value.created_at,
            children: vec![].into(),
        }
    }
}
impl IntoResponse for FolderShared {
    fn into_response(self) -> axum::response::Response {
        Json(self).into_response()
    }
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct FileShared {
    pub id: Uuid,
    pub parent_id: Uuid,
    pub name: String,
    pub size: i64,
    pub etag: String,
    pub mime_type: String,
    pub last_modified: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}
impl FileShared {
    pub fn key(&self) -> String {
        self.id.to_string()
    }
}
impl From<&FileRecord> for FileShared {
    fn from(value: &FileRecord) -> Self {
        Self {
            id: value.id,
            parent_id: value.parent_id,
            name: value.name.to_string(),
            size: value.size,
            mime_type: value.mime_type.to_string(),
            created_at: value.created_at,
            etag: value.etag.to_string(),
            last_modified: value.last_modified,
        }
    }
}
impl IntoResponse for FileShared {
    fn into_response(self) -> axum::response::Response {
        Json(self).into_response()
    }
}
pub struct FileStream {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub name: String,
    pub size: i64,
    pub etag: String,
    pub mime_type: String,
}

impl FileStream {
    pub fn from_file_shared(f_sh: FileShared, owner_id: Uuid) -> Self {
        Self {
            id: f_sh.id,
            etag: f_sh.etag,
            name: f_sh.name,
            size: f_sh.size,
            mime_type: f_sh.mime_type,
            owner_id,
        }
    }
}
impl From<&FileRecord> for FileStream {
    fn from(value: &FileRecord) -> Self {
        Self {
            id: value.id,
            owner_id: value.owner_id,
            name: value.name.to_string(),
            size: value.size,
            etag: value.etag.to_string(),
            mime_type: value.mime_type.to_string(),
        }
    }
}
