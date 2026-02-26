use axum::Json;
use axum::response::IntoResponse;
use chrono::DateTime;
use chrono::SubsecRound;
use chrono::{NaiveDateTime, Utc};
use derivative::Derivative;
use secrecy::{ExposeSecret, SecretBox, SecretString};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;
use sqlx::prelude::FromRow;
use std::{fmt::Display, str::FromStr};
use tracing::{error, info, warn};
use uuid::Uuid;

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
#[derive(Debug, Serialize, Deserialize, sqlx::Type, PartialEq, Eq)]
#[sqlx(type_name = "object_kind_type", rename_all = "PascalCase")]
#[serde(rename_all = "lowercase")]
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
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq, FromRow)]
pub struct FileRecord {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub parent_id: Uuid,
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
        Self {
            id: Uuid::new_v4(),
            owner_id,
            parent_id,
            name,
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
    pub copying_children_count: i32,
    pub deleting_children_count: i32,
    pub owner_id: Uuid,
    pub parent_id: Option<Uuid>, // folder
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub status: ObjectStatus,
    pub visibility: Visibility,
}
impl FolderRecord {
    pub fn new(owner_id: Uuid, parent_id: Option<Uuid>, name: String) -> Self {
        let f_id = Uuid::new_v4();
        Self {
            id: f_id,
            owner_id,
            parent_id,
            name,
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
