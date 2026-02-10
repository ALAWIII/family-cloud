use std::sync::OnceLock;

use sqlx::postgres::{PgPool, PgPoolOptions, PgQueryResult};
use tracing::{Level, debug, error, instrument};
use uuid::Uuid;

use crate::{
    DatabaseConfig, DatabaseError, ObjectDownload, ObjectRecord, ObjectStatus, RustFSError, User,
    UserStorageInfo,
};

static DB_POOL: OnceLock<PgPool> = OnceLock::new();

#[instrument(skip_all,ret(level=Level::DEBUG),fields(
    init_id=%Uuid::new_v4(),
    db_name=db.db_name,
    host=db.host,
    port=db.port,
    user_name=db.user_name,
))]
pub async fn init_db(db: &DatabaseConfig) -> Result<(), DatabaseError> {
    debug!("configuring and initializing the database.");
    let pool = PgPoolOptions::new()
        .max_connections(20)
        .connect(&db.url())
        .await
        .inspect_err(|e| error!("failed to establish connection to database: {}", e))?;
    DB_POOL
        .set(pool)
        .map_err(|_| DatabaseError::PoolAlreadyInitialized)
        .inspect_err(|e| error!("{}", e))?;
    debug!("establishing database connection successfully");
    Ok(())
}
pub fn get_db() -> Result<PgPool, DatabaseError> {
    debug!("trying to get a reference of database pool connection");
    DB_POOL
        .get()
        .ok_or(DatabaseError::PoolNotInitialized)
        .inspect_err(|e| error!("{}", e))
        .cloned()
}

pub async fn insert_new_account(user: &User, db_pool: &PgPool) -> Result<(), DatabaseError> {
    debug!(
    user_id=%user.id,
    user_name=user.username,
    email=user.email,
    "inserting new account user information into database");
    sqlx::query!(
        "INSERT INTO users (id, username, email, password_hash, created_at, storage_quota_bytes, storage_used_bytes)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
        user.id,
        user.username,
        user.email,
        user.password_hash,
        user.created_at,
        user.storage_quota_bytes ,
        user.storage_used_bytes
    )
    .execute(db_pool)
    .await.map_err(|e|{
        e.as_database_error()
            .filter(|db_err|
                db_err.constraint()==Some("users_email_key"))
            .map(|_|DatabaseError::Duplicate)
            .unwrap_or(DatabaseError::Connection(e))
            })
    .inspect_err(|e| error!("{}", e))?;
    debug!("successfully inserting new user");
    Ok(())
}
/// searching for a user by its email ,
///
/// # Error
/// If the email not found : DatabaseError::NotFound
///
/// otherwise : DatabaseError::Connection(e)
pub async fn fetch_account_info(con: &PgPool, email: &str) -> Result<User, DatabaseError> {
    debug!(email = email, "searching user account by using email.");

    sqlx::query_as!(
        User,
        "SELECT id, username, email, password_hash, created_at,
                storage_quota_bytes, storage_used_bytes
         FROM users WHERE email = $1",
        email
    )
    .fetch_optional(con)
    .await
    .inspect_err(|e| error!("database error: {}", e))? // connection error propogation
    .ok_or(DatabaseError::NotFound)
    .inspect_err(|e| error!("{}", e))
    // if user not found !!
}

/// Check if email exists/verified and stored in database. (returns user_id)
pub async fn is_account_exist(con: &PgPool, email: &str) -> Result<Option<Uuid>, DatabaseError> {
    debug!(
        email = email,
        "searching for account existence by email : {}.", email
    );

    Ok(
        sqlx::query_scalar!("SELECT id FROM users WHERE email = $1", email)
            .fetch_optional(con)
            .await
            .inspect_err(|e| error!("database error when searching for id by email : {}", e))?,
    )
}

pub async fn fetch_email_by_id(con: &PgPool, id: Uuid) -> Result<Option<String>, DatabaseError> {
    debug!(user_id=%id,"fetching email by user id.");
    Ok(
        sqlx::query_scalar!("select email from users where id=$1", id)
            .fetch_optional(con)
            .await
            .inspect_err(|e| {
                error!("database error when searching for email by user id : {}", e)
            })?,
    )
}

pub async fn update_account_email(
    con: &PgPool,
    id: Uuid,
    email: &str,
) -> Result<PgQueryResult, DatabaseError> {
    debug!(user_id=%id,email=email,"updating user account email.");
    sqlx::query!("UPDATE users SET email=$2 where id=$1", id, email)
        .execute(con)
        .await
        .map_err(|e| {
            e.as_database_error()
                .filter(|db_err| db_err.constraint() == Some("users_email_key"))
                .map(|_| DatabaseError::Duplicate)
                .unwrap_or(DatabaseError::Connection(e))
        })
        .inspect_err(|e| error!("error updating account email : {}", e))
}
/// Update password
pub async fn update_account_password(
    con: &PgPool,
    user_id: Uuid,
    password_hash: &str,
) -> Result<PgQueryResult, DatabaseError> {
    debug!(user_id=%user_id,"updating account password");
    Ok(sqlx::query!(
        "UPDATE users SET password_hash = $2 WHERE id = $1",
        user_id,
        password_hash
    )
    .execute(con)
    .await
    .inspect_err(|e| error!("database error: {}", e))?)
}

//------------------------------------------ database object download endpoint fetch ----------------------
// FIX: Tell sqlx to treat this column as your Rust type 'ObjectStatus'
pub async fn fetch_object_info(
    con: &PgPool,
    file_id: Uuid,
    user_id: Uuid,
) -> Result<Option<ObjectDownload>, DatabaseError> {
    Ok(sqlx::query_as!(
        ObjectDownload,
        r#"
        SELECT
            id,
            user_id,
            object_key,
            is_folder,
            etag,
            status as "status:_",
            size,
            checksum_sha256
        FROM objects
        WHERE id = $1 and user_id=$2 and status='active'
        "#,
        file_id,
        user_id,
    )
    .fetch_optional(con)
    .await?)
}
// When user explicitly creates a folder
pub async fn insert_obj(con: &PgPool, obj: ObjectRecord) -> Result<PgQueryResult, DatabaseError> {
    Ok(sqlx::query(
        r#"
        INSERT INTO objects (
            id, user_id, object_key, size, etag, mime_type, last_modified,
            created_at, checksum_sha256, custom_metadata, status, visibility, is_folder
        )
        VALUES (
            $1, $2, $3, $4, $5, $6, $7,
            $8, $9, $10, $11, $12, $13
        )
        "#,
    )
    .bind(obj.id)
    .bind(obj.user_id)
    .bind(obj.object_key)
    .bind(obj.size)
    .bind(obj.etag)
    .bind(obj.mime_type)
    .bind(obj.last_modified)
    .bind(obj.created_at)
    .bind(obj.checksum_sha256)
    .bind(obj.custom_metadata)
    .bind(obj.status) // ObjectStatus works via sqlx::Type here
    .bind(obj.visibility)
    .bind(obj.is_folder)
    .execute(con)
    .await?)
}

pub async fn get_user_available_storage(
    con: &PgPool,
    user_id: Uuid,
) -> Result<UserStorageInfo, DatabaseError> {
    Ok(sqlx::query_as!(
        UserStorageInfo,
        "SELECT storage_quota_bytes,storage_used_bytes FROM users where id=$1",
        user_id
    )
    .fetch_one(con)
    .await?)
}
