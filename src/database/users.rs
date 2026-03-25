use crate::{DatabaseError, FileId, FolderRecord, User, UserProfile, UserStorageInfo};

use anyhow::anyhow;
use sqlx::{
    postgres::{PgPool, PgQueryResult},
    {Postgres, Transaction},
};
use tracing::{debug, error};
use uuid::Uuid;
static DELETE_ACCOUNT_QUERY: &str = include_str!("../../db_queries/delete_account.sql");

/// Increments a user’s `storage_used_bytes` counter by the given size, and
/// returns the number of affected rows (0 if the user does not exist).
pub async fn increment_storage_used_for_user(
    con: &PgPool,
    user_id: Uuid,
    size: i64,
) -> Result<u64, DatabaseError> {
    let r = sqlx::query!(
        r#"
        UPDATE users SET storage_used_bytes=storage_used_bytes+$1 WHERE id=$2
        "#,
        size,
        user_id
    )
    .execute(con)
    .await
    .inspect_err(|e| error!("failed to increment storage for a user: {e}"))?;
    Ok(r.rows_affected())
}
/// Updates a user’s `storage_quota_bytes` (maximum allowed storage) and
/// returns the number of rows affected so callers can detect missing users.
pub async fn update_user_maximum_storage(
    con: &PgPool,
    user_id: Uuid,
    b: i64,
) -> Result<u64, DatabaseError> {
    let r = sqlx::query!(
        r#"UPDATE users SET storage_quota_bytes=$1 WHERE id=$2"#,
        b,
        user_id
    )
    .execute(con)
    .await
    .inspect(|e| error!("failed to update user maximum storage: {e:?}"))?;
    Ok(r.rows_affected())
}
/// Creates a new user together with its root folder in a single
/// transaction by:
/// 1. Inserting the `FolderRecord` into `folders`.
/// 2. Inserting the `User` into `users` with `root_folder` pointing to
///    that folder id.
/// 3. Translating unique email violations into `DatabaseError::Duplicate`
///    and any other failure into `DatabaseError::Connection`.
pub async fn insert_user_with_root_folder(
    user: &User,
    folder: &FolderRecord,
    db_pool: &PgPool,
) -> Result<(), DatabaseError> {
    let mut tx: Transaction<'_, Postgres> =
        db_pool.begin().await.map_err(DatabaseError::Connection)?;

    // insert folder first (we need its id for users.root_folder)
    sqlx::query!(
        r#"INSERT INTO folders (id, owner_id, parent_id, name, created_at)
           VALUES ($1, $2, $3, $4, $5)"#,
        folder.id,
        folder.owner_id,
        folder.parent_id,
        folder.name,
        folder.created_at,
    )
    .execute(&mut *tx)
    .await
    .map_err(DatabaseError::Connection)?;

    // insert user referencing folder.id
    sqlx::query!(
        r#"INSERT INTO users
           (id, username, email, password_hash, created_at,
            storage_quota_bytes, storage_used_bytes, root_folder)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8)"#,
        user.id,
        user.username,
        user.email,
        user.password_hash,
        user.created_at,
        user.storage_quota_bytes,
        user.storage_used_bytes,
        folder.id, // set root_folder here
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        e.as_database_error()
            .filter(|db_err| db_err.constraint() == Some("users_email_key"))
            .map(|_| DatabaseError::Duplicate)
            .unwrap_or(DatabaseError::Connection(e))
    })?;

    tx.commit().await.map_err(DatabaseError::Connection)?;

    Ok(())
}

/// Fetches a full user account by email for authentication flows by:
/// 1. Querying `users` for id, root_folder, username, email,
///    password_hash, created_at, storage quota and usage.
/// 2. Returning `DatabaseError::NotFound` when no user has that email.
pub async fn fetch_account_info(con: &PgPool, email: &str) -> Result<User, DatabaseError> {
    debug!(email = email, "searching user account by using email.");

    sqlx::query_as!(
        User,
        "SELECT id,root_folder, username, email, password_hash, created_at,
                storage_quota_bytes, storage_used_bytes
         FROM users WHERE email = $1",
        email
    )
    .fetch_optional(con)
    .await
    .inspect_err(|e| error!("database error: {}", e))? // connection error propogation
    .ok_or(DatabaseError::NotFound(anyhow!(
        "failed to fetch account information"
    )))
    .inspect_err(|e| error!("{}", e))
    // if user not found !!
}
/// Fetches a lightweight `UserProfile` for a given user id, returning
/// `Ok(Some(profile))` when found or `Ok(None)` when the user does not
/// exist.
pub async fn fetch_profile_info(
    con: &PgPool,
    user_id: Uuid,
) -> Result<Option<UserProfile>, DatabaseError> {
    let v = sqlx::query_as!(
        UserProfile,
        r#"
        SELECT id,root_folder, username, email, created_at,
        storage_quota_bytes, storage_used_bytes
        FROM users
        WHERE id=$1
        "#,
        user_id
    )
    .fetch_optional(con)
    .await
    .inspect_err(|e| error!("failed to obtain user profile info: {e}"))?;
    Ok(v)
}
/// Checks if an account with the given email exists and returns its user
/// id if present, or `None` otherwise; used for signup and change‑email
/// validation.
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
/// Deletes a user account and all associated objects using a single SQL
/// script, returning the ids of all files that should be deleted from
/// object storage (skipping any `NULL` placeholders).
pub async fn delete_account_db(con: &PgPool, user_id: Uuid) -> Result<Vec<Uuid>, DatabaseError> {
    let res = sqlx::query_as::<_, FileId>(DELETE_ACCOUNT_QUERY)
        .bind(user_id)
        .fetch_all(con)
        .await
        .inspect_err(|e| error!("failed to delete user with all its associated objects: {e}"))?;
    Ok(res.into_iter().filter_map(|v| v.id).collect())
}
/// Fetches a user’s email address by id, returning `Ok(Some(email))` when
/// found or `Ok(None)` when no such user exists.
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
/// Updates a user’s email address and maps unique constraint violations on
/// `users_email_key` to `DatabaseError::Duplicate`, returning the raw
/// `PgQueryResult` on success.
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
/// Updates a user’s password hash for the given id and returns the
/// underlying `PgQueryResult` so callers can verify that exactly one row
/// was updated.
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
/// Updates the username for a user and returns the canonical username
/// value as stored in the database (e.g., after any DB‑side normalization).
pub async fn update_account_username(
    con: &PgPool,
    user_id: Uuid,
    username: &str,
) -> Result<String, DatabaseError> {
    let v = sqlx::query!(
        r#"
        UPDATE users SET username=$1 WHERE id=$2
        RETURNING username
        "#,
        username,
        user_id
    )
    .fetch_one(con)
    .await
    .inspect_err(|e| error!("failed to update username: {e}"))?;
    Ok(v.username)
}

/// Returns storage quota and current usage for a user as a
/// `UserStorageInfo` struct, used for both enforcement and UI display.
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
    .await
    .inspect_err(|e| error!("failed to fetch user storage info: {}", e))?)
}
