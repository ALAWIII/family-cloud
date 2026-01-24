use std::sync::OnceLock;

use sqlx::postgres::{PgPool, PgPoolOptions, PgQueryResult};
use uuid::Uuid;

use crate::{DatabaseConfig, DatabaseError, User};

static DB_POOL: OnceLock<PgPool> = OnceLock::new();

pub async fn init_db(db: &DatabaseConfig) -> Result<(), DatabaseError> {
    let pool = PgPoolOptions::new()
        .max_connections(20)
        .connect(&db.url())
        .await?;
    DB_POOL
        .set(pool)
        .map_err(|_| DatabaseError::PoolAlreadyInitialized)?;
    Ok(())
}

pub fn get_db() -> Result<PgPool, DatabaseError> {
    DB_POOL
        .get()
        .ok_or(DatabaseError::PoolNotInitialized)
        .cloned()
}
pub async fn insert_new_account(user: User, db_pool: &PgPool) -> Result<(), DatabaseError> {
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
            })?;
    Ok(())
}

pub async fn fetch_account_info(con: &PgPool, email: &str) -> Result<User, DatabaseError> {
    sqlx::query_as!(
        User,
        "SELECT id, username, email, password_hash, created_at,
                storage_quota_bytes, storage_used_bytes
         FROM users WHERE email = $1",
        email
    )
    .fetch_optional(con)
    .await? // connection error propogation
    .ok_or(DatabaseError::NotFound) // if user not found !!
}

/// Check if email exists/verified and stored in database. (returns user_id)
pub async fn is_account_exist(con: &PgPool, email: &str) -> Result<Option<Uuid>, DatabaseError> {
    Ok(
        sqlx::query_scalar!("SELECT id FROM users WHERE email = $1", email)
            .fetch_optional(con)
            .await?,
    )
}
pub async fn fetch_email_by_id(con: &PgPool, id: Uuid) -> Result<Option<String>, DatabaseError> {
    Ok(
        sqlx::query_scalar!("select email from users where id=$1", id)
            .fetch_optional(con)
            .await?,
    )
}

pub async fn update_account_email(
    con: &PgPool,
    id: Uuid,
    email: &str,
) -> Result<PgQueryResult, DatabaseError> {
    sqlx::query!("UPDATE users SET email=$2 where id=$1", id, email)
        .execute(con)
        .await
        .map_err(|e| {
            e.as_database_error()
                .filter(|db_err| db_err.constraint() == Some("users_email_key"))
                .map(|_| DatabaseError::Duplicate)
                .unwrap_or(DatabaseError::Connection(e))
        })
}
/// Update password
pub async fn update_account_password(
    con: &PgPool,
    user_id: Uuid,
    password_hash: &str,
) -> Result<PgQueryResult, DatabaseError> {
    Ok(sqlx::query!(
        "UPDATE users SET password_hash = $2 WHERE id = $1",
        user_id,
        password_hash
    )
    .execute(con)
    .await?)
}
