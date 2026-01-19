use std::sync::OnceLock;

use sqlx::postgres::{PgPool, PgPoolOptions, PgQueryResult};
use uuid::Uuid;

use crate::User;

static DB_POOL: OnceLock<PgPool> = OnceLock::new();

pub async fn init_db() -> Result<(), sqlx::Error> {
    let url = std::env::var("DATABASE_URL").expect("Failed to obtain the DATABASE_URL");

    let pool = PgPoolOptions::new()
        .max_connections(20)
        .connect(&url)
        .await?;
    DB_POOL
        .set(pool)
        .expect("Failed to set the db connection pool");
    Ok(())
}

pub fn get_db() -> PgPool {
    DB_POOL
        .get()
        .expect("the underlying database connection is not established yet")
        .clone()
}
pub async fn insert_new_account(user: User, db_pool: &PgPool) -> Result<(), sqlx::Error> {
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
    .await?;

    Ok(())
}

pub async fn fetch_account_info(con: &PgPool, email: &str) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as!(
        User,
        "SELECT id, username, email, password_hash, created_at,
                storage_quota_bytes, storage_used_bytes
         FROM users WHERE email = $1",
        email
    )
    .fetch_optional(con)
    .await
}

// Check if email exists (returns user_id)
pub async fn is_account_exist(con: &PgPool, email: &str) -> Result<Option<Uuid>, sqlx::Error> {
    sqlx::query_scalar!("SELECT id FROM users WHERE email = $1", email)
        .fetch_optional(con)
        .await
}
pub async fn fetch_email_by_id(con: &PgPool, id: Uuid) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar!("select email from users where id=$1", id)
        .fetch_optional(con)
        .await
}

pub async fn update_account_email(
    con: &PgPool,
    id: Uuid,
    email: &str,
) -> Result<PgQueryResult, sqlx::Error> {
    sqlx::query!("UPDATE users SET email=$2 where id=$1", id, email)
        .execute(con)
        .await
}
/// Update password
pub async fn update_account_password(
    con: &PgPool,
    user_id: Uuid,
    password_hash: &str,
) -> Result<PgQueryResult, sqlx::Error> {
    sqlx::query!(
        "UPDATE users SET password_hash = $2 WHERE id = $1",
        user_id,
        password_hash
    )
    .execute(con)
    .await
}
