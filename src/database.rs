use std::sync::OnceLock;

use sqlx::postgres::{PgPool, PgPoolOptions};

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

pub async fn search_for_user_by_email(con: &PgPool, email: &str) -> Option<User> {
    sqlx::query_as!(User, "select * from users where email=$1", email)
        .fetch_optional(con)
        .await
        .ok()
        .flatten()
}
