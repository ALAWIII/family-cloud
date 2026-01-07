use std::sync::OnceLock;

use sqlx::postgres::{PgPool, PgPoolOptions};

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

pub fn get_db() -> &'static PgPool {
    DB_POOL
        .get()
        .expect("the underlying database connection is not established yet")
}
