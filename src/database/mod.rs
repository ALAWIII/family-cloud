mod objects;
mod users;
pub use objects::*;
use std::sync::OnceLock;
pub use users::*;

use crate::{DatabaseConfig, DatabaseError};
use sqlx::postgres::{PgPool, PgPoolOptions};
use tracing::{Level, debug, error, instrument};
use uuid::Uuid;

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
        .max_connections(200)
        .connect(&db.url())
        .await
        .inspect_err(|e| error!("failed to establish connection to database: {}", e))?;

    sqlx::migrate!("./migrations")
        .set_ignore_missing(true)
        .run(&pool.clone())
        .await
        .inspect_err(|e| error!("{e}"))?;
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
