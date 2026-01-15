use std::sync::OnceLock;

use deadpool_redis::{
    Config, Connection, Pool, Runtime,
    redis::{self, AsyncTypedCommands, RedisError},
};
use serde::Serialize;

static REDIS_POOL: OnceLock<Pool> = OnceLock::new();

pub async fn init_redis_pool() {
    let redis_url = std::env::var("REDIS_URL").expect("REDIS_URL must be set");
    let cfg = Config::from_url(redis_url);
    let pool = cfg
        .builder()
        .expect("Failed to configure redis config")
        .max_size(50)
        .create_timeout(Some(std::time::Duration::from_secs(5)))
        .runtime(Runtime::Tokio1)
        .build()
        .expect("Falied to build redis configs");
    REDIS_POOL
        .set(pool)
        .expect("Falied to set redis connection pool");
}

pub fn get_redis_pool() -> Pool {
    REDIS_POOL
        .get()
        .expect("Failed to get redis connection pool")
        .clone()
}

/// accepts key_token an hmac hashed version of the raw token , ttl (seconds) is the time to set to expire the entry in database
pub async fn store_token_redis<T: Serialize>(
    mut conn: Connection,
    key_token: String,
    content: &T,
    ttl: u64,
) -> Result<(), RedisError> {
    let content = serde_json::to_string(content).expect("Faield to convert to json string");
    conn.set_ex(key_token, content, ttl).await
}

pub async fn search_redis_for_token(hashed_token: &str, mut con: Connection) -> Option<String> {
    con.get(hashed_token).await.unwrap()
}
pub async fn remove_verified_account_from_redis(
    mut con: Connection,
    hashed_token: &str,
) -> Result<(), RedisError> {
    con.del(hashed_token).await?;
    Ok(())
}
