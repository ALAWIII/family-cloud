use std::sync::OnceLock;

use deadpool_redis::{Config, Connection, Pool as RPool, Runtime, redis::AsyncTypedCommands};

use crate::{CRedisError, RedisConfig};

static REDIS_POOL: OnceLock<RPool> = OnceLock::new();

pub async fn init_redis_pool(rds_conf: &RedisConfig) -> Result<(), CRedisError> {
    let cfg = Config::from_url(rds_conf.url());
    let pool = cfg
        .builder()?
        .max_size(50)
        .create_timeout(Some(std::time::Duration::from_secs(5)))
        .runtime(Runtime::Tokio1)
        .build()?;

    REDIS_POOL
        .set(pool)
        .map_err(|_| CRedisError::PoolAlreadyInitialized)
}
pub fn get_redis_pool() -> Result<RPool, CRedisError> {
    REDIS_POOL
        .get()
        .ok_or(CRedisError::PoolNotInitialized)
        .cloned()
}
pub async fn get_redis_con(pool: RPool) -> Result<Connection, CRedisError> {
    Ok(pool.get().await?)
}

/// accepts key_token an hmac hashed version of the raw token , ttl (seconds) is the time to set to expire the entry in database
pub async fn store_token_redis(
    conn: &mut Connection,
    key_token: &str,
    serialized_content: &str,
    ttl: u64,
) -> Result<(), CRedisError> {
    conn.set_ex(key_token, serialized_content, ttl).await?; // Can fail Redis op , converted to CRedisError::Connection
    Ok(())
}
/// checks whether a token still exists in redis or not.
///
/// true: exists , false: does not exists
pub async fn is_token_exist(con: &mut Connection, hashed_token: &str) -> Result<bool, CRedisError> {
    Ok(con.exists(hashed_token).await?)
}

pub async fn get_verification_data(
    con: &mut Connection,
    hashed_token: &str,
) -> Result<Option<String>, CRedisError> {
    Ok(con.get(hashed_token).await?)
}
pub async fn delete_token_from_redis(
    con: &mut Connection,
    hashed_token: &str,
) -> Result<(), CRedisError> {
    con.del(hashed_token).await?;
    Ok(())
}
