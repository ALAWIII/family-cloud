use std::sync::OnceLock;

use crate::{CRedisError, RedisConfig};
use deadpool_redis::{Config, Connection, Pool as RPool, Runtime, redis::AsyncTypedCommands};
use tracing::{debug, error, instrument};
use uuid::Uuid;

static REDIS_POOL: OnceLock<RPool> = OnceLock::new();

#[instrument(skip_all,fields(
    init_id=%Uuid::new_v4(),
    redis_host = %rds_conf.host,
    redis_port = rds_conf.port
))]
pub async fn init_redis_pool(rds_conf: &RedisConfig) -> Result<(), CRedisError> {
    debug!("Initializing Redis pool");
    let cfg = Config::from_url(rds_conf.url());
    let pool = cfg
        .builder()
        .inspect_err(|e| error!("Failed to create Redis config builder: {}", e))?
        .max_size(50)
        .create_timeout(Some(std::time::Duration::from_secs(5)))
        .runtime(Runtime::Tokio1)
        .build()
        .inspect_err(|e| error!("Failed to build Redis pool: {}", e))?;

    REDIS_POOL
        .set(pool)
        .map_err(|_| CRedisError::PoolAlreadyInitialized)
        .inspect_err(|e| error!("Failed to set Redis pool: {}", e))?;
    debug!("Redis pool initialized successfully");
    Ok(())
}
pub fn get_redis_pool() -> Result<RPool, CRedisError> {
    debug!("Retrieving Redis pool from static storage");
    REDIS_POOL
        .get()
        .ok_or(CRedisError::PoolNotInitialized)
        .inspect_err(|e| error!("failed to get redis pool: {}", e))
        .cloned()
}
pub async fn get_redis_con(pool: RPool) -> Result<Connection, CRedisError> {
    debug!("Acquiring Redis connection from pool");
    Ok(pool
        .get()
        .await
        .inspect_err(|e| error!("Failed to acquire Redis connection: {}", e))?)
}

/// accepts key_token an hmac hashed version of the raw token , ttl (seconds) is the time to set to expire the entry in database
pub async fn store_token_redis(
    conn: &mut Connection,
    key_token: &str,
    serialized_content: &str,
    ttl: u64,
) -> Result<(), CRedisError> {
    debug!("Storing token in Redis with TTL={} seconds", ttl);
    conn.set_ex(key_token, serialized_content, ttl)
        .await
        .inspect_err(|e| error!("Failed to store token in Redis: {}", e))?; // Can fail Redis op , converted to CRedisError::Connection
    Ok(())
}
/// checks whether a token still exists in redis or not.
///
/// true: exists , false: does not exists
pub async fn is_token_exist(con: &mut Connection, hashed_token: &str) -> Result<bool, CRedisError> {
    debug!("Checking if token exists in Redis");
    Ok(con
        .exists(hashed_token)
        .await
        .inspect_err(|e| error!("Failed to check token existence: {}", e))?)
}

/// Retrieves verification data for token from Redis
pub async fn get_verification_data(
    con: &mut Connection,
    hashed_token: &str,
) -> Result<Option<String>, CRedisError> {
    debug!("Retrieving verification data from Redis");
    Ok(con
        .get(hashed_token)
        .await
        .inspect_err(|e| error!("Failed to retrieve verification data: {}", e))?)
}
/// Deletes token from Redis
pub async fn delete_token_from_redis(
    con: &mut Connection,
    hashed_token: &str,
) -> Result<(), CRedisError> {
    debug!("Deleting token from Redis");
    con.del(hashed_token)
        .await
        .inspect_err(|e| error!("Failed to delete token from Redis: {}", e))?;

    Ok(())
}
