use std::sync::OnceLock;

use crate::{CRedisError, RedisConfig};
use deadpool_redis::{Config, Connection, Pool as RPool, Runtime, redis::AsyncTypedCommands};
use tracing::{debug, error, instrument};
use uuid::Uuid;

static REDIS_POOL: OnceLock<RPool> = OnceLock::new();

/// Initializes a global Redis connection pool once by:
/// 1. Building a `deadpool_redis::Pool` from `RedisConfig` with max size,
///    timeout, and Tokio runtime.
/// 2. Storing it in a `OnceLock<RPool>`, returning
///    `CRedisError::PoolAlreadyInitialized` if called more than once.
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
/// Returns a clone of the globally initialized Redis pool, or
/// `CRedisError::PoolNotInitialized` if `init_redis_pool` has not run yet.
pub fn get_redis_pool() -> Result<RPool, CRedisError> {
    debug!("Retrieving Redis pool from static storage");
    REDIS_POOL
        .get()
        .ok_or(CRedisError::PoolNotInitialized)
        .inspect_err(|e| error!("failed to get redis pool: {}", e))
        .cloned()
}
/// Acquires a single Redis `Connection` from the given pool, mapping pool
/// acquisition failures into `CRedisError::Connection`.
pub async fn get_redis_con(pool: &RPool) -> Result<Connection, CRedisError> {
    debug!("Acquiring Redis connection from pool");
    Ok(pool
        .get()
        .await
        .inspect_err(|e| error!("Failed to acquire Redis connection: {}", e))?)
}

/// Stores a serialized token payload in Redis with a TTL by:
/// 1. Writing `serialized_content` under `key_token` using `SETEX`.
/// 2. Setting expiry to `ttl` seconds so verification tokens are
///    automatically removed after their lifetime.
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
/// Checks whether a given token key exists in Redis, returning `true` if
/// present and `false` otherwise, using the `EXISTS` command.
pub async fn is_token_exist(con: &mut Connection, hashed_token: &str) -> Result<bool, CRedisError> {
    debug!("Checking if token exists in Redis");
    Ok(con
        .exists(hashed_token)
        .await
        .inspect_err(|e| error!("Failed to check token existence: {}", e))?)
}

/// Retrieves the raw serialized value associated with a token key from
/// Redis using `GET`, returning `Ok(Some(String))` when found or
/// `Ok(None)` when no entry exists.
pub async fn fetch_redis_data(
    con: &mut Connection,
    key_token: &str,
) -> Result<Option<String>, CRedisError> {
    debug!("Retrieving verification data from Redis");
    Ok(con
        .get(key_token)
        .await
        .inspect_err(|e| error!("Failed to retrieve verification data: {}", e))?)
}
/// Deletes a token key from Redis using `DEL` and returns the number of
/// keys removed (0 if already missing), so callers can detect invalid or
/// reused tokens.
pub async fn delete_token_from_redis(
    con: &mut Connection,
    hashed_token: &str,
) -> Result<usize, CRedisError> {
    debug!("Deleting token from Redis");
    let count = con
        .del(hashed_token)
        .await
        .inspect_err(|e| error!("Failed to delete token from Redis: {}", e))?;

    Ok(count)
}
