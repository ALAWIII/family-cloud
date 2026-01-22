use deadpool_redis::{BuildError, ConfigError};

use thiserror::Error as TError;

#[derive(TError, Debug)]
pub enum CRedisError {
    /// Low-level Redis protocol or IO error
    #[error("Redis connection error")]
    Connection(#[from] deadpool_redis::redis::RedisError),

    /// Pool runtime failure
    #[error("Redis pool error")]
    Pool(#[from] deadpool_redis::PoolError),

    /// Pool lifecycle errors
    #[error("Redis pool not initialized")]
    PoolNotInitialized,

    #[error("Redis pool already initialized")]
    PoolAlreadyInitialized,

    /// Pool construction failure
    #[error("Redis pool build error")]
    Build(#[from] BuildError),

    /// Invalid configuration
    #[error("Redis configuration error")]
    Config(#[from] ConfigError),
}
