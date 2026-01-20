use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use deadpool_redis::{BuildError, ConfigError};
use hmac::digest::InvalidLength;
use lettre::address::AddressError;
use rand::rand_core::OsError;
use serde_json::json;
use thiserror::Error as TError;
#[derive(TError, Debug)]
pub enum CloudError {}

#[derive(TError, Debug)]
pub enum EmailError {
    #[error("SMTP transport error")]
    Transport(#[from] lettre::transport::smtp::Error),

    #[error("Failed to build email message")]
    MessageBuilder(#[from] lettre::error::Error),

    #[error("Invalid email address: {0}")]
    InvalidAddress(#[from] AddressError),

    #[error("Mail client already initialized")]
    ClientAlreadyInitialized,
    #[error("Mail client not initialized")]
    ClientNotInitialized,
    //------------------ will be used later in config files instead of env variables
    #[error("Invalid port number")]
    InvalidPort(#[from] std::num::ParseIntError),
    #[error("Environment variable missing: {0}")]
    EnvVar(#[from] std::env::VarError),
    #[error("Email configuration error: {0}")]
    Config(String),
}
//--------------------------------------
#[derive(TError, Debug)]
pub enum CRedisError {
    #[error("Redis connection failed: {0}")]
    Connection(#[from] deadpool_redis::redis::RedisError),

    #[error("Redis Pool error: {0}")]
    Pool(#[from] deadpool_redis::PoolError),

    #[error("Redis Serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Redis Pool not initialized")]
    PoolNotInitialized,

    #[error("Redis Pool already initialized")]
    PoolAlreadyInitialized,

    #[error("Redis Pool Building error")]
    Build(#[from] BuildError),
    //-------------------------- need refinement
    #[error("Redis configuration error")]
    Config(#[from] ConfigError),
    #[error("Environment variable missing: {0}")]
    EnvVar(#[from] std::env::VarError),
}
//----------------------------------
#[derive(TError, Debug)]
pub enum DatabaseError {
    #[error("Database connection failed")]
    Connection(#[from] sqlx::Error),

    #[error("Database Pool not initialized")]
    PoolNotInitialized,

    #[error("Database Pool already initialized")]
    PoolAlreadyInitialized,

    #[error("User not found")]
    UserNotFound,

    #[error("Duplicate email")]
    DuplicateEmail,
    //------------------- need refinement
    #[error("Query failed: {0}")]
    QueryFailed(String),

    #[error("Environment variable missing: {0}")]
    EnvVar(#[from] std::env::VarError),
}
//----------------------------------------------
#[derive(TError, Debug)]
pub enum CryptoError {
    #[error("Password hashing failed")]
    PasswordHash(#[from] argon2::password_hash::Error),

    #[error("JWT encoding failed")]
    JwtEncode(#[from] jsonwebtoken::errors::Error),

    #[error("Token decoding failed")]
    TokenDecode(#[from] base64::DecodeError),

    #[error("Random number generation failed")]
    RngFailed(#[from] OsError),
    #[error("HMAC can take secret of any length (panic only on zero-length)")]
    Hmac(#[from] InvalidLength),

    //----------------------------- need refinement
    #[error("Invalid token format")]
    InvalidToken,

    #[error("Password verification failed")]
    VerificationFailed,
    #[error("HMAC secret missing")]
    HmacSecretMissing(#[from] std::env::VarError),
}
