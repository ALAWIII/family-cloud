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
//--------------------------
#[derive(Debug, TError)]
#[error(transparent)]
pub struct CSerializeError(#[from] serde_json::Error);
//-----------------------------------------------------------

#[derive(TError, Debug)]
pub enum ApiError {
    #[error(transparent)]
    Database(#[from] DatabaseError),
    #[error(transparent)]
    Redis(#[from] CRedisError),
    #[error(transparent)]
    Email(#[from] EmailError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),

    #[error("Account already exists")]
    AccountExists,
    #[error("Invalid token")]
    InvalidToken,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::Database(e) => {
                // tracing::error!("Database error: {}", e);  // Log details
                (StatusCode::INTERNAL_SERVER_ERROR, "Service unavailable")
            }
            ApiError::Redis(e) => {
                // tracing::error!("Redis error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Service unavailable")
            }
            ApiError::Email(e) => {
                //  tracing::error!("Email error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Failed to send email")
            }
            ApiError::Crypto(e) => {
                // tracing::error!("Crypto error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Service unavailable")
            }
            ApiError::AccountExists => (StatusCode::CONFLICT, "Email already registered"),
            ApiError::InvalidToken => (StatusCode::BAD_REQUEST, "Invalid or expired token"),
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}
