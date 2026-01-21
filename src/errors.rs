use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use deadpool_redis::{BuildError, ConfigError};
use hmac::digest::InvalidLength;
use lettre::address::AddressError;
use rand::rand_core::OsError;
use thiserror::Error as TError;
#[derive(TError, Debug)]
pub enum CloudError {}

#[derive(TError, Debug)]
pub enum EmailError {
    /// SMTP transport-level failure (network, TLS, auth, etc.)
    #[error("SMTP transport failure")]
    Transport(#[from] lettre::transport::smtp::Error),

    /// Invalid email message structure
    #[error("Email message build failed")]
    MessageBuilder(#[from] lettre::error::Error),

    /// Invalid email address format
    #[error("Invalid email address")]
    InvalidAddress(#[from] AddressError),

    /// Email client lifecycle errors
    #[error("Mail client already initialized")]
    ClientAlreadyInitialized,

    #[error("Mail client not initialized")]
    ClientNotInitialized,
}

//--------------------------------------

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

//----------------------------------

#[derive(TError, Debug)]
pub enum DatabaseError {
    /// Connection, timeout, protocol errors
    #[error("Database connection error")]
    Connection(#[from] sqlx::Error),

    /// Pool lifecycle
    #[error("Database pool not initialized")]
    PoolNotInitialized,

    #[error("Database pool already initialized")]
    PoolAlreadyInitialized,

    // -------- Domain-level (safe to bubble up) --------
    /// Used internally; API should normalize response
    #[error("Entity not found")]
    NotFound,

    /// Unique constraint violation
    #[error("Duplicate entry")]
    Duplicate,
}

//----------------------------------------------

#[derive(TError, Debug)]
pub enum CryptoError {
    /// Hashing or verification failure (internal)
    #[error("Password hashing failed")]
    PasswordHash(#[from] argon2::password_hash::Error),

    /// JWT encode/decode internal failure
    #[error("JWT error")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    /// Token decoding failure
    #[error("Token decoding failed")]
    TokenDecode(#[from] base64::DecodeError),

    /// Secure RNG failure (system-level)
    #[error("Random generator failure")]
    RngFailed(#[from] OsError),

    /// HMAC misconfiguration
    #[error("Invalid HMAC configuration")]
    Hmac(#[from] InvalidLength),

    // -------- Domain auth failures --------
    /// Invalid credentials / token
    #[error("Authentication failed")]
    AuthFailed,

    /// Token expired (semantic, not crypto failure)
    #[error("Token expired")]
    TokenExpired,
}

//-----------------------------------------------------------

#[derive(TError, Debug)]
pub enum ApiError {
    // -------- Infra --------
    #[error(transparent)]
    Database(#[from] DatabaseError),

    #[error(transparent)]
    Redis(#[from] CRedisError),

    #[error(transparent)]
    Email(#[from] EmailError),

    #[error(transparent)]
    Crypto(#[from] CryptoError),

    #[error(transparent)]
    Serialization(#[from] serde_json::Error),

    // -------- Domain --------
    #[error("Conflict")]
    Conflict,

    #[error("Bad request")]
    BadRequest,

    #[error("Unauthorized")]
    Unauthorized,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        // optional: centralized logging
        // tracing::error!(error = ?self);

        let status = match self {
            // ---------- Database ----------
            ApiError::Database(db) => match db {
                DatabaseError::NotFound => StatusCode::NOT_FOUND, // resource missing
                DatabaseError::Duplicate => StatusCode::CONFLICT, // unique constraint
                DatabaseError::PoolNotInitialized
                | DatabaseError::PoolAlreadyInitialized
                | DatabaseError::Connection(_) => StatusCode::SERVICE_UNAVAILABLE, // infra
            },

            // ---------- Redis ----------
            ApiError::Redis(_) => StatusCode::SERVICE_UNAVAILABLE, // infra

            // ---------- Email ----------
            ApiError::Email(e) => match e {
                EmailError::InvalidAddress(_) => StatusCode::BAD_REQUEST, // malformed recipient
                EmailError::ClientNotInitialized | EmailError::ClientAlreadyInitialized => {
                    StatusCode::INTERNAL_SERVER_ERROR // lifecycle misconfiguration
                }
                EmailError::Transport(_) | EmailError::MessageBuilder(_) => {
                    StatusCode::SERVICE_UNAVAILABLE
                } // transient network / SMTP
            },

            // ---------- Crypto ----------
            ApiError::Crypto(c) => match c {
                CryptoError::AuthFailed
                | CryptoError::TokenExpired
                | CryptoError::TokenDecode(_) => StatusCode::UNAUTHORIZED, // semantic auth errors
                CryptoError::PasswordHash(_)
                | CryptoError::Jwt(_)
                | CryptoError::RngFailed(_)
                | CryptoError::Hmac(_) => StatusCode::INTERNAL_SERVER_ERROR, // internal crypto failure
            },

            // ---------- Serialization ----------
            ApiError::Serialization(_) => StatusCode::INTERNAL_SERVER_ERROR,

            // ---------- Domain helpers ----------
            ApiError::Conflict => StatusCode::CONFLICT,
            ApiError::BadRequest => StatusCode::BAD_REQUEST,
            ApiError::Unauthorized => StatusCode::UNAUTHORIZED,
        };

        status.into_response()
    }
}
