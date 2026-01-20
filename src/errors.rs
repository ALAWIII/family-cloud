use thiserror::Error as TError;
#[derive(TError, Debug)]
pub enum CloudError {}

#[derive(TError, Debug)]
pub enum EmailError {
    #[error("SMTP transport error")]
    Transport(#[from] lettre::transport::smtp::Error),

    #[error("Failed to build email message")]
    MessageBuilder(#[from] lettre::error::Error),

    #[error("Environment variable missing: {0}")]
    EnvVar(#[from] std::env::VarError),

    #[error("Invalid port number")]
    InvalidPort(#[from] std::num::ParseIntError),

    #[error("Invalid email address: {0}")]
    InvalidAddress(String),

    #[error("Email configuration error: {0}")]
    Config(String),

    #[error("Failed to send email")]
    SendFailed,

    #[error("Mail client not initialized")]
    ClientNotInitialized,
}

#[derive(TError, Debug)]
pub enum RedisError {
    #[error("Redis connection failed")]
    Connection(#[from] deadpool_redis::redis::RedisError),

    #[error("Pool error: {0}")]
    Pool(#[from] deadpool_redis::PoolError),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Serialization failed")]
    Serialization(#[from] serde_json::Error),

    #[error("Pool not initialized")]
    PoolNotInitialized,

    #[error("Environment variable missing: {0}")]
    EnvVar(#[from] std::env::VarError),
}

#[derive(TError, Debug)]
pub enum DatabaseError {
    #[error("Database connection failed")]
    Connection(#[from] sqlx::Error),

    #[error("Environment variable missing: {0}")]
    EnvVar(#[from] std::env::VarError),

    #[error("Pool not initialized")]
    PoolNotInitialized,

    #[error("User not found")]
    UserNotFound,

    #[error("Duplicate email")]
    DuplicateEmail,

    #[error("Query failed: {0}")]
    QueryFailed(String),
}

#[derive(TError, Debug)]
pub enum CryptoError {
    #[error("Password hashing failed")]
    PasswordHash(#[from] argon2::password_hash::Error),

    #[error("JWT encoding failed")]
    JwtEncode(#[from] jsonwebtoken::errors::Error),

    #[error("Token decoding failed")]
    TokenDecode(#[from] base64::DecodeError),

    #[error("Random number generation failed")]
    RngFailed,

    #[error("HMAC secret missing")]
    HmacSecretMissing(#[from] std::env::VarError),

    #[error("Invalid token format")]
    InvalidToken,

    #[error("Password verification failed")]
    VerificationFailed,
}
