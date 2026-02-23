use super::*;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use config::ConfigError;
use thiserror::Error as TError;
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

    #[error("rustfs error: {0}")]
    RustFs(#[from] RustFSError),

    #[error(transparent)]
    Serialization(#[from] serde_json::Error),
    #[error(transparent)]
    Config(#[from] ConfigError),
    // -------- Domain --------
    #[error("Corrupted or malformed byte stream: {0}")]
    CorruptedByte(#[from] axum::Error),
    //--------- rustfs -------------
    #[error("Conflict")]
    Conflict,

    #[error("Bad request: {0}")]
    BadRequest(#[from] anyhow::Error),

    #[error("Unauthorized")]
    Unauthorized,
    #[error("user exceeded the limit of concurrent downloads allowed.")]
    TooManyDownloads,
    #[error("requested object is not available.")]
    NotFound,
    #[error("object was already deleted.")]
    AlreadyDeleted,
    #[error("file wanted to be uploaded was to big to fit user available capacity.")]
    ObjectTooLarge,
    #[error("file upload corrupted because mismatch in checksum!")]
    ChecksumMismatch,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        // optional: centralized logging
        // tracing::error!(error = ?self);

        let status = match self {
            // ---------- Database ----------
            ApiError::Database(db) => match db {
                DatabaseError::NotFound(_) => StatusCode::NOT_FOUND, // resource missing
                DatabaseError::Duplicate => StatusCode::CONFLICT,    // unique constraint
                DatabaseError::PoolNotInitialized
                | DatabaseError::PoolAlreadyInitialized
                | DatabaseError::Connection(_) => StatusCode::SERVICE_UNAVAILABLE, // infra
            },

            // ---------- Redis ----------
            ApiError::Redis(_) => StatusCode::SERVICE_UNAVAILABLE, // infra

            // ---------- Email ----------
            ApiError::Email(e) => match e {
                EmailError::InvalidAddress(_) => StatusCode::BAD_REQUEST, // malformed recipient
                EmailError::ClientNotInitialized
                | EmailError::ClientAlreadyInitialized
                | EmailError::EnvVar(_) => {
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
            ApiError::Serialization(_) | ApiError::Config(_) => StatusCode::INTERNAL_SERVER_ERROR,
            //---------------------
            ApiError::RustFs(_) => StatusCode::INTERNAL_SERVER_ERROR,
            // ---------- Domain helpers ----------
            ApiError::Conflict => StatusCode::CONFLICT,
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::Unauthorized => StatusCode::UNAUTHORIZED,
            ApiError::TooManyDownloads => StatusCode::TOO_MANY_REQUESTS,
            ApiError::NotFound => StatusCode::NOT_FOUND,
            ApiError::CorruptedByte(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::AlreadyDeleted => StatusCode::NO_CONTENT,
            ApiError::ObjectTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            ApiError::ChecksumMismatch => StatusCode::UNPROCESSABLE_ENTITY,
        };

        status.into_response()
    }
}
