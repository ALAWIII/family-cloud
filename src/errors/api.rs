use super::*;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
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
