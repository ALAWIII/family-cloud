use hmac::digest::InvalidLength;

use rand::rand_core::OsError;
use thiserror::Error as TError;

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
