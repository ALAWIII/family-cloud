use lettre::address::AddressError;

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
