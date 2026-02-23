use thiserror::Error as TError;
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
    #[error("Database entity,user or email not found: {0}")]
    NotFound(anyhow::Error),

    /// Unique constraint violation
    #[error("Database duplicate entry,account or email")]
    Duplicate,
}
