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
    #[error("Entity not found")]
    NotFound,

    /// Unique constraint violation
    #[error("Duplicate entry")]
    Duplicate,
}
