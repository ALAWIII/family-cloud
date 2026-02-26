#[derive(Debug, thiserror::Error)]
pub enum JobError {
    #[error("{0}")]
    SharedCreation(anyhow::Error),
    #[error("{0}")]
    Postgres(anyhow::Error),
    #[error("{0}")]
    Worker(anyhow::Error),
    #[error("{0}")]
    Push(anyhow::Error),
    #[error("initalization error: {0}")]
    AlreadyInitalized(anyhow::Error),
    #[error("initalization error: {0}")]
    NotInitalized(anyhow::Error),
    #[error("{0}")]
    Send(anyhow::Error),
    #[error("{0}")]
    Receive(anyhow::Error),
    #[error("{0}")]
    DeleteBlocked(anyhow::Error),
}
