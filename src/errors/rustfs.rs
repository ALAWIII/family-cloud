#[derive(Debug, thiserror::Error)]
pub enum RustFSError {
    #[error("Rustfs Client already initalized.")]
    AlreadyInit,
    #[error("Failed to get the RustFS connection,maybe not initalized yet.")]
    Connection,
    #[error("Folder compression failed: {0}")]
    Compress(#[from] anyhow::Error),
    #[error("object has changed internally, no way to retreive old versions.")]
    ETagChanged,
    #[error("folder is empty, nothing to stream.")]
    EmptyFolder,
    #[error("failed to create new user bucket: {0}")]
    BucketCreate(anyhow::Error),
    #[error("failed to obtain object metadata: {0}")]
    Metadata(anyhow::Error),
    #[error("S3 operation failed: {0}")]
    S3(anyhow::Error),
    #[error("Upload error: {0}")]
    Upload(anyhow::Error),
}
