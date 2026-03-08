use aws_sdk_s3::{
    Client,
    config::{BehaviorVersion, Credentials, Region},
    operation::head_object::HeadObjectOutput,
};
use secrecy::{ExposeSecret, SecretString};
use std::sync::OnceLock;
use tracing::{error, instrument};
use uuid::Uuid;

use crate::{FileRecord, RustFSError, RustfsConfig};

static RUST_FS_CONN: OnceLock<Client> = OnceLock::new();

#[instrument(skip_all, fields(
    init_id=%Uuid::new_v4(),
    rustfs_url=rconfig.url()
))]
pub async fn init_rustfs(rconfig: &RustfsConfig, secret: &SecretString) -> Result<(), RustFSError> {
    let credit = Credentials::new(
        &rconfig.access_key,
        secret.expose_secret(),
        None,
        None,
        "rustfs",
    );
    let region = Region::new(rconfig.region.to_string());
    let shard_config = aws_config::defaults(BehaviorVersion::latest())
        .region(region)
        .credentials_provider(credit)
        .endpoint_url(rconfig.url.to_string())
        .load()
        .await;
    RUST_FS_CONN
        .set(Client::new(&shard_config))
        .map_err(|_| RustFSError::AlreadyInit)
}

pub fn get_rustfs() -> Result<Client, RustFSError> {
    RUST_FS_CONN.get().ok_or(RustFSError::Connection).cloned()
}

pub async fn create_user_bucket(rfs_con: &Client, user_id: &str) -> Result<(), RustFSError> {
    rfs_con
        .create_bucket()
        .bucket(user_id)
        .send()
        .await
        .map_err(|e| RustFSError::BucketCreate(e.into()))
        .inspect_err(|e| error!("{}", e))?;
    Ok(())
}

pub async fn fetch_object_metadata(
    rfs_con: &Client,
    file: &FileRecord,
) -> Result<HeadObjectOutput, RustFSError> {
    rfs_con
        .head_object()
        .bucket(file.bucket_name()) // user_id = bucket
        .key(file.key())
        .checksum_mode(aws_sdk_s3::types::ChecksumMode::Enabled)
        .send()
        .await
        .map_err(|e| RustFSError::Metadata(e.into()))
}
