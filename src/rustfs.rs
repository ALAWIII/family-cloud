use aws_sdk_s3::{
    Client,
    config::{BehaviorVersion, Credentials, Region},
};
use aws_smithy_types_convert::date_time::DateTimeExt;
use secrecy::{ExposeSecret, SecretString};
use std::sync::OnceLock;
use tracing::{error, instrument};
use uuid::Uuid;

use crate::{ObjectRecord, RustFSError, RustfsConfig};

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
    obj: &mut ObjectRecord,
) -> Result<(), RustFSError> {
    let head = rfs_con
        .head_object()
        .bucket(obj.user_id.to_string()) // user_id = bucket
        .key(&obj.object_key)
        .checksum_mode(aws_sdk_s3::types::ChecksumMode::Enabled)
        .send()
        .await
        .map_err(|e| RustFSError::Metadata(e.into()))?;

    obj.etag = head.e_tag;
    obj.last_modified = head.last_modified.and_then(|lm| lm.to_chrono_utc().ok());
    obj.size = head.content_length;
    Ok(())
}
