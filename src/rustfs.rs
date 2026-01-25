use aws_sdk_s3::{
    Client,
    config::{BehaviorVersion, Credentials, Region},
};
use secrecy::{ExposeSecret, SecretString};
use std::sync::OnceLock;

use crate::RustfsConfig;

static RUST_FS_CONN: OnceLock<Client> = OnceLock::new();

pub async fn init_rustfs(rconfig: &RustfsConfig, secret: &SecretString) -> Result<(), Client> {
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
    RUST_FS_CONN.set(Client::new(&shard_config))
}

pub fn get_rustfs() -> Client {
    RUST_FS_CONN
        .get()
        .expect("Failed to get the RustFS connection")
        .clone()
}
