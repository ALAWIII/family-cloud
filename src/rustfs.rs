use aws_sdk_s3::{
    Client,
    config::{BehaviorVersion, Credentials, Region},
};
use std::{
    env::{self, VarError},
    sync::OnceLock,
};

static RUST_FS_CONN: OnceLock<Client> = OnceLock::new();

struct Config {
    pub region: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub endpoint_url: String,
}

impl Config {
    pub fn from_env() -> Result<Self, VarError> {
        let region = env::var("RUSTFS_REGION")?;
        let access_key_id = env::var("RUSTFS_ACCESS_KEY_ID")?;
        let secret_access_key = env::var("RUSTFS_SECRET_ACCESS_KEY")?;
        let endpoint_url = env::var("RUSTFS_ENDPOINT_URL")?;

        Ok(Config {
            region,
            access_key_id,
            secret_access_key,
            endpoint_url,
        })
    }
}
pub async fn init_rustfs() -> Result<(), Client> {
    let config = Config::from_env().expect("Failed to configure RustFS connection settings");
    let credit = Credentials::new(
        config.access_key_id,
        config.secret_access_key,
        None,
        None,
        "rustfs",
    );
    let region = Region::new(config.region);
    let endpoint_url = config.endpoint_url;
    let shard_config = aws_config::defaults(BehaviorVersion::latest())
        .region(region)
        .credentials_provider(credit)
        .endpoint_url(endpoint_url)
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
