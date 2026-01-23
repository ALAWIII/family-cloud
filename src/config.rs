use config::{Config as ConfigBuilder, File};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

use crate::ApiError;
#[derive(Debug, Clone, Deserialize)]
pub struct AppSettings {
    pub app: AppConfig,
    pub database: DatabaseConfig,
    pub email: EmailConfig,
    pub rustfs: RustfsConfig,
    pub secrets: Secrets,
    pub redis: RedisConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub user_name: String,
    pub password: SecretString,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EmailConfig {
    pub protocol: String,
    pub tls_param: bool,
    pub port: u16,
    pub host: String,
    pub username: String,
    pub password: SecretString,
    pub from_sender: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RustfsConfig {
    pub region: String,
    pub access_key: String,
    pub url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Secrets {
    pub hmac: SecretString,
    pub rustfs: SecretString,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RedisConfig {
    pub host: String,
    pub port: u16,
}

impl AppConfig {
    pub fn url(&self) -> String {
        format!("http://{}:{}", self.host, self.port)
    }
}

impl DatabaseConfig {
    pub fn url(&self) -> String {
        format!(
            "postgresql://{}:{}@{}:{}/{}",
            self.user_name,
            self.password.expose_secret(),
            self.host,
            self.port,
            self.name
        )
    }
}

impl EmailConfig {
    pub fn url(&self) -> String {
        let paswd_encoded = urlencoding::encode(self.password.expose_secret());
        let tls_parm = self.tls_param.then_some("?tls=required").unwrap_or("");
        format!(
            "{}://{}:{}@{}:{}{}",
            self.protocol, // smtp or smtps
            self.username,
            paswd_encoded,
            self.host,
            self.port,
            tls_parm
        )
    }
}

impl RustfsConfig {
    pub fn url(&self) -> String {
        self.url.clone()
    }
}

impl RedisConfig {
    pub fn url(&self) -> String {
        format!("redis://{}:{}", self.host, self.port)
    }
}

impl AppSettings {
    pub fn load() -> Result<AppSettings, ApiError> {
        let config = ConfigBuilder::builder()
            .add_source(File::with_name("config/settings"))
            .build()?;

        let settings: AppSettings = config.try_deserialize()?;
        Ok(settings)
    }
}
