use std::fmt::Display;

use crate::ApiError;
use config::{Config as ConfigBuilder, File};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub enum LogLevel {
    /// Highest level → TRACE + DEBUG + INFO + WARN + ERROR
    Trace,
    /// → DEBUG + INFO + WARN + ERROR
    Debug,
    /// → INFO + WARN + ERROR
    Info,
    /// → WARN + ERROR
    Warn,
    /// → ERROR only
    Error,
}

impl<'de> Deserialize<'de> for LogLevel {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.to_lowercase().as_str() {
            "trace" => Ok(LogLevel::Trace),
            "debug" => Ok(LogLevel::Debug),
            "info" => Ok(LogLevel::Info),
            "warn" | "warning" => Ok(LogLevel::Warn),
            "error" => Ok(LogLevel::Error),
            _ => Err(serde::de::Error::custom("invalid log level")),
        }
    }
}
#[derive(Debug, Clone, Deserialize)]
pub struct AppSettings {
    pub app: AppConfig,
    pub database: DatabaseConfig,
    pub email: Option<EmailConfig>,
    pub rustfs: RustfsConfig,
    pub secrets: Secrets,
    pub redis: RedisConfig,
    pub token_options: TokenOptions,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub log_level: LogLevel,
    pub log_directory: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub db_name: String,
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
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct TokenOptions {
    pub max_concurrent_download: u64,
    pub password_reset_token: u64,
    pub download_token_ttl: u64,
    pub change_email_token: u64,
    pub refresh_token: u64,
    pub signup_token: u64,
    pub jwt_token: u64,
}

impl AppConfig {
    pub fn url(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
    pub fn tracing_settings(&self) -> String {
        format!("family_cloud={},warn", self.log_level)
    }
}
impl Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Trace => "trace",
                Self::Debug => "debug",
                Self::Info => "info",
                Self::Warn => "warn",
                _ => "error",
            }
        )
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
            self.db_name
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
