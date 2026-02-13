//! Container initialization and configuration
//! Container management for integration tests
//!
//! Manages Docker containers for PostgreSQL, Redis, and MailHog
use family_cloud::{DatabaseConfig, EmailConfig, RedisConfig, RustfsConfig};
use secrecy::SecretString;
use std::{env, time::Duration};
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt, core::IntoContainerPort, runners::AsyncRunner,
};
use tokio::net::TcpStream;

use crate::MailHogClient;

use tokio::time::sleep;

/// Manages all test infrastructure containers
#[derive(Debug)]
pub struct TestContainers {
    pub mailhog: ContainerAsync<GenericImage>,
}

impl TestContainers {
    /// Stop all containers gracefully
    pub async fn stop(self) -> anyhow::Result<()> {
        self.mailhog.stop().await?;
        Ok(())
    }
}

const MAILHOG_SMTP_PORT: u16 = 1025;
const MAILHOG_WEB_PORT: u16 = 8025;

/// Initialize all test containers
pub async fn init_test_containers() -> anyhow::Result<MailHogClient> {
    let m_container = setup_mailhog_container().await?;
    let email_config = get_email_config(&m_container).await?;
    family_cloud::init_mail_client(&email_config)?;
    let mailhog_url = std::env::var("MAILHOG_URL")?;
    let mailhog = MailHogClient::new(mailhog_url, email_config, m_container);
    Ok(mailhog)
}

/// Setup MailHog container for email testing
async fn setup_mailhog_container() -> anyhow::Result<ContainerAsync<GenericImage>> {
    let container = GenericImage::new("cd2team/mailhog", "latest")
        .with_exposed_port(MAILHOG_SMTP_PORT.tcp())
        .with_exposed_port(MAILHOG_WEB_PORT.tcp())
        .with_startup_timeout(Duration::from_secs(60 * 10))
        .start()
        .await?;
    let host = container.get_host().await?;
    let port = container.get_host_port_ipv4(MAILHOG_SMTP_PORT).await?;
    wait_for_container(&host.to_string(), port).await?;
    assert!(container.is_running().await?);
    Ok(container)
}

/// Get database configuration from container or env
pub async fn get_database_config(host: &str, port: u16) -> anyhow::Result<DatabaseConfig> {
    Ok(DatabaseConfig {
        host: host.to_string(),
        port,
        user_name: get_db_user(),
        password: get_db_password(),
        db_name: "familycloud".into(),
    })
}

/// Get Redis configuration from container
pub async fn get_redis_config(host: &str, port: u16) -> anyhow::Result<RedisConfig> {
    Ok(RedisConfig {
        host: host.to_string(),
        port,
    })
}

/// Get email configuration from container
pub async fn get_email_config(
    mailhog: &ContainerAsync<GenericImage>,
) -> anyhow::Result<EmailConfig> {
    let host = mailhog.get_host().await?;
    let smtp_port = mailhog.get_host_port_ipv4(MAILHOG_SMTP_PORT).await?;
    let web_port = mailhog.get_host_port_ipv4(MAILHOG_WEB_PORT).await?;

    // Store web URL for later email verification
    unsafe {
        env::set_var("MAILHOG_URL", format!("http://{}:{}", host, web_port));
    }

    Ok(EmailConfig {
        protocol: "smtp".into(),
        tls_param: false,
        username: "test".into(),
        password: "test".into(),
        from_sender: "noreply@yourapp.com".into(),
        host: host.to_string(),
        port: smtp_port,
    })
}

/// Get Rustfs (MinIO) configuration for file storage
pub fn get_rustfs_config() -> RustfsConfig {
    RustfsConfig {
        region: env::var("RUSTFS_REGION").unwrap_or("us-east-1".into()),
        access_key: env::var("RUSTFS_ACCESS_KEY_ID").unwrap_or("minioadmin".into()),
        url: env::var("RUSTFS_ENDPOINT_URL").unwrap_or("http://127.0.0.1:9000".into()),
    }
}

/// Helper: Get database user from env or default
fn get_db_user() -> String {
    env::var("DB_USER").unwrap_or("testuser".into())
}

/// Helper: Get database password from env or default
fn get_db_password() -> SecretString {
    env::var("DB_PASSWORD").unwrap_or("testpass".into()).into()
}

/// Wait until the host:port is accepting TCP connections.
/// Returns an error if the timeout is reached.
pub async fn wait_for_container(host: &str, port: u16) -> anyhow::Result<()> {
    while TcpStream::connect((host, port)).await.is_err() {
        sleep(Duration::from_millis(100)).await;
    }
    Ok(())
}
