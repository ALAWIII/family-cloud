//! Container initialization and configuration
//! Container management for integration tests
//!
//! Manages Docker containers for PostgreSQL, Redis, and MailHog
use family_cloud::{DatabaseConfig, EmailConfig, RedisConfig, RustfsConfig};
use secrecy::{ExposeSecret, SecretString};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use std::{env, time::Duration};
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
};
use tokio::time::sleep;

/// Manages all test infrastructure containers
#[derive(Debug)]
pub struct TestContainers {
    pub postgres: ContainerAsync<GenericImage>,
    pub redis: ContainerAsync<GenericImage>,
    pub mailhog: ContainerAsync<GenericImage>,
}

impl TestContainers {
    /// Stop all containers gracefully
    pub async fn stop(self) -> anyhow::Result<()> {
        self.postgres.stop().await?;
        self.redis.stop().await?;
        self.mailhog.stop().await?;
        Ok(())
    }
}

const REDIS_PORT: u16 = 6379;
const MAILHOG_SMTP_PORT: u16 = 1025;
const MAILHOG_WEB_PORT: u16 = 8025;
const POSTGRES_PORT: u16 = 5432;

/// Initialize all test containers
pub async fn init_test_containers() -> anyhow::Result<TestContainers> {
    let (postgres, redis, mailhog) = tokio::join!(
        setup_postgres_container(), // uses WaitFor::message_on_stdout or list_port
        setup_redis_container(),    // WaitFor::listening_port
        setup_mailhog_container()   // WaitFor::listening_port
    );
    Ok(TestContainers {
        postgres: postgres?,
        redis: redis?,
        mailhog: mailhog?,
    })
}

/// Setup PostgreSQL container with proper wait conditions
async fn setup_postgres_container() -> anyhow::Result<ContainerAsync<GenericImage>> {
    let container = GenericImage::new("yobasystems/alpine-postgres", "latest")
        .with_exposed_port(POSTGRES_PORT.tcp())
        .with_env_var("POSTGRES_DB", "familycloud")
        .with_env_var("POSTGRES_USER", get_db_user())
        .with_env_var("POSTGRES_PASSWORD", get_db_password().expose_secret())
        .with_cmd(vec![
            "postgres",
            "-c",
            "fsync=off",
            "-c",
            "synchronous_commit=off",
            "-c",
            "full_page_writes=off",
        ])
        .with_startup_timeout(Duration::from_secs(60 * 10))
        .start()
        .await?;

    let host = container.get_host().await?;
    let port = container.get_host_port_ipv4(POSTGRES_PORT).await?;

    let db_url = format!(
        "postgresql://{}:{}@{}:{}/familycloud",
        get_db_user(),
        get_db_password().expose_secret(),
        host,
        port
    );
    wait_for_postgres(&db_url).await?;
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    assert!(container.is_running().await?);
    Ok(container)
}

/// Setup Redis container
async fn setup_redis_container() -> anyhow::Result<ContainerAsync<GenericImage>> {
    let container = GenericImage::new("yobasystems/alpine-redis", "latest")
        .with_exposed_port(REDIS_PORT.tcp())
        .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
        .with_startup_timeout(Duration::from_secs(60 * 10))
        .start()
        .await?;

    assert!(container.is_running().await?);
    Ok(container)
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
pub async fn get_database_config(
    postgres: &ContainerAsync<GenericImage>,
) -> anyhow::Result<DatabaseConfig> {
    let host = postgres.get_host().await?;
    let port = postgres.get_host_port_ipv4(POSTGRES_PORT).await?;

    Ok(DatabaseConfig {
        host: host.to_string(),
        port,
        user_name: get_db_user(),
        password: get_db_password(),
        name: "familycloud".into(),
    })
}

/// Get Redis configuration from container
pub async fn get_redis_config(redis: &ContainerAsync<GenericImage>) -> anyhow::Result<RedisConfig> {
    let host = redis.get_host().await?;
    let port = redis.get_host_port_ipv4(REDIS_PORT).await?;

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
        access_key: env::var("RUSTFS_ACCESS_KEY").unwrap_or("minioadmin".into()),
        url: env::var("RUSTFS_URL").unwrap_or("http://127.0.0.1:9000".into()),
    }
}

/// Helper: Get database user from env or default
fn get_db_user() -> String {
    env::var("TEST_DB_USER").unwrap_or("testuser".into())
}

/// Helper: Get database password from env or default
fn get_db_password() -> SecretString {
    env::var("TEST_DB_PASSWORD")
        .unwrap_or("testpass".into())
        .into()
}

use tokio::net::TcpStream;

/// Wait until the host:port is accepting TCP connections.
/// Returns an error if the timeout is reached.
pub async fn wait_for_container(host: &str, port: u16) -> anyhow::Result<()> {
    while TcpStream::connect((host, port)).await.is_err() {
        sleep(Duration::from_millis(100)).await;
    }
    Ok(())
}

pub async fn wait_for_postgres(db_url: &str) -> anyhow::Result<()> {
    loop {
        if let Ok(pool) = PgPool::connect(db_url).await
            && sqlx::query("SELECT 1").execute(&pool).await.is_ok()
        {
            return Ok(());
        }

        sleep(Duration::from_millis(100)).await;
    }
}
