use deadpool_redis::redis::ConnectionLike;
use family_cloud::{DatabaseConfig, EmailConfig, RedisConfig, RustfsConfig};
use testcontainers::{
    ContainerAsync, GenericImage,
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
};
#[derive(Debug)]
pub struct AppContainers {
    pub redis: ContainerAsync<GenericImage>,

    pub mailhog: ContainerAsync<GenericImage>,
}
pub async fn setup_redis_container() -> anyhow::Result<(ContainerAsync<GenericImage>, RedisConfig)>
{
    let rds = GenericImage::new("redis", "latest")
        .with_exposed_port(6379.tcp())
        .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
        .start()
        .await?;

    let host = rds.get_host().await?;
    let host_port = rds.get_host_port_ipv4(6379).await?;
    let url = format!("redis://{host}:{host_port}");
    let mut client = deadpool_redis::redis::Client::open(url.as_ref())?;
    assert!(client.check_connection());
    unsafe {
        std::env::set_var("REDIS_URL", &url);
    } // No unsafe needed}
    let conf = RedisConfig {
        host: host.to_string(),
        port: host_port,
    };
    Ok((rds, conf))
}

pub async fn setup_mailhog_container() -> anyhow::Result<(ContainerAsync<GenericImage>, EmailConfig)>
{
    let mailhog = GenericImage::new("mailhog/mailhog", "latest")
        .with_exposed_port(1025.tcp())
        .with_exposed_port(8025.tcp())
        .start()
        .await?;

    let host = mailhog.get_host().await?;
    let smtp_port = mailhog.get_host_port_ipv4(1025).await?;
    let web_port = mailhog.get_host_port_ipv4(8025).await?;

    unsafe {
        std::env::set_var("MAILHOG_URL", format!("http://{}:{}", host, web_port));
    } // No unsafe needed}
    //email:

    let conf = EmailConfig {
        protocol: "smtp".into(),
        tls_param: false,
        username: "anything".into(),
        password: "anything".into(),
        from_sender: "noreply@yourapp.com".into(),
        host: host.to_string(),
        port: smtp_port,
    };
    Ok((mailhog, conf))
}

pub fn setup_db() -> DatabaseConfig {
    DatabaseConfig {
        name: "familycloud".into(),
        host: "localhost".into(),
        port: 5432,
        password: "0788".into(),
        user_name: "allawiii".into(),
    }
}

pub fn setup_rustfs() -> RustfsConfig {
    RustfsConfig {
        region: "us-east-1".into(),
        access_key: "family".into(),
        url: "http://127.0.0.1:9000".into(),
    }
}
