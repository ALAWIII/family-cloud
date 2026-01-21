use anyhow::anyhow;
use axum::Router;
use deadpool_redis::Pool as RedisPool;
use lettre::{AsyncSmtpTransport, Tokio1Executor};
use sqlx::PgPool;
use tokio::net::TcpListener;

use crate::{database::init_db, email::get_mail_client, init_rustfs, *};

#[derive(Clone)]
pub struct AppState {
    pub db_pool: PgPool,
    pub rustfs_con: aws_sdk_s3::Client,
    pub redis_pool: RedisPool,
    pub mail_client: AsyncSmtpTransport<Tokio1Executor>,
}

//---------------------------------------server---------------------------------------
pub fn build_router() -> Result<Router, ApiError> {
    let state = AppState {
        db_pool: get_db()?,
        rustfs_con: get_rustfs(),
        redis_pool: get_redis_pool()?,
        mail_client: get_mail_client()?,
    };
    let router = Router::new()
        .merge(authentication())
        .merge(user_management())
        .merge(storage_objects())
        .merge(sharing_object())
        .merge(storage_status())
        .with_state(state);
    Ok(router)
}

async fn start_app_server(router: Router) -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:5050").await?;
    axum::serve(listener, router).await?;
    Ok(())
}

pub async fn run() -> anyhow::Result<()> {
    dotenv::dotenv().ok();
    init_mail_client()?;
    init_redis_pool().await?;
    init_rustfs().await;
    init_db().await?;
    let router = build_router()?;
    start_app_server(router).await?;
    Ok(())
}
