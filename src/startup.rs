use std::sync::Arc;

use crate::{database::init_db, email::get_mail_client, init_rustfs, *};
use axum::Router;
use deadpool_redis::Pool as RedisPool;
use lettre::{AsyncSmtpTransport, Tokio1Executor};
use sqlx::PgPool;
use tokio::net::TcpListener;
pub type AAppState = Arc<AppState>;
#[derive(Clone)]
pub struct AppState {
    pub settings: AppSettings,
    pub db_pool: PgPool,
    pub rustfs_con: aws_sdk_s3::Client,
    pub redis_pool: RedisPool,
    pub mail_client: AsyncSmtpTransport<Tokio1Executor>,
}

pub fn setup_app() -> Result<AppState, ApiError> {
    let settings = AppSettings::load()?;
    Ok(AppState {
        settings,
        db_pool: get_db()?,
        rustfs_con: get_rustfs(),
        redis_pool: get_redis_pool()?,
        mail_client: get_mail_client()?,
    })
}
//---------------------------------------server---------------------------------------
pub fn build_router(state: AppState) -> Result<Router, ApiError> {
    let router = Router::new()
        .merge(authentication())
        .merge(user_management())
        .merge(storage_objects())
        .merge(sharing_object())
        .merge(storage_status())
        .merge(pswd_router())
        .merge(change_email_router(state.settings.secrets.hmac.clone()))
        .with_state(state);
    Ok(router)
}

async fn start_app_server(router: Router) -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:5050").await?;
    axum::serve(listener, router).await?;
    Ok(())
}

pub async fn run() -> anyhow::Result<()> {
    let state = setup_app()?;
    init_mail_client(&state.settings.email)?;
    init_redis_pool(&state.settings.redis).await?;
    init_rustfs(&state.settings).await;
    init_db(&state.settings.database).await?;
    let router = build_router(state)?;
    start_app_server(router).await?;
    Ok(())
}
