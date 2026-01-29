use crate::{database::init_db, email::get_mail_client, init_rustfs, *};
use axum::Router;
use deadpool_redis::Pool as RedisPool;
use lettre::{AsyncSmtpTransport, Tokio1Executor};
use sqlx::PgPool;
use tokio::net::TcpListener;

#[derive(Clone, Debug)]
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
        .with_state(state)
        .layer(axum::middleware::from_fn(tracing_middleware));
    Ok(router)
}

async fn start_app_server(state: AppState) -> anyhow::Result<()> {
    let app_url = state.settings.app.url();
    let router = build_router(state)?;
    let listener = TcpListener::bind(app_url).await?;
    axum::serve(listener, router).await?;
    Ok(())
}

pub async fn run() -> anyhow::Result<()> {
    let state = setup_app()?;
    init_tracing(
        &state.settings.app.name,
        &state.settings.app.tracing_settings(),
        &state.settings.app.log_directory,
    )?;
    init_mail_client(&state.settings.email)?;
    init_redis_pool(&state.settings.redis).await?;
    init_rustfs(&state.settings.rustfs, &state.settings.secrets.rustfs).await;
    init_db(&state.settings.database).await?;
    start_app_server(state).await?;
    Ok(())
}
