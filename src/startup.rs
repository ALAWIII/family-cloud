use std::net::SocketAddr;

use crate::{database::init_db, email::get_mail_client, init_rustfs, *};
use axum::Router;
use deadpool_redis::Pool as RedisPool;
use lettre::{AsyncSmtpTransport, Tokio1Executor};
use sqlx::PgPool;
use tokio::net::TcpListener;

/// Shared application state injected into all Axum handlers, bundling
/// configuration, database pool, RustFS client, Redis pool, and optional
/// SMTP client for email features.
#[derive(Clone, Debug)]
pub struct AppState {
    pub settings: AppSettings,
    pub db_pool: PgPool,
    pub rustfs_con: aws_sdk_s3::Client,
    pub redis_pool: RedisPool,
    pub mail_client: Option<AsyncSmtpTransport<Tokio1Executor>>,
}
/// Constructs `AppState` from loaded `AppSettings` by:
/// 1. Grabbing globally initialized DB, RustFS, and Redis pools.
/// 2. Creating an async mail client (if email is configured).
pub fn setup_app(settings: AppSettings) -> Result<AppState, ApiError> {
    Ok(AppState {
        settings,
        db_pool: get_db()?,
        rustfs_con: get_rustfs()?,
        redis_pool: get_redis_pool()?,
        mail_client: Some(get_mail_client()?),
    })
}
//---------------------------------------server---------------------------------------
/// Builds the main Axum router by:
/// 1. Creating route trees (`app_router`) with the HMAC secret for auth
///    middleware.
/// 2. Attaching the shared `AppState`.
/// 3. Adding the `tracing_middleware` for per‑request spans and IDs.
pub fn build_router(state: AppState) -> Result<Router, ApiError> {
    let hmac = state.settings.secrets.hmac.clone();
    Ok(app_router(hmac)
        .with_state(state)
        .layer(axum::middleware::from_fn(tracing_middleware)))
}
/// Binds the HTTP server to the configured address and starts serving the
/// Axum router with `ConnectInfo<SocketAddr>` support for downstream
/// handlers.
async fn start_app_server(state: AppState) -> anyhow::Result<()> {
    let app_url = state.settings.app.url();
    let router = build_router(state)?;
    let listener = TcpListener::bind(app_url).await?;
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
/// Main application entrypoint that:
/// 1. Loads configuration (`AppSettings::load`) and initializes tracing.
/// 2. Initializes mail client, Redis pool, RustFS client, and Postgres
///    (migrations).
/// 3. Builds `AppState`, starts Apalis workers for copy/delete jobs, and
///    finally runs the Axum HTTP server.
pub async fn run() -> anyhow::Result<()> {
    let settings = AppSettings::load()?;
    let w_names = WorkersName {
        delete: "delete".into(),
        copy: "copy".into(),
    };
    init_tracing(
        &settings.app.name,
        &settings.app.tracing_settings(),
        &settings.app.log_directory,
    )?;
    init_mail_client(
        settings
            .email
            .as_ref()
            .ok_or(EmailError::ClientNotInitialized)?,
    )?;
    init_redis_pool(&settings.redis).await?;
    init_rustfs(&settings.rustfs, &settings.secrets.rustfs).await?;
    init_db(&settings.database).await?;
    let state = setup_app(settings)?;
    init_apalis(&state.db_pool, state.rustfs_con.clone(), w_names).await?;
    start_app_server(state).await?;
    Ok(())
}
