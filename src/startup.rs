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
pub fn build_router() -> Router {
    let state = AppState {
        db_pool: get_db(),
        rustfs_con: get_rustfs(),
        redis_pool: get_redis_pool(),
        mail_client: get_mail_client(),
    };
    Router::new()
        .merge(authentication())
        .merge(verification_router())
        .merge(user_management())
        .merge(storage_objects())
        .merge(sharing_object())
        .merge(storage_status())
        .with_state(state)
}

async fn start_app_server() -> Result<(), std::io::Error> {
    let router = build_router();
    let listener = TcpListener::bind("127.0.0.1:5050").await.unwrap();
    axum::serve(listener, router).await
}

pub async fn run() {
    dotenv::dotenv().ok();
    init_redis_pool().await;
    init_rustfs().await;
    init_db().await;
    start_app_server().await;
}
