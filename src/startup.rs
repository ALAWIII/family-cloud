use axum::Router;
use tokio::net::TcpListener;

use crate::{database::init_db, init_rustfs, *};

//---------------------------------------server---------------------------------------
async fn server() {
    let app = Router::new()
        .merge(authentication())
        .merge(user_management())
        .merge(storage_objects())
        .merge(sharing_object())
        .merge(storage_status());
    let listener = TcpListener::bind("127.0.0.1:5050").await.unwrap();
    axum::serve(listener, app).await;
}

pub async fn run() -> Result<(), sqlx::Error> {
    dotenv::dotenv().ok();
    init_rustfs().await;
    init_db().await
}
