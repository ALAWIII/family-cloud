use axum::{
    Router,
    routing::{get, post, put},
};
use tokio::net::TcpListener;

use crate::{database::init_db, init_rustfs};

//-----------------------------------authentication management-----
async fn login() {}
async fn logout() {}
async fn signup() {}
async fn refresh_token() {}
fn authentication() -> Router {
    Router::new()
        .route("/api/auth/signup", post(signup))
        .route("/api/auth/login", post(login))
        .route("/api/auth/logout", post(logout))
        .route("/api/auth/refresh", post(refresh_token))
}
//------------------------------------user management-------
async fn user_profile() {}
async fn update_user_profile_info() {}
async fn change_password() {}
fn user_management() -> Router {
    Router::new()
        .route(
            "/api/users/me",
            get(user_profile).patch(update_user_profile_info),
        )
        .route("/api/users/me/password", put(change_password))
}
//--------------------------------------
async fn list_objects_with_metadata() {}
async fn upload_object() {}
async fn download_object() {}
async fn fetch_metadata() {}
async fn replace_object() {}
async fn update_metadata() {}
async fn delete_object() {}
fn storage_objects() -> Router {
    Router::new()
        .route(
            "/api/objects",
            get(list_objects_with_metadata).post(upload_object),
        )
        .route(
            "/api/objects/{id}",
            get(download_object)
                .head(fetch_metadata)
                .put(replace_object)
                .patch(update_metadata)
                .delete(delete_object),
        )
}
//------------------------------------share objects links ----------------------------
async fn create_link_share() {}
async fn access_object() {}
fn sharing_object() -> Router {
    Router::new()
        .route("/api/objects/{id}/shares", post(create_link_share))
        .route("/api/shares/{token}", get(access_object))
}
//---------------------------------------storage usage information -------------------

async fn fetch_storage_info() {}
fn storage_status() -> Router {
    Router::new().route("/api/storage/usage", get(fetch_storage_info))
}

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
