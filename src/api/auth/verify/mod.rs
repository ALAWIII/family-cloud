use axum::{
    Router, debug_handler,
    extract::{Query, State},
    routing::{get, post},
};
use deadpool_redis::{Connection, redis::AsyncTypedCommands};
use serde::Deserialize;

use crate::{
    AppState, PendingAccount, User, decode_token, hash_token, insert_new_account,
    remove_verified_account_from_redis, search_redis_for_token,
};

mod email_change;
mod pswd_reset;
pub use email_change::*;
pub use pswd_reset::*;

pub fn verification_router() -> Router<AppState> {
    Router::new()
        .route("/api/auth/verify/signup", get(verify_signup_token)) // returns 200 ok if didnt expire yet , otherwise user should re signup again
        .route("/api/auth/verify/password-reset", get(verify_signup_token)) // returns a page form asking for new password if the token didnt expire yet.
        .route("/api/auth/verify/change-email", get(verify_signup_token)) // returns a page form asking for the new email if the token didnt expire yet.
        .route("/api/auth/password-reset", post(password_rest)) // request to allow change password , body contains user email
        .route(
            "/api/auth/password-reset/confirm", // request contains (token, old password,new password)
            post(confirm_password_reset),
        )
}
#[debug_handler]
pub async fn verify_signup_token(
    State(appstate): State<AppState>,
    Query(token): Query<TokenQuery>,
) {
    let redis_con = appstate.redis_pool.get().await.unwrap();
    let decoded = decode_token(&token.token).unwrap();
    let hashed_token = hash_token(&decoded);
    let account: PendingAccount = serde_json::from_str(
        &search_redis_for_token(&hashed_token, redis_con)
            .await
            .expect("fail to find a pending account"),
    )
    .expect("failed to deserialize");
    let user = User::new(account.username, account.email, account.password_hash);
    insert_new_account(user, &appstate.db_pool)
        .await
        .expect("Failed to insert into database");
    remove_verified_account_from_redis(appstate.redis_pool.get().await.unwrap(), &hashed_token)
        .await
        .unwrap()
}

#[derive(Deserialize)]
pub struct TokenQuery {
    pub token: String,
}
