use axum::{Json, debug_handler, extract::State, http::StatusCode};
use secrecy::SecretBox;

use crate::{
    AppState, Credentials, LoginResponse, UserProfile, UserTokenPayload, create_access_token,
    create_verification_key, encode_token, fetch_account_info, generate_token_bytes, hash_token,
    store_token_redis, verify_password,
};

#[debug_handler]
pub(super) async fn login(
    State(appstate): State<AppState>,
    Json(credentials): Json<Credentials>,
) -> Result<Json<LoginResponse>, StatusCode> {
    let secret_key = SecretBox::new(Box::new(std::env::var("HMAC_SECRET").unwrap()));
    let user = fetch_account_info(&appstate.db_pool, &credentials.email)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if !verify_password(&credentials.password, &user.password_hash)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    {
        return Err(StatusCode::UNAUTHORIZED);
    }
    //--------------------------generating refresh token--------------
    let token_bytes = generate_token_bytes(32);
    let refresh_token = encode_token(&token_bytes);
    let token_hash = hash_token(&token_bytes);
    let mut redis_con = appstate
        .redis_pool
        .get()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let key = create_verification_key(crate::TokenType::Refresh, &token_hash);
    let refresh_payload = UserTokenPayload::new(user.id, &user.username);
    //-------------------------- generate access token---------------

    let access_token = create_access_token(&refresh_payload, 60 * 15, secret_key)
        .expect("Failed to create access token");
    store_token_redis(&mut redis_con, &key, &refresh_payload, 30 * 24 * 60 * 60) // storing refresh token in redis to prevent a failure from not returning it to user
        .await
        .unwrap();
    let user_profile = UserProfile::from(user);

    Ok(Json(LoginResponse {
        access_token,
        refresh_token,
        user: user_profile,
    }))
}
