use axum::{Json, debug_handler, extract::State};
use secrecy::ExposeSecret;

use crate::{
    ApiError, AppState, Credentials, LoginResponse, UserProfile, UserTokenPayload,
    create_access_token, create_verification_key, encode_token, fetch_account_info,
    generate_token_bytes, get_redis_con, hash_token, serialize_content, store_token_redis,
    verify_password,
};

#[debug_handler]
pub(super) async fn login(
    State(appstate): State<AppState>,
    Json(credentials): Json<Credentials>,
) -> Result<Json<LoginResponse>, ApiError> {
    let secret = appstate.settings.secrets.hmac;
    let user = fetch_account_info(&appstate.db_pool, &credentials.email).await?;
    if !verify_password(&credentials.password, &user.password_hash)? {
        //500 propogates
        return Err(ApiError::Unauthorized);
    }
    //--------------------------generating refresh token--------------
    let token_bytes = generate_token_bytes(32)?;
    let refresh_token = encode_token(&token_bytes);
    let token_hash = hash_token(&token_bytes, secret.expose_secret())?;
    let mut redis_con = get_redis_con(appstate.redis_pool).await?;
    let key = create_verification_key(crate::TokenType::Refresh, &token_hash);
    let refresh_payload = UserTokenPayload::new(user.id, &user.username);
    let ser_refresh_payload = serialize_content(&refresh_payload)?;
    //-------------------------- generate access token---------------

    let access_token = create_access_token(&refresh_payload, 60 * 15, secret)?;
    store_token_redis(
        &mut redis_con,
        &key,
        &ser_refresh_payload,
        30 * 24 * 60 * 60,
    ) // storing refresh token in redis to prevent a failure from not returning it to user
    .await?;
    let user_profile = UserProfile::from(user);

    Ok(Json(LoginResponse {
        access_token,
        refresh_token,
        user: user_profile,
    }))
}
