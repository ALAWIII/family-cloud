use axum::{
    extract::{Json, State},
    http::StatusCode,
};
use axum_extra::extract::CookieJar;
use secrecy::{ExposeSecret, SecretBox};

use crate::{
    AppState, TokenPayload, create_verification_key, decode_token, delete_token_from_redis,
    hash_token,
};

pub(super) async fn logout(
    State(appstate): State<AppState>,
    cookie_jar: CookieJar,
    Json(body): Json<Option<TokenPayload>>,
) -> Result<StatusCode, StatusCode> {
    let refresh_token = cookie_jar
        .get("refresh_token")
        .map(|cookie| SecretBox::new(Box::new(cookie.value().into())))
        .or_else(|| body.map(|t| t.token))
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let mut redis_con = appstate
        .redis_pool
        .get()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let token_bytes = decode_token(refresh_token.expose_secret()).map_err(|_| StatusCode::OK)?;
    let token_hash = hash_token(&token_bytes);
    let key = create_verification_key(crate::TokenType::Refresh, &token_hash);
    delete_token_from_redis(&mut redis_con, &key)
        .await
        .map_err(|_| StatusCode::OK)?; // already deleted
    Ok(StatusCode::NO_CONTENT)
}
