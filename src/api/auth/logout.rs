use axum::{
    extract::{Json, State},
    http::StatusCode,
};
use axum_extra::extract::CookieJar;
use secrecy::{ExposeSecret, SecretBox};

use crate::{
    ApiError, AppState, TokenPayload, create_verification_key, decode_token,
    delete_token_from_redis, get_redis_con, hash_token,
};

pub(super) async fn logout(
    State(appstate): State<AppState>,
    cookie_jar: CookieJar,
    Json(body): Json<Option<TokenPayload>>,
) -> Result<StatusCode, ApiError> {
    let refresh_token = cookie_jar
        .get("refresh_token")
        .map(|cookie| SecretBox::new(Box::new(cookie.value().into())))
        .or_else(|| body.map(|t| t.token))
        .ok_or(ApiError::Unauthorized)?;
    let mut redis_con = get_redis_con(appstate.redis_pool).await?;

    let token_bytes = decode_token(refresh_token.expose_secret())?;
    let token_hash = hash_token(&token_bytes)?;
    let key = create_verification_key(crate::TokenType::Refresh, &token_hash);
    delete_token_from_redis(&mut redis_con, &key).await?; // already deleted
    Ok(StatusCode::NO_CONTENT)
}
