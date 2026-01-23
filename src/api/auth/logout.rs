use axum::{
    extract::{Json, State},
    http::StatusCode,
};
use axum_extra::extract::CookieJar;
use secrecy::ExposeSecret;

use crate::{
    ApiError, AppState, TokenPayload, create_verification_key, decode_token,
    delete_token_from_redis, extract_refresh_token, get_redis_con, hash_token,
};

pub(super) async fn logout(
    State(appstate): State<AppState>,
    cookie_jar: CookieJar,
    body: Option<Json<TokenPayload>>,
) -> Result<StatusCode, ApiError> {
    let secret = appstate.settings.secrets.hmac.expose_secret();
    let refresh_token = extract_refresh_token(&cookie_jar, body)?;
    let mut redis_con = get_redis_con(appstate.redis_pool).await?;

    let token_bytes = decode_token(refresh_token.expose_secret())?;
    let token_hash = hash_token(&token_bytes, secret)?;
    let key = create_verification_key(crate::TokenType::Refresh, &token_hash);
    delete_token_from_redis(&mut redis_con, &key).await?; // already deleted
    Ok(StatusCode::NO_CONTENT)
}
