use axum::{
    extract::{Json, State},
    http::StatusCode,
};
use axum_extra::extract::CookieJar;
use secrecy::ExposeSecret;
use tracing::{info, instrument};

use crate::{
    ApiError, AppState, TokenPayload, create_redis_key, decode_token, delete_token_from_redis,
    extract_refresh_token, get_redis_con, hash_token,
};
#[instrument(skip_all)]
pub(super) async fn logout(
    State(appstate): State<AppState>,
    cookie_jar: CookieJar,
    body: Option<Json<TokenPayload>>,
) -> Result<StatusCode, ApiError> {
    info!("performing logout request");
    let secret = appstate.settings.secrets.hmac.expose_secret();
    info!("extracting refresh token from body or cookies.");
    let refresh_token = extract_refresh_token(&cookie_jar, body)?;
    info!("decoding and hashing the refresh token for logout");
    let token_bytes = decode_token(refresh_token.expose_secret())?;
    let token_hash = hash_token(&token_bytes, secret)?;
    let key = create_redis_key(crate::TokenType::Refresh, &token_hash);

    info!("deleting and invalidating the refresh token from redis.");
    let mut redis_con = get_redis_con(&appstate.redis_pool).await?;
    delete_token_from_redis(&mut redis_con, &key).await?; // already deleted

    info!("logout request success.");
    Ok(StatusCode::NO_CONTENT)
}
