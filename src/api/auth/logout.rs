use axum::{
    extract::{Json, State},
    http::StatusCode,
};
use axum_extra::extract::CookieJar;
use secrecy::ExposeSecret;
use tracing::{info, instrument};

use crate::{
    ApiError, AppState, TokenPayload, extract_refresh_token, get_redis_con, revoke_refresh_token,
};

/// Handles user logout by extracting the refresh token from cookies or the
/// request body and revoking it server‑side. It derives the Redis key from
/// the token using the HMAC secret, removes the corresponding refresh token
/// entry so it can no longer be used to mint new access tokens, and responds
/// with 204 No Content on success.
#[instrument(skip_all)]
pub async fn logout(
    State(appstate): State<AppState>,
    cookie_jar: CookieJar,
    body: Option<Json<TokenPayload>>,
) -> Result<StatusCode, ApiError> {
    info!("performing logout request");
    let hmac_sec = appstate.settings.secrets.hmac.expose_secret();
    info!("extracting refresh token from body or cookies.");
    let refresh_token = extract_refresh_token(&cookie_jar, body)?;
    let mut redis_con = get_redis_con(&appstate.redis_pool).await?;
    revoke_refresh_token(hmac_sec, refresh_token.expose_secret(), &mut redis_con).await?;
    info!("logout request success.");
    Ok(StatusCode::NO_CONTENT)
}
