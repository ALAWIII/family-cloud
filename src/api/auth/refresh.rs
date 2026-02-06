use axum::{Json, debug_handler, extract::State};
use axum_extra::extract::CookieJar;
use secrecy::ExposeSecret;
use tracing::{info, instrument};

use crate::{
    ApiError, AppState, TokenPayload, UserTokenPayload, create_jwt_access_token, create_redis_key,
    decode_token, deserialize_content, extract_refresh_token, fetch_redis_data, get_redis_con,
    hash_token,
};
/// responsible for generating new jwt access tokens as a response
#[debug_handler]
#[instrument(skip_all)]
pub(super) async fn refresh_token(
    State(appstate): State<AppState>,
    cookie_jar: CookieJar,
    body: Option<Json<TokenPayload>>,
) -> Result<Json<TokenPayload>, ApiError> {
    info!("extracting refresh token from request cookie or body.");
    let refresh_token = extract_refresh_token(&cookie_jar, body)?;

    info!("decoding, hashing and creating redis verification key.");
    let secret = appstate.settings.secrets.hmac;
    let token_bytes = decode_token(refresh_token.expose_secret())?; // unauthrized
    let token_hash = hash_token(&token_bytes, secret.expose_secret())?;
    let key = create_redis_key(crate::TokenType::Refresh, &token_hash);

    info!("fetching redis for data by the refresh token.");
    let mut redis_con = get_redis_con(&appstate.redis_pool).await?;
    let user_data = fetch_redis_data(&mut redis_con, &key)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    let refresh_payload: UserTokenPayload = deserialize_content(&user_data)?;
    //-------------------------------
    let jwt = create_jwt_access_token(&refresh_payload, 15 * 60, secret)
        .map(|v| Json(TokenPayload { token: v.into() }))?;
    info!("success jwt response.");
    Ok(jwt)
}
