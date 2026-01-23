use axum::{Json, debug_handler, extract::State};
use axum_extra::extract::CookieJar;
use secrecy::{ExposeSecret, SecretBox};

use crate::{
    ApiError, AppState, TokenPayload, UserTokenPayload, create_access_token,
    create_verification_key, decode_token, deserialize_content, extract_refresh_token,
    get_redis_con, get_verification_data, hash_token,
};
#[debug_handler]
/// responsible for generating new access tokens as a response
pub(super) async fn refresh_token(
    State(appstate): State<AppState>,
    cookie_jar: CookieJar,
    body: Option<Json<TokenPayload>>,
) -> Result<Json<TokenPayload>, ApiError> {
    let refresh_token = extract_refresh_token(&cookie_jar, body)?;

    let secret = appstate.settings.secrets.hmac;
    let mut redis_con = get_redis_con(appstate.redis_pool).await?;
    let token_bytes = decode_token(refresh_token.expose_secret())?; // unauthrized

    let token_hash = hash_token(&token_bytes)?;
    let key = create_verification_key(crate::TokenType::Refresh, &token_hash);
    let user_data = get_verification_data(&mut redis_con, &key)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    let refresh_payload: UserTokenPayload = deserialize_content(&user_data)?;
    Ok(
        create_access_token(&refresh_payload, 15 * 60, secret).map(|v| {
            Json(TokenPayload {
                token: SecretBox::new(Box::new(v)),
            })
        })?,
    )
}
