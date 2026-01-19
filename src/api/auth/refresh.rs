use axum::{Json, debug_handler, extract::State, http::StatusCode};
use axum_extra::extract::CookieJar;
use secrecy::{ExposeSecret, SecretBox};

use crate::{
    AppState, TokenPayload, UserTokenPayload, create_access_token, create_verification_key,
    decode_token, get_verification_data, hash_token,
};
#[debug_handler]
/// responsible for generating new access tokens as a response
pub(super) async fn refresh_token(
    State(appstate): State<AppState>,
    cookie_jar: CookieJar,
    Json(body): Json<Option<TokenPayload>>,
) -> Result<Json<TokenPayload>, StatusCode> {
    let secret = SecretBox::new(Box::new(std::env::var("HMAC_SECRET").unwrap()));
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
    let token_bytes =
        decode_token(refresh_token.expose_secret()).map_err(|_| StatusCode::UNAUTHORIZED)?;

    let token_hash = hash_token(&token_bytes);
    let key = create_verification_key(crate::TokenType::Refresh, &token_hash);
    let user_data = get_verification_data(&mut redis_con, &key)
        .await
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let refresh_payload: UserTokenPayload =
        serde_json::from_str(&user_data).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    create_access_token(&refresh_payload, 15 * 60, secret)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
        .map(|v| {
            Json(TokenPayload {
                token: SecretBox::new(Box::new(v)),
            })
        })
}
