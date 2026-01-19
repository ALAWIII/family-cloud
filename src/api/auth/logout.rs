use axum::{
    extract::{Json, State},
    http::StatusCode,
};

use crate::{
    AppState, TokenQuery, create_verification_key, decode_token, delete_token_from_redis,
    hash_token,
};

pub(super) async fn logout(
    State(appstate): State<AppState>,
    Json(token): Json<TokenQuery>,
) -> Result<StatusCode, StatusCode> {
    let mut redis_con = appstate
        .redis_pool
        .get()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let refresh_token = token.token;
    let token_bytes = decode_token(&refresh_token).map_err(|_| StatusCode::OK)?;
    let token_hash = hash_token(&token_bytes);
    let key = create_verification_key(crate::TokenType::Refresh, &token_hash);
    delete_token_from_redis(&mut redis_con, &key)
        .await
        .map_err(|_| StatusCode::OK)?; // already deleted
    Ok(StatusCode::NO_CONTENT)
}
