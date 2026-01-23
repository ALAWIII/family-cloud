use crate::{AppState, Claims};
use axum::{
    debug_middleware,
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use jsonwebtoken::{DecodingKey, Validation, decode};
use secrecy::{ExposeSecret, SecretString};

#[debug_middleware]
pub async fn auth_middleware(
    State(secret): State<SecretString>,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let token = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|v| v.trim())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let claims = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.expose_secret().as_bytes()),
        &Validation::default(),
    )
    .map_err(|_| StatusCode::UNAUTHORIZED)?
    .claims;
    req.extensions_mut().insert(claims);
    Ok(next.run(req).await)
}
