use crate::Claims;
use axum::{extract::Request, http::StatusCode, middleware::Next, response::Response};
use jsonwebtoken::{DecodingKey, Validation, decode};

pub async fn auth_middleware(mut req: Request, next: Next) -> Result<Response, StatusCode> {
    let secret = std::env::var("HMAC_SECRET").unwrap();
    let token = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|v| v.trim())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let claims = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|_| StatusCode::UNAUTHORIZED)?
    .claims;
    req.extensions_mut().insert(claims);
    Ok(next.run(req).await)
}
