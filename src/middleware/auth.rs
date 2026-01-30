use crate::Claims;
use axum::{
    debug_middleware,
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use jsonwebtoken::{DecodingKey, Validation, decode};
use secrecy::{ExposeSecret, SecretString};
use tracing::{debug, error, instrument};

/// accepts the request and extracts the JWT access token and then evaluate its validity
#[debug_middleware]
#[instrument(skip_all)]
pub async fn validate_jwt_access_token(
    State(secret): State<SecretString>,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    debug!("extracting JWT access token from request headers.");
    let token = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|v| v.trim())
        .ok_or(StatusCode::UNAUTHORIZED)
        .inspect_err(|e| error!("failed to extract the access token: {}", e))?;
    debug!("validating jwt claims.");
    let claims = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.expose_secret().as_bytes()),
        &Validation::default(),
    )
    .inspect_err(|e| error!("error validating jwt access token: {}", e))
    .map_err(|_| StatusCode::UNAUTHORIZED)?
    .claims;
    debug!("inserting claims as extension.");
    req.extensions_mut().insert(claims);
    debug!("passing request to the handler.");
    Ok(next.run(req).await)
}
