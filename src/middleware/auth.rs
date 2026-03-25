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

/// Middleware that validates a JWT access token from the `Authorization`
/// header and injects its `Claims` into the request by:
/// 1. Extracting a `Bearer <token>` string from the `authorization` header;
///    returning `401 Unauthorized` if missing or malformed.
/// 2. Decoding and verifying the token using the shared HMAC secret, mapping
///    any validation failure to `401 Unauthorized`.
/// 3. Inserting the decoded `Claims` into the request extensions so
///    downstream handlers can access authenticated user data, then
///    forwarding the request to the next middleware/handler.
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
