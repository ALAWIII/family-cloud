use axum::{debug_middleware, extract::Request, middleware::Next, response::Response};
use tracing::{Instrument, info_span};
use uuid::Uuid;

/// Middleware that assigns a unique `request_id` and wraps each HTTP
/// request in a tracing span by:
/// 1. Generating a UUID and storing it in the request extensions so
///    handlers and logs can correlate work across layers.
/// 2. Creating an `info_span!` named `http_request` with the request id,
///    method, and path as fields.
/// 3. Executing the rest of the middleware/handler chain within this span
///    so all logs for the request share the same context.
#[debug_middleware]
pub async fn tracing_middleware(mut req: Request, next: Next) -> Response {
    let request_id = Uuid::new_v4().to_string();

    // attach request_id to request extensions (accessible everywhere)
    req.extensions_mut().insert(request_id.clone());

    let span = info_span!(
        "http_request",
        request_id = %request_id,
        method = %req.method(),
        path = %req.uri().path(),
    );

    next.run(req).instrument(span).await
}
