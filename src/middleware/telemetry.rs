use axum::{debug_middleware, extract::Request, middleware::Next, response::Response};
use tracing::{Instrument, info_span};
use uuid::Uuid;

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
