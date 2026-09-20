use axum::extract::Request;
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::Response;
use uuid::Uuid;

/// Header used to carry the correlation id across requests and services.
pub const X_REQUEST_ID: &str = "x-request-id";

/// Correlation id stored in request extensions so downstream handlers and the
/// trace layer can read it.
#[derive(Debug, Clone)]
pub struct RequestId(pub String);

/// Extracts an incoming `x-request-id` or generates a fresh UUID, stores it in
/// request extensions for the trace layer, and echoes it back on the response.
///
/// This middleware must be the outermost layer so that `TraceLayer`'s
/// `make_span_with` can read the id from extensions.
pub async fn track(mut req: Request, next: Next) -> Response {
    let id = req
        .headers()
        .get(X_REQUEST_ID)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    req.extensions_mut().insert(RequestId(id.clone()));

    let mut resp = next.run(req).await;

    if let Ok(value) = HeaderValue::from_str(&id) {
        resp.headers_mut().insert(X_REQUEST_ID, value);
    }
    resp
}
