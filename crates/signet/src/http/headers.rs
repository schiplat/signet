//! Response security headers.
//!
//! The dashboard is the crown-jewel surface — a session cookie and the client
//! secret dialogs live there — so the standard browser hardening is applied to
//! every response rather than per route. None of it is a substitute for the
//! server-side checks elsewhere; it bounds what a successful injection or a
//! framing trick could do.
//!
//! The CSP allows `'unsafe-inline'` for styles only: the server-rendered
//! test-callback page sets `style="..."` attributes, and the SPA has a handful
//! of inline style attributes. Scripts are strictly same-origin — the Vite build
//! emits external bundles, and the Google Fonts dependency is gone, so nothing
//! third-party needs an allowance.

use axum::extract::Request;
use axum::http::header::{
    CONTENT_SECURITY_POLICY, REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
};
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::Response;

const CSP: &str = "default-src 'self'; \
     script-src 'self'; \
     style-src 'self' 'unsafe-inline'; \
     img-src 'self' data:; \
     font-src 'self'; \
     connect-src 'self'; \
     frame-ancestors 'none'; \
     base-uri 'none'; \
     form-action 'self'";

pub async fn security(req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP));
    // Nothing in the product uses these browser capabilities; denying them
    // shrinks the surface without a compatibility cost.
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    response
}
