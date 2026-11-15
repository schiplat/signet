//! The OTel trace export wiring: with a `tracing_opentelemetry` layer
//! installed, the access-log middleware's per-request span becomes an
//! exported OTel span carrying the correlation fields (`x-request-id`,
//! method, route, status). Without the layer the span is free — that case is
//! every deployment that has not set `SIGNET_OTEL_ENDPOINT` and is exercised
//! by every other test in this suite.

use axum::body::Body;
use axum::routing::get;
use axum::Router;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::trace::{SpanData, SpanExporter};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;
use tracing_subscriber::prelude::*;

/// Minimal in-memory exporter.
///
/// The SDK's `testing` feature ships one, but it also enables `rt-async-std`,
/// which drags the unmaintained `async-std`/`pin-utils` pair into the lockfile
/// (dev-only, but flagged by `cargo audit`). The middleware exports
/// synchronously, so a Vec behind a mutex is all this test needs.
#[derive(Debug, Default)]
struct CollectSpans(Arc<Mutex<Vec<SpanData>>>);

impl SpanExporter for CollectSpans {
    fn export(
        &mut self,
        batch: Vec<SpanData>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = OTelSdkResult> + Send + 'static>> {
        self.0.lock().expect("collect spans").extend(batch);
        Box::pin(async { Ok(()) })
    }
}

#[tokio::test]
async fn the_request_span_is_exported_with_its_correlation_fields() {
    let spans = Arc::new(Mutex::new(Vec::new()));
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_simple_exporter(CollectSpans(spans.clone()))
        .build();
    let tracer = provider.tracer("test");

    // Thread-local default dispatcher: everything this test's thread runs —
    // including the middleware the current-thread runtime drives — reports
    // into the OTel layer.
    let _guard = tracing::subscriber::set_default(
        tracing_subscriber::registry().with(tracing_opentelemetry::layer().with_tracer(tracer)),
    );

    // The middleware as the live router mounts it — request-id outermost, so
    // the access-log span reads the id from extensions like it does in prod.
    let app: Router = Router::new()
        .route("/health", get(|| async { "ok" }))
        .layer(axum::middleware::from_fn(signet::http::access_log::track))
        .layer(axum::middleware::from_fn(signet::http::request_id::track));
    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/health?probe=1")
        .body(Body::empty())
        .expect("build request");
    let response = app.oneshot(req).await.expect("middleware runs the handler");
    assert_eq!(response.status().as_u16(), 200);

    // The span closes when the middleware's own handle drops (it already has:
    // the call returned), so the simple exporter must have received it.
    let exported = spans.lock().expect("read exported spans");
    let span = exported
        .last()
        .expect("the http.request span is exported synchronously");
    assert_eq!(span.name, "http.request");
    let attrs: Vec<(String, String)> = span
        .attributes
        .iter()
        .map(|kv| (kv.key.to_string(), kv.value.to_string()))
        .collect();
    let get = |key: &str| {
        attrs
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };
    assert_eq!(get("http.request.method"), "GET");
    assert_eq!(get("http.route"), "/health");
    assert_eq!(get("http.response.status_code"), "200");
    // The request carried no x-request-id, so the middleware generated one —
    // whatever it is, the span must carry it rather than a placeholder.
    let request_id = get("request_id");
    assert!(
        !request_id.is_empty() && request_id != "-",
        "request_id = {request_id}"
    );
}
