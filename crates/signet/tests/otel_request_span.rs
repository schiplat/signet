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
use tower::ServiceExt;
use tracing_subscriber::prelude::*;

#[tokio::test]
async fn the_request_span_is_exported_with_its_correlation_fields() {
    let (exporter, mut rx, _shutdown_rx) =
        opentelemetry_sdk::testing::trace::new_tokio_test_exporter();
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_simple_exporter(exporter)
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
    let span = rx
        .try_recv()
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
