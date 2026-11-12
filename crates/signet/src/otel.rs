//! Optional OpenTelemetry trace export (OTLP/HTTP, protobuf).
//!
//! Everything here is opt-in and env-configured, like the rest of the boot
//! configuration: without `SIGNET_OTEL_ENDPOINT` no SDK, exporter or layer is
//! built and tracing behaves exactly as before. With it, the access-log
//! middleware's per-request span (`http.request`) and anything it nests in
//! flows to an OTLP collector — Tempo, Jaeger, SigNoz, a vendor agent — and
//! carries the same `x-request-id` the JSON logs use, so the two join on one
//! field when reconciling a trace against its log lines.
//!
//! Configuration is boot-time only, deliberately: the tracing subscriber is
//! installed before the database exists, and a tracing pipeline is not the
//! kind of thing that can hot-swap its exporter mid-flight anyway.

use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::{Protocol, WithExportConfig as _};
use opentelemetry_sdk::resource::Resource;
use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider, Tracer};
use std::time::Duration;

/// The endpoint variable that switches OTLP export on
/// (`http://collector:4318/v1/traces` for the standard OTLP/HTTP port).
pub const OTEL_ENDPOINT_ENV: &str = "SIGNET_OTEL_ENDPOINT";
/// Overrides the `service.name` resource attribute (default `signet`).
pub const OTEL_SERVICE_NAME_ENV: &str = "SIGNET_OTEL_SERVICE_NAME";
/// Fraction of traces to sample, 0.0–1.0 (default 1.0).
pub const OTEL_SAMPLE_RATIO_ENV: &str = "SIGNET_OTEL_SAMPLE_RATIO";

/// How the exporter behaves once installed. Held to the end of `main` so its
/// `Drop` (which flushes the batch processor) runs *after* the server has
/// drained in-flight requests — dropping it early would lose the traces of
/// requests the graceful shutdown is still serving.
pub struct OtelGuard {
    provider: SdkTracerProvider,
}

impl Drop for OtelGuard {
    fn drop(&mut self) {
        // Batched spans must reach the collector before the process exits.
        // Best effort: an unreachable collector fails this, but the shutdown
        // path is not the place to retry or block the process over it.
        let _ = self.provider.shutdown();
    }
}

/// What `init` hands back: the guard to keep alive, and the tracer main.rs
/// wraps in a `tracing_opentelemetry` layer (per subscriber branch, so the
/// layer's subscriber generic is inferred where it is used).
pub struct Otel {
    pub guard: OtelGuard,
    pub tracer: Tracer,
}

/// Reads the OTLP configuration; `None` when the endpoint is unset.
fn read_config() -> Option<(String, String, f64)> {
    let endpoint = std::env::var(OTEL_ENDPOINT_ENV)
        .ok()
        .map(|e| e.trim().to_string())
        .filter(|e| !e.is_empty())?;
    let service_name = std::env::var(OTEL_SERVICE_NAME_ENV)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "signet".to_string());
    let ratio = std::env::var(OTEL_SAMPLE_RATIO_ENV)
        .ok()
        .and_then(|r| r.trim().parse::<f64>().ok())
        .map(|r| r.clamp(0.0, 1.0))
        .unwrap_or(1.0);
    Some((endpoint, service_name, ratio))
}

/// Builds the provider. Failure is reported, not fatal (see below).
fn build_provider(
    endpoint: &str,
    service_name: &str,
    ratio: f64,
) -> anyhow::Result<SdkTracerProvider> {
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_endpoint(endpoint)
        .with_protocol(Protocol::HttpBinary)
        .with_timeout(Duration::from_secs(10))
        .build()?;

    let resource = Resource::builder()
        .with_service_name(service_name.to_string())
        .with_attributes([opentelemetry::KeyValue::new(
            "service.version",
            env!("CARGO_PKG_VERSION"),
        )])
        .build();

    Ok(SdkTracerProvider::builder()
        .with_resource(resource)
        // Parent-based: once a trace is (not) sampled upstream — a gateway
        // instrumentation, say — we honor that; the ratio governs root spans
        // only. Sampled `Signet` events all flow as one trace per request.
        .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
            ratio,
        ))))
        .with_batch_exporter(exporter)
        .build())
}

/// Installs the OpenTelemetry span layer when `SIGNET_OTEL_ENDPOINT` is set.
///
/// Returns the guard (hold it to the end of `main`) and the layer to add to
/// the subscriber. On exporter-build failure the process keeps booting with
/// plain logs — an observability backend being misconfigured must not take
/// the IdP with it.
pub fn init() -> anyhow::Result<Option<Otel>> {
    let Some((endpoint, service_name, ratio)) = read_config() else {
        return Ok(None);
    };
    let provider = build_provider(&endpoint, &service_name, ratio)?;
    let tracer = provider.tracer(service_name.clone());
    tracing::info!(
        endpoint = %endpoint,
        service_name = %service_name,
        sample_ratio = ratio,
        "OTLP trace export enabled"
    );
    Ok(Some(Otel {
        guard: OtelGuard { provider },
        tracer,
    }))
}
