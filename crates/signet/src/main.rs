use clap::Parser;
use signet::build_app;
use signet::config::Config;
use signet::directory::cli::{Cli, Command as SignetCommand};
use std::fmt;
use std::net::SocketAddr;
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::FormatTime;
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;

/// Local-time timestamp rendered as `YYYY-MM-DD HH:MM:SS.mmm`.
struct LocalTime;

impl FormatTime for LocalTime {
    fn format_time(&self, w: &mut Writer<'_>) -> fmt::Result {
        write!(
            w,
            "{}",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3fZ")
        )
    }
}

fn init_logger() -> Option<signet::otel::OtelGuard> {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,signet=debug"));

    // OTel trace export is opt-in via SIGNET_OTEL_ENDPOINT; an exporter build
    // failure is reported and the process boots with plain logs (see the
    // module docs). The guard is returned to main: its Drop flushes batched
    // spans, so it must outlive the server drain.
    let otel = match signet::otel::init() {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!("OTLP trace export could not start: {e:#}");
            None
        }
    };
    // The layer is built per branch so its subscriber generic is inferred
    // against the subscriber that branch composes.
    let otel_layer =
        |o: &signet::otel::Otel| tracing_opentelemetry::layer().with_tracer(o.tracer.clone());

    let is_production = std::env::var("APP_ENV")
        .map(|v| v == "production")
        .unwrap_or(false);

    if is_production {
        // Production: flat single-line JSON for log aggregation.
        tracing_subscriber::registry()
            .with(filter)
            .with(otel.as_ref().map(otel_layer))
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .flatten_event(true)
                    .with_current_span(true)
                    .with_ansi(false)
                    .with_target(true),
            )
            .init();
    } else {
        // Development: readable compact text with source location.
        tracing_subscriber::registry()
            .with(filter)
            .with(otel.as_ref().map(otel_layer))
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(std::io::stdout)
                    .with_timer(LocalTime)
                    .with_ansi(true)
                    .with_level(true)
                    .with_target(true)
                    .with_line_number(true)
                    .compact(),
            )
            .init();
    }

    otel.map(|o| o.guard)
}

/// Resolves on SIGINT or SIGTERM. `axum::serve` then stops accepting and drains
/// in-flight requests.
///
/// Container orchestration stops a container with SIGTERM: without this, every
/// rolling restart cut live requests, half-finished directory syncs and in-flight
/// audit/webhook writes. Draining is also what lets a sync close its run row
/// instead of leaving it `running` for the staleness sweep.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            // No SIGTERM handler available (should not happen on unix): wait
            // forever, so the SIGINT arm still works on its own.
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutdown signal received; draining connections");
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Lives to the end of main: dropping it after the drain flushes the
    // trace spans of requests the graceful shutdown was still serving.
    let _otel_guard = init_logger();

    // No subcommand keeps the historical behaviour (read env, serve HTTP), so
    // existing container commands and deploy scripts keep working unchanged.
    let cli = Cli::parse();
    let cfg = Config::from_env()?;

    match cli.command {
        None | Some(SignetCommand::Serve) => {
            let bind = cfg.http_bind;
            let app = build_app(cfg).await?;

            // The effective issuer is logged with the runtime settings in
            // `build_state`: it may come from the dashboard, not from `cfg`.
            tracing::info!(%bind, "signet listening");
            let listener = tokio::net::TcpListener::bind(bind).await?;
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(shutdown_signal())
            .await?;
            Ok(())
        }
        Some(SignetCommand::Sync { command }) => {
            let state = signet::build_state(cfg).await?;
            signet::directory::cli::run(command, &state).await
        }
        Some(SignetCommand::Keys { command }) => {
            match command {
                signet::directory::cli::KeysCommand::Prune { keep } => {
                    let removed =
                        signet::crypto::keys::prune_retired(&cfg.jwt_retired_key_dir, keep)?;
                    println!("removed {removed} retired key(s); kept the newest {keep}");
                    tracing::info!(removed, keep, "pruned retired signing keys");
                }
                signet::directory::cli::KeysCommand::Rotate => {
                    let kid = signet::crypto::keys::rotate(
                        &cfg.jwt_private_key_path,
                        &cfg.jwt_retired_key_dir,
                    )?;
                    // Printed as well as logged: this is a CLI, and the kid is
                    // what the operator checks in /jwks afterwards.
                    println!("new signing key: {kid}");
                    println!(
                        "retired key written to {}",
                        cfg.jwt_retired_key_dir.display()
                    );
                    println!("restart signet to sign with the new key");
                    tracing::info!(%kid, "signing key rotated");
                }
            }
            Ok(())
        }
    }
}
