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

fn init_logger() {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,signet=debug"));

    let is_production = std::env::var("APP_ENV")
        .map(|v| v == "production")
        .unwrap_or(false);

    if is_production {
        // Production: flat single-line JSON for log aggregation.
        tracing_subscriber::registry()
            .with(filter)
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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_logger();

    // No subcommand keeps the historical behaviour (read env, serve HTTP), so
    // existing container commands and deploy scripts keep working unchanged.
    let cli = Cli::parse();
    let cfg = Config::from_env()?;

    match cli.command {
        None | Some(SignetCommand::Serve) => {
            let bind = cfg.http_bind;
            let issuer = cfg.issuer.clone();
            let app = build_app(cfg).await?;

            tracing::info!(%bind, %issuer, "signet listening");
            let listener = tokio::net::TcpListener::bind(bind).await?;
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await?;
            Ok(())
        }
        Some(SignetCommand::Sync { command }) => {
            let state = signet::build_state(cfg).await?;
            signet::directory::cli::run(command, &state).await
        }
    }
}
