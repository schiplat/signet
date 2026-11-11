use anyhow::{Context, Result};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::time::Duration;

/// Connects with a bounded, explicit pool.
///
/// `max_connections` is configurable because the right number depends on the
/// deployment: `/admin/stats` alone fans out six queries per dashboard open, so
/// a fixed 10 leaves everyone else queueing behind a two-person ops team.
/// `acquire_timeout` turns sqlx's 30-second default wait into a fast, visible
/// failure: a request that cannot get a connection in five seconds should
/// return an error, not hang until the client gives up.
pub async fn connect(database_url: &str, max_connections: u32) -> Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .min_connections(2)
        .acquire_timeout(Duration::from_secs(5))
        .idle_timeout(Duration::from_secs(300))
        .connect(database_url)
        .await
        .context("connect to postgres")?;
    Ok(pool)
}

pub async fn migrate(pool: &PgPool) -> Result<()> {
    // Migrations live at workspace root `migrations/`
    sqlx::migrate!("../../migrations")
        .run(pool)
        .await
        .context("run migrations")?;
    Ok(())
}
