use crate::config::Config;
use crate::crypto::encryption::Encryptor;
use anyhow::Result;
use sqlx::PgPool;
use uuid::Uuid;

/// True when at least one active `admin` user exists. Generic over the SQL
/// executor so it can run against either a `&PgPool` or a `&mut Transaction`.
pub async fn admin_exists<'c, E>(executor: E) -> Result<bool, sqlx::Error>
where
    E: sqlx::PgExecutor<'c>,
{
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE role = 'admin' AND status = 'active'")
            .fetch_one(executor)
            .await?;
    Ok(count > 0)
}

/// Seed the SCIM bearer token from `SIGNET_SCIM_BEARER_TOKEN` on first boot only.
/// Once a token exists (whether seeded or generated from the dashboard), the env
/// var is ignored so that UI-based rotation becomes the source of truth.
pub async fn ensure_scim_token(pool: &PgPool, cfg: &Config) -> Result<()> {
    let Some(env_token) = cfg.scim_bearer_token.as_deref() else {
        return Ok(());
    };
    let hash = crate::crypto::util::sha256_hex(env_token);
    sqlx::query(
        r#"
        INSERT INTO scim_config (id, token_hash) VALUES (TRUE, $1)
        ON CONFLICT (id) DO NOTHING
        "#,
    )
    .bind(hash)
    .execute(pool)
    .await?;
    Ok(())
}

/// Seals legacy plaintext `webhooks.secret` values with the application key and
/// clears the plaintext column.
///
/// Idempotent, so it runs on every boot and from every replica: the UPDATE is
/// guarded on `secret IS NOT NULL`, and a concurrent migrator simply finds
/// nothing left to do.
pub async fn encrypt_webhook_secrets(pool: &PgPool, encryptor: &Encryptor) -> Result<()> {
    // NULL `secret_enc` distinguishes "not migrated yet" from "no secret set",
    // which is why the condition needs both predicates.
    let rows: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id, secret FROM webhooks WHERE secret IS NOT NULL AND secret_enc IS NULL",
    )
    .fetch_all(pool)
    .await?;

    if rows.is_empty() {
        return Ok(());
    }

    for (id, secret) in &rows {
        let enc = encryptor.encrypt(secret);
        sqlx::query(
            "UPDATE webhooks SET secret_enc = $2, secret = NULL, updated_at = NOW() \
             WHERE id = $1 AND secret IS NOT NULL",
        )
        .bind(id)
        .bind(&enc)
        .execute(pool)
        .await?;
    }

    tracing::info!(
        count = rows.len(),
        "migrated webhook secrets to encrypted storage"
    );
    Ok(())
}
