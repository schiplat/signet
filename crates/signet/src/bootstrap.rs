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

/// Pins the deployment's encryption key into `app_settings` on first boot and
/// refuses to serve when a later boot presents a different one.
///
/// TOTP secrets and webhook secrets are AES-GCM ciphertexts under this key.
/// Two instances serving one database with two keys is the silent disaster
/// case: each writes rows the other cannot read, and the symptom surfaces far
/// from the cause (a TOTP enrolled via instance A fails base32 decoding on
/// instance B). A fresh database records the first key it sees, so rolling
/// out the check changes nothing for existing deployments; an operator who
/// genuinely means to re-key clears the
/// `crypto.encryption_key_fingerprint` row in `app_settings`.
pub async fn ensure_encryption_key_fingerprint(pool: &PgPool, fingerprint: &str) -> Result<()> {
    const KEY: &str = "crypto.encryption_key_fingerprint";
    let stored: Option<String> =
        sqlx::query_scalar("SELECT value #>> '{}' FROM app_settings WHERE key = $1")
            .bind(KEY)
            .fetch_optional(pool)
            .await?;
    match stored.as_deref() {
        None => {
            sqlx::query("INSERT INTO app_settings (key, value, updated_at) VALUES ($1, $2, NOW())")
                .bind(KEY)
                .bind(serde_json::json!(fingerprint))
                .execute(pool)
                .await?;
            Ok(())
        }
        Some(prev) if prev == fingerprint => Ok(()),
        Some(_) => Err(anyhow::anyhow!(
            "the encryption key does not match the one this database was provisioned with \
             (stored fingerprint differs). Every instance serving one database must share a \
             single data/encryption.key, or TOTP and webhook secrets become unreadable across \
             instances. Point SIGNET_ENCRYPTION_KEY_PATH at the key the database was \
             provisioned with — or, only when you are certain no encrypted secrets remain, \
             delete the app_settings row 'crypto.encryption_key_fingerprint' to re-arm the check."
        )),
    }
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
