use crate::audit::{record, AuditEvent};
use crate::email;
use crate::models::User;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

/// Track a successful login source and emit a new-device alert on first sight.
///
/// Best-effort: failures are logged but never fail the login itself.
pub async fn track_login(pool: &PgPool, user: &User, ip: Option<&str>, user_agent: Option<&str>) {
    let Some(ip) = ip else { return };
    if ip.is_empty() {
        return;
    }

    let is_new = match upsert_device(pool, user.id, ip, user_agent).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "failed to track login device");
            return;
        }
    };

    if !is_new {
        return;
    }

    record(
        pool,
        AuditEvent {
            actor: Some(user.clone()),
            action: "auth.new_device",
            resource_type: "user",
            resource_id: Some(user.id.to_string()),
            detail: json!({ "ip": ip, "user_agent": user_agent }),
            ip: Some(ip.to_string()),
            user_agent: user_agent.map(|s| s.to_string()),
            client_id: None,
        },
    )
    .await;

    email::send(
        &user.email,
        "Signet new sign-in device",
        &format!(
            "A sign-in from a new device/IP was detected for {}.\n\nIP: {}\nDevice: {}\n\nIf this was you, no action is needed. If not, change your password and review active sessions immediately.",
            user.email,
            ip,
            user_agent.unwrap_or("unknown"),
        ),
    )
    .await;
}

/// Returns `true` when this (user, ip) pair was seen for the first time.
async fn upsert_device(
    pool: &PgPool,
    user_id: Uuid,
    ip: &str,
    user_agent: Option<&str>,
) -> sqlx::Result<bool> {
    let exists: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM login_devices WHERE user_id = $1 AND ip = $2")
            .bind(user_id)
            .bind(ip)
            .fetch_one(pool)
            .await?;

    if exists == 0 {
        sqlx::query(
            "INSERT INTO login_devices (id, user_id, ip, user_agent) VALUES ($1, $2, $3, $4)",
        )
        .bind(Uuid::new_v4())
        .bind(user_id)
        .bind(ip)
        .bind(user_agent)
        .execute(pool)
        .await?;
        Ok(true)
    } else {
        sqlx::query(
            "UPDATE login_devices SET last_seen_at = NOW(), user_agent = $3 \
             WHERE user_id = $1 AND ip = $2",
        )
        .bind(user_id)
        .bind(ip)
        .bind(user_agent)
        .execute(pool)
        .await?;
        Ok(false)
    }
}
