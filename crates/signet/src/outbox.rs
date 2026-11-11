//! Durable outbound delivery: webhooks and email, with backoff.
//!
//! Both sides of this module used to be best-effort in the worst way. Webhook
//! dispatch was a spawned task with a single attempt — a restart lost in-flight
//! dispatches and a receiver blip lost the event permanently. The reset email
//! was awaited inline, coupling the account-recovery request to whatever the
//! SMTP relay felt like that day.
//!
//! The outbox inverts the ownership: callers *enqueue* (one synchronous INSERT,
//! cheap and durable), and a background worker delivers with backoff
//! (`1m → 5m → 30m`, five attempts, then the row is dropped with its last
//! error). Delivery latency is the poll interval, which is fine for operational
//! notifications; the guarantee is "enqueued means at-least-five-attempts",
//! which fire-and-forget never had.

use crate::state::AppState;
use anyhow::{anyhow, Result};
use serde_json::Value;
use std::time::Duration;
use uuid::Uuid;

/// Delivery attempt schedule. Index = attempt number; the 6th failure drops
/// the row.
const BACKOFF: &[Duration] = &[
    Duration::from_secs(60),
    Duration::from_secs(5 * 60),
    Duration::from_secs(30 * 60),
    Duration::from_secs(30 * 60),
    Duration::from_secs(30 * 60),
];

/// How often the worker looks for due rows.
const POLL: Duration = Duration::from_secs(10);

/// One webhook delivery, enqueued durably.
pub async fn enqueue_webhook(state: &AppState, event_id: Uuid, payload: &Value) -> Result<()> {
    let rows: Vec<(Uuid,)> =
        sqlx::query_as("SELECT id FROM webhooks WHERE enabled AND kind IS NOT NULL")
            .fetch_all(&state.pool)
            .await
            .unwrap_or_default();
    if rows.is_empty() {
        return Ok(());
    }
    for (webhook_id,) in &rows {
        sqlx::query(
            r#"
            INSERT INTO outbox (id, kind, webhook_id, event_id, payload)
            VALUES ($1, 'webhook', $2, $3, $4)
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(webhook_id)
        .bind(event_id)
        .bind(payload)
        .execute(&state.pool)
        .await
        .map_err(|e| anyhow!("enqueue webhook delivery: {e}"))?;
    }
    Ok(())
}

/// One email, enqueued durably.
///
/// `log_body` rides along for the dev fallback (see [`crate::email`]). The body
/// can carry a one-time reset link, so it is sealed with the application key
/// before it touches the table.
pub async fn enqueue_email(
    state: &AppState,
    to: &str,
    subject: &str,
    body: &str,
    log_body: bool,
) -> Result<()> {
    let sealed = state.encryptor.encrypt(body);
    sqlx::query(
        r#"
        INSERT INTO outbox (id, kind, email_to, email_subject, email_body_enc, email_log_body)
        VALUES ($1, 'email', $2, $3, $4, $5)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(to)
    .bind(subject)
    .bind(&sealed)
    .bind(log_body)
    .execute(&state.pool)
    .await
    .map_err(|e| anyhow!("enqueue email: {e}"))?;
    Ok(())
}

/// Starts the delivery worker. Called once from `build_app`.
pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(POLL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            if let Err(e) = drain_due(&state).await {
                tracing::warn!(error = %e, "outbox delivery pass failed; retrying next tick");
            }
        }
    });
}

/// Delivers every row whose backoff has elapsed. Bounded per pass by the
/// due-index select; a large backlog drains over ticks.
///
/// One struct instead of a ten-tuple: `sqlx::FromRow` keeps the SELECT honest
/// about column names, and the match below reads like the domain.
#[derive(sqlx::FromRow)]
struct OutboxRow {
    id: Uuid,
    kind: String,
    webhook_id: Option<Uuid>,
    event_id: Option<Uuid>,
    payload: Option<Value>,
    email_to: Option<String>,
    email_subject: Option<String>,
    email_body_enc: Option<String>,
    email_log_body: Option<bool>,
    attempts: i32,
}

async fn drain_due(state: &AppState) -> Result<()> {
    let rows: Vec<OutboxRow> = sqlx::query_as(
        r#"
            SELECT id, kind, webhook_id, event_id, payload,
                   email_to, email_subject, email_body_enc, email_log_body, attempts
            FROM outbox
            WHERE attempts < 5 AND next_attempt_at <= NOW()
            ORDER BY next_attempt_at
            LIMIT 200
            "#,
    )
    .fetch_all(&state.pool)
    .await?;

    for row in rows {
        let result = match row.kind.as_str() {
            "webhook" => match (row.webhook_id, row.event_id, row.payload) {
                (Some(webhook_id), Some(event_id), Some(payload)) => {
                    deliver_webhook(state, webhook_id, event_id, &payload).await
                }
                _ => Err(anyhow!("outbox row {} is missing webhook fields", row.id)),
            },
            "email" => match (&row.email_to, &row.email_subject, &row.email_body_enc) {
                (Some(to), Some(subject), Some(sealed)) => {
                    let body = state
                        .encryptor
                        .decrypt(sealed)
                        .ok_or_else(|| anyhow!("outbox row {} body cannot be decrypted", row.id))?;
                    crate::email::send(
                        state,
                        to,
                        subject,
                        &body,
                        row.email_log_body.unwrap_or(false),
                    )
                    .await
                }
                _ => Err(anyhow!("outbox row {} is missing email fields", row.id)),
            },
            other => Err(anyhow!("outbox row {} has unknown kind {other}", row.id)),
        };

        match result {
            Ok(()) => {
                sqlx::query("DELETE FROM outbox WHERE id = $1")
                    .bind(row.id)
                    .execute(&state.pool)
                    .await?;
            }
            Err(e) => {
                let attempts = row.attempts + 1;
                if let Some(backoff) = BACKOFF.get(row.attempts as usize) {
                    sqlx::query(
                        "UPDATE outbox SET attempts = $2, next_attempt_at = NOW() + $3::interval, \
                         last_error = $4 WHERE id = $1",
                    )
                    .bind(row.id)
                    .bind(attempts)
                    .bind(backoff.as_secs().to_string() + " seconds")
                    .bind(e.to_string())
                    .execute(&state.pool)
                    .await?;
                } else {
                    tracing::warn!(error = %e, row = %row.id, attempts, "outbox row dropped after final attempt");
                    sqlx::query("DELETE FROM outbox WHERE id = $1")
                        .bind(row.id)
                        .execute(&state.pool)
                        .await?;
                }
            }
        }
    }
    Ok(())
}

/// The single-attempt delivery moved verbatim from `webhooks::dispatch` —
/// same validation, same pinning, same recording; only the ownership changed.
async fn deliver_webhook(
    state: &AppState,
    webhook_id: Uuid,
    event_id: Uuid,
    payload: &Value,
) -> Result<()> {
    let wh: Option<(Uuid, String, Option<String>, String)> =
        sqlx::query_as("SELECT id, url, secret_enc, kind FROM webhooks WHERE id = $1 AND enabled")
            .bind(webhook_id)
            .fetch_optional(&state.pool)
            .await?;
    let Some((id, url, secret_enc, kind)) = wh else {
        // Receiver deleted or disabled while the row waited: nothing to
        // deliver, and retrying would never help.
        return Ok(());
    };
    let wh = crate::webhooks::WebhookRef {
        id,
        url,
        secret_enc,
        kind,
    };
    crate::webhooks::attempt_delivery(state, &wh, event_id, payload).await
}
