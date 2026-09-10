use crate::audit::AuditEvent;
use crate::crypto_util::{hmac_sha256_b64, hmac_sha256_hex};
use crate::error::{AppError, AppResult};
use crate::roles::require_admin_role;
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/admin/webhooks", get(list_webhooks).post(create_webhook))
        .route(
            "/admin/webhooks/{id}",
            axum::routing::delete(delete_webhook),
        )
        .route("/admin/webhooks/{id}/deliveries", get(list_deliveries))
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
struct Webhook {
    id: Uuid,
    url: String,
    kind: String,
    enabled: bool,
    secret_set: bool,
}

const WEBHOOK_COLS: &str = "id, url, kind, enabled, (secret IS NOT NULL) AS secret_set";

async fn list_webhooks(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<Vec<Webhook>>> {
    let actor = crate::auth::current_user(&state, &headers).await?;
    require_admin_role(&actor)?;
    let rows = sqlx::query_as::<_, Webhook>(&format!(
        "SELECT {WEBHOOK_COLS} FROM webhooks ORDER BY created_at DESC"
    ))
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(rows))
}

#[derive(Debug, Deserialize)]
struct CreateWebhookBody {
    url: String,
    secret: Option<String>,
    kind: Option<String>,
}

fn normalize_kind(kind: Option<String>) -> AppResult<String> {
    let kind = kind
        .unwrap_or_else(|| "generic".into())
        .trim()
        .to_lowercase();
    match kind.as_str() {
        "generic" | "feishu" => Ok(kind),
        other => Err(AppError::bad_request(format!(
            "unsupported webhook kind: {other} (expected 'generic' or 'feishu')"
        ))),
    }
}

async fn create_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateWebhookBody>,
) -> AppResult<Json<Webhook>> {
    let actor = crate::auth::current_user(&state, &headers).await?;
    require_admin_role(&actor)?;

    let url = body.url.trim().to_string();
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(AppError::bad_request("webhook url must be http(s)"));
    }
    let kind = normalize_kind(body.kind)?;

    let row = sqlx::query_as::<_, Webhook>(&format!(
        r#"
        INSERT INTO webhooks (id, url, secret, kind) VALUES ($1, $2, $3, $4)
        RETURNING {WEBHOOK_COLS}
        "#,
    ))
    .bind(Uuid::new_v4())
    .bind(&url)
    .bind(
        body.secret
            .as_deref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
    )
    .bind(&kind)
    .fetch_one(&state.pool)
    .await?;

    crate::audit::record(
        &state.pool,
        AuditEvent {
            actor: Some(actor),
            action: "webhook.create",
            resource_type: "webhook",
            resource_id: Some(row.id.to_string()),
            detail: json!({ "url": row.url, "kind": row.kind }),
            ip: None,
            user_agent: crate::http_util::user_agent(&headers),
            client_id: None,
        },
    )
    .await;

    Ok(Json(row))
}

async fn delete_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> AppResult<Json<Value>> {
    let actor = crate::auth::current_user(&state, &headers).await?;
    require_admin_role(&actor)?;

    sqlx::query("DELETE FROM webhooks WHERE id = $1")
        .bind(id)
        .execute(&state.pool)
        .await?;

    crate::audit::record(
        &state.pool,
        AuditEvent {
            actor: Some(actor),
            action: "webhook.delete",
            resource_type: "webhook",
            resource_id: Some(id.to_string()),
            detail: json!({}),
            ip: None,
            user_agent: crate::http_util::user_agent(&headers),
            client_id: None,
        },
    )
    .await;

    Ok(Json(json!({ "ok": true })))
}

#[derive(Debug, sqlx::FromRow, Serialize)]
struct Delivery {
    id: Uuid,
    event_id: Uuid,
    status_code: Option<i16>,
    success: bool,
    error: Option<String>,
    created_at: DateTime<Utc>,
}

async fn list_deliveries(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> AppResult<Json<Vec<Delivery>>> {
    let actor = crate::auth::current_user(&state, &headers).await?;
    require_admin_role(&actor)?;
    let rows = sqlx::query_as::<_, Delivery>(
        r#"
        SELECT id, event_id, status_code, success, error, created_at
        FROM webhook_deliveries
        WHERE webhook_id = $1
        ORDER BY created_at DESC
        LIMIT 50
        "#,
    )
    .bind(id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(rows))
}

/// Fire-and-forget dispatch of an audit event to all enabled webhooks.
pub fn dispatch(pool: &PgPool, event_id: Uuid, payload: Value) {
    let pool = pool.clone();
    tokio::spawn(async move {
        if let Err(e) = deliver_all(&pool, event_id, &payload).await {
            tracing::warn!(error = %e, "webhook dispatch failed");
        }
    });
}

#[derive(Debug, sqlx::FromRow)]
struct WebhookRow {
    id: Uuid,
    url: String,
    kind: String,
    secret: Option<String>,
}

async fn deliver_all(pool: &PgPool, event_id: Uuid, payload: &Value) -> AppResult<()> {
    let rows = sqlx::query_as::<_, WebhookRow>(
        "SELECT id, url, kind, secret FROM webhooks WHERE enabled = TRUE",
    )
    .fetch_all(pool)
    .await?;

    for wh in rows {
        let pool = pool.clone();
        let payload = payload.clone();
        tokio::spawn(async move {
            if let Err(e) = deliver_one(&pool, &wh, event_id, &payload).await {
                tracing::warn!(webhook = %wh.id, error = %e, "webhook delivery failed");
            }
        });
    }
    Ok(())
}

async fn deliver_one(
    pool: &PgPool,
    wh: &WebhookRow,
    event_id: Uuid,
    payload: &Value,
) -> AppResult<()> {
    let (body, content_type) = if wh.kind == "feishu" {
        (
            feishu_body(payload, wh.secret.as_deref()),
            "application/json",
        )
    } else {
        (payload.to_string(), "application/json")
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| AppError::Anyhow(e.into()))?;

    let mut req = client
        .post(&wh.url)
        .header("content-type", content_type)
        .header("x-signet-event", event_id.to_string());

    // Generic webhooks sign via header; Feishu embeds sign in the body instead.
    if wh.kind != "feishu" {
        if let Some(s) = wh.secret.as_deref() {
            let sig = hmac_sha256_hex(s.as_bytes(), body.as_bytes());
            req = req.header("x-signet-signature", format!("sha256={sig}"));
        }
    }

    let (success, status_code, err) = match req.body(body).send().await {
        Ok(resp) => {
            let code = resp.status().as_u16();
            let ok = (200..300).contains(&code);
            (ok, Some(code as i16), None)
        }
        Err(e) => (false, None, Some(e.to_string())),
    };

    sqlx::query(
        r#"
        INSERT INTO webhook_deliveries (id, webhook_id, event_id, status_code, success, error)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(wh.id)
    .bind(event_id)
    .bind(status_code)
    .bind(success)
    .bind(err)
    .execute(pool)
    .await?;

    Ok(())
}

/// Build a Feishu custom-bot message body (interactive card), with optional
/// signature verification ("加签") embedded as `timestamp` + `sign`.
fn feishu_body(payload: &Value, secret: Option<&str>) -> String {
    let action = payload
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("audit event");
    let created = payload
        .get("created_at")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let event_id = payload.get("id").and_then(|v| v.as_str()).unwrap_or("");

    let mut body = json!({
        "msg_type": "interactive",
        "card": {
            "config": { "wide_screen_mode": true },
            "header": {
                "template": "blue",
                "title": { "tag": "plain_text", "content": format!("Signet · {action}") }
            },
            "elements": [
                { "tag": "div", "text": { "tag": "lark_md", "content": format_md(payload) } },
                { "tag": "hr" },
                {
                    "tag": "note",
                    "elements": [
                        { "tag": "plain_text", "content": format!("{created} · {event_id}") }
                    ]
                }
            ]
        }
    });

    if let Some(s) = secret {
        let ts = Utc::now().timestamp().to_string();
        let sign = hmac_sha256_b64(format!("{ts}\n{s}").as_bytes(), b"");
        body["timestamp"] = json!(ts);
        body["sign"] = json!(sign);
    }

    body.to_string()
}

fn format_md(payload: &Value) -> String {
    let mut lines: Vec<String> = Vec::new();

    if let Some(v) = payload.get("actor_email").and_then(|v| v.as_str()) {
        lines.push(format!("**操作者**: {v}"));
    }
    if let Some(v) = payload.get("action").and_then(|v| v.as_str()) {
        lines.push(format!("**动作**: {v}"));
    }
    if let Some(rt) = payload.get("resource_type").and_then(|v| v.as_str()) {
        let rid = payload
            .get("resource_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let res = if rid.is_empty() {
            rt.to_string()
        } else {
            format!("{rt} ({rid})")
        };
        lines.push(format!("**资源**: {res}"));
    }
    if let Some(v) = payload.get("ip").and_then(|v| v.as_str()) {
        lines.push(format!("**IP**: {v}"));
    }
    let mut device = Vec::new();
    if let Some(v) = payload.get("os").and_then(|v| v.as_str()) {
        device.push(v.to_string());
    }
    if let Some(v) = payload.get("browser").and_then(|v| v.as_str()) {
        device.push(v.to_string());
    }
    if !device.is_empty() {
        lines.push(format!("**设备**: {}", device.join(" / ")));
    }
    if let Some(detail) = payload.get("detail") {
        if !detail.is_null() {
            lines.push(format!("**详情**: {}", detail));
        }
    }

    lines.join("\n")
}
