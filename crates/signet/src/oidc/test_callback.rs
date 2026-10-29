//! The test-drive round trip for a registered client.
//!
//! `authorize` always permits one extra redirect for every client — the
//! test-callback URL on this very issuer. An administrator picks it from the
//! Clients page (which generates the PKCE pair and state), walks the real
//! login/consent flow, and lands here: the page proves the parts that live
//! entirely inside Signet (discovery, authorize, authentication, MFA gates,
//! consent, redirect match, scope grant) and names the parts it cannot reach
//! (the token endpoint — the server stores only the client secret's hash, so
//! it cannot perform a real exchange on the operator's behalf).
//!
//! The code is consumed on read, exactly like the real `/oauth/token` would:
//! the result page cannot be replayed or shared.

use crate::crypto::util::sha256_hex;
use crate::error::AppResult;
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::response::Html;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct TestCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

#[derive(Debug, sqlx::FromRow)]
struct CodeRow {
    id: uuid::Uuid,
    user_id: uuid::Uuid,
    scope: String,
    redirect_uri: String,
    consumed_at: Option<chrono::DateTime<chrono::Utc>>,
    expires_at: chrono::DateTime<chrono::Utc>,
}

/// The always-permitted test redirect URI for `client_id`.
pub fn test_callback_url(public_base: &str, client_id: &str) -> String {
    format!("{public_base}/oauth/test-callback/{client_id}")
}

pub async fn test_callback(
    State(state): State<AppState>,
    Path(client_id): Path<String>,
    Query(q): Query<TestCallbackQuery>,
) -> AppResult<Html<String>> {
    let esc = |s: &str| {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
    };

    let fail = |msg: String| {
        Html(format!(
            "<!doctype html><meta charset=\"utf-8\"><title>Test drive failed</title>\
             <body style=\"font-family:ui-sans-serif;max-width:34rem;margin:3rem auto;padding:0 1rem\">\
             <h1 style=\"font-size:1.15rem\">Test drive failed</h1>\
             <p style=\"color:#b91c1c\">{}</p>\
             <p><a href=\"/clients\">Back to Clients</a></p></body>",
            esc(&msg)
        ))
    };

    if let Some(err) = q.error {
        return Ok(fail(format!(
            "authorize returned {} — {}",
            err,
            q.error_description.unwrap_or_default()
        )));
    }
    let Some(code) = q.code.as_deref() else {
        return Ok(fail("no code was returned".into()));
    };
    let state_note = match q.state.as_deref() {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => "(missing)".to_string(),
    };

    let row = sqlx::query_as::<_, CodeRow>(
        r#"
        SELECT id, user_id, scope, redirect_uri, consumed_at, expires_at
        FROM auth_codes WHERE code_hash = $1
        "#,
    )
    .bind(sha256_hex(code))
    .fetch_optional(&state.pool)
    .await?;

    let Some(row) = row else {
        return Ok(fail(
            "the code is unknown — it may have already been consumed".into(),
        ));
    };
    if row.consumed_at.is_some() {
        return Ok(fail(
            "the code was already used (codes are one-time)".into(),
        ));
    }
    if row.expires_at < chrono::Utc::now() {
        return Ok(fail("the code has expired".into()));
    }
    if row.redirect_uri != test_callback_url(state.config.public_base(), &client_id) {
        return Ok(fail(format!(
            "the code was issued for another client ({} vs {})",
            row.redirect_uri,
            test_callback_url(state.config.public_base(), &client_id)
        )));
    }

    // Consume like the real token endpoint would: one drive per code.
    sqlx::query("UPDATE auth_codes SET consumed_at = NOW() WHERE id = $1")
        .bind(row.id)
        .execute(&state.pool)
        .await?;

    let user: Option<(String, String)> =
        sqlx::query_as("SELECT email, display_name FROM users WHERE id = $1")
            .bind(row.user_id)
            .fetch_optional(&state.pool)
            .await?;
    let Some((email, display_name)) = user else {
        return Ok(fail("the authorizing user no longer exists".into()));
    };

    let ok = |label: &str, detail: String| {
        format!(
            "<li><strong>✔ {label}</strong><br><span style=\"color:#555\">{}</span></li>",
            esc(&detail)
        )
    };
    // The path segment is echoed into the page. Today only a real client code
    // can reach this render (the redirect check pins it, and codes constrain
    // the charset) — escaping keeps the page safe if that invariant moves.
    let safe_client_id = esc(&client_id);
    let html = format!(
        "<!doctype html><meta charset=\"utf-8\"><title>Test drive — {safe_client_id}</title>\
         <body style=\"font-family:ui-sans-serif;max-width:34rem;margin:3rem auto;padding:0 1rem;line-height:1.5\">\
         <h1 style=\"font-size:1.15rem\">Test drive passed for <code>{safe_client_id}</code></h1>\
         <p style=\"color:#555\">Everything inside Signet worked end to end:</p>\
         <ul style=\"padding-left:1.2rem\">\
         {}\
         {}\
         {}\
         {}\
         {}\
         </ul>\
         <p style=\"background:#fffbeb;border:1px solid #fde68a;border-radius:.5rem;padding:.75rem 1rem\">\
         <strong>Not covered by this drive:</strong> the token endpoint, PKCE verifier and the client \
         secret. Signet stores only the secret's hash, so it cannot exchange the code on your \
         behalf — verify those with your real integration (or the quickstart example) once.</p>\
         <p><a href=\"/clients\">Back to Clients</a></p></body>",
        ok("Authentication", format!("{display_name} <{email}>")),
        ok("Consent & scopes", row.scope.clone()),
        ok(
            "Redirect match",
            "the exact test URI was accepted and the code came back to it".to_string(),
        ),
        ok("Code", "valid, one-time, now consumed".to_string()),
        ok("state (as generated by the console)", state_note),
    );
    Ok(Html(html))
}
