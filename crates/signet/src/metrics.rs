use std::sync::atomic::{AtomicU64, Ordering};

use axum::extract::{Request, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::state::AppState;

static LOGINS_TOTAL: AtomicU64 = AtomicU64::new(0);
static LOGIN_FAILURES_TOTAL: AtomicU64 = AtomicU64::new(0);
/// Passwords the owning directory rejected (bind returned `invalidCredentials`).
/// Separate from `LOGIN_FAILURES_TOTAL`, which counts only locally verified
/// rejections, so the two systems' failure rates stay distinguishable (§8.4).
static DIRECTORY_LOGIN_FAILURES_TOTAL: AtomicU64 = AtomicU64::new(0);
/// Logins that could not be attempted because the directory was unreachable.
/// A non-zero rate here means 503s in the dashboard, not 401s (§8.3).
static DIRECTORY_UNAVAILABLE_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Sync runs that started, by any trigger. Dry runs are excluded: they open no
/// run row, so counting them would make the number disagree with the run history.
static DIRECTORY_SYNC_RUNS_TOTAL: AtomicU64 = AtomicU64::new(0);
/// Runs that ended `failed` — the engine threw. The directory may have stopped
/// answering, or the writes may have hit an unexpected constraint.
static DIRECTORY_SYNC_FAILURES_TOTAL: AtomicU64 = AtomicU64::new(0);
/// Runs that ended `partial`: they completed, but conflicts or unreadable entries
/// were left for a human. Kept separate from failures because the operator action
/// is different — nothing is broken, something needs a decision.
static DIRECTORY_SYNC_PARTIAL_TOTAL: AtomicU64 = AtomicU64::new(0);
/// Entries that collided with an unmanaged local account, summed over runs.
static DIRECTORY_SYNC_CONFLICTS_TOTAL: AtomicU64 = AtomicU64::new(0);
/// Unix time of the last run that finished `succeeded`, 0 for never.
///
/// This is the metric the scheduler exists to make checkable: the failure mode of
/// a background sync is *silence*, and a staleness alert on this gauge is the only
/// thing that notices. Deliberately not advanced by `partial` runs — those need a
/// human, so treating them as fresh would hide the problem they are reporting.
static DIRECTORY_SYNC_LAST_SUCCESS_SECONDS: AtomicU64 = AtomicU64::new(0);
static TOKENS_ISSUED_TOTAL: AtomicU64 = AtomicU64::new(0);
static MFA_VERIFY_TOTAL: AtomicU64 = AtomicU64::new(0);
static MFA_VERIFY_FAILURES_TOTAL: AtomicU64 = AtomicU64::new(0);

static HTTP_TOTAL: AtomicU64 = AtomicU64::new(0);
static HTTP_2XX: AtomicU64 = AtomicU64::new(0);
static HTTP_3XX: AtomicU64 = AtomicU64::new(0);
static HTTP_4XX: AtomicU64 = AtomicU64::new(0);
static HTTP_5XX: AtomicU64 = AtomicU64::new(0);

static HTTP_IN_FLIGHT: AtomicU64 = AtomicU64::new(0);

// Fixed-bucket latency histogram (seconds).
static BUCKETS: [f64; 11] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];
static BUCKET_COUNTS: [AtomicU64; 11] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
static DURATION_SUM_SECS: AtomicU64 = AtomicU64::new(0); // micros
static DURATION_COUNT: AtomicU64 = AtomicU64::new(0);

pub fn inc_logins() {
    LOGINS_TOTAL.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_login_failures() {
    LOGIN_FAILURES_TOTAL.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_directory_login_failures() {
    DIRECTORY_LOGIN_FAILURES_TOTAL.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_directory_unavailable() {
    DIRECTORY_UNAVAILABLE_TOTAL.fetch_add(1, Ordering::Relaxed);
}

/// One sync run has started (never called for a dry run).
pub fn inc_directory_sync_run() {
    DIRECTORY_SYNC_RUNS_TOTAL.fetch_add(1, Ordering::Relaxed);
}

/// One sync run ended `failed`.
pub fn inc_directory_sync_failure() {
    DIRECTORY_SYNC_FAILURES_TOTAL.fetch_add(1, Ordering::Relaxed);
}

/// One sync run ended `partial` — it completed but left conflicts or errors.
pub fn inc_directory_sync_partial() {
    DIRECTORY_SYNC_PARTIAL_TOTAL.fetch_add(1, Ordering::Relaxed);
}

/// Records the conflicts found by one run, plus a success if it was clean.
///
/// Called once per finished run with the whole result, rather than incrementing
/// from inside the apply loop: a single call at the end cannot be reached twice
/// by a partially applied plan, and it keeps the counters equal to the run
/// history by construction.
pub fn record_directory_sync_outcome(status: &str, conflicts: i64) {
    if conflicts > 0 {
        DIRECTORY_SYNC_CONFLICTS_TOTAL.fetch_add(conflicts as u64, Ordering::Relaxed);
    }
    match status {
        "succeeded" => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            DIRECTORY_SYNC_LAST_SUCCESS_SECONDS.store(now, Ordering::Relaxed);
        }
        "partial" => inc_directory_sync_partial(),
        _ => inc_directory_sync_failure(),
    }
}
pub fn inc_tokens_issued() {
    TOKENS_ISSUED_TOTAL.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_mfa_verify() {
    MFA_VERIFY_TOTAL.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_mfa_verify_failure() {
    MFA_VERIFY_FAILURES_TOTAL.fetch_add(1, Ordering::Relaxed);
}

/// axum middleware: records request count, status class, latency.
pub async fn track(req: Request, next: Next) -> Response {
    HTTP_TOTAL.fetch_add(1, Ordering::Relaxed);
    HTTP_IN_FLIGHT.fetch_add(1, Ordering::Relaxed);
    let start = std::time::Instant::now();
    let resp = next.run(req).await;
    let micros = start.elapsed().as_micros() as u64;
    HTTP_IN_FLIGHT.fetch_sub(1, Ordering::Relaxed);

    let secs = micros as f64 / 1_000_000.0;
    for (i, le) in BUCKETS.iter().enumerate() {
        if secs <= *le {
            BUCKET_COUNTS[i].fetch_add(1, Ordering::Relaxed);
        }
    }
    DURATION_SUM_SECS.fetch_add(micros, Ordering::Relaxed);
    DURATION_COUNT.fetch_add(1, Ordering::Relaxed);

    let code = resp.status().as_u16();
    match code {
        200..=299 => HTTP_2XX.fetch_add(1, Ordering::Relaxed),
        300..=399 => HTTP_3XX.fetch_add(1, Ordering::Relaxed),
        400..=499 => HTTP_4XX.fetch_add(1, Ordering::Relaxed),
        _ => HTTP_5XX.fetch_add(1, Ordering::Relaxed),
    };

    resp
}

/// Liveness/readiness: probes the database and reports dependency health.
pub async fn health(State(state): State<AppState>) -> Response {
    let db_ok = sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.pool)
        .await
        .is_ok();

    if db_ok {
        (StatusCode::OK, "ok").into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "unavailable: db").into_response()
    }
}

fn render() -> String {
    let mut out = String::with_capacity(2048);

    out.push_str("# HELP signet_logins_total Successful Signet sign-ins (sessions established).\n");
    out.push_str("# TYPE signet_logins_total counter\n");
    out.push_str(&format!(
        "signet_logins_total {}\n",
        LOGINS_TOTAL.load(Ordering::Relaxed)
    ));

    out.push_str("# HELP signet_login_failures_total Failed password logins.\n");
    out.push_str("# TYPE signet_login_failures_total counter\n");
    out.push_str(&format!(
        "signet_login_failures_total {}\n",
        LOGIN_FAILURES_TOTAL.load(Ordering::Relaxed)
    ));

    out.push_str("# HELP signet_directory_login_failures_total Passwords rejected by the owning directory (LDAP bind-through).\n");
    out.push_str("# TYPE signet_directory_login_failures_total counter\n");
    out.push_str(&format!(
        "signet_directory_login_failures_total {}\n",
        DIRECTORY_LOGIN_FAILURES_TOTAL.load(Ordering::Relaxed)
    ));

    out.push_str("# HELP signet_directory_unavailable_total Logins that could not be attempted because the directory was unreachable.\n");
    out.push_str("# TYPE signet_directory_unavailable_total counter\n");
    out.push_str(&format!(
        "signet_directory_unavailable_total {}\n",
        DIRECTORY_UNAVAILABLE_TOTAL.load(Ordering::Relaxed)
    ));

    out.push_str("# HELP signet_directory_sync_runs_total Directory sync runs started (excludes dry runs).\n");
    out.push_str("# TYPE signet_directory_sync_runs_total counter\n");
    out.push_str(&format!(
        "signet_directory_sync_runs_total {}\n",
        DIRECTORY_SYNC_RUNS_TOTAL.load(Ordering::Relaxed)
    ));

    out.push_str(
        "# HELP signet_directory_sync_failures_total Directory sync runs that ended failed.\n",
    );
    out.push_str("# TYPE signet_directory_sync_failures_total counter\n");
    out.push_str(&format!(
        "signet_directory_sync_failures_total {}\n",
        DIRECTORY_SYNC_FAILURES_TOTAL.load(Ordering::Relaxed)
    ));

    out.push_str("# HELP signet_directory_sync_partial_total Directory sync runs that completed with conflicts or entry errors.\n");
    out.push_str("# TYPE signet_directory_sync_partial_total counter\n");
    out.push_str(&format!(
        "signet_directory_sync_partial_total {}\n",
        DIRECTORY_SYNC_PARTIAL_TOTAL.load(Ordering::Relaxed)
    ));

    out.push_str("# HELP signet_directory_sync_conflicts_total Directory entries that collided with an unmanaged local account.\n");
    out.push_str("# TYPE signet_directory_sync_conflicts_total counter\n");
    out.push_str(&format!(
        "signet_directory_sync_conflicts_total {}\n",
        DIRECTORY_SYNC_CONFLICTS_TOTAL.load(Ordering::Relaxed)
    ));

    out.push_str("# HELP signet_directory_sync_last_success_timestamp_seconds Unix time of the last fully successful sync run (0 = never).\n");
    out.push_str("# TYPE signet_directory_sync_last_success_timestamp_seconds gauge\n");
    out.push_str(&format!(
        "signet_directory_sync_last_success_timestamp_seconds {}\n",
        DIRECTORY_SYNC_LAST_SUCCESS_SECONDS.load(Ordering::Relaxed)
    ));

    out.push_str("# HELP signet_tokens_issued_total OIDC token responses issued.\n");
    out.push_str("# TYPE signet_tokens_issued_total counter\n");
    out.push_str(&format!(
        "signet_tokens_issued_total {}\n",
        TOKENS_ISSUED_TOTAL.load(Ordering::Relaxed)
    ));

    out.push_str("# HELP signet_mfa_verifications_total MFA verification attempts.\n");
    out.push_str("# TYPE signet_mfa_verifications_total counter\n");
    out.push_str(&format!(
        "signet_mfa_verifications_total {}\n",
        MFA_VERIFY_TOTAL.load(Ordering::Relaxed)
    ));

    out.push_str("# HELP signet_mfa_verification_failures_total MFA verification failures.\n");
    out.push_str("# TYPE signet_mfa_verification_failures_total counter\n");
    out.push_str(&format!(
        "signet_mfa_verification_failures_total {}\n",
        MFA_VERIFY_FAILURES_TOTAL.load(Ordering::Relaxed)
    ));

    out.push_str("# HELP signet_http_requests_total Total HTTP requests by status class.\n");
    out.push_str("# TYPE signet_http_requests_total counter\n");
    out.push_str(&format!(
        "signet_http_requests_total{} {}\n",
        "{status=\"2xx\"}",
        HTTP_2XX.load(Ordering::Relaxed)
    ));
    out.push_str(&format!(
        "signet_http_requests_total{} {}\n",
        "{status=\"3xx\"}",
        HTTP_3XX.load(Ordering::Relaxed)
    ));
    out.push_str(&format!(
        "signet_http_requests_total{} {}\n",
        "{status=\"4xx\"}",
        HTTP_4XX.load(Ordering::Relaxed)
    ));
    out.push_str(&format!(
        "signet_http_requests_total{} {}\n",
        "{status=\"5xx\"}",
        HTTP_5XX.load(Ordering::Relaxed)
    ));

    out.push_str("# HELP signet_http_requests_in_flight Current in-flight requests.\n");
    out.push_str("# TYPE signet_http_requests_in_flight gauge\n");
    out.push_str(&format!(
        "signet_http_requests_in_flight {}\n",
        HTTP_IN_FLIGHT.load(Ordering::Relaxed)
    ));

    out.push_str("# HELP signet_http_request_duration_seconds HTTP request latency.\n");
    out.push_str("# TYPE signet_http_request_duration_seconds histogram\n");
    let mut cumulative = 0u64;
    for (i, le) in BUCKETS.iter().enumerate() {
        cumulative += BUCKET_COUNTS[i].load(Ordering::Relaxed);
        out.push_str(&format!(
            "signet_http_request_duration_seconds_bucket{{le=\"{}\"}} {}\n",
            le, cumulative
        ));
    }
    out.push_str(&format!(
        "signet_http_request_duration_seconds_bucket{{le=\"+Inf\"}} {}\n",
        DURATION_COUNT.load(Ordering::Relaxed)
    ));
    out.push_str(&format!(
        "signet_http_request_duration_seconds_sum {}\n",
        DURATION_SUM_SECS.load(Ordering::Relaxed) as f64 / 1_000_000.0
    ));
    out.push_str(&format!(
        "signet_http_request_duration_seconds_count {}\n",
        DURATION_COUNT.load(Ordering::Relaxed)
    ));

    out
}

pub async fn metrics() -> Response {
    let mut resp = Response::new(axum::body::Body::from(render()));
    resp.headers_mut().insert(
        CONTENT_TYPE,
        axum::http::HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    resp
}
