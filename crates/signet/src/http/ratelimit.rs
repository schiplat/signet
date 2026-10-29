use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::state::AppState;

/// In-memory sliding-window rate limiter keyed by client IP.
pub struct RateLimiter {
    window: Duration,
    limit: usize,
    state: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl RateLimiter {
    pub fn new(per_minute: usize) -> Self {
        Self {
            window: Duration::from_secs(60),
            limit: per_minute,
            state: Mutex::new(HashMap::new()),
        }
    }

    fn allow(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut map = self.state.lock().unwrap_or_else(|e| e.into_inner());

        // Opportunistic cleanup to bound memory under many distinct IPs.
        if map.len() > 100_000 {
            map.retain(|_, q| {
                while q
                    .front()
                    .is_some_and(|t| now.duration_since(*t) > self.window)
                {
                    q.pop_front();
                }
                !q.is_empty()
            });
        }

        let q = map.entry(key.to_string()).or_default();
        while q
            .front()
            .is_some_and(|t| now.duration_since(*t) > self.window)
        {
            q.pop_front();
        }
        if q.len() >= self.limit {
            return false;
        }
        q.push_back(now);
        true
    }
}

/// axum middleware enforcing the global rate limit (see `AppState::rate_limiter`).
pub async fn track(State(state): State<AppState>, req: Request, next: Next) -> Response {
    // The shared extractor, not a local copy: rate-limit keys must obey the
    // same trusted-proxy rules as allowlists and audit IPs, or a spoofed
    // `X-Forwarded-For` would mint fresh rate-limit buckets per request.
    let key = crate::http::extract::client_ip(
        req.headers(),
        req.extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0),
    )
    .unwrap_or_else(|| "unknown".to_string());

    if state.rate_limiter.allow(&key) {
        next.run(req).await
    } else {
        (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({ "error": "rate limit exceeded" })),
        )
            .into_response()
    }
}
