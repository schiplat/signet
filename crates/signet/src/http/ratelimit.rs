use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, StatusCode};
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
    let key = client_ip(
        req.headers(),
        req.extensions().get::<ConnectInfo<SocketAddr>>().cloned(),
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

/// Best-effort client IP: `X-Forwarded-For` → `X-Real-IP` → peer.
fn client_ip(headers: &HeaderMap, peer: Option<ConnectInfo<SocketAddr>>) -> Option<String> {
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = xff.split(',').next() {
            let t = first.trim();
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
    }
    if let Some(real) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        let t = real.trim();
        if !t.is_empty() {
            return Some(t.to_string());
        }
    }
    peer.map(|c| c.0.ip().to_string())
}
