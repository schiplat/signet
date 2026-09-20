//! Request-layer plumbing shared by every route.
//!
//! Two kinds of things live here, both concerned with the wire rather than with
//! any particular feature:
//!
//! * middleware that wraps every request (`access_log`, `request_id`,
//!   `ratelimit`),
//! * helpers that read facts off a request (`extract`, `source_ip`,
//!   `user_agent`),
//! * the static asset fallback that serves the dashboard (`static_files`).
//!
//! `ratelimit` also holds the limiter state that `AppState` carries, which is
//! why it is reachable as a module rather than being only a middleware
//! function.

pub mod access_log;
pub mod extract;
pub mod ratelimit;
pub mod request_id;
pub mod source_ip;
pub mod static_files;
pub mod user_agent;
