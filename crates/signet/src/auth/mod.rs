//! Sign-in and credentials.
//!
//! `routes` is the session-based sign-in flow and the account self-service
//! endpoints (`/me/*`). The remaining modules are the other ways in and the
//! pieces they share: password credentials, the password-reset flow, WebAuthn
//! passkeys, and the new-device notification sent after a successful sign-in.

pub mod login_alert;
pub mod passkey;
pub mod password;
pub mod password_reset;
mod routes;
pub mod session;

pub use routes::router;
pub use session::{
    clear_session_cookie, create_session, current_user, destroy_session, SESSION_COOKIE,
};
