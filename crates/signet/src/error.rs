use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Unauthorized(String),
    #[error("{0}")]
    Forbidden(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Conflict(String),
    /// A dependency the server talks to (an upstream directory, an IdP) failed or
    /// is unreachable. Distinct from `Anyhow` so the message reaches the client
    /// and the status is 502 rather than a generic 500.
    #[error("{0}")]
    Upstream(String),
    /// A dependency is temporarily unusable, so this request cannot be served
    /// *now* even though the request itself is fine. 503 rather than 502: it
    /// tells clients and load balancers the condition is transient and worth
    /// retrying, which is exactly the semantics of "the directory is down" (D6).
    #[error("{0}")]
    Unavailable(String),
    /// An OAuth 2.0 / OIDC protocol error (RFC 6749 §5.2). Unlike the generic
    /// variants above, this serializes the machine-readable `error` code that
    /// client libraries branch on, plus a human `error_description`. A 401 also
    /// carries `WWW-Authenticate`, which lets a Basic-auth client tell "wrong
    /// secret" apart from "bad grant" without parsing prose.
    #[error("{code}: {description}")]
    OAuth {
        status: StatusCode,
        code: &'static str,
        description: String,
    },
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
}

impl AppError {
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::BadRequest(msg.into())
    }

    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self::Unauthorized(msg.into())
    }

    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self::Forbidden(msg.into())
    }

    pub fn conflict(msg: impl Into<String>) -> Self {
        Self::Conflict(msg.into())
    }

    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::NotFound(msg.into())
    }

    pub fn upstream(msg: impl Into<String>) -> Self {
        Self::Upstream(msg.into())
    }

    pub fn unavailable(msg: impl Into<String>) -> Self {
        Self::Unavailable(msg.into())
    }

    /// A 400 protocol error with an RFC 6749 §5.2 code.
    pub fn oauth(code: &'static str, description: impl Into<String>) -> Self {
        Self::OAuth {
            status: StatusCode::BAD_REQUEST,
            code,
            description: description.into(),
        }
    }

    /// A 401 protocol error, for client-authentication failures.
    pub fn oauth_unauthorized(code: &'static str, description: impl Into<String>) -> Self {
        Self::OAuth {
            status: StatusCode::UNAUTHORIZED,
            code,
            description: description.into(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // Protocol errors have their own wire shape; everything else keeps the
        // `{"error": "..."}` envelope the dashboard reads.
        if let AppError::OAuth {
            status,
            code,
            description,
        } = &self
        {
            let mut response = (
                *status,
                Json(json!({ "error": code, "error_description": description })),
            )
                .into_response();
            if *status == StatusCode::UNAUTHORIZED {
                response.headers_mut().insert(
                    axum::http::header::WWW_AUTHENTICATE,
                    axum::http::HeaderValue::from_static("Basic realm=\"signet\""),
                );
            }
            return response;
        }

        let (status, message) = match &self {
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, m.clone()),
            AppError::Unauthorized(m) => (StatusCode::UNAUTHORIZED, m.clone()),
            AppError::Forbidden(m) => (StatusCode::FORBIDDEN, m.clone()),
            AppError::NotFound(m) => (StatusCode::NOT_FOUND, m.clone()),
            AppError::Conflict(m) => (StatusCode::CONFLICT, m.clone()),
            AppError::Upstream(m) => (StatusCode::BAD_GATEWAY, m.clone()),
            AppError::Unavailable(m) => (StatusCode::SERVICE_UNAVAILABLE, m.clone()),
            // Handled above; this arm exists so the match stays exhaustive
            // without a `_` that would silently swallow a future variant.
            AppError::OAuth { description, .. } => (StatusCode::BAD_REQUEST, description.clone()),
            AppError::Anyhow(e) => {
                tracing::error!(error = %e, "internal error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal server error".into(),
                )
            }
            AppError::Sqlx(e) => {
                tracing::error!(error = %e, "database error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal server error".into(),
                )
            }
        };

        (status, Json(json!({ "error": message }))).into_response()
    }
}

pub type AppResult<T> = Result<T, AppError>;
