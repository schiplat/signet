//! The SCIM delete path must respect the same "never hard-delete a managed
//! user" rule (D3) the admin delete path enforces.
//!
//! This is driven through the real router rather than by calling a helper,
//! because what was wrong was the wiring: the guard simply was not there. A test
//! of an extracted predicate would keep passing after someone deleted the call
//! site, which is exactly the regression worth catching.
//!
//! The damage from getting it wrong is not a lost row but a changed identity:
//! `directory_entries.user_id` cascades, so deleting the user takes the link
//! with it, the next sync run no longer recognises the external id, and it
//! provisions a *new* account for the same person under a new UUID.
//!
//! Both scenarios live in one test on purpose. The SCIM token is a singleton
//! row, so two tests in this binary would race on it.
//!
//! Test code never lives in `src/` — see `.cursor/rules/test-directory.mdc`.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const DN: &str = "uid=alice,ou=people,dc=corp";

/// Issues `DELETE /scim/v2/Users/{id}` and returns the status and body.
async fn scim_delete(router: &axum::Router, token: &str, user: Uuid) -> (StatusCode, String) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/scim/v2/Users/{user}"))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .expect("build the request"),
        )
        .await
        .expect("the SCIM router must answer");
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("read the response body")
        .to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

async fn user_exists(pool: &PgPool, user: Uuid) -> bool {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE id = $1")
        .bind(user)
        .fetch_one(pool)
        .await
        .expect("count the user")
        > 0
}

/// The link is the thing that makes the loss of identity permanent: while it
/// exists, the next sync recognises the account instead of creating a new one.
async fn link_exists(pool: &PgPool, user: Uuid) -> bool {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM directory_entries WHERE user_id = $1")
        .bind(user)
        .fetch_one(pool)
        .await
        .expect("count the link")
        > 0
}

#[tokio::test]
async fn a_directory_managed_user_survives_a_scim_delete() {
    let Some(state) = common::state().await else {
        return;
    };

    let source = common::create_source(&state.pool).await;
    let managed = common::create_user(&state.pool, "").await;
    common::link_entry(&state.pool, source.id, "e-1", managed, Some(DN)).await;
    // A second, unmanaged user so the test also shows the guard is specific:
    // a delete that refuses *everything* would pass the first half alone.
    let plain = common::create_user(&state.pool, "").await;

    common::run_isolated(
        state,
        vec![source],
        vec![managed, plain],
        move |state| async move {
            common::with_scim_token(state, move |state, token| async move {
                let router = common::scim_router(&state);

                let (status, body) = scim_delete(&router, &token, managed).await;
                assert_eq!(
                    status,
                    StatusCode::FORBIDDEN,
                    "a managed account must be refused, got {status} with body: {body}"
                );
                assert!(
                    user_exists(&state.pool, managed).await,
                    "the refused delete must not have removed the account"
                );
                assert!(
                    link_exists(&state.pool, managed).await,
                    "the link must survive, or the next sync creates a new identity"
                );

                let (status, body) = scim_delete(&router, &token, plain).await;
                assert_eq!(
                    status,
                    StatusCode::NO_CONTENT,
                    "an unmanaged account must still be deletable, got {status} with body: {body}"
                );
                assert!(
                    !user_exists(&state.pool, plain).await,
                    "the unmanaged account should be gone"
                );
            })
            .await;
        },
    )
    .await;
}
