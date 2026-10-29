//! Refresh-token family revocation.
//!
//! A refresh token is single-use: rotation revokes it. So a *revoked* token
//! presented to the token endpoint is not an expired-credential nuisance, it is
//! evidence that either the client or a thief replayed an already-rotated
//! token — and the response is to revoke the whole family, so the newest
//! (thief-usable) token dies with the old one.
//!
//! These tests pin the family SQL: a chain shares one `family_id`, rotation
//! kills exactly one token, and family revocation spares unrelated grants.
//! Pre-family rows (NULL `family_id`) behave as families of one.

mod common;

use signet::crypto::util::{random_token, sha256_hex};
use signet::oidc::revoke_refresh_family;
use signet::state::AppState;
use uuid::Uuid;

/// Inserts a client row for the refresh-token FK and returns its client_id.
async fn create_client(state: &AppState) -> String {
    let client_id = format!("it-{}", Uuid::new_v4().simple());
    sqlx::query(
        r#"
        INSERT INTO client_apps (id, client_id, client_secret_hash, redirect_uris)
        VALUES ($1, $2, 'test', ARRAY['http://localhost/callback'])
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(&client_id)
    .execute(&state.pool)
    .await
    .expect("insert a test client");
    client_id
}

/// Inserts one refresh token row and returns its row id.
async fn insert_refresh_token(
    state: &AppState,
    client_id: &str,
    user_id: Uuid,
    family_id: Option<Uuid>,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO refresh_tokens (id, token_hash, client_id, user_id, scope, family_id, expires_at)
        VALUES ($1, $2, $3, $4, 'openid', $5, NOW() + INTERVAL '30 days')
        "#,
    )
    .bind(id)
    .bind(sha256_hex(&random_token(32)))
    .bind(client_id)
    .bind(user_id)
    .bind(family_id)
    .execute(&state.pool)
    .await
    .expect("insert a refresh token");
    id
}

async fn live_count(state: &AppState, ids: &[Uuid]) -> i64 {
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM refresh_tokens \
         WHERE id = ANY($1::uuid[]) AND revoked_at IS NULL",
    )
    .bind(ids)
    .fetch_one(&state.pool)
    .await
    .expect("count refresh tokens");
    n
}

/// Deletes the test client; its refresh tokens cascade with it, and the user
/// delete below takes the rest.
async fn delete_client(state: &AppState, client_id: &str) {
    sqlx::query("DELETE FROM client_apps WHERE client_id = $1")
        .bind(client_id)
        .execute(&state.pool)
        .await
        .expect("delete the test client");
}

#[tokio::test]
async fn family_revocation_kills_the_whole_chain_and_spares_neighbors() {
    let Some(state) = common::state().await else {
        return;
    };
    let user_id = common::create_user(&state.pool, "x").await;
    let client_id = create_client(&state).await;

    // One grant's chain: the original token and two rotations, all sharing a
    // family. A second grant for the same user and client stays independent.
    let family = Uuid::new_v4();
    let chain: Vec<Uuid> = [
        insert_refresh_token(&state, &client_id, user_id, Some(family)).await,
        insert_refresh_token(&state, &client_id, user_id, Some(family)).await,
        insert_refresh_token(&state, &client_id, user_id, Some(family)).await,
    ]
    .into();
    let other_family =
        insert_refresh_token(&state, &client_id, user_id, Some(Uuid::new_v4())).await;

    let killed = revoke_refresh_family(&state.pool, family)
        .await
        .expect("revoke the family");
    assert_eq!(killed, 3, "every live member of the family is revoked");

    assert_eq!(live_count(&state, &chain).await, 0);
    assert_eq!(live_count(&state, &[other_family]).await, 1);

    delete_client(&state, &client_id).await;
    common::delete_user(&state.pool, user_id).await;
}

/// A revoked member does not resurrect; revoking again is a no-op on it but
/// still catches later-live siblings (a thief re-arming the family is impossible,
/// but the call must stay idempotent).
#[tokio::test]
async fn family_revocation_is_idempotent() {
    let Some(state) = common::state().await else {
        return;
    };
    let user_id = common::create_user(&state.pool, "x").await;
    let client_id = create_client(&state).await;

    let family = Uuid::new_v4();
    let head = insert_refresh_token(&state, &client_id, user_id, Some(family)).await;
    let successor = insert_refresh_token(&state, &client_id, user_id, Some(family)).await;

    assert_eq!(revoke_refresh_family(&state.pool, family).await.unwrap(), 2);
    assert_eq!(revoke_refresh_family(&state.pool, family).await.unwrap(), 0);
    assert_eq!(live_count(&state, &[head, successor]).await, 0);

    delete_client(&state, &client_id).await;
    common::delete_user(&state.pool, user_id).await;
}

/// Rows from before the `family_id` column have NULL there; the reuse check
/// treats each as its own family so a legacy replay cannot take down tokens
/// from other grants.
#[tokio::test]
async fn a_null_family_row_is_a_family_of_one() {
    let Some(state) = common::state().await else {
        return;
    };
    let user_id = common::create_user(&state.pool, "x").await;
    let client_id = create_client(&state).await;

    let legacy = insert_refresh_token(&state, &client_id, user_id, None).await;
    let unrelated = insert_refresh_token(&state, &client_id, user_id, None).await;

    assert_eq!(revoke_refresh_family(&state.pool, legacy).await.unwrap(), 1);
    assert_eq!(live_count(&state, &[legacy]).await, 0);
    assert_eq!(live_count(&state, &[unrelated]).await, 1);

    delete_client(&state, &client_id).await;
    common::delete_user(&state.pool, user_id).await;
}
