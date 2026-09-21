//! Shared harness for the DB-backed integration tests.
//!
//! These tests talk to a real PostgreSQL server on purpose: what they pin down
//! is SQL — constraint names, `ON DELETE CASCADE` behaviour, `CHECK` values and
//! the exact columns the sync writes. A mock would assert that the code calls
//! the mock, which is the one thing that cannot break.
//!
//! Cleanup is opt-in and must be panic-safe. A failed test that leaks rows is
//! worse than one that fails loudly: users carry unique emails, usernames and
//! phones, so a row left behind can fail a later run in a way that points at the
//! wrong test. Write the body inside [`scoped`] / [`run_scoped`] when the rows
//! hang off a directory source, or [`with_user`] / [`with_users`] when the test
//! creates them directly. Both run the body in a spawned task and clean up
//! after it settles, so an assertion failure still cleans up; a bare
//! [`delete_user`] at the end of a test body does not.
//!
//! Test code never lives in `src/` — see `.cursor/rules/test-directory.mdc`.

#![allow(dead_code)] // Each test binary uses a different subset of these helpers.

use signet::config::Config;
use signet::directory::source::SourceRow;
use signet::state::AppState;
use sqlx::PgPool;
use uuid::Uuid;

/// Builds an `AppState` against the configured database, running migrations.
///
/// Returns `None` when the database is unreachable so the suite skips instead of
/// failing on a machine that has no PostgreSQL. The skip is loud: a silently
/// skipped integration test is worse than a failing one.
pub async fn state() -> Option<AppState> {
    state_with(|_| {}).await
}

/// [`state`] with a chance to adjust the configuration first.
///
/// Exists for the tests that need a non-default deployment flag — notably
/// `outbound_allow_private`, which is what makes a loopback test server
/// reachable at all. Passing a modifier rather than mutating a shared state
/// keeps each test's policy its own.
pub async fn state_with(adjust: impl FnOnce(&mut Config)) -> Option<AppState> {
    let mut cfg = match Config::from_env() {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("skipping DB-backed tests: invalid configuration: {e}");
            return None;
        }
    };
    adjust(&mut cfg);
    match signet::build_state(cfg).await {
        Ok(state) => Some(state),
        Err(e) => {
            eprintln!("skipping DB-backed tests: cannot reach the database: {e}");
            None
        }
    }
}

/// Creates an enabled `ldap` source with a random suffix and returns its row.
pub async fn create_source(pool: &PgPool) -> SourceRow {
    create_source_with(pool, "ldap", true, 100).await
}

/// Creates a source with the given kind, enabled flag and precedence.
///
/// The row is inserted directly rather than through the admin API: these tests
/// are about the engine and the login path, and the API's validation is covered
/// elsewhere. The `config` is still shaped like a valid `LdapConfig` so
/// `kind`/`config` stay consistent for the kinds that read it.
pub async fn create_source_with(
    pool: &PgPool,
    kind: &str,
    enabled: bool,
    priority: i32,
) -> SourceRow {
    let code = format!("it-{}", Uuid::new_v4().simple());
    let config = serde_json::json!({
        "url": "ldaps://ldap.invalid:636",
        "bind_dn": "cn=svc,dc=corp",
        "base_dn": "ou=people,dc=corp",
        "username_attribute": "uid",
        "external_id_attribute": "entryUUID",
        "group_base_dn": "ou=groups,dc=corp"
    });
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO directory_sources
            (id, code, name, kind, enabled, priority, config, sync_groups)
        VALUES ($1, $2, $2, $3, $4, $5, $6, TRUE)
        "#,
    )
    .bind(id)
    .bind(&code)
    .bind(kind)
    .bind(enabled)
    .bind(priority)
    .bind(&config)
    .execute(pool)
    .await
    .expect("insert directory source");

    signet::directory::source::get_by_code(pool, &code)
        .await
        .expect("load the source that was just inserted")
}

/// Creates an enabled `http_json` source pointing at `url`, with group sync on
/// and a valid mapping against this module's test documents (`data.users`).
pub async fn create_http_json_source(pool: &PgPool, url: &str) -> SourceRow {
    let code = format!("it-{}", Uuid::new_v4().simple());
    let config = serde_json::json!({
        "url": url,
        "users_path": "data.users",
        "external_id_path": "id",
        "email_path": "email",
        "username_path": "login",
        "display_name_path": "name",
        "groups_path": "groups"
    });
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO directory_sources
            (id, code, name, kind, enabled, priority, config, sync_groups)
        VALUES ($1, $2, $2, 'http_json', TRUE, 100, $3, TRUE)
        "#,
    )
    .bind(id)
    .bind(&code)
    .bind(&config)
    .execute(pool)
    .await
    .expect("insert http_json source");

    signet::directory::source::get_by_code(pool, &code)
        .await
        .expect("load the source that was just inserted")
}

/// Inserts a local user with a unique email, so tests never collide in a shared
/// database. Returns its id.
pub async fn create_user(pool: &PgPool, password_hash: &str) -> Uuid {
    let id = Uuid::new_v4();
    let tag = Uuid::new_v4().simple().to_string();
    sqlx::query(
        r#"
        INSERT INTO users (id, sub, email, username, display_name, password_hash, status, role)
        VALUES ($1, $2, $3, $4, 'Test User', $5, 'active', 'member')
        "#,
    )
    .bind(id)
    .bind(Uuid::new_v4().to_string())
    .bind(format!("{tag}@login.test"))
    .bind(format!("login/{tag}"))
    .bind(password_hash)
    .execute(pool)
    .await
    .expect("insert a local user");
    id
}

/// Links `external_id` in `source_id` to `user_id`, with an optional stored DN.
pub async fn link_entry(
    pool: &PgPool,
    source_id: Uuid,
    external_id: &str,
    user_id: Uuid,
    external_dn: Option<&str>,
) {
    sqlx::query(
        r#"
        INSERT INTO directory_entries (id, source_id, external_id, external_dn, user_id)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(source_id)
    .bind(external_id)
    .bind(external_dn)
    .bind(user_id)
    .execute(pool)
    .await
    .expect("insert a directory link");
}

/// Deletes a user created by [`create_user`], which has no directory link to
/// cascade through.
pub async fn delete_user(pool: &PgPool, user_id: Uuid) {
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await
        .expect("delete the test user");
}

/// Opens a run row, so `apply_plan` has an id to attach audit events to.
pub async fn begin_run(pool: &PgPool, source_id: Uuid) -> Uuid {
    signet::directory::model::begin_run(pool, source_id, "cli", None)
        .await
        .expect("open a sync run")
}

/// Runs `body` against a fresh source and removes everything it created, even
/// when an assertion fails.
///
/// Without this, the first failing assertion leaves a provisioned user and a
/// source row behind; the next run then sees a directory whose people already
/// exist locally and reports conflicts where the test expects creates. The body
/// runs in its own task so a panic is caught instead of unwinding past the
/// cleanup, and is re-raised afterwards so the test still fails loudly.
pub async fn scoped<F, Fut>(state: AppState, source: SourceRow, body: F)
where
    F: FnOnce(AppState, SourceRow) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    run_scoped(state, vec![source], move |state, mut sources| async move {
        body(state, sources.remove(0)).await
    })
    .await;
}

/// [`scoped`] for the multi-source tests, which need both sources cleaned up.
pub async fn run_scoped<F, Fut>(state: AppState, sources: Vec<SourceRow>, body: F)
where
    F: FnOnce(AppState, Vec<SourceRow>) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let outcome = tokio::spawn(body(state.clone(), sources.clone())).await;
    for source in &sources {
        cleanup(&state.pool, source).await;
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic.into_panic());
    }
}

/// [`run_scoped`] for users a test creates directly rather than through a
/// source, so nothing cascades them away.
///
/// The body runs in a spawned task and the deletes happen after it settles, so
/// an assertion failure still cleans up. Cleanup written at the end of a test
/// body is skipped when the body panics — and users carry unique emails,
/// usernames and phones, so a row leaked by one run can fail a later one.
/// That is not hypothetical: it happened twice while the user write path was
/// being converged, once through a fixed phone number left behind.
///
/// Prefer [`scoped`] when the users hang off a source; it deletes them through
/// the link and needs no ids passed in.
pub async fn with_users<F, Fut>(state: AppState, users: Vec<Uuid>, body: F)
where
    F: FnOnce(AppState, Vec<Uuid>) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let outcome = tokio::spawn(body(state.clone(), users.clone())).await;
    for user in &users {
        delete_user(&state.pool, *user).await;
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic.into_panic());
    }
}

/// [`with_users`] for the single-user case.
pub async fn with_user<F, Fut>(state: AppState, user: Uuid, body: F)
where
    F: FnOnce(AppState, Uuid) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    with_users(state, vec![user], move |state, mut users| async move {
        body(state, users.remove(0)).await
    })
    .await;
}

/// Runs `body` against the SCIM router with a bearer token the test knows.
///
/// The configured token is stored only as a hash and is seeded from the
/// environment on first boot, so its plaintext cannot be recovered. The test
/// installs its own hash for the duration and puts the previous value back
/// afterwards.
///
/// Restoring matters for the same reason `with_users` does: `scim_config` is a
/// singleton, so a test that clobbered it and then panicked would silently break
/// the SCIM token a real IdP is configured with. The body runs in a spawned task
/// and the restore happens after it settles, so an assertion failure still puts
/// the original back.
pub async fn with_scim_token<F, Fut>(state: AppState, body: F)
where
    F: FnOnce(AppState, String) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    // The column is nullable, so the scalar type is `Option<String>` and
    // `fetch_optional` nests: `None` means no row at all.
    let previous: Option<Option<String>> =
        sqlx::query_scalar("SELECT token_hash FROM scim_config WHERE id = TRUE")
            .fetch_optional(&state.pool)
            .await
            .expect("read the configured SCIM token");

    let token = format!("test-scim-{}", Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO scim_config (id, token_hash) VALUES (TRUE, $1) \
         ON CONFLICT (id) DO UPDATE SET token_hash = $1",
    )
    .bind(signet::crypto::util::sha256_hex(&token))
    .execute(&state.pool)
    .await
    .expect("install a test SCIM token");

    let outcome = tokio::spawn(body(state.clone(), token)).await;

    match previous {
        Some(hash) => {
            sqlx::query("UPDATE scim_config SET token_hash = $1 WHERE id = TRUE")
                .bind(hash)
                .execute(&state.pool)
                .await
                .expect("restore the configured SCIM token");
        }
        // There was no row: remove the one this helper created rather than
        // leaving SCIM configured with a token nobody holds.
        None => {
            sqlx::query("DELETE FROM scim_config WHERE id = TRUE")
                .execute(&state.pool)
                .await
                .expect("remove the test SCIM token");
        }
    }

    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic.into_panic());
    }
}

/// The SCIM API router, ready to drive with [`tower::ServiceExt::oneshot`].
pub fn scim_router(state: &AppState) -> axum::Router {
    signet::scim::router().with_state(state.clone())
}

/// Runs `body`, then removes the `sources` and the `users`, even if the body
/// panics.
///
/// For tests that need a source *and* a user the source does not own, or that
/// change the links themselves part-way through. Those are the cases
/// [`scoped`] cannot cover: it deletes the users it finds hanging off the
/// source's links, so a body that removes a link — or deletes the source — has
/// already hidden the user from it by the time cleanup runs.
///
/// Pass the source clones to be cleaned up as `sources`; the body receives only
/// the state, and captures whatever handles it needs.
pub async fn run_isolated<F, Fut>(
    state: AppState,
    sources: Vec<SourceRow>,
    users: Vec<Uuid>,
    body: F,
) where
    F: FnOnce(AppState) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let outcome = tokio::spawn(body(state.clone())).await;
    // Users first: `cleanup` resolves them through the links, which the body may
    // already have changed, so deleting by id is the reliable half.
    for user in &users {
        delete_user(&state.pool, *user).await;
    }
    for source in &sources {
        cleanup(&state.pool, source).await;
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic.into_panic());
    }
}

/// Removes the source and everything the test created through it.
///
/// Order matters: the users are deleted through the links (deleting the source
/// first would cascade the links away and orphan them), then audit rows are
/// dropped so a long-lived dev database does not slowly fill with test events.
pub async fn cleanup(pool: &PgPool, source: &SourceRow) {
    let user_ids: Vec<Uuid> =
        sqlx::query_scalar("SELECT user_id FROM directory_entries WHERE source_id = $1")
            .bind(source.id)
            .fetch_all(pool)
            .await
            .unwrap_or_default();

    if !user_ids.is_empty() {
        sqlx::query("DELETE FROM users WHERE id = ANY($1)")
            .bind(&user_ids)
            .execute(pool)
            .await
            .expect("delete users created by the test");
    }
    // `directory_entries` and `directory_sync_runs` cascade from the source.
    sqlx::query("DELETE FROM directory_sources WHERE id = $1")
        .bind(source.id)
        .execute(pool)
        .await
        .expect("delete the test source");

    sqlx::query("DELETE FROM audit_logs WHERE detail ->> 'source' = $1")
        .bind(&source.code)
        .execute(pool)
        .await
        .expect("delete the test audit rows");
}

/// Email of a user provisioned by the sync, looked up through its link.
pub async fn email_for_link(pool: &PgPool, source_id: Uuid, external_id: &str) -> Option<String> {
    sqlx::query_scalar(
        r#"
        SELECT u.email
        FROM directory_entries e JOIN users u ON u.id = e.user_id
        WHERE e.source_id = $1 AND e.external_id = $2
        "#,
    )
    .bind(source_id)
    .bind(external_id)
    .fetch_optional(pool)
    .await
    .expect("look up the linked user")
}
