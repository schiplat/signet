//! Contract tests for the generic HTTP JSON connector (§13).
//!
//! What is pinned down here is the mapping contract and the outbound policy.
//! The risky failures for this connector are not "the request failed" — that is
//! loud — but the quiet ones: a path that resolves to nothing looks exactly like
//! an empty directory, and an empty directory disables every user the source
//! manages (D3 turns deletions into disables, so a bad mapping is a mass
//! lockout). Each such case therefore has to be an error, and that is what these
//! tests assert.
//!
//! The fetch tests use a real HTTP server on loopback. That is only reachable
//! because the state is built with `outbound_allow_private = true`, which is
//! itself the property under test in the refusal case.
//!
//! Test code never lives in `src/` — see `.cursor/rules/test-directory.mdc`.

mod common;

use serde_json::json;
use signet::directory::http_json::lookup;
use signet::directory::source::{HttpJsonConfig, Pagination, SourceConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

// ─── Path resolution ──────────────────────────────────────────────────────

#[test]
fn dotted_paths_reach_nested_values() {
    let doc = json!({
        "data": { "users": [ { "id": 7, "profile": { "email": "a@b.c" } } ] }
    });
    assert_eq!(
        lookup(&doc, "data.users")
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        lookup(&doc, "data.users[0].profile.email").unwrap(),
        &json!("a@b.c")
    );
    // A JSONPath root marker is accepted so a config can be copied from a tool
    // that emits one; it means the same as omitting it.
    assert_eq!(
        lookup(&doc, "$.data.users").unwrap(),
        lookup(&doc, "data.users").unwrap()
    );
    // Bracket-key access, for a key that contains a dot.
    let dotted = json!({ "a.b": 1 });
    assert_eq!(lookup(&dotted, "[\"a.b\"]").unwrap(), &json!(1));
}

#[test]
fn malformed_paths_are_rejected_rather_than_ignored() {
    let doc = json!({ "a": { "b": 1 } });
    // An empty or doubled separator is a typo, not a request for "whatever is
    // there": treating it as "no value" is how a mapping silently goes empty.
    for path in ["", " ", "a..b", ".a", "a.", "$"] {
        assert!(
            lookup(&doc, path).is_none(),
            "path {path:?} must not resolve"
        );
    }
    // Well-formed but absent, and well-formed but of the wrong type.
    assert!(lookup(&doc, "a.c").is_none());
    assert!(lookup(&doc, "a[0]").is_none());
    assert!(lookup(&doc, "a[not a number or key").is_none());
}

/// The whole reason `users_path` is required and checked: resolving it to
/// something that is not an array must fail the run loudly.
#[test]
fn a_users_path_that_is_not_an_array_is_a_config_error() {
    let cfg = HttpJsonConfig::parse(&json!({
        "url": "https://directory.example.com/users",
        "users_path": "data.users",
        "external_id_path": "id",
        "email_path": "email",
    }))
    .expect("a minimal config must parse");

    // Object instead of array, and a missing path: both are upstream/mapping
    // errors, not "the directory is empty".
    let object = json!({ "data": { "users": { "id": "1" } } });
    assert!(lookup(&object, &cfg.users_path).is_some());
    assert!(
        lookup(&object, &cfg.users_path)
            .unwrap()
            .as_array()
            .is_none(),
        "the connector refuses this shape; see http_json::array_at"
    );
    assert!(lookup(&json!({ "data": {} }), &cfg.users_path).is_none());
}

// ─── Config validation ────────────────────────────────────────────────────

fn minimal_config() -> serde_json::Value {
    json!({
        "url": "https://directory.example.com/users",
        "users_path": "data.users",
        "external_id_path": "id",
        "email_path": "email",
    })
}

#[test]
fn a_minimal_config_parses_with_documented_defaults() {
    let cfg = HttpJsonConfig::parse(&minimal_config()).expect("minimal config");
    assert_eq!(cfg.method, "GET");
    assert!(!cfg.groups_configured());
    assert!(matches!(cfg.pagination, Pagination::None));
    assert!(!cfg.auth.requires_credential());
}

#[test]
fn an_unknown_config_key_is_refused() {
    // `deny_unknown_fields`: a misspelled mapping key would otherwise be dropped
    // and the sync would run with a default that nobody chose.
    let mut raw = minimal_config();
    raw["externalIdPath"] = json!("id");
    let err = HttpJsonConfig::parse(&raw).unwrap_err().to_string();
    assert!(err.contains("invalid http_json source config"), "{err}");
}

#[test]
fn the_required_paths_must_be_present() {
    for missing in ["users_path", "external_id_path", "email_path"] {
        let mut raw = minimal_config();
        raw[missing] = json!("");
        let err = HttpJsonConfig::parse(&raw).unwrap_err().to_string();
        assert!(
            err.contains(missing),
            "expected the error to name {missing}: {err}"
        );
    }
}

#[test]
fn a_config_that_is_not_a_plain_https_endpoint_is_refused() {
    for url in [
        "ftp://directory.example.com/users",
        "not a url",
        // Embedded credentials would be overwritten by the Authorization header
        // and would leak a secret into the stored, log-safe `config`.
        "https://user:pass@directory.example.com/users",
    ] {
        let mut raw = minimal_config();
        raw["url"] = json!(url);
        assert!(
            HttpJsonConfig::parse(&raw).is_err(),
            "{url} must not be accepted"
        );
    }
}

/// Routability is deliberately *not* part of config validation: whether an
/// internal address is a mistake or the point depends on
/// `SIGNET_OUTBOUND_ALLOW_PRIVATE`, which the parser cannot see. The strict
/// default is enforced at save time (`source::ensure_destination_allowed`) and
/// again on every request, which is what
/// `the_strict_policy_refuses_an_internal_address_at_fetch_time` covers.
#[test]
fn a_literal_internal_address_is_accepted_by_shape_validation_alone() {
    for url in [
        "http://127.0.0.1:8080/users",
        "http://10.1.2.3/users",
        "http://[::1]/users",
    ] {
        let mut raw = minimal_config();
        raw["url"] = json!(url);
        assert!(
            HttpJsonConfig::parse(&raw).is_ok(),
            "{url} must parse; the outbound guard rejects it later"
        );
    }
}

#[test]
fn a_post_method_is_refused_with_a_reason() {
    let mut raw = minimal_config();
    raw["method"] = json!("POST");
    let err = HttpJsonConfig::parse(&raw).unwrap_err().to_string();
    // The message has to say *why*, otherwise the operator retries with a
    // different spelling instead of learning that bodies are unsupported.
    assert!(err.contains("POST bodies are not supported"), "{err}");
}

#[test]
fn pagination_bounds_are_enforced() {
    for bad in [
        json!({"mode": "page", "param": "p", "max_pages": 0}),
        json!({"mode": "page", "param": "p", "max_pages": 100_000}),
        json!({"mode": "page", "param": "p", "max_pages": 2, "size": 0}),
        json!({"mode": "page", "param": "", "max_pages": 2}),
        json!({"mode": "cursor", "param": "c", "next_path": "", "max_pages": 2}),
        json!({"mode": "cursor", "param": "", "next_path": "next", "max_pages": 2}),
        // An unknown mode cannot be silently ignored: there is no default walk
        // that would be safe to assume.
        json!({"mode": "offset", "param": "p", "max_pages": 2}),
    ] {
        let mut raw = minimal_config();
        raw["pagination"] = bad.clone();
        assert!(
            HttpJsonConfig::parse(&raw).is_err(),
            "pagination {bad} must not be accepted"
        );
    }
}

#[test]
fn basic_auth_needs_a_username_and_bearer_needs_a_credential() {
    let mut raw = minimal_config();
    raw["auth"] = json!({"basic": {"username": " "}});
    assert!(HttpJsonConfig::parse(&raw).is_err());

    raw["auth"] = json!("bearer");
    let cfg = HttpJsonConfig::parse(&raw).expect("a bearer config is valid on its own");
    assert!(cfg.auth.requires_credential());
}

#[test]
fn the_source_config_dispatch_refuses_kinds_without_a_connector() {
    // `scim` is accepted by the table's CHECK but has no pull connector yet, so
    // storing one must fail at save time rather than at the next sync.
    let err = SourceConfig::parse("scim", &minimal_config())
        .unwrap_err()
        .to_string();
    assert!(err.contains("no connector yet"), "{err}");

    assert!(SourceConfig::parse("ldap", &minimal_config()).is_err());
    assert!(SourceConfig::parse("http_json", &minimal_config()).is_ok());
}

#[test]
fn group_ownership_follows_the_configured_path_not_the_toggle_alone() {
    let plain = SourceConfig::parse("http_json", &minimal_config()).unwrap();
    // Toggle on but nowhere to read groups from: the run must not claim
    // ownership, or it would wipe memberships it never fetched.
    assert!(!plain.groups_configured(true));
    assert!(!plain.groups_configured(false));

    let mut raw = minimal_config();
    raw["groups_path"] = json!("groups");
    let with_groups = SourceConfig::parse("http_json", &raw).unwrap();
    assert!(with_groups.groups_configured(true));
    assert!(!with_groups.groups_configured(false));
}

// ─── Fetching, against a real endpoint ────────────────────────────────────

#[tokio::test]
async fn a_single_page_listing_is_mapped_into_upstream_users() {
    let Some(state) = common::state_with(|cfg| cfg.outbound_allow_private = true).await else {
        return;
    };
    let server = TestServer::start(vec![json!({
        "data": { "users": [
            {"id": 1, "email": "Ada@Example.com", "login": "ada", "name": "Ada Lovelace",
             "groups": ["eng", "ops"]},
            // A number id, to pin the coercion: many APIs use numeric ids and
            // stringifying them here is what keeps the link stable.
            {"id": 2, "email": "bob@example.com"},
            // No email: mapped, and left for the planner to report as `skip`.
            {"id": 3},
        ]}
    })])
    .await;

    let cfg = HttpJsonConfig::parse(&json!({
        "url": server.url(),
        "users_path": "data.users",
        "external_id_path": "id",
        "email_path": "email",
        "username_path": "login",
        "display_name_path": "name",
        "groups_path": "groups",
    }))
    .unwrap();

    let users = signet::directory::http_json::fetch_users(
        &cfg,
        None,
        state.config.outbound_allow_private,
        None,
    )
    .await
    .expect("the listing must be read");

    // The connector does not normalize (that is the planner's job), so the
    // email is passed through as-is here.
    assert_eq!(users.len(), 3);
    assert_eq!(users[0].external_id, "1");
    assert_eq!(users[0].email, "Ada@Example.com");
    assert_eq!(users[0].username.as_deref(), Some("ada"));
    assert_eq!(users[0].display_name.as_deref(), Some("Ada Lovelace"));
    assert_eq!(users[0].groups, vec!["eng".to_string(), "ops".to_string()]);
    assert_eq!(users[1].external_id, "2");
    assert_eq!(users[1].username, None);
    assert!(users[1].groups.is_empty());
    assert_eq!(users[2].email, "");
    // An HTTP source has no DN, so bind-through must never be attempted for it.
    assert!(users.iter().all(|u| u.external_dn.is_none()));
}

#[tokio::test]
async fn cursor_pagination_follows_the_next_link_and_stops_at_the_end() {
    let Some(state) = common::state_with(|cfg| cfg.outbound_allow_private = true).await else {
        return;
    };
    // Page 2 has no `next`, which is what ends the walk: the connector must not
    // depend on a page being short, since a full last page is indistinguishable.
    let server = TestServer::start(vec![
        json!({
            "users": [{"id": "a", "email": "a@example.com"}],
            "paging": {"next": "c2"}
        }),
        json!({
            "users": [{"id": "b", "email": "b@example.com"}],
            "paging": {"next": null}
        }),
    ])
    .await;

    let cfg = HttpJsonConfig::parse(&json!({
        "url": server.url(),
        "users_path": "users",
        "external_id_path": "id",
        "email_path": "email",
        "pagination": {"mode": "cursor", "param": "cursor", "next_path": "paging.next",
                       "max_pages": 5},
    }))
    .unwrap();

    let users = signet::directory::http_json::fetch_users(
        &cfg,
        None,
        state.config.outbound_allow_private,
        None,
    )
    .await
    .expect("both pages must be read");

    assert_eq!(
        users
            .iter()
            .map(|u| u.external_id.as_str())
            .collect::<Vec<_>>(),
        vec!["a", "b"]
    );
    let requested = server.requested_paths().await;
    assert_eq!(
        requested.len(),
        2,
        "exactly one request per page: {requested:?}"
    );
    assert_eq!(requested[0], "/");
    // The cursor is threaded back as the configured parameter name.
    assert!(requested[1].contains("cursor=c2"), "{:?}", requested[1]);
}

#[tokio::test]
async fn page_pagination_stops_at_max_pages_instead_of_looping() {
    let Some(state) = common::state_with(|cfg| cfg.outbound_allow_private = true).await else {
        return;
    };
    // Every response says "there is more" (no cursor, so Page mode never sees an
    // end signal). The bound is the only thing that stops the walk, and without
    // it this test would hang rather than fail.
    let server = TestServer::start(vec![
        json!({"users": [{"id": "x", "email": "x@example.com"}]});
        3
    ])
    .await;

    let cfg = HttpJsonConfig::parse(&json!({
        "url": server.url(),
        "users_path": "users",
        "external_id_path": "id",
        "email_path": "email",
        "username_path": "login",
        "pagination": {"mode": "page", "param": "page", "size": 1, "max_pages": 3},
    }))
    .unwrap();

    let users = signet::directory::http_json::fetch_users(
        &cfg,
        None,
        state.config.outbound_allow_private,
        None,
    )
    .await
    .unwrap();

    assert_eq!(users.len(), 3, "one entry per page, three pages");
    let requested = server.requested_paths().await;
    assert_eq!(
        requested.len(),
        3,
        "max_pages must stop the walk: {requested:?}"
    );
    assert!(requested[2].contains("page=3"), "{:?}", requested[2]);
    assert!(requested[2].contains("page_size=1"), "{:?}", requested[2]);
}

#[tokio::test]
async fn the_limit_caps_the_entries_and_the_requests() {
    let Some(state) = common::state_with(|cfg| cfg.outbound_allow_private = true).await else {
        return;
    };
    let server = TestServer::start(vec![json!({
        "users": [
            {"id": "1", "email": "one@example.com"},
            {"id": "2", "email": "two@example.com"},
            {"id": "3", "email": "three@example.com"},
        ]
    })])
    .await;

    let cfg = HttpJsonConfig::parse(&json!({
        "url": server.url(),
        "users_path": "users",
        "external_id_path": "id",
        "email_path": "email",
    }))
    .unwrap();

    let users = signet::directory::http_json::fetch_users(
        &cfg,
        None,
        state.config.outbound_allow_private,
        Some(2),
    )
    .await
    .unwrap();
    assert_eq!(users.len(), 2);
}

#[tokio::test]
async fn a_bearer_credential_is_sent_and_never_when_unset() {
    let Some(state) = common::state_with(|cfg| cfg.outbound_allow_private = true).await else {
        return;
    };
    let server = TestServer::start(vec![json!({ "users": [] }); 1]).await;
    let cfg = HttpJsonConfig::parse(&json!({
        "url": server.url(),
        "users_path": "users",
        "external_id_path": "id",
        "email_path": "email",
        "auth": "bearer",
    }))
    .unwrap();

    signet::directory::http_json::fetch_users(
        &cfg,
        Some("s3cret"),
        state.config.outbound_allow_private,
        None,
    )
    .await
    .unwrap();
    let headers = server.requested_headers().await;
    assert_eq!(
        headers.first().and_then(|h| h.authorization.clone()),
        Some("Bearer s3cret".to_string())
    );

    let server = TestServer::start(vec![json!({ "users": [] }); 1]).await;
    let mut raw = json!({
        "url": server.url(),
        "users_path": "users",
        "external_id_path": "id",
        "email_path": "email",
        "auth": "bearer",
    });
    raw["auth"] = json!("bearer");
    let cfg = HttpJsonConfig::parse(&raw).unwrap();
    signet::directory::http_json::fetch_users(
        &cfg,
        None,
        state.config.outbound_allow_private,
        None,
    )
    .await
    .unwrap();
    // No credential means no header at all, rather than an empty one that an
    // upstream would read as a malformed token.
    assert_eq!(server.requested_headers().await[0].authorization, None);
}

#[tokio::test]
async fn an_error_status_is_reported_without_echoing_the_body() {
    let Some(state) = common::state_with(|cfg| cfg.outbound_allow_private = true).await else {
        return;
    };
    let server = TestServer::start_error(500, "<html>internal error, no secrets here</html>").await;
    let cfg = HttpJsonConfig::parse(&json!({
        "url": server.url(),
        "users_path": "users",
        "external_id_path": "id",
        "email_path": "email",
    }))
    .unwrap();

    let err = signet::directory::http_json::fetch_users(
        &cfg,
        None,
        state.config.outbound_allow_private,
        None,
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(err.contains("500"), "{err}");
    assert!(
        !err.contains("no secrets here"),
        "the upstream body must not be echoed into the error: {err}"
    );
}

/// The P4 acceptance criterion from §16: the strict policy refuses an internal
/// address even when a source is already configured to point at one — a stored
/// URL is not evidence that it is safe to call today.
#[tokio::test]
async fn the_strict_policy_refuses_an_internal_address_at_fetch_time() {
    let Some(state) = common::state_with(|cfg| cfg.outbound_allow_private = false).await else {
        return;
    };
    let server = TestServer::start(vec![json!({ "users": [] }); 1]).await;

    // The config is accepted (shape-only validation cannot resolve DNS), but the
    // fetch is not: this is the layering §12 describes.
    let cfg = HttpJsonConfig::parse(&json!({
        "url": server.url(),
        "users_path": "users",
        "external_id_path": "id",
        "email_path": "email",
    }))
    .unwrap();

    let err = signet::directory::http_json::fetch_users(&cfg, None, false, None)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("not publicly routable"), "{err}");
    assert!(
        server.requested_paths().await.is_empty(),
        "the request must not have left the process"
    );
    drop(state);
}

// ─── End-to-end through the engine ────────────────────────────────────────

/// The §16 acceptance criterion for P4: one full sync writes the users through
/// the shared planner and apply path, and a second run is a no-op.
///
/// This is the test that would catch the connector feeding the engine something
/// the planner cannot use — an id that is not stable across runs, or a group
/// list that changes order every fetch and therefore rewrites every user.
#[tokio::test]
async fn a_full_sync_creates_the_users_and_a_rerun_changes_nothing() {
    use signet::directory::engine::{self, SyncOptions, Trigger};

    let Some(state) = common::state_with(|cfg| cfg.outbound_allow_private = true).await else {
        return;
    };
    let page = json!({
        "data": { "users": [
            // Mixed case, to pin that the planner's normalization is what lands
            // in the database rather than the raw upstream string.
            {"id": "u1", "email": "Ada@Example.com", "login": "Ada", "name": "Ada Lovelace",
             "groups": ["eng", "ops", "eng"]},
            {"id": "u2", "email": "bob@example.com", "login": "bob", "name": "Bob",
             "groups": []},
        ]}
    });
    // One response per run; a third request would get a 404, which fails the run
    // loudly rather than silently reusing a page.
    let server = TestServer::start(vec![page.clone(), page]).await;
    let source = common::create_http_json_source(&state.pool, &server.url()).await;

    common::scoped(state, source, |state, source| async move {
        let first = engine::run_source(
            &state,
            &source.code,
            Trigger::Manual,
            None,
            &SyncOptions::default(),
        )
        .await
        .expect("the first sync must succeed");

        assert_eq!(
            (
                first.counts.created,
                first.counts.errors,
                first.counts.conflicts
            ),
            (2, 0, 0),
            "changes: {:#?}",
            first.changes
        );
        assert!(first.reconciled, "a full run must reconcile");

        let ada = common::email_for_link(&state.pool, source.id, "u1")
            .await
            .expect("u1 must be linked to a local user");
        assert_eq!(ada, "ada@example.com", "the planner lowercases the email");
        let (username, display_name, groups): (Option<String>, String, Vec<String>) =
            sqlx::query_as(
                "SELECT username, display_name, directory_groups FROM users WHERE email = $1",
            )
            .bind(&ada)
            .fetch_one(&state.pool)
            .await
            .expect("read the provisioned user");
        assert_eq!(username.as_deref(), Some("ada"));
        assert_eq!(display_name, "Ada Lovelace");
        // Normalized: trimmed, deduplicated and sorted, which is what makes the
        // fingerprint — and therefore "nothing changed" — stable.
        assert_eq!(groups, vec!["eng".to_string(), "ops".to_string()]);

        // ── Second run ───────────────────────────────────────────────────
        let second = engine::run_source(
            &state,
            &source.code,
            Trigger::Manual,
            None,
            &SyncOptions::default(),
        )
        .await
        .expect("the second sync must succeed");
        assert_eq!(
            (
                second.counts.created,
                second.counts.updated,
                second.counts.disabled,
                second.counts.conflicts
            ),
            (0, 0, 0, 0),
            "a rerun must be a no-op; changes: {:#?}",
            second.changes
        );
        assert_eq!(second.counts.skipped, 2, "both entries are unchanged");
        assert_eq!(second.scanned, 2);
    })
    .await;
}

// ─── Test server ──────────────────────────────────────────────────────────

/// A minimal single-purpose HTTP/1.1 responder.
///
/// Hand-rolled rather than pulled in as a dependency: what the connector needs
/// from a server is a body, a status and the request line, and a dev-dependency
/// that large would be all cost. Each response is served once, then the socket
/// is closed, which also keeps "how many requests were made" observable.
struct TestServer {
    addr: SocketAddr,
    requests: Arc<tokio::sync::Mutex<Vec<Request>>>,
}

#[derive(Clone, Debug, Default)]
struct Request {
    path: String,
    authorization: Option<String>,
}

impl TestServer {
    /// Serves `bodies` in order, one request each; extra requests get a 404.
    async fn start(bodies: Vec<serde_json::Value>) -> Self {
        let requests = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let seen = requests.clone();
        tokio::spawn(async move {
            for body in bodies {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let Ok(request) = read_request(&mut socket).await else {
                    return;
                };
                seen.lock().await.push(request);
                let payload = body.to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    payload.len(),
                    payload
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            }
        });
        Self { addr, requests }
    }

    /// Serves one error response with a non-JSON body.
    async fn start_error(status: u16, body: &'static str) -> Self {
        let requests = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let seen = requests.clone();
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                if let Ok(request) = read_request(&mut socket).await {
                    seen.lock().await.push(request);
                    let response = format!(
                        "HTTP/1.1 {status} Internal Server Error\r\ncontent-type: text/html\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                }
            }
        });
        Self { addr, requests }
    }

    fn url(&self) -> String {
        format!("http://{}/", self.addr)
    }

    async fn requested_paths(&self) -> Vec<String> {
        self.requests
            .lock()
            .await
            .iter()
            .map(|r| r.path.clone())
            .collect()
    }

    async fn requested_headers(&self) -> Vec<Request> {
        self.requests.lock().await.clone()
    }
}

/// Reads one request head, ignoring the body (these are GETs).
async fn read_request(socket: &mut tokio::net::TcpStream) -> std::io::Result<Request> {
    let mut buf = vec![0u8; 4096];
    let mut read = 0usize;
    let mut head_end = None;
    while head_end.is_none() {
        let n = socket.read(&mut buf[read..]).await?;
        if n == 0 {
            break;
        }
        read += n;
        head_end = buf[..read]
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|p| p + 4);
        if read == buf.len() {
            break;
        }
    }
    let head = String::from_utf8_lossy(&buf[..head_end.unwrap_or(read)]).to_string();
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or_default().to_string();
    let path = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .to_string();
    let authorization = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        .map(|(_, value)| value.trim().to_string());
    Ok(Request {
        path,
        authorization,
    })
}
