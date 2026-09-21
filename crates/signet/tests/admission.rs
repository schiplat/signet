//! The sign-in and provisioning allowlist, and the one domain comparison
//! underneath it.
//!
//! `tests/directory_scope.rs` covers the *scope* reading of a domain list, where
//! a user who leaves is disabled. This file covers the *admission* reading,
//! where nobody is ever disabled — so the same `corp.example` must admit
//! `mail.corp.example` and refuse `evilcorp.example` in both, and the two must
//! not drift apart. The pure half runs everywhere; the DB half walks the
//! `app_settings` row and its fallback.
//!
//! Test code never lives in `src/` — see `.cursor/rules/test-directory.mdc`.

mod common;

use signet::admission::{
    allowed_domains, allows, domain_matches, domain_of, origin, set_allowed_domains,
    validate_domains, Origin, AUDIT_SETTING_UPDATE, SETTING_KEY,
};

fn list(entries: &[&str]) -> Vec<String> {
    entries.iter().map(|s| s.to_string()).collect()
}

// ─── The comparison every caller shares ───────────────────────────────────

#[test]
fn a_domain_is_admitted_by_itself_and_by_a_real_subdomain() {
    assert!(domain_matches("corp.example", "corp.example"));
    assert!(domain_matches("mail.corp.example", "corp.example"));
    assert!(domain_matches("a.b.corp.example", "corp.example"));
}

#[test]
fn a_domain_that_merely_ends_with_the_same_letters_is_not_admitted() {
    // The whole reason this is not a suffix test: `evilcorp.example` ends with
    // `corp.example` as a string and is a different company.
    assert!(!domain_matches("evilcorp.example", "corp.example"));
    assert!(!domain_matches("notcorp.example", "corp.example"));
    // And the boundary has to be the dot, not just the letters.
    assert!(!domain_matches("xcorp.example", "corp.example"));
}

#[test]
fn the_configured_side_is_normalized_but_the_entry_is_matched_as_a_domain() {
    assert!(domain_matches("corp.example", "  CORP.example "));
    assert!(domain_matches("corp.example", ".corp.example"));
    assert!(!domain_matches("corp.example", ""));
}

#[test]
fn the_last_at_sign_decides_the_domain() {
    // An `@` in the local part is legal, and splitting on the first one would
    // read `name@corp.example` as the domain.
    assert_eq!(
        domain_of("weird@name@corp.example").as_deref(),
        Some("corp.example")
    );
    assert_eq!(
        domain_of(" Someone@Corp.Example ").as_deref(),
        Some("corp.example")
    );
}

#[test]
fn an_address_with_no_domain_has_none_to_read() {
    assert_eq!(domain_of("nodomain"), None);
    assert_eq!(domain_of("@corp.example"), None);
    assert_eq!(domain_of("user@"), None);
    assert_eq!(domain_of(""), None);
}

#[test]
fn an_empty_list_restricts_nothing() {
    // What keeps every deployment that never configures this, and the whole test
    // suite, behaving exactly as before.
    assert!(allows(&[], "anyone@anywhere.example"));
    assert!(allows(&[], "not-even-an-address"));
}

#[test]
fn an_address_with_no_readable_domain_is_refused_when_a_list_is_configured() {
    // "Cannot be shown to belong" is not "unknown": admitting it would let in
    // exactly what the administrator meant to keep out.
    let domains = list(&["corp.example"]);
    assert!(!allows(&domains, "nodomain"));
    assert!(!allows(&domains, "user@"));
}

#[test]
fn any_one_of_the_listed_domains_admits_an_address() {
    let domains = list(&["corp.example", "partner.example"]);
    assert!(allows(&domains, "a@corp.example"));
    assert!(allows(&domains, "b@sub.partner.example"));
    assert!(!allows(&domains, "c@other.example"));
}

// ─── Save-time checks ─────────────────────────────────────────────────────

#[test]
fn the_list_is_normalized_so_comparison_never_has_to_be() {
    let normalized = validate_domains(
        &list(&[" CORP.Example ", ".corp.example", "partner.example"]),
        "x",
    )
    .expect("accepted");
    assert_eq!(normalized, list(&["corp.example", "partner.example"]));
}

#[test]
fn an_address_in_the_domain_list_is_rejected() {
    // The mistake the list cannot survive: `a@corp.example` matches nobody, and
    // a list that matches nobody is either an outage or (if it becomes empty) an
    // open door.
    let err = validate_domains(&list(&["a@corp.example"]), "email_domains").expect_err("rejected");
    assert!(err.contains("not addresses"), "got: {err}");
}

#[test]
fn a_wildcard_is_rejected_by_name() {
    let err = validate_domains(&list(&["*.corp.example"]), "email_domains").expect_err("rejected");
    assert!(err.contains("no wildcards"), "got: {err}");
    assert!(
        err.contains("subdomains are matched automatically"),
        "the message has to say what to do instead: {err}"
    );
}

#[test]
fn an_empty_entry_is_rejected_rather_than_dropped() {
    let err =
        validate_domains(&list(&["corp.example", "  "]), "email_domains").expect_err("rejected");
    assert!(err.contains("empty entry"), "got: {err}");
}

// ─── The `app_settings` row and its fallback ───────────────────────────────

#[tokio::test]
async fn the_environment_is_the_fallback_until_a_row_exists() {
    let Some(state) = common::state().await else {
        return;
    };
    let env = list(&["env.example"]);
    let outside = env.clone();
    // Held separately: `state` moves into the helper, and the point of the last
    // assertion is that it is readable again once the helper returns.
    let pool = state.pool.clone();

    common::with_allowed_domains(state, None, move |state| async move {
        let pool = state.pool.clone();
        assert_eq!(allowed_domains(&pool, &env).await.unwrap(), env);
        assert_eq!(origin(&pool, &env).await.unwrap(), Origin::Environment);

        set_allowed_domains(&pool, Some(&list(&["row.example"])))
            .await
            .expect("write the row");
        assert_eq!(
            allowed_domains(&pool, &env).await.unwrap(),
            list(&["row.example"]),
            "the row wins over the environment"
        );
        assert_eq!(origin(&pool, &env).await.unwrap(), Origin::Setting);
    })
    .await;

    // The helper put the row back, so the environment is in force again. Without
    // this the restore could silently not happen and nothing would notice until
    // another binary's sign-in test failed.
    assert_eq!(allowed_domains(&pool, &outside).await.unwrap(), outside);
    assert_eq!(origin(&pool, &outside).await.unwrap(), Origin::Environment);
}

#[tokio::test]
async fn nothing_configured_reports_itself_as_unrestricted() {
    let Some(state) = common::state().await else {
        return;
    };
    common::with_allowed_domains(state, None, |state| async move {
        let pool = state.pool.clone();
        assert_eq!(origin(&pool, &[]).await.unwrap(), Origin::Unrestricted);
        assert!(allows(
            &allowed_domains(&pool, &[]).await.unwrap(),
            "a@b.example"
        ));
    })
    .await;
}

#[tokio::test]
async fn a_row_that_is_not_a_list_of_strings_falls_back_rather_than_restricting_nothing() {
    let Some(state) = common::state().await else {
        return;
    };
    let env = list(&["env.example"]);

    common::with_allowed_domains(state, None, move |state| async move {
        let pool = state.pool.clone();
        // Someone edited the row by hand and got it wrong. Reading it as "no
        // restriction" would open the door; the env value is what the operator
        // believed was in force.
        sqlx::query(
            "INSERT INTO app_settings (key, value) VALUES ($1, $2) \
             ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind(SETTING_KEY)
        .bind(serde_json::json!({ "not": "a list" }))
        .execute(&pool)
        .await
        .expect("write a malformed row");
        assert_eq!(allowed_domains(&pool, &env).await.unwrap(), env);
        assert_eq!(origin(&pool, &env).await.unwrap(), Origin::Environment);
    })
    .await;
}

// ─── The settings route ───────────────────────────────────────────────────

mod route {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use uuid::Uuid;

    async fn call(
        router: &axum::Router,
        cookie: &str,
        method: &str,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, String) {
        let request = Request::builder()
            .method(method)
            .uri("/admin/settings/sign-in")
            .header("cookie", cookie)
            .header("content-type", "application/json")
            .body(match body {
                Some(json) => Body::from(json.to_string()),
                None => Body::empty(),
            })
            .expect("build the request");
        let response = router
            .clone()
            .oneshot(request)
            .await
            .expect("the settings route must answer");
        let status = response.status();
        let text = response
            .into_body()
            .collect()
            .await
            .expect("read the response body")
            .to_bytes();
        (status, String::from_utf8_lossy(&text).into_owned())
    }

    async fn get(router: &axum::Router, cookie: &str) -> (StatusCode, String) {
        call(router, cookie, "GET", None).await
    }

    async fn patch(
        router: &axum::Router,
        cookie: &str,
        domains: serde_json::Value,
    ) -> (StatusCode, String) {
        call(
            router,
            cookie,
            "PATCH",
            Some(serde_json::json!({ "allowed_email_domains": domains })),
        )
        .await
    }

    /// Tests in this module only ever install a list that admits the test admin
    /// (`common::create_user` mails everyone at `login.test`), which is also what
    /// keeps them from breaking a concurrent binary's sign-in test.
    const ADMIN_DOMAIN: &str = "login.test";

    #[tokio::test]
    async fn an_unconfigured_list_reads_as_unrestricted() {
        let Some(state) = common::state().await else {
            return;
        };
        common::with_allowed_domains(state, None, |state| async move {
            let (_, cookie) = common::admin_cookie(&state).await;
            let (status, body) = get(&common::admission_router(&state), &cookie).await;
            assert_eq!(status, StatusCode::OK, "got {body}");
            let json: serde_json::Value = serde_json::from_str(&body).expect("json body");
            assert_eq!(json["origin"], "unrestricted");
            assert_eq!(json["allowed_email_domains"], serde_json::json!([]));
        })
        .await;
    }

    #[tokio::test]
    async fn a_saved_list_is_reported_as_a_setting() {
        let Some(state) = common::state().await else {
            return;
        };
        common::with_allowed_domains(state, None, |state| async move {
            let (_, cookie) = common::admin_cookie(&state).await;
            let router = common::admission_router(&state);

            // Mixed case and a leading dot on the way in, normalized on the way
            // out: what the operator sees has to be what is compared.
            let (status, body) = patch(
                &router,
                &cookie,
                serde_json::json!([".Login.Test", ADMIN_DOMAIN]),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "got {body}");
            let json: serde_json::Value = serde_json::from_str(&body).expect("json body");
            assert_eq!(json["origin"], "setting");
            assert_eq!(
                json["allowed_email_domains"],
                serde_json::json!([ADMIN_DOMAIN]),
                "duplicates and case collapse"
            );
        })
        .await;
    }

    #[tokio::test]
    async fn a_list_that_would_lock_the_acting_admin_out_is_refused() {
        let Some(state) = common::state().await else {
            return;
        };
        common::with_allowed_domains(state, None, |state| async move {
            let (_, cookie) = common::admin_cookie(&state).await;
            let router = common::admission_router(&state);

            let (status, body) =
                patch(&router, &cookie, serde_json::json!(["elsewhere.example"])).await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "the one save nothing could undo: got {body}"
            );
            assert!(
                body.contains("your own email domain"),
                "the refusal has to name the reason: {body}"
            );

            // And nothing was written, so the attempt left no restriction behind.
            let (status, body) = get(&router, &cookie).await;
            assert_eq!(status, StatusCode::OK);
            let json: serde_json::Value = serde_json::from_str(&body).expect("json body");
            assert_eq!(json["origin"], "unrestricted");
        })
        .await;
    }

    #[tokio::test]
    async fn an_address_in_the_list_is_refused_rather_than_stored() {
        let Some(state) = common::state().await else {
            return;
        };
        common::with_allowed_domains(state, None, |state| async move {
            let (_, cookie) = common::admin_cookie(&state).await;
            // The list has to be checked before the lockout guard, or a typo
            // would be reported as a policy refusal and the admin would go
            // looking for the wrong problem.
            let (status, body) = patch(
                &common::admission_router(&state),
                &cookie,
                serde_json::json!(["a@login.test"]),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "got {body}");
            assert!(body.contains("not addresses"), "got {body}");
        })
        .await;
    }

    #[tokio::test]
    async fn clearing_the_row_falls_back_to_the_environment() {
        let Some(state) = common::state().await else {
            return;
        };
        common::with_allowed_domains(state, None, |state| async move {
            let (_, cookie) = common::admin_cookie(&state).await;
            let router = common::admission_router(&state);

            let (status, _) = patch(&router, &cookie, serde_json::json!([ADMIN_DOMAIN])).await;
            assert_eq!(status, StatusCode::OK);

            let (status, body) = patch(&router, &cookie, serde_json::Value::Null).await;
            assert_eq!(status, StatusCode::OK, "got {body}");
            let json: serde_json::Value = serde_json::from_str(&body).expect("json body");
            assert_eq!(
                json["origin"], "unrestricted",
                "no row and no environment value means nothing is restricted"
            );
        })
        .await;
    }

    #[tokio::test]
    async fn a_save_that_strands_another_admin_names_them_in_the_audit() {
        let Some(state) = common::state().await else {
            return;
        };
        common::with_allowed_domains(state, None, |state| async move {
            let (_, cookie) = common::admin_cookie(&state).await;

            // A second admin outside the list about to be saved. The guard only
            // covers the acting admin, so this one is allowed through — which is
            // exactly why the audit has to record who it strands.
            let other = common::create_user(&state.pool, "").await;
            let stranded = format!("stranded-{}@elsewhere.example", Uuid::new_v4().simple());
            sqlx::query("UPDATE users SET role = 'admin', email = $2 WHERE id = $1")
                .bind(other)
                .bind(&stranded)
                .execute(&state.pool)
                .await
                .expect("seed the second admin");

            let (status, body) = patch(
                &common::admission_router(&state),
                &cookie,
                serde_json::json!([ADMIN_DOMAIN]),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "got {body}");

            let detail: serde_json::Value = sqlx::query_scalar(
                "SELECT detail FROM audit_logs WHERE action = $1 ORDER BY created_at DESC LIMIT 1",
            )
            .bind(AUDIT_SETTING_UPDATE)
            .fetch_one(&state.pool)
            .await
            .expect("the save is recorded");
            // Contained, not equal: the database is shared, so other admins
            // (a real `admin@example.com` among them) are outside the test's
            // list too — which is exactly the situation being recorded.
            let excluded = detail["excluded_admins"]
                .as_array()
                .expect("a list of emails");
            assert!(
                excluded.iter().any(|e| e == &serde_json::json!(stranded)),
                "an admin locked out this way cannot report it themselves: {detail}"
            );

            sqlx::query("DELETE FROM users WHERE id = $1")
                .bind(other)
                .execute(&state.pool)
                .await
                .expect("clean up the second admin");
        })
        .await;
    }
}
