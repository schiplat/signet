//! The group-membership predicate has to be indexable.
//!
//! SCIM membership lives in the denormalised `users.groups` array, and both the
//! group reads and the membership writes filter on it. They filter with
//! `groups @> ARRAY[$1]` rather than the more obvious `$1 = ANY(groups)`, and
//! migration `030` adds the GIN index that serves them.
//!
//! Both halves of that are easy to get silently wrong. The planner does *not*
//! rewrite `value = ANY(column)` into a containment test, so that spelling gets
//! an index it cannot use and a sequential scan of `users` per group, per
//! membership write. And an index that exists but is never chosen is
//! indistinguishable in production from one that does not exist — it only costs
//! write throughput. So this asserts on the plan rather than on the catalogue.

mod common;

use sqlx::PgPool;
use sqlx::Row;

/// Runs the query under `enable_seqscan = off` and returns the plan as one text
/// blob.
///
/// The penalty matters more than the setting: on an empty test table the planner
/// prices a sequential scan below an index scan and would report success for an
/// index it never considered. Disabling the alternative asks the planner the
/// real question — *can* this predicate be served by an index? — and a predicate
/// it cannot index still falls back to a scan, so the assertion below cannot
/// pass by accident.
async fn plan_for(pool: &PgPool, sql: &str, value: &str) -> String {
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL enable_seqscan = off")
        .execute(&mut *tx)
        .await
        .unwrap();
    let rows = sqlx::query(sql)
        .bind(value)
        .fetch_all(&mut *tx)
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    rows.iter()
        .map(|row| row.get::<String, _>(0))
        .collect::<Vec<_>>()
        .join("\n")
}

#[tokio::test]
async fn the_membership_predicate_uses_the_gin_index() {
    let Some(state) = common::state().await else {
        return;
    };

    for sql in [
        // group_members(): "who is in this group?" — the exact read path, sort
        // and all; the planner answers it with a bitmap scan plus a sort.
        "EXPLAIN SELECT id, email FROM users WHERE groups @> ARRAY[$1::text] ORDER BY email",
        // array_remove(): "everyone in this group loses membership"
        "EXPLAIN UPDATE users SET groups = array_remove(groups, $1) WHERE groups @> ARRAY[$1::text]",
    ] {
        let plan = plan_for(&state.pool, sql, "engineering").await;
        assert!(
            plan.contains("users_groups_gin"),
            "the planner did not use the GIN index for:\n  {sql}\nplan:\n{plan}"
        );
    }
}
