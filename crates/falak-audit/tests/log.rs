//! The audit log on a real SQLite database: appending, the chain, and tampering.

use std::sync::atomic::{AtomicI64, Ordering};

use falak_audit::{AuditLog, Placeholders, Problem, VerifyError};
use falak_contracts::{
    ErrorKind,
    driver::{Statement, StorageDriver},
    identity::RequestContext,
    support::Clock,
};
use falak_driver_sqlite::SqliteDriver;

struct Tick(AtomicI64);
impl Clock for Tick {
    fn now_micros(&self) -> i64 {
        self.0.fetch_add(1, Ordering::Relaxed)
    }
}

fn ctx() -> RequestContext {
    RequestContext {
        principal: None,
        request_id: "t".into(),
    }
}

async fn log() -> AuditLog<SqliteDriver, Tick> {
    let log = AuditLog::new(
        SqliteDriver::in_memory().await.unwrap(),
        Tick(AtomicI64::new(1_000)),
        Placeholders::Question,
    );
    log.migrate().await.unwrap();
    log
}

async fn fill(log: &AuditLog<SqliteDriver, Tick>, n: usize) {
    for i in 0..n {
        log.append(Some(&format!("u{i}")), "login", None, "ok", "{}")
            .await
            .unwrap();
    }
}

#[tokio::test(flavor = "current_thread")]
async fn entries_chain_and_verify() {
    let log = log().await;
    assert!(log.verify(None).await.is_ok(), "an empty log is fine");
    fill(&log, 5).await;
    let all = log.entries(0, 100).await.unwrap();
    assert_eq!(all.len(), 5);
    assert_eq!(all[0].seq, 1);
    assert_eq!(all[4].prev_hash, all[3].hash);
    assert!(log.verify(None).await.is_ok());
    // Paging.
    let page = log.entries(2, 2).await.unwrap();
    assert_eq!(page.iter().map(|e| e.seq).collect::<Vec<_>>(), [3, 4]);
}

#[tokio::test(flavor = "current_thread")]
async fn optional_fields_round_trip() {
    let log = log().await;
    let e = log
        .append(None, "key_rotated", Some("k1"), "ok", "{\"by\":\"system\"}")
        .await
        .unwrap();
    let back = &log.entries(0, 10).await.unwrap()[0];
    assert_eq!(back, &e);
    assert_eq!(back.actor, None);
    assert_eq!(back.target.as_deref(), Some("k1"));
}

#[tokio::test(flavor = "current_thread")]
async fn anchor_detects_truncation_of_a_copy() {
    let log = log().await;
    fill(&log, 4).await;
    let anchor = log.anchor().await.unwrap().unwrap();
    fill(&log, 2).await;
    assert!(
        log.verify(Some(&anchor)).await.is_ok(),
        "the log grew past the anchor"
    );
    // An anchor from a log that was longer than this one.
    let short = self::log().await;
    fill(&short, 2).await;
    match short.verify(Some(&anchor)).await {
        Err(VerifyError::Tampered(f)) => assert_eq!(f.problem, Problem::DoesNotReachAnchor),
        other => panic!("expected a tamper finding, got {other:?}"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn updates_and_deletes_are_refused_by_the_database() {
    let driver = SqliteDriver::in_memory().await.unwrap();
    let log = AuditLog::new(
        // A clone shares the same pools, so raw statements hit the same database.
        driver.clone(),
        Tick(AtomicI64::new(1)),
        Placeholders::Question,
    );
    log.migrate().await.unwrap();
    log.append(Some("u"), "login", None, "ok", "{}")
        .await
        .unwrap();

    for sql in [
        "UPDATE falak_audit SET action = 'nothing happened'",
        "DELETE FROM falak_audit",
    ] {
        let err = driver
            .batch(&ctx(), vec![Statement::new(sql, vec![])])
            .await
            .unwrap_err();
        assert!(
            err.internal_source()
                .is_some_and(|s| s.to_string().contains("append-only")),
            "{sql}: {err:?}"
        );
    }
    let all = log.entries(0, 10).await.unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].action, "login");
    assert!(log.verify(None).await.is_ok());
}

#[tokio::test(flavor = "current_thread")]
async fn a_changed_row_is_found_even_if_the_triggers_are_removed() {
    let driver = SqliteDriver::in_memory().await.unwrap();
    let log = AuditLog::new(
        driver.clone(),
        Tick(AtomicI64::new(1)),
        Placeholders::Question,
    );
    log.migrate().await.unwrap();
    fill(&log, 4).await;

    // An attacker with full database rights drops the triggers and edits row 2.
    for sql in [
        "DROP TRIGGER falak_audit_no_update",
        "UPDATE falak_audit SET outcome = 'ok', action = 'nothing_happened' WHERE seq = 2",
    ] {
        driver
            .batch(&ctx(), vec![Statement::new(sql, vec![])])
            .await
            .unwrap();
    }
    match log.verify(None).await {
        Err(VerifyError::Tampered(f)) => {
            assert_eq!(f.seq, 2);
            assert_eq!(f.problem, Problem::Altered);
        }
        other => panic!("expected a tamper finding, got {other:?}"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn concurrent_appends_keep_one_chain() {
    let log = std::rc::Rc::new(log().await);
    let tasks = tokio::task::LocalSet::new();
    tasks
        .run_until(async {
            let mut handles = Vec::new();
            for i in 0..6 {
                let l = log.clone();
                handles.push(tokio::task::spawn_local(async move {
                    l.append(Some(&format!("u{i}")), "login", None, "ok", "{}")
                        .await
                }));
            }
            for h in handles {
                h.await.unwrap().unwrap();
            }
        })
        .await;
    let all = log.entries(0, 100).await.unwrap();
    assert_eq!(all.len(), 6);
    assert!(log.verify(None).await.is_ok());
}

#[tokio::test(flavor = "current_thread")]
async fn oversized_fields_are_refused() {
    let log = log().await;
    let e = log
        .append(None, &"a".repeat(257), None, "ok", "{}")
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput);
    let e = log
        .append(None, "x", None, "ok", &"d".repeat(4097))
        .await
        .unwrap_err();
    assert_eq!(e.code(), "audit_details_too_long");
}

#[tokio::test(flavor = "current_thread")]
async fn removing_the_oldest_entries_is_found_without_an_anchor() {
    let driver = SqliteDriver::in_memory().await.unwrap();
    let log = AuditLog::new(
        driver.clone(),
        Tick(AtomicI64::new(1)),
        Placeholders::Question,
    );
    log.migrate().await.unwrap();
    fill(&log, 5).await;
    for sql in [
        "DROP TRIGGER falak_audit_no_delete",
        "DELETE FROM falak_audit WHERE seq <= 2",
    ] {
        driver
            .batch(&ctx(), vec![Statement::new(sql, vec![])])
            .await
            .unwrap();
    }
    // The rest is a valid chain from seq 3, but the log no longer starts at its start.
    match log.verify(None).await {
        Err(VerifyError::Tampered(f)) => {
            assert_eq!(f.seq, 3);
            assert_eq!(f.problem, Problem::BadStart);
        }
        other => panic!("expected a tamper finding, got {other:?}"),
    }
}
