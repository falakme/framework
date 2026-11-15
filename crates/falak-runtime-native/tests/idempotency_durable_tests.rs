//! The database-backed idempotency store: the same behaviour as the in-memory one, but
//! shared by every instance that uses the database (the edge runtime relies on it).

use std::sync::Arc;

use axum::http::StatusCode;
use falak_driver_sqlite::SqliteDriver;
use falak_runtime_native::{
    NativeDriver,
    idempotency::{CachedResponse, CheckResult, IdempotencyKeyScope, IdempotencyStore},
};

fn scope(key: &str) -> IdempotencyKeyScope {
    IdempotencyKeyScope {
        subject: "alice".into(),
        method: "POST".into(),
        path: "/v1/notes".into(),
        key: key.into(),
    }
}

fn reply() -> CachedResponse {
    CachedResponse {
        status: StatusCode::CREATED,
        etag: Some("1".into()),
        body: br#"{"id":"n1"}"#.to_vec(),
    }
}

async fn store() -> (IdempotencyStore, Arc<SqliteDriver>) {
    let driver = Arc::new(SqliteDriver::in_memory().await.unwrap());
    let shared: Arc<dyn NativeDriver> = driver.clone();
    let store = IdempotencyStore::durable(shared);
    store.migrate().await.unwrap();
    (store, driver)
}

#[tokio::test]
async fn first_use_proceeds_and_the_same_request_replays() {
    let (store, _db) = store().await;
    let s = scope("k1");
    assert!(matches!(
        store.check_or_start(&s, "h1").await.unwrap(),
        CheckResult::Proceed
    ));
    store.complete(s.clone(), "h1".into(), reply()).await;
    match store.check_or_start(&s, "h1").await.unwrap() {
        CheckResult::Replay(r) => {
            assert_eq!(r.status, StatusCode::CREATED);
            assert_eq!(r.etag.as_deref(), Some("1"));
            assert_eq!(r.body, br#"{"id":"n1"}"#);
        }
        CheckResult::Proceed => panic!("expected a replay"),
    }
}

#[tokio::test]
async fn another_body_with_the_same_key_is_422() {
    let (store, _db) = store().await;
    let s = scope("k2");
    store.check_or_start(&s, "h1").await.unwrap();
    store.complete(s.clone(), "h1".into(), reply()).await;
    let err = store.check_or_start(&s, "h2").await.err().unwrap();
    assert_eq!(err.code(), "idempotency_payload_mismatch");
}

#[tokio::test]
async fn a_second_request_while_the_first_runs_conflicts() {
    let (store, _db) = store().await;
    let s = scope("k3");
    store.check_or_start(&s, "h1").await.unwrap();
    let err = store.check_or_start(&s, "h1").await.err().unwrap();
    assert_eq!(err.code(), "concurrent_mutation_in_progress");
}

#[tokio::test]
async fn releasing_a_failed_request_lets_it_retry() {
    let (store, _db) = store().await;
    let s = scope("k4");
    store.check_or_start(&s, "h1").await.unwrap();
    store.release(&s).await;
    assert!(matches!(
        store.check_or_start(&s, "h1").await.unwrap(),
        CheckResult::Proceed
    ));
}

#[tokio::test]
async fn keys_are_per_caller() {
    let (store, _db) = store().await;
    let mut other = scope("k5");
    other.subject = "bob".into();
    store.check_or_start(&scope("k5"), "h1").await.unwrap();
    assert!(matches!(
        store.check_or_start(&other, "h1").await.unwrap(),
        CheckResult::Proceed
    ));
}

#[tokio::test]
async fn two_stores_on_one_database_share_keys() {
    let (first, db) = store().await;
    let shared: Arc<dyn NativeDriver> = db.clone();
    let second = IdempotencyStore::durable(shared);
    let s = scope("k6");
    first.check_or_start(&s, "h1").await.unwrap();
    first.complete(s.clone(), "h1".into(), reply()).await;
    assert!(matches!(
        second.check_or_start(&s, "h1").await.unwrap(),
        CheckResult::Replay(_)
    ));
}
