//! Idempotency key store and replay cache.
//!
//! Two kinds. The in-memory store is the default for `falak serve`: one process, so one
//! cache. The durable store keeps entries in the app's database, so every instance
//! sees the same keys. The edge runtime needs it, because each Worker isolate has its
//! own memory and a retry may land on another isolate.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use axum::http::StatusCode;
use falak_contracts::{
    Error, ErrorKind, Result,
    driver::{Statement, Value},
    identity::RequestContext,
    support::wall_clock_micros,
};

use crate::driver::NativeDriver;

/// How long a finished key keeps replaying.
const KEEP_MICROS: i64 = 24 * 3600 * 1_000_000;
/// A key still `in_flight` after this long is taken to be from a request that died.
const STALE_MICROS: i64 = 120 * 1_000_000;

const TABLE: &str = "_falak_idempotency";

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdempotencyKeyScope {
    pub subject: String,
    pub method: String,
    pub path: String,
    pub key: String,
}

#[derive(Debug, Clone)]
pub struct CachedResponse {
    pub status: StatusCode,
    pub etag: Option<String>,
    pub body: Vec<u8>,
}

/// Most keys the in-memory store holds. Each needs a caller with a valid token, so this
/// is a ceiling on memory, not a limit a client meets.
const MAX_MEMORY_ENTRIES: usize = 100_000;

#[derive(Debug, Clone)]
enum Entry {
    InFlight {
        _payload_hash: String,
        at: i64,
    },
    Completed {
        payload_hash: String,
        response: CachedResponse,
        at: i64,
    },
}

impl Entry {
    /// An in-flight key goes stale after [`STALE_MICROS`] and a finished one is dropped
    /// after [`KEEP_MICROS`], as in the durable store.
    fn expired(&self, now: i64) -> bool {
        match self {
            Self::InFlight { at, .. } => now - at > STALE_MICROS,
            Self::Completed { at, .. } => now - at > KEEP_MICROS,
        }
    }
}

#[derive(Clone, Default)]
pub struct IdempotencyStore {
    entries: Arc<Mutex<HashMap<IdempotencyKeyScope, Entry>>>,
    durable: Option<Arc<dyn NativeDriver>>,
}

pub enum CheckResult {
    Proceed,
    Replay(CachedResponse),
}

fn in_progress() -> Error {
    Error::new(
        ErrorKind::Conflict,
        "concurrent_mutation_in_progress",
        "A concurrent mutation with this idempotency key is currently in progress.",
    )
}

fn payload_mismatch() -> Error {
    Error::new(
        ErrorKind::Unprocessable,
        "idempotency_payload_mismatch",
        "The idempotency key was previously used with a different request payload.",
    )
}

impl IdempotencyStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// A store that keeps its entries in the app's database. Call [`Self::migrate`]
    /// once before use.
    pub fn durable(driver: Arc<dyn NativeDriver>) -> Self {
        Self {
            entries: Arc::default(),
            durable: Some(driver),
        }
    }

    /// Create the table for a durable store. Does nothing for the in-memory store.
    pub async fn migrate(&self) -> Result<()> {
        let Some(driver) = &self.durable else {
            return Ok(());
        };
        let sql = format!(
            "CREATE TABLE IF NOT EXISTS {TABLE} (\
             subject TEXT NOT NULL, method TEXT NOT NULL, path TEXT NOT NULL, \
             \"key\" TEXT NOT NULL, payload_hash TEXT NOT NULL, state TEXT NOT NULL, \
             status INTEGER, etag TEXT, body TEXT, created_at BIGINT NOT NULL, \
             PRIMARY KEY (subject, method, path, \"key\"))"
        );
        driver
            .batch(&context(), vec![Statement::new(sql, vec![])])
            .await
            .map(|_| ())
    }

    /// Check the idempotency key.
    ///
    /// * If unseen: marks in-flight and returns `CheckResult::Proceed`.
    /// * If in-flight: returns `Conflict` (`concurrent_mutation_in_progress`).
    /// * If completed with matching payload: returns `CheckResult::Replay`.
    /// * If completed with different payload: returns `Unprocessable` (`idempotency_payload_mismatch`).
    pub async fn check_or_start(
        &self,
        scope: &IdempotencyKeyScope,
        payload_hash: &str,
    ) -> Result<CheckResult> {
        match &self.durable {
            Some(driver) => durable_check(driver.as_ref(), scope, payload_hash).await,
            None => self.memory_check(scope, payload_hash),
        }
    }

    /// Mark an in-flight key as successfully completed.
    pub async fn complete(
        &self,
        scope: IdempotencyKeyScope,
        payload_hash: String,
        response: CachedResponse,
    ) {
        match &self.durable {
            Some(driver) => durable_complete(driver.as_ref(), &scope, &response).await,
            None => {
                let mut map = self.entries.lock().unwrap_or_else(|p| p.into_inner());
                map.insert(
                    scope,
                    Entry::Completed {
                        payload_hash,
                        response,
                        at: wall_clock_micros(),
                    },
                );
            }
        }
    }

    /// Remove an in-flight entry if the operation failed so it can be retried.
    pub async fn release(&self, scope: &IdempotencyKeyScope) {
        match &self.durable {
            Some(driver) => durable_release(driver.as_ref(), scope).await,
            None => {
                let mut map = self.entries.lock().unwrap_or_else(|p| p.into_inner());
                if let Some(Entry::InFlight { .. }) = map.get(scope) {
                    map.remove(scope);
                }
            }
        }
    }

    fn memory_check(&self, scope: &IdempotencyKeyScope, payload_hash: &str) -> Result<CheckResult> {
        let now = wall_clock_micros();
        let mut map = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        if map.get(scope).is_some_and(|e| e.expired(now)) {
            map.remove(scope);
        }
        match map.get(scope) {
            None => {
                if map.len() >= MAX_MEMORY_ENTRIES {
                    map.retain(|_, e| !e.expired(now));
                    if map.len() >= MAX_MEMORY_ENTRIES {
                        return Err(Error::new(
                            ErrorKind::Unavailable,
                            "idempotency_store_full",
                            "Too many idempotency keys are in use. Please retry later.",
                        ));
                    }
                }
                map.insert(
                    scope.clone(),
                    Entry::InFlight {
                        _payload_hash: payload_hash.to_string(),
                        at: now,
                    },
                );
                Ok(CheckResult::Proceed)
            }
            Some(Entry::InFlight { .. }) => Err(in_progress()),
            Some(Entry::Completed {
                payload_hash: recorded,
                response,
                ..
            }) => {
                if recorded != payload_hash {
                    Err(payload_mismatch())
                } else {
                    Ok(CheckResult::Replay(response.clone()))
                }
            }
        }
    }
}

fn context() -> RequestContext {
    RequestContext {
        principal: None,
        request_id: "idempotency".to_string(),
    }
}

/// `?` for SQLite and D1, `$n` for PostgreSQL.
fn ph(driver: &dyn NativeDriver, n: usize) -> String {
    if driver.profile().name == "postgres" {
        format!("${n}")
    } else {
        "?".to_string()
    }
}

fn key_values(scope: &IdempotencyKeyScope) -> Vec<Value> {
    vec![
        Value::Text(scope.subject.clone()),
        Value::Text(scope.method.clone()),
        Value::Text(scope.path.clone()),
        Value::Text(scope.key.clone()),
    ]
}

fn key_filter(driver: &dyn NativeDriver, first: usize) -> String {
    format!(
        "subject = {} AND method = {} AND path = {} AND \"key\" = {}",
        ph(driver, first),
        ph(driver, first + 1),
        ph(driver, first + 2),
        ph(driver, first + 3)
    )
}

fn text(v: Option<&Value>) -> Option<String> {
    match v {
        Some(Value::Text(s)) => Some(s.clone()),
        _ => None,
    }
}

fn int(v: Option<&Value>) -> Option<i64> {
    match v {
        Some(Value::Int64(n)) => Some(*n),
        Some(Value::TimestampMicros(n)) => Some(*n),
        _ => None,
    }
}

async fn durable_check(
    driver: &dyn NativeDriver,
    scope: &IdempotencyKeyScope,
    payload_hash: &str,
) -> Result<CheckResult> {
    let ctx = context();
    // Two attempts: the second runs after an expired or stale entry is cleared.
    for _ in 0..2 {
        let now = wall_clock_micros();
        let mut params = key_values(scope);
        params.push(Value::Text(payload_hash.to_string()));
        params.push(Value::Int64(now));
        let insert = format!(
            "INSERT INTO {TABLE} (subject, method, path, \"key\", payload_hash, state, created_at) \
             VALUES ({}, {}, {}, {}, {}, 'in_flight', {}) \
             ON CONFLICT (subject, method, path, \"key\") DO NOTHING",
            ph(driver, 1),
            ph(driver, 2),
            ph(driver, 3),
            ph(driver, 4),
            ph(driver, 5),
            ph(driver, 6)
        );
        let outcome = driver
            .batch(&ctx, vec![Statement::new(insert, params)])
            .await?;
        if outcome.first().is_some_and(|o| o.rows_affected > 0) {
            return Ok(CheckResult::Proceed);
        }

        let select = format!(
            "SELECT payload_hash, state, status, etag, body, created_at FROM {TABLE} WHERE {}",
            key_filter(driver, 1)
        );
        let rows = driver
            .query(&ctx, Statement::new(select, key_values(scope)))
            .await?;
        let Some(row) = rows.rows.first() else {
            continue; // Removed between the two statements. Try again.
        };
        let recorded = text(row.first()).unwrap_or_default();
        let state = text(row.get(1)).unwrap_or_default();
        let created = int(row.get(5)).unwrap_or(0);
        let age = now - created;

        let expired = if state == "in_flight" {
            age > STALE_MICROS
        } else {
            age > KEEP_MICROS
        };
        if expired {
            let delete = format!("DELETE FROM {TABLE} WHERE {}", key_filter(driver, 1));
            driver
                .batch(&ctx, vec![Statement::new(delete, key_values(scope))])
                .await?;
            continue;
        }
        if state == "in_flight" {
            return Err(in_progress());
        }
        if recorded != payload_hash {
            return Err(payload_mismatch());
        }
        let status = int(row.get(2))
            .and_then(|n| u16::try_from(n).ok())
            .and_then(|n| StatusCode::from_u16(n).ok())
            .unwrap_or(StatusCode::OK);
        return Ok(CheckResult::Replay(CachedResponse {
            status,
            etag: text(row.get(3)),
            body: text(row.get(4)).unwrap_or_default().into_bytes(),
        }));
    }
    Err(in_progress())
}

async fn durable_complete(
    driver: &dyn NativeDriver,
    scope: &IdempotencyKeyScope,
    response: &CachedResponse,
) {
    let mut params = vec![
        Value::Int64(i64::from(response.status.as_u16())),
        response.etag.clone().map_or(Value::Null, Value::Text),
        Value::Text(String::from_utf8_lossy(&response.body).into_owned()),
    ];
    params.extend(key_values(scope));
    let sql = format!(
        "UPDATE {TABLE} SET state = 'done', status = {}, etag = {}, body = {} WHERE {}",
        ph(driver, 1),
        ph(driver, 2),
        ph(driver, 3),
        key_filter(driver, 4)
    );
    // The write already happened. If this fails the key replays as a conflict until it
    // goes stale, which is the safe side.
    let _ = driver
        .batch(&context(), vec![Statement::new(sql, params)])
        .await;
}

async fn durable_release(driver: &dyn NativeDriver, scope: &IdempotencyKeyScope) {
    let sql = format!(
        "DELETE FROM {TABLE} WHERE state = 'in_flight' AND {}",
        key_filter(driver, 1)
    );
    let _ = driver
        .batch(&context(), vec![Statement::new(sql, key_values(scope))])
        .await;
}

/// The problem response for a refused idempotency check. A request that arrives while
/// the first is still running also carries `Retry-After: 1` (API specification §5.2).
pub fn rejection(error: &Error, instance: &str, request_id: &str) -> axum::response::Response {
    let mut res = crate::error::problem_response(error, instance, request_id, vec![]);
    if error.code() == "concurrent_mutation_in_progress" {
        res.headers_mut().insert(
            axum::http::header::RETRY_AFTER,
            axum::http::HeaderValue::from_static("1"),
        );
    }
    res
}
