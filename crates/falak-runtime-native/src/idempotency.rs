//! In-memory idempotency key store and replay cache.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use axum::http::StatusCode;
use falak_contracts::{Error, ErrorKind, Result};

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

#[derive(Debug, Clone)]
enum Entry {
    InFlight {
        _payload_hash: String,
    },
    Completed {
        payload_hash: String,
        response: CachedResponse,
    },
}

#[derive(Clone, Default)]
pub struct IdempotencyStore {
    entries: Arc<Mutex<HashMap<IdempotencyKeyScope, Entry>>>,
}

pub enum CheckResult {
    Proceed,
    Replay(CachedResponse),
}

impl IdempotencyStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check the idempotency key.
    ///
    /// * If unseen: marks in-flight and returns `CheckResult::Proceed`.
    /// * If in-flight: returns `Conflict` (`concurrent_mutation_in_progress`).
    /// * If completed with matching payload: returns `CheckResult::Replay`.
    /// * If completed with different payload: returns `InvalidInput` (`idempotency_payload_mismatch`).
    pub fn check_or_start(
        &self,
        scope: &IdempotencyKeyScope,
        payload_hash: &str,
    ) -> Result<CheckResult> {
        let mut map = self.entries.lock().unwrap();
        match map.get(scope) {
            None => {
                map.insert(
                    scope.clone(),
                    Entry::InFlight {
                        _payload_hash: payload_hash.to_string(),
                    },
                );
                Ok(CheckResult::Proceed)
            }
            Some(Entry::InFlight { .. }) => Err(Error::new(
                ErrorKind::Conflict,
                "concurrent_mutation_in_progress",
                "A concurrent mutation with this idempotency key is currently in progress.",
            )),
            Some(Entry::Completed {
                payload_hash: recorded,
                response,
            }) => {
                if recorded != payload_hash {
                    Err(Error::invalid_input(
                        "idempotency_payload_mismatch",
                        "The idempotency key was previously used with a different request payload.",
                    ))
                } else {
                    Ok(CheckResult::Replay(response.clone()))
                }
            }
        }
    }

    /// Mark an in-flight key as successfully completed.
    pub fn complete(
        &self,
        scope: IdempotencyKeyScope,
        payload_hash: String,
        response: CachedResponse,
    ) {
        let mut map = self.entries.lock().unwrap();
        map.insert(
            scope,
            Entry::Completed {
                payload_hash,
                response,
            },
        );
    }

    /// Remove an in-flight entry if the operation failed so it can be retried.
    pub fn release(&self, scope: &IdempotencyKeyScope) {
        let mut map = self.entries.lock().unwrap();
        if let Some(Entry::InFlight { .. }) = map.get(scope) {
            map.remove(scope);
        }
    }
}
