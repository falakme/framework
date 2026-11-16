//! Keys shared through the database, so more than one Office instance can run (T6.2).
//!
//! Each instance used to read its signing keys from a file in its own data directory;
//! a second instance would have generated different keys and nothing it signed would
//! verify at the first. Now the key set lives in `office_keystore`, and every instance
//! loads it at start and re-reads it every few seconds, so a rotation done through one
//! instance reaches the others without a restart. A file in the data directory is still
//! written, as a local copy, and still seeds the database the first time (so an existing
//! single-instance Office keeps its keys when it is upgraded).
//!
//! The database already holds everything else Office has to keep consistent (revocation
//! feed, request nonces, enrollments, audit chain), so any number of instances can serve
//! behind a load balancer that uses `/readyz`. Nothing here needs a leader.

use std::path::Path;

use falak_auth::keys::LocalKeys;
use falak_contracts::{Error, Result, driver::Value};

use crate::{
    Office,
    db::{Db, int, t, text},
    now,
};

/// The key set called `name`: from the database if it is there, otherwise from `path`
/// (created if missing) and then stored. Two instances starting at once end up with
/// the same set, because the second insert is ignored and both read back the winner.
pub async fn shared_keys(db: &Db, name: &str, path: &Path) -> Result<LocalKeys> {
    let read = || async {
        db.rows(
            "SELECT body FROM office_keystore WHERE name = ?",
            vec![t(name)],
        )
        .await
    };
    if let Some(r) = read().await?.first() {
        return LocalKeys::from_json(&text(r.first()));
    }
    let seed = LocalKeys::load_or_create(path)?;
    db.run(
        "INSERT INTO office_keystore (name, body, updated_at) VALUES (?, ?, ?) ON CONFLICT (name) DO NOTHING",
        vec![t(name), t(&seed.to_json_string()), Value::Int64(now())],
    )
    .await?;
    let rows = read().await?;
    let body = rows
        .first()
        .map(|r| text(r.first()))
        .ok_or_else(|| Error::internal("the key set was not stored"))?;
    let keys = LocalKeys::from_json(&body)?;
    keys.save(path)?;
    Ok(keys)
}

impl Office {
    /// Store the current signing keys for the other instances. Call after a rotation.
    pub async fn persist_keys(&self) -> Result<()> {
        let body = self
            .keys
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .to_json_string();
        let at = now();
        self.db
            .run(
                "INSERT INTO office_keystore (name, body, updated_at) VALUES ('signing', ?, ?) \
                 ON CONFLICT (name) DO UPDATE SET body = excluded.body, updated_at = excluded.updated_at",
                vec![t(&body), Value::Int64(at)],
            )
            .await?;
        self.keys_changed
            .store(at, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    /// Pick up a key set another instance stored. Returns true if the keys changed.
    pub async fn refresh_keys(&self) -> Result<bool> {
        let rows = self
            .db
            .rows(
                "SELECT body, updated_at FROM office_keystore WHERE name = 'signing'",
                vec![],
            )
            .await?;
        let Some(r) = rows.first() else {
            return Ok(false);
        };
        let body = text(r.first());
        self.keys_changed
            .store(int(r.get(1)), std::sync::atomic::Ordering::Relaxed);
        let current = self
            .keys
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .to_json_string();
        if body == current {
            return Ok(false);
        }
        let fresh = LocalKeys::from_json(&body)?;
        if let Some(path) = &self.keys_path {
            fresh.save(path)?;
        }
        *self.keys.write().unwrap_or_else(|p| p.into_inner()) = fresh;
        Ok(true)
    }

    /// Whether `sig` is a signature by key `kid` over `message`.
    pub fn verify_signature(&self, kid: &str, message: &[u8], sig: &[u8]) -> bool {
        self.keys
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .verify_with(kid, message, sig)
    }

    /// When the signing keys last changed (seconds).
    pub fn keys_changed_at(&self) -> i64 {
        self.keys_changed.load(std::sync::atomic::Ordering::Relaxed)
    }
}
