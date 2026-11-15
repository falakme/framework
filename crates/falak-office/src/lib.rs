//! Falak Office: identity, registry and key service (FEDERATION specification).
//!
//! One process, one database. It signs in people, enrolls apps, issues each app tokens
//! for its own audience, publishes the keys that verify them, and keeps the revocation
//! feed. It holds no app data.
//!
//! The sign-in provider sits behind `falak-runtime-native`'s `AuthService`: today it is
//! Falak's own local identity (passwords, rotating refresh tokens). Wrapping an OIDC
//! provider with passkeys is an owner decision (ADR-0004) and is not built.

pub mod db;
mod routes;
pub mod users;

use std::{
    path::PathBuf,
    sync::{Arc, RwLock},
};

use falak_auth::{
    keys::LocalKeys,
    token::{TokenConfig, Verifier},
};
use falak_contracts::{Error, Result, support::wall_clock_micros};

use crate::{db::Db, users::Users};

pub use routes::router;

/// Seconds an access token for a tier 1 app lives; tiers 2 and 3 live a third as long.
pub const TIER1_TOKEN_SECS: i64 = 15 * 60;
pub const TIER2_TOKEN_SECS: i64 = 5 * 60;
/// How long a passport lasts.
pub const PASSPORT_SECS: i64 = 90 * 24 * 3600;
/// An enrollment token's life.
pub const ENROLLMENT_SECS: i64 = 15 * 60;
/// Clock difference allowed on a signed request.
pub const SKEW_SECS: i64 = 60;
/// How long the revocation feed says it is good for.
pub const FEED_TTL_SECS: i64 = 60;
/// The audience of Office's own session tokens.
pub const OFFICE_AUDIENCE: &str = "office";

pub struct Office {
    pub issuer: String,
    pub db: Db,
    keys: RwLock<LocalKeys>,
    keys_path: Option<PathBuf>,
    /// Verifies Office's own session tokens (audience `office`).
    session: Verifier,
    pub users: Arc<dyn Users>,
}

pub fn now() -> i64 {
    wall_clock_micros() / 1_000_000
}

impl Office {
    /// `keys_path` is where the signing keys live (`None` keeps them in memory, for
    /// tests). `session` verifies the tokens `/v1/auth/login` issues.
    pub fn new(
        issuer: String,
        db: Db,
        keys: LocalKeys,
        keys_path: Option<PathBuf>,
        session: Verifier,
        users: Arc<dyn Users>,
    ) -> Self {
        Self {
            issuer,
            db,
            keys: RwLock::new(keys),
            keys_path,
            session,
            users,
        }
    }

    pub fn session_verifier(&self) -> &Verifier {
        &self.session
    }

    /// The key set that verifies what Office signs.
    pub fn jwks(&self) -> serde_json::Value {
        let keys = self.keys.read().unwrap_or_else(|p| p.into_inner());
        let mut v = Verifier::new(TokenConfig {
            issuer: self.issuer.clone(),
            audience: String::new(),
            leeway_secs: 0,
        });
        keys.trust_all(&mut v);
        v.jwks()
    }

    pub fn active_kid(&self) -> String {
        let keys = self.keys.read().unwrap_or_else(|p| p.into_inner());
        keys.active().0.to_owned()
    }

    /// Sign with the active key: `(kid, signature bytes)`.
    pub fn sign(&self, message: &[u8]) -> (String, Vec<u8>) {
        use ed25519_dalek::Signer;
        let keys = self.keys.read().unwrap_or_else(|p| p.into_inner());
        let (kid, key) = keys.active();
        (kid.to_owned(), key.sign(message).to_bytes().to_vec())
    }

    /// Issue a token with the active key.
    pub fn issue(&self, audience: &str, claims: &falak_auth::token::Claims) -> String {
        let keys = self.keys.read().unwrap_or_else(|p| p.into_inner());
        let (kid, key) = keys.active();
        falak_auth::token::issue(
            key,
            kid,
            &TokenConfig {
                issuer: self.issuer.clone(),
                audience: audience.to_owned(),
                leeway_secs: 0,
            },
            claims,
        )
    }

    /// Make a new key the signing key. Older keys keep verifying (overlap).
    pub fn rotate(&self) -> Result<String> {
        let mut keys = self.keys.write().unwrap_or_else(|p| p.into_inner());
        let kid = keys.rotate();
        if let Some(path) = &self.keys_path {
            keys.save(path)?;
        }
        Ok(kid.0)
    }

    /// Stop trusting every key except the active one.
    pub fn retire(&self) -> Result<usize> {
        let mut keys = self.keys.write().unwrap_or_else(|p| p.into_inner());
        keys.retire_old();
        if let Some(path) = &self.keys_path {
            keys.save(path)?;
        }
        Ok(1)
    }

    pub fn key_count(&self) -> usize {
        self.jwks()["keys"].as_array().map_or(0, Vec::len)
    }
}

pub(crate) fn conflict(code: &'static str, message: &str) -> Error {
    Error::new(falak_contracts::ErrorKind::Conflict, code, message)
}
