//! Falak Office: identity, registry and key service (FEDERATION specification).
//!
//! One process, one database. It signs in people, enrolls apps, issues each app tokens
//! for its own audience, publishes the keys that verify them, and keeps the revocation
//! feed. It holds no app data.
//!
//! Sign-in has two doors. Falak's own local identity (passwords, rotating refresh
//! tokens) sits behind `falak-runtime-native`'s `AuthService`. Any OpenID Connect provider
//! (Clerk, Auth0, Keycloak, ...) can be used instead through `oidc`: passkeys and
//! multi-factor are the provider's job (ADR-0011).

pub mod anchor;
pub mod compute;
pub mod db;
pub mod keystore;
pub mod observe;
pub mod oidc;
pub mod pii;
mod routes;
pub mod settings;
pub mod users;
pub mod vault;

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
    /// When the signing keys last changed (seconds), for the key-age objective.
    keys_changed: std::sync::atomic::AtomicI64,
    /// Wraps tenant data keys (`vault`).
    kek: RwLock<vault::KekSet>,
    keys_path: Option<PathBuf>,
    /// Verifies Office's own session tokens (audience `office`).
    session: Verifier,
    pub users: Arc<dyn Users>,
    /// Sign-in through an outside OpenID Connect provider, when one is configured. It can
    /// be changed while Office runs.
    oidc: RwLock<Option<Arc<oidc::Oidc>>>,
    /// Where `settings.json` lives (`None` in tests: settings are not saved).
    data_dir: Option<PathBuf>,
    /// While nobody has an account, the one-time token that lets the first person set
    /// Office up from a browser. Printed on the console, never sent anywhere.
    setup_token: std::sync::Mutex<Option<String>>,
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
            keys_changed: std::sync::atomic::AtomicI64::new(now()),
            kek: RwLock::new(vault::KekSet::ephemeral()),
            keys_path,
            session,
            users,
            oidc: RwLock::new(None),
            data_dir: None,
            setup_token: std::sync::Mutex::new(None),
        }
    }

    /// Accept ID tokens from this provider at `POST /v1/auth/oidc/exchange`.
    #[must_use]
    pub fn with_oidc(self, oidc: oidc::OidcConfig) -> Self {
        self.set_oidc(Some(oidc));
        self
    }

    /// The vault's key-encryption keys (from `FALAK_VAULT_KEK` or the data directory).
    #[must_use]
    pub fn with_kek(self, kek: vault::KekSet) -> Self {
        *self.kek.write().unwrap_or_else(|p| p.into_inner()) = kek;
        self
    }

    /// Where settings are saved (`settings.json`).
    #[must_use]
    pub fn with_data_dir(mut self, dir: PathBuf) -> Self {
        self.data_dir = Some(dir);
        self
    }

    /// The configured identity provider, if any.
    pub fn oidc(&self) -> Option<Arc<oidc::Oidc>> {
        self.oidc.read().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Turn sign-in through a provider on, change it, or (`None`) off.
    pub fn set_oidc(&self, cfg: Option<oidc::OidcConfig>) {
        *self.oidc.write().unwrap_or_else(|p| p.into_inner()) =
            cfg.map(|c| Arc::new(oidc::Oidc::new(c)));
    }

    /// Make the one-time setup token, if nobody has an account yet.
    pub async fn arm_setup(&self) -> Result<Option<String>> {
        let n = self
            .db
            .rows("SELECT COUNT(*) FROM falak_auth_users", vec![])
            .await?;
        if db::int(n.first().and_then(|r| r.first())) > 0 {
            return Ok(None);
        }
        let mut b = [0u8; 18];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut b);
        let token = hex::encode(b);
        *self.setup_token.lock().unwrap_or_else(|p| p.into_inner()) = Some(token.clone());
        Ok(Some(token))
    }

    /// Spend the setup token: true once, for the right token.
    pub(crate) fn take_setup_token(&self, given: &str) -> bool {
        let mut t = self.setup_token.lock().unwrap_or_else(|p| p.into_inner());
        let ok = t.as_deref().is_some_and(|want| {
            want.len() == given.len()
                && want
                    .bytes()
                    .zip(given.bytes())
                    .fold(0u8, |a, (x, y)| a | (x ^ y))
                    == 0
        });
        if ok {
            *t = None;
        }
        ok
    }

    /// Give the token back after a failed setup (for example a weak password), so the
    /// person can try again.
    pub(crate) fn return_setup_token(&self, token: &str) {
        *self.setup_token.lock().unwrap_or_else(|p| p.into_inner()) = Some(token.to_owned());
    }

    pub fn setup_open(&self) -> bool {
        self.setup_token
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_some()
    }

    pub fn data_dir(&self) -> Option<&std::path::Path> {
        self.data_dir.as_deref()
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
