//! The app side of Falak Office (FEDERATION specification).
//!
//! * [`AppKey`] and [`OfficeConfig`]: the key an app made when it enrolled, and what
//!   Office told it.
//! * [`enroll_request`], [`request_headers`], [`verify_feed`]: the wire formats.
//! * [`Federation`]: what an app knows about Office while it runs: the key set, the
//!   revocation feed, and how stale they are. It decides what is allowed when Office
//!   cannot be reached, per trust tier (§8).
//! * [`FederatedAuthenticator`]: verifies Office tokens against that knowledge.

#[cfg(feature = "http")]
pub mod http;

use std::{
    collections::HashSet,
    path::Path,
    sync::{Arc, RwLock},
};

use axum::{
    extract::{Request, State},
    http::Method,
    middleware::Next,
    response::Response,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier as _, VerifyingKey};
use falak_auth::{
    jwks::{CachePolicy, JwksCache, parse_jwks},
    token::{TokenConfig, token_id},
};
use falak_contracts::{Error, identity::Principal};
use falak_runtime_native::{
    context::{Authenticator, bearer_token, extract_request_id},
    error::problem_response,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Default limit on how old the revocation feed may be before a tier 2 app turns read
/// only. Five minutes.
pub const DEFAULT_MAX_STALENESS_SECS: i64 = 300;

/// How long the app trusts the key set it fetched before it fetches again.
pub const KEY_SET_TTL_SECS: i64 = 60;

/// A token with a key id the app does not know fetches the key set, but never more often
/// than this, so a stream of made-up key ids cannot become a stream of requests to Office.
pub const UNKNOWN_KEY_COOLDOWN_SECS: i64 = 2;

// ---------------------------------------------------------------- key and config

/// The app's Ed25519 key. The private half never leaves the app.
pub struct AppKey(SigningKey);

impl AppKey {
    pub fn generate() -> Self {
        Self(SigningKey::generate(&mut rand_core::OsRng))
    }

    /// Load the key file, or make one (owner-only permissions on Unix).
    pub fn load_or_create(path: &Path) -> Result<Self, String> {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                let v: Value =
                    serde_json::from_str(&text).map_err(|_| "the app key file is not valid")?;
                let bytes = v["secret"]
                    .as_str()
                    .and_then(|s| B64.decode(s).ok())
                    .and_then(|b| <[u8; 32]>::try_from(b).ok())
                    .ok_or("the app key file is not valid")?;
                Ok(Self(SigningKey::from_bytes(&bytes)))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let key = Self::generate();
                key.save(path)?;
                Ok(key)
            }
            Err(e) => Err(format!("cannot read the app key: {e}")),
        }
    }

    fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let text = json!({"secret": B64.encode(self.0.to_bytes())}).to_string();
        write_private(path, &text)
    }

    /// The public key, base64url.
    pub fn public(&self) -> String {
        B64.encode(self.0.verifying_key().to_bytes())
    }

    fn sign(&self, message: &[u8]) -> String {
        B64.encode(self.0.sign(message).to_bytes())
    }
}

impl std::fmt::Debug for AppKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AppKey(public ")
            .and_then(|()| f.write_str(&self.public()))
            .and_then(|()| f.write_str(")"))
    }
}

fn write_private(path: &Path, text: &str) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::{io::Write, os::unix::fs::OpenOptionsExt};
        let tmp = path.with_extension("tmp");
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| e.to_string())?;
        f.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, path).map_err(|e| e.to_string())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, text).map_err(|e| e.to_string())
    }
}

/// What an app keeps after enrolling (`.falak/office.json`). It holds no secret: the
/// private key is in its own file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfficeConfig {
    pub office_url: String,
    pub app: String,
    pub tier: u8,
    pub issuer: String,
    pub jwks_url: String,
    pub passport: String,
}

impl OfficeConfig {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read `{}`: {e}", path.display()))?;
        let cfg: Self = serde_json::from_str(&text)
            .map_err(|e| format!("`{}` is not valid: {e}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let text = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(path, text).map_err(|e| e.to_string())
    }

    /// Keys come from Office over `https`, or over plain `http` to this machine in
    /// development (FEDERATION §5.4).
    pub fn validate(&self) -> Result<(), String> {
        for url in [&self.office_url, &self.jwks_url] {
            let ok = url.starts_with("https://")
                || ["http://127.0.0.1", "http://localhost", "http://[::1]"]
                    .iter()
                    .any(|p| {
                        url.starts_with(p)
                            && matches!(url.as_bytes().get(p.len()), None | Some(b':' | b'/'))
                    });
            if !ok {
                return Err(format!("`{url}` must be https (or http to this machine)"));
            }
        }
        if !(1..=2).contains(&self.tier) {
            return Err("this version supports tier 1 and 2 apps".into());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------- wire formats

pub fn random_nonce() -> String {
    use rand_core::RngCore;
    let mut b = [0u8; 18];
    rand_core::OsRng.fill_bytes(&mut b);
    B64.encode(b)
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// The body of `POST /v1/_office/enroll`, with proof of the key.
pub fn enroll_request(key: &AppKey, token: &str, app: &str, now: i64, nonce: &str) -> Value {
    let public = key.public();
    let message = format!("falak-enroll\n{app}\n{public}\n{nonce}\n{now}");
    json!({
        "token": token, "app": app, "public_key": public,
        "timestamp": now, "nonce": nonce, "signature": key.sign(message.as_bytes()),
    })
}

/// Headers for a signed request to Office (§4).
pub fn request_headers(
    key: &AppKey,
    app: &str,
    method: &str,
    path_and_query: &str,
    body: &[u8],
    now: i64,
    nonce: &str,
) -> Vec<(String, String)> {
    let message = format!(
        "{method}\n{path_and_query}\n{now}\n{nonce}\n{}",
        sha256_hex(body)
    );
    vec![
        ("x-falak-app".into(), app.to_owned()),
        ("x-falak-timestamp".into(), now.to_string()),
        ("x-falak-nonce".into(), nonce.to_owned()),
        ("x-falak-signature".into(), key.sign(message.as_bytes())),
    ]
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub kind: String,
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Feed {
    pub version: i64,
    pub issued_at: i64,
    pub ttl_secs: i64,
    pub entries: Vec<Entry>,
}

/// Check a revocation feed document against the Office key set (§6).
pub fn verify_feed(doc: &Value, keys: &[(String, VerifyingKey)]) -> Result<Feed, String> {
    let (payload, kid, sig) = (
        doc["payload"].as_str().ok_or("the feed has no payload")?,
        doc["kid"].as_str().ok_or("the feed has no key id")?,
        doc["signature"]
            .as_str()
            .ok_or("the feed has no signature")?,
    );
    let key = keys
        .iter()
        .find(|(k, _)| k == kid)
        .map(|(_, k)| k)
        .ok_or("the feed is signed with a key that is not in the key set")?;
    let sig = B64
        .decode(sig)
        .ok()
        .and_then(|b| Signature::from_slice(&b).ok())
        .ok_or("the feed signature is malformed")?;
    key.verify(payload.as_bytes(), &sig)
        .map_err(|_| "the feed signature does not verify")?;
    let p: Value = serde_json::from_str(payload).map_err(|_| "the feed payload is not JSON")?;
    Ok(Feed {
        version: p["version"].as_i64().ok_or("the feed has no version")?,
        issued_at: p["issued_at"].as_i64().unwrap_or(0),
        ttl_secs: p["ttl_secs"].as_i64().unwrap_or(60),
        entries: p["entries"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|e| {
                        Some(Entry {
                            kind: e["kind"].as_str()?.to_owned(),
                            id: e["id"].as_str()?.to_owned(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default(),
    })
}

// ---------------------------------------------------------------- what the app knows

struct Inner {
    jwks: JwksCache,
    keys: Vec<(String, VerifyingKey)>,
    revoked_tokens: HashSet<String>,
    revoked_subjects: HashSet<String>,
    app_revoked: bool,
    feed_version: i64,
    last_feed_ok: Option<i64>,
    last_error: Option<String>,
}

/// Office, as the app currently knows it.
pub struct Federation {
    pub app: String,
    pub tier: u8,
    max_staleness_secs: i64,
    inner: RwLock<Inner>,
}

/// A snapshot for `office status` and health checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub keys: usize,
    pub feed_version: i64,
    pub feed_age_secs: Option<i64>,
    pub read_only: bool,
    pub app_revoked: bool,
    pub last_error: Option<String>,
}

impl Federation {
    pub fn new(cfg: &OfficeConfig, max_staleness_secs: i64) -> Self {
        let config = TokenConfig {
            issuer: cfg.issuer.clone(),
            audience: cfg.app.clone(),
            leeway_secs: 30,
        };
        Self {
            app: cfg.app.clone(),
            tier: cfg.tier,
            max_staleness_secs,
            inner: RwLock::new(Inner {
                jwks: JwksCache::new(
                    config,
                    CachePolicy {
                        ttl_secs: KEY_SET_TTL_SECS,
                        min_refresh_secs: UNKNOWN_KEY_COOLDOWN_SECS,
                    },
                ),
                keys: Vec::new(),
                revoked_tokens: HashSet::new(),
                revoked_subjects: HashSet::new(),
                app_revoked: false,
                feed_version: 0,
                last_feed_ok: None,
                last_error: None,
            }),
        }
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Inner> {
        self.inner.write().unwrap_or_else(|p| p.into_inner())
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Inner> {
        self.inner.read().unwrap_or_else(|p| p.into_inner())
    }

    /// Replace the key set. On error the old keys stay.
    pub fn load_jwks(&self, text: &str, now: i64) -> Result<(), String> {
        let keys = parse_jwks(text).map_err(|e| e.public_message().to_owned())?;
        let mut i = self.write();
        i.jwks
            .load(text, now)
            .map_err(|e| e.public_message().to_owned())?;
        i.keys = keys;
        Ok(())
    }

    /// Whether the app should fetch the key set now: never loaded or old, or a token
    /// names a key it does not know.
    pub fn wants_jwks(&self, now: i64) -> bool {
        self.read().jwks.is_stale(now)
    }

    pub fn wants_jwks_for(&self, token: &str, now: i64) -> bool {
        JwksCache::kid_of(token).is_some_and(|k| self.read().jwks.should_refresh_for(&k, now))
    }

    pub fn keys(&self) -> Vec<(String, VerifyingKey)> {
        self.read().keys.clone()
    }

    pub fn feed_version(&self) -> i64 {
        self.read().feed_version
    }

    /// Apply a verified feed. A feed older than one already applied is ignored (§6).
    pub fn apply_feed(&self, feed: &Feed, now: i64) -> bool {
        let mut i = self.write();
        if feed.version < i.feed_version {
            return false;
        }
        for e in &feed.entries {
            match e.kind.as_str() {
                "token" => {
                    i.revoked_tokens.insert(e.id.clone());
                }
                "subject" => {
                    i.revoked_subjects.insert(e.id.clone());
                }
                "app" if e.id == self.app => i.app_revoked = true,
                _ => {}
            }
        }
        i.feed_version = feed.version;
        i.last_feed_ok = Some(now);
        i.last_error = None;
        true
    }

    pub fn note_error(&self, message: String) {
        self.write().last_error = Some(message);
    }

    /// The caller, if the token verifies with the cached keys and has not been revoked.
    pub fn verify(&self, token: &str, now: i64) -> Option<Principal> {
        let i = self.read();
        if i.app_revoked {
            return None;
        }
        let principal = i.jwks.verify(token, now).ok()?;
        if i.revoked_subjects.contains(&principal.subject) {
            return None;
        }
        if token_id(token).is_some_and(|j| i.revoked_tokens.contains(&j)) {
            return None;
        }
        Some(principal)
    }

    /// Tier 2 and above: once the feed is older than the limit, only reads (§8).
    pub fn read_only(&self, now: i64) -> bool {
        if self.tier < 2 {
            return false;
        }
        match self.read().last_feed_ok {
            Some(t) => now - t > self.max_staleness_secs,
            None => true,
        }
    }

    pub fn status(&self, now: i64) -> Status {
        let i = self.read();
        Status {
            keys: i.keys.len(),
            feed_version: i.feed_version,
            feed_age_secs: i.last_feed_ok.map(|t| now - t),
            read_only: self.tier >= 2
                && i.last_feed_ok
                    .is_none_or(|t| now - t > self.max_staleness_secs),
            app_revoked: i.app_revoked,
            last_error: i.last_error.clone(),
        }
    }
}

/// Verifies Office tokens with what the app knows. Plug it into `create_router`.
pub struct FederatedAuthenticator(pub Arc<Federation>);

impl Authenticator for FederatedAuthenticator {
    fn authenticate(&self, headers: &axum::http::HeaderMap) -> Option<Principal> {
        let token = bearer_token(headers)?;
        self.0.verify(token, now())
    }
}

pub fn now() -> i64 {
    falak_contracts::support::wall_clock_micros() / 1_000_000
}

/// Middleware: while a tier 2 app is read only, anything but a read answers `503`.
pub async fn read_only_gate(
    State(fed): State<Arc<Federation>>,
    req: Request,
    next: Next,
) -> Response {
    let safe = matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    let path = req.uri().path();
    let exempt = path == "/healthz" || path == "/readyz" || path.starts_with("/v1/auth/");
    if !safe && !exempt && fed.read_only(now()) {
        let id = extract_request_id(req.headers());
        let instance = path.to_owned();
        return problem_response(
            &Error::new(
                falak_contracts::ErrorKind::Unavailable,
                "office_unavailable",
                "Changes are paused because Office cannot be reached. Reading still works.",
            ),
            &instance,
            &id,
            vec![],
        );
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(tier: u8) -> OfficeConfig {
        OfficeConfig {
            office_url: "https://office.test".into(),
            app: "notebook".into(),
            tier,
            issuer: "https://office.test".into(),
            jwks_url: "https://office.test/.well-known/jwks.json".into(),
            passport: "p".into(),
        }
    }

    #[test]
    fn urls_must_be_https_or_this_machine() {
        assert!(cfg(1).validate().is_ok());
        let mut c = cfg(1);
        c.jwks_url = "http://127.0.0.1:8788/.well-known/jwks.json".into();
        c.office_url = "http://localhost:8788".into();
        assert!(c.validate().is_ok());
        for bad in [
            "http://office.test",
            "http://127.0.0.1.evil.test/x",
            "ftp://x",
        ] {
            let mut c = cfg(1);
            c.jwks_url = bad.into();
            assert!(c.validate().is_err(), "{bad}");
        }
        assert!(cfg(3).validate().is_err());
    }

    #[test]
    fn tier_one_never_goes_read_only_tier_two_does_when_the_feed_is_old() {
        let t1 = Federation::new(&cfg(1), 300);
        assert!(!t1.read_only(1_000_000));
        let t2 = Federation::new(&cfg(2), 300);
        assert!(t2.read_only(1000), "a feed never fetched is stale");
        let feed = Feed {
            version: 1,
            issued_at: 1000,
            ttl_secs: 60,
            entries: vec![],
        };
        assert!(t2.apply_feed(&feed, 1000));
        assert!(!t2.read_only(1200));
        assert!(!t2.read_only(1300));
        assert!(t2.read_only(1301));
    }

    #[test]
    fn an_older_feed_is_ignored_and_revocations_stick() {
        let f = Federation::new(&cfg(2), 300);
        let newer = Feed {
            version: 5,
            issued_at: 10,
            ttl_secs: 60,
            entries: vec![Entry {
                kind: "app".into(),
                id: "notebook".into(),
            }],
        };
        assert!(f.apply_feed(&newer, 10));
        assert!(f.status(10).app_revoked);
        let older = Feed {
            version: 4,
            issued_at: 9,
            ttl_secs: 60,
            entries: vec![],
        };
        assert!(!f.apply_feed(&older, 11));
        assert_eq!(f.feed_version(), 5);
    }

    #[test]
    fn requests_and_enrolments_are_signed_over_what_the_spec_says() {
        let key = AppKey::generate();
        let body = enroll_request(&key, "tok", "notebook", 100, "nonce-nonce-nonce-1");
        let message = format!(
            "falak-enroll\nnotebook\n{}\nnonce-nonce-nonce-1\n100",
            key.public()
        );
        let sig = Signature::from_slice(&B64.decode(body["signature"].as_str().unwrap()).unwrap())
            .unwrap();
        assert!(
            key.0
                .verifying_key()
                .verify(message.as_bytes(), &sig)
                .is_ok()
        );

        let h = request_headers(
            &key,
            "notebook",
            "GET",
            "/v1/_office/manifest",
            b"",
            100,
            "n",
        );
        assert_eq!(h[0].1, "notebook");
        let msg = format!("GET\n/v1/_office/manifest\n100\nn\n{}", sha256_hex(b""));
        let sig = Signature::from_slice(&B64.decode(&h[3].1).unwrap()).unwrap();
        assert!(key.0.verifying_key().verify(msg.as_bytes(), &sig).is_ok());
    }
}
