//! Verifying tokens with a cached key set (T2.9). Works without randomness or a
//! database, so it builds for `wasm32` and runs on the edge.
//!
//! The runtime fetches the issuer's JWKS and hands the text to [`JwksCache`]. The cache
//! decides *when* to fetch again; it never fetches itself, so it has no I/O and no clock
//! of its own.
//!
//! * Keys are replaced as a whole set on each refresh, so a removed key stops working.
//! * Entries that are not Ed25519 (`kty` `OKP`, `crv` `Ed25519`) are skipped.
//! * A token with an unknown `kid` may mean a key was just rotated, so the cache allows a
//!   refresh, but at most once per `min_refresh_secs`. Without that limit a stream of
//!   bad tokens would make the edge fetch the key set on every request.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ed25519_dalek::VerifyingKey;
use falak_contracts::{Error, Result, identity::Principal};
use serde_json::Value;

use crate::token::{TokenConfig, Verifier};

/// Parse a JWKS document into `(kid, key)` pairs.
pub fn parse_jwks(text: &str) -> Result<Vec<(String, VerifyingKey)>> {
    let bad = |why: &str| Error::internal(format!("key set is not valid: {why}"));
    let doc: Value = serde_json::from_str(text).map_err(|_| bad("not JSON"))?;
    let list = doc["keys"]
        .as_array()
        .ok_or_else(|| bad("no `keys` list"))?;
    let mut out = Vec::new();
    for k in list {
        if k["kty"] != "OKP" || k["crv"] != "Ed25519" {
            continue;
        }
        let (Some(kid), Some(x)) = (k["kid"].as_str(), k["x"].as_str()) else {
            continue;
        };
        let Some(bytes) = B64
            .decode(x)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
        else {
            continue;
        };
        if let Ok(key) = VerifyingKey::from_bytes(&bytes) {
            out.push((kid.to_owned(), key));
        }
    }
    if out.is_empty() {
        return Err(bad("no usable Ed25519 keys"));
    }
    Ok(out)
}

/// Timing for refreshes, in seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CachePolicy {
    /// Refresh after this long even if nothing looks wrong.
    pub ttl_secs: i64,
    /// Never refresh more often than this, even for unknown key ids.
    pub min_refresh_secs: i64,
}

impl Default for CachePolicy {
    fn default() -> Self {
        Self {
            ttl_secs: 600,
            min_refresh_secs: 30,
        }
    }
}

/// A verifier plus the knowledge of how old its keys are.
#[derive(Debug)]
pub struct JwksCache {
    config: TokenConfig,
    policy: CachePolicy,
    verifier: Verifier,
    /// When the key set was last replaced. `None` before the first load.
    fetched_at: Option<i64>,
}

impl JwksCache {
    pub fn new(config: TokenConfig, policy: CachePolicy) -> Self {
        Self {
            verifier: Verifier::new(config.clone()),
            config,
            policy,
            fetched_at: None,
        }
    }

    /// Replace every key with the set in `jwks`. On error the old keys stay.
    pub fn load(&mut self, jwks: &str, now: i64) -> Result<()> {
        let keys = parse_jwks(jwks)?;
        let mut verifier = Verifier::new(self.config.clone());
        for (kid, key) in keys {
            verifier.add_key(kid, key);
        }
        self.verifier = verifier;
        self.fetched_at = Some(now);
        Ok(())
    }

    /// True if the runtime should fetch the key set now: never loaded, or older than the
    /// time to live.
    pub fn is_stale(&self, now: i64) -> bool {
        self.fetched_at
            .is_none_or(|t| now.saturating_sub(t) >= self.policy.ttl_secs)
    }

    /// True if a token with this `kid` should trigger a refresh: the key is not known and
    /// the last refresh was not too recent.
    pub fn should_refresh_for(&self, kid: &str, now: i64) -> bool {
        !self.verifier_knows(kid)
            && self
                .fetched_at
                .is_none_or(|t| now.saturating_sub(t) >= self.policy.min_refresh_secs)
    }

    fn verifier_knows(&self, kid: &str) -> bool {
        self.verifier.jwks()["keys"]
            .as_array()
            .is_some_and(|keys| keys.iter().any(|k| k["kid"] == kid))
    }

    /// Verify a token with the cached keys.
    pub fn verify(&self, token: &str, now: i64) -> Result<Principal> {
        self.verifier.verify(token, now)
    }

    /// The `kid` named in a token's header, without trusting it. For deciding whether to
    /// refresh. `None` if the token is malformed.
    pub fn kid_of(token: &str) -> Option<String> {
        let header = token.split('.').next()?;
        let bytes = B64.decode(header).ok()?;
        let v: Value = serde_json::from_slice(&bytes).ok()?;
        v["kid"].as_str().map(str::to_owned)
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use serde_json::json;

    use super::*;
    use crate::token::{Claims, issue};

    fn config() -> TokenConfig {
        TokenConfig {
            issuer: "i".into(),
            audience: "a".into(),
            leeway_secs: 0,
        }
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn jwks_of(keys: &[(&str, u8)]) -> String {
        let mut v = Verifier::new(config());
        for (kid, seed) in keys {
            v.add_key(*kid, key(*seed).verifying_key());
        }
        v.jwks().to_string()
    }

    fn token(kid: &str, seed: u8) -> String {
        issue(
            &key(seed),
            kid,
            &config(),
            &Claims {
                subject: "u".into(),
                tenant: None,
                roles: vec![],
                issued_at: 100,
                expires_at: 1000,
                token_id: "j".into(),
            },
        )
    }

    #[test]
    fn loads_keys_and_verifies() {
        let mut c = JwksCache::new(config(), CachePolicy::default());
        assert!(c.is_stale(100));
        c.load(&jwks_of(&[("k1", 1)]), 100).unwrap();
        assert!(!c.is_stale(101));
        assert_eq!(c.verify(&token("k1", 1), 200).unwrap().subject, "u");
        assert!(c.verify(&token("k1", 2), 200).is_err(), "other key");
    }

    #[test]
    fn a_refresh_replaces_the_whole_set() {
        let mut c = JwksCache::new(config(), CachePolicy::default());
        c.load(&jwks_of(&[("old", 1)]), 100).unwrap();
        c.load(&jwks_of(&[("new", 2)]), 200).unwrap();
        assert!(c.verify(&token("old", 1), 300).is_err());
        assert!(c.verify(&token("new", 2), 300).is_ok());
    }

    #[test]
    fn a_bad_document_keeps_the_old_keys() {
        let mut c = JwksCache::new(config(), CachePolicy::default());
        c.load(&jwks_of(&[("k1", 1)]), 100).unwrap();
        for bad in [
            "",
            "{}",
            "{\"keys\":[]}",
            "{\"keys\":[{\"kty\":\"RSA\"}]}",
            "nope",
        ] {
            assert!(c.load(bad, 200).is_err(), "{bad}");
        }
        assert!(c.verify(&token("k1", 1), 300).is_ok());
    }

    #[test]
    fn skips_keys_that_are_not_ed25519_or_are_malformed() {
        let good = json!({"kty":"OKP","crv":"Ed25519","kid":"k","x":B64.encode(key(1).verifying_key().as_bytes())});
        let doc = json!({"keys":[
            {"kty":"RSA","kid":"r","n":"x","e":"AQAB"},
            {"kty":"OKP","crv":"Ed25519","kid":"short","x":"AAAA"},
            {"kty":"OKP","crv":"Ed25519","x":"AAAA"},
            good,
        ]});
        let keys = parse_jwks(&doc.to_string()).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].0, "k");
    }

    #[test]
    fn stale_after_the_ttl() {
        let mut c = JwksCache::new(
            config(),
            CachePolicy {
                ttl_secs: 600,
                min_refresh_secs: 30,
            },
        );
        c.load(&jwks_of(&[("k1", 1)]), 1000).unwrap();
        assert!(!c.is_stale(1599));
        assert!(c.is_stale(1600));
    }

    #[test]
    fn unknown_kid_refreshes_at_most_once_per_interval() {
        let mut c = JwksCache::new(
            config(),
            CachePolicy {
                ttl_secs: 600,
                min_refresh_secs: 30,
            },
        );
        assert!(c.should_refresh_for("k2", 100), "nothing loaded yet");
        c.load(&jwks_of(&[("k1", 1)]), 100).unwrap();
        assert!(!c.should_refresh_for("k1", 500), "known key");
        assert!(!c.should_refresh_for("k2", 110), "refreshed 10 seconds ago");
        assert!(c.should_refresh_for("k2", 131), "30 seconds have passed");
    }

    #[test]
    fn reads_the_kid_without_trusting_it() {
        assert_eq!(JwksCache::kid_of(&token("k9", 1)).as_deref(), Some("k9"));
        assert_eq!(JwksCache::kid_of("garbage"), None);
        assert_eq!(JwksCache::kid_of(""), None);
    }
}
