//! Access tokens: compact JWTs signed with Ed25519 (T1.13).
//!
//! Rules, all enforced in [`Verifier::verify`]:
//! * The algorithm is fixed to `EdDSA`. The token's own `alg` is only compared against
//!   it, never used to choose one, so `none` and `HS256` confusion cannot happen.
//! * The signing key is found by `kid` in a set the server controls. An unknown `kid`
//!   is refused.
//! * `iss`, `aud`, `exp` and `nbf` are checked. A token for another app is refused.
//! * Every failure returns the same public error. The reason goes to the internal
//!   source for logs.
//!
//! A token is data, never a source of authority beyond its signed claims. The runtime
//! builds the `Principal` from a verified token only.

use std::collections::HashMap;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use falak_contracts::{Error, Result, identity::Principal};
use serde_json::{Value, json};

/// Tokens longer than this are refused before any parsing.
pub const MAX_TOKEN_BYTES: usize = 8 * 1024;

/// Settings shared by issuing and verifying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenConfig {
    /// `iss` claim: who issues tokens.
    pub issuer: String,
    /// `aud` claim: the app the token is for.
    pub audience: String,
    /// Allowed clock difference, in seconds, when checking `exp` and `nbf`.
    pub leeway_secs: i64,
}

/// What a token states about its subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claims {
    pub subject: String,
    pub tenant: Option<String>,
    pub roles: Vec<String>,
    pub issued_at: i64,
    pub expires_at: i64,
    pub token_id: String,
}

/// Create a signed token.
pub fn issue(key: &SigningKey, kid: &str, config: &TokenConfig, claims: &Claims) -> String {
    let header = json!({ "alg": "EdDSA", "typ": "JWT", "kid": kid });
    let mut payload = json!({
        "iss": config.issuer,
        "aud": config.audience,
        "sub": claims.subject,
        "iat": claims.issued_at,
        "nbf": claims.issued_at,
        "exp": claims.expires_at,
        "jti": claims.token_id,
        "roles": claims.roles,
    });
    if let Some(t) = &claims.tenant {
        payload["tenant"] = json!(t);
    }
    let signing_input = format!("{}.{}", encode(&header), encode(&payload));
    let signature = key.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", B64.encode(signature.to_bytes()))
}

fn encode(value: &Value) -> String {
    B64.encode(value.to_string())
}

/// Checks tokens against a set of public keys.
#[derive(Debug, Clone)]
pub struct Verifier {
    keys: HashMap<String, VerifyingKey>,
    config: TokenConfig,
}

fn reject(reason: &str) -> Error {
    Error::unauthenticated().with_source(reason.to_owned())
}

impl Verifier {
    pub fn new(config: TokenConfig) -> Self {
        Self {
            keys: HashMap::new(),
            config,
        }
    }

    /// Trust a public key under `kid`.
    pub fn add_key(&mut self, kid: impl Into<String>, key: VerifyingKey) {
        self.keys.insert(kid.into(), key);
    }

    /// Stop trusting a key, for example after rotation overlap ends.
    pub fn remove_key(&mut self, kid: &str) {
        self.keys.remove(kid);
    }

    /// Verify `token` at time `now` (seconds since the epoch) and return the caller.
    pub fn verify(&self, token: &str, now: i64) -> Result<Principal> {
        if token.len() > MAX_TOKEN_BYTES {
            return Err(reject("token too long"));
        }
        let mut parts = token.split('.');
        let (Some(h), Some(p), Some(s), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(reject("not three parts"));
        };

        let header = decode_json(h).ok_or_else(|| reject("bad header"))?;
        if header.get("alg").and_then(Value::as_str) != Some("EdDSA") {
            return Err(reject("algorithm is not EdDSA"));
        }
        let kid = header
            .get("kid")
            .and_then(Value::as_str)
            .ok_or_else(|| reject("no kid"))?;
        let key = self.keys.get(kid).ok_or_else(|| reject("unknown kid"))?;

        let sig_bytes = B64
            .decode(s)
            .map_err(|_| reject("bad signature encoding"))?;
        let signature =
            Signature::from_slice(&sig_bytes).map_err(|_| reject("bad signature length"))?;
        key.verify_strict(format!("{h}.{p}").as_bytes(), &signature)
            .map_err(|_| reject("signature does not match"))?;

        let claims = decode_json(p).ok_or_else(|| reject("bad payload"))?;
        self.check_claims(&claims, now)
    }

    fn check_claims(&self, claims: &Value, now: i64) -> Result<Principal> {
        let text = |name: &str| claims.get(name).and_then(Value::as_str);
        let number = |name: &str| claims.get(name).and_then(Value::as_i64);

        if text("iss") != Some(self.config.issuer.as_str()) {
            return Err(reject("wrong issuer"));
        }
        if text("aud") != Some(self.config.audience.as_str()) {
            return Err(reject("wrong audience"));
        }
        let exp = number("exp").ok_or_else(|| reject("no exp"))?;
        if now > exp.saturating_add(self.config.leeway_secs) {
            return Err(reject("expired"));
        }
        if let Some(nbf) = number("nbf")
            && now.saturating_add(self.config.leeway_secs) < nbf
        {
            return Err(reject("not yet valid"));
        }
        let subject = text("sub")
            .filter(|s| !s.is_empty())
            .ok_or_else(|| reject("no subject"))?;
        let roles = match claims.get("roles") {
            None => Vec::new(),
            Some(Value::Array(items)) => items
                .iter()
                .map(|v| v.as_str().map(str::to_owned))
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| reject("roles must be strings"))?,
            Some(_) => return Err(reject("roles must be a list")),
        };
        Ok(Principal {
            subject: subject.to_owned(),
            tenant: text("tenant").map(str::to_owned),
            roles,
        })
    }

    /// The trusted keys as a JSON Web Key Set, for publishing.
    pub fn jwks(&self) -> Value {
        let mut keys: Vec<(&String, &VerifyingKey)> = self.keys.iter().collect();
        keys.sort_by(|a, b| a.0.cmp(b.0));
        json!({ "keys": keys.iter().map(|(kid, k)| json!({
            "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig",
            "kid": kid, "x": B64.encode(k.as_bytes()),
        })).collect::<Vec<_>>() })
    }
}

fn decode_json(part: &str) -> Option<Value> {
    let bytes = B64.decode(part).ok()?;
    let value: Value = serde_json::from_slice(&bytes).ok()?;
    value.is_object().then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use falak_contracts::ErrorKind;

    fn config() -> TokenConfig {
        TokenConfig {
            issuer: "falak-local".into(),
            audience: "notebook".into(),
            leeway_secs: 30,
        }
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn claims(now: i64) -> Claims {
        Claims {
            subject: "u1".into(),
            tenant: Some("t1".into()),
            roles: vec!["admin".into()],
            issued_at: now,
            expires_at: now + 900,
            token_id: "j1".into(),
        }
    }

    fn verifier() -> Verifier {
        let mut v = Verifier::new(config());
        v.add_key("k1", key(1).verifying_key());
        v
    }

    #[test]
    fn round_trip() {
        let t = issue(&key(1), "k1", &config(), &claims(1000));
        let p = verifier().verify(&t, 1100).unwrap();
        assert_eq!(p.subject, "u1");
        assert_eq!(p.tenant.as_deref(), Some("t1"));
        assert_eq!(p.roles, ["admin"]);
    }

    #[test]
    fn expired_and_premature_tokens_fail() {
        let t = issue(&key(1), "k1", &config(), &claims(1000));
        assert!(verifier().verify(&t, 1000 + 900 + 31).is_err());
        assert!(verifier().verify(&t, 1000 + 900 + 29).is_ok());
        assert!(verifier().verify(&t, 1000 - 31).is_err());
    }

    #[test]
    fn wrong_key_audience_and_issuer_fail() {
        let t = issue(&key(2), "k1", &config(), &claims(1000));
        assert!(
            verifier().verify(&t, 1100).is_err(),
            "signed by another key"
        );

        let mut other = config();
        other.audience = "other-app".into();
        let t = issue(&key(1), "k1", &other, &claims(1000));
        assert!(verifier().verify(&t, 1100).is_err(), "wrong audience");

        let mut other = config();
        other.issuer = "someone".into();
        let t = issue(&key(1), "k1", &other, &claims(1000));
        assert!(verifier().verify(&t, 1100).is_err(), "wrong issuer");
    }

    #[test]
    fn unknown_kid_fails() {
        let t = issue(&key(1), "nope", &config(), &claims(1000));
        assert!(verifier().verify(&t, 1100).is_err());
    }

    #[test]
    fn tampered_payload_fails() {
        let t = issue(&key(1), "k1", &config(), &claims(1000));
        let mut parts: Vec<&str> = t.split('.').collect();
        let evil = encode(&json!({
            "iss": "falak-local", "aud": "notebook", "sub": "someone-else",
            "nbf": 1000, "exp": 5000, "roles": ["admin"],
        }));
        parts[1] = &evil;
        assert!(verifier().verify(&parts.join("."), 1100).is_err());
    }

    #[test]
    fn algorithm_is_never_taken_from_the_token() {
        let t = issue(&key(1), "k1", &config(), &claims(1000));
        let rest = t.split_once('.').unwrap().1;
        for alg in ["none", "HS256", "RS256", "eddsa"] {
            let header = encode(&json!({ "alg": alg, "kid": "k1" }));
            assert!(
                verifier()
                    .verify(&format!("{header}.{rest}"), 1100)
                    .is_err(),
                "{alg}"
            );
        }
        // An unsigned token in the `none` style.
        let header = encode(&json!({ "alg": "none", "kid": "k1" }));
        let payload = t.split('.').nth(1).unwrap();
        assert!(
            verifier()
                .verify(&format!("{header}.{payload}."), 1100)
                .is_err()
        );
    }

    #[test]
    fn junk_never_panics_and_all_failures_look_the_same() {
        let long = "a".repeat(MAX_TOKEN_BYTES + 1);
        for junk in ["", ".", "..", "a.b.c", "a.b.c.d", "é.é.é", long.as_str()] {
            let e = verifier().verify(junk, 1).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Unauthenticated);
            assert_eq!(
                e.to_string(),
                "unauthenticated: Authentication is required."
            );
        }
    }

    #[test]
    fn jwks_lists_keys_in_order() {
        let mut v = verifier();
        v.add_key("a0", key(3).verifying_key());
        let jwks = v.jwks();
        assert_eq!(jwks["keys"][0]["kid"], "a0");
        assert_eq!(jwks["keys"][1]["kid"], "k1");
        assert_eq!(jwks["keys"][0]["crv"], "Ed25519");
    }

    #[test]
    fn removed_key_no_longer_verifies() {
        let mut v = verifier();
        let t = issue(&key(1), "k1", &config(), &claims(1000));
        assert!(v.verify(&t, 1100).is_ok());
        v.remove_key("k1");
        assert!(v.verify(&t, 1100).is_err());
    }
}
