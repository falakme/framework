//! Sign in through any OpenID Connect provider (Clerk, Auth0, Keycloak, Zitadel, Google,
//! Entra, ...).
//!
//! Office does not run a login screen, keep passkeys or do multi-factor. The provider and
//! its SDK do that. The person signs in there, the front end hands Office the ID token,
//! and Office checks it against the provider's published keys and gives back its own
//! session (`POST /v1/auth/oidc/exchange`). Everything after that (per-app tokens,
//! revocation, key rotation) is unchanged.

use std::sync::RwLock;

use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode, decode_header,
    jwk::{Jwk, JwkSet},
};
use serde::Deserialize;
use serde_json::Value;

/// Refresh the provider's key set at least this often.
const KEY_SET_TTL_SECS: i64 = 600;
/// A token with an unknown `kid` fetches the key set, but not more often than this.
const UNKNOWN_KEY_COOLDOWN_SECS: i64 = 10;
/// Only asymmetric algorithms. `none` and shared-secret algorithms are never accepted.
const ALGORITHMS: [Algorithm; 5] = [
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::ES256,
    Algorithm::EdDSA,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcConfig {
    /// The provider's issuer URL (its `iss`). Discovery is `<issuer>/.well-known/openid-configuration`.
    pub issuer: String,
    /// What this Office is to the provider: the token's `aud` (or `azp`) must be this.
    pub audience: String,
    /// Email domains whose people get an Office account on first sign-in. Empty: only
    /// people an administrator already made can sign in.
    pub auto_create_domains: Vec<String>,
    /// Accept a token whose provider does not say the email is verified. Off by default.
    pub trust_unverified_email: bool,
}

impl OidcConfig {
    /// `FALAK_OIDC_ISSUER`, `FALAK_OIDC_AUDIENCE`, and optionally
    /// `FALAK_OIDC_AUTO_CREATE` (comma separated email domains) and
    /// `FALAK_OIDC_TRUST_UNVERIFIED_EMAIL=1`. `None` when no issuer is set.
    pub fn from_env() -> Result<Option<Self>, String> {
        let Ok(issuer) = std::env::var("FALAK_OIDC_ISSUER") else {
            return Ok(None);
        };
        let audience = std::env::var("FALAK_OIDC_AUDIENCE")
            .map_err(|_| "`FALAK_OIDC_AUDIENCE` is required with `FALAK_OIDC_ISSUER`")?;
        let cfg = Self {
            issuer: issuer.trim_end_matches('/').to_owned(),
            audience,
            auto_create_domains: std::env::var("FALAK_OIDC_AUTO_CREATE")
                .unwrap_or_default()
                .split(',')
                .map(|d| d.trim().to_lowercase())
                .filter(|d| !d.is_empty())
                .collect(),
            trust_unverified_email: std::env::var("FALAK_OIDC_TRUST_UNVERIFIED_EMAIL")
                .is_ok_and(|v| v == "1"),
        };
        cfg.validate()?;
        Ok(Some(cfg))
    }

    pub fn validate(&self) -> Result<(), String> {
        if !trusted_url(&self.issuer) {
            return Err(format!(
                "`{}` must be https (or http to this machine)",
                self.issuer
            ));
        }
        if self.audience.is_empty() {
            return Err("the OIDC audience is empty".into());
        }
        Ok(())
    }
}

/// `https`, or `http` to this machine for development.
pub fn trusted_url(url: &str) -> bool {
    url.starts_with("https://")
        || ["http://127.0.0.1", "http://localhost", "http://[::1]"]
            .iter()
            .any(|p| {
                // What follows the host must be a port and then a path: `@` (user
                // information, which would name a different host), `\\` and the like fail.
                url.strip_prefix(p).is_some_and(|rest| {
                    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
                    authority.is_empty()
                        || authority
                            .strip_prefix(':')
                            .is_some_and(|port| port.bytes().all(|b| b.is_ascii_digit()))
                })
            })
}

/// Who the provider says this is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalIdentity {
    pub issuer: String,
    pub subject: String,
    pub email: String,
    /// When the person last signed in at the provider, if it says (`auth_time`).
    pub auth_time: Option<i64>,
}

struct Keys {
    set: JwkSet,
    fetched_at: Option<i64>,
    /// When a fetch was last handed out, whether or not it worked.
    attempted_at: Option<i64>,
}

pub struct Oidc {
    pub config: OidcConfig,
    keys: RwLock<Keys>,
}

#[derive(Deserialize)]
struct Claims {
    sub: String,
    email: Option<String>,
    email_verified: Option<Value>,
    aud: Option<Value>,
    azp: Option<String>,
    auth_time: Option<i64>,
}

impl Oidc {
    pub fn new(config: OidcConfig) -> Self {
        Self {
            config,
            keys: RwLock::new(Keys {
                set: JwkSet { keys: vec![] },
                fetched_at: None,
                attempted_at: None,
            }),
        }
    }

    /// Whether the key set should be fetched before this token is checked: never loaded
    /// or old, or the token names a key not in the set (and the last fetch was not
    /// just now). A `true` hands out the fetch: the next caller gets `false` until the
    /// cooldown has passed, even if the provider is down and nothing was loaded, so the
    /// public exchange route cannot be used to start a fetch per request.
    pub fn wants_refresh(&self, token: &str, now: i64) -> bool {
        let kid = decode_header(token).ok().and_then(|h| h.kid);
        let mut k = self.keys.write().unwrap_or_else(|p| p.into_inner());
        let due = match k.fetched_at {
            None => true,
            Some(t) if now - t >= KEY_SET_TTL_SECS => true,
            Some(t) => {
                let known = match kid.as_deref() {
                    Some(kid) => k
                        .set
                        .keys
                        .iter()
                        .any(|j| j.common.key_id.as_deref() == Some(kid)),
                    None => k.set.keys.len() == 1,
                };
                !known && now - t >= UNKNOWN_KEY_COOLDOWN_SECS
            }
        };
        if !due
            || k.attempted_at
                .is_some_and(|a| (0..UNKNOWN_KEY_COOLDOWN_SECS).contains(&(now - a)))
        {
            return false;
        }
        k.attempted_at = Some(now);
        true
    }

    /// Replace the key set. A document with no usable key leaves the old set alone.
    pub fn load_jwks(&self, text: &str, now: i64) -> Result<(), String> {
        let set: JwkSet =
            serde_json::from_str(text).map_err(|_| "the provider's key set is not valid")?;
        if set.keys.is_empty() {
            return Err("the provider's key set is empty".into());
        }
        let mut k = self.keys.write().unwrap_or_else(|p| p.into_inner());
        k.set = set;
        k.fetched_at = Some(now);
        Ok(())
    }

    /// Discovery, then the key set. Blocking: call from a blocking task.
    pub fn refresh_blocking(&self, now: i64) -> Result<(), String> {
        // No redirects: a provider (or whoever sits in front of it) must not be able to
        // move the key fetch to a plain http or internal address after the checks above.
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(std::time::Duration::from_secs(10)))
            .max_redirects(0)
            .build()
            .into();
        let doc: Value = agent
            .get(&format!(
                "{}/.well-known/openid-configuration",
                self.config.issuer
            ))
            .call()
            .map_err(|e| format!("cannot reach the identity provider: {e}"))?
            .body_mut()
            .read_json()
            .map_err(|e| e.to_string())?;
        // The document must name the issuer we were told to trust (OIDC Discovery §4.3).
        if doc["issuer"].as_str().map(|s| s.trim_end_matches('/')) != Some(&self.config.issuer) {
            return Err("the provider's discovery document names a different issuer".into());
        }
        let jwks_uri = doc["jwks_uri"]
            .as_str()
            .ok_or("discovery has no jwks_uri")?;
        if !trusted_url(jwks_uri) {
            return Err("the provider's key set is not served over https".into());
        }
        let text = agent
            .get(jwks_uri)
            .call()
            .map_err(|e| format!("cannot fetch the provider's key set: {e}"))?
            .body_mut()
            .read_to_string()
            .map_err(|e| e.to_string())?;
        self.load_jwks(&text, now)
    }

    fn key_for(&self, kid: Option<&str>) -> Option<Jwk> {
        let k = self.keys.read().unwrap_or_else(|p| p.into_inner());
        match kid {
            Some(kid) => k
                .set
                .keys
                .iter()
                .find(|j| j.common.key_id.as_deref() == Some(kid))
                .cloned(),
            None if k.set.keys.len() == 1 => k.set.keys.first().cloned(),
            None => None,
        }
    }

    /// Check an ID token. The refusal text is for logs only: the caller answers `401`
    /// with the same words every time.
    pub fn verify(&self, token: &str) -> Result<ExternalIdentity, String> {
        let header = decode_header(token).map_err(|_| "not a JWT")?;
        if !ALGORITHMS.contains(&header.alg) {
            return Err("algorithm not accepted".into());
        }
        let jwk = self
            .key_for(header.kid.as_deref())
            .ok_or("the token's key is not in the provider's key set")?;
        let key = DecodingKey::from_jwk(&jwk).map_err(|_| "unusable key")?;
        let mut v = Validation::new(header.alg);
        v.set_issuer(&[self.config.issuer.as_str()]);
        v.set_required_spec_claims(&["exp", "iss", "sub"]);
        v.validate_nbf = true;
        v.validate_aud = false; // checked below: some providers send `azp` and no `aud`
        v.leeway = 30;
        let claims = decode::<Claims>(token, &key, &v)
            .map_err(|e| format!("token refused: {:?}", e.kind()))?
            .claims;

        let aud_ok = match &claims.aud {
            Some(Value::String(s)) => *s == self.config.audience,
            Some(Value::Array(a)) => a.iter().any(|x| x.as_str() == Some(&self.config.audience)),
            _ => false,
        } || claims.azp.as_deref() == Some(&self.config.audience);
        if !aud_ok {
            return Err("the token is for a different audience".into());
        }
        let verified = match &claims.email_verified {
            Some(Value::Bool(b)) => *b,
            Some(Value::String(s)) => s == "true",
            _ => self.config.trust_unverified_email,
        };
        if !verified {
            return Err("the provider does not vouch for the email".into());
        }
        let email = claims
            .email
            .map(|e| e.trim().to_lowercase())
            .filter(|e| e.contains('@'))
            .ok_or("the token carries no email")?;
        Ok(ExternalIdentity {
            issuer: self.config.issuer.clone(),
            subject: claims.sub,
            email,
            auth_time: claims.auth_time,
        })
    }

    /// Whether this email may get an account on first sign-in.
    pub fn may_create(&self, email: &str) -> bool {
        email
            .rsplit_once('@')
            .is_some_and(|(_, d)| self.config.auto_create_domains.iter().any(|a| a == d))
    }
}
