//! Local identity (T1.12): sign-up, login, rate-limited attempts, revocable sessions
//! and single-use password resets for standalone apps.
//!
//! * **Passwords** are Argon2id hashes. A login for an unknown email spends the same
//!   time as a real one, and both failures return the same error.
//! * **Rate limit:** after [`Policy::max_failures`] failed logins for one email inside
//!   [`Policy::window_secs`], further attempts are refused with `RateLimited`, even
//!   with the right password, until the window passes. This also lets an attacker lock
//!   out a known email for that window; the window is kept short to bound the harm.
//! * **Sessions** are random 256-bit refresh tokens stored as SHA-256 hashes. Refresh
//!   rotates the token. Presenting an already-rotated token means it leaked, so every
//!   session of that user ends.
//! * **Access tokens** are short-lived Ed25519 tokens (see [`crate::token`]). Revoking a
//!   session stops new access tokens at once; one already issued works until it
//!   expires, which is why the lifetime is short.
//! * **Reset tokens** are single use and expire. Using one ends every session.

use falak_contracts::{
    Error, ErrorKind, Result,
    identity::{IdentityProvider, Principal},
    support::{Clock, IdGenerator},
};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

use crate::{
    keys::LocalKeys,
    password::{hash_password, validate_password, verify_against_dummy, verify_password},
    store::{AuthStore, Revoked, SessionRecord, UserRecord},
    token::{Claims, TokenConfig, Verifier, issue},
};

/// Tunable limits. The defaults are the recommended values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub max_failures: u32,
    pub window_secs: i64,
    pub access_ttl_secs: i64,
    pub session_ttl_secs: i64,
    pub reset_ttl_secs: i64,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            max_failures: 5,
            window_secs: 15 * 60,
            access_ttl_secs: 15 * 60,
            session_ttl_secs: 30 * 24 * 60 * 60,
            reset_ttl_secs: 60 * 60,
        }
    }
}

/// What a successful login or refresh returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tokens {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
}

pub struct LocalIdentity<S, C, G> {
    store: S,
    keys: LocalKeys,
    verifier: Verifier,
    config: TokenConfig,
    policy: Policy,
    clock: C,
    ids: G,
    per_user_tenants: bool,
}

/// The tenant of a user in an app with tenancy and local identity: a workspace of one,
/// named by a hash of the user id. It is computed by the server and is the same every
/// time. A tenant shared by several people needs membership, which Office provides.
pub fn tenant_of(user_id: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"falak-tenant\0");
    h.update(user_id.as_bytes());
    let d = h.finalize();
    let mut b = [0u8; 16];
    b.copy_from_slice(&d[..16]);
    b[6] = (b[6] & 0x0f) | 0x50;
    b[8] = (b[8] & 0x3f) | 0x80;
    uuid_string(b)
}

fn invalid_credentials() -> Error {
    Error::new(
        ErrorKind::Unauthenticated,
        "invalid_credentials",
        "The email or password is not correct.",
    )
}

fn too_many_attempts() -> Error {
    Error::new(
        ErrorKind::RateLimited,
        "too_many_attempts",
        "Too many failed attempts. Try again later.",
    )
}

/// Lowercase and trim an email, and check its shape. Not a full RFC 5322 check; the
/// address is proven by delivering a mail to it, not by parsing.
pub fn normalize_email(raw: &str) -> Result<String> {
    let email = raw.trim().to_lowercase();
    let ok = email.len() <= 254
        && email.chars().all(|c| !c.is_control() && !c.is_whitespace())
        && email.split_once('@').is_some_and(|(l, d)| {
            !l.is_empty()
                && d.contains('.')
                && !d.starts_with('.')
                && !d.ends_with('.')
                && !d.contains('@')
        });
    if ok {
        Ok(email)
    } else {
        Err(Error::invalid_input(
            "invalid_email",
            "Enter a valid email address.",
        ))
    }
}

fn random_token() -> String {
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    hex(&b)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hash_token(token: &str) -> String {
    hex(&Sha256::digest(token.as_bytes()))
}

/// A UUID string (lowercase, hyphenated) from 16 bytes.
pub fn uuid_string(b: [u8; 16]) -> String {
    let h = hex(&b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

impl<S: AuthStore, C: Clock, G: IdGenerator> LocalIdentity<S, C, G> {
    pub fn new(
        store: S,
        keys: LocalKeys,
        config: TokenConfig,
        policy: Policy,
        clock: C,
        ids: G,
    ) -> Self {
        let mut verifier = Verifier::new(config.clone());
        keys.trust_all(&mut verifier);
        Self {
            store,
            keys,
            verifier,
            config,
            policy,
            clock,
            ids,
            per_user_tenants: false,
        }
    }

    /// Put each user in a tenant of their own (see [`tenant_of`]). Use for apps whose
    /// `tenancy` is `row` or `database`.
    #[must_use]
    pub fn with_per_user_tenants(mut self) -> Self {
        self.per_user_tenants = true;
        self
    }

    fn now(&self) -> i64 {
        self.clock.now_micros() / 1_000_000
    }

    /// Create an account. Returns its id.
    pub async fn signup(&self, email: &str, password: &str) -> Result<String> {
        let email = normalize_email(email)?;
        validate_password(password)?;
        let id = uuid_string(self.ids.new_id());
        self.store
            .create_user(
                UserRecord {
                    id: id.clone(),
                    email,
                    password_hash: hash_password(password)?,
                    roles: vec![],
                },
                self.now(),
            )
            .await?;
        Ok(id)
    }

    /// Give a user a set of roles (replaces the old set). For setup and admin tools.
    pub async fn set_roles(&self, user_id: &str, roles: &[String]) -> Result<()> {
        self.store.set_roles(user_id, roles).await
    }

    pub async fn login(&self, email: &str, password: &str) -> Result<Tokens> {
        // A malformed email cannot be an account; treat it like a wrong password.
        let Ok(email) = normalize_email(email) else {
            verify_against_dummy(password);
            return Err(invalid_credentials());
        };
        let now = self.now();
        let failures = self
            .store
            .failures_since(&email, now - self.policy.window_secs)
            .await?;
        if failures >= self.policy.max_failures {
            return Err(too_many_attempts());
        }

        let user = self.store.user_by_email(&email).await?;
        let ok = match &user {
            Some(u) => verify_password(&u.password_hash, password),
            None => {
                verify_against_dummy(password);
                false
            }
        };
        let Some(user) = user.filter(|_| ok) else {
            self.store.record_failure(&email, now).await?;
            return Err(invalid_credentials());
        };
        self.store.clear_failures(&email).await?;
        self.start_session(&user).await
    }

    async fn start_session(&self, user: &UserRecord) -> Result<Tokens> {
        let now = self.now();
        let refresh_token = random_token();
        self.store
            .create_session(SessionRecord {
                id: uuid_string(self.ids.new_id()),
                user_id: user.id.clone(),
                token_hash: hash_token(&refresh_token),
                expires_at: now + self.policy.session_ttl_secs,
                revoked: None,
            })
            .await?;
        let (kid, key) = self.keys.active();
        let access_token = issue(
            key,
            kid,
            &self.config,
            &Claims {
                subject: user.id.clone(),
                tenant: self.per_user_tenants.then(|| tenant_of(&user.id)),
                roles: user.roles.clone(),
                issued_at: now,
                expires_at: now + self.policy.access_ttl_secs,
                token_id: uuid_string(self.ids.new_id()),
            },
        );
        Ok(Tokens {
            access_token,
            refresh_token,
            expires_in: self.policy.access_ttl_secs,
        })
    }

    /// Exchange a refresh token for new tokens. The old refresh token stops working.
    pub async fn refresh(&self, refresh_token: &str) -> Result<Tokens> {
        let now = self.now();
        let session = self
            .store
            .session_by_hash(&hash_token(refresh_token))
            .await?
            .ok_or_else(Error::unauthenticated)?;
        match session.revoked {
            Some(Revoked::Rotated) => {
                // A rotated token came back: someone kept a copy. End everything.
                self.store.revoke_all_sessions(&session.user_id).await?;
                return Err(Error::unauthenticated());
            }
            Some(Revoked::Ended) => return Err(Error::unauthenticated()),
            None => {}
        }
        if session.expires_at <= now {
            return Err(Error::unauthenticated());
        }
        let user = self
            .store
            .user_by_id(&session.user_id)
            .await?
            .ok_or_else(Error::unauthenticated)?;
        self.store
            .revoke_session(&session.id, Revoked::Rotated)
            .await?;
        self.start_session(&user).await
    }

    /// End the session behind a refresh token. Unknown tokens are ignored.
    pub async fn logout(&self, refresh_token: &str) -> Result<()> {
        if let Some(s) = self
            .store
            .session_by_hash(&hash_token(refresh_token))
            .await?
        {
            self.store.revoke_session(&s.id, Revoked::Ended).await?;
        }
        Ok(())
    }

    /// Start a password reset. Returns the token to deliver to the address, or `None`
    /// if no such account exists. The caller must give the same answer either way.
    pub async fn request_reset(&self, email: &str) -> Result<Option<String>> {
        let Ok(email) = normalize_email(email) else {
            return Ok(None);
        };
        let Some(user) = self.store.user_by_email(&email).await? else {
            return Ok(None);
        };
        let token = random_token();
        self.store
            .create_reset(
                &hash_token(&token),
                &user.id,
                self.now() + self.policy.reset_ttl_secs,
            )
            .await?;
        Ok(Some(token))
    }

    /// Set a new password with a reset token. The token works once. Every session of
    /// the user ends, and the failed-login count is cleared.
    pub async fn reset_password(&self, token: &str, new_password: &str) -> Result<()> {
        validate_password(new_password)?;
        let invalid = || {
            Error::new(
                ErrorKind::InvalidInput,
                "invalid_reset_token",
                "This reset link is not valid or has expired.",
            )
        };
        let user_id = self
            .store
            .consume_reset(&hash_token(token), self.now())
            .await?
            .ok_or_else(invalid)?;
        let user = self.store.user_by_id(&user_id).await?.ok_or_else(invalid)?;
        self.store
            .set_password_hash(&user_id, &hash_password(new_password)?)
            .await?;
        self.store.revoke_all_sessions(&user_id).await?;
        self.store.clear_failures(&user.email).await?;
        Ok(())
    }

    /// The keys, for publishing a key set or rotating.
    pub fn verifier(&self) -> &Verifier {
        &self.verifier
    }
}

impl<S: AuthStore, C: Clock, G: IdGenerator> IdentityProvider for LocalIdentity<S, C, G> {
    async fn verify(&self, bearer_token: &str) -> Result<Principal> {
        self.verifier.verify(bearer_token, self.now())
    }
}
