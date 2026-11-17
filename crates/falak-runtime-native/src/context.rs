//! Request context and principal extraction.

use axum::http::HeaderMap;
use falak_auth::token::Verifier;
use falak_contracts::{
    identity::{Principal, RequestContext},
    support::Clock,
};
use falak_core::sql::Scope;

/// Longest caller-supplied request id kept. The id is echoed in responses, written to
/// logs and stored with events, so it is bounded and limited to plain characters.
const MAX_REQUEST_ID: usize = 128;

/// Extract or generate a request ID from headers. A caller's own id is used only if it is
/// short and made of letters, digits and `-_.:`; anything else gets a fresh id.
pub fn extract_request_id(headers: &HeaderMap) -> String {
    if let Some(val) = headers.get("x-request-id")
        && let Ok(s) = val.to_str()
        && !s.trim().is_empty()
        && s.trim().len() <= MAX_REQUEST_ID
        && s.trim()
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
    {
        s.trim().to_string()
    } else {
        format!(
            "req_{}",
            &falak_core::values::format_uuid(&generate_uuid())[..12]
        )
    }
}

/// Turns a request's credentials into the verified caller.
///
/// This is the only place a [`Principal`] comes from. Handlers never read an identity
/// from a header, query string or body.
pub trait Authenticator: Send + Sync + 'static {
    /// The caller, or `None` if there is no valid credential. The caller sends 401.
    fn authenticate(&self, headers: &HeaderMap) -> Option<Principal>;
}

/// The bearer token in the `Authorization` header: exactly one header, scheme `Bearer`
/// (any case), one non-empty token with no spaces.
pub fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all("authorization").iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    let (scheme, token) = value.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer")
        && !token.is_empty()
        && !token.contains(char::is_whitespace))
    .then_some(token)
}

/// Verifies signed access tokens (T1.14). Anything that does not verify is anonymous.
pub struct TokenAuthenticator<C> {
    verifier: Verifier,
    clock: C,
}

impl<C: Clock> TokenAuthenticator<C> {
    pub fn new(verifier: Verifier, clock: C) -> Self {
        Self { verifier, clock }
    }
}

impl<C: Clock + Send + Sync + 'static> Authenticator for TokenAuthenticator<C> {
    fn authenticate(&self, headers: &HeaderMap) -> Option<Principal> {
        let token = bearer_token(headers)?;
        self.verifier
            .verify(token, self.clock.now_micros() / 1_000_000)
            .ok()
    }
}

/// **Tests only.** Treats the bearer value as the subject, with no verification:
/// `Bearer <subject>` or `Bearer sub:<subject>,role:<role>`. Compiled only with the
/// `dev-auth` feature, which no binary enables.
#[cfg(feature = "dev-auth")]
pub struct DevAuthenticator;

#[cfg(feature = "dev-auth")]
impl Authenticator for DevAuthenticator {
    fn authenticate(&self, headers: &HeaderMap) -> Option<Principal> {
        let token = bearer_token(headers)?;
        if let Some(sub) = token.strip_prefix("sub:") {
            let mut parts = sub.split(',');
            let subject = parts.next().unwrap_or(token).to_string();
            let roles = parts
                .filter_map(|p| p.strip_prefix("role:"))
                .map(str::to_string)
                .collect();
            return Some(Principal {
                subject,
                tenant: None,
                roles,
            });
        }
        Some(Principal {
            subject: token.to_string(),
            tenant: None,
            roles: vec![],
        })
    }
}

pub fn make_context(request_id: String, principal: Option<Principal>) -> RequestContext {
    RequestContext {
        principal,
        request_id,
    }
}

pub fn make_scope(principal: Option<&Principal>) -> Scope {
    Scope {
        tenant: principal.and_then(|p| p.tenant.clone()),
        subject: principal.map(|p| p.subject.clone()),
    }
}

fn generate_uuid() -> [u8; 16] {
    use falak_contracts::support::IdGenerator;
    falak_auth::system::RandomIds.new_id()
}
