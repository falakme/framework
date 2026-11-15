//! Callers and identity verification.

use crate::Result;

/// How much assurance an app requires. See ARCHITECTURE §4.6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustTier {
    Standard = 1,
    Sensitive = 2,
    HighAssurance = 3,
}

/// A verified caller. Built only from a verified token and a server-side membership
/// check; never from a header, query string or body supplied by the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub subject: String,
    pub tenant: Option<String>,
    pub roles: Vec<String>,
}

/// Per-request context passed to storage so the driver can apply isolation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestContext {
    /// `None` for an anonymous request. Policies treat `None` as default deny.
    pub principal: Option<Principal>,
    pub request_id: String,
}

/// Verifies bearer tokens and produces a [`Principal`].
pub trait IdentityProvider {
    /// Verify a bearer token for this app's audience. Fails with `Unauthenticated`.
    async fn verify(&self, bearer_token: &str) -> Result<Principal>;
}
