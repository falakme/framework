//! The AI egress policy (T7.10): what may leave the app for an AI model, and where to.
//!
//! 1. **Where.** A model provider is reachable only if the operator listed its host
//!    (`FALAK_AI_ALLOW`, comma separated). The check is `falak-egress`'s: `https` only, no
//!    credentials in the URL, and no private, loopback or metadata address after DNS.
//! 2. **What.** Fields marked `pii: true` never leave as they are. Rows bound for a model
//!    pass through [`AiPolicy::redact`], which replaces those fields with stable tokens
//!    (`falak_core::pseudonymize`). Text that is about to be sent can be checked against the
//!    originals it must not contain with [`guard_text`].
//!
//! The operator can switch redaction off for a deployment (`expose_pii`), and that is the
//! only way PII reaches a model.

use falak_contracts::{Error, ErrorKind, Result, ir::Ir};
use falak_core::pseudonymize::{Mapping, Pseudonymizer, leaks};
use falak_egress::{Entry, Permit, Policy, Resolver};
use serde_json::Value;

#[derive(Debug, Clone, Default)]
pub struct AiPolicy {
    providers: Policy,
    /// Let PII fields through unredacted. Off unless the operator turns it on.
    pub expose_pii: bool,
}

impl AiPolicy {
    /// Entries that do not parse are dropped: a typo permits nothing.
    pub fn new(hosts: &[String]) -> Self {
        Self {
            providers: Policy::new(hosts.iter().filter_map(|h| Entry::parse(h).ok()).collect()),
            expose_pii: false,
        }
    }

    /// `FALAK_AI_ALLOW=api.anthropic.com,*.example.com`. Unset allows no provider.
    pub fn from_env() -> Self {
        let list = std::env::var("FALAK_AI_ALLOW").unwrap_or_default();
        let hosts: Vec<String> = list
            .split(',')
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .collect();
        Self::new(&hosts)
    }

    /// May the app call this URL as an AI provider? On success, connect to the returned
    /// addresses and do not resolve the name again.
    pub fn check_url(&self, url: &str, resolver: &impl Resolver) -> Result<Permit> {
        self.providers.check(url, resolver)
    }

    /// Replace the `pii: true` fields of a response body bound for a model. `body` is a
    /// runtime response: `{"data": {...}}` or `{"data": [{...}, ...]}`. Returns what was
    /// replaced, to keep or drop.
    pub fn redact(&self, ir: &Ir, entity: &str, body: &mut Value, ps: &Pseudonymizer) -> Mapping {
        let mut all = Mapping::new();
        let Some(e) = ir.entity(entity) else {
            return all;
        };
        if self.expose_pii {
            return all;
        }
        // A list or wrapped row has `data`; a single read is a bare row.
        let wrapped = matches!(body.get("data"), Some(Value::Array(_) | Value::Object(_)));
        let mut rows: Vec<&mut Value> = Vec::new();
        if wrapped {
            match body.get_mut("data") {
                Some(Value::Array(a)) => rows.extend(a.iter_mut()),
                Some(v) => rows.push(v),
                None => {}
            }
        } else if body.is_object() {
            rows.push(body);
        }
        for row in rows {
            if let Some(obj) = row.as_object_mut() {
                all.extend(ps.apply_row(e, obj));
            }
        }
        all
    }
}

/// Refuse text that still holds an original value it must not carry.
pub fn guard_text(text: &str, originals: &Mapping) -> Result<()> {
    if leaks(text, originals) {
        Err(Error::new(
            ErrorKind::Forbidden,
            "ai_pii_leak",
            "The text still contains personal data and was not sent.",
        ))
    } else {
        Ok(())
    }
}
