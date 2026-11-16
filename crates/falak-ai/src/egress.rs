//! The AI egress policy (T7.10): what may leave the app for an AI model, and where to.
//!
//! 1. **Where.** A model provider is reachable only if the operator listed its host
//!    (`FALAK_AI_ALLOW`, comma separated). The check is `falak-egress`'s: `https` only, no
//!    credentials in the URL, and no private, loopback or metadata address after DNS.
//! 2. **What.** Fields marked `pii: true`, and encrypted fields, are omitted from what an
//!    agent reads ([`AiPolicy::redact`]). The operator can allow them for a deployment
//!    (`expose_pii`), and that is the only way they reach a model.

use falak_contracts::{Result, ir::Ir};
use falak_egress::{Entry, Permit, Policy, Resolver};
use serde_json::Value;

#[derive(Debug, Clone, Default)]
pub struct AiPolicy {
    providers: Policy,
    /// Let `pii` and encrypted fields through. Off unless the operator turns it on.
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

    /// Remove the `pii: true` and encrypted fields from a response body bound for a model.
    /// `body` is a runtime response: `{"data": {...}}`, `{"data": [{...}, ...]}` or a bare row.
    pub fn redact(&self, ir: &Ir, entity: &str, body: &mut Value) {
        let Some(e) = ir.entity(entity) else {
            return;
        };
        if self.expose_pii {
            return;
        }
        let hidden: Vec<&str> = e
            .fields
            .iter()
            .filter(|f| f.pii || f.encrypted)
            .map(|f| f.name.as_str())
            .collect();
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
                for f in &hidden {
                    obj.remove(*f);
                }
            }
        }
    }
}
