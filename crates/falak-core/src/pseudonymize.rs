//! PII pseudonymization (T7.7). Personal data is replaced by stable tokens before it
//! leaves the trust boundary (to an AI model, a log, a third party), and put back only
//! where the policy allows.
//!
//! * A token is `KIND_<16 hex>`: HMAC-SHA256 over the tenant, the kind and the value, with a
//!   key the operator holds. The same value in the same tenant always gets the same token
//!   (so a model can still tell that two mentions are one person); the same value in
//!   another tenant gets a different one, and without the key a token cannot be linked to
//!   a value or a guess confirmed.
//! * The tokens map back to values through a [`Mapping`], which the caller stores
//!   encrypted and scoped to the tenant (Office keeps it; see `office/compute`).
//! * Fields marked `pii: true` in the schema are found with [`pii_fields`].
//!
//! No I/O and no clock: this builds for `wasm32`.

use std::collections::BTreeMap;

use falak_contracts::ir::{FieldType, IrEntity};
use serde_json::{Map, Value};

use sha2::{Digest, Sha256};

const BLOCK: usize = 64;

pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    // HMAC-SHA256 (RFC 2104) over the `sha2` the core already depends on.
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(k.map(|b| b ^ 0x36));
    inner.update(message);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(k.map(|b| b ^ 0x5c));
    outer.update(inner);
    outer.finalize().into()
}

/// A stretch of text that is personal data. `start` and `end` count characters (Unicode
/// scalar values), `end` exclusive, as Python's string indexes do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Span {
    pub kind: String,
    pub start: usize,
    pub end: usize,
}

/// Token to original value.
pub type Mapping = BTreeMap<String, String>;

pub struct Pseudonymizer {
    key: Vec<u8>,
    tenant: String,
}

/// Names of the fields marked `pii: true` that hold text, in table order.
pub fn pii_fields(entity: &IrEntity) -> Vec<&str> {
    entity
        .fields
        .iter()
        .filter(|f| f.pii && f.ty == FieldType::Text)
        .map(|f| f.name.as_str())
        .collect()
}

fn kind_label(kind: &str) -> String {
    let k: String = kind
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .take(24)
        .collect();
    if k.is_empty() { "PII".into() } else { k }
}

impl Pseudonymizer {
    /// `key` is the operator's secret (at least 16 bytes is sensible); `tenant` scopes the
    /// tokens. Use `""` for an app without tenants.
    pub fn new(key: &[u8], tenant: &str) -> Self {
        Self {
            key: key.to_vec(),
            tenant: tenant.to_owned(),
        }
    }

    pub fn token(&self, kind: &str, value: &str) -> String {
        let label = kind_label(kind);
        let mut m = Vec::new();
        for part in [self.tenant.as_str(), &label, value.trim()] {
            m.extend_from_slice(&(part.len() as u64).to_be_bytes());
            m.extend_from_slice(part.as_bytes());
        }
        let mac = hmac_sha256(&self.key, &m);
        let mut hex = String::with_capacity(16);
        for b in &mac[..8] {
            hex.push_str(&format!("{b:02x}"));
        }
        format!("{label}_{hex}")
    }

    /// Replace each span of `text` with its token. Spans that overlap an earlier span, run
    /// past the text or are empty are ignored. Returns the new text and what to store.
    pub fn apply(&self, text: &str, spans: &[Span]) -> (String, Mapping) {
        let chars: Vec<char> = text.chars().collect();
        let mut sorted: Vec<&Span> = spans
            .iter()
            .filter(|s| s.start < s.end && s.end <= chars.len())
            .collect();
        sorted.sort_by_key(|s| (s.start, std::cmp::Reverse(s.end)));
        let mut out = String::with_capacity(text.len());
        let mut mapping = Mapping::new();
        let mut at = 0;
        for s in sorted {
            if s.start < at {
                continue;
            }
            out.extend(&chars[at..s.start]);
            let original: String = chars[s.start..s.end].iter().collect();
            let token = self.token(&s.kind, &original);
            out.push_str(&token);
            mapping.insert(token, original);
            at = s.end;
        }
        out.extend(&chars[at..]);
        (out, mapping)
    }

    /// Replace every `pii: true` text field of a JSON row with a token for the whole value.
    /// Other fields are untouched. Returns what to store.
    pub fn apply_row(&self, entity: &IrEntity, row: &mut Map<String, Value>) -> Mapping {
        let mut mapping = Mapping::new();
        for name in pii_fields(entity) {
            if let Some(Value::String(v)) = row.get_mut(name) {
                if v.is_empty() {
                    continue;
                }
                let token = self.token(name, v);
                mapping.insert(token.clone(), std::mem::take(v));
                *v = token;
            }
        }
        mapping
    }
}

/// Put originals back into `text` wherever one of `mapping`'s tokens appears.
pub fn restore(text: &str, mapping: &Mapping) -> String {
    let mut out = text.to_owned();
    for (token, original) in mapping {
        out = out.replace(token.as_str(), original);
    }
    out
}

/// Whether `text` still holds any original value of `mapping`: the check before text goes
/// somewhere that must never see personal data.
pub fn leaks(text: &str, mapping: &Mapping) -> bool {
    mapping
        .values()
        .any(|original| !original.is_empty() && text.contains(original.as_str()))
}
