//! PII scan results and the mapping table (T7.8).
//!
//! A NER job (`scan_pii`, run by a worker) reports the personal data it found as
//! `pii_entities: [{kind, start, end, original}]`. The original text must not stay in the
//! job result, which many people can read. When such a result reaches Office, each
//! `original` is replaced by a pseudonym token (`falak_core::pseudonymize`) and the
//! token-to-original mapping is stored **encrypted** (ChaCha20-Poly1305) in a table keyed by
//! tenant. The tenant comes from the job's payload, never from the result, so a job cannot
//! write into another tenant's mapping, and the ciphertext is bound to its tenant and
//! token, so a row moved between tenants no longer decrypts.
//!
//! Only an Office administrator can reveal an original, and each reveal is audited.

use std::path::Path;

use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use falak_contracts::{Error, Result, driver::Value, support::wall_clock_micros};
use falak_core::pseudonymize::{Pseudonymizer, hmac_sha256};
use serde_json::{Value as Json, json};

use crate::db::{Db, t, text};

pub const SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS pii_mappings (tenant TEXT NOT NULL, token TEXT NOT NULL, nonce TEXT NOT NULL, ciphertext TEXT NOT NULL, created_at BIGINT NOT NULL, PRIMARY KEY (tenant, token))",
];

/// The master secret for pseudonym tokens and for encrypting the mapping.
#[derive(Clone)]
pub struct PiiKey([u8; 32]);

impl PiiKey {
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    /// `FALAK_PII_KEY` (64 hex characters) if set; otherwise `pii.key` in the data
    /// directory, made on first use; otherwise a key that lives as long as the process (tests).
    pub fn load(data_dir: Option<&Path>) -> Result<Self> {
        if let Ok(h) = std::env::var("FALAK_PII_KEY") {
            let b = hex::decode(h.trim())
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .ok_or_else(|| {
                    Error::invalid_input(
                        "invalid_pii_key",
                        "FALAK_PII_KEY must be 64 hex characters.",
                    )
                })?;
            return Ok(Self(b));
        }
        let random = || {
            use rand_core::{OsRng, RngCore};
            let mut b = [0u8; 32];
            OsRng.fill_bytes(&mut b);
            b
        };
        let Some(dir) = data_dir else {
            // No data directory (tests): one key for the life of the process.
            static KEY: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
            return Ok(Self(*KEY.get_or_init(random)));
        };
        let path = dir.join("pii.key");
        if let Ok(h) = std::fs::read_to_string(&path)
            && let Some(b) = hex::decode(h.trim())
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
        {
            return Ok(Self(b));
        }
        let b = random();
        std::fs::create_dir_all(dir).map_err(Error::internal)?;
        std::fs::write(&path, hex::encode(b)).map_err(Error::internal)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(Self(b))
    }

    fn derive(&self, purpose: &str) -> [u8; 32] {
        hmac_sha256(&self.0, purpose.as_bytes())
    }

    fn cipher(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(Key::from_slice(&self.derive("falak-pii-encrypt")))
    }

    pub fn pseudonymizer(&self, tenant: &str) -> Pseudonymizer {
        Pseudonymizer::new(&self.derive("falak-pii-pseudonym"), tenant)
    }
}

fn aad(tenant: &str, token: &str) -> Vec<u8> {
    format!("{tenant}\u{0}{token}").into_bytes()
}

pub struct Vault<'a> {
    pub db: &'a Db,
    pub key: &'a PiiKey,
}

impl Vault<'_> {
    pub async fn store(&self, tenant: &str, token: &str, original: &str) -> Result<()> {
        use rand_core::{OsRng, RngCore};
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let ct = self
            .key
            .cipher()
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: original.as_bytes(),
                    aad: &aad(tenant, token),
                },
            )
            .map_err(|_| Error::internal("encryption failed".to_owned()))?;
        // The same value in the same tenant has the same token: keep the first row.
        self.db
            .run(
                "INSERT INTO pii_mappings (tenant, token, nonce, ciphertext, created_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT (tenant, token) DO NOTHING",
                vec![
                    t(tenant),
                    t(token),
                    t(&hex::encode(nonce)),
                    t(&hex::encode(ct)),
                    Value::Int64(wall_clock_micros()),
                ],
            )
            .await?;
        Ok(())
    }

    /// The original for `token` in `tenant`, or `None`.
    pub async fn reveal(&self, tenant: &str, token: &str) -> Result<Option<String>> {
        let rows = self
            .db
            .rows(
                "SELECT nonce, ciphertext FROM pii_mappings WHERE tenant = ? AND token = ?",
                vec![t(tenant), t(token)],
            )
            .await?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let nonce = hex::decode(text(row.first())).unwrap_or_default();
        let ct = hex::decode(text(row.get(1))).unwrap_or_default();
        if nonce.len() != 12 {
            return Ok(None);
        }
        let plain = self
            .key
            .cipher()
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ct,
                    aad: &aad(tenant, token),
                },
            )
            .map_err(|_| Error::internal("a stored mapping does not decrypt".to_owned()))?;
        Ok(String::from_utf8(plain).ok())
    }

    /// Replace every `original` in `result["pii_entities"]` by its token, storing the
    /// mapping. A result with no such list is returned as it is.
    pub async fn sanitize(&self, tenant: &str, mut result: Json) -> Result<Json> {
        let ps = self.key.pseudonymizer(tenant);
        if let Some(list) = result.get_mut("pii_entities").and_then(Json::as_array_mut) {
            for e in list {
                let kind = e["kind"].as_str().unwrap_or("PII").to_owned();
                let Some(original) = e["original"].as_str().map(str::to_owned) else {
                    continue;
                };
                let token = ps.token(&kind, &original);
                self.store(tenant, &token, &original).await?;
                if let Some(o) = e.as_object_mut() {
                    o.remove("original");
                    o.insert("token".into(), json!(token));
                }
            }
        }
        Ok(result)
    }
}
