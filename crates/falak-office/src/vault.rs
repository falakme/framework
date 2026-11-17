//! Vault: per-tenant data keys (DEKs) wrapped by a key-encryption key (KEK), and the
//! rotation of both (T6.5).
//!
//! * A DEK is 32 random bytes per tenant and version. Only its wrapped form is stored
//!   (`office_deks`). The wrap is ChaCha20-Poly1305 with the tenant and version as
//!   associated data, so a wrapped key cannot be moved to another tenant.
//! * The KEK never enters the database. In production it comes from the environment
//!   (`FALAK_VAULT_KEK`, 64 hex characters, from a secret manager); in development it is a
//!   file in the data directory. Backups of the database alone therefore hold no usable
//!   data key.
//! * Rotating a DEK adds a new version and retires the old one (it still unwraps, so data
//!   can be re-encrypted, then `retire_old` drops it). Rotating the KEK re-wraps every DEK
//!   without changing any of them, so no data is re-encrypted.
//! * Deleting a tenant's DEKs is how its encrypted data is erased.

use std::path::Path;

use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use falak_contracts::{Error, Result, driver::Value};
use rand_core::{OsRng, RngCore};

use crate::{
    db::{Db, int, t, text},
    now,
};

/// The KEKs this Office knows: one active, older ones kept until every DEK has been
/// re-wrapped.
#[derive(Clone)]
pub struct KekSet {
    active: String,
    keys: Vec<(String, [u8; 32])>,
}

fn random32() -> [u8; 32] {
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    b
}

impl KekSet {
    /// A throwaway KEK: wrapped keys do not survive a restart. For tests.
    pub fn ephemeral() -> Self {
        Self {
            active: "ephemeral".into(),
            keys: vec![("ephemeral".into(), random32())],
        }
    }

    /// `FALAK_VAULT_KEK` if set (the only way to share one KEK across instances), else
    /// the file `vault-kek.json` in `dir`, created on first use.
    pub fn load(dir: &Path) -> std::result::Result<Self, String> {
        if let Ok(h) = std::env::var("FALAK_VAULT_KEK") {
            let b = hex::decode(h.trim())
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .ok_or("FALAK_VAULT_KEK must be 64 hex characters")?;
            return Ok(Self {
                active: "env".into(),
                keys: vec![("env".into(), b)],
            });
        }
        let path = dir.join("vault-kek.json");
        match std::fs::read_to_string(&path) {
            Ok(text) => Self::from_json(&text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let set = Self {
                    active: "k1".into(),
                    keys: vec![("k1".into(), random32())],
                };
                set.save(dir)?;
                Ok(set)
            }
            Err(e) => Err(format!("cannot read {}: {e}", path.display())),
        }
    }

    fn from_json(text: &str) -> std::result::Result<Self, String> {
        let v: serde_json::Value =
            serde_json::from_str(text).map_err(|_| "vault-kek.json is not JSON")?;
        let active = v["active"].as_str().ok_or("vault-kek.json has no active")?;
        let mut keys = Vec::new();
        for (id, k) in v["keys"].as_object().ok_or("vault-kek.json has no keys")? {
            let b = k
                .as_str()
                .and_then(|s| hex::decode(s).ok())
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .ok_or("a KEK in vault-kek.json is not 32 bytes of hex")?;
            keys.push((id.clone(), b));
        }
        if !keys.iter().any(|(id, _)| id == active) {
            return Err("the active KEK is missing from vault-kek.json".into());
        }
        Ok(Self {
            active: active.into(),
            keys,
        })
    }

    pub fn save(&self, dir: &Path) -> std::result::Result<(), String> {
        let keys: serde_json::Map<String, serde_json::Value> = self
            .keys
            .iter()
            .map(|(id, k)| (id.clone(), hex::encode(k).into()))
            .collect();
        let body = serde_json::json!({"active": self.active, "keys": keys}).to_string();
        let path = dir.join("vault-kek.json");
        let tmp = dir.join("vault-kek.json.tmp");
        write_private(&tmp, body.as_bytes())?;
        std::fs::rename(&tmp, &path).map_err(|e| format!("cannot save the KEK file: {e}"))
    }

    pub fn active_id(&self) -> &str {
        &self.active
    }

    pub fn is_env(&self) -> bool {
        self.active == "env"
    }

    /// Add a new KEK and make it active.
    pub fn rotate(&mut self) -> String {
        let id = format!("k{}", self.keys.len() + 1);
        self.keys.push((id.clone(), random32()));
        self.active = id.clone();
        id
    }

    /// Forget every KEK except the active one. Only after every DEK is re-wrapped.
    pub fn drop_old(&mut self) {
        let a = self.active.clone();
        self.keys.retain(|(id, _)| *id == a);
    }

    fn cipher(&self, id: &str) -> Result<ChaCha20Poly1305> {
        let (_, k) =
            self.keys.iter().find(|(i, _)| i == id).ok_or_else(|| {
                Error::internal("a data key is wrapped by a KEK this Office lacks")
            })?;
        Ok(ChaCha20Poly1305::new(&Key::from(*k)))
    }

    fn wrap(&self, kek: &str, tenant: &str, version: i64, dek: &[u8]) -> Result<String> {
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let aad = format!("{tenant}|{version}");
        let ct = self
            .cipher(kek)?
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: dek,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| Error::internal("cannot wrap a data key"))?;
        Ok(format!("{}{}", hex::encode(nonce), hex::encode(ct)))
    }

    fn unwrap(&self, kek: &str, tenant: &str, version: i64, wrapped: &str) -> Result<Vec<u8>> {
        let bad = || Error::internal("a wrapped data key does not open");
        let raw = hex::decode(wrapped).map_err(|_| bad())?;
        if raw.len() < 12 {
            return Err(bad());
        }
        let (nonce, ct) = raw.split_at(12);
        let nonce = Nonce::try_from(nonce).map_err(|_| bad())?;
        let aad = format!("{tenant}|{version}");
        self.cipher(kek)?
            .decrypt(
                &nonce,
                Payload {
                    msg: ct,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| bad())
    }
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> std::result::Result<(), String> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    f.write_all(bytes)
        .map_err(|e| format!("cannot write {}: {e}", path.display()))
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> std::result::Result<(), String> {
    std::fs::write(path, bytes).map_err(|e| format!("cannot write {}: {e}", path.display()))
}

/// One stored DEK version, without its secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DekInfo {
    pub version: i64,
    pub status: String,
    pub kek: String,
    pub created_at: i64,
}

/// Make the tenant's next DEK version active, retiring the current one. Returns the new
/// version and the plaintext key (shown to the caller once, never stored).
pub async fn rotate_dek(db: &Db, kek: &KekSet, tenant: &str) -> Result<(i64, Vec<u8>)> {
    for _ in 0..5 {
        let rows = db
            .rows(
                "SELECT COALESCE(MAX(version), 0) FROM office_deks WHERE tenant = ?",
                vec![t(tenant)],
            )
            .await?;
        let version = rows.first().map_or(0, |r| int(r.first())) + 1;
        let dek = random32();
        let wrapped = kek.wrap(kek.active_id(), tenant, version, &dek)?;
        let out = db
            .batch(vec![
                db.stmt(
                    "INSERT INTO office_deks (tenant, version, kek, wrapped, status, created_at) VALUES (?, ?, ?, ?, 'active', ?)",
                    vec![
                        t(tenant),
                        Value::Int64(version),
                        t(kek.active_id()),
                        t(&wrapped),
                        Value::Int64(now()),
                    ],
                ),
                db.stmt(
                    "UPDATE office_deks SET status = 'retired' WHERE tenant = ? AND version < ? AND status = 'active'",
                    vec![t(tenant), Value::Int64(version)],
                ),
            ])
            .await;
        if out.is_ok() {
            return Ok((version, dek.to_vec()));
        }
    }
    Err(Error::new(
        falak_contracts::ErrorKind::Conflict,
        "dek_busy",
        "Try again.",
    ))
}

/// The plaintext of a DEK version (the active one when `version` is `None`).
pub async fn open_dek(
    db: &Db,
    kek: &KekSet,
    tenant: &str,
    version: Option<i64>,
) -> Result<Option<(i64, Vec<u8>)>> {
    let rows = match version {
        Some(v) => {
            db.rows(
                "SELECT version, kek, wrapped FROM office_deks WHERE tenant = ? AND version = ?",
                vec![t(tenant), Value::Int64(v)],
            )
            .await?
        }
        None => {
            db.rows(
                "SELECT version, kek, wrapped FROM office_deks WHERE tenant = ? AND status = 'active'",
                vec![t(tenant)],
            )
            .await?
        }
    };
    let Some(r) = rows.first() else {
        return Ok(None);
    };
    let v = int(r.first());
    Ok(Some((
        v,
        kek.unwrap(&text(r.get(1)), tenant, v, &text(r.get(2)))?,
    )))
}

pub async fn list_deks(db: &Db, tenant: &str) -> Result<Vec<DekInfo>> {
    Ok(db
        .rows(
            "SELECT version, status, kek, created_at FROM office_deks WHERE tenant = ? ORDER BY version",
            vec![t(tenant)],
        )
        .await?
        .iter()
        .map(|r| DekInfo {
            version: int(r.first()),
            status: text(r.get(1)),
            kek: text(r.get(2)),
            created_at: int(r.get(3)),
        })
        .collect())
}

/// Delete retired versions, once the tenant's data has been re-encrypted under the
/// active one.
pub async fn retire_old(db: &Db, tenant: &str) -> Result<u64> {
    db.run(
        "DELETE FROM office_deks WHERE tenant = ? AND status = 'retired'",
        vec![t(tenant)],
    )
    .await
}

/// Erase a tenant's data keys: its encrypted data can no longer be read.
pub async fn destroy(db: &Db, tenant: &str) -> Result<u64> {
    db.run("DELETE FROM office_deks WHERE tenant = ?", vec![t(tenant)])
        .await
}

/// Re-wrap every DEK under a new active KEK. The DEKs themselves do not change.
/// Returns `(new KEK id, DEKs re-wrapped)`.
pub async fn rotate_kek(db: &Db, kek: &mut KekSet) -> Result<(String, usize)> {
    let rows = db
        .rows(
            "SELECT tenant, version, kek, wrapped FROM office_deks",
            vec![],
        )
        .await?;
    let new = kek.rotate();
    let mut stmts = Vec::new();
    for r in &rows {
        let (tenant, version) = (text(r.first()), int(r.get(1)));
        let dek = kek.unwrap(&text(r.get(2)), &tenant, version, &text(r.get(3)))?;
        let wrapped = kek.wrap(&new, &tenant, version, &dek)?;
        stmts.push(db.stmt(
            "UPDATE office_deks SET kek = ?, wrapped = ? WHERE tenant = ? AND version = ?",
            vec![t(&new), t(&wrapped), t(&tenant), Value::Int64(version)],
        ));
    }
    let n = stmts.len();
    if !stmts.is_empty() {
        db.batch(stmts).await?;
    }
    Ok((new, n))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dek_wrapped_by_an_earlier_release_still_opens() {
        // Produced by chacha20poly1305 0.10 with a fixed key and nonce: wrapped keys are
        // stored, so the format must not change when the crate is upgraded.
        let k = KekSet {
            keys: vec![("k1".into(), [7u8; 32])],
            active: "k1".into(),
        };
        let nonce = [9u8; 12];
        let ct = k
            .cipher("k1")
            .unwrap()
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: b"0123456789abcdef0123456789abcdef",
                    aad: b"acme|3",
                },
            )
            .unwrap();
        let known = "cc48c9e4d03bb392e5516f5aa383c1b74e3f78be0c327baf64955ff47e3a64bd9468f45e534a2ee99a5656298fc4d969";
        assert_eq!(hex::encode(ct), known);
        let wrapped = format!("{}{known}", hex::encode(nonce));
        assert_eq!(
            k.unwrap("k1", "acme", 3, &wrapped).unwrap(),
            b"0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn a_wrapped_key_opens_only_for_its_tenant_and_version() {
        let k = KekSet::ephemeral();
        let w = k
            .wrap("ephemeral", "acme", 1, b"0123456789abcdef0123456789abcdef")
            .unwrap();
        assert_eq!(
            k.unwrap("ephemeral", "acme", 1, &w).unwrap(),
            b"0123456789abcdef0123456789abcdef"
        );
        assert!(k.unwrap("ephemeral", "other", 1, &w).is_err());
        assert!(k.unwrap("ephemeral", "acme", 2, &w).is_err());
    }

    #[test]
    fn rotating_the_kek_keeps_old_wraps_readable_until_dropped() {
        let mut k = KekSet::ephemeral();
        let w = k.wrap("ephemeral", "acme", 1, &[7u8; 32]).unwrap();
        let new = k.rotate();
        assert!(k.unwrap("ephemeral", "acme", 1, &w).is_ok());
        k.drop_old();
        assert!(k.unwrap("ephemeral", "acme", 1, &w).is_err());
        let w2 = k.wrap(&new, "acme", 1, &[7u8; 32]).unwrap();
        assert!(k.unwrap(&new, "acme", 1, &w2).is_ok());
    }
}
