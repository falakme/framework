//! The local key provider: Ed25519 signing keys kept in a file next to the app.
//!
//! Standalone apps use this. Office-managed apps use a vault-backed provider instead
//! (T6.5); both implement `SigningKeyProvider`.
//!
//! * The file is created with owner-only permissions (0600 on Unix).
//! * Several keys can exist. New tokens use the active one, and older keys keep
//!   verifying until they are removed, which is how rotation avoids failed requests.
//! * Secret bytes never appear in `Debug` output.

use std::{fmt, fs, io::Write, path::Path};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use falak_contracts::{
    Error, Result,
    keys::{KeyId, PublicKey, SigningAlgorithm, SigningKeyProvider},
};
use rand_core::OsRng;
use serde_json::{Value, json};

use crate::token::Verifier;

struct Entry {
    kid: String,
    key: SigningKey,
}

/// A set of signing keys with one active.
pub struct LocalKeys {
    entries: Vec<Entry>,
    active: usize,
}

impl fmt::Debug for LocalKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalKeys")
            .field(
                "kids",
                &self.entries.iter().map(|e| &e.kid).collect::<Vec<_>>(),
            )
            .field("active", &self.entries[self.active].kid)
            .finish_non_exhaustive()
    }
}

fn io_error(what: &str, e: std::io::Error) -> Error {
    Error::internal(format!("{what}: {e}"))
}

impl LocalKeys {
    /// A set with one fresh key.
    pub fn generate() -> Self {
        Self {
            entries: vec![Entry {
                kid: new_kid(),
                key: SigningKey::generate(&mut OsRng),
            }],
            active: 0,
        }
    }

    /// Load the key file, or create it with a fresh key if it does not exist.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        match fs::read_to_string(path) {
            Ok(text) => Self::from_json(&text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let keys = Self::generate();
                keys.save(path)?;
                Ok(keys)
            }
            Err(e) => Err(io_error("cannot read key file", e)),
        }
    }

    /// Write the key file, replacing any existing one, with owner-only permissions.
    pub fn save(&self, path: &Path) -> Result<()> {
        let text = self.to_json().to_string();
        let tmp = path.with_extension("tmp");
        let mut file = open_private(&tmp).map_err(|e| io_error("cannot write key file", e))?;
        file.write_all(text.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|e| io_error("cannot write key file", e))?;
        fs::rename(&tmp, path).map_err(|e| io_error("cannot replace key file", e))
    }

    /// Add a new key and make it active. Older keys still verify.
    pub fn rotate(&mut self) -> KeyId {
        let kid = new_kid();
        self.entries.push(Entry {
            kid: kid.clone(),
            key: SigningKey::generate(&mut OsRng),
        });
        self.active = self.entries.len() - 1;
        KeyId(kid)
    }

    /// Stop trusting every key except the active one. Call after rotation overlap.
    pub fn retire_old(&mut self) {
        let active = self.entries.swap_remove(self.active);
        self.entries = vec![active];
        self.active = 0;
    }

    /// The active key and its id, for issuing tokens.
    pub fn active(&self) -> (&str, &SigningKey) {
        let e = &self.entries[self.active];
        (&e.kid, &e.key)
    }

    /// Add every public key to a verifier.
    pub fn trust_all(&self, verifier: &mut Verifier) {
        for e in &self.entries {
            verifier.add_key(e.kid.clone(), e.key.verifying_key());
        }
    }

    fn to_json(&self) -> Value {
        json!({
            "active": self.entries[self.active].kid,
            "keys": self.entries.iter().map(|e| json!({
                "kid": e.kid,
                "secret": B64.encode(e.key.to_bytes()),
            })).collect::<Vec<_>>(),
        })
    }

    pub fn from_json(text: &str) -> Result<Self> {
        let bad = |why: &str| Error::internal(format!("key file is not valid: {why}"));
        let v: Value = serde_json::from_str(text).map_err(|_| bad("not JSON"))?;
        let active = v["active"].as_str().ok_or_else(|| bad("no active key"))?;
        let list = v["keys"].as_array().ok_or_else(|| bad("no keys"))?;
        let mut entries = Vec::new();
        for item in list {
            let kid = item["kid"].as_str().ok_or_else(|| bad("key without kid"))?;
            let secret = item["secret"]
                .as_str()
                .and_then(|s| B64.decode(s).ok())
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .ok_or_else(|| bad("secret is not 32 bytes"))?;
            entries.push(Entry {
                kid: kid.to_owned(),
                key: SigningKey::from_bytes(&secret),
            });
        }
        let active = entries
            .iter()
            .position(|e| e.kid == active)
            .ok_or_else(|| bad("active key is missing"))?;
        Ok(Self { entries, active })
    }

    fn find(&self, kid: &KeyId) -> Option<&Entry> {
        self.entries.iter().find(|e| e.kid == kid.0)
    }
}

#[cfg(unix)]
fn open_private(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn open_private(path: &Path) -> std::io::Result<fs::File> {
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
}

/// A key id is 8 random bytes in base64url.
fn new_kid() -> String {
    use rand_core::RngCore;
    let mut b = [0u8; 8];
    OsRng.fill_bytes(&mut b);
    B64.encode(b)
}

impl SigningKeyProvider for LocalKeys {
    fn active_key_id(&self) -> KeyId {
        KeyId(self.entries[self.active].kid.clone())
    }

    async fn sign(&self, kid: &KeyId, message: &[u8]) -> Result<Vec<u8>> {
        let e = self
            .find(kid)
            .ok_or_else(|| Error::internal("unknown signing key"))?;
        Ok(e.key.sign(message).to_bytes().to_vec())
    }

    async fn verify(&self, kid: &KeyId, message: &[u8], signature: &[u8]) -> Result<bool> {
        let Some(e) = self.find(kid) else {
            return Ok(false);
        };
        let Ok(sig) = Signature::from_slice(signature) else {
            return Ok(false);
        };
        Ok(e.key.verifying_key().verify_strict(message, &sig).is_ok())
    }

    async fn public_keys(&self) -> Result<Vec<PublicKey>> {
        Ok(self
            .entries
            .iter()
            .map(|e| PublicKey {
                kid: KeyId(e.kid.clone()),
                algorithm: SigningAlgorithm::EdDsa,
                key: VerifyingKey::from(&e.key).to_bytes().to_vec(),
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        pin::pin,
        task::{Context, Poll, Waker},
    };

    use super::*;

    fn block_on<F: Future>(fut: F) -> F::Output {
        let mut fut = pin!(fut);
        let mut cx = Context::from_waker(Waker::noop());
        loop {
            if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }

    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("falak-keys-{}-{name}", std::process::id()))
    }

    #[test]
    fn file_round_trip_keeps_keys_and_is_private() {
        let path = temp_path("rt.json");
        let _ = fs::remove_file(&path);
        let first = LocalKeys::load_or_create(&path).unwrap();
        let again = LocalKeys::load_or_create(&path).unwrap();
        assert_eq!(first.active().0, again.active().0);
        assert_eq!(first.active().1.to_bytes(), again.active().1.to_bytes());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn rotation_keeps_old_keys_verifying_until_retired() {
        let mut keys = LocalKeys::generate();
        let old = keys.active_key_id();
        let sig = block_on(keys.sign(&old, b"m")).unwrap();
        let new = keys.rotate();
        assert_ne!(old, new);
        assert_eq!(keys.active_key_id(), new);
        assert!(block_on(keys.verify(&old, b"m", &sig)).unwrap());
        assert_eq!(block_on(keys.public_keys()).unwrap().len(), 2);
        keys.retire_old();
        assert!(!block_on(keys.verify(&old, b"m", &sig)).unwrap());
        assert_eq!(block_on(keys.public_keys()).unwrap().len(), 1);
    }

    #[test]
    fn bad_signatures_are_false_not_errors() {
        let keys = LocalKeys::generate();
        let kid = keys.active_key_id();
        assert!(!block_on(keys.verify(&kid, b"m", b"short")).unwrap());
        assert!(!block_on(keys.verify(&KeyId("zzz".into()), b"m", &[0; 64])).unwrap());
    }

    #[test]
    fn debug_never_prints_secrets() {
        let keys = LocalKeys::generate();
        let secret = B64.encode(keys.active().1.to_bytes());
        assert!(!format!("{keys:?}").contains(&secret));
    }

    #[test]
    fn corrupt_file_is_an_error() {
        let path = temp_path("bad.json");
        fs::write(&path, "{\"active\":\"x\",\"keys\":[]}").unwrap();
        assert!(LocalKeys::load_or_create(&path).is_err());
        fs::remove_file(&path).unwrap();
    }
}
