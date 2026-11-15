//! Signing and envelope-encryption keys. Two separate roles, so a signing-key
//! compromise does not expose data keys and the reverse.

use crate::Result;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyId(pub String);

/// Only `EdDSA` (Ed25519) is accepted; the algorithm is pinned, never read from a token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningAlgorithm {
    EdDsa,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    pub kid: KeyId,
    pub algorithm: SigningAlgorithm,
    /// Raw 32-byte Ed25519 public key.
    pub key: Vec<u8>,
}

pub trait SigningKeyProvider {
    /// Key used for new signatures. During rotation, older keys stay verifiable.
    fn active_key_id(&self) -> KeyId;
    async fn sign(&self, kid: &KeyId, message: &[u8]) -> Result<Vec<u8>>;
    /// Returns `Ok(false)` for a bad signature, and an error only for provider failures.
    async fn verify(&self, kid: &KeyId, message: &[u8], signature: &[u8]) -> Result<bool>;
    /// All currently valid public keys, for publishing as a key set.
    async fn public_keys(&self) -> Result<Vec<PublicKey>>;
}

/// A per-tenant data key and its wrapped (encrypted) form for storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataKey {
    pub plaintext: Vec<u8>,
    pub wrapped: Vec<u8>,
}

pub trait EncryptionKeyProvider {
    async fn generate_data_key(&self, tenant: &str) -> Result<DataKey>;
    async fn unwrap_data_key(&self, tenant: &str, wrapped: &[u8]) -> Result<Vec<u8>>;
}
