//! Tier 3 controls for sensitive commands (T8.4), such as moving money.
//!
//! A command at trust tier 3 is allowed only when **all** of these hold:
//!
//! 1. **Sender-constrained token.** The access token carries `cnf.jkt`, the thumbprint of
//!    a client key, and the request carries a proof signed by that key over the method,
//!    URL, a fresh `jti`, the time and the hash of the token. A stolen token is useless
//!    without the key; a captured proof cannot be replayed or moved to another request.
//! 2. **Online check.** The identity authority is asked, for this command, whether the
//!    session is still active. If it cannot be asked, the command is refused (fail
//!    closed). Tier 3 never runs on a cached "yes".
//! 3. **Passkey assertion over the transaction hash.** A WebAuthn assertion (ES256) whose
//!    challenge is the SHA-256 of the exact command (`falak_ledger::Command::hash`), so
//!    the person approved *this* transfer and not just "a" transfer. User presence and
//!    user verification flags are required, and the signature counter must advance.
//! 4. **Optional dual approval.** `n` other people, distinct from the initiator, each
//!    signed the same transaction hash with their own key.
//!
//! Time is passed in (`now`, Unix seconds) so the same code runs where `SystemTime` is
//! unavailable. This module checks evidence; it does not store credentials, and its
//! replay cache is per process (a multi-instance deployment needs a shared one).

use std::{
    collections::{HashMap, HashSet},
    sync::Mutex,
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use falak_contracts::{Error, ErrorKind, Result};
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256Key, signature::Verifier};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::token::{Claims, bound_key_thumbprint};

fn denied(code: &'static str, message: &'static str) -> Error {
    Error::new(ErrorKind::Forbidden, code, message)
}

fn sha(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn unhex(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// Thumbprint of a client key, as placed in a token's `cnf.jkt`.
pub fn thumbprint(public_key: &[u8; 32]) -> String {
    B64.encode(sha(public_key))
}

// ---- 1. Proof of possession -------------------------------------------------------

fn pop_message(method: &str, url: &str, iat: i64, jti: &str, ath: &str) -> Vec<u8> {
    format!("falak-pop-v1\n{method}\n{url}\n{iat}\n{jti}\n{ath}").into_bytes()
}

/// Client side: sign a proof for one request. Format: `key.iat.jti.signature`.
pub fn make_proof(
    key: &SigningKey,
    method: &str,
    url: &str,
    iat: i64,
    jti: &str,
    token: &str,
) -> String {
    let ath = B64.encode(sha(token.as_bytes()));
    let sig = key.sign(&pop_message(method, url, iat, jti, &ath));
    format!(
        "{}.{iat}.{jti}.{}",
        B64.encode(key.verifying_key().to_bytes()),
        B64.encode(sig.to_bytes())
    )
}

/// Remembers recent proof ids, so a captured proof cannot be used twice.
#[derive(Default)]
pub struct ReplayGuard {
    seen: Mutex<HashMap<String, i64>>,
}

impl ReplayGuard {
    /// True if `id` is new. Entries older than `keep_until` are dropped.
    fn first_use(&self, id: String, now: i64, keep_secs: i64) -> bool {
        let Ok(mut seen) = self.seen.lock() else {
            return false;
        };
        seen.retain(|_, t| *t > now - keep_secs);
        seen.insert(id, now).is_none()
    }
}

fn verify_proof(
    proof: &str,
    token: &str,
    method: &str,
    url: &str,
    now: i64,
    skew: i64,
    replay: &ReplayGuard,
) -> Result<()> {
    let bad = || {
        denied(
            "tier3_proof_invalid",
            "The proof of possession is not valid.",
        )
    };
    let parts: Vec<&str> = proof.split('.').collect();
    let [key_b64, iat, jti, sig_b64] = parts[..] else {
        return Err(bad());
    };
    let key_bytes: [u8; 32] = B64
        .decode(key_b64)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(bad)?;
    if bound_key_thumbprint(token).as_deref() != Some(thumbprint(&key_bytes).as_str()) {
        return Err(denied(
            "tier3_token_not_bound",
            "The token is not bound to this key.",
        ));
    }
    let iat: i64 = iat.parse().map_err(|_| bad())?;
    if (now - iat).abs() > skew || jti.is_empty() || jti.len() > 100 {
        return Err(bad());
    }
    let sig_bytes: [u8; 64] = B64
        .decode(sig_b64)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(bad)?;
    let ath = B64.encode(sha(token.as_bytes()));
    VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| bad())?
        .verify_strict(
            &pop_message(method, url, iat, jti, &ath),
            &Signature::from_bytes(&sig_bytes),
        )
        .map_err(|_| bad())?;
    if !replay.first_use(format!("{key_b64}:{jti}"), now, skew * 2 + 1) {
        return Err(denied(
            "tier3_proof_replayed",
            "This proof was already used.",
        ));
    }
    Ok(())
}

// ---- 2. Online check --------------------------------------------------------------

/// Asks the identity authority whether a session is still valid, right now.
pub trait OnlineCheck {
    /// `Ok(true)` only when the authority answered that the token's session is active.
    async fn is_active(&self, subject: &str, token_id: &str) -> Result<bool>;
}

// ---- 3. Passkey assertion over the transaction hash -------------------------------

/// The site a passkey belongs to.
#[derive(Debug, Clone)]
pub struct RelyingParty {
    pub id: String,
    /// Allowed `origin` values in the client data, such as `https://bank.example`.
    pub origins: Vec<String>,
}

/// A stored passkey: its P-256 public key (SEC1 bytes) and last signature counter.
#[derive(Debug, Clone)]
pub struct PasskeyCredential {
    pub public_key_sec1: Vec<u8>,
    pub sign_count: u32,
}

/// What the browser returns from `navigator.credentials.get`.
#[derive(Debug, Clone)]
pub struct Assertion {
    pub authenticator_data: Vec<u8>,
    pub client_data_json: Vec<u8>,
    /// ASN.1 DER ECDSA signature.
    pub signature: Vec<u8>,
}

/// Verify an assertion whose challenge is `tx_hash` (64 hex characters). Returns the new
/// signature counter to store.
pub fn verify_assertion(
    rp: &RelyingParty,
    credential: &PasskeyCredential,
    assertion: &Assertion,
    tx_hash: &str,
) -> Result<u32> {
    let bad = || {
        denied(
            "tier3_passkey_invalid",
            "The passkey assertion is not valid for this transaction.",
        )
    };
    let hash = unhex(tx_hash).ok_or_else(bad)?;
    let client: Value = serde_json::from_slice(&assertion.client_data_json).map_err(|_| bad())?;
    let field = |name: &str| client.get(name).and_then(Value::as_str);
    if field("type") != Some("webauthn.get")
        || field("challenge") != Some(B64.encode(hash).as_str())
        || !rp
            .origins
            .iter()
            .any(|o| Some(o.as_str()) == field("origin"))
    {
        return Err(bad());
    }
    let data = &assertion.authenticator_data;
    if data.len() < 37 || data[..32] != sha(rp.id.as_bytes()) {
        return Err(bad());
    }
    // 0x01 user present, 0x04 user verified.
    if data[32] & 0x05 != 0x05 {
        return Err(bad());
    }
    let count = u32::from_be_bytes([data[33], data[34], data[35], data[36]]);
    if (count != 0 || credential.sign_count != 0) && count <= credential.sign_count {
        return Err(denied(
            "tier3_passkey_cloned",
            "The passkey's signature counter did not advance.",
        ));
    }
    let key = P256Key::from_sec1_bytes(&credential.public_key_sec1).map_err(|_| bad())?;
    let signature = P256Signature::from_der(&assertion.signature).map_err(|_| bad())?;
    let mut signed = data.clone();
    signed.extend_from_slice(&sha(&assertion.client_data_json));
    key.verify(&signed, &signature).map_err(|_| bad())?;
    Ok(count)
}

// ---- 4. Dual approval -------------------------------------------------------------

/// One person's signed approval of one transaction hash.
#[derive(Debug, Clone)]
pub struct Approval {
    pub approver: String,
    pub expires_at: i64,
    pub signature: [u8; 64],
}

fn approval_message(tx_hash: &str, approver: &str, expires_at: i64) -> Vec<u8> {
    format!("falak-approval-v1\n{tx_hash}\n{approver}\n{expires_at}").into_bytes()
}

pub fn sign_approval(key: &SigningKey, tx_hash: &str, approver: &str, expires_at: i64) -> Approval {
    Approval {
        approver: approver.to_owned(),
        expires_at,
        signature: key
            .sign(&approval_message(tx_hash, approver, expires_at))
            .to_bytes(),
    }
}

fn verify_approvals(
    directory: &HashMap<String, VerifyingKey>,
    initiator: &str,
    tx_hash: &str,
    approvals: &[Approval],
    required: usize,
    now: i64,
) -> Result<()> {
    let mut counted = HashSet::new();
    for a in approvals {
        let Some(key) = directory.get(&a.approver) else {
            continue;
        };
        if a.approver == initiator || a.expires_at < now {
            continue;
        }
        let message = approval_message(tx_hash, &a.approver, a.expires_at);
        if key
            .verify_strict(&message, &Signature::from_bytes(&a.signature))
            .is_ok()
        {
            counted.insert(a.approver.as_str());
        }
    }
    if counted.len() < required {
        return Err(denied(
            "tier3_approvals_insufficient",
            "More approvals from other people are needed.",
        ));
    }
    Ok(())
}

// ---- The guard --------------------------------------------------------------------

pub struct Tier3 {
    pub rp: RelyingParty,
    /// Allowed clock difference for proofs, in seconds.
    pub skew_secs: i64,
    /// Approvals needed from people other than the initiator; 0 turns dual approval off.
    pub approvals_required: usize,
    replay: ReplayGuard,
}

/// One sensitive request.
pub struct Request<'a> {
    pub method: &'a str,
    pub url: &'a str,
    /// The access token, already accepted by `token::Verifier`.
    pub token: &'a str,
    pub claims: &'a Claims,
    /// Hash of the exact command: 64 hex characters.
    pub tx_hash: &'a str,
}

pub struct Evidence<'a> {
    pub proof: &'a str,
    pub assertion: &'a Assertion,
    pub approvals: &'a [Approval],
}

/// What the caller stores after an allowed command.
#[derive(Debug, PartialEq, Eq)]
pub struct Authorized {
    pub new_sign_count: u32,
}

impl Tier3 {
    pub fn new(rp: RelyingParty, approvals_required: usize) -> Self {
        Self {
            rp,
            skew_secs: 60,
            approvals_required,
            replay: ReplayGuard::default(),
        }
    }

    /// Allow the command only if every control passes. Cheap local checks run before the
    /// network call.
    pub async fn authorize<O: OnlineCheck>(
        &self,
        online: &O,
        request: &Request<'_>,
        evidence: &Evidence<'_>,
        credential: &PasskeyCredential,
        approvers: &HashMap<String, VerifyingKey>,
        now: i64,
    ) -> Result<Authorized> {
        verify_proof(
            evidence.proof,
            request.token,
            request.method,
            request.url,
            now,
            self.skew_secs,
            &self.replay,
        )?;
        match online
            .is_active(&request.claims.subject, &request.claims.token_id)
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                return Err(denied(
                    "tier3_session_revoked",
                    "The session is no longer active.",
                ));
            }
            Err(_) => {
                return Err(Error::new(
                    ErrorKind::Unavailable,
                    "tier3_online_check_unavailable",
                    "A sensitive command needs the identity service, which did not answer.",
                ));
            }
        }
        let new_sign_count =
            verify_assertion(&self.rp, credential, evidence.assertion, request.tx_hash)?;
        if self.approvals_required > 0 {
            verify_approvals(
                approvers,
                &request.claims.subject,
                request.tx_hash,
                evidence.approvals,
                self.approvals_required,
                now,
            )?;
        }
        Ok(Authorized { new_sign_count })
    }
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::{SigningKey as P256Signing, signature::Signer as _};

    use super::*;
    use crate::token::{TokenConfig, issue_with_cnf};

    const NOW: i64 = 1_800_000_000;
    const HASH: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    struct Online(Result<bool>);
    impl OnlineCheck for Online {
        async fn is_active(&self, _: &str, _: &str) -> Result<bool> {
            match &self.0 {
                Ok(b) => Ok(*b),
                Err(_) => Err(Error::new(ErrorKind::Unavailable, "down", "down")),
            }
        }
    }

    struct World {
        guard: Tier3,
        client: SigningKey,
        token: String,
        claims: Claims,
        passkey: P256Signing,
        credential: PasskeyCredential,
        approver_keys: HashMap<String, SigningKey>,
        directory: HashMap<String, VerifyingKey>,
    }

    fn signing(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn world(approvals_required: usize) -> World {
        let client = signing(1);
        let issuer = signing(2);
        let claims = Claims {
            subject: "alice".into(),
            tenant: None,
            roles: vec![],
            issued_at: NOW - 10,
            expires_at: NOW + 600,
            token_id: "jti-1".into(),
        };
        let config = TokenConfig {
            issuer: "i".into(),
            audience: "a".into(),
            leeway_secs: 0,
        };
        let jkt = thumbprint(&client.verifying_key().to_bytes());
        let token = issue_with_cnf(&issuer, "k1", &config, &claims, Some(&jkt));
        let passkey = P256Signing::from_slice(&[7u8; 32]).unwrap();
        let credential = PasskeyCredential {
            public_key_sec1: passkey
                .verifying_key()
                .to_sec1_point(false)
                .as_bytes()
                .to_vec(),
            sign_count: 5,
        };
        let mut approver_keys = HashMap::new();
        let mut directory = HashMap::new();
        for (i, name) in ["bob", "carol", "alice"].iter().enumerate() {
            let k = signing(10 + i as u8);
            directory.insert((*name).to_owned(), k.verifying_key());
            approver_keys.insert((*name).to_owned(), k);
        }
        World {
            guard: Tier3::new(
                RelyingParty {
                    id: "bank.example".into(),
                    origins: vec!["https://bank.example".into()],
                },
                approvals_required,
            ),
            client,
            token,
            claims,
            passkey,
            credential,
            approver_keys,
            directory,
        }
    }

    fn assertion(w: &World, hash: &str, count: u32, flags: u8) -> Assertion {
        let challenge = B64.encode(unhex(hash).unwrap());
        let client_data = format!(
            r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"https://bank.example"}}"#
        )
        .into_bytes();
        let mut data = sha(b"bank.example").to_vec();
        data.push(flags);
        data.extend_from_slice(&count.to_be_bytes());
        let mut signed = data.clone();
        signed.extend_from_slice(&sha(&client_data));
        let sig: P256Signature = w.passkey.sign(&signed);
        Assertion {
            authenticator_data: data,
            client_data_json: client_data,
            signature: sig.to_der().as_bytes().to_vec(),
        }
    }

    fn proof(w: &World, jti: &str) -> String {
        make_proof(&w.client, "POST", "/v1/_commands/pay", NOW, jti, &w.token)
    }

    async fn run(
        w: &World,
        online: &Online,
        proof: &str,
        assertion: &Assertion,
        approvals: &[Approval],
    ) -> Result<Authorized> {
        let request = Request {
            method: "POST",
            url: "/v1/_commands/pay",
            token: &w.token,
            claims: &w.claims,
            tx_hash: HASH,
        };
        let evidence = Evidence {
            proof,
            assertion,
            approvals,
        };
        w.guard
            .authorize(
                online,
                &request,
                &evidence,
                &w.credential,
                &w.directory,
                NOW,
            )
            .await
    }

    fn approvals(w: &World, who: &[&str]) -> Vec<Approval> {
        who.iter()
            .map(|n| sign_approval(&w.approver_keys[*n], HASH, n, NOW + 300))
            .collect()
    }

    #[tokio::test]
    async fn all_controls_pass() {
        let w = world(1);
        let ok = run(
            &w,
            &Online(Ok(true)),
            &proof(&w, "p1"),
            &assertion(&w, HASH, 6, 0x05),
            &approvals(&w, &["bob"]),
        )
        .await
        .unwrap();
        assert_eq!(ok.new_sign_count, 6);
    }

    #[tokio::test]
    async fn a_stolen_token_without_the_key_is_refused() {
        let w = world(0);
        let thief = signing(99);
        let p = make_proof(&thief, "POST", "/v1/_commands/pay", NOW, "x", &w.token);
        let e = run(&w, &Online(Ok(true)), &p, &assertion(&w, HASH, 6, 5), &[])
            .await
            .unwrap_err();
        assert_eq!(e.code(), "tier3_token_not_bound");
        // A proof for another URL does not verify either.
        let p = make_proof(&w.client, "POST", "/other", NOW, "y", &w.token);
        let e = run(&w, &Online(Ok(true)), &p, &assertion(&w, HASH, 6, 5), &[])
            .await
            .unwrap_err();
        assert_eq!(e.code(), "tier3_proof_invalid");
    }

    #[tokio::test]
    async fn a_proof_cannot_be_replayed() {
        let w = world(0);
        let p = proof(&w, "once");
        let a = assertion(&w, HASH, 6, 5);
        run(&w, &Online(Ok(true)), &p, &a, &[]).await.unwrap();
        let e = run(&w, &Online(Ok(true)), &p, &a, &[]).await.unwrap_err();
        assert_eq!(e.code(), "tier3_proof_replayed");
    }

    #[tokio::test]
    async fn the_online_check_fails_closed() {
        let w = world(0);
        let a = assertion(&w, HASH, 6, 5);
        let e = run(&w, &Online(Ok(false)), &proof(&w, "a"), &a, &[])
            .await
            .unwrap_err();
        assert_eq!(e.code(), "tier3_session_revoked");
        let down = Online(Err(Error::forbidden()));
        let e = run(&w, &down, &proof(&w, "b"), &a, &[]).await.unwrap_err();
        assert_eq!(e.code(), "tier3_online_check_unavailable");
    }

    #[tokio::test]
    async fn the_passkey_must_approve_this_exact_transaction() {
        let w = world(0);
        let other = "ff".repeat(32);
        let e = run(
            &w,
            &Online(Ok(true)),
            &proof(&w, "c"),
            &assertion(&w, &other, 6, 5),
            &[],
        )
        .await
        .unwrap_err();
        assert_eq!(e.code(), "tier3_passkey_invalid");
        // User verification missing.
        let e = run(
            &w,
            &Online(Ok(true)),
            &proof(&w, "d"),
            &assertion(&w, HASH, 6, 0x01),
            &[],
        )
        .await
        .unwrap_err();
        assert_eq!(e.code(), "tier3_passkey_invalid");
        // Counter did not advance.
        let e = run(
            &w,
            &Online(Ok(true)),
            &proof(&w, "e"),
            &assertion(&w, HASH, 5, 5),
            &[],
        )
        .await
        .unwrap_err();
        assert_eq!(e.code(), "tier3_passkey_cloned");
        // Signed by a different key.
        let mut forged = assertion(&w, HASH, 6, 5);
        forged.signature = {
            let other: P256Signature = P256Signing::from_slice(&[8u8; 32]).unwrap().sign(b"x");
            other.to_der().as_bytes().to_vec()
        };
        let e = run(&w, &Online(Ok(true)), &proof(&w, "f"), &forged, &[])
            .await
            .unwrap_err();
        assert_eq!(e.code(), "tier3_passkey_invalid");
    }

    #[tokio::test]
    async fn dual_approval_needs_distinct_other_people() {
        let w = world(2);
        let a = assertion(&w, HASH, 6, 5);
        // The initiator's own approval and a duplicate do not count.
        let e = run(
            &w,
            &Online(Ok(true)),
            &proof(&w, "g"),
            &a,
            &approvals(&w, &["alice", "bob", "bob"]),
        )
        .await
        .unwrap_err();
        assert_eq!(e.code(), "tier3_approvals_insufficient");
        // An approval of another transaction does not count.
        let mut wrong = approvals(&w, &["bob", "carol"]);
        wrong[1] = sign_approval(
            &w.approver_keys["carol"],
            &"ab".repeat(32),
            "carol",
            NOW + 300,
        );
        let e = run(&w, &Online(Ok(true)), &proof(&w, "h"), &a, &wrong)
            .await
            .unwrap_err();
        assert_eq!(e.code(), "tier3_approvals_insufficient");
        // An expired approval does not count.
        let mut old = approvals(&w, &["bob"]);
        old.push(sign_approval(
            &w.approver_keys["carol"],
            HASH,
            "carol",
            NOW - 1,
        ));
        let e = run(&w, &Online(Ok(true)), &proof(&w, "i"), &a, &old)
            .await
            .unwrap_err();
        assert_eq!(e.code(), "tier3_approvals_insufficient");
        run(
            &w,
            &Online(Ok(true)),
            &proof(&w, "j"),
            &a,
            &approvals(&w, &["bob", "carol"]),
        )
        .await
        .unwrap();
    }
}
