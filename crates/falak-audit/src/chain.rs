//! The hash chain: how entries link and how a copy is checked.
//!
//! Each entry's hash covers its own fields and the previous entry's hash, so changing,
//! removing, inserting or reordering any entry changes every hash after it. A reader
//! who holds an *anchor* (the sequence number and hash of the newest entry at some
//! earlier time, kept somewhere the log's writer cannot reach) can also detect that the
//! log was cut short or rewritten from the start.
//!
//! The chain proves integrity, not secrecy: entries are plain text. Keep personal data
//! out of `details`.

use sha2::{Digest, Sha256};

/// A SHA-256 hash.
pub type Hash = [u8; 32];

/// The `prev_hash` of the first entry.
pub const GENESIS: Hash = [0; 32];

/// What happened. Everything here is hashed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Position in the log, starting at 1 and rising by one.
    pub seq: u64,
    /// Microseconds since the epoch, UTC.
    pub at_micros: i64,
    /// Who did it (a user id or a system name). `None` for the system itself.
    pub actor: Option<String>,
    /// What was done, as a stable code such as `login_failed` or `policy_denied`.
    pub action: String,
    /// What it was done to, if anything.
    pub target: Option<String>,
    /// `ok`, `denied` or `error`.
    pub outcome: String,
    /// Extra context as compact JSON text. No personal data, tokens or secrets.
    pub details: String,
    pub prev_hash: Hash,
    pub hash: Hash,
}

fn put_bytes(h: &mut Sha256, bytes: &[u8]) {
    // A length prefix, so ("ab","c") and ("a","bc") cannot hash alike.
    h.update(u32::try_from(bytes.len()).unwrap_or(u32::MAX).to_be_bytes());
    h.update(bytes);
}

fn put_opt(h: &mut Sha256, value: Option<&str>) {
    match value {
        None => h.update([0u8]),
        Some(s) => {
            h.update([1u8]);
            put_bytes(h, s.as_bytes());
        }
    }
}

/// Compute an entry's hash from its fields and the previous hash.
#[allow(clippy::too_many_arguments)]
pub fn entry_hash(
    prev_hash: &Hash,
    seq: u64,
    at_micros: i64,
    actor: Option<&str>,
    action: &str,
    target: Option<&str>,
    outcome: &str,
    details: &str,
) -> Hash {
    let mut h = Sha256::new();
    h.update(b"falak-audit-v1\0");
    h.update(prev_hash);
    h.update(seq.to_be_bytes());
    h.update(at_micros.to_be_bytes());
    put_opt(&mut h, actor);
    put_bytes(&mut h, action.as_bytes());
    put_opt(&mut h, target);
    put_bytes(&mut h, outcome.as_bytes());
    put_bytes(&mut h, details.as_bytes());
    h.finalize().into()
}

impl Entry {
    /// Build the next entry after `prev` (or the first, if `None`).
    pub fn next(
        prev: Option<&Entry>,
        at_micros: i64,
        actor: Option<String>,
        action: String,
        target: Option<String>,
        outcome: String,
        details: String,
    ) -> Entry {
        let (seq, prev_hash) = prev.map_or((1, GENESIS), |p| (p.seq + 1, p.hash));
        let hash = entry_hash(
            &prev_hash,
            seq,
            at_micros,
            actor.as_deref(),
            &action,
            target.as_deref(),
            &outcome,
            &details,
        );
        Entry {
            seq,
            at_micros,
            actor,
            action,
            target,
            outcome,
            details,
            prev_hash,
            hash,
        }
    }

    fn recompute(&self) -> Hash {
        entry_hash(
            &self.prev_hash,
            self.seq,
            self.at_micros,
            self.actor.as_deref(),
            &self.action,
            self.target.as_deref(),
            &self.outcome,
            &self.details,
        )
    }
}

/// The newest entry's position and hash at some moment. Store it outside the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Anchor {
    pub seq: u64,
    pub hash: Hash,
}

/// Why a check failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Problem {
    /// The first entry does not start from the genesis hash, or is not seq 1 (when the
    /// copy is meant to start at the beginning).
    BadStart,
    /// Sequence numbers are not consecutive.
    Gap,
    /// An entry's `prev_hash` is not the previous entry's hash.
    BrokenLink,
    /// An entry's hash does not match its contents.
    Altered,
    /// The log is shorter than the anchor says, or has a different entry at the
    /// anchor's position.
    DoesNotReachAnchor,
}

/// Where and what.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Failure {
    pub seq: u64,
    pub problem: Problem,
}

/// Check a run of entries. `entries` must be in order. If it starts at seq 1 it must
/// start from the genesis hash; a later start is allowed (a page of the log) and its first
/// `prev_hash` is trusted only as far as the entries after it agree with it.
///
/// With an `anchor`, the run must also contain the anchor's entry with the same hash,
/// which detects a log that was truncated or rewritten.
pub fn verify(entries: &[Entry], anchor: Option<&Anchor>) -> Result<(), Failure> {
    let mut prev: Option<&Entry> = None;
    for e in entries {
        match prev {
            None => {
                if e.seq == 1 && e.prev_hash != GENESIS {
                    return Err(Failure {
                        seq: e.seq,
                        problem: Problem::BadStart,
                    });
                }
            }
            Some(p) => {
                if e.seq != p.seq + 1 {
                    return Err(Failure {
                        seq: e.seq,
                        problem: Problem::Gap,
                    });
                }
                if e.prev_hash != p.hash {
                    return Err(Failure {
                        seq: e.seq,
                        problem: Problem::BrokenLink,
                    });
                }
            }
        }
        if e.hash != e.recompute() {
            return Err(Failure {
                seq: e.seq,
                problem: Problem::Altered,
            });
        }
        prev = Some(e);
    }
    if let Some(a) = anchor {
        let found = entries.iter().find(|e| e.seq == a.seq);
        if found.is_none_or(|e| e.hash != a.hash) {
            return Err(Failure {
                seq: a.seq,
                problem: Problem::DoesNotReachAnchor,
            });
        }
    }
    Ok(())
}

/// Lowercase hex, for storage and display.
pub fn to_hex(hash: &Hash) -> String {
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse lowercase or uppercase hex into a hash.
pub fn from_hex(text: &str) -> Option<Hash> {
    if text.len() != 64 || !text.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain(n: usize) -> Vec<Entry> {
        let mut v: Vec<Entry> = Vec::new();
        for i in 0..n {
            let e = Entry::next(
                v.last(),
                1_000 + i as i64,
                Some(format!("user{i}")),
                "login".into(),
                None,
                "ok".into(),
                "{}".into(),
            );
            v.push(e);
        }
        v
    }

    #[test]
    fn a_good_chain_verifies() {
        let c = chain(5);
        assert_eq!(c[0].seq, 1);
        assert_eq!(c[0].prev_hash, GENESIS);
        assert_eq!(verify(&c, None), Ok(()));
        assert_eq!(verify(&[], None), Ok(()));
    }

    #[test]
    fn editing_any_field_is_detected() {
        let edits: [fn(&mut Entry); 6] = [
            |e| e.actor = Some("someone-else".into()),
            |e| e.action = "logout".into(),
            |e| e.target = Some("x".into()),
            |e| e.outcome = "denied".into(),
            |e| e.details = "{\"a\":1}".into(),
            |e| e.at_micros += 1,
        ];
        for edit in edits {
            let mut c = chain(5);
            edit(&mut c[2]);
            assert_eq!(
                verify(&c, None),
                Err(Failure {
                    seq: 3,
                    problem: Problem::Altered
                })
            );
        }
    }

    #[test]
    fn a_rewritten_entry_with_a_fresh_hash_breaks_the_next_link() {
        let mut c = chain(5);
        c[2].action = "logout".into();
        c[2].hash = c[2].recompute();
        assert_eq!(
            verify(&c, None),
            Err(Failure {
                seq: 4,
                problem: Problem::BrokenLink
            })
        );
    }

    #[test]
    fn deleting_inserting_or_reordering_is_detected() {
        let mut c = chain(5);
        c.remove(2);
        assert_eq!(
            verify(&c, None),
            Err(Failure {
                seq: 4,
                problem: Problem::Gap
            })
        );

        let mut c = chain(5);
        c.swap(1, 2);
        assert!(verify(&c, None).is_err());

        let mut c = chain(5);
        let dup = c[2].clone();
        c.insert(3, dup);
        assert!(verify(&c, None).is_err());
    }

    #[test]
    fn the_first_entry_must_start_at_genesis() {
        let mut c = chain(3);
        c[0].prev_hash = [9; 32];
        c[0].hash = c[0].recompute();
        assert_eq!(
            verify(&c, None),
            Err(Failure {
                seq: 1,
                problem: Problem::BadStart
            })
        );
    }

    #[test]
    fn a_page_from_the_middle_verifies_on_its_own() {
        let c = chain(6);
        assert_eq!(verify(&c[2..5], None), Ok(()));
    }

    #[test]
    fn field_boundaries_cannot_be_shifted() {
        let a = entry_hash(&GENESIS, 1, 0, Some("ab"), "c", None, "ok", "{}");
        let b = entry_hash(&GENESIS, 1, 0, Some("a"), "bc", None, "ok", "{}");
        assert_ne!(a, b);
        // None and the empty string differ.
        let none = entry_hash(&GENESIS, 1, 0, None, "x", None, "ok", "{}");
        let empty = entry_hash(&GENESIS, 1, 0, Some(""), "x", None, "ok", "{}");
        assert_ne!(none, empty);
    }

    #[test]
    fn an_anchor_catches_truncation_and_rewrites() {
        let c = chain(5);
        let anchor = Anchor {
            seq: 5,
            hash: c[4].hash,
        };
        assert_eq!(verify(&c, Some(&anchor)), Ok(()));
        // Cut the tail off.
        assert_eq!(
            verify(&c[..3], Some(&anchor)),
            Err(Failure {
                seq: 5,
                problem: Problem::DoesNotReachAnchor
            })
        );
        // Rebuild the whole log from the start with a different history.
        let mut forged: Vec<Entry> = Vec::new();
        for i in 0..5 {
            forged.push(Entry::next(
                forged.last(),
                9_000 + i,
                None,
                "other".into(),
                None,
                "ok".into(),
                "{}".into(),
            ));
        }
        assert_eq!(
            verify(&forged, None),
            Ok(()),
            "a forged chain is internally consistent"
        );
        assert_eq!(
            verify(&forged, Some(&anchor)),
            Err(Failure {
                seq: 5,
                problem: Problem::DoesNotReachAnchor
            })
        );
    }

    #[test]
    fn hex_round_trip() {
        let h = chain(1)[0].hash;
        assert_eq!(from_hex(&to_hex(&h)), Some(h));
        assert_eq!(from_hex("zz"), None);
        assert_eq!(from_hex(&"g".repeat(64)), None);
    }
}
