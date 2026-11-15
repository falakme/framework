//! Cloudflare D1 storage driver.
//!
//! * [`D1Driver`] implements the `StorageDriver` contract. D1 offers atomic batches and
//!   no interactive transactions, so `begin` returns `Unsupported`.
//! * [`D1Binding`] is the seam to Cloudflare. On `wasm32`, `WorkerD1` implements it
//!   with `workers-rs` and the D1 Sessions API. On native targets only the portable
//!   logic is built, which is what the tests exercise.
//! * Limits and behaviour are taken from `specifications/CLOUDFLARE_LIMITS.md`.
//!
//! Known limits of this driver:
//! * `Int64` and timestamps beyond ±(2^53 − 1) are refused, because the Workers
//!   binding passes numbers as JavaScript doubles. A ledger that needs larger minor
//!   units must store them another way (Phase 8).
//! * A result number with no fractional part comes back as `Int64`, because D1 does
//!   not return column types. The core coerces by the type declared in the IR.

// Workers futures are not `Send`, so the traits carry no `Send` bound (as in falak-contracts).
#![allow(async_fn_in_trait)]

pub mod convert;
pub mod driver;
pub mod error;
pub mod validate;

#[cfg(target_arch = "wasm32")]
mod worker_binding;

pub use driver::{BoundStatement, D1Binding, D1Driver, NoTransaction, RawResult};
#[cfg(target_arch = "wasm32")]
pub use worker_binding::WorkerD1;

use falak_contracts::{Error, Result};

/// Where a request's D1 session starts.
///
/// D1 read replication serves reads from a nearby replica that may lag. A bookmark from
/// an earlier response forces this request to read at least that fresh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionStart {
    /// The first query goes to the primary database. Use after login or any write the
    /// caller must see.
    FirstPrimary,
    /// The first query may use any replica. Lowest latency.
    FirstUnconstrained,
    /// Continue after a previous response. Built with [`SessionStart::from_bookmark`].
    Bookmark(String),
}

/// Longest bookmark accepted. Real bookmarks are about 60 characters.
const MAX_BOOKMARK_LEN: usize = 128;

impl SessionStart {
    /// Accept a bookmark a client sent back. Clients are untrusted, so the value is
    /// checked before it reaches D1: letters, digits, `-`, `_` and `.` only.
    pub fn from_bookmark(value: &str) -> Result<Self> {
        let valid = !value.is_empty()
            && value.len() <= MAX_BOOKMARK_LEN
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
        if valid {
            Ok(Self::Bookmark(value.to_owned()))
        } else {
            Err(Error::invalid_input(
                "invalid_bookmark",
                "The consistency bookmark is not valid.",
            ))
        }
    }

    /// The string D1's `withSession` expects.
    pub fn as_str(&self) -> &str {
        match self {
            Self::FirstPrimary => "first-primary",
            Self::FirstUnconstrained => "first-unconstrained",
            Self::Bookmark(b) => b,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bookmark_accepts_the_d1_format() {
        let b = "00000085-0000024c-00004c6d-8e61117bf38d7adb71b934ebbf891683";
        assert_eq!(SessionStart::from_bookmark(b).unwrap().as_str(), b);
    }

    #[test]
    fn bookmark_rejects_junk() {
        for bad in ["", "a b", "x;DROP", "a\nb", &"a".repeat(129), "é"] {
            assert!(SessionStart::from_bookmark(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn constraints_use_the_d1_names() {
        assert_eq!(SessionStart::FirstPrimary.as_str(), "first-primary");
        assert_eq!(
            SessionStart::FirstUnconstrained.as_str(),
            "first-unconstrained"
        );
    }
}
