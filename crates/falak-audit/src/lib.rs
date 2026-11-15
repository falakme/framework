//! Hash-chained, append-only audit log (T3.13).
//!
//! * [`chain`]: the entry format, the hash chain and `verify`.
//! * [`log`]: the log stored through a `StorageDriver`, with triggers that refuse edits.
//!
//! Record: authentication events, policy denials, admin actions, key operations,
//! migrations and break-glass use. Keep personal data and secrets out of `details`.

// Workers futures are not `Send`, so nothing here adds a `Send` bound.
#![allow(async_fn_in_trait)]

pub mod chain;
pub mod log;

pub use chain::{Anchor, Entry, Failure, Problem, verify};
pub use log::{AuditLog, Placeholders, VerifyError};
