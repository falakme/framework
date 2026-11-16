//! Double-entry ledger (Phase 8).
//!
//! * [`command`]: the commands (`transfer`, `reserve`, `capture`, `release`, `reverse`,
//!   `settle`) and the pure planning that turns each into balanced postings, with checked
//!   arithmetic and currency checks. No database, so it is fully unit tested.
//! * [`reconcile`]: statement lines, CSV import and the reconciliation report.
//!
//! Money is `i64` minor units. There is no floating point anywhere in this crate.

#![allow(async_fn_in_trait)]

pub mod command;
pub mod money;
pub mod reconcile;

pub use command::{Command, Plan, Posting};
pub use money::Currency;
