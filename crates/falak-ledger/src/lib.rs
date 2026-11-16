//! Double-entry ledger (Phase 8).
//!
//! * [`command`]: the commands (`transfer`, `reserve`, `capture`, `release`, `reverse`,
//!   `settle`) and the pure planning that turns each into balanced postings, with checked
//!   arithmetic and currency checks. No database, so it is fully unit tested.
//! * [`schema`]: the PostgreSQL schema: append-only tables, a deferred balance
//!   constraint, a deferred no-overdraft constraint and the idempotency table.
//! * [`pg`]: execution under `SERIALIZABLE` with bounded retries.
//! * [`reconcile`]: statement lines, CSV import and the reconciliation report.
//!
//! Money is `i64` minor units. There is no floating point anywhere in this crate.

#![allow(async_fn_in_trait)]

pub mod command;
pub mod money;
pub mod pg;
pub mod reconcile;
pub mod schema;

pub use command::{Command, Plan, Posting};
pub use money::Currency;
pub use pg::{Invariants, Ledger, LedgerConfig, Posted};
