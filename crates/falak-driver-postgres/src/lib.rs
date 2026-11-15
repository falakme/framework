//! PostgreSQL storage driver for Falak.
//!
//! Provides SQLx connection pooling, per-request transaction execution,
//! and session variable context setting for Row-Level Security (`falak.tenant_id`, `falak.subject`).

pub mod convert;
pub mod driver;
pub mod error;

pub use driver::{PostgresConfig, PostgresDriver, PostgresTx};
