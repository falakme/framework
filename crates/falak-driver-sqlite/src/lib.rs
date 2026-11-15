//! SQLite storage driver for Falak.
//!
//! Provides a single dedicated writer connection and a reader pool with WAL mode,
//! `busy_timeout` configuration, and `BEGIN IMMEDIATE` transaction execution.

pub mod convert;
pub mod driver;
pub mod error;

pub use driver::{SqliteConfig, SqliteDriver, SqliteTx};
