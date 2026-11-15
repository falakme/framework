//! Migration planning and application for Falak.
//!
//! Provides DDL schema execution and initial migration tracking from the
//! compiled intermediate representation (IR) into SQLite, PostgreSQL, and D1.

pub mod runner;

pub use runner::{MIGRATIONS_TABLE, apply_initial_migration};
