//! Migration planning and application for Falak.
//!
//! Provides DDL schema execution, expand-and-contract planning, advisory locking,
//! checksum verification, and drift detection for SQLite, PostgreSQL, and D1.

pub mod diff;
pub mod history;
pub mod lock;
pub mod plan;
pub mod runner;

pub use diff::{IndexSpec, SchemaDiff, diff_ir};
pub use history::{
    MIGRATIONS_TABLE, MigrationRecord, detect_drift, ensure_history_table, fetch_history,
};
pub use lock::{acquire_migration_lock, migration_lock_statement};
pub use plan::{
    Destructiveness, LockImpact, MigrationPhase, MigrationPlan, PlannedStatement, plan_migration,
};
pub use runner::{
    MigrateOptions, MigrateOutcome, SCHEMA_TABLE, apply_initial_migration, apply_migration_phase,
    dialect_for_driver, latest_ir, migrate, plan_to,
};
