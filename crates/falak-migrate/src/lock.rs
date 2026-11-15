//! Advisory locks and migration concurrency control.

use falak_contracts::{
    Result,
    driver::{Statement, StorageDriver},
    identity::RequestContext,
};
use falak_core::sql::Dialect;

/// Lock key identifier for Falak migrations in PostgreSQL (64-bit hashtext value).
pub const PG_MIGRATION_LOCK_SQL: &str =
    "SELECT pg_advisory_xact_lock(hashtext('falak_migration_lock'));";

/// Statement to acquire advisory lock before running migrations, depending on dialect.
pub fn migration_lock_statement(dialect: Dialect) -> Option<Statement> {
    match dialect {
        Dialect::Postgres => Some(Statement::new(PG_MIGRATION_LOCK_SQL, vec![])),
        // SQLite uses BEGIN IMMEDIATE on writer connection; D1 uses atomic batches.
        _ => None,
    }
}

/// Helper to acquire migration advisory lock.
pub async fn acquire_migration_lock<D: StorageDriver>(
    driver: &D,
    ctx: &RequestContext,
    dialect: Dialect,
) -> Result<()> {
    if let Some(stmt) = migration_lock_statement(dialect) {
        driver.query(ctx, stmt).await?;
    }
    Ok(())
}
