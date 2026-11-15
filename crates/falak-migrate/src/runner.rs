//! Migration runner that provisions tables, applies plans, and tracks history.

use falak_contracts::{
    Result,
    driver::{Statement, StorageDriver, Value},
    identity::RequestContext,
    ir::Ir,
};
use falak_core::sql::Dialect;

use crate::{
    history::{MIGRATIONS_TABLE, ensure_history_table, record_migration_statement},
    lock::migration_lock_statement,
    plan::{MigrationPhase, MigrationPlan, plan_migration},
};

pub fn dialect_for_driver<D: StorageDriver>(driver: &D) -> Dialect {
    match driver.profile().name {
        "postgres" => Dialect::Postgres,
        "d1" => Dialect::D1,
        _ => Dialect::Sqlite,
    }
}

/// Apply initial migrations from an IR if not already applied.
///
/// Returns `Ok(true)` if tables were created, or `Ok(false)` if already up to date.
pub async fn apply_initial_migration<D: StorageDriver>(
    driver: &D,
    ctx: &RequestContext,
    ir: &Ir,
) -> Result<bool> {
    let dialect = dialect_for_driver(driver);

    // 1. Ensure `_falak_migrations` table exists
    ensure_history_table(driver, ctx, dialect).await?;

    // 2. Check if this content hash has already been migrated
    let placeholder = match dialect {
        Dialect::Postgres => "$1",
        _ => "?",
    };
    let check_stmt = Statement::new(
        format!(
            "SELECT \"content_hash\" FROM \"{MIGRATIONS_TABLE}\" WHERE \"content_hash\" = {placeholder};"
        ),
        vec![Value::Text(ir.content_hash.clone())],
    );
    let rows = driver.query(ctx, check_stmt).await?;
    if !rows.rows.is_empty() {
        return Ok(false);
    }

    // 3. Plan the initial migration
    let plan = plan_migration(None, ir, dialect);

    // 4. Build execution batch (with advisory lock statement if Postgres)
    let mut batch_stmts = Vec::new();
    if let Some(lock_stmt) = migration_lock_statement(dialect) {
        batch_stmts.push(lock_stmt);
    }

    for stmt in plan.expand_statements() {
        batch_stmts.push(Statement::new(stmt.sql.clone(), vec![]));
    }

    // 5. Append migration record with checksum
    let record_stmt = record_migration_statement(
        ir.ir_version as i64,
        &ir.content_hash,
        &plan.checksum,
        dialect,
    );
    batch_stmts.push(record_stmt);

    // 6. Execute atomically
    driver.batch(ctx, batch_stmts).await?;

    Ok(true)
}

/// Apply a planned migration phase (Expand or Contract).
pub async fn apply_migration_phase<D: StorageDriver>(
    driver: &D,
    ctx: &RequestContext,
    plan: &MigrationPlan,
    phase: MigrationPhase,
    version: i64,
) -> Result<()> {
    let dialect = dialect_for_driver(driver);
    ensure_history_table(driver, ctx, dialect).await?;

    let stmts = match phase {
        MigrationPhase::Expand => plan.expand_statements(),
        MigrationPhase::Contract => plan.contract_statements(),
    };

    if stmts.is_empty() {
        return Ok(());
    }

    let mut batch_stmts = Vec::new();
    if let Some(lock_stmt) = migration_lock_statement(dialect) {
        batch_stmts.push(lock_stmt);
    }

    for stmt in stmts {
        batch_stmts.push(Statement::new(stmt.sql.clone(), vec![]));
    }

    if phase == MigrationPhase::Expand {
        let record_stmt =
            record_migration_statement(version, &plan.to_hash, &plan.checksum, dialect);
        batch_stmts.push(record_stmt);
    }

    driver.batch(ctx, batch_stmts).await?;
    Ok(())
}
