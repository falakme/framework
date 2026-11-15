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

// ---------------------------------------------------------------- snapshots and `migrate`

/// Holds the IR each applied migration produced, so the next migration can be planned
/// from what the database actually has.
pub const SCHEMA_TABLE: &str = "_falak_schema";

async fn ensure_schema_table<D: StorageDriver>(
    driver: &D,
    ctx: &RequestContext,
    dialect: Dialect,
) -> Result<()> {
    let (text, time) = if dialect == Dialect::Postgres {
        ("text", "timestamptz")
    } else {
        ("TEXT", "INTEGER")
    };
    let sql = format!(
        "CREATE TABLE IF NOT EXISTS \"{SCHEMA_TABLE}\" (\"content_hash\" {text} NOT NULL PRIMARY KEY, \"ir\" {text} NOT NULL, \"applied_at\" {time} NOT NULL)"
    );
    driver.batch(ctx, vec![Statement::new(sql, vec![])]).await?;
    Ok(())
}

fn snapshot_statement(ir: &Ir, dialect: Dialect) -> Result<Statement> {
    let json = serde_json::to_string(ir)
        .map_err(|e| falak_contracts::Error::internal(format!("cannot save the schema: {e}")))?;
    let (sql, at) = match dialect {
        Dialect::Postgres => (
            format!(
                "INSERT INTO \"{SCHEMA_TABLE}\" (\"content_hash\", \"ir\", \"applied_at\") VALUES ($1, $2, $3)"
            ),
            Value::TimestampMicros(falak_contracts::support::wall_clock_micros()),
        ),
        _ => (
            format!(
                "INSERT INTO \"{SCHEMA_TABLE}\" (\"content_hash\", \"ir\", \"applied_at\") VALUES (?, ?, ?)"
            ),
            Value::TimestampMicros(falak_contracts::support::wall_clock_micros()),
        ),
    };
    Ok(Statement::new(
        sql,
        vec![Value::Text(ir.content_hash.clone()), Value::Text(json), at],
    ))
}

/// The IR of the most recently applied migration, if the database has one.
pub async fn latest_ir<D: StorageDriver>(driver: &D, ctx: &RequestContext) -> Result<Option<Ir>> {
    let dialect = dialect_for_driver(driver);
    ensure_schema_table(driver, ctx, dialect).await?;
    let rows = driver
        .query(
            ctx,
            Statement::new(
                format!(
                    "SELECT \"ir\" FROM \"{SCHEMA_TABLE}\" ORDER BY \"applied_at\" DESC LIMIT 1"
                ),
                vec![],
            ),
        )
        .await?;
    let Some(Value::Text(json)) = rows.rows.first().and_then(|r| r.first()) else {
        return Ok(None);
    };
    serde_json::from_str(json).map(Some).map_err(|e| {
        falak_contracts::Error::internal(format!("the saved schema is unreadable: {e}"))
    })
}

/// What `migrate` may do without being told.
#[derive(Debug, Clone, Copy, Default)]
pub struct MigrateOptions {
    /// Allow statements rated `Caution` or `Breaking`: table rebuilds, dropped columns
    /// and tables, type changes.
    pub allow_destructive: bool,
}

#[derive(Debug, Clone)]
pub struct MigrateOutcome {
    /// `false` when the database already has this version of the app.
    pub applied: bool,
    pub plan: MigrationPlan,
}

fn migrate_error(code: &'static str, message: String) -> falak_contracts::Error {
    falak_contracts::Error::new(falak_contracts::ErrorKind::Conflict, code, message)
}

/// The plan to bring the database to `ir`, from the schema it has now. Nothing is run.
pub async fn plan_to<D: StorageDriver>(
    driver: &D,
    ctx: &RequestContext,
    ir: &Ir,
) -> Result<MigrationPlan> {
    let dialect = dialect_for_driver(driver);
    ensure_history_table(driver, ctx, dialect).await?;
    let applied = crate::history::fetch_history(driver, ctx, dialect).await?;
    let previous = latest_ir(driver, ctx).await?;
    if previous.is_none() && !applied.is_empty() {
        return Err(migrate_error(
            "schema_unknown",
            "this database was set up before schema snapshots existed, so the changes cannot be planned. Export the data and start from a new database"
                .to_owned(),
        ));
    }
    Ok(plan_migration(previous.as_ref(), ir, dialect))
}

/// Bring the database to `ir`: the first version creates the tables, later versions
/// apply the planned change. One atomic batch under the migration lock, recorded with
/// its checksum and a snapshot of the schema.
///
/// Refuses a plan with changes it cannot make safely, and (unless allowed) one with
/// rebuilds, drops or type changes. A second runner that races this one finds the
/// version already recorded and does nothing.
pub async fn migrate<D: StorageDriver>(
    driver: &D,
    ctx: &RequestContext,
    ir: &Ir,
    options: MigrateOptions,
) -> Result<MigrateOutcome> {
    let dialect = dialect_for_driver(driver);
    ensure_history_table(driver, ctx, dialect).await?;
    ensure_schema_table(driver, ctx, dialect).await?;

    let placeholder = if dialect == Dialect::Postgres {
        "$1"
    } else {
        "?"
    };
    let seen = |rows: falak_contracts::driver::Rows| !rows.rows.is_empty();
    let check = Statement::new(
        format!(
            "SELECT \"content_hash\" FROM \"{MIGRATIONS_TABLE}\" WHERE \"content_hash\" = {placeholder}"
        ),
        vec![Value::Text(ir.content_hash.clone())],
    );
    if seen(driver.query(ctx, check.clone()).await?) {
        return Ok(MigrateOutcome {
            applied: false,
            plan: plan_migration(Some(ir), ir, dialect),
        });
    }

    let plan = plan_to(driver, ctx, ir).await?;
    if !plan.unsupported.is_empty() {
        return Err(migrate_error(
            "migration_unsupported",
            format!(
                "this change needs a hand written migration: {}",
                plan.unsupported.join("; ")
            ),
        ));
    }
    if !options.allow_destructive {
        let risky: Vec<&str> = plan
            .statements
            .iter()
            .filter(|s| s.destructiveness != crate::plan::Destructiveness::Safe)
            .map(|s| s.description.as_str())
            .collect();
        if !risky.is_empty() {
            return Err(migrate_error(
                "migration_needs_approval",
                format!(
                    "this change rebuilds, drops or retypes data and needs approval (run `falak migrate apply --allow-destructive`): {}",
                    risky.join("; ")
                ),
            ));
        }
    }

    let mut batch = Vec::new();
    if let Some(lock) = migration_lock_statement(dialect) {
        batch.push(lock);
    }
    for s in &plan.statements {
        batch.push(Statement::new(s.sql.clone(), vec![]));
    }
    batch.push(record_migration_statement(
        i64::from(ir.ir_version),
        &ir.content_hash,
        &plan.checksum,
        dialect,
    ));
    batch.push(snapshot_statement(ir, dialect)?);

    match driver.batch(ctx, batch).await {
        Ok(_) => Ok(MigrateOutcome {
            applied: true,
            plan,
        }),
        Err(e) => {
            // Another runner may have applied this version while we planned it.
            if seen(driver.query(ctx, check).await?) {
                Ok(MigrateOutcome {
                    applied: false,
                    plan,
                })
            } else {
                Err(e)
            }
        }
    }
}
