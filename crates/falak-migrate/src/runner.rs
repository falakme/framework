//! Migration runner that provisions tables and tracks history in `_falak_migrations`.

use std::time::{SystemTime, UNIX_EPOCH};

use falak_contracts::{
    Result,
    driver::{Statement, StorageDriver, Value},
    identity::RequestContext,
    ir::Ir,
};
use falak_core::{ddl::create_all, sql::Dialect};

pub const MIGRATIONS_TABLE: &str = "_falak_migrations";

fn dialect_for_driver<D: StorageDriver>(driver: &D) -> Dialect {
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
    let create_migrations_table = match dialect {
        Dialect::Postgres => Statement::new(
            format!(
                "CREATE TABLE IF NOT EXISTS \"{MIGRATIONS_TABLE}\" (
                    \"version\" bigint NOT NULL,
                    \"content_hash\" text NOT NULL PRIMARY KEY,
                    \"applied_at\" timestamptz NOT NULL
                );"
            ),
            vec![],
        ),
        _ => Statement::new(
            format!(
                "CREATE TABLE IF NOT EXISTS \"{MIGRATIONS_TABLE}\" (
                    \"version\" INTEGER NOT NULL,
                    \"content_hash\" TEXT NOT NULL PRIMARY KEY,
                    \"applied_at\" INTEGER NOT NULL
                );"
            ),
            vec![],
        ),
    };
    driver.batch(ctx, vec![create_migrations_table]).await?;

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

    // 3. Generate DDL for all entities
    let ddl_strings = create_all(ir, dialect);
    let mut ddl_statements: Vec<Statement> = ddl_strings
        .into_iter()
        .map(|sql| Statement::new(sql, vec![]))
        .collect();

    // 4. Record migration entry
    let now_micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as i64;

    let (insert_sql, val) = match dialect {
        Dialect::Postgres => (
            format!(
                "INSERT INTO \"{MIGRATIONS_TABLE}\" (\"version\", \"content_hash\", \"applied_at\") VALUES ($1, $2, $3);"
            ),
            Value::TimestampMicros(now_micros),
        ),
        _ => (
            format!(
                "INSERT INTO \"{MIGRATIONS_TABLE}\" (\"version\", \"content_hash\", \"applied_at\") VALUES (?, ?, ?);"
            ),
            Value::TimestampMicros(now_micros),
        ),
    };

    let record_migration = Statement::new(
        insert_sql,
        vec![
            Value::Int64(ir.ir_version as i64),
            Value::Text(ir.content_hash.clone()),
            val,
        ],
    );
    ddl_statements.push(record_migration);

    // 5. Execute atomically
    driver.batch(ctx, ddl_statements).await?;

    Ok(true)
}
