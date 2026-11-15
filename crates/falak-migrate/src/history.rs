//! Migration history tracking and drift detection.

use falak_contracts::{
    Error, ErrorKind, Result,
    driver::{Statement, StorageDriver, Value},
    identity::RequestContext,
};
use falak_core::sql::Dialect;
use serde::{Deserialize, Serialize};

pub const MIGRATIONS_TABLE: &str = "_falak_migrations";

/// A recorded migration in `_falak_migrations`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationRecord {
    pub version: i64,
    pub content_hash: String,
    pub checksum: String,
    pub applied_at: i64,
}

/// Ensure that `_falak_migrations` table exists with checksum support.
pub async fn ensure_history_table<D: StorageDriver>(
    driver: &D,
    ctx: &RequestContext,
    dialect: Dialect,
) -> Result<()> {
    let stmt = match dialect {
        Dialect::Postgres => Statement::new(
            format!(
                "CREATE TABLE IF NOT EXISTS \"{MIGRATIONS_TABLE}\" (
                    \"version\" bigint NOT NULL,
                    \"content_hash\" text NOT NULL PRIMARY KEY,
                    \"checksum\" text NOT NULL DEFAULT '',
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
                    \"checksum\" TEXT NOT NULL DEFAULT '',
                    \"applied_at\" INTEGER NOT NULL
                );"
            ),
            vec![],
        ),
    };
    driver.batch(ctx, vec![stmt]).await?;
    Ok(())
}

/// Fetch all applied migration records from `_falak_migrations`.
pub async fn fetch_history<D: StorageDriver>(
    driver: &D,
    ctx: &RequestContext,
    dialect: Dialect,
) -> Result<Vec<MigrationRecord>> {
    ensure_history_table(driver, ctx, dialect).await?;

    let sql = format!(
        "SELECT \"version\", \"content_hash\", \"checksum\", \"applied_at\" FROM \"{MIGRATIONS_TABLE}\" ORDER BY \"version\" ASC, \"applied_at\" ASC;"
    );
    let rows = driver.query(ctx, Statement::new(sql, vec![])).await?;

    let mut records = Vec::with_capacity(rows.rows.len());
    for row in rows.rows {
        if row.len() < 4 {
            continue;
        }
        let version = match &row[0] {
            Value::Int64(i) => *i,
            _ => 0,
        };
        let content_hash = match &row[1] {
            Value::Text(s) => s.clone(),
            _ => String::new(),
        };
        let checksum = match &row[2] {
            Value::Text(s) => s.clone(),
            _ => String::new(),
        };
        let applied_at = match &row[3] {
            Value::TimestampMicros(t) => *t,
            Value::Int64(i) => *i,
            _ => 0,
        };

        records.push(MigrationRecord {
            version,
            content_hash,
            checksum,
            applied_at,
        });
    }

    Ok(records)
}

/// Verify that applied database migrations have not drifted from expected history.
pub fn detect_drift(applied: &[MigrationRecord], expected: &[MigrationRecord]) -> Result<()> {
    for (i, app) in applied.iter().enumerate() {
        if i >= expected.len() {
            return Err(Error::new(
                ErrorKind::Conflict,
                "migration_drift",
                format!(
                    "Database has extra applied migration `{}` not in expected plan",
                    app.content_hash
                ),
            ));
        }
        let exp = &expected[i];
        if app.content_hash != exp.content_hash {
            return Err(Error::new(
                ErrorKind::Conflict,
                "migration_drift",
                format!(
                    "Migration history mismatch at step {i}: expected hash `{}`, found `{}`",
                    exp.content_hash, app.content_hash
                ),
            ));
        }
        if !exp.checksum.is_empty() && !app.checksum.is_empty() && app.checksum != exp.checksum {
            return Err(Error::new(
                ErrorKind::Conflict,
                "migration_drift",
                format!(
                    "Migration checksum drift for `{}`: expected checksum `{}`, found `{}`",
                    app.content_hash, exp.checksum, app.checksum
                ),
            ));
        }
    }
    Ok(())
}

/// Helper to generate record migration statement.
pub fn record_migration_statement(
    version: i64,
    content_hash: &str,
    checksum: &str,
    dialect: Dialect,
) -> Statement {
    let now_micros = falak_contracts::support::wall_clock_micros();

    let (insert_sql, val) = match dialect {
        Dialect::Postgres => (
            format!(
                "INSERT INTO \"{MIGRATIONS_TABLE}\" (\"version\", \"content_hash\", \"checksum\", \"applied_at\") VALUES ($1, $2, $3, $4);"
            ),
            Value::TimestampMicros(now_micros),
        ),
        _ => (
            format!(
                "INSERT INTO \"{MIGRATIONS_TABLE}\" (\"version\", \"content_hash\", \"checksum\", \"applied_at\") VALUES (?, ?, ?, ?);"
            ),
            Value::TimestampMicros(now_micros),
        ),
    };

    Statement::new(
        insert_sql,
        vec![
            Value::Int64(version),
            Value::Text(content_hash.to_string()),
            Value::Text(checksum.to_string()),
            val,
        ],
    )
}
