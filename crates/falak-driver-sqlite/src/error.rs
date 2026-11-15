//! Error mapping for SQLite and SQLx.

use falak_contracts::{Error, ErrorKind};

/// Map a SQLx error to a standardized `falak_contracts::Error`.
pub fn map_sqlx_error(err: sqlx::Error) -> Error {
    match err {
        sqlx::Error::Database(db_err) => {
            let code = db_err.code().map(|s| s.to_string());
            let message = db_err.message().to_string();
            map_database_error(code.as_deref(), &message, sqlx::Error::Database(db_err))
        }
        sqlx::Error::PoolTimedOut => Error::new(
            ErrorKind::Timeout,
            "sqlite_pool_timeout",
            "Database connection pool timed out.",
        )
        .with_source(err),
        sqlx::Error::PoolClosed => Error::new(
            ErrorKind::Unavailable,
            "sqlite_pool_closed",
            "Database connection pool is closed.",
        )
        .with_source(err),
        sqlx::Error::RowNotFound => {
            Error::new(ErrorKind::NotFound, "not_found", "Not found.").with_source(err)
        }
        _ => Error::new(
            ErrorKind::Internal,
            "sqlite_internal",
            "Database operation failed.",
        )
        .with_source(err),
    }
}

/// Map a database-level error using SQLite error codes.
fn map_database_error(code_opt: Option<&str>, message: &str, source: sqlx::Error) -> Error {
    let code = code_opt.unwrap_or_default();

    // SQLite primary and extended result codes:
    // 5 = SQLITE_BUSY, 6 = SQLITE_LOCKED, 261 = SQLITE_BUSY_RECOVERY, 517 = SQLITE_BUSY_SNAPSHOT
    // 19 = SQLITE_CONSTRAINT, 2067 = SQLITE_CONSTRAINT_UNIQUE, 1555 = SQLITE_CONSTRAINT_PRIMARYKEY
    // 787 = SQLITE_CONSTRAINT_FOREIGNKEY, 275 = SQLITE_CONSTRAINT_CHECK, 1299 = SQLITE_CONSTRAINT_NOTNULL
    // 18 = SQLITE_TOOBIG
    if code == "5"
        || code == "6"
        || code == "261"
        || code == "517"
        || message.contains("busy")
        || message.contains("locked")
    {
        Error::new(
            ErrorKind::Unavailable,
            "sqlite_busy",
            "Database is temporarily busy. Retry shortly.",
        )
        .with_source(source)
    } else if code == "2067"
        || code == "1555"
        || (code == "19"
            && (message.contains("UNIQUE")
                || message.contains("PRIMARY KEY")
                || message.contains("unique")))
    {
        Error::new(
            ErrorKind::Conflict,
            "unique_violation",
            "A record with this identifier already exists.",
        )
        .with_source(source)
    } else if code == "787"
        || code == "275"
        || code == "1299"
        || code == "19"
        || code == "18"
        || message.contains("FOREIGN KEY")
        || message.contains("CHECK")
        || message.contains("NOT NULL")
    {
        Error::new(
            ErrorKind::InvalidInput,
            "constraint_violation",
            "Database constraint violation.",
        )
        .with_source(source)
    } else {
        Error::new(
            ErrorKind::Internal,
            "sqlite_error",
            "Database error encountered.",
        )
        .with_source(source)
    }
}
