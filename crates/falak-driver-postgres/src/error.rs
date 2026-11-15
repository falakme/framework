//! Error mapping for PostgreSQL and SQLx.

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
            "postgres_pool_timeout",
            "Database connection pool timed out.",
        )
        .with_source(err),
        sqlx::Error::PoolClosed => Error::new(
            ErrorKind::Unavailable,
            "postgres_pool_closed",
            "Database connection pool is closed.",
        )
        .with_source(err),
        sqlx::Error::RowNotFound => {
            Error::new(ErrorKind::NotFound, "not_found", "Not found.").with_source(err)
        }
        _ => Error::new(
            ErrorKind::Internal,
            "postgres_internal",
            "Database operation failed.",
        )
        .with_source(err),
    }
}

/// Map a PostgreSQL SQLSTATE error code.
fn map_database_error(code_opt: Option<&str>, message: &str, source: sqlx::Error) -> Error {
    let code = code_opt.unwrap_or_default();

    // SQLSTATE mapping according to DRIVER_SPECIFICATION §6.3:
    // 55P03 = lock_not_available -> Unavailable
    // 40P01 = deadlock_detected -> Conflict
    // 40001 = serialization_failure -> Conflict
    // 57014 = query_canceled -> Timeout
    // 23505 = unique_violation -> Conflict
    // 23503 = foreign_key_violation -> InvalidInput
    // 23514 = check_violation -> InvalidInput
    // 22003 = numeric_value_out_of_range -> InvalidInput
    // 23502 = not_null_violation -> InvalidInput
    match code {
        "55P03" => Error::new(
            ErrorKind::Unavailable,
            "postgres_lock_not_available",
            "Lock not available. Retry shortly.",
        )
        .with_source(source),
        "40P01" => Error::new(
            ErrorKind::Conflict,
            "postgres_deadlock_detected",
            "Deadlock detected. Transaction aborted.",
        )
        .with_source(source),
        "40001" => Error::new(
            ErrorKind::Conflict,
            "postgres_serialization_failure",
            "Could not serialize access due to concurrent update.",
        )
        .with_source(source),
        "57014" => Error::new(
            ErrorKind::Timeout,
            "postgres_query_canceled",
            "Query was canceled or timed out.",
        )
        .with_source(source),
        "23505" => Error::new(
            ErrorKind::Conflict,
            "unique_violation",
            "A record with this identifier already exists.",
        )
        .with_source(source),
        "23503" | "23514" | "22003" | "23502" => Error::new(
            ErrorKind::InvalidInput,
            "constraint_violation",
            "Database constraint violation.",
        )
        .with_source(source),
        _ => Error::new(
            ErrorKind::Internal,
            "postgres_error",
            format!("Database error: {message}"),
        )
        .with_source(source),
    }
}
