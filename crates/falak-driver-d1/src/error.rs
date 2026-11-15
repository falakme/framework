//! Map D1 failures to the Falak error taxonomy.
//!
//! D1 reports failures as message strings. The raw text can contain SQL and table
//! names, so it is attached as the internal source and never shown to callers.

use falak_contracts::{Error, ErrorKind};

/// Classify a D1 error message. `message` is the vendor text, kept internal.
pub fn map_d1_error(message: &str) -> Error {
    let lower = message.to_ascii_lowercase();
    let (kind, code, public) = if lower.contains("unique constraint failed")
        || lower.contains("primary key constraint failed")
    {
        (
            ErrorKind::Conflict,
            "unique_violation",
            "A record with these values already exists.",
        )
    } else if lower.contains("foreign key constraint failed") {
        (
            ErrorKind::Conflict,
            "foreign_key_violation",
            "The record refers to, or is used by, another record.",
        )
    } else if lower.contains("not null constraint failed")
        || lower.contains("check constraint failed")
    {
        (
            ErrorKind::InvalidInput,
            "constraint_violation",
            "The values violate a rule of the data model.",
        )
    } else if lower.contains("overloaded") {
        (
            ErrorKind::Unavailable,
            "storage_overloaded",
            "The service is busy. Try again shortly.",
        )
    } else if lower.contains("too many api requests") {
        (
            ErrorKind::RateLimited,
            "storage_query_limit",
            "The request needed too many storage calls.",
        )
    } else if lower.contains("timeout") || (lower.contains("exceeded") && lower.contains("time")) {
        (
            ErrorKind::Timeout,
            "storage_timeout",
            "The storage layer did not answer in time.",
        )
    } else if lower.contains("network connection lost")
        || lower.contains("reset because its code was updated")
        || lower.contains("database is not available")
    {
        (
            ErrorKind::Unavailable,
            "storage_unavailable",
            "The storage layer is unavailable. Try again shortly.",
        )
    } else if lower.contains("statement too long")
        || lower.contains("too many sql variables")
        || lower.contains("string or blob too big")
        || lower.contains("too big")
    {
        (
            ErrorKind::InvalidInput,
            "storage_size_limit",
            "The request is larger than the storage layer allows.",
        )
    } else {
        return Error::internal(message.to_owned());
    };
    Error::new(kind, code, public).with_source(message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unique_violation_is_a_conflict_and_hides_sql() {
        let e = map_d1_error("D1_ERROR: UNIQUE constraint failed: notes.id: SQLITE_CONSTRAINT");
        assert_eq!(e.kind(), ErrorKind::Conflict);
        assert_eq!(e.code(), "unique_violation");
        assert!(!e.to_string().contains("notes"));
        assert!(e.internal_source().is_some());
    }

    #[test]
    fn overload_is_retryable() {
        let e = map_d1_error("D1 DB is overloaded. Requests queued for too long.");
        assert_eq!(e.kind(), ErrorKind::Unavailable);
        assert!(e.kind().retryable());
    }

    #[test]
    fn per_invocation_query_cap_is_rate_limited() {
        let e = map_d1_error("Error: Too many API requests by single worker invocation.");
        assert_eq!(e.kind(), ErrorKind::RateLimited);
    }

    #[test]
    fn unknown_failure_is_internal() {
        let e = map_d1_error("D1_ERROR: something new");
        assert_eq!(e.kind(), ErrorKind::Internal);
        assert_eq!(e.to_string(), "internal: Internal error.");
    }
}
