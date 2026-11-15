//! Pre-flight checks against D1's limits (see `specifications/CLOUDFLARE_LIMITS.md`).
//!
//! The build-time validator (T2.1) should reject statement templates that can never
//! fit. These runtime checks are the second line: they turn a vendor failure into a
//! clear, early error, and they stop a hostile value from reaching D1.

use falak_contracts::{Error, Result, capability::Limits, driver::Statement, driver::Value};

/// Largest integer a JavaScript number holds exactly: 2^53 - 1.
///
/// The Workers binding passes numbers to D1 as JavaScript numbers, so an `Int64`
/// outside this range would lose digits silently. The driver refuses it instead.
pub const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

/// Check one statement against the driver's limits.
pub fn check_statement(statement: &Statement, limits: &Limits) -> Result<()> {
    if let Some(max) = limits.max_statement_bytes
        && statement.sql.len() > max as usize
    {
        return Err(Error::invalid_input(
            "storage_size_limit",
            "The request is larger than the storage layer allows.",
        ));
    }
    if let Some(max) = limits.max_bound_params
        && statement.params.len() > max as usize
    {
        return Err(Error::invalid_input(
            "storage_param_limit",
            "The request has too many values for the storage layer.",
        ));
    }
    for value in &statement.params {
        check_value(value, limits)?;
    }
    Ok(())
}

fn check_value(value: &Value, limits: &Limits) -> Result<()> {
    let too_big = |len: usize| limits.max_row_bytes.is_some_and(|max| len > max as usize);
    match value {
        Value::Int64(n) | Value::TimestampMicros(n)
            if !(-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(n) =>
        {
            Err(Error::invalid_input(
                "storage_integer_range",
                "A number is outside the range the storage layer can hold exactly.",
            ))
        }
        Value::Float64(f) if !f.is_finite() => Err(Error::invalid_input(
            "storage_non_finite_number",
            "A number is not finite.",
        )),
        Value::Text(s) if too_big(s.len()) => Err(Error::invalid_input(
            "storage_size_limit",
            "A value is larger than the storage layer allows.",
        )),
        Value::Bytes(b) if too_big(b.len()) => Err(Error::invalid_input(
            "storage_size_limit",
            "A value is larger than the storage layer allows.",
        )),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use falak_contracts::capability::D1;

    fn stmt(params: Vec<Value>) -> Statement {
        Statement::new("SELECT ?", params)
    }

    #[test]
    fn accepts_a_normal_statement() {
        let s = stmt(vec![Value::Int64(1), Value::Text("a".into())]);
        assert!(check_statement(&s, &D1.limits).is_ok());
    }

    #[test]
    fn rejects_more_than_100_params() {
        let s = stmt(vec![Value::Null; 101]);
        let e = check_statement(&s, &D1.limits).unwrap_err();
        assert_eq!(e.code(), "storage_param_limit");
        assert!(check_statement(&stmt(vec![Value::Null; 100]), &D1.limits).is_ok());
    }

    #[test]
    fn rejects_sql_over_100kb() {
        let s = Statement::new("x".repeat(100_001), vec![]);
        assert_eq!(
            check_statement(&s, &D1.limits).unwrap_err().code(),
            "storage_size_limit"
        );
    }

    #[test]
    fn rejects_integers_javascript_cannot_hold() {
        for n in [MAX_SAFE_INTEGER + 1, i64::MIN, i64::MAX] {
            let e = check_statement(&stmt(vec![Value::Int64(n)]), &D1.limits).unwrap_err();
            assert_eq!(e.code(), "storage_integer_range");
        }
        assert!(check_statement(&stmt(vec![Value::Int64(MAX_SAFE_INTEGER)]), &D1.limits).is_ok());
        assert!(check_statement(&stmt(vec![Value::Int64(-MAX_SAFE_INTEGER)]), &D1.limits).is_ok());
    }

    #[test]
    fn rejects_nan_and_oversized_values() {
        assert!(check_statement(&stmt(vec![Value::Float64(f64::NAN)]), &D1.limits).is_err());
        let big = Value::Bytes(vec![0; 2_000_001]);
        assert!(check_statement(&stmt(vec![big]), &D1.limits).is_err());
    }
}
