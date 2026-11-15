//! Value conversion between the Falak contract and what D1 accepts and returns.
//!
//! D1 is reached through JavaScript, so it sees numbers as IEEE doubles and blobs as
//! byte arrays. This module holds the rules, kept free of any binding code so they can
//! be tested natively.

use std::fmt;

use falak_contracts::{
    Error, Result,
    driver::{Rows, Value},
};
use serde::{
    Deserialize, Deserializer,
    de::{MapAccess, SeqAccess, Visitor},
};

use crate::validate::MAX_SAFE_INTEGER;

/// A value ready to bind to a D1 statement.
#[derive(Debug, Clone, PartialEq)]
pub enum Param {
    Null,
    /// An integer already checked to be exactly representable as a JavaScript number.
    Integer(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

/// Convert a contract value to a D1 parameter.
///
/// * `Bool` becomes `0` or `1`.
/// * `Uuid` becomes a 16-byte blob.
/// * `TimestampMicros` becomes an integer count of microseconds.
/// * `Int64` and `TimestampMicros` outside ±(2^53 − 1) are refused, because the
///   JavaScript binding would round them.
pub fn to_param(value: &Value) -> Result<Param> {
    Ok(match value {
        Value::Null => Param::Null,
        Value::Bool(b) => Param::Integer(i64::from(*b)),
        Value::Int64(n) | Value::TimestampMicros(n) => {
            if !(-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(n) {
                return Err(Error::invalid_input(
                    "storage_integer_range",
                    "A number is outside the range the storage layer can hold exactly.",
                ));
            }
            Param::Integer(*n)
        }
        Value::Float64(f) => Param::Real(*f),
        Value::Text(s) => Param::Text(s.clone()),
        Value::Bytes(b) => Param::Blob(b.clone()),
        Value::Uuid(u) => Param::Blob(u.to_vec()),
    })
}

/// One cell of a result row, as D1 returns it.
#[derive(Debug, Clone, PartialEq)]
pub enum Cell {
    Null,
    Number(f64),
    Text(String),
    Blob(Vec<u8>),
}

impl Cell {
    /// Convert to a contract value.
    ///
    /// D1 does not say whether a number was an integer or a real, so a number with no
    /// fractional part inside the safe range becomes `Int64` and any other number
    /// becomes `Float64`. The core coerces to the column type declared in the IR.
    pub fn into_value(self) -> Value {
        match self {
            Cell::Null => Value::Null,
            Cell::Number(n) => {
                if n.fract() == 0.0 && n.abs() <= MAX_SAFE_INTEGER as f64 {
                    Value::Int64(n as i64)
                } else {
                    Value::Float64(n)
                }
            }
            Cell::Text(s) => Value::Text(s),
            Cell::Blob(b) => Value::Bytes(b),
        }
    }
}

impl<'de> Deserialize<'de> for Cell {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct CellVisitor;

        impl<'de> Visitor<'de> for CellVisitor {
            type Value = Cell;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("null, a number, a string or an array of bytes")
            }

            fn visit_unit<E>(self) -> std::result::Result<Cell, E> {
                Ok(Cell::Null)
            }
            fn visit_none<E>(self) -> std::result::Result<Cell, E> {
                Ok(Cell::Null)
            }
            fn visit_bool<E>(self, v: bool) -> std::result::Result<Cell, E> {
                Ok(Cell::Number(if v { 1.0 } else { 0.0 }))
            }
            fn visit_i64<E>(self, v: i64) -> std::result::Result<Cell, E> {
                Ok(Cell::Number(v as f64))
            }
            fn visit_u64<E>(self, v: u64) -> std::result::Result<Cell, E> {
                Ok(Cell::Number(v as f64))
            }
            fn visit_f64<E>(self, v: f64) -> std::result::Result<Cell, E> {
                Ok(Cell::Number(v))
            }
            fn visit_str<E>(self, v: &str) -> std::result::Result<Cell, E> {
                Ok(Cell::Text(v.to_owned()))
            }
            fn visit_string<E>(self, v: String) -> std::result::Result<Cell, E> {
                Ok(Cell::Text(v))
            }
            fn visit_bytes<E>(self, v: &[u8]) -> std::result::Result<Cell, E> {
                Ok(Cell::Blob(v.to_vec()))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Cell, A::Error> {
                let mut bytes = Vec::with_capacity(seq.size_hint().unwrap_or(0));
                while let Some(b) = seq.next_element::<u8>()? {
                    bytes.push(b);
                }
                Ok(Cell::Blob(bytes))
            }
        }

        deserializer.deserialize_any(CellVisitor)
    }
}

/// A result row that keeps column order.
///
/// D1 returns each row as an object. A plain map would sort or scramble the columns,
/// and the contract's `Rows` is positional, so order is kept as it arrives.
#[derive(Debug, Clone, PartialEq)]
pub struct OrderedRow(pub Vec<(String, Cell)>);

impl<'de> Deserialize<'de> for OrderedRow {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct RowVisitor;

        impl<'de> Visitor<'de> for RowVisitor {
            type Value = OrderedRow;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a result row object")
            }

            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<OrderedRow, A::Error> {
                let mut cells = Vec::with_capacity(map.size_hint().unwrap_or(0));
                while let Some((name, cell)) = map.next_entry::<String, Cell>()? {
                    cells.push((name, cell));
                }
                Ok(OrderedRow(cells))
            }
        }

        deserializer.deserialize_map(RowVisitor)
    }
}

/// Build positional [`Rows`] from ordered rows. Columns come from the first row.
///
/// An empty result has no columns, because D1 reports none for it.
pub fn rows_from_ordered(rows: Vec<OrderedRow>) -> Rows {
    let columns = rows
        .first()
        .map(|r| r.0.iter().map(|(name, _)| name.clone()).collect())
        .unwrap_or_default();
    let rows = rows
        .into_iter()
        .map(|r| r.0.into_iter().map(|(_, cell)| cell.into_value()).collect())
        .collect();
    Rows { columns, rows }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bool_uuid_and_timestamp_map_to_storage_forms() {
        assert_eq!(to_param(&Value::Bool(true)).unwrap(), Param::Integer(1));
        assert_eq!(to_param(&Value::Bool(false)).unwrap(), Param::Integer(0));
        assert_eq!(
            to_param(&Value::Uuid([7; 16])).unwrap(),
            Param::Blob(vec![7; 16])
        );
        assert_eq!(
            to_param(&Value::TimestampMicros(1_700_000_000_000_000)).unwrap(),
            Param::Integer(1_700_000_000_000_000)
        );
    }

    #[test]
    fn unsafe_integer_is_refused_not_rounded() {
        let e = to_param(&Value::Int64(MAX_SAFE_INTEGER + 1)).unwrap_err();
        assert_eq!(e.code(), "storage_integer_range");
    }

    #[test]
    fn numbers_become_int_or_float() {
        assert_eq!(Cell::Number(42.0).into_value(), Value::Int64(42));
        assert_eq!(Cell::Number(-3.0).into_value(), Value::Int64(-3));
        assert_eq!(Cell::Number(2.5).into_value(), Value::Float64(2.5));
        assert_eq!(Cell::Number(1e300).into_value(), Value::Float64(1e300));
    }

    #[test]
    fn rows_keep_column_order() {
        // Column names deliberately not in alphabetical order.
        let json = r#"[{"zed":1,"alpha":"a","mid":null,"blob":[1,2,3]},
                       {"zed":2,"alpha":"b","mid":0.5,"blob":[]}]"#;
        let rows: Vec<OrderedRow> = serde_json::from_str(json).unwrap();
        let rows = rows_from_ordered(rows);
        assert_eq!(rows.columns, ["zed", "alpha", "mid", "blob"]);
        assert_eq!(
            rows.rows[0],
            [
                Value::Int64(1),
                Value::Text("a".into()),
                Value::Null,
                Value::Bytes(vec![1, 2, 3])
            ]
        );
        assert_eq!(rows.rows[1][2], Value::Float64(0.5));
    }

    #[test]
    fn empty_result_has_no_columns() {
        let rows = rows_from_ordered(vec![]);
        assert!(rows.columns.is_empty() && rows.rows.is_empty());
    }
}
