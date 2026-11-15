//! Value conversion and parameter binding for SQLite.

use falak_contracts::{
    Result,
    driver::{Rows, Statement, Value},
};
use sqlx::{
    Arguments, Column, Row, TypeInfo, ValueRef,
    sqlite::{SqliteArguments, SqliteRow},
};

use crate::error::map_sqlx_error;

/// Bind a Falak statement into SQLx `SqliteArguments`.
pub fn bind_statement(statement: &Statement) -> SqliteArguments<'static> {
    let mut args = SqliteArguments::default();
    for param in &statement.params {
        match param {
            Value::Null => {
                args.add(None::<String>);
            }
            Value::Bool(b) => {
                args.add(if *b { 1i64 } else { 0i64 });
            }
            Value::Int64(i) => {
                args.add(*i);
            }
            Value::Float64(f) => {
                args.add(*f);
            }
            Value::Text(s) => {
                args.add(s.clone());
            }
            Value::Bytes(b) => {
                args.add(b.clone());
            }
            Value::Uuid(u) => {
                args.add(u.to_vec());
            }
            Value::TimestampMicros(t) => {
                args.add(*t);
            }
        }
    }
    args
}

/// Convert a list of `SqliteRow` into `Rows`.
pub fn rows_from_sqlite(sqlite_rows: Vec<SqliteRow>) -> Result<Rows> {
    if sqlite_rows.is_empty() {
        return Ok(Rows::default());
    }

    let columns: Vec<String> = sqlite_rows[0]
        .columns()
        .iter()
        .map(|col| col.name().to_string())
        .collect();

    let mut rows = Vec::with_capacity(sqlite_rows.len());
    for row in sqlite_rows {
        let mut row_values = Vec::with_capacity(columns.len());
        for i in 0..columns.len() {
            let val_ref = row.try_get_raw(i).map_err(map_sqlx_error)?;
            let value = if val_ref.is_null() {
                Value::Null
            } else {
                let type_name = val_ref.type_info().name();
                match type_name {
                    "INTEGER" | "INT" | "BIGINT" | "TINYINT" | "SMALLINT" => {
                        let i: i64 = row.try_get(i).map_err(map_sqlx_error)?;
                        Value::Int64(i)
                    }
                    "REAL" | "FLOAT" | "DOUBLE" => {
                        let f: f64 = row.try_get(i).map_err(map_sqlx_error)?;
                        Value::Float64(f)
                    }
                    "TEXT" | "VARCHAR" | "CHAR" => {
                        let s: String = row.try_get(i).map_err(map_sqlx_error)?;
                        Value::Text(s)
                    }
                    "BLOB" => {
                        let b: Vec<u8> = row.try_get(i).map_err(map_sqlx_error)?;
                        Value::Bytes(b)
                    }
                    "BOOLEAN" | "BOOL" => {
                        let b: bool = row.try_get(i).map_err(map_sqlx_error)?;
                        Value::Bool(b)
                    }
                    _ => {
                        // Fallback: try decoding as text or bytes
                        if let Ok(s) = row.try_get::<String, _>(i) {
                            Value::Text(s)
                        } else if let Ok(b) = row.try_get::<Vec<u8>, _>(i) {
                            Value::Bytes(b)
                        } else if let Ok(i) = row.try_get::<i64, _>(i) {
                            Value::Int64(i)
                        } else if let Ok(f) = row.try_get::<f64, _>(i) {
                            Value::Float64(f)
                        } else {
                            Value::Null
                        }
                    }
                }
            };
            row_values.push(value);
        }
        rows.push(row_values);
    }

    Ok(Rows { columns, rows })
}
