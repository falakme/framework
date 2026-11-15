//! Value conversion and parameter binding for PostgreSQL.

use chrono::{DateTime, NaiveDateTime, Utc};
use falak_contracts::{
    Result,
    driver::{Rows, Statement, Value},
};
use sqlx::{
    Arguments, Column, Row, TypeInfo, ValueRef,
    postgres::{PgArguments, PgRow},
};
use uuid::Uuid;

use crate::error::map_sqlx_error;

/// Bind a Falak statement into SQLx `PgArguments`.
pub fn bind_statement(statement: &Statement) -> PgArguments {
    let mut args = PgArguments::default();
    for param in &statement.params {
        match param {
            Value::Null => {
                let _ = args.add(None::<String>);
            }
            Value::Bool(b) => {
                let _ = args.add(*b);
            }
            Value::Int64(i) => {
                let _ = args.add(*i);
            }
            Value::Float64(f) => {
                let _ = args.add(*f);
            }
            Value::Text(s) => {
                let _ = args.add(s.clone());
            }
            Value::Bytes(b) => {
                let _ = args.add(b.clone());
            }
            Value::Uuid(u) => {
                let _ = args.add(Uuid::from_bytes(*u));
            }
            Value::TimestampMicros(t) => {
                let dt = DateTime::<Utc>::from_timestamp_micros(*t)
                    .unwrap_or(DateTime::<Utc>::UNIX_EPOCH);
                let _ = args.add(dt);
            }
        }
    }
    args
}

/// Convert a list of `PgRow` into `Rows`.
pub fn rows_from_postgres(pg_rows: Vec<PgRow>) -> Result<Rows> {
    if pg_rows.is_empty() {
        return Ok(Rows::default());
    }

    let columns: Vec<String> = pg_rows[0]
        .columns()
        .iter()
        .map(|col| col.name().to_string())
        .collect();

    let mut rows = Vec::with_capacity(pg_rows.len());
    for row in pg_rows {
        let mut row_values = Vec::with_capacity(columns.len());
        for i in 0..columns.len() {
            let val_ref = row.try_get_raw(i).map_err(map_sqlx_error)?;
            let value = if val_ref.is_null() {
                Value::Null
            } else {
                let type_info = val_ref.type_info();
                let type_name = type_info.name();
                match type_name {
                    "BOOL" | "BOOLEAN" => {
                        let b: bool = row.try_get(i).map_err(map_sqlx_error)?;
                        Value::Bool(b)
                    }
                    "INT8" | "BIGINT" => {
                        let val: i64 = row.try_get(i).map_err(map_sqlx_error)?;
                        Value::Int64(val)
                    }
                    "INT4" | "INTEGER" | "INT" => {
                        let val: i32 = row.try_get(i).map_err(map_sqlx_error)?;
                        Value::Int64(val as i64)
                    }
                    "INT2" | "SMALLINT" => {
                        let val: i16 = row.try_get(i).map_err(map_sqlx_error)?;
                        Value::Int64(val as i64)
                    }
                    "FLOAT8" | "DOUBLE PRECISION" => {
                        let val: f64 = row.try_get(i).map_err(map_sqlx_error)?;
                        Value::Float64(val)
                    }
                    "FLOAT4" | "REAL" => {
                        let val: f32 = row.try_get(i).map_err(map_sqlx_error)?;
                        Value::Float64(val as f64)
                    }
                    "TEXT" | "VARCHAR" | "CHAR" | "BPCHAR" | "NAME" => {
                        let s: String = row.try_get(i).map_err(map_sqlx_error)?;
                        Value::Text(s)
                    }
                    "BYTEA" => {
                        let b: Vec<u8> = row.try_get(i).map_err(map_sqlx_error)?;
                        Value::Bytes(b)
                    }
                    "UUID" => {
                        let u: Uuid = row.try_get(i).map_err(map_sqlx_error)?;
                        Value::Uuid(*u.as_bytes())
                    }
                    "TIMESTAMPTZ" | "TIMESTAMP WITH TIME ZONE" => {
                        let dt: DateTime<Utc> = row.try_get(i).map_err(map_sqlx_error)?;
                        Value::TimestampMicros(dt.timestamp_micros())
                    }
                    "TIMESTAMP" | "TIMESTAMP WITHOUT TIME ZONE" => {
                        let dt: NaiveDateTime = row.try_get(i).map_err(map_sqlx_error)?;
                        Value::TimestampMicros(dt.and_utc().timestamp_micros())
                    }
                    "JSON" | "JSONB" => {
                        if let Ok(v) = row.try_get::<serde_json::Value, _>(i) {
                            Value::Text(v.to_string())
                        } else if let Ok(s) = row.try_get::<String, _>(i) {
                            Value::Text(s)
                        } else {
                            Value::Null
                        }
                    }
                    _ => {
                        // Fallback type resolution
                        if let Ok(u) = row.try_get::<Uuid, _>(i) {
                            Value::Uuid(*u.as_bytes())
                        } else if let Ok(s) = row.try_get::<String, _>(i) {
                            Value::Text(s)
                        } else if let Ok(i) = row.try_get::<i64, _>(i) {
                            Value::Int64(i)
                        } else if let Ok(f) = row.try_get::<f64, _>(i) {
                            Value::Float64(f)
                        } else if let Ok(b) = row.try_get::<bool, _>(i) {
                            Value::Bool(b)
                        } else if let Ok(bytes) = row.try_get::<Vec<u8>, _>(i) {
                            Value::Bytes(bytes)
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
