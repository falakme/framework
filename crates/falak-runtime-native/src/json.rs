//! JSON serialization and conversion to/from driver values.

use falak_contracts::{
    Error, Result,
    driver::Value,
    ir::{FieldType, IrEntity, IrField},
};
use falak_core::values::{check_value, format_uuid, parse_timestamp, parse_uuid};
use serde_json::{Map, json};
use unicode_normalization::UnicodeNormalization;

pub fn format_timestamp(micros: i64) -> String {
    let secs = micros.div_euclid(1_000_000);
    let subs = micros.rem_euclid(1_000_000);
    let days = secs.div_euclid(86_400);
    let day_secs = secs.rem_euclid(86_400);
    let h = day_secs / 3600;
    let m = (day_secs % 3600) / 60;
    let s = day_secs % 60;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m_month = if mp < 10 { mp + 3 } else { mp - 9 };
    let y_year = if m_month <= 2 { y + 1 } else { y };
    if subs == 0 {
        format!("{y_year:04}-{m_month:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
    } else {
        let frac_str = format!("{subs:06}").trim_end_matches('0').to_string();
        format!("{y_year:04}-{m_month:02}-{d:02}T{h:02}:{m:02}:{s:02}.{frac_str}Z")
    }
}

pub fn json_to_driver_value(json: &serde_json::Value, field: &IrField) -> Result<Value> {
    if json.is_null() {
        if !field.nullable && !field.builtin {
            return Err(Error::invalid_input(
                "invalid_input",
                format!("field `{}` cannot be null", field.name),
            ));
        }
        return Ok(Value::Null);
    }

    let value = match field.ty {
        FieldType::Uuid => {
            let s = json.as_str().ok_or_else(|| {
                Error::invalid_input(
                    "invalid_input",
                    format!("field `{}` must be a UUID string", field.name),
                )
            })?;
            let bytes = parse_uuid(s).ok_or_else(|| {
                Error::invalid_input(
                    "invalid_input",
                    format!("field `{}` is not a valid UUID", field.name),
                )
            })?;
            Value::Uuid(bytes)
        }
        FieldType::Int64 | FieldType::DecimalMinor => {
            let i = json.as_i64().ok_or_else(|| {
                Error::invalid_input(
                    "invalid_input",
                    format!("field `{}` must be an integer", field.name),
                )
            })?;
            Value::Int64(i)
        }
        FieldType::Bool => {
            let b = json.as_bool().ok_or_else(|| {
                Error::invalid_input(
                    "invalid_input",
                    format!("field `{}` must be a boolean", field.name),
                )
            })?;
            Value::Bool(b)
        }
        FieldType::Text => {
            let s = json.as_str().ok_or_else(|| {
                Error::invalid_input(
                    "invalid_input",
                    format!("field `{}` must be a string", field.name),
                )
            })?;
            Value::Text(s.nfc().collect::<String>())
        }
        FieldType::Timestamptz => {
            if let Some(s) = json.as_str() {
                let micros = parse_timestamp(s).ok_or_else(|| {
                    Error::invalid_input(
                        "invalid_input",
                        format!("field `{}` must be an ISO 8601 UTC timestamp", field.name),
                    )
                })?;
                Value::TimestampMicros(micros)
            } else if let Some(i) = json.as_i64() {
                Value::TimestampMicros(i)
            } else {
                return Err(Error::invalid_input(
                    "invalid_input",
                    format!("field `{}` must be a timestamp", field.name),
                ));
            }
        }
        FieldType::Bytes => {
            if let Some(s) = json.as_str() {
                Value::Bytes(s.as_bytes().to_vec())
            } else {
                return Err(Error::invalid_input(
                    "invalid_input",
                    format!("field `{}` must be bytes", field.name),
                ));
            }
        }
        FieldType::Json => Value::Text(json.to_string()),
    };

    check_value(field, &value)?;
    Ok(value)
}

pub fn driver_value_to_json(val: &Value) -> serde_json::Value {
    match val {
        Value::Null => serde_json::Value::Null,
        Value::Bool(b) => serde_json::Value::Bool(*b),
        Value::Int64(i) => json!(i),
        Value::Float64(f) => json!(f),
        Value::Text(s) => serde_json::Value::String(s.clone()),
        Value::Bytes(b) => json!(b),
        Value::Uuid(u) => serde_json::Value::String(format_uuid(u)),
        Value::TimestampMicros(t) => serde_json::Value::String(format_timestamp(*t)),
    }
}

pub fn row_to_json_object(
    entity: Option<&IrEntity>,
    columns: &[String],
    row: &[Value],
) -> serde_json::Value {
    let mut map = Map::with_capacity(columns.len());
    for (col, val) in columns.iter().zip(row.iter()) {
        let field_opt = entity.and_then(|e| e.field(col));
        let json_val = match (field_opt.map(|f| &f.ty), val) {
            (_, Value::Null) => serde_json::Value::Null,
            (Some(FieldType::Bool), Value::Int64(i)) => serde_json::Value::Bool(*i != 0),
            (Some(FieldType::Bool), Value::Bool(b)) => serde_json::Value::Bool(*b),
            (Some(FieldType::Uuid), Value::Uuid(u)) => serde_json::Value::String(format_uuid(u)),
            (Some(FieldType::Uuid), Value::Bytes(b)) if b.len() == 16 => {
                let mut u = [0u8; 16];
                u.copy_from_slice(b);
                serde_json::Value::String(format_uuid(&u))
            }
            (Some(FieldType::Timestamptz), Value::TimestampMicros(t)) => {
                serde_json::Value::String(format_timestamp(*t))
            }
            (Some(FieldType::Timestamptz), Value::Int64(t)) => {
                serde_json::Value::String(format_timestamp(*t))
            }
            (Some(FieldType::Json), Value::Text(s)) => {
                serde_json::from_str(s).unwrap_or_else(|_| serde_json::Value::String(s.clone()))
            }
            _ => driver_value_to_json(val),
        };
        map.insert(col.clone(), json_val);
    }
    serde_json::Value::Object(map)
}
