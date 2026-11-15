//! Parsing and checking of values against field definitions.

use falak_contracts::{
    Error, Result,
    driver::Value,
    ir::{FieldType, IrField},
};

/// Parse a canonical UUID (`8-4-4-4-12` hex, any case) into bytes.
pub fn parse_uuid(s: &str) -> Option<[u8; 16]> {
    let b = s.as_bytes();
    if b.len() != 36 || [8, 13, 18, 23].iter().any(|&i| b[i] != b'-') {
        return None;
    }
    let mut out = [0u8; 16];
    let mut n = 0;
    let mut i = 0;
    while i < 36 {
        if matches!(i, 8 | 13 | 18 | 23) {
            i += 1;
            continue;
        }
        let hi = (b[i] as char).to_digit(16)?;
        let lo = (b[i + 1] as char).to_digit(16)?;
        out[n] = (hi * 16 + lo) as u8;
        n += 1;
        i += 2;
    }
    Some(out)
}

/// Lowercase canonical form of a UUID.
pub fn format_uuid(u: &[u8; 16]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(36);
    for (i, b) in u.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            s.push('-');
        }
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Parse `YYYY-MM-DDTHH:MM:SS[.ffffff]Z` (UTC only) into microseconds since the epoch.
pub fn parse_timestamp(s: &str) -> Option<i64> {
    let s = s.strip_suffix('Z')?;
    let (date, time) = s.split_once('T')?;
    let mut d = date.split('-');
    let (y, mo, da): (i64, i64, i64) = (
        d.next()?.parse().ok()?,
        d.next()?.parse().ok()?,
        d.next()?.parse().ok()?,
    );
    if d.next().is_some() || !(1..=12).contains(&mo) || !(1..=31).contains(&da) {
        return None;
    }
    let (hms, frac) = match time.split_once('.') {
        Some((a, b)) => (a, b),
        None => (time, ""),
    };
    let mut t = hms.split(':');
    let (h, mi, se): (i64, i64, i64) = (
        t.next()?.parse().ok()?,
        t.next()?.parse().ok()?,
        t.next()?.parse().ok()?,
    );
    if t.next().is_some()
        || h > 23
        || mi > 59
        || se > 59
        || frac.len() > 6
        || !frac.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let micros: i64 = if frac.is_empty() {
        0
    } else {
        format!("{frac:0<6}").parse().ok()?
    };
    let days = days_from_civil(y, mo, da);
    Some(((days * 86_400 + h * 3600 + mi * 60 + se) * 1_000_000) + micros)
}

/// Turn a query-string value into a [`Value`] of the field's type.
pub fn coerce_text(field: &IrField, text: &str) -> Result<Value> {
    let bad = || {
        Error::invalid_input(
            "invalid_value",
            format!("`{}` is not a valid {}", field.name, type_name(&field.ty)),
        )
    };
    Ok(match field.ty {
        FieldType::Uuid => Value::Uuid(parse_uuid(text).ok_or_else(bad)?),
        FieldType::Int64 | FieldType::DecimalMinor => {
            Value::Int64(text.parse().map_err(|_| bad())?)
        }
        FieldType::Text => Value::Text(text.to_string()),
        FieldType::Bool => match text {
            "true" => Value::Bool(true),
            "false" => Value::Bool(false),
            _ => return Err(bad()),
        },
        FieldType::Timestamptz => Value::TimestampMicros(parse_timestamp(text).ok_or_else(bad)?),
        FieldType::Bytes | FieldType::Json => return Err(bad()),
    })
}

pub fn type_name(t: &FieldType) -> &'static str {
    match t {
        FieldType::Uuid => "uuid",
        FieldType::Int64 => "int64",
        FieldType::DecimalMinor => "decimal_minor",
        FieldType::Text => "text",
        FieldType::Bool => "bool",
        FieldType::Timestamptz => "timestamptz",
        FieldType::Bytes => "bytes",
        FieldType::Json => "json",
    }
}

/// Default maximum length of a `text` field with no explicit `max_length`.
pub const DEFAULT_TEXT_MAX: u32 = 4096;

/// Check a value against a field: type, nullability, length and bounds.
pub fn check_value(field: &IrField, value: &Value) -> Result<()> {
    let name = &field.name;
    let wrong = |what: &str| Error::invalid_input("invalid_field", format!("`{name}` {what}"));
    match (&field.ty, value) {
        (_, Value::Null) => {
            if field.nullable {
                Ok(())
            } else {
                Err(wrong("is required"))
            }
        }
        (FieldType::Uuid, Value::Uuid(_)) | (FieldType::Bool, Value::Bool(_)) => Ok(()),
        (FieldType::Timestamptz, Value::TimestampMicros(_)) | (FieldType::Json, Value::Text(_)) => {
            Ok(())
        }
        (FieldType::Int64 | FieldType::DecimalMinor, Value::Int64(i)) => {
            if field.min.is_some_and(|m| *i < m) || field.max.is_some_and(|m| *i > m) {
                Err(wrong("is out of range"))
            } else {
                Ok(())
            }
        }
        (FieldType::Text, Value::Text(s)) => {
            let limit = field.max_length.unwrap_or(DEFAULT_TEXT_MAX) as usize;
            if s.chars().count() > limit {
                Err(wrong(&format!("is longer than {limit} characters")))
            } else {
                Ok(())
            }
        }
        (FieldType::Bytes, Value::Bytes(b)) => match field.max_length {
            Some(l) if b.len() > l as usize => Err(wrong(&format!("is longer than {l} bytes"))),
            _ => Ok(()),
        },
        _ => Err(wrong(&format!("must be a {}", type_name(&field.ty)))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_round_trip_and_rejects_garbage() {
        let u = parse_uuid("018F6C4A-67a2-7b81-9b1e-355f309a4d88").unwrap();
        assert_eq!(format_uuid(&u), "018f6c4a-67a2-7b81-9b1e-355f309a4d88");
        assert!(parse_uuid("not-a-uuid").is_none());
        assert!(parse_uuid("018f6c4a67a27b819b1e355f309a4d88").is_none());
        assert!(parse_uuid("018f6c4a-67a2-7b81-9b1e-355f309a4dzz").is_none());
    }

    #[test]
    fn timestamps_parse_to_microseconds() {
        assert_eq!(parse_timestamp("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_timestamp("1970-01-01T00:00:01.5Z"), Some(1_500_000));
        assert_eq!(
            parse_timestamp("2026-11-15T00:00:00Z"),
            Some(1_794_700_800_000_000)
        );
        assert_eq!(parse_timestamp("2026-11-15T00:00:00+01:00"), None);
        assert_eq!(parse_timestamp("2026-13-15T00:00:00Z"), None);
    }
}
