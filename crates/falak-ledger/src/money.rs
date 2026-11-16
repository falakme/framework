//! Currency codes and checked arithmetic on minor units.

use falak_contracts::{Error, ErrorKind, Result};
use serde::{Deserialize, Serialize};

/// A three-letter upper-case currency code (ISO 4217 shape). Amounts in different
/// currencies are never added or moved between accounts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Currency([u8; 3]);

impl Currency {
    pub fn new(code: &str) -> Result<Self> {
        let b = code.as_bytes();
        if b.len() != 3 || !b.iter().all(u8::is_ascii_uppercase) {
            return Err(Error::invalid_input(
                "ledger_bad_currency",
                "A currency is three upper-case letters, such as USD.",
            ));
        }
        Ok(Self([b[0], b[1], b[2]]))
    }

    pub fn as_str(&self) -> &str {
        // Construction guarantees ASCII.
        std::str::from_utf8(&self.0).unwrap_or("???")
    }
}

impl std::fmt::Display for Currency {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for Currency {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Currency {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Currency::new(&s).map_err(serde::de::Error::custom)
    }
}

/// An amount in a command must be positive.
pub fn positive(amount: i64) -> Result<i64> {
    if amount <= 0 {
        return Err(Error::invalid_input(
            "ledger_bad_amount",
            "An amount must be greater than zero.",
        ));
    }
    Ok(amount)
}

pub fn overflow() -> Error {
    Error::new(
        ErrorKind::InvalidInput,
        "ledger_overflow",
        "The amount is too large.",
    )
}

pub fn checked_add(a: i64, b: i64) -> Result<i64> {
    a.checked_add(b).ok_or_else(overflow)
}

pub fn checked_neg(a: i64) -> Result<i64> {
    a.checked_neg().ok_or_else(overflow)
}

/// An account id: 1 to 128 bytes, no control characters.
pub fn account_id(id: &str) -> Result<()> {
    if id.is_empty() || id.len() > 128 || id.chars().any(char::is_control) {
        return Err(Error::invalid_input(
            "ledger_bad_account",
            "An account id is 1 to 128 characters with no control characters.",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn currency_shape() {
        assert!(Currency::new("USD").is_ok());
        assert!(Currency::new("usd").is_err());
        assert!(Currency::new("US").is_err());
        assert_eq!(Currency::new("EUR").unwrap().to_string(), "EUR");
    }

    #[test]
    fn arithmetic_is_checked() {
        assert!(checked_add(i64::MAX, 1).is_err());
        assert_eq!(checked_add(2, 3).unwrap(), 5);
        assert!(checked_neg(i64::MIN).is_err());
        assert!(positive(0).is_err());
        assert!(positive(-5).is_err());
    }
}
