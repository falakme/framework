//! Password hashing with Argon2id.
//!
//! Parameters follow the OWASP minimum for Argon2id: 19 MiB of memory, 2 passes, 1 lane.
//! Hashes are PHC strings, so the parameters travel with each hash and can be raised
//! later without breaking old ones.

use std::sync::OnceLock;

use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use falak_contracts::{Error, Result};
use rand_core::OsRng;

pub const MIN_PASSWORD_CHARS: usize = 12;
pub const MAX_PASSWORD_CHARS: usize = 128;

fn argon2() -> Argon2<'static> {
    let params = Params::new(19 * 1024, 2, 1, None).expect("fixed Argon2 parameters are valid");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Check a new password. The message is safe to show to the person choosing it.
pub fn validate_password(password: &str) -> Result<()> {
    let chars = password.chars().count();
    let problem = if chars < MIN_PASSWORD_CHARS {
        Some("The password must have at least 12 characters.")
    } else if chars > MAX_PASSWORD_CHARS {
        Some("The password must have at most 128 characters.")
    } else if password.contains('\0') {
        Some("The password contains a character that is not allowed.")
    } else if is_one_repeated_character(password) {
        Some("The password must not be one repeated character.")
    } else {
        None
    };
    match problem {
        Some(message) => Err(Error::invalid_input("weak_password", message)),
        None => Ok(()),
    }
}

fn is_one_repeated_character(password: &str) -> bool {
    let mut chars = password.chars();
    let first = chars.next();
    chars.all(|c| Some(c) == first)
}

/// Hash a password with a fresh random salt.
pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    argon2()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| Error::internal(e.to_string()))
}

/// Check a password against a stored hash. A malformed hash counts as a mismatch.
pub fn verify_password(hash: &str, password: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    argon2()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// Spend the same time as a real check, for a login that names no real account, so the
/// response time does not reveal which emails exist.
pub fn verify_against_dummy(password: &str) {
    static DUMMY: OnceLock<String> = OnceLock::new();
    let hash =
        DUMMY.get_or_init(|| hash_password("falak dummy password for timing").unwrap_or_default());
    let _ = verify_password(hash, password);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_then_verify() {
        let h = hash_password("correct horse battery").unwrap();
        assert!(h.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
        assert!(verify_password(&h, "correct horse battery"));
        assert!(!verify_password(&h, "correct horse batterY"));
    }

    #[test]
    fn same_password_gets_different_salts() {
        let a = hash_password("correct horse battery").unwrap();
        let b = hash_password("correct horse battery").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn malformed_hash_is_a_mismatch_not_a_panic() {
        for bad in ["", "plain", "$argon2id$", "$2b$12$abc"] {
            assert!(!verify_password(bad, "whatever whatever"));
        }
    }

    #[test]
    fn password_rules() {
        assert!(validate_password("short").is_err());
        assert!(validate_password(&"a".repeat(20)).is_err());
        assert!(validate_password(&"ab".repeat(65)).is_err());
        assert!(validate_password("has a nul \0 inside!").is_err());
        assert!(validate_password("a perfectly fine passphrase").is_ok());
        assert!(validate_password("пароль-достаточной-длины").is_ok());
    }
}
