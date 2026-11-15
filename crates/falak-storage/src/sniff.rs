//! What an uploaded file really is, from its first bytes.
//!
//! The declared content type is the client's word. Before a file leaves quarantine its
//! first bytes must match the type it was declared as, and the type must be on the list.

/// Types an upload may be. Anything else is refused at presign time.
pub const ALLOWED_TYPES: &[&str] = &[
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "application/pdf",
    "text/plain",
];

/// How many bytes `sniff` needs.
pub const SNIFF_BYTES: usize = 512;

/// The type the bytes say they are, if it is one of [`ALLOWED_TYPES`].
pub fn sniff(head: &[u8]) -> Option<&'static str> {
    if head.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]) {
        return Some("image/png");
    }
    if head.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Some("image/jpeg");
    }
    if head.starts_with(b"GIF87a") || head.starts_with(b"GIF89a") {
        return Some("image/gif");
    }
    if head.len() >= 12 && &head[0..4] == b"RIFF" && &head[8..12] == b"WEBP" {
        return Some("image/webp");
    }
    if head.starts_with(b"%PDF-") {
        return Some("application/pdf");
    }
    if is_text(head) {
        return Some("text/plain");
    }
    None
}

/// Valid UTF-8 (a cut-off character at the end is fine), no NUL, no control characters
/// other than tab, newline and carriage return.
fn is_text(head: &[u8]) -> bool {
    if head.is_empty() {
        return false;
    }
    let valid = match std::str::from_utf8(head) {
        Ok(s) => s,
        Err(e) if e.error_len().is_none() => {
            std::str::from_utf8(&head[..e.valid_up_to()]).unwrap_or("")
        }
        Err(_) => return false,
    };
    !valid.is_empty()
        && valid
            .chars()
            .all(|c| !c.is_control() || matches!(c, '\t' | '\n' | '\r'))
}

/// Why a file was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    TypeNotAllowed,
    ContentDoesNotMatch,
}

/// The declared type must be allowed and the bytes must agree with it.
pub fn check_declared(declared: &str, head: &[u8]) -> Result<(), Refusal> {
    if !ALLOWED_TYPES.contains(&declared) {
        return Err(Refusal::TypeNotAllowed);
    }
    match sniff(head) {
        Some(found) if found == declared => Ok(()),
        _ => Err(Refusal::ContentDoesNotMatch),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PNG: &[u8] = &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 13];

    #[test]
    fn known_types_are_recognised() {
        assert_eq!(sniff(PNG), Some("image/png"));
        assert_eq!(sniff(&[0xFF, 0xD8, 0xFF, 0xE0]), Some("image/jpeg"));
        assert_eq!(sniff(b"GIF89a...."), Some("image/gif"));
        assert_eq!(sniff(b"RIFF\0\0\0\0WEBPVP8 "), Some("image/webp"));
        assert_eq!(sniff(b"%PDF-1.7\n"), Some("application/pdf"));
        assert_eq!(sniff("héllo\nworld".as_bytes()), Some("text/plain"));
    }

    #[test]
    fn binary_and_executables_are_not_text() {
        assert_eq!(sniff(b"MZ\x90\x00\x03"), None);
        assert_eq!(sniff(b"\x7fELF\x02"), None);
        assert_eq!(sniff(b"PK\x03\x04"), None);
        assert_eq!(sniff(b"a\0b"), None);
        assert_eq!(sniff(b""), None);
    }

    #[test]
    fn a_cut_off_multibyte_character_is_still_text() {
        let mut b = "ok ".as_bytes().to_vec();
        b.extend_from_slice(&"é".as_bytes()[..1]);
        assert_eq!(sniff(&b), Some("text/plain"));
    }

    #[test]
    fn the_declared_type_has_to_match_the_bytes() {
        assert_eq!(check_declared("image/png", PNG), Ok(()));
        assert_eq!(
            check_declared("image/png", b"MZ\x90\x00"),
            Err(Refusal::ContentDoesNotMatch)
        );
        assert_eq!(
            check_declared("image/png", b"%PDF-1.4"),
            Err(Refusal::ContentDoesNotMatch)
        );
        assert_eq!(
            check_declared("text/html", b"<html>"),
            Err(Refusal::TypeNotAllowed)
        );
    }
}
