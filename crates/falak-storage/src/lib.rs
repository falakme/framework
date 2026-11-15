//! Object storage presigning and upload checks (T3.11, ARCHITECTURE §4.7).
//!
//! * **Server-generated keys under a tenant prefix.** A caller never names an object:
//!   [`object_key`] builds `quarantine/<tenant>/<id>` or `files/<tenant>/<id>`, and
//!   refuses a tenant or id that is not a plain UUID.
//! * **Presigned upload with the limits inside the signature.** The upload URL signs the
//!   `content-type` and the exact `content-length`, so the store itself refuses another
//!   type or size. The type must be on [`sniff::ALLOWED_TYPES`] and the size under the
//!   cap, before any URL is made.
//! * **Quarantine.** An upload lands under `quarantine/`. [`FileFlow::finish_upload`]
//!   reads its first bytes, checks them against the declared type (magic bytes), and only
//!   then moves it to `files/`. A file that fails is deleted.
//! * **Download as an attachment.** The download URL is short lived and overrides the
//!   response to `application/octet-stream` with `Content-Disposition: attachment`, and
//!   it exists only for a file in `files/`.
//!
//! Who may ask for a download URL is decided by the caller (the runtime checks the file's
//! owner and tenant first). This crate never reads identity.

// The futures are run on whatever thread the caller uses; no `Send` promise is made.
#![allow(async_fn_in_trait)]

pub mod flow;
#[cfg(feature = "s3")]
pub mod s3;
pub mod sigv4;
pub mod sniff;

pub use flow::{Begun, FileFlow, MemoryBackend, ObjectBackend, UploadLimits};
pub use sigv4::S3Config;
pub use sniff::{ALLOWED_TYPES, Refusal, check_declared, sniff};

use falak_contracts::{Error, Result};

/// Where an object is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Area {
    /// Uploaded, not yet checked. Never served.
    Quarantine,
    /// Checked. May be downloaded.
    Clean,
}

fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_digit() || (b'a'..=b'f').contains(c),
        })
}

/// The key of an object. `tenant` is the verified tenant id, or `None` for an app
/// without tenancy.
pub fn object_key(area: Area, tenant: Option<&str>, id: &str) -> Result<String> {
    let segment = match tenant {
        Some(t) if is_uuid(t) => t,
        Some(_) => return Err(Error::forbidden()),
        None => "shared",
    };
    if !is_uuid(id) {
        return Err(Error::invalid_input("invalid_file", "not a file id"));
    }
    let prefix = match area {
        Area::Quarantine => "quarantine",
        Area::Clean => "files",
    };
    Ok(format!("{prefix}/{segment}/{id}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: &str = "00000000-0000-0000-0000-0000000000a1";
    const ID: &str = "11111111-2222-3333-4444-555555555555";

    #[test]
    fn keys_are_built_by_the_server_under_the_tenant() {
        assert_eq!(
            object_key(Area::Quarantine, Some(T), ID).unwrap(),
            format!("quarantine/{T}/{ID}")
        );
        assert_eq!(
            object_key(Area::Clean, None, ID).unwrap(),
            format!("files/shared/{ID}")
        );
    }

    #[test]
    fn a_key_cannot_climb_out_of_its_prefix() {
        for bad in ["../x", "a/b", "", "00000000-0000-0000-0000-0000000000A1"] {
            assert!(object_key(Area::Clean, Some(bad), ID).is_err(), "{bad}");
            assert!(object_key(Area::Clean, Some(T), bad).is_err(), "{bad}");
        }
    }
}
