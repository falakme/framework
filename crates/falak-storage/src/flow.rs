//! The upload and download flow over an object store.

use std::{collections::HashMap, sync::Mutex};

use falak_contracts::{Error, Result};

use crate::{
    Area, S3Config, object_key,
    sigv4::presign,
    sniff::{ALLOWED_TYPES, Refusal, SNIFF_BYTES, check_declared},
};

/// What the flow needs from a store: enough to check and move an object.
pub trait ObjectBackend {
    /// The size of the object, or `None` if there is none.
    async fn size(&self, key: &str) -> Result<Option<u64>>;
    /// The first `n` bytes.
    async fn head(&self, key: &str, n: usize) -> Result<Vec<u8>>;
    async fn copy(&self, from: &str, to: &str) -> Result<()>;
    async fn delete(&self, key: &str) -> Result<()>;
}

/// An in-memory store, for tests and tools.
#[derive(Default)]
pub struct MemoryBackend {
    objects: Mutex<HashMap<String, Vec<u8>>>,
}

impl MemoryBackend {
    pub fn put(&self, key: &str, bytes: &[u8]) {
        self.objects
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(key.to_owned(), bytes.to_vec());
    }

    pub fn has(&self, key: &str) -> bool {
        self.objects
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains_key(key)
    }
}

impl ObjectBackend for MemoryBackend {
    async fn size(&self, key: &str) -> Result<Option<u64>> {
        Ok(self
            .objects
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(key)
            .map(|b| b.len() as u64))
    }

    async fn head(&self, key: &str, n: usize) -> Result<Vec<u8>> {
        let map = self.objects.lock().unwrap_or_else(|p| p.into_inner());
        let b = map.get(key).ok_or_else(Error::not_found)?;
        Ok(b[..n.min(b.len())].to_vec())
    }

    async fn copy(&self, from: &str, to: &str) -> Result<()> {
        let mut map = self.objects.lock().unwrap_or_else(|p| p.into_inner());
        let b = map.get(from).cloned().ok_or_else(Error::not_found)?;
        map.insert(to.to_owned(), b);
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.objects
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(key);
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct UploadLimits {
    pub max_bytes: u64,
    /// How long a presigned URL works, in seconds.
    pub url_ttl_secs: u32,
}

impl Default for UploadLimits {
    fn default() -> Self {
        Self {
            max_bytes: 10 * 1024 * 1024,
            url_ttl_secs: 300,
        }
    }
}

/// What a client needs to upload one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Begun {
    pub key: String,
    pub url: String,
    /// Headers the client must send, exactly.
    pub headers: Vec<(String, String)>,
    pub expires_in_secs: u32,
}

pub struct FileFlow<B> {
    pub config: S3Config,
    pub backend: B,
    pub limits: UploadLimits,
}

fn refusal(r: &Refusal) -> Error {
    match r {
        Refusal::TypeNotAllowed => Error::invalid_input(
            "file_type_not_allowed",
            format!("a file must be one of: {}", ALLOWED_TYPES.join(", ")),
        ),
        Refusal::ContentDoesNotMatch => Error::invalid_input(
            "file_content_mismatch",
            "the file is not what its type says it is",
        ),
    }
}

impl<B: ObjectBackend> FileFlow<B> {
    /// A presigned upload into quarantine. The type and size are checked first and then
    /// signed into the URL.
    pub fn begin_upload(
        &self,
        tenant: Option<&str>,
        id: &str,
        content_type: &str,
        size: u64,
        now_secs: i64,
    ) -> Result<Begun> {
        if !ALLOWED_TYPES.contains(&content_type) {
            return Err(refusal(&Refusal::TypeNotAllowed));
        }
        if size == 0 || size > self.limits.max_bytes {
            return Err(Error::invalid_input(
                "file_size",
                format!(
                    "a file must be between 1 and {} bytes",
                    self.limits.max_bytes
                ),
            ));
        }
        let key = object_key(Area::Quarantine, tenant, id)?;
        let len = size.to_string();
        let headers = [
            ("content-type", content_type),
            ("content-length", len.as_str()),
        ];
        let url = presign(
            &self.config,
            "PUT",
            &key,
            self.limits.url_ttl_secs,
            &headers,
            &[],
            now_secs,
        );
        Ok(Begun {
            key,
            url,
            headers: headers
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            expires_in_secs: self.limits.url_ttl_secs,
        })
    }

    /// Check an uploaded file and, if it is what it says, move it out of quarantine.
    /// A file that is missing, the wrong size or the wrong kind is deleted and refused.
    pub async fn finish_upload(
        &self,
        tenant: Option<&str>,
        id: &str,
        declared_type: &str,
        declared_size: u64,
    ) -> Result<String> {
        let from = object_key(Area::Quarantine, tenant, id)?;
        let to = object_key(Area::Clean, tenant, id)?;
        let Some(size) = self.backend.size(&from).await? else {
            return Err(Error::invalid_input(
                "file_missing",
                "no upload was received",
            ));
        };
        let verdict = if size != declared_size || size > self.limits.max_bytes {
            Err(Error::invalid_input(
                "file_size",
                "the file is not the size that was declared",
            ))
        } else {
            let head = self.backend.head(&from, SNIFF_BYTES).await?;
            check_declared(declared_type, &head).map_err(|r| refusal(&r))
        };
        match verdict {
            Ok(()) => {
                self.backend.copy(&from, &to).await?;
                // The upload URL stays valid for its whole lifetime and the client can
                // write to the quarantine key at any moment, so what was checked may not
                // be what was copied. The copy cannot be changed by the client: check
                // that, and only then call the file clean.
                let copied = async {
                    if self.backend.size(&to).await? != Some(declared_size) {
                        return Err(Error::invalid_input(
                            "file_size",
                            "the file is not the size that was declared",
                        ));
                    }
                    let head = self.backend.head(&to, SNIFF_BYTES).await?;
                    check_declared(declared_type, &head).map_err(|r| refusal(&r))
                }
                .await;
                if let Err(e) = copied {
                    let _ = self.backend.delete(&to).await;
                    self.backend.delete(&from).await?;
                    return Err(e);
                }
                self.backend.delete(&from).await?;
                Ok(to)
            }
            Err(e) => {
                self.backend.delete(&from).await?;
                Err(e)
            }
        }
    }

    /// A short-lived download URL for a checked file, served as an attachment.
    pub fn download_url(
        &self,
        tenant: Option<&str>,
        id: &str,
        file_name: &str,
        now_secs: i64,
    ) -> Result<String> {
        let key = object_key(Area::Clean, tenant, id)?;
        // Only characters that are safe in a header value.
        let safe: String = file_name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                    c
                } else {
                    '_'
                }
            })
            .take(100)
            .collect();
        let disposition = format!("attachment; filename=\"{safe}\"");
        Ok(presign(
            &self.config,
            "GET",
            &key,
            self.limits.url_ttl_secs,
            &[],
            &[
                ("response-content-disposition", disposition.as_str()),
                ("response-content-type", "application/octet-stream"),
            ],
            now_secs,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        future::Future,
        pin::pin,
        task::{Context, Poll, Waker},
    };

    const T: &str = "00000000-0000-0000-0000-0000000000a1";
    const ID: &str = "11111111-2222-3333-4444-555555555555";
    const PNG: &[u8] = &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 1, 2, 3];

    fn block_on<F: Future>(f: F) -> F::Output {
        let mut f = pin!(f);
        let mut cx = Context::from_waker(Waker::noop());
        loop {
            if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }

    fn flow() -> FileFlow<MemoryBackend> {
        FileFlow {
            config: S3Config {
                endpoint: "http://store.test:9000".into(),
                bucket: "b".into(),
                region: "us-east-1".into(),
                access_key: "k".into(),
                secret_key: "s".into(),
                path_style: true,
            },
            backend: MemoryBackend::default(),
            limits: UploadLimits {
                max_bytes: 1000,
                url_ttl_secs: 60,
            },
        }
    }

    #[test]
    fn the_type_and_size_are_checked_before_a_url_exists() {
        let f = flow();
        assert!(f.begin_upload(Some(T), ID, "text/html", 10, 0).is_err());
        assert!(f.begin_upload(Some(T), ID, "image/png", 0, 0).is_err());
        assert!(f.begin_upload(Some(T), ID, "image/png", 1001, 0).is_err());
        let ok = f.begin_upload(Some(T), ID, "image/png", 11, 0).unwrap();
        assert_eq!(ok.key, format!("quarantine/{T}/{ID}"));
        assert!(
            ok.url.contains("content-length%3Bcontent-type%3Bhost"),
            "{}",
            ok.url
        );
        assert!(ok.headers.contains(&("content-length".into(), "11".into())));
    }

    #[test]
    fn a_good_file_moves_out_of_quarantine() {
        let f = flow();
        f.backend.put(&format!("quarantine/{T}/{ID}"), PNG);
        let to = block_on(f.finish_upload(Some(T), ID, "image/png", PNG.len() as u64)).unwrap();
        assert_eq!(to, format!("files/{T}/{ID}"));
        assert!(f.backend.has(&to));
        assert!(!f.backend.has(&format!("quarantine/{T}/{ID}")));
    }

    #[test]
    fn a_file_that_is_not_what_it_says_is_deleted_and_never_published() {
        let f = flow();
        let q = format!("quarantine/{T}/{ID}");
        let exe: &[u8] = b"MZ\x90\x00 an executable";
        f.backend.put(&q, exe);
        let err =
            block_on(f.finish_upload(Some(T), ID, "image/png", exe.len() as u64)).unwrap_err();
        assert_eq!(err.code(), "file_content_mismatch");
        assert!(!f.backend.has(&q));
        assert!(!f.backend.has(&format!("files/{T}/{ID}")));
    }

    /// A store whose quarantine object is replaced by the client after the check and
    /// before the copy: the URL is still valid, so the client can do this.
    struct Swapping {
        inner: MemoryBackend,
        swap_on_copy: Vec<u8>,
    }

    impl ObjectBackend for Swapping {
        async fn size(&self, key: &str) -> Result<Option<u64>> {
            self.inner.size(key).await
        }
        async fn head(&self, key: &str, n: usize) -> Result<Vec<u8>> {
            self.inner.head(key, n).await
        }
        async fn copy(&self, from: &str, to: &str) -> Result<()> {
            self.inner.put(from, &self.swap_on_copy);
            self.inner.copy(from, to).await
        }
        async fn delete(&self, key: &str) -> Result<()> {
            self.inner.delete(key).await
        }
    }

    #[test]
    fn a_file_swapped_after_the_check_is_not_published() {
        let f = flow();
        let swapping = FileFlow {
            config: f.config.clone(),
            limits: f.limits,
            backend: Swapping {
                inner: MemoryBackend::default(),
                // Same length, no longer a PNG.
                swap_on_copy: {
                    let mut v = b"MZ".to_vec();
                    v.resize(PNG.len() + 10, b'x');
                    v
                },
            },
        };
        let q = format!("quarantine/{T}/{ID}");
        let mut good = PNG.to_vec();
        good.extend_from_slice(&[0; 10]);
        swapping.backend.inner.put(&q, &good);
        let err = block_on(swapping.finish_upload(Some(T), ID, "image/png", good.len() as u64))
            .unwrap_err();
        assert_eq!(err.code(), "file_content_mismatch");
        assert!(!swapping.backend.inner.has(&format!("files/{T}/{ID}")));
        assert!(!swapping.backend.inner.has(&q));
    }

    #[test]
    fn a_wrong_size_or_a_missing_upload_is_refused() {
        let f = flow();
        let q = format!("quarantine/{T}/{ID}");
        f.backend.put(&q, PNG);
        assert_eq!(
            block_on(f.finish_upload(Some(T), ID, "image/png", 3))
                .unwrap_err()
                .code(),
            "file_size"
        );
        assert!(!f.backend.has(&q));
        assert_eq!(
            block_on(f.finish_upload(Some(T), ID, "image/png", 3))
                .unwrap_err()
                .code(),
            "file_missing"
        );
    }

    #[test]
    fn one_tenant_cannot_finish_or_fetch_another_tenants_file() {
        let f = flow();
        let other = "00000000-0000-0000-0000-0000000000b2";
        f.backend.put(&format!("quarantine/{T}/{ID}"), PNG);
        let err =
            block_on(f.finish_upload(Some(other), ID, "image/png", PNG.len() as u64)).unwrap_err();
        assert_eq!(err.code(), "file_missing");
        assert!(f.backend.has(&format!("quarantine/{T}/{ID}")));
        let url = f.download_url(Some(other), ID, "x.png", 0).unwrap();
        assert!(url.contains(&format!("files/{other}/{ID}")), "{url}");
        assert!(!url.contains(T));
    }

    #[test]
    fn a_download_is_an_attachment_with_a_clean_name() {
        let f = flow();
        let url = f.download_url(Some(T), ID, "../a\"b\r\nc.png", 0).unwrap();
        assert!(
            url.contains("response-content-disposition=attachment"),
            "{url}"
        );
        assert!(
            url.contains("response-content-type=application%2Foctet-stream"),
            "{url}"
        );
        assert!(!url.contains("%0D") && !url.contains("%22b"), "{url}");
    }
}
