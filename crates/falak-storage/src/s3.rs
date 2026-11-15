//! The S3 and R2 backend over HTTP. Blocking: call it from a thread that may block (a
//! `spawn_blocking` task, a CLI), not from an async executor thread.

use std::io::Read;

use falak_contracts::{Error, Result, support::wall_clock_micros};

use crate::{
    flow::ObjectBackend,
    sigv4::{EMPTY_SHA256, S3Config, encode, sign_request},
};

pub struct S3Backend {
    pub config: S3Config,
}

fn unavailable(e: impl std::fmt::Display) -> Error {
    Error::new(
        falak_contracts::ErrorKind::Unavailable,
        "object_store_unavailable",
        format!("the object store did not answer: {e}"),
    )
}

impl S3Backend {
    fn call(
        &self,
        method: &str,
        key: &str,
        extra: &[(&str, &str)],
    ) -> Result<Option<ureq::Response>> {
        let signed = sign_request(
            &self.config,
            method,
            key,
            extra,
            EMPTY_SHA256,
            wall_clock_micros() / 1_000_000,
        );
        let mut req = ureq::request(method, &signed.url);
        for (k, v) in &signed.headers {
            req = req.set(k, v);
        }
        match req.call() {
            Ok(r) => Ok(Some(r)),
            Err(ureq::Error::Status(404, _)) => Ok(None),
            Err(ureq::Error::Status(code, _)) => Err(unavailable(format!("status {code}"))),
            Err(e) => Err(unavailable(e)),
        }
    }
}

impl ObjectBackend for S3Backend {
    async fn size(&self, key: &str) -> Result<Option<u64>> {
        Ok(self
            .call("HEAD", key, &[])?
            .and_then(|r| r.header("content-length").and_then(|v| v.parse().ok())))
    }

    async fn head(&self, key: &str, n: usize) -> Result<Vec<u8>> {
        let range = format!("bytes=0-{}", n.saturating_sub(1));
        let Some(resp) = self.call("GET", key, &[("range", range.as_str())])? else {
            return Err(Error::not_found());
        };
        let mut buf = Vec::with_capacity(n);
        std::io::Read::take(resp.into_reader(), n as u64)
            .read_to_end(&mut buf)
            .map_err(unavailable)?;
        Ok(buf)
    }

    async fn copy(&self, from: &str, to: &str) -> Result<()> {
        let source = format!("/{}/{}", self.config.bucket, encode(from, true));
        self.call("PUT", to, &[("x-amz-copy-source", source.as_str())])?
            .map(|_| ())
            .ok_or_else(Error::not_found)
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.call("DELETE", key, &[])?;
        Ok(())
    }
}
