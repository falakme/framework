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
    ) -> Result<Option<ureq::http::Response<ureq::Body>>> {
        let conditional = extra.iter().any(|(k, _)| *k == "if-none-match");
        let signed = sign_request(
            &self.config,
            method,
            key,
            extra,
            EMPTY_SHA256,
            wall_clock_micros() / 1_000_000,
        );
        let mut req = ureq::http::Request::builder()
            .method(method)
            .uri(signed.url.as_str());
        for (k, v) in &signed.headers {
            req = req.header(k.as_str(), v.as_str());
        }
        let req = req.body(()).map_err(unavailable)?;
        match ureq::run(req) {
            Ok(r) => Ok(Some(r)),
            Err(ureq::Error::StatusCode(404)) => Ok(None),
            // A conditional write that lost: the object is already there.
            Err(ureq::Error::StatusCode(409 | 412)) if conditional => Err(Error::new(
                falak_contracts::ErrorKind::Conflict,
                "object_exists",
                "the object already exists",
            )),
            Err(ureq::Error::StatusCode(code)) => Err(unavailable(format!("status {code}"))),
            Err(e) => Err(unavailable(e)),
        }
    }
}

impl ObjectBackend for S3Backend {
    async fn size(&self, key: &str) -> Result<Option<u64>> {
        Ok(self.call("HEAD", key, &[])?.and_then(|r| {
            r.headers()
                .get("content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse().ok())
        }))
    }

    async fn head(&self, key: &str, n: usize) -> Result<Vec<u8>> {
        let range = format!("bytes=0-{}", n.saturating_sub(1));
        let Some(resp) = self.call("GET", key, &[("range", range.as_str())])? else {
            return Err(Error::not_found());
        };
        let mut buf = Vec::with_capacity(n);
        std::io::Read::take(resp.into_body().into_reader(), n as u64)
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

    async fn copy_if_absent(&self, from: &str, to: &str) -> Result<bool> {
        let source = format!("/{}/{}", self.config.bucket, encode(from, true));
        // `If-None-Match: *` makes the store create the object only if none exists.
        match self.call(
            "PUT",
            to,
            &[
                ("if-none-match", "*"),
                ("x-amz-copy-source", source.as_str()),
            ],
        ) {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Err(Error::not_found()),
            Err(e) if e.code() == "object_exists" => Ok(false),
            Err(e) => Err(e),
        }
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.call("DELETE", key, &[])?;
        Ok(())
    }
}
