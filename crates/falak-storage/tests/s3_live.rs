//! The flow against a real S3-compatible store (MinIO, R2). Set
//! `FALAK_TEST_S3=<endpoint>,<bucket>,<access key>,<secret key>`; without it the test
//! says so and passes. The bucket must exist.

use std::{
    future::Future,
    io::Read,
    pin::pin,
    task::{Context, Poll, Waker},
};

use falak_contracts::support::wall_clock_micros;
use falak_storage::{FileFlow, S3Config, UploadLimits, s3::S3Backend};

fn block_on<F: Future>(f: F) -> F::Output {
    let mut f = pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
    }
}

fn config() -> Option<S3Config> {
    let v = std::env::var("FALAK_TEST_S3").ok()?;
    let p: Vec<&str> = v.split(',').collect();
    Some(S3Config {
        endpoint: p[0].into(),
        bucket: p[1].into(),
        region: "us-east-1".into(),
        access_key: p[2].into(),
        secret_key: p[3].into(),
        path_style: true,
    })
}

fn put(url: &str, headers: &[(String, String)], body: &[u8]) -> u16 {
    let mut req = ureq::put(url);
    for (k, v) in headers {
        req = req.header(k.as_str(), v.as_str());
    }
    match req.send(body) {
        Ok(r) => r.status().as_u16(),
        Err(ureq::Error::StatusCode(code)) => code,
        Err(e) => panic!("{e}"),
    }
}

#[test]
fn upload_check_publish_and_download_against_a_real_store() {
    let Some(config) = config() else {
        eprintln!("skipped: FALAK_TEST_S3 is not set");
        return;
    };
    let flow = FileFlow {
        config: config.clone(),
        backend: S3Backend { config },
        limits: UploadLimits {
            max_bytes: 4096,
            url_ttl_secs: 60,
        },
    };
    let now = wall_clock_micros() / 1_000_000;
    let tenant = "00000000-0000-0000-0000-0000000000a1";
    let png: Vec<u8> = [
        &[0x89u8, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A][..],
        &[7u8; 40],
    ]
    .concat();

    // A good upload, through the presigned URL alone.
    let id = "11111111-2222-3333-4444-00000000a001";
    let begun = flow
        .begin_upload(Some(tenant), id, "image/png", png.len() as u64, now)
        .unwrap();
    assert_eq!(put(&begun.url, &begun.headers, &png), 200);

    // The type is signed: the same URL refuses another content type.
    let wrong = vec![
        ("content-type".to_owned(), "text/plain".to_owned()),
        ("content-length".to_owned(), png.len().to_string()),
    ];
    assert!(put(&begun.url, &wrong, &png) >= 400);
    // The size is signed too. A client that sends more bytes than it signed has the extra
    // bytes ignored by the server's HTTP framing, so `finish_upload` checks the stored size.

    let key =
        block_on(flow.finish_upload(Some(tenant), id, "image/png", png.len() as u64)).unwrap();
    assert_eq!(key, format!("files/{tenant}/{id}"));

    // Download: an attachment, with the right bytes.
    let url = flow
        .download_url(Some(tenant), id, "photo.png", now)
        .unwrap();
    let resp = ureq::get(&url).call().unwrap();
    let header = |n: &str| resp.headers().get(n).map(|v| v.to_str().unwrap());
    assert!(
        header("content-disposition")
            .unwrap()
            .starts_with("attachment")
    );
    assert_eq!(header("content-type"), Some("application/octet-stream"));
    let mut got = Vec::new();
    resp.into_body()
        .into_reader()
        .read_to_end(&mut got)
        .unwrap();
    assert_eq!(got, png);

    // A file that is not a PNG is refused and removed, and never reaches `files/`.
    let bad_id = "11111111-2222-3333-4444-00000000a002";
    let exe = b"MZ\x90\x00 pretending";
    let begun = flow
        .begin_upload(Some(tenant), bad_id, "image/png", exe.len() as u64, now)
        .unwrap();
    assert_eq!(put(&begun.url, &begun.headers, exe), 200);
    let err = block_on(flow.finish_upload(Some(tenant), bad_id, "image/png", exe.len() as u64))
        .unwrap_err();
    assert_eq!(err.code(), "file_content_mismatch");
    let dl = flow
        .download_url(Some(tenant), bad_id, "x.png", now)
        .unwrap();
    assert!(matches!(
        ureq::get(&dl).call(),
        Err(ureq::Error::StatusCode(404))
    ));

    // Another tenant's key is another object: the download of this id under a different
    // tenant is a 404, not the file.
    let other = "00000000-0000-0000-0000-0000000000b2";
    let dl = flow.download_url(Some(other), id, "x.png", now).unwrap();
    assert!(matches!(
        ureq::get(&dl).call(),
        Err(ureq::Error::StatusCode(404))
    ));
}
