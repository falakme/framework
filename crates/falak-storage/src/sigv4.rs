//! AWS Signature Version 4 for S3 and S3-compatible stores such as R2 and MinIO.
//!
//! Two uses: a presigned URL a client can use alone (query authentication), and the
//! `Authorization` header for the server's own calls.

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Where the bucket is and how to sign for it.
#[derive(Clone)]
pub struct S3Config {
    /// `https://<account>.r2.cloudflarestorage.com`, a local MinIO address, ...
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    pub access_key: String,
    pub secret_key: String,
    /// `endpoint/bucket/key` (R2, MinIO) rather than `bucket.endpoint/key` (AWS).
    pub path_style: bool,
}

impl std::fmt::Debug for S3Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Config")
            .field("endpoint", &self.endpoint)
            .field("bucket", &self.bucket)
            .field("region", &self.region)
            .finish_non_exhaustive()
    }
}

/// The empty payload's SHA-256, for requests with no body.
pub const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";

fn hmac(key: &[u8], data: &str) -> Vec<u8> {
    let mut m = HmacSha256::new_from_slice(key).expect("HMAC takes any key length");
    m.update(data.as_bytes());
    m.finalize().into_bytes().to_vec()
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Percent-encode as SigV4 requires: letters, digits and `-_.~` stay; `/` stays in a
/// path and is encoded in a query value.
pub fn encode(s: &str, keep_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            b'/' if keep_slash => out.push('/'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// `(YYYYMMDD, YYYYMMDDTHHMMSSZ)` for a Unix time in seconds.
pub fn amz_dates(now_secs: i64) -> (String, String) {
    let days = now_secs.div_euclid(86_400);
    let rem = now_secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = i64::from(yoe) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    let date = format!("{y:04}{m:02}{d:02}");
    let stamp = format!(
        "{date}T{:02}{:02}{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    );
    (date, stamp)
}

fn host_and_scheme(cfg: &S3Config) -> (String, String) {
    let (scheme, rest) = cfg
        .endpoint
        .split_once("://")
        .unwrap_or(("https", &cfg.endpoint));
    let rest = rest.trim_end_matches('/');
    let host = if cfg.path_style {
        rest.to_owned()
    } else {
        format!("{}.{rest}", cfg.bucket)
    };
    (scheme.to_owned(), host)
}

fn canonical_path(cfg: &S3Config, key: &str) -> String {
    if cfg.path_style {
        format!("/{}/{}", encode(&cfg.bucket, true), encode(key, true))
    } else {
        format!("/{}", encode(key, true))
    }
}

fn signing_key(cfg: &S3Config, date: &str) -> Vec<u8> {
    let k = hmac(format!("AWS4{}", cfg.secret_key).as_bytes(), date);
    let k = hmac(&k, &cfg.region);
    let k = hmac(&k, "s3");
    hmac(&k, "aws4_request")
}

fn canonical_query(params: &[(String, String)]) -> String {
    let mut p: Vec<(String, String)> = params
        .iter()
        .map(|(k, v)| (encode(k, false), encode(v, false)))
        .collect();
    p.sort();
    p.iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

struct Parts<'a> {
    method: &'a str,
    key: &'a str,
    query: &'a [(String, String)],
    headers: &'a [(String, String)],
    payload: &'a str,
    date: &'a str,
    stamp: &'a str,
}

/// The signature, and the signed header names.
fn sign(cfg: &S3Config, p: &Parts) -> (String, String) {
    let mut h: Vec<(String, String)> = p
        .headers
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v.trim().to_owned()))
        .collect();
    h.sort();
    let canonical_headers: String = h.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    let signed = h
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let canonical = format!(
        "{}\n{}\n{}\n{canonical_headers}\n{signed}\n{}",
        p.method,
        canonical_path(cfg, p.key),
        canonical_query(p.query),
        p.payload
    );
    let scope = format!("{}/{}/s3/aws4_request", p.date, cfg.region);
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{scope}\n{}",
        p.stamp,
        sha256_hex(canonical.as_bytes())
    );
    let signature = hex::encode(hmac(&signing_key(cfg, p.date), &to_sign));
    (signature, signed)
}

/// A presigned URL. `headers` are the headers the client must send with exactly these
/// values (for example `content-type` and `content-length` on an upload); the host is
/// added. `query` adds fixed query parameters such as `response-content-disposition`.
pub fn presign(
    cfg: &S3Config,
    method: &str,
    key: &str,
    expires_secs: u32,
    headers: &[(&str, &str)],
    query: &[(&str, &str)],
    now_secs: i64,
) -> String {
    let (date, stamp) = amz_dates(now_secs);
    let (scheme, host) = host_and_scheme(cfg);
    let mut hs: Vec<(String, String)> = vec![("host".into(), host.clone())];
    hs.extend(
        headers
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned())),
    );
    let mut signed_names: Vec<String> = hs.iter().map(|(k, _)| k.to_lowercase()).collect();
    signed_names.sort();
    let mut q: Vec<(String, String)> = query
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    q.extend([
        ("X-Amz-Algorithm".into(), "AWS4-HMAC-SHA256".into()),
        (
            "X-Amz-Credential".into(),
            format!("{}/{date}/{}/s3/aws4_request", cfg.access_key, cfg.region),
        ),
        ("X-Amz-Date".into(), stamp.clone()),
        ("X-Amz-Expires".into(), expires_secs.to_string()),
        ("X-Amz-SignedHeaders".into(), signed_names.join(";")),
    ]);
    let (signature, _) = sign(
        cfg,
        &Parts {
            method,
            key,
            query: &q,
            headers: &hs,
            payload: UNSIGNED_PAYLOAD,
            date: &date,
            stamp: &stamp,
        },
    );
    format!(
        "{scheme}://{host}{}?{}&X-Amz-Signature={signature}",
        canonical_path(cfg, key),
        canonical_query(&q)
    )
}

/// The URL and headers for a request the server makes itself.
pub struct Signed {
    pub url: String,
    pub headers: Vec<(String, String)>,
}

/// Sign a request with the `Authorization` header. `payload_sha256` is the hex SHA-256
/// of the body ([`EMPTY_SHA256`] for none).
pub fn sign_request(
    cfg: &S3Config,
    method: &str,
    key: &str,
    extra_headers: &[(&str, &str)],
    payload_sha256: &str,
    now_secs: i64,
) -> Signed {
    let (date, stamp) = amz_dates(now_secs);
    let (scheme, host) = host_and_scheme(cfg);
    let mut hs: Vec<(String, String)> = vec![
        ("host".into(), host.clone()),
        ("x-amz-content-sha256".into(), payload_sha256.to_owned()),
        ("x-amz-date".into(), stamp.clone()),
    ];
    hs.extend(
        extra_headers
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned())),
    );
    let (signature, signed) = sign(
        cfg,
        &Parts {
            method,
            key,
            query: &[],
            headers: &hs,
            payload: payload_sha256,
            date: &date,
            stamp: &stamp,
        },
    );
    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={}/{date}/{}/s3/aws4_request, SignedHeaders={signed}, Signature={signature}",
        cfg.access_key, cfg.region
    );
    let mut headers: Vec<(String, String)> = hs.into_iter().filter(|(k, _)| k != "host").collect();
    headers.push(("authorization".into(), auth));
    Signed {
        url: format!("{scheme}://{host}{}", canonical_path(cfg, key)),
        headers,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The public example credentials from the AWS documentation.
    fn aws_example() -> S3Config {
        S3Config {
            endpoint: "https://s3.amazonaws.com".into(),
            bucket: "examplebucket".into(),
            region: "us-east-1".into(),
            access_key: ["AKIAIOSFODNN7", "EXAMPLE"].concat(),
            secret_key: ["wJalrXUtnFEMI/K7MDENG/bPxRfiCY", "EXAMPLEKEY"].concat(),
            path_style: false,
        }
    }

    #[test]
    fn the_aws_documented_presigned_get_signature_is_reproduced() {
        // From "Authenticating Requests: Using Query Parameters (AWS Signature Version 4)".
        let url = presign(
            &aws_example(),
            "GET",
            "test.txt",
            86_400,
            &[],
            &[],
            1_369_353_600,
        );
        assert!(
            url.ends_with(
                "X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
            ),
            "{url}"
        );
        assert!(url.starts_with("https://examplebucket.s3.amazonaws.com/test.txt?"));
    }

    #[test]
    fn hmac_and_sha256_match_published_known_answers() {
        // RFC 4231 test case 2, and the FIPS 180 "abc" vector: these must not change
        // across RustCrypto upgrades, since signatures and stored hashes depend on them.
        assert_eq!(
            hex::encode(hmac(b"Jefe", "what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn dates_are_formatted_in_utc() {
        assert_eq!(
            amz_dates(1_369_353_600),
            ("20130524".to_owned(), "20130524T000000Z".to_owned())
        );
        assert_eq!(amz_dates(0).1, "19700101T000000Z");
    }

    #[test]
    fn encoding_keeps_unreserved_and_escapes_the_rest() {
        assert_eq!(encode("a b/c~d", true), "a%20b/c~d");
        assert_eq!(encode("a b/c", false), "a%20b%2Fc");
        assert_eq!(encode("é", true), "%C3%A9");
    }

    #[test]
    fn a_path_style_url_names_the_bucket_in_the_path() {
        let mut cfg = aws_example();
        cfg.endpoint = "http://minio.test:9000".into();
        cfg.path_style = true;
        let url = presign(
            &cfg,
            "PUT",
            "files/x",
            60,
            &[("content-type", "image/png")],
            &[],
            0,
        );
        assert!(
            url.starts_with("http://minio.test:9000/examplebucket/files/x?"),
            "{url}"
        );
        assert!(
            url.contains("X-Amz-SignedHeaders=content-type%3Bhost"),
            "{url}"
        );
    }

    #[test]
    fn the_signature_depends_on_the_signed_headers() {
        let cfg = aws_example();
        let a = presign(&cfg, "PUT", "k", 60, &[("content-length", "10")], &[], 0);
        let b = presign(&cfg, "PUT", "k", 60, &[("content-length", "11")], &[], 0);
        assert_ne!(a, b);
    }

    #[test]
    fn debug_output_never_shows_the_secret() {
        let text = format!("{:?}", aws_example());
        assert!(!text.contains("wJalr"));
        assert!(!text.contains("AKIA"));
    }
}
