//! Calls to Office over HTTP. Blocking: run them from a blocking task or the CLI.

use serde_json::Value;

use crate::{AppKey, Federation, OfficeConfig, enroll_request, now, random_nonce, request_headers};

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(10)))
        // Keys and the feed come from the configured address only: a redirect could
        // move them to plain http, or carry a signed request to another host.
        .max_redirects(0)
        .build()
        .into()
}

fn read(resp: Result<ureq::http::Response<ureq::Body>, ureq::Error>) -> Result<Value, String> {
    match resp {
        // A redirect is not followed, so a 3xx arrives here as an answer: refuse it.
        Ok(r) if !r.status().is_success() => {
            Err(format!("Office answered {}", r.status().as_u16()))
        }
        Ok(mut r) => r
            .body_mut()
            .read_json()
            .map_err(|e| format!("Office sent something unreadable: {e}")),
        Err(ureq::Error::StatusCode(code)) => Err(format!("Office answered {code}")),
        Err(e) => Err(format!("cannot reach Office: {e}")),
    }
}

/// `POST /v1/_office/enroll`. Returns Office's answer (the passport).
pub fn enroll(office_url: &str, token: &str, app: &str, key: &AppKey) -> Result<Value, String> {
    let body = enroll_request(key, token, app, now(), &random_nonce());
    let url = format!("{}/v1/_office/enroll", office_url.trim_end_matches('/'));
    read(agent().post(&url).send_json(body))
}

/// A signed `GET` to Office.
pub fn signed_get(cfg: &OfficeConfig, key: &AppKey, path_and_query: &str) -> Result<Value, String> {
    let headers = request_headers(
        key,
        &cfg.app,
        "GET",
        path_and_query,
        b"",
        now(),
        &random_nonce(),
    );
    let url = format!("{}{path_and_query}", cfg.office_url.trim_end_matches('/'));
    let mut req = agent().get(&url);
    for (k, v) in headers {
        req = req.header(k.as_str(), v.as_str());
    }
    read(req.call())
}

/// A signed request with a JSON body (`POST`, `PUT`). Any answer but a success is an
/// error that says the status, so a caller can tell a refusal from an outage.
pub fn signed_send(
    cfg: &OfficeConfig,
    key: &AppKey,
    method: &str,
    path_and_query: &str,
    body: &Value,
) -> Result<Value, String> {
    let text = body.to_string();
    let headers = request_headers(
        key,
        &cfg.app,
        method,
        path_and_query,
        text.as_bytes(),
        now(),
        &random_nonce(),
    );
    let url = format!("{}{path_and_query}", cfg.office_url.trim_end_matches('/'));
    let mut req = ureq::http::Request::builder()
        .method(method)
        .uri(url.as_str())
        .header("content-type", "application/json");
    for (k, v) in headers {
        req = req.header(k.as_str(), v.as_str());
    }
    let req = req.body(text).map_err(|e| format!("bad request: {e}"))?;
    read(agent().run(req))
}

/// Tell Office what this app publishes and consumes.
pub fn put_contract(cfg: &OfficeConfig, key: &AppKey, body: &Value) -> Result<(), String> {
    signed_send(cfg, key, "PUT", "/v1/_office/events/contract", body).map(|_| ())
}

/// Publish one signed event. `Ok` only after Office has stored it.
pub fn publish_event(cfg: &OfficeConfig, key: &AppKey, body: &Value) -> Result<(), String> {
    signed_send(cfg, key, "POST", "/v1/_office/events", body).map(|_| ())
}

/// The caller's next deliveries.
pub fn claim_events(cfg: &OfficeConfig, key: &AppKey, limit: u32) -> Result<Vec<Value>, String> {
    let v = signed_send(
        cfg,
        key,
        "POST",
        "/v1/_office/events/claim",
        &serde_json::json!({"limit": limit}),
    )?;
    Ok(v["events"].as_array().cloned().unwrap_or_default())
}

/// Acknowledge a delivery: `ok`, `retry` or `fail`.
pub fn ack_event(
    cfg: &OfficeConfig,
    key: &AppKey,
    seq: i64,
    outcome: &str,
    error: &str,
) -> Result<(), String> {
    signed_send(
        cfg,
        key,
        "POST",
        "/v1/_office/events/ack",
        &serde_json::json!({"seq": seq, "outcome": outcome, "error": error}),
    )
    .map(|_| ())
}

pub fn fetch_jwks(cfg: &OfficeConfig) -> Result<String, String> {
    agent()
        .get(&cfg.jwks_url)
        .call()
        .map_err(|e| format!("cannot fetch the key set: {e}"))?
        .body_mut()
        .read_to_string()
        .map_err(|e| e.to_string())
}

/// One round of keeping up with Office: refresh the key set if it is stale, then fetch
/// and apply the revocation feed. A failure is recorded and the old knowledge stays.
pub fn sync_once(fed: &Federation, cfg: &OfficeConfig, key: &AppKey) -> Result<(), String> {
    let result: Result<(), String> = (|| {
        let t = now();
        if fed.wants_jwks(t) {
            fed.load_jwks(&fetch_jwks(cfg)?, t)?;
        }
        let doc = signed_get(cfg, key, &fed.feed_path())?;
        if let Err(first) = fed.apply_document(&doc, now()) {
            // The feed may be signed with a key we have not seen: one refetch.
            fed.load_jwks(&fetch_jwks(cfg)?, t)?;
            fed.apply_document(&doc, now()).map_err(|_| first)?;
        }
        Ok(())
    })();
    if let Err(e) = &result {
        fed.note_error(e.clone());
    }
    result
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::TcpListener,
    };

    use super::*;

    /// Answer one request with a fixed reply; return the address.
    fn serve_once(reply: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 2048];
            let _ = s.read(&mut buf);
            s.write_all(reply.as_bytes()).unwrap();
        });
        format!("http://{addr}")
    }

    #[test]
    fn a_json_answer_is_read() {
        let url = serve_once(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 8\r\nconnection: close\r\n\r\n{\"a\": 1}",
        );
        assert_eq!(read(agent().get(&url).call()).unwrap()["a"], 1);
    }

    #[test]
    fn a_redirect_is_not_followed_and_a_refusal_names_its_status() {
        let url = serve_once(
            "HTTP/1.1 302 Found\r\nlocation: http://127.0.0.1:1/elsewhere\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
        );
        assert_eq!(
            read(agent().get(&url).call()).unwrap_err(),
            "Office answered 302"
        );
        let url =
            serve_once("HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
        assert_eq!(
            read(agent().get(&url).call()).unwrap_err(),
            "Office answered 403"
        );
    }
}
