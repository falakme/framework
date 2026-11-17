//! Calls to Office over HTTP. Blocking: run them from a blocking task or the CLI.

use serde_json::Value;

use crate::{AppKey, Federation, OfficeConfig, enroll_request, now, random_nonce, request_headers};

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(10))
        // Keys and the feed come from the configured address only: a redirect could
        // move them to plain http, or carry a signed request to another host.
        .redirects(0)
        .build()
}

fn read(resp: Result<ureq::Response, ureq::Error>) -> Result<Value, String> {
    match resp {
        Ok(r) => r
            .into_json()
            .map_err(|e| format!("Office sent something unreadable: {e}")),
        Err(ureq::Error::Status(code, _)) => Err(format!("Office answered {code}")),
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
        req = req.set(&k, &v);
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
    let mut req = agent()
        .request(method, &url)
        .set("content-type", "application/json");
    for (k, v) in headers {
        req = req.set(&k, &v);
    }
    read(req.send_string(&text))
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
        .into_string()
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
