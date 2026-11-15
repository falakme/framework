//! Calls to Office over HTTP. Blocking: run them from a blocking task or the CLI.

use serde_json::Value;

use crate::{
    AppKey, Federation, OfficeConfig, enroll_request, now, random_nonce, request_headers,
    verify_feed,
};

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(10))
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
        let path = format!("/v1/_office/revocations?since={}", fed.feed_version());
        let doc = signed_get(cfg, key, &path)?;
        let feed = match verify_feed(&doc, &fed.keys()) {
            Ok(f) => f,
            Err(first) => {
                // The feed may be signed with a key we have not seen: one refetch.
                fed.load_jwks(&fetch_jwks(cfg)?, t)?;
                verify_feed(&doc, &fed.keys()).map_err(|_| first)?
            }
        };
        fed.apply_feed(&feed, now());
        Ok(())
    })();
    if let Err(e) = &result {
        fed.note_error(e.clone());
    }
    result
}
