//! The edge relay (T5.4, FEDERATION §13.6).
//!
//! A Worker has no background thread, so events move in two ways: a Cron Trigger runs a
//! pass every minute, and a request that wrote something starts one at once
//! (`ctx.wait_until`). A pass is the same logic as the native loops, over D1:
//!
//! 1. register the app's contract with Office;
//! 2. send the outbox to Office in order, marking a row sent only after Office has stored
//!    it (so a Worker that dies mid-pass sends the row again, and Office deduplicates);
//! 3. claim what Office delivers, verify it, apply it through the inbox and acknowledge.
//!
//! Everything lives in D1, so any isolate can pick up where another stopped.

use std::sync::Arc;

use falak_contracts::ir::Ir;
use falak_core::sql::Dialect;
use falak_federation::{events as fe, now, random_nonce, request_headers};
use falak_runtime_native::{
    driver::NativeDriver,
    events::{ApplyError, apply, relay_once},
};
use serde_json::{Value, json};
use worker::{Fetch, Headers, Method, Request, RequestInit};

use crate::office::OfficeLink;

pub struct EdgeEvents {
    ir: Arc<Ir>,
    driver: Arc<dyn NativeDriver>,
    link: Arc<OfficeLink>,
}

/// A signed request to Office with a JSON body.
async fn call(link: &OfficeLink, method: &str, path: &str, body: &Value) -> Result<Value, String> {
    let text = body.to_string();
    let headers = Headers::new();
    for (k, v) in request_headers(
        link.key(),
        &link.config().app,
        method,
        path,
        text.as_bytes(),
        now(),
        &random_nonce(),
    ) {
        headers.set(&k, &v).map_err(|e| e.to_string())?;
    }
    headers
        .set("content-type", "application/json")
        .map_err(|e| e.to_string())?;
    let mut init = RequestInit::new();
    init.with_method(if method == "PUT" {
        Method::Put
    } else {
        Method::Post
    })
    .with_headers(headers)
    .with_body(Some(text.into()));
    let url = format!("{}{path}", link.config().office_url.trim_end_matches('/'));
    let req = Request::new_with_init(&url, &init).map_err(|e| e.to_string())?;
    let mut res = Fetch::Request(req)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !(200..300).contains(&res.status_code()) {
        return Err(format!("Office answered {}", res.status_code()));
    }
    let text = res.text().await.map_err(|e| e.to_string())?;
    serde_json::from_str(&text).map_err(|_| "Office sent something unreadable".to_owned())
}

impl EdgeEvents {
    pub fn new(ir: Arc<Ir>, driver: Arc<dyn NativeDriver>, link: Arc<OfficeLink>) -> Self {
        Self { ir, driver, link }
    }

    /// One pass. Safe to run at the same time as another: the outbox row is marked sent
    /// after Office has it, Office deduplicates by event id and the inbox by event id.
    pub async fn run_once(&self) {
        self.link.refresh_if_needed(None).await;
        if let Err(why) = call(
            &self.link,
            "PUT",
            "/v1/_office/events/contract",
            &fe::contract_body(&self.ir),
        )
        .await
        {
            worker::console_error!("falak events: cannot register the contract: {why}");
            return;
        }
        self.relay().await;
        if !self.ir.subscriptions.is_empty() {
            self.consume().await;
        }
    }

    async fn relay(&self) {
        let app = self.link.config().app.clone();
        let result = relay_once(
            &self.driver,
            Dialect::D1,
            50,
            falak_contracts::support::wall_clock_micros(),
            |row| {
                let body = fe::publish_body(self.link.key(), &app, &row);
                let link = self.link.clone();
                async move {
                    call(&link, "POST", "/v1/_office/events", &body)
                        .await
                        .map(|_| ())
                }
            },
        )
        .await;
        match result {
            Ok(r) => {
                if let Some(why) = r.stopped {
                    worker::console_error!("falak events: Office did not take an event: {why}");
                }
            }
            Err(e) => worker::console_error!("falak events: relay: {}", e.public_message()),
        }
    }

    async fn consume(&self) {
        let claimed = call(
            &self.link,
            "POST",
            "/v1/_office/events/claim",
            &json!({"limit": 20}),
        )
        .await;
        let items = match claimed {
            Ok(v) => v["events"].as_array().cloned().unwrap_or_default(),
            Err(why) => {
                worker::console_error!("falak events: claim: {why}");
                return;
            }
        };
        let fed = self.link.federation();
        for item in items {
            let Some(seq) = item["seq"].as_i64() else {
                continue;
            };
            let mut verified = fe::verify_delivery(&item, &fed.keys());
            if verified.is_err() {
                // Office may have rotated its key: look again once.
                self.link.reload_keys().await;
                verified = fe::verify_delivery(&item, &fed.keys());
            }
            let (outcome, error) = match verified {
                Err(e) => ("fail", e),
                Ok(d) => {
                    let at = falak_contracts::support::wall_clock_micros();
                    match apply(&self.driver, &self.ir, Dialect::D1, &d, at).await {
                        Ok(_) => ("ok", String::new()),
                        Err(ApplyError::Retry(m)) => ("retry", m),
                        Err(ApplyError::Permanent(m)) => ("fail", m),
                    }
                }
            };
            let _ = call(
                &self.link,
                "POST",
                "/v1/_office/events/ack",
                &json!({"seq": seq, "outcome": outcome, "error": error}),
            )
            .await;
        }
    }
}
