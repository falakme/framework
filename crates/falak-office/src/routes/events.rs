//! Office Events (FEDERATION §13): the durable store apps publish to and consume from,
//! with per-aggregate ordering, retries, a dead-letter queue and the saga orchestrator.
//!
//! An event is stored, with one delivery per authorised subscriber, in one transaction
//! before the publisher is told `200`. Subscribers pull their deliveries and acknowledge
//! each one after they have applied it.

use std::sync::atomic::{AtomicI64, Ordering};

use axum::{
    body::Bytes,
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use falak_contracts::{Error, Result, driver::Value};
use falak_core::outbox::signing_message;
use falak_runtime_native::context::extract_request_id;
use serde_json::{Value as Json, json};

use super::{Shared, body_json, fail, field, json_response, sha256_hex};
use crate::{
    Office,
    db::{int, t, text},
    now,
};

/// Delivery attempts before an event goes to the dead-letter queue.
pub const MAX_ATTEMPTS: i64 = 5;
/// How long a fully delivered event is kept, in seconds.
pub const RETENTION_SECS: i64 = 7 * 86_400;
/// The most events one claim returns.
const MAX_CLAIM: i64 = 100;
/// The largest payload Office stores.
const MAX_PAYLOAD: usize = 64 * 1024;

static LAST_PRUNE: AtomicI64 = AtomicI64::new(0);
static LAST_SAGA_SWEEP: AtomicI64 = AtomicI64::new(0);

fn conflict_err(code: &'static str, m: &str) -> Error {
    crate::conflict(code, m)
}

/// A named event, as one app's contract lists it.
struct Contract(Json);

impl Contract {
    fn published(&self, name: &str) -> Option<&Json> {
        self.0["events"]
            .as_array()?
            .iter()
            .find(|e| e["name"] == name)
    }

    fn subscription(&self, event: &str, from: &str) -> Option<&Json> {
        self.0["subscriptions"]
            .as_array()?
            .iter()
            .find(|s| s["event"] == event && s["from"] == from)
    }
}

impl Office {
    async fn contract(&self, app: &str) -> Result<Option<Contract>> {
        let rows = self
            .db
            .rows(
                "SELECT contract FROM office_contracts WHERE app = ?",
                vec![t(app)],
            )
            .await?;
        Ok(rows
            .first()
            .and_then(|r| serde_json::from_str(&text(r.first())).ok())
            .map(Contract))
    }

    async fn app_public_key(&self, app: &str) -> Result<Option<String>> {
        let rows = self
            .db
            .rows(
                "SELECT public_key FROM office_apps WHERE name = ? AND status = 'active'",
                vec![t(app)],
            )
            .await?;
        Ok(rows.first().map(|r| text(r.first())))
    }

    /// Store an event and a delivery for each subscriber, in one transaction. A second
    /// call with the same event id changes nothing. Returns the event's sequence number.
    #[allow(clippy::too_many_arguments)]
    async fn store_event(&self, e: &StoredEvent, subscribers: &[String]) -> Result<i64> {
        for _ in 0..8 {
            let existing = self
                .db
                .rows(
                    "SELECT seq, publisher FROM office_events WHERE id = ?",
                    vec![t(&e.id)],
                )
                .await?;
            if let Some(r) = existing.first() {
                // An id is one publisher's. Another app that sends the same id is not
                // told "stored": that would drop its event, and let it take an id its
                // neighbour is about to use.
                if text(r.get(1)) != e.publisher {
                    return Err(conflict_err(
                        "event_id_taken",
                        "That event id belongs to another publisher.",
                    ));
                }
                return Ok(int(r.first()));
            }
            let mut batch = vec![self.db.stmt(
                "INSERT INTO office_events (seq, id, publisher, signer, name, aggregate_type, aggregate_id, revision, version, occurred_at, payload, signature, saga_id, saga_step, saga_kind, received_at) \
                 SELECT COALESCE(MAX(seq), 0) + 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? FROM office_events",
                vec![
                    t(&e.id),
                    t(&e.publisher),
                    t(&e.signer),
                    t(&e.name),
                    t(&e.aggregate_type),
                    t(&e.aggregate_id),
                    Value::Int64(e.revision),
                    Value::Int64(e.version),
                    Value::Int64(e.occurred_at),
                    t(&e.payload),
                    t(&e.signature),
                    t(&e.saga_id),
                    Value::Int64(e.saga_step),
                    t(&e.saga_kind),
                    Value::Int64(now()),
                ],
            )];
            for s in subscribers {
                batch.push(self.db.stmt(
                    "INSERT INTO office_deliveries (seq, subscriber, status, attempts, next_at, last_error) \
                     SELECT seq, ?, 'pending', 0, 0, '' FROM office_events WHERE id = ?",
                    vec![t(s), t(&e.id)],
                ));
            }
            // A lost race for the sequence number or for the event id fails the whole
            // batch; the loop then finds the event or tries the next number.
            if self.db.batch(batch).await.is_ok() {
                let rows = self
                    .db
                    .rows("SELECT seq FROM office_events WHERE id = ?", vec![t(&e.id)])
                    .await?;
                return Ok(rows.first().map_or(0, |r| int(r.first())));
            }
        }
        Err(conflict_err("event_busy", "Try again."))
    }

    async fn prune_events(&self) {
        let cut = now() - RETENTION_SECS;
        let _ = self
            .db
            .batch(vec![
                self.db.stmt(
                    "DELETE FROM office_deliveries WHERE status = 'done' AND seq IN (SELECT seq FROM office_events WHERE received_at < ?)",
                    vec![Value::Int64(cut)],
                ),
                self.db.stmt(
                    "DELETE FROM office_events WHERE received_at < ? AND NOT EXISTS (SELECT 1 FROM office_deliveries d WHERE d.seq = office_events.seq)",
                    vec![Value::Int64(cut)],
                ),
            ])
            .await;
    }

    // ------------------------------------------------------------ sagas

    /// Start every saga of `owner` that begins on this event. A saga's id comes from the
    /// event and the saga's name, so starting it again (the publisher sends the event
    /// again after Office stopped half way) finds the saga and sends its first step again;
    /// the step's event id is fixed, so that stores nothing twice.
    async fn start_sagas(
        &self,
        owner: &str,
        contract: &Contract,
        event_id: &str,
        event: &str,
        payload: &str,
    ) {
        let Some(sagas) = contract.0["sagas"].as_array() else {
            return;
        };
        for s in sagas.iter().filter(|s| s["start"] == event) {
            let name = s["name"].as_str().unwrap_or("");
            let id = format!("{event_id}:{name}");
            let def = s.to_string();
            let made = self
                .db
                .run(
                    "INSERT INTO office_sagas (id, saga, owner, def, status, step, payload, updated_at) VALUES (?, ?, ?, ?, 'running', 0, ?, ?) ON CONFLICT (id) DO NOTHING",
                    vec![t(&id), t(name), t(owner), t(&def), t(payload), Value::Int64(now())],
                )
                .await;
            if made.is_err() {
                continue;
            }
            // Only a saga still at its first step needs its first command (again).
            if let Ok(Some((_, status, _, _, step))) = self.saga_row(&id).await {
                if status == "running" && step == 0 {
                    self.saga_send(&id, owner, s, "step", 0, payload).await;
                }
            }
        }
    }

    /// Sagas that a stop of Office left half way: a step whose delivery is done but whose
    /// next step was never sent, or a step whose command event was never stored. Run
    /// from the claim route, at most every few seconds.
    async fn recover_sagas(&self) {
        let rows = self
            .db
            .rows(
                "SELECT s.id, s.step, \
                   (SELECT COUNT(*) FROM office_events e WHERE e.id = s.id || ':step:' || CAST(s.step AS TEXT)), \
                   (SELECT COUNT(*) FROM office_events e JOIN office_deliveries d ON d.seq = e.seq \
                      WHERE e.id = s.id || ':step:' || CAST(s.step AS TEXT) AND d.status <> 'done') \
                 FROM office_sagas s WHERE s.status = 'running' ORDER BY s.updated_at LIMIT 100",
                vec![],
            )
            .await
            .unwrap_or_default();
        for r in rows {
            let (id, step) = (text(r.first()), int(r.get(1)));
            let (stored, open) = (int(r.get(2)), int(r.get(3)));
            let Ok(Some((def, _, payload, owner, _))) = self.saga_row(&id).await else {
                continue;
            };
            if stored == 0 {
                self.saga_send(&id, &owner, &def, "step", step as usize, &payload)
                    .await;
            } else if open == 0 {
                self.saga_done(&id, "step", step as usize).await;
            }
        }
    }

    /// Send the command event of one step (or its compensation) to the app that handles
    /// it. If that app has not declared that it consumes it, the step fails.
    async fn saga_send(
        &self,
        saga_id: &str,
        owner: &str,
        def: &Json,
        kind: &str,
        idx: usize,
        payload: &str,
    ) {
        let steps = def["steps"].as_array().cloned().unwrap_or_default();
        let target = steps.get(idx).and_then(|s| {
            if kind == "step" {
                s["command"].as_str()
            } else {
                s["compensate"].as_str()
            }
        });
        let ok = async {
            let target = target.ok_or_else(|| conflict_err("saga_step", "no such step"))?;
            let (app, event) = target
                .split_once('.')
                .ok_or_else(|| conflict_err("saga_step", "a step is `<app>.<event>`"))?;
            let contract = self
                .contract(app)
                .await?
                .ok_or_else(|| conflict_err("saga_step", "the app has no contract"))?;
            let sub = contract
                .subscription(event, owner)
                .ok_or_else(|| conflict_err("saga_step", "the app does not consume it"))?;
            let version = sub["version"].as_i64().unwrap_or(1);
            let mut p: Json = serde_json::from_str(payload).unwrap_or_else(|_| json!({}));
            if let Some(o) = p.as_object_mut() {
                o.insert("saga_id".into(), json!(saga_id));
            }
            let body = p.to_string();
            let eid = format!("{saga_id}:{kind}:{idx}");
            let revision = if kind == "step" {
                idx as i64
            } else {
                1000 + idx as i64
            };
            let occurred = now() * 1_000_000;
            let msg = format!(
                "office\n{}",
                signing_message(
                    owner,
                    &eid,
                    event,
                    "saga",
                    saga_id,
                    revision,
                    version,
                    occurred,
                    &sha256_hex(body.as_bytes()),
                )
            );
            let (_, sig) = self.sign(msg.as_bytes());
            let ev = StoredEvent {
                id: eid,
                publisher: owner.to_owned(),
                signer: "office".into(),
                name: event.to_owned(),
                aggregate_type: "saga".into(),
                aggregate_id: saga_id.to_owned(),
                revision,
                version,
                occurred_at: occurred,
                payload: body,
                signature: B64.encode(sig),
                saga_id: saga_id.to_owned(),
                saga_step: idx as i64,
                saga_kind: kind.to_owned(),
            };
            self.store_event(&ev, &[app.to_owned()]).await
        }
        .await;
        if ok.is_err() {
            Box::pin(self.saga_failed(saga_id, kind, idx)).await;
        }
    }

    async fn saga(&self, id: &str) -> Result<Option<(Json, String, String, String)>> {
        Ok(self
            .saga_row(id)
            .await?
            .map(|(def, status, payload, owner, _)| (def, status, payload, owner)))
    }

    /// A saga's definition, status, payload, owner and current step.
    async fn saga_row(&self, id: &str) -> Result<Option<(Json, String, String, String, i64)>> {
        let rows = self
            .db
            .rows(
                "SELECT def, status, payload, owner, step FROM office_sagas WHERE id = ?",
                vec![t(id)],
            )
            .await?;
        Ok(rows.first().and_then(|r| {
            Some((
                serde_json::from_str(&text(r.first())).ok()?,
                text(r.get(1)),
                text(r.get(2)),
                text(r.get(3)),
                int(r.get(4)),
            ))
        }))
    }

    async fn saga_status(&self, id: &str, status: &str, step: i64) {
        let _ = self
            .db
            .run(
                "UPDATE office_sagas SET status = ?, step = ?, updated_at = ? WHERE id = ?",
                vec![t(status), Value::Int64(step), Value::Int64(now()), t(id)],
            )
            .await;
    }

    /// A saga delivery was acknowledged as applied.
    async fn saga_done(&self, id: &str, kind: &str, idx: usize) {
        let Ok(Some((def, status, payload, owner))) = self.saga(id).await else {
            return;
        };
        let steps = def["steps"].as_array().map_or(0, Vec::len);
        if kind == "step" && status == "running" {
            if idx + 1 < steps {
                self.saga_status(id, "running", (idx + 1) as i64).await;
                self.saga_send(id, &owner, &def, "step", idx + 1, &payload)
                    .await;
            } else {
                self.saga_status(id, "completed", idx as i64).await;
            }
        } else if kind == "compensate" && status == "compensating" {
            self.saga_compensate_from(id, &owner, &def, idx, &payload)
                .await;
        }
    }

    /// Compensate steps below `before`, newest first, skipping steps that have nothing to
    /// undo. When none is left the saga is `compensated`.
    async fn saga_compensate_from(
        &self,
        id: &str,
        owner: &str,
        def: &Json,
        before: usize,
        payload: &str,
    ) {
        let steps = def["steps"].as_array().cloned().unwrap_or_default();
        for i in (0..before).rev() {
            if steps[i]["compensate"].is_string() {
                self.saga_status(id, "compensating", i as i64).await;
                self.saga_send(id, owner, def, "compensate", i, payload)
                    .await;
                return;
            }
        }
        self.saga_status(id, "compensated", 0).await;
    }

    /// A saga delivery failed for good (or could not be sent).
    async fn saga_failed(&self, id: &str, kind: &str, idx: usize) {
        let Ok(Some((def, status, payload, owner))) = self.saga(id).await else {
            return;
        };
        if kind == "step" && status == "running" {
            self.saga_status(id, "compensating", idx as i64).await;
            Box::pin(self.saga_compensate_from(id, &owner, &def, idx, &payload)).await;
        } else if kind == "compensate" {
            // A compensation that cannot be applied needs a person.
            self.saga_status(id, "stuck", idx as i64).await;
        }
    }
}

/// An event row as Office stores it.
pub struct StoredEvent {
    pub id: String,
    pub publisher: String,
    /// `office` for events Office signs itself (saga commands); otherwise the publisher.
    pub signer: String,
    pub name: String,
    pub aggregate_type: String,
    pub aggregate_id: String,
    pub revision: i64,
    pub version: i64,
    pub occurred_at: i64,
    pub payload: String,
    pub signature: String,
    pub saga_id: String,
    pub saga_step: i64,
    pub saga_kind: String,
}

// ---------------------------------------------------------------- handlers

/// `PUT /v1/_office/events/contract` (app signed): the events the app publishes and
/// consumes, and its sagas. Office delivers only what the contracts allow.
pub async fn put_contract(State(o): State<Shared>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let rid = extract_request_id(&parts.headers);
    let inst = "/v1/_office/events/contract";
    let bytes = axum::body::to_bytes(body, 256 * 1024)
        .await
        .unwrap_or_default();
    let run = async {
        let who = o
            .app_request(&parts.method, &parts.uri, &parts.headers, &bytes)
            .await?;
        let v = body_json(&Bytes::from(bytes.to_vec()))?;
        let doc = json!({
            "events": v["events"].as_array().cloned().unwrap_or_default(),
            "subscriptions": v["subscriptions"].as_array().cloned().unwrap_or_default(),
            "sagas": v["sagas"].as_array().cloned().unwrap_or_default(),
        });
        o.db.batch(vec![
            o.db.stmt(
                "DELETE FROM office_contracts WHERE app = ?",
                vec![t(&who.name)],
            ),
            o.db.stmt(
                "INSERT INTO office_contracts (app, contract, updated_at) VALUES (?, ?, ?)",
                vec![t(&who.name), t(&doc.to_string()), Value::Int64(now())],
            ),
        ])
        .await?;
        Ok::<_, Error>(json!({"status": "ok"}))
    };
    match run.await {
        Ok(v) => json_response(StatusCode::OK, &v, &rid),
        Err(e) => fail(&e, inst, &rid),
    }
}

/// `POST /v1/_office/events` (app signed): publish one signed event. `200` means the
/// event is stored (with its deliveries); anything else means it is not, and the
/// publisher keeps it in its outbox and tries again.
pub async fn publish(State(o): State<Shared>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let rid = extract_request_id(&parts.headers);
    let inst = "/v1/_office/events";
    let bytes = axum::body::to_bytes(body, MAX_PAYLOAD * 2)
        .await
        .unwrap_or_default();
    let run = async {
        let who = o
            .app_request(&parts.method, &parts.uri, &parts.headers, &bytes)
            .await?;
        let v = body_json(&Bytes::from(bytes.to_vec()))?;
        let (id, name, agg_type, agg_id, payload, sig) = (
            field(&v, "id")?,
            field(&v, "event")?,
            field(&v, "aggregate_type")?,
            field(&v, "aggregate_id")?,
            field(&v, "payload")?,
            field(&v, "signature")?,
        );
        let (revision, version, occurred) = (
            v["revision"].as_i64().unwrap_or(0),
            v["version"].as_i64().unwrap_or(0),
            v["occurred_at"].as_i64().unwrap_or(0),
        );
        if payload.len() > MAX_PAYLOAD
            || id.len() > 128
            || serde_json::from_str::<Json>(payload).is_err()
        {
            return Err(Error::invalid_input(
                "invalid_event",
                "The event is not valid.",
            ));
        }
        // The contract decides whether this app may publish this event and to whom.
        let contract = o.contract(&who.name).await?.ok_or_else(Error::forbidden)?;
        let declared = contract.published(name).ok_or_else(Error::forbidden)?;
        if declared["version"].as_i64() != Some(version) {
            return Err(Error::forbidden());
        }
        // The signature proves the publisher made this exact event.
        let key =
            VerifyingKey::from_bytes(&who.public_key).map_err(|_| Error::unauthenticated())?;
        let msg = signing_message(
            &who.name,
            id,
            name,
            agg_type,
            agg_id,
            revision,
            version,
            occurred,
            &sha256_hex(payload.as_bytes()),
        );
        let sigb = B64
            .decode(sig)
            .ok()
            .and_then(|b| Signature::from_slice(&b).ok())
            .ok_or_else(Error::unauthenticated)?;
        key.verify(msg.as_bytes(), &sigb)
            .map_err(|_| Error::unauthenticated())?;
        let subscribers: Vec<String> = declared["subscribers"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|s| s.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        let ev = StoredEvent {
            id: id.to_owned(),
            publisher: who.name.clone(),
            signer: who.name.clone(),
            name: name.to_owned(),
            aggregate_type: agg_type.to_owned(),
            aggregate_id: agg_id.to_owned(),
            revision,
            version,
            occurred_at: occurred,
            payload: payload.to_owned(),
            signature: sig.to_owned(),
            saga_id: String::new(),
            saga_step: 0,
            saga_kind: String::new(),
        };
        let fresh =
            o.db.rows("SELECT seq FROM office_events WHERE id = ?", vec![t(id)])
                .await?
                .is_empty();
        let seq = o.store_event(&ev, &subscribers).await?;
        if fresh {
            o.tally("event_published", &who.name).await;
        }
        // Also for an event stored before: Office may have stopped before it started the sagas.
        o.start_sagas(&who.name, &contract, id, name, payload).await;
        Ok::<_, Error>(json!({"seq": seq}))
    };
    match run.await {
        Ok(v) => json_response(StatusCode::OK, &v, &rid),
        Err(e) => fail(&e, inst, &rid),
    }
}

/// `POST /v1/_office/events/claim` (app signed): the caller's next deliveries. An event
/// comes back until it is acknowledged, and never ahead of an earlier event for the same
/// aggregate that is waiting or dead.
pub async fn claim(State(o): State<Shared>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let rid = extract_request_id(&parts.headers);
    let inst = "/v1/_office/events/claim";
    let bytes = axum::body::to_bytes(body, 4096).await.unwrap_or_default();
    let run = async {
        let who = o
            .app_request(&parts.method, &parts.uri, &parts.headers, &bytes)
            .await?;
        let v: Json = serde_json::from_slice(&bytes).unwrap_or_else(|_| json!({}));
        let limit = v["limit"].as_i64().unwrap_or(20).clamp(1, MAX_CLAIM);
        let t0 = now();
        if t0 - LAST_PRUNE.load(Ordering::Relaxed) > 60 {
            LAST_PRUNE.store(t0, Ordering::Relaxed);
            o.prune_events().await;
        }
        if t0 - LAST_SAGA_SWEEP.load(Ordering::Relaxed) > 3 {
            LAST_SAGA_SWEEP.store(t0, Ordering::Relaxed);
            o.recover_sagas().await;
        }
        let rows = o
            .db
            .rows(
                "SELECT e.seq, e.id, e.publisher, e.signer, e.name, e.aggregate_type, e.aggregate_id, e.revision, e.version, e.occurred_at, e.payload, e.signature, d.attempts \
                 FROM office_deliveries d JOIN office_events e ON e.seq = d.seq \
                 WHERE d.subscriber = ? AND d.status = 'pending' AND d.next_at <= ? \
                 AND NOT EXISTS (SELECT 1 FROM office_deliveries d2 JOIN office_events e2 ON e2.seq = d2.seq \
                   WHERE d2.subscriber = d.subscriber AND d2.status IN ('pending', 'dead') AND d2.seq < d.seq \
                   AND e2.publisher = e.publisher AND e2.aggregate_type = e.aggregate_type AND e2.aggregate_id = e.aggregate_id) \
                 ORDER BY d.seq LIMIT ?",
                vec![t(&who.name), Value::Int64(t0), Value::Int64(limit)],
            )
            .await?;
        let mut out = Vec::new();
        for r in &rows {
            let (publisher, signer) = (text(r.get(2)), text(r.get(3)));
            let mut item = json!({
                "seq": int(r.first()), "id": text(r.get(1)), "publisher": publisher,
                "signer": signer, "event": text(r.get(4)), "aggregate_type": text(r.get(5)),
                "aggregate_id": text(r.get(6)), "revision": int(r.get(7)), "version": int(r.get(8)),
                "occurred_at": int(r.get(9)), "payload": text(r.get(10)),
                "signature": text(r.get(11)), "attempts": int(r.get(12)),
            });
            if signer == "office" {
                item["kid"] = json!(o.active_kid());
            } else if let Some(key) = o.app_public_key(&signer).await? {
                // Office vouches for the publisher's key, so the subscriber can check the
                // event against the key set it already trusts.
                let (kid, sig) = o.sign(format!("falak-app-key\n{signer}\n{key}").as_bytes());
                item["publisher_key"] = json!(key);
                item["kid"] = json!(kid);
                item["key_attestation"] = json!(B64.encode(sig));
            }
            out.push(item);
        }
        Ok::<_, Error>(json!({"events": out}))
    };
    match run.await {
        Ok(v) => json_response(StatusCode::OK, &v, &rid),
        Err(e) => fail(&e, inst, &rid),
    }
}

/// `POST /v1/_office/events/ack` (app signed): `{seq, outcome}` with outcome `ok`,
/// `retry` (try again later) or `fail` (it will never work: dead-letter it).
pub async fn ack(State(o): State<Shared>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let rid = extract_request_id(&parts.headers);
    let inst = "/v1/_office/events/ack";
    let bytes = axum::body::to_bytes(body, 8192).await.unwrap_or_default();
    let run = async {
        let who = o
            .app_request(&parts.method, &parts.uri, &parts.headers, &bytes)
            .await?;
        let v = body_json(&Bytes::from(bytes.to_vec()))?;
        let seq = v["seq"]
            .as_i64()
            .ok_or_else(|| Error::invalid_input("invalid_body", "`seq` is required."))?;
        let outcome = field(&v, "outcome")?;
        let error: String = v["error"]
            .as_str()
            .unwrap_or("")
            .chars()
            .take(300)
            .collect();
        let rows = o
            .db
            .rows(
                "SELECT d.status, d.attempts, e.saga_id, e.saga_step, e.saga_kind FROM office_deliveries d JOIN office_events e ON e.seq = d.seq WHERE d.seq = ? AND d.subscriber = ?",
                vec![Value::Int64(seq), t(&who.name)],
            )
            .await?;
        let row = rows.first().ok_or_else(Error::not_found)?;
        let (status, attempts) = (text(row.first()), int(row.get(1)));
        let (saga_id, step, kind) = (text(row.get(2)), int(row.get(3)) as usize, text(row.get(4)));
        if status != "pending" {
            // A repeat acknowledgement is harmless.
            return Ok(json!({"status": status}));
        }
        let (new_status, next_at) = match outcome {
            "ok" => ("done", 0),
            "retry" if attempts + 1 < MAX_ATTEMPTS => {
                ("pending", now() + (1_i64 << attempts.clamp(0, 6)))
            }
            "retry" | "fail" => ("dead", 0),
            _ => return Err(Error::invalid_input("invalid_body", "Unknown outcome.")),
        };
        o.db.run(
            "UPDATE office_deliveries SET status = ?, attempts = attempts + 1, next_at = ?, last_error = ? WHERE seq = ? AND subscriber = ? AND status = 'pending'",
            vec![t(new_status), Value::Int64(next_at), t(&error), Value::Int64(seq), t(&who.name)],
        )
        .await?;
        if new_status == "dead" {
            o.tally("event_dead", &who.name).await;
        }
        if !saga_id.is_empty() {
            match new_status {
                "done" => o.saga_done(&saga_id, &kind, step).await,
                "dead" => o.saga_failed(&saga_id, &kind, step).await,
                _ => {}
            }
        }
        Ok::<_, Error>(json!({"status": new_status}))
    };
    match run.await {
        Ok(v) => json_response(StatusCode::OK, &v, &rid),
        Err(e) => fail(&e, inst, &rid),
    }
}

/// `GET /v1/_office/events/dead` (administrator): events no subscriber could apply.
pub async fn dead(State(o): State<Shared>, headers: HeaderMap) -> Response {
    let (rid, inst) = (extract_request_id(&headers), "/v1/_office/events/dead");
    let run = async {
        o.admin(&headers).await?;
        let rows = o
            .db
            .rows(
                "SELECT e.seq, d.subscriber, e.publisher, e.name, e.aggregate_id, d.attempts, d.last_error FROM office_deliveries d JOIN office_events e ON e.seq = d.seq WHERE d.status = 'dead' ORDER BY e.seq",
                vec![],
            )
            .await?;
        Ok::<_, Error>(json!({"data": rows.iter().map(|r| json!({
            "seq": int(r.first()), "subscriber": text(r.get(1)), "publisher": text(r.get(2)),
            "event": text(r.get(3)), "aggregate_id": text(r.get(4)), "attempts": int(r.get(5)),
            "error": text(r.get(6)),
        })).collect::<Vec<_>>()}))
    };
    match run.await {
        Ok(v) => json_response(StatusCode::OK, &v, &rid),
        Err(e) => fail(&e, inst, &rid),
    }
}

/// `POST /v1/_office/events/replay` (administrator): `{seq, subscriber}` puts a dead
/// event back in the queue. Replay is audited.
pub async fn replay(State(o): State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    let (rid, inst) = (extract_request_id(&headers), "/v1/_office/events/replay");
    let run = async {
        let admin = o.admin(&headers).await?;
        let v = body_json(&body)?;
        let seq = v["seq"]
            .as_i64()
            .ok_or_else(|| Error::invalid_input("invalid_body", "`seq` is required."))?;
        let sub = field(&v, "subscriber")?;
        let n = o
            .db
            .run(
                "UPDATE office_deliveries SET status = 'pending', attempts = 0, next_at = 0, last_error = '' WHERE seq = ? AND subscriber = ? AND status = 'dead'",
                vec![Value::Int64(seq), t(sub)],
            )
            .await?;
        if n == 0 {
            return Err(Error::not_found());
        }
        o.audit(&admin.subject, "event_replayed", &format!("{seq}:{sub}"))
            .await;
        Ok::<_, Error>(json!({"status": "pending"}))
    };
    match run.await {
        Ok(v) => json_response(StatusCode::OK, &v, &rid),
        Err(e) => fail(&e, inst, &rid),
    }
}

/// `GET /v1/_office/sagas` (administrator): the newest 200 saga instances and where they
/// are, and how many there are in each state.
pub async fn sagas(State(o): State<Shared>, headers: HeaderMap) -> Response {
    let (rid, inst) = (extract_request_id(&headers), "/v1/_office/sagas");
    let run = async {
        o.admin(&headers).await?;
        let rows = o
            .db
            .rows(
                "SELECT id, saga, owner, status, step, updated_at FROM office_sagas ORDER BY updated_at DESC LIMIT 200",
                vec![],
            )
            .await?;
        let counts =
            o.db.rows(
                "SELECT status, COUNT(*) FROM office_sagas GROUP BY status",
                vec![],
            )
            .await?;
        let counts: serde_json::Map<String, Json> = counts
            .iter()
            .map(|r| (text(r.first()), json!(int(r.get(1)))))
            .collect();
        Ok::<_, Error>(json!({"counts": counts, "data": rows.iter().map(|r| json!({
            "id": text(r.first()), "saga": text(r.get(1)), "owner": text(r.get(2)),
            "status": text(r.get(3)), "step": int(r.get(4)), "updated_at": int(r.get(5)),
        })).collect::<Vec<_>>()}))
    };
    match run.await {
        Ok(v) => json_response(StatusCode::OK, &v, &rid),
        Err(e) => fail(&e, inst, &rid),
    }
}
