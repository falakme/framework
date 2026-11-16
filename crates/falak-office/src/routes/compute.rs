//! HTTP for Office Compute (T7.2, T7.4). Three kinds of caller, three credentials:
//!
//! * a person with an Office session (`office_admin` or `compute`): register and revoke
//!   workers, queue jobs, read their state and the dead-letter queue;
//! * a worker (`wk_...`): lease, heartbeat, complete and fail. Workers only call out;
//!   Office never calls a worker;
//! * a running job (`jt_...`): hand back its result, for its own job only.

use falak_contracts::{
    ir::IrJob,
    jobs::{Job, JobDispatcher},
};

use super::*;
use crate::compute::{Queue, job_id_hex};

/// Longest a single lease may be asked for.
const MAX_LEASE_MILLIS: u64 = 3_600_000;
const MAX_PAYLOAD_BYTES: usize = 1_048_576;

pub fn routes() -> Router<Shared> {
    Router::new()
        .route(
            "/v1/_office/compute/workers",
            get(workers).post(make_worker),
        )
        .route(
            "/v1/_office/compute/workers/{id}/revoke",
            post(revoke_worker),
        )
        .route("/v1/_office/compute/jobs", post(enqueue))
        .route("/v1/_office/compute/jobs/{id}", get(job_status))
        .route("/v1/_office/compute/dead", get(dead))
        .route("/v1/_office/compute/lease", post(lease))
        .route(
            "/v1/_office/compute/leases/{lease}/heartbeat",
            post(heartbeat),
        )
        .route(
            "/v1/_office/compute/leases/{lease}/complete",
            post(complete),
        )
        .route("/v1/_office/compute/leases/{lease}/fail", post(fail_lease))
        .route("/v1/_office/compute/job/result", post(job_result))
        .route("/v1/_office/compute/pii/reveal", post(reveal))
}

/// A scan result with personal data in it never stays as written: originals become tokens
/// and go to the encrypted mapping, under the tenant the job was queued for.
async fn clean_result(o: &Office, lease: &str, result: Json) -> Result<Json> {
    if result.get("pii_entities").is_none() {
        return Ok(result);
    }
    let rows =
        o.db.rows(
            "SELECT payload FROM compute_jobs WHERE lease_id = ?",
            vec![t(lease)],
        )
        .await?;
    let payload: Json = rows
        .first()
        .and_then(|r| serde_json::from_str(&text(r.first())).ok())
        .unwrap_or(Json::Null);
    let tenant = payload["tenant"].as_str().unwrap_or("");
    let key = crate::pii::PiiKey::load(o.data_dir())?;
    crate::pii::Vault {
        db: &o.db,
        key: &key,
    }
    .sanitize(tenant, result)
    .await
}

/// An administrator reads one original back. Each reveal is audited.
async fn reveal(State(o): State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    let (rid, inst) = (
        extract_request_id(&headers),
        "/v1/_office/compute/pii/reveal",
    );
    let run = async {
        let admin = o.admin(&headers)?;
        let v = body_json(&body)?;
        let (tenant, token) = (v["tenant"].as_str().unwrap_or(""), field(&v, "token")?);
        let key = crate::pii::PiiKey::load(o.data_dir())?;
        let original = crate::pii::Vault {
            db: &o.db,
            key: &key,
        }
        .reveal(tenant, token)
        .await?
        .ok_or_else(Error::not_found)?;
        o.audit(&admin.subject, "pii_revealed", token).await;
        Ok(json!({"token": token, "original": original}))
    };
    respond(StatusCode::OK, run.await, &rid, inst)
}

fn operator(o: &Office, headers: &HeaderMap) -> Result<Principal> {
    let p = o.session(headers)?;
    if p.roles
        .iter()
        .any(|r| r == "office_admin" || r == "compute")
    {
        Ok(p)
    } else {
        Err(Error::forbidden())
    }
}

async fn worker(o: &Office, headers: &HeaderMap) -> Result<String> {
    let token = bearer_token(headers).ok_or_else(Error::unauthenticated)?;
    Queue::new(&o.db)
        .verify_worker(token)
        .await?
        .ok_or_else(Error::unauthenticated)
}

/// The worker must hold the lease it acts on.
async fn holds(o: &Office, worker: &str, lease: &str) -> Result<()> {
    let rows =
        o.db.rows(
            "SELECT lease_worker FROM compute_jobs WHERE lease_id = ?",
            vec![t(lease)],
        )
        .await?;
    if rows.first().is_some_and(|r| text(r.first()) == worker) {
        Ok(())
    } else {
        Err(Error::forbidden())
    }
}

fn respond(status: StatusCode, r: Result<Json>, rid: &str, inst: &str) -> Response {
    match r {
        Ok(v) => json_response(status, &v, rid),
        Err(e) => fail(&e, inst, rid),
    }
}

async fn make_worker(State(o): State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    let (rid, inst) = (extract_request_id(&headers), "/v1/_office/compute/workers");
    let run = async {
        let admin = o.admin(&headers)?;
        let v = body_json(&body)?;
        let name = field(&v, "name")?;
        let (id, credential) = Queue::new(&o.db).create_worker(name).await?;
        o.audit(&admin.subject, "compute_worker_created", &id).await;
        Ok(json!({"id": id, "name": name, "credential": credential}))
    };
    respond(StatusCode::CREATED, run.await, &rid, inst)
}

async fn workers(State(o): State<Shared>, headers: HeaderMap) -> Response {
    let (rid, inst) = (extract_request_id(&headers), "/v1/_office/compute/workers");
    let run = async {
        o.admin(&headers)?;
        let list = Queue::new(&o.db).workers().await?;
        Ok(
            json!({"workers": list.iter().map(|(id, name, status)| json!({"id": id, "name": name, "status": status})).collect::<Vec<_>>()}),
        )
    };
    respond(StatusCode::OK, run.await, &rid, inst)
}

async fn revoke_worker(
    State(o): State<Shared>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let (rid, inst) = (
        extract_request_id(&headers),
        format!("/v1/_office/compute/workers/{id}/revoke"),
    );
    let run = async {
        let admin = o.admin(&headers)?;
        if !Queue::new(&o.db).revoke_worker(&id).await? {
            return Err(Error::not_found());
        }
        o.audit(&admin.subject, "compute_worker_revoked", &id).await;
        Ok(json!({"id": id, "status": "revoked"}))
    };
    respond(StatusCode::OK, run.await, &rid, &inst)
}

async fn enqueue(State(o): State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    let (rid, inst) = (extract_request_id(&headers), "/v1/_office/compute/jobs");
    let run = async {
        let who = operator(&o, &headers)?;
        let v = body_json(&body)?;
        let job: IrJob = serde_json::from_value(v["job"].clone()).map_err(|_| {
            Error::invalid_input("invalid_job", "`job` must be a compiled job contract.")
        })?;
        let payload = v["payload"].clone();
        if let Err(problems) = falak_core::jobs::validate_payload(&job, &payload) {
            return Err(Error::invalid_input("invalid_payload", problems.join("; ")));
        }
        let payload_text = payload.to_string();
        if payload_text.len() > MAX_PAYLOAD_BYTES {
            return Err(Error::invalid_input(
                "payload_too_large",
                "The payload is too large; store the data and pass its key.",
            ));
        }
        // The caller may name the job, so a retried request queues it once.
        let id = match v["id"].as_str() {
            Some(s) => falak_core::values::parse_uuid(s)
                .ok_or_else(|| Error::invalid_input("invalid_id", "`id` must be a UUID."))?,
            None => <[u8; 16]>::try_from(random(16)).unwrap_or_default(),
        };
        let run_at = v["run_at_micros"]
            .as_i64()
            .unwrap_or_else(falak_contracts::support::wall_clock_micros);
        Queue::new(&o.db)
            .enqueue_with(
                &Job {
                    id,
                    kind: job.name.clone(),
                    payload: payload_text.into_bytes(),
                    attempts: 0,
                    run_at_micros: run_at,
                },
                &serde_json::to_string(&job).unwrap_or_default(),
                job.max_attempts,
            )
            .await?;
        o.audit(&who.subject, "compute_job_queued", &job.name).await;
        Ok(json!({"id": job_id_hex(&id), "kind": job.name}))
    };
    respond(StatusCode::ACCEPTED, run.await, &rid, inst)
}

fn status_json(s: &crate::compute::JobStatus) -> Json {
    json!({
        "id": s.id, "kind": s.kind, "status": s.status, "attempts": s.attempts,
        "result": s.result.as_deref().and_then(|r| serde_json::from_str::<Json>(r).ok()),
        "error": s.last_error,
    })
}

async fn job_status(
    State(o): State<Shared>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let (rid, inst) = (
        extract_request_id(&headers),
        format!("/v1/_office/compute/jobs/{id}"),
    );
    let run = async {
        operator(&o, &headers)?;
        let s = Queue::new(&o.db)
            .status(&id)
            .await?
            .ok_or_else(Error::not_found)?;
        Ok(status_json(&s))
    };
    respond(StatusCode::OK, run.await, &rid, &inst)
}

async fn dead(State(o): State<Shared>, headers: HeaderMap) -> Response {
    let (rid, inst) = (extract_request_id(&headers), "/v1/_office/compute/dead");
    let run = async {
        operator(&o, &headers)?;
        let list = Queue::new(&o.db).dead_letters().await?;
        Ok(json!({"dead": list.iter().map(status_json).collect::<Vec<_>>()}))
    };
    respond(StatusCode::OK, run.await, &rid, inst)
}

async fn lease(State(o): State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    let (rid, inst) = (extract_request_id(&headers), "/v1/_office/compute/lease");
    let run = async {
        let w = worker(&o, &headers).await?;
        let v = body_json(&body)?;
        let kinds: Vec<String> = v["kinds"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|k| k.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        let max = v["max"].as_u64().unwrap_or(1).clamp(1, 10) as usize;
        let millis = v["lease_millis"]
            .as_u64()
            .unwrap_or(60_000)
            .clamp(1_000, MAX_LEASE_MILLIS);
        let leased = Queue::new(&o.db).lease_for(&w, &kinds, max, millis).await?;
        let jobs: Vec<Json> = leased
            .iter()
            .map(|l| {
                json!({
                    "lease_id": l.lease.lease_id,
                    "job_id": job_id_hex(&l.lease.job.id),
                    "kind": l.lease.job.kind,
                    "attempt": l.lease.job.attempts,
                    "payload": serde_json::from_slice::<Json>(&l.lease.job.payload).unwrap_or(Json::Null),
                    "spec": serde_json::from_str::<Json>(&l.spec).unwrap_or(Json::Null),
                    "expires_at_micros": l.lease.expires_at_micros,
                    // What the job itself holds: short-lived and good for this job only.
                    "credential": l.credential,
                })
            })
            .collect();
        Ok(json!({"jobs": jobs}))
    };
    respond(StatusCode::OK, run.await, &rid, inst)
}

async fn heartbeat(
    State(o): State<Shared>,
    Path(lease): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let rid = extract_request_id(&headers);
    let inst = "/v1/_office/compute/leases/heartbeat";
    let run = async {
        let w = worker(&o, &headers).await?;
        holds(&o, &w, &lease).await?;
        let v = body_json(&body).unwrap_or_else(|_| json!({}));
        let extend = v["extend_millis"]
            .as_u64()
            .unwrap_or(60_000)
            .clamp(1_000, MAX_LEASE_MILLIS);
        Queue::new(&o.db).heartbeat(&lease, extend).await?;
        Ok(json!({"ok": true}))
    };
    respond(StatusCode::OK, run.await, &rid, inst)
}

async fn complete(
    State(o): State<Shared>,
    Path(lease): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let rid = extract_request_id(&headers);
    let inst = "/v1/_office/compute/leases/complete";
    let run = async {
        let w = worker(&o, &headers).await?;
        holds(&o, &w, &lease).await?;
        let q = Queue::new(&o.db);
        let v = body_json(&body).unwrap_or_else(|_| json!({}));
        if !v["result"].is_null() {
            let r = v["result"].to_string();
            if r.len() > MAX_PAYLOAD_BYTES {
                return Err(Error::invalid_input(
                    "result_too_large",
                    "The result is too large; store it and return its key.",
                ));
            }
            let r = clean_result(&o, &lease, v["result"].clone())
                .await?
                .to_string();
            // A completion that arrives again carries the same result: keep the first.
            let _ = q.set_result(&lease, &r).await;
        }
        q.complete(&lease).await?;
        Ok(json!({"ok": true}))
    };
    respond(StatusCode::OK, run.await, &rid, inst)
}

async fn fail_lease(
    State(o): State<Shared>,
    Path(lease): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let rid = extract_request_id(&headers);
    let inst = "/v1/_office/compute/leases/fail";
    let run = async {
        let w = worker(&o, &headers).await?;
        holds(&o, &w, &lease).await?;
        let v = body_json(&body).unwrap_or_else(|_| json!({}));
        let retry = v["retry"].as_bool().unwrap_or(true);
        let reason: String = v["reason"]
            .as_str()
            .unwrap_or("failed")
            .chars()
            .take(500)
            .collect();
        Queue::new(&o.db).fail(&lease, retry, &reason).await?;
        Ok(json!({"ok": true}))
    };
    respond(StatusCode::OK, run.await, &rid, inst)
}

/// A job hands back its result with its own credential.
async fn job_result(State(o): State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    let (rid, inst) = (
        extract_request_id(&headers),
        "/v1/_office/compute/job/result",
    );
    let run = async {
        let token = bearer_token(&headers).ok_or_else(Error::unauthenticated)?;
        let q = Queue::new(&o.db);
        let (_, lease_id, _) = q
            .verify_job_token(token)
            .await?
            .ok_or_else(Error::unauthenticated)?;
        let v = body_json(&body)?;
        let r = clean_result(&o, &lease_id, v["result"].clone())
            .await?
            .to_string();
        if r.len() > MAX_PAYLOAD_BYTES {
            return Err(Error::invalid_input(
                "result_too_large",
                "The result is too large.",
            ));
        }
        q.set_result(&lease_id, &r).await?;
        Ok(json!({"ok": true}))
    };
    respond(StatusCode::OK, run.await, &rid, inst)
}
