//! Office Compute (T7.2, T7.4): a durable job queue for heavy work, and the credentials
//! the workers that run it hold.
//!
//! * A worker **leases** due jobs for a visibility timeout and **heartbeats** to keep
//!   them. A lease that lapses makes the job due again; the next lease replaces the lease
//!   id, so the first worker can no longer complete it.
//! * **Completion is idempotent**: completing a job that is already done answers `Ok`;
//!   completing with a lease that was lost answers a conflict. The job runs to a
//!   recorded completion once.
//! * A job that fails with no retry, or whose attempts are used up, is **dead-lettered**
//!   and kept for inspection.
//! * A **worker credential** (`wk_<id>.<secret>`) is stored hashed and can be revoked at
//!   once; revoking also ends the leases the worker holds.
//! * Each lease carries a **job credential** (`jt_...`): short-lived, valid only while
//!   that lease is the job's current lease, and good for nothing but that job.

use falak_contracts::{
    Error, ErrorKind, Result,
    driver::Value,
    jobs::{Job, JobDispatcher, Lease},
    support::wall_clock_micros,
};
use sha2::{Digest, Sha256};

use crate::db::{Db, int, t, text};

pub const SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS compute_jobs (id TEXT NOT NULL PRIMARY KEY, kind TEXT NOT NULL, payload TEXT NOT NULL, spec TEXT NOT NULL, status TEXT NOT NULL, attempts BIGINT NOT NULL, max_attempts BIGINT NOT NULL, run_at BIGINT NOT NULL, lease_id TEXT, lease_worker TEXT, lease_expires BIGINT, result TEXT, last_error TEXT, created_at BIGINT NOT NULL, done_at BIGINT)",
    "CREATE TABLE IF NOT EXISTS compute_workers (id TEXT NOT NULL PRIMARY KEY, name TEXT NOT NULL, secret_hash TEXT NOT NULL, status TEXT NOT NULL, created_at BIGINT NOT NULL, last_seen BIGINT)",
    "CREATE TABLE IF NOT EXISTS compute_tokens (token_hash TEXT NOT NULL PRIMARY KEY, job_id TEXT NOT NULL, lease_id TEXT NOT NULL, egress TEXT NOT NULL, expires_at BIGINT NOT NULL)",
];

/// A job a worker holds: the lease, the contract the app declared for it, and the
/// credential the job (not the worker) uses.
#[derive(Debug, Clone)]
pub struct Leased {
    pub lease: Lease,
    pub spec: String,
    pub credential: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobStatus {
    pub id: String,
    pub kind: String,
    pub status: String,
    pub attempts: i64,
    pub result: Option<String>,
    pub last_error: Option<String>,
}

pub struct Queue<'a> {
    db: &'a Db,
    /// Tests pin the clock; production reads it.
    fixed_now: Option<i64>,
}

fn conflict(code: &'static str, message: &str) -> Error {
    Error::new(ErrorKind::Conflict, code, message)
}

fn random_hex(n: usize) -> String {
    use rand_core::{OsRng, RngCore};
    let mut b = vec![0u8; n];
    OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

fn sha256_hex(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

pub fn job_id_hex(id: &[u8; 16]) -> String {
    hex::encode(id)
}

fn opt(v: Option<&Value>) -> Option<String> {
    match v {
        Some(Value::Text(s)) => Some(s.clone()),
        _ => None,
    }
}

impl<'a> Queue<'a> {
    pub fn new(db: &'a Db) -> Self {
        Self {
            db,
            fixed_now: None,
        }
    }

    /// The same queue with the clock pinned to `micros` (tests).
    pub fn at(db: &'a Db, micros: i64) -> Self {
        Self {
            db,
            fixed_now: Some(micros),
        }
    }

    fn now(&self) -> i64 {
        self.fixed_now.unwrap_or_else(wall_clock_micros)
    }

    // ------------------------------------------------------------------ jobs

    /// Add a job with its contract (`spec`, JSON). Adding the same id again does
    /// nothing, so a retried request cannot queue a job twice.
    pub async fn enqueue_with(&self, job: &Job, spec: &str, max_attempts: u32) -> Result<()> {
        let payload = String::from_utf8(job.payload.clone())
            .map_err(|_| Error::invalid_input("invalid_payload", "The payload is not UTF-8."))?;
        self.db
            .run(
                "INSERT INTO compute_jobs (id, kind, payload, spec, status, attempts, max_attempts, run_at, created_at) VALUES (?, ?, ?, ?, 'queued', 0, ?, ?, ?) ON CONFLICT (id) DO NOTHING",
                vec![
                    t(&job_id_hex(&job.id)),
                    t(&job.kind),
                    t(&payload),
                    t(spec),
                    Value::Int64(i64::from(max_attempts.max(1))),
                    Value::Int64(job.run_at_micros),
                    Value::Int64(self.now()),
                ],
            )
            .await?;
        Ok(())
    }

    /// Lease up to `max` due jobs of `kinds` to `worker` for `lease_millis`.
    pub async fn lease_for(
        &self,
        worker: &str,
        kinds: &[String],
        max: usize,
        lease_millis: u64,
    ) -> Result<Vec<Leased>> {
        if kinds.is_empty() || max == 0 {
            return Ok(vec![]);
        }
        let now = self.now();
        // Jobs whose lease lapsed with no attempts left go to the dead-letter queue.
        self.db
            .run(
                "UPDATE compute_jobs SET status = 'dead', last_error = 'lease expired on the last attempt' WHERE status = 'leased' AND lease_expires < ? AND attempts >= max_attempts",
                vec![Value::Int64(now)],
            )
            .await?;
        let marks = vec!["?"; kinds.len()].join(", ");
        let mut params: Vec<Value> = kinds.iter().map(|k| t(k)).collect();
        params.push(Value::Int64(now));
        params.push(Value::Int64(now));
        params.push(Value::Int64(i64::try_from(max).unwrap_or(i64::MAX)));
        let candidates = self
            .db
            .rows(
                &format!(
                    "SELECT id, kind, payload, attempts, run_at, spec FROM compute_jobs WHERE kind IN ({marks}) AND ((status = 'queued' AND run_at <= ?) OR (status = 'leased' AND lease_expires < ? AND attempts < max_attempts)) ORDER BY run_at, id LIMIT ?"
                ),
                params,
            )
            .await?;
        let mut out = Vec::new();
        let expires = now + i64::try_from(lease_millis).unwrap_or(i64::MAX / 2) * 1000;
        for row in candidates {
            let id = text(row.first());
            let lease_id = random_hex(16);
            // Take the job only if nobody else has since: the same condition again.
            let taken = self
                .db
                .run(
                    "UPDATE compute_jobs SET status = 'leased', lease_id = ?, lease_worker = ?, lease_expires = ?, attempts = attempts + 1 WHERE id = ? AND ((status = 'queued' AND run_at <= ?) OR (status = 'leased' AND lease_expires < ? AND attempts < max_attempts))",
                    vec![
                        t(&lease_id),
                        t(worker),
                        Value::Int64(expires),
                        t(&id),
                        Value::Int64(now),
                        Value::Int64(now),
                    ],
                )
                .await?;
            if taken != 1 {
                continue;
            }
            let credential = format!("jt_{}", random_hex(24));
            let spec = text(row.get(5));
            let egress = serde_json::from_str::<serde_json::Value>(&spec)
                .ok()
                .map(|v| v["egress"].to_string())
                .unwrap_or_else(|| "[]".into());
            self.db
                .run(
                    "INSERT INTO compute_tokens (token_hash, job_id, lease_id, egress, expires_at) VALUES (?, ?, ?, ?, ?)",
                    vec![
                        t(&sha256_hex(&credential)),
                        t(&id),
                        t(&lease_id),
                        t(&egress),
                        Value::Int64(expires),
                    ],
                )
                .await?;
            let mut raw = [0u8; 16];
            if let Ok(b) = hex::decode(&id)
                && b.len() == 16
            {
                raw.copy_from_slice(&b);
            }
            out.push(Leased {
                lease: Lease {
                    lease_id,
                    job: Job {
                        id: raw,
                        kind: text(row.get(1)),
                        payload: text(row.get(2)).into_bytes(),
                        attempts: u32::try_from(int(row.get(3)) + 1).unwrap_or(u32::MAX),
                        run_at_micros: int(row.get(4)),
                    },
                    expires_at_micros: expires,
                },
                spec,
                credential,
            });
        }
        Ok(out)
    }

    async fn lease_row(&self, lease_id: &str) -> Result<Option<(String, String)>> {
        let rows = self
            .db
            .rows(
                "SELECT status, id FROM compute_jobs WHERE lease_id = ?",
                vec![t(lease_id)],
            )
            .await?;
        Ok(rows.first().map(|r| (text(r.first()), text(r.get(1)))))
    }

    /// Record the result of the job that holds `lease_id` (before completing it).
    pub async fn set_result(&self, lease_id: &str, result: &str) -> Result<()> {
        let n = self
            .db
            .run(
                "UPDATE compute_jobs SET result = ? WHERE lease_id = ? AND status = 'leased'",
                vec![t(result), t(lease_id)],
            )
            .await?;
        if n == 1 {
            Ok(())
        } else {
            Err(conflict("lease_lost", "The lease is no longer held."))
        }
    }

    pub async fn status(&self, id_hex: &str) -> Result<Option<JobStatus>> {
        let rows = self
            .db
            .rows(
                "SELECT id, kind, status, attempts, result, last_error FROM compute_jobs WHERE id = ?",
                vec![t(id_hex)],
            )
            .await?;
        Ok(rows.first().map(|r| JobStatus {
            id: text(r.first()),
            kind: text(r.get(1)),
            status: text(r.get(2)),
            attempts: int(r.get(3)),
            result: opt(r.get(4)),
            last_error: opt(r.get(5)),
        }))
    }

    /// Jobs in the dead-letter queue, oldest first.
    pub async fn dead_letters(&self) -> Result<Vec<JobStatus>> {
        let rows = self
            .db
            .rows(
                "SELECT id, kind, status, attempts, result, last_error FROM compute_jobs WHERE status = 'dead' ORDER BY created_at, id",
                vec![],
            )
            .await?;
        Ok(rows
            .iter()
            .map(|r| JobStatus {
                id: text(r.first()),
                kind: text(r.get(1)),
                status: text(r.get(2)),
                attempts: int(r.get(3)),
                result: opt(r.get(4)),
                last_error: opt(r.get(5)),
            })
            .collect())
    }

    // ------------------------------------------------------------------ workers

    /// Register a worker. The credential is shown once; Office keeps its hash.
    pub async fn create_worker(&self, name: &str) -> Result<(String, String)> {
        let id = random_hex(8);
        let secret = random_hex(24);
        self.db
            .run(
                "INSERT INTO compute_workers (id, name, secret_hash, status, created_at) VALUES (?, ?, ?, 'active', ?)",
                vec![t(&id), t(name), t(&sha256_hex(&secret)), Value::Int64(self.now())],
            )
            .await?;
        let credential = format!("wk_{id}.{secret}");
        Ok((id, credential))
    }

    /// The worker id a credential belongs to, if it is genuine and not revoked.
    pub async fn verify_worker(&self, credential: &str) -> Result<Option<String>> {
        let Some((id, secret)) = credential
            .strip_prefix("wk_")
            .and_then(|c| c.split_once('.'))
        else {
            return Ok(None);
        };
        let rows = self
            .db
            .rows(
                "SELECT secret_hash, status FROM compute_workers WHERE id = ?",
                vec![t(id)],
            )
            .await?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        // Compare hashes, whose time does not depend on how much of the secret matched.
        let ok = text(row.first()) == sha256_hex(secret) && text(row.get(1)) == "active";
        if ok {
            self.db
                .run(
                    "UPDATE compute_workers SET last_seen = ? WHERE id = ?",
                    vec![Value::Int64(self.now()), t(id)],
                )
                .await?;
        }
        Ok(ok.then(|| id.to_owned()))
    }

    /// Revoke a worker: its credential stops working and its leases lapse now.
    pub async fn revoke_worker(&self, id: &str) -> Result<bool> {
        let n = self
            .db
            .run(
                "UPDATE compute_workers SET status = 'revoked' WHERE id = ? AND status = 'active'",
                vec![t(id)],
            )
            .await?;
        self.db
            .run(
                "UPDATE compute_jobs SET lease_expires = 0 WHERE lease_worker = ? AND status = 'leased'",
                vec![t(id)],
            )
            .await?;
        self.db
            .run(
                "UPDATE compute_tokens SET expires_at = 0 WHERE lease_id IN (SELECT lease_id FROM compute_jobs WHERE lease_worker = ?)",
                vec![t(id)],
            )
            .await?;
        Ok(n == 1)
    }

    pub async fn workers(&self) -> Result<Vec<(String, String, String)>> {
        let rows = self
            .db
            .rows(
                "SELECT id, name, status FROM compute_workers ORDER BY created_at, id",
                vec![],
            )
            .await?;
        Ok(rows
            .iter()
            .map(|r| (text(r.first()), text(r.get(1)), text(r.get(2))))
            .collect())
    }

    // ------------------------------------------------------------------ job credentials

    /// `(job id, lease id, egress allow-list JSON)` for a live job credential: one that has
    /// not expired and whose lease is still the job's current lease.
    pub async fn verify_job_token(
        &self,
        credential: &str,
    ) -> Result<Option<(String, String, String)>> {
        if !credential.starts_with("jt_") {
            return Ok(None);
        }
        let rows = self
            .db
            .rows(
                "SELECT k.job_id, k.lease_id, k.egress FROM compute_tokens k JOIN compute_jobs j ON j.lease_id = k.lease_id AND j.id = k.job_id WHERE k.token_hash = ? AND k.expires_at > ? AND j.status = 'leased'",
                vec![t(&sha256_hex(credential)), Value::Int64(self.now())],
            )
            .await?;
        Ok(rows
            .first()
            .map(|r| (text(r.first()), text(r.get(1)), text(r.get(2)))))
    }
}

/// The contract's trait over the same tables (without a worker identity or a contract
/// spec: those are what `lease_for` and `enqueue_with` add).
impl JobDispatcher for Queue<'_> {
    async fn enqueue(&self, job: Job) -> Result<()> {
        self.enqueue_with(&job, "{}", 3).await
    }

    async fn lease(&self, kinds: &[String], max: usize, lease_millis: u64) -> Result<Vec<Lease>> {
        Ok(self
            .lease_for("", kinds, max, lease_millis)
            .await?
            .into_iter()
            .map(|l| l.lease)
            .collect())
    }

    async fn heartbeat(&self, lease_id: &str, extend_millis: u64) -> Result<()> {
        let expires = self.now() + i64::try_from(extend_millis).unwrap_or(i64::MAX / 2) * 1000;
        let n = self
            .db
            .run(
                "UPDATE compute_jobs SET lease_expires = ? WHERE lease_id = ? AND status = 'leased'",
                vec![Value::Int64(expires), t(lease_id)],
            )
            .await?;
        if n != 1 {
            return Err(conflict("lease_lost", "The lease is no longer held."));
        }
        self.db
            .run(
                "UPDATE compute_tokens SET expires_at = ? WHERE lease_id = ?",
                vec![Value::Int64(expires), t(lease_id)],
            )
            .await?;
        Ok(())
    }

    async fn complete(&self, lease_id: &str) -> Result<()> {
        let n = self
            .db
            .run(
                "UPDATE compute_jobs SET status = 'done', done_at = ? WHERE lease_id = ? AND status = 'leased'",
                vec![Value::Int64(self.now()), t(lease_id)],
            )
            .await?;
        if n == 1 {
            return Ok(());
        }
        match self.lease_row(lease_id).await? {
            // Completed already by this lease: the retry changes nothing.
            Some((status, _)) if status == "done" => Ok(()),
            _ => Err(conflict("lease_lost", "The lease is no longer held.")),
        }
    }

    async fn fail(&self, lease_id: &str, retry: bool, reason: &str) -> Result<()> {
        let now = self.now();
        let rows = self
            .db
            .rows(
                "SELECT attempts, max_attempts FROM compute_jobs WHERE lease_id = ? AND status = 'leased'",
                vec![t(lease_id)],
            )
            .await?;
        let (attempts, max) = rows
            .first()
            .map_or((0, 0), |r| (int(r.first()), int(r.get(1))));
        let requeue = retry && attempts < max;
        // Back off 2^attempts seconds, at most five minutes.
        let delay_secs = if attempts > 8 { 300 } else { 1i64 << attempts };
        let n = self
            .db
            .run(
                "UPDATE compute_jobs SET status = ?, last_error = ?, run_at = ? WHERE lease_id = ? AND status = 'leased'",
                vec![
                    t(if requeue { "queued" } else { "dead" }),
                    t(reason),
                    Value::Int64(now + delay_secs * 1_000_000),
                    t(lease_id),
                ],
            )
            .await?;
        if n == 1 {
            return Ok(());
        }
        match self.lease_row(lease_id).await? {
            Some((status, _)) if status == "queued" || status == "dead" => Ok(()),
            _ => Err(conflict("lease_lost", "The lease is no longer held.")),
        }
    }
}
