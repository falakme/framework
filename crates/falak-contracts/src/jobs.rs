//! Asynchronous jobs with leasing. A worker that stops heartbeating loses its lease and
//! the job is retried, so completion must be idempotent.

use crate::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    pub id: [u8; 16],
    pub kind: String,
    /// JSON bytes, validated against the job contract.
    pub payload: Vec<u8>,
    pub attempts: u32,
    pub run_at_micros: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    pub lease_id: String,
    pub job: Job,
    pub expires_at_micros: i64,
}

pub trait JobDispatcher {
    async fn enqueue(&self, job: Job) -> Result<()>;
    /// Lease up to `max` due jobs of the given kinds for `lease_millis`.
    async fn lease(&self, kinds: &[String], max: usize, lease_millis: u64) -> Result<Vec<Lease>>;
    async fn heartbeat(&self, lease_id: &str, extend_millis: u64) -> Result<()>;
    async fn complete(&self, lease_id: &str) -> Result<()>;
    /// Report failure. With `retry` false the job goes to the dead-letter queue.
    async fn fail(&self, lease_id: &str, retry: bool, reason: &str) -> Result<()>;
}
