//! The worker's only conversation: outbound HTTPS calls to Office. Nothing listens.

use std::time::Duration;

use falak_contracts::ir::IrJob;
use serde_json::{Value, json};

#[derive(Debug)]
pub enum ClientError {
    /// Office answered with a refusal: 401/403 (credential revoked or wrong) or 409 (the
    /// lease is no longer ours).
    Rejected(u16),
    Transport(String),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected(s) => write!(f, "Office refused the request ({s})"),
            Self::Transport(e) => write!(f, "cannot reach Office: {e}"),
        }
    }
}

/// A job this worker holds.
#[derive(Debug, Clone)]
pub struct Leased {
    pub lease_id: String,
    pub job_id: String,
    pub kind: String,
    pub attempt: u32,
    pub payload: Value,
    pub spec: IrJob,
    /// The job's own short-lived credential.
    pub credential: String,
}

pub struct Office {
    pub base: String,
    credential: String,
    agent: ureq::Agent,
}

impl Office {
    pub fn new(base: &str, credential: &str) -> Self {
        Self {
            base: base.trim_end_matches('/').to_owned(),
            credential: credential.to_owned(),
            agent: ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(30))
                .build(),
        }
    }

    fn post(&self, path: &str, body: &Value) -> Result<Value, ClientError> {
        let res = self
            .agent
            .post(&format!("{}/v1/_office/compute/{path}", self.base))
            .set("authorization", &format!("Bearer {}", self.credential))
            .send_json(body);
        match res {
            Ok(r) => r
                .into_json::<Value>()
                .map_err(|e| ClientError::Transport(e.to_string())),
            Err(ureq::Error::Status(code, _)) => Err(ClientError::Rejected(code)),
            Err(e) => Err(ClientError::Transport(e.to_string())),
        }
    }

    pub fn lease(
        &self,
        kinds: &[String],
        max: usize,
        lease_millis: u64,
    ) -> Result<Vec<Leased>, ClientError> {
        let v = self.post(
            "lease",
            &json!({"kinds": kinds, "max": max, "lease_millis": lease_millis}),
        )?;
        let mut out = Vec::new();
        for j in v["jobs"].as_array().into_iter().flatten() {
            let Ok(spec) = serde_json::from_value::<IrJob>(j["spec"].clone()) else {
                // A job without a readable contract cannot run; failing it for good
                // keeps it from being leased forever.
                if let Some(l) = j["lease_id"].as_str() {
                    let _ = self.fail(l, false, "the job contract is unreadable");
                }
                continue;
            };
            out.push(Leased {
                lease_id: j["lease_id"].as_str().unwrap_or_default().to_owned(),
                job_id: j["job_id"].as_str().unwrap_or_default().to_owned(),
                kind: j["kind"].as_str().unwrap_or_default().to_owned(),
                attempt: u32::try_from(j["attempt"].as_u64().unwrap_or(1)).unwrap_or(1),
                payload: j["payload"].clone(),
                spec,
                credential: j["credential"].as_str().unwrap_or_default().to_owned(),
            });
        }
        Ok(out)
    }

    pub fn heartbeat(&self, lease: &str, extend_millis: u64) -> Result<(), ClientError> {
        self.post(
            &format!("leases/{lease}/heartbeat"),
            &json!({"extend_millis": extend_millis}),
        )
        .map(|_| ())
    }

    pub fn complete(&self, lease: &str, result: Option<&Value>) -> Result<(), ClientError> {
        self.post(
            &format!("leases/{lease}/complete"),
            &json!({"result": result}),
        )
        .map(|_| ())
    }

    pub fn fail(&self, lease: &str, retry: bool, reason: &str) -> Result<(), ClientError> {
        self.post(
            &format!("leases/{lease}/fail"),
            &json!({"retry": retry, "reason": reason}),
        )
        .map(|_| ())
    }
}
