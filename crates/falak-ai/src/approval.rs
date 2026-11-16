//! The human approval gate for AI writes (T7.10).
//!
//! An agent never changes data. With writes switched on, a `create_*`, `update_*` or
//! `delete_*` tool call only **queues a proposal**: the exact request, a plain-language
//! summary and a digest of both. A person looks at it and approves or rejects it:
//!
//! * the approver is the person the agent acts for (same subject), never anyone else;
//! * the approval must carry the `step_up` role, which Office grants only after the
//!   person has just proven themselves again, so the agent's ordinary token cannot approve
//!   its own proposal;
//! * the approver must quote the proposal's `digest`, so what they approve is exactly what
//!   they were shown, and a proposal cannot be swapped between viewing and approving;
//! * approval is one-time and the proposal expires;
//! * the request then runs with the **approver's** credential, through the policy engine,
//!   so the write is allowed only if the person was allowed to make it.
//!
//! Proposals live in the process: a restart drops the queue, which is the safe direction.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// How long a proposal waits for a person.
pub const PROPOSAL_TTL_SECS: u64 = 15 * 60;
/// The role a fresh proof of the person adds to their token.
pub const STEP_UP_ROLE: &str = "step_up";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Pending,
    Approved,
    Rejected,
}

#[derive(Debug, Clone)]
pub struct Proposal {
    pub id: String,
    /// Who the agent acts for.
    pub subject: String,
    pub tool: String,
    pub method: String,
    pub path: String,
    pub body: Value,
    pub summary: String,
    pub digest: String,
    pub created: u64,
    pub state: State,
    /// What the write answered, once approved.
    pub outcome: Option<Value>,
}

impl Proposal {
    pub fn public(&self) -> Value {
        json!({
            "id": self.id,
            "tool": self.tool,
            "summary": self.summary,
            "method": self.method,
            "path": self.path,
            "body": self.body,
            "digest": self.digest,
            "state": match self.state {
                State::Pending => "pending",
                State::Approved => "approved",
                State::Rejected => "rejected",
            },
            "outcome": self.outcome,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// No such proposal for this person (or it is not theirs: the same answer).
    NotFound,
    /// Needs a fresh proof of the person.
    StepUpRequired,
    DigestMismatch,
    /// Already decided, or expired.
    Closed,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn random_hex(n: usize) -> String {
    use rand_core::{OsRng, RngCore};
    let mut b = vec![0u8; n];
    OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

pub fn digest_of(method: &str, path: &str, body: &Value) -> String {
    let mut h = Sha256::new();
    for part in [method, path, &body.to_string()] {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part.as_bytes());
    }
    hex::encode(h.finalize())
}

#[derive(Default)]
pub struct Approvals {
    items: Mutex<HashMap<String, Proposal>>,
    /// An append-only account of what happened, for the audit trail.
    log: Mutex<Vec<String>>,
}

impl Approvals {
    fn items(&self) -> std::sync::MutexGuard<'_, HashMap<String, Proposal>> {
        self.items.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn note(&self, line: String) {
        self.log
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(line);
    }

    pub fn log(&self) -> Vec<String> {
        self.log.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    pub fn propose(
        &self,
        subject: &str,
        tool: &str,
        method: &str,
        path: &str,
        body: Value,
        summary: &str,
    ) -> Proposal {
        let p = Proposal {
            id: random_hex(12),
            subject: subject.to_owned(),
            tool: tool.to_owned(),
            method: method.to_owned(),
            path: path.to_owned(),
            digest: digest_of(method, path, &body),
            body,
            summary: summary.to_owned(),
            created: now(),
            state: State::Pending,
            outcome: None,
        };
        self.note(format!(
            "proposed {} by agent for {subject}: {summary}",
            p.id
        ));
        self.items().insert(p.id.clone(), p.clone());
        p
    }

    /// The person's own proposals, newest first. Expired ones are dropped.
    pub fn list(&self, subject: &str) -> Vec<Proposal> {
        let t = now();
        let mut v: Vec<Proposal> = self
            .items()
            .values()
            .filter(|p| p.subject == subject && t.saturating_sub(p.created) <= PROPOSAL_TTL_SECS)
            .cloned()
            .collect();
        v.sort_by(|a, b| b.created.cmp(&a.created).then(a.id.cmp(&b.id)));
        v
    }

    /// Decide to approve: checks everything and, if it all holds, closes the proposal and
    /// returns it for the caller to execute. `roles` are the approver's.
    pub fn approve(
        &self,
        id: &str,
        subject: &str,
        roles: &[String],
        digest: &str,
    ) -> Result<Proposal, Refusal> {
        let mut items = self.items();
        let p = items
            .get_mut(id)
            .filter(|p| p.subject == subject)
            .ok_or(Refusal::NotFound)?;
        if !roles.iter().any(|r| r == STEP_UP_ROLE) {
            self.note(format!("refused {id}: no step-up"));
            return Err(Refusal::StepUpRequired);
        }
        if p.state != State::Pending || now().saturating_sub(p.created) > PROPOSAL_TTL_SECS {
            return Err(Refusal::Closed);
        }
        if p.digest != digest {
            self.note(format!("refused {id}: digest mismatch"));
            return Err(Refusal::DigestMismatch);
        }
        p.state = State::Approved;
        self.note(format!("approved {id} by {subject}"));
        Ok(p.clone())
    }

    pub fn reject(&self, id: &str, subject: &str) -> Result<Proposal, Refusal> {
        let mut items = self.items();
        let p = items
            .get_mut(id)
            .filter(|p| p.subject == subject)
            .ok_or(Refusal::NotFound)?;
        if p.state != State::Pending {
            return Err(Refusal::Closed);
        }
        p.state = State::Rejected;
        self.note(format!("rejected {id} by {subject}"));
        Ok(p.clone())
    }

    pub fn record_outcome(&self, id: &str, outcome: Value) {
        if let Some(p) = self.items().get_mut(id) {
            p.outcome = Some(outcome);
        }
    }
}
