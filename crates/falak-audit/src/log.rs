//! The audit log stored through a `StorageDriver` (T3.13).
//!
//! * **Append-only.** The table has triggers that refuse `UPDATE` and `DELETE`, and the
//!   runtime role should not own the table or be allowed to drop triggers. On PostgreSQL
//!   also `REVOKE UPDATE, DELETE` from the runtime role.
//! * **Chained.** Each row carries the hash of the row before it (see [`crate::chain`]).
//! * **One writer at a time per sequence number.** `seq` is the primary key, so two
//!   writers that read the same last row cannot both insert; the loser retries.

use falak_contracts::{
    Error, ErrorKind, Result,
    driver::{Statement, StorageDriver, Value},
    identity::RequestContext,
    support::Clock,
};

use crate::chain::{Anchor, Entry, Failure, GENESIS, from_hex, to_hex, verify};

/// How the database spells a parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placeholders {
    /// `?` (SQLite and D1).
    Question,
    /// `$1`, `$2`, ... (PostgreSQL).
    Numbered,
}

/// Longest `details` text accepted.
pub const MAX_DETAILS_BYTES: usize = 4096;
/// Longest `actor`, `action`, `target` and `outcome` accepted.
pub const MAX_FIELD_BYTES: usize = 256;

const TABLE: &str = "CREATE TABLE IF NOT EXISTS falak_audit (\
    seq BIGINT PRIMARY KEY, at_micros BIGINT NOT NULL, actor TEXT, action TEXT NOT NULL, \
    target TEXT, outcome TEXT NOT NULL, details TEXT NOT NULL, \
    prev_hash TEXT NOT NULL, hash TEXT NOT NULL)";

const SQLITE_TRIGGERS: [&str; 2] = [
    "CREATE TRIGGER IF NOT EXISTS falak_audit_no_update BEFORE UPDATE ON falak_audit \
     BEGIN SELECT RAISE(ABORT, 'the audit log is append-only'); END",
    "CREATE TRIGGER IF NOT EXISTS falak_audit_no_delete BEFORE DELETE ON falak_audit \
     BEGIN SELECT RAISE(ABORT, 'the audit log is append-only'); END",
];

const POSTGRES_TRIGGERS: [&str; 5] = [
    "CREATE OR REPLACE FUNCTION falak_audit_immutable() RETURNS trigger AS $$ \
     BEGIN RAISE EXCEPTION 'the audit log is append-only'; END $$ LANGUAGE plpgsql",
    "DROP TRIGGER IF EXISTS falak_audit_immutable ON falak_audit",
    "CREATE TRIGGER falak_audit_immutable BEFORE UPDATE OR DELETE ON falak_audit \
     FOR EACH ROW EXECUTE FUNCTION falak_audit_immutable()",
    // A row trigger does not fire for TRUNCATE, which would wipe the log in one statement.
    "DROP TRIGGER IF EXISTS falak_audit_immutable_truncate ON falak_audit",
    "CREATE TRIGGER falak_audit_immutable_truncate BEFORE TRUNCATE ON falak_audit \
     FOR EACH STATEMENT EXECUTE FUNCTION falak_audit_immutable()",
];

const COLUMNS: &str = "seq, at_micros, actor, action, target, outcome, details, prev_hash, hash";

/// A failure to verify: either the log was altered, or it could not be read.
#[derive(Debug)]
pub enum VerifyError {
    Tampered(Failure),
    Storage(Error),
}

pub struct AuditLog<D, C> {
    driver: D,
    clock: C,
    style: Placeholders,
}

fn ctx() -> RequestContext {
    RequestContext {
        principal: None,
        request_id: "falak-audit".into(),
    }
}

fn corrupt() -> Error {
    Error::internal("audit row has an unexpected shape")
}

fn too_long(what: &'static str) -> Error {
    Error::invalid_input(what, "An audit field is too long.")
}

fn text(v: Option<&Value>) -> Option<String> {
    match v {
        Some(Value::Text(s)) => Some(s.clone()),
        _ => None,
    }
}

fn int(v: Option<&Value>) -> Option<i64> {
    match v {
        Some(Value::Int64(n)) => Some(*n),
        _ => None,
    }
}

fn entry_from(row: &[Value]) -> Result<Entry> {
    let opt = |i: usize| match row.get(i) {
        Some(Value::Null) => Ok(None),
        v => text(v).map(Some).ok_or_else(corrupt),
    };
    let req = |i: usize| text(row.get(i)).ok_or_else(corrupt);
    Ok(Entry {
        seq: u64::try_from(int(row.first()).ok_or_else(corrupt)?).map_err(|_| corrupt())?,
        at_micros: int(row.get(1)).ok_or_else(corrupt)?,
        actor: opt(2)?,
        action: req(3)?,
        target: opt(4)?,
        outcome: req(5)?,
        details: req(6)?,
        prev_hash: from_hex(&req(7)?).ok_or_else(corrupt)?,
        hash: from_hex(&req(8)?).ok_or_else(corrupt)?,
    })
}

impl<D: StorageDriver, C: Clock> AuditLog<D, C> {
    pub fn new(driver: D, clock: C, style: Placeholders) -> Self {
        Self {
            driver,
            clock,
            style,
        }
    }

    fn render(&self, sql: &str) -> String {
        match self.style {
            Placeholders::Question => sql.to_owned(),
            Placeholders::Numbered => {
                let mut n = 0;
                let mut out = String::with_capacity(sql.len() + 8);
                for c in sql.chars() {
                    if c == '?' {
                        n += 1;
                        out.push_str(&format!("${n}"));
                    } else {
                        out.push(c);
                    }
                }
                out
            }
        }
    }

    /// Create the table and the append-only triggers if they are missing.
    pub async fn migrate(&self) -> Result<()> {
        let mut statements = vec![Statement::new(TABLE, vec![])];
        match self.style {
            Placeholders::Question => {
                statements.extend(SQLITE_TRIGGERS.iter().map(|s| Statement::new(*s, vec![])));
            }
            Placeholders::Numbered => {
                statements.extend(POSTGRES_TRIGGERS.iter().map(|s| Statement::new(*s, vec![])));
            }
        }
        self.driver.batch(&ctx(), statements).await.map(|_| ())
    }

    async fn last(&self) -> Result<Option<Entry>> {
        let rows = self
            .driver
            .query(
                &ctx(),
                Statement::new(
                    format!("SELECT {COLUMNS} FROM falak_audit ORDER BY seq DESC LIMIT 1"),
                    vec![],
                ),
            )
            .await?
            .rows;
        rows.first().map(|r| entry_from(r)).transpose()
    }

    /// Add an entry. `details` is compact JSON text without personal data or secrets.
    pub async fn append(
        &self,
        actor: Option<&str>,
        action: &str,
        target: Option<&str>,
        outcome: &str,
        details: &str,
    ) -> Result<Entry> {
        for (value, what) in [
            (Some(action), "audit_action_too_long"),
            (Some(outcome), "audit_outcome_too_long"),
            (actor, "audit_actor_too_long"),
            (target, "audit_target_too_long"),
        ] {
            if value.is_some_and(|v| v.len() > MAX_FIELD_BYTES) {
                return Err(too_long(what));
            }
        }
        if details.len() > MAX_DETAILS_BYTES {
            return Err(too_long("audit_details_too_long"));
        }
        let at = self.clock.now_micros();

        // Two writers can read the same last row; the primary key lets one win.
        for _ in 0..8 {
            let prev = self.last().await?;
            let entry = Entry::next(
                prev.as_ref(),
                at,
                actor.map(str::to_owned),
                action.to_owned(),
                target.map(str::to_owned),
                outcome.to_owned(),
                details.to_owned(),
            );
            let sql = self.render(&format!(
                "INSERT INTO falak_audit ({COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
            ));
            let opt = |s: &Option<String>| s.clone().map_or(Value::Null, Value::Text);
            let result = self
                .driver
                .batch(
                    &ctx(),
                    vec![Statement::new(
                        sql,
                        vec![
                            Value::Int64(i64::try_from(entry.seq).map_err(|_| corrupt())?),
                            Value::Int64(entry.at_micros),
                            opt(&entry.actor),
                            Value::Text(entry.action.clone()),
                            opt(&entry.target),
                            Value::Text(entry.outcome.clone()),
                            Value::Text(entry.details.clone()),
                            Value::Text(to_hex(&entry.prev_hash)),
                            Value::Text(to_hex(&entry.hash)),
                        ],
                    )],
                )
                .await;
            match result {
                Ok(_) => return Ok(entry),
                Err(e) if e.kind() == ErrorKind::Conflict => {}
                Err(e) => return Err(e),
            }
        }
        Err(Error::new(
            ErrorKind::Unavailable,
            "audit_busy",
            "The audit log is busy. Try again.",
        ))
    }

    /// Entries after `after_seq`, in order, at most `limit` (capped at 1,000).
    pub async fn entries(&self, after_seq: u64, limit: u32) -> Result<Vec<Entry>> {
        let after = i64::try_from(after_seq).unwrap_or(i64::MAX);
        let rows = self
            .driver
            .query(
                &ctx(),
                Statement::new(
                    self.render(&format!(
                        "SELECT {COLUMNS} FROM falak_audit WHERE seq > ? ORDER BY seq ASC LIMIT ?"
                    )),
                    vec![
                        Value::Int64(after),
                        Value::Int64(i64::from(limit.min(1000))),
                    ],
                ),
            )
            .await?
            .rows;
        rows.iter().map(|r| entry_from(r)).collect()
    }

    /// The newest entry's position and hash, to store somewhere the log's writer cannot
    /// reach. `None` for an empty log.
    pub async fn anchor(&self) -> Result<Option<Anchor>> {
        Ok(self.last().await?.map(|e| Anchor {
            seq: e.seq,
            hash: e.hash,
        }))
    }

    /// Read the whole log and check the chain, and the anchor if one is given.
    pub async fn verify(&self, anchor: Option<&Anchor>) -> std::result::Result<(), VerifyError> {
        let mut all: Vec<Entry> = Vec::new();
        loop {
            let after = all.last().map_or(0, |e| e.seq);
            let page = self
                .entries(after, 500)
                .await
                .map_err(VerifyError::Storage)?;
            if page.is_empty() {
                break;
            }
            all.extend(page);
        }
        // An empty log has nothing to check unless an anchor says it should not be empty.
        if all.is_empty() {
            return match anchor {
                Some(a) => Err(VerifyError::Tampered(Failure {
                    seq: a.seq,
                    problem: crate::chain::Problem::DoesNotReachAnchor,
                })),
                None => Ok(()),
            };
        }
        // The log is read whole, so it must begin at its beginning. `chain::verify` lets a
        // page from the middle stand alone; here a first entry that is not seq 1 means
        // the oldest entries were removed, which no anchor taken later would reveal.
        if all[0].seq != 1 {
            return Err(VerifyError::Tampered(Failure {
                seq: all[0].seq,
                problem: crate::chain::Problem::BadStart,
            }));
        }
        verify(&all, anchor).map_err(VerifyError::Tampered)
    }

    /// The hash the next entry will chain from.
    pub async fn head(&self) -> Result<[u8; 32]> {
        Ok(self.last().await?.map_or(GENESIS, |e| e.hash))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn postgres_refuses_truncate_as_well_as_update_and_delete() {
        assert!(
            POSTGRES_TRIGGERS
                .iter()
                .any(|s| s.contains("BEFORE TRUNCATE ON falak_audit"))
        );
    }
}
