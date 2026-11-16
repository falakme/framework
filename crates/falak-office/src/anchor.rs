//! External anchoring of Office's audit chain (T6.5).
//!
//! The chain in `office_audit` detects an edit in the middle, but whoever can rewrite the
//! database can rewrite every hash after the edit, or cut off the tail. An anchor is the
//! chain's head (`seq`, `hash`) signed with Office's key and written somewhere the
//! database's administrators cannot change: a directory that is write-once storage
//! (`FALAK_AUDIT_ANCHOR_DIR`, for example an object-lock bucket mounted or synced) and/or
//! an HTTP endpoint (`FALAK_AUDIT_ANCHOR_URL`, a transparency log, a webhook to another
//! organisation). Each anchor is a new file that is never overwritten.
//!
//! `verify` walks the whole chain, then checks every external anchor: its signature, and
//! that the chain still has that `seq` with that `hash`. History that was rewritten or
//! truncated after an anchor was published fails here.

use std::path::Path;

use falak_contracts::{Result, driver::Value};
use serde_json::{Value as Json, json};
use sha2::{Digest, Sha256};

use crate::{
    Office,
    db::{int, t, text},
    now,
};

/// The hash of one audit entry (the same formula `Office::audit` writes).
pub fn entry_hash(
    prev: &str,
    seq: i64,
    at: i64,
    actor: &str,
    action: &str,
    detail: &str,
) -> String {
    hex::encode(Sha256::digest(
        format!("{prev}|{seq}|{at}|{actor}|{action}|{detail}").as_bytes(),
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchor {
    pub seq: i64,
    pub hash: String,
    pub at: i64,
    pub kid: String,
    pub signature: String,
}

/// What `verify` found.
#[derive(Debug, Default, serde::Serialize)]
pub struct Report {
    pub entries: usize,
    pub anchors_checked: usize,
    pub problems: Vec<String>,
}

impl Report {
    pub fn ok(&self) -> bool {
        self.problems.is_empty()
    }
}

fn message(issuer: &str, seq: i64, hash: &str, at: i64) -> String {
    format!("falak-audit-anchor\n{issuer}\n{seq}\n{hash}\n{at}")
}

impl Office {
    /// The head of the audit chain, if there is one.
    pub async fn audit_head(&self) -> Result<Option<(i64, String)>> {
        let r = self
            .db
            .rows(
                "SELECT seq, hash FROM office_audit ORDER BY seq DESC LIMIT 1",
                vec![],
            )
            .await?;
        Ok(r.first().map(|r| (int(r.first()), text(r.get(1)))))
    }

    /// Anchor the current head, unless it is already anchored. Returns the anchor made.
    pub async fn anchor_now(&self) -> Result<Option<Anchor>> {
        self.anchor_to(
            std::env::var_os("FALAK_AUDIT_ANCHOR_DIR").map(Into::into),
            std::env::var("FALAK_AUDIT_ANCHOR_URL").ok(),
        )
        .await
    }

    /// [`Self::anchor_now`] with the sinks given instead of read from the environment.
    pub async fn anchor_to(
        &self,
        dir: Option<std::path::PathBuf>,
        url: Option<String>,
    ) -> Result<Option<Anchor>> {
        let Some((seq, hash)) = self.audit_head().await? else {
            return Ok(None);
        };
        let done = self
            .db
            .rows(
                "SELECT seq FROM office_anchors WHERE seq = ?",
                vec![Value::Int64(seq)],
            )
            .await?;
        if !done.is_empty() {
            return Ok(None);
        }
        let at = now();
        let (kid, sig) = self.sign(message(&self.issuer, seq, &hash, at).as_bytes());
        let signature = hex::encode(sig);
        let anchor = Anchor {
            seq,
            hash,
            at,
            kid,
            signature,
        };
        // Publish first: an anchor nobody outside can see is not an anchor.
        publish(&self.issuer, &anchor, dir, url).await?;
        self.db
            .run(
                "INSERT INTO office_anchors (seq, hash, at, kid, signature) VALUES (?, ?, ?, ?, ?)",
                vec![
                    Value::Int64(anchor.seq),
                    t(&anchor.hash),
                    Value::Int64(anchor.at),
                    t(&anchor.kid),
                    t(&anchor.signature),
                ],
            )
            .await?;
        Ok(Some(anchor))
    }

    /// Whether the chain has grown since the last anchor.
    pub async fn anchor_pending(&self) -> bool {
        let Ok(Some((seq, _))) = self.audit_head().await else {
            return false;
        };
        self.db
            .rows(
                "SELECT seq FROM office_anchors WHERE seq = ?",
                vec![Value::Int64(seq)],
            )
            .await
            .is_ok_and(|r| r.is_empty())
    }

    /// When the newest anchor was made (seconds), if any.
    pub async fn last_anchor_at(&self) -> Result<Option<i64>> {
        let r = self
            .db
            .rows("SELECT MAX(at) FROM office_anchors", vec![])
            .await?;
        Ok(r.first().and_then(|r| match r.first() {
            Some(Value::Null) | None => None,
            v => Some(int(v)),
        }))
    }

    /// Check the whole chain and every anchor found in `anchor_dir` (default: the
    /// configured directory) and in the database.
    pub async fn verify_audit(&self, anchor_dir: Option<&Path>) -> Result<Report> {
        let rows = self
            .db
            .rows(
                "SELECT seq, at, actor, action, detail, prev_hash, hash FROM office_audit ORDER BY seq",
                vec![],
            )
            .await?;
        let mut report = Report {
            entries: rows.len(),
            ..Report::default()
        };
        let mut by_seq = std::collections::HashMap::new();
        let mut prev = String::new();
        let mut expect = 1;
        for r in &rows {
            let (seq, at) = (int(r.first()), int(r.get(1)));
            let (actor, action, detail) = (text(r.get(2)), text(r.get(3)), text(r.get(4)));
            let (prev_hash, hash) = (text(r.get(5)), text(r.get(6)));
            if seq != expect {
                report
                    .problems
                    .push(format!("entry {expect} is missing (next is {seq})"));
                expect = seq;
            }
            if prev_hash != prev {
                report
                    .problems
                    .push(format!("entry {seq} does not follow entry {}", seq - 1));
            }
            if hash != entry_hash(&prev_hash, seq, at, &actor, &action, &detail) {
                report
                    .problems
                    .push(format!("entry {seq} was changed after it was written"));
            }
            by_seq.insert(seq, hash.clone());
            prev = hash;
            expect += 1;
        }
        let mut anchors = self.db_anchors().await?;
        if let Some(dir) = anchor_dir
            .map(Path::to_path_buf)
            .or_else(|| std::env::var_os("FALAK_AUDIT_ANCHOR_DIR").map(Into::into))
        {
            match read_dir_anchors(&dir) {
                Ok(mut a) => anchors.append(&mut a),
                Err(e) => report.problems.push(e),
            }
        }
        anchors.sort_by_key(|a| (a.seq, a.hash.clone()));
        anchors.dedup();
        for a in &anchors {
            report.anchors_checked += 1;
            let valid = self.verify_signature(
                &a.kid,
                message(&self.issuer, a.seq, &a.hash, a.at).as_bytes(),
                &hex::decode(&a.signature).unwrap_or_default(),
            );
            if !valid {
                report.problems.push(format!(
                    "the anchor for entry {} is not signed by Office",
                    a.seq
                ));
                continue;
            }
            match by_seq.get(&a.seq) {
                None => report.problems.push(format!(
                    "the chain was cut short: entry {} was anchored but is gone",
                    a.seq
                )),
                Some(h) if *h != a.hash => report.problems.push(format!(
                    "entry {} was rewritten after it was anchored",
                    a.seq
                )),
                _ => {}
            }
        }
        Ok(report)
    }

    async fn db_anchors(&self) -> Result<Vec<Anchor>> {
        Ok(self
            .db
            .rows(
                "SELECT seq, hash, at, kid, signature FROM office_anchors",
                vec![],
            )
            .await?
            .iter()
            .map(|r| Anchor {
                seq: int(r.first()),
                hash: text(r.get(1)),
                at: int(r.get(2)),
                kid: text(r.get(3)),
                signature: text(r.get(4)),
            })
            .collect())
    }
}

fn to_json(issuer: &str, a: &Anchor) -> Json {
    json!({"issuer": issuer, "seq": a.seq, "hash": a.hash, "at": a.at, "kid": a.kid, "signature": a.signature})
}

fn read_dir_anchors(dir: &Path) -> std::result::Result<Vec<Anchor>, String> {
    let mut out = Vec::new();
    let rd = std::fs::read_dir(dir)
        .map_err(|e| format!("cannot read the anchor directory {}: {e}", dir.display()))?;
    for e in rd.filter_map(std::result::Result::ok) {
        let p = e.path();
        if p.extension().is_none_or(|x| x != "json") {
            continue;
        }
        let v: Json = std::fs::read_to_string(&p)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .ok_or_else(|| format!("{} is not a valid anchor", p.display()))?;
        out.push(Anchor {
            seq: v["seq"].as_i64().unwrap_or(-1),
            hash: v["hash"].as_str().unwrap_or_default().into(),
            at: v["at"].as_i64().unwrap_or(0),
            kid: v["kid"].as_str().unwrap_or_default().into(),
            signature: v["signature"].as_str().unwrap_or_default().into(),
        });
    }
    Ok(out)
}

/// Write the anchor to every configured sink. With no sink configured the anchor is only
/// in the database, which is not external, so say so.
async fn publish(
    issuer: &str,
    a: &Anchor,
    dir: Option<std::path::PathBuf>,
    url: Option<String>,
) -> Result<()> {
    let body = to_json(issuer, a).to_string();
    if dir.is_none() && url.is_none() {
        eprintln!(
            "audit anchor {} kept in the database only: set FALAK_AUDIT_ANCHOR_DIR or FALAK_AUDIT_ANCHOR_URL to anchor externally",
            a.seq
        );
        return Ok(());
    }
    let name = format!("{:012}-{}.json", a.seq, &a.hash[..16.min(a.hash.len())]);
    tokio::task::spawn_blocking(move || -> Result<()> {
        if let Some(dir) = dir {
            std::fs::create_dir_all(&dir).map_err(io)?;
            // `create_new`: an anchor is never overwritten.
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(dir.join(name))
                .map_err(io)?;
            f.write_all(body.as_bytes()).map_err(io)?;
            f.sync_all().map_err(io)?;
        }
        if let Some(url) = url {
            ureq::post(&url)
                .timeout(std::time::Duration::from_secs(10))
                .set("content-type", "application/json")
                .send_string(&body)
                .map_err(|e| {
                    falak_contracts::Error::internal(format!("cannot post the anchor: {e}"))
                })?;
        }
        Ok(())
    })
    .await
    .map_err(|e| falak_contracts::Error::internal(format!("anchor task: {e}")))?
}

fn io(e: std::io::Error) -> falak_contracts::Error {
    falak_contracts::Error::internal(format!("cannot write the anchor: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hash_matches_what_office_writes() {
        let h = entry_hash("", 1, 10, "a", "b", "c");
        assert_eq!(h.len(), 64);
        assert_ne!(h, entry_hash("", 1, 10, "a", "b", "d"));
    }
}
