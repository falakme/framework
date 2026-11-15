//! Falak Studio: one admin interface for every app in an Office, with no code of its
//! own for any app.
//!
//! * **Generated.** What it shows comes from each app's `GET /v1/_schema` (entities,
//!   fields and the `admin:` metadata), so a new app needs only an entry in the config.
//! * **Backend for frontend.** The browser holds one `HttpOnly`, `SameSite=Strict` cookie
//!   and never sees a token. Office and app tokens stay on the server.
//! * **Only through the apps.** Every read and write is a call to the app's own API with
//!   an Office-issued token for that app, so the app's policies decide. Studio has no
//!   database access and no way to widen what a person may do.
//! * **Personal data is masked** before it leaves the server. Showing it is a separate,
//!   audited action.
//! * **Audited.** Sign-ins, writes and reveals go to a hash-chained log. Values never do.

use std::{
    path::{Path, PathBuf},
    sync::Mutex,
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

mod routes;
pub use routes::{Studio, router};

/// A session ends after this long idle, or this long in all.
pub const IDLE_SECS: i64 = 30 * 60;
pub const ABSOLUTE_SECS: i64 = 8 * 60 * 60;
/// Office roles that may use Studio at all.
pub const STUDIO_ROLES: [&str; 2] = ["office_admin", "studio"];

#[derive(Debug, Clone, Deserialize)]
pub struct AppEntry {
    pub name: String,
    /// The app's API, for example `https://notebook.example.com`.
    pub url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub office_url: String,
    pub apps: Vec<AppEntry>,
    /// Mark the cookie `Secure`. On whenever Studio is served over https.
    #[serde(default)]
    pub cookie_secure: bool,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read `{}`: {e}", path.display()))?;
        let cfg: Self = serde_json::from_str(&text)
            .map_err(|e| format!("`{}` is not valid: {e}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), String> {
        for url in std::iter::once(&self.office_url).chain(self.apps.iter().map(|a| &a.url)) {
            if !trusted_url(url) {
                return Err(format!("`{url}` must be https (or http to this machine)"));
            }
        }
        for a in &self.apps {
            let ok = !a.name.is_empty()
                && a.name.bytes().all(|c| {
                    c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'_'
                });
            if !ok {
                return Err(format!("`{}` is not an app name", a.name));
            }
        }
        Ok(())
    }
}

/// `https`, or `http` to this machine for development.
pub fn trusted_url(url: &str) -> bool {
    url.starts_with("https://")
        || ["http://127.0.0.1", "http://localhost", "http://[::1]"]
            .iter()
            .any(|p| {
                url.starts_with(p)
                    && matches!(url.as_bytes().get(p.len()), None | Some(b':' | b'/'))
            })
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0))
}

pub fn random_id() -> String {
    use rand_core::RngCore;
    let mut b = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut b);
    B64.encode(b)
}

// ---------------------------------------------------------------- masking

/// The character a hidden value is made of.
pub const MASK: &str = "•";

/// Hide a value. Text keeps its first character and a rough length; anything else is
/// hidden whole.
pub fn mask(v: &Value) -> Value {
    match v {
        Value::Null => Value::Null,
        Value::String(s) => {
            let n = s.chars().count();
            if n <= 3 {
                Value::String(MASK.repeat(3))
            } else {
                let first: String = s.chars().take(1).collect();
                Value::String(format!("{first}{}", MASK.repeat(n.min(8) - 1)))
            }
        }
        _ => Value::String(MASK.repeat(3)),
    }
}

/// Mask the personal fields (and encrypted ones) of each row in a list, or of a record.
pub fn mask_rows(body: &mut Value, sensitive: &[String]) {
    fn one(row: &mut Value, sensitive: &[String]) {
        if let Some(o) = row.as_object_mut() {
            for k in sensitive {
                if let Some(v) = o.get_mut(k) {
                    *v = mask(v);
                }
            }
        }
    }
    if let Some(rows) = body.get_mut("data").and_then(Value::as_array_mut) {
        for r in rows {
            one(r, sensitive);
        }
    } else {
        one(body, sensitive);
    }
}

// ---------------------------------------------------------------- audit

/// An append-only log in which each line commits to the one before it. It records who
/// did what to which record, never the values.
pub struct Audit {
    path: Option<PathBuf>,
    state: Mutex<(i64, String)>,
}

impl Audit {
    pub fn open(path: Option<PathBuf>) -> Result<Self, String> {
        let mut last = (0, "genesis".to_owned());
        if let Some(p) = &path {
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            if let Ok(text) = std::fs::read_to_string(p)
                && let Some(line) = text.lines().last()
            {
                let v: Value =
                    serde_json::from_str(line).map_err(|_| "the audit log is damaged")?;
                last = (
                    v["seq"].as_i64().unwrap_or(0),
                    v["hash"].as_str().unwrap_or_default().to_owned(),
                );
            }
        }
        Ok(Self {
            path,
            state: Mutex::new(last),
        })
    }

    fn hash(prev: &str, seq: i64, at: i64, actor: &str, action: &str, target: &str) -> String {
        hex::encode(Sha256::digest(
            format!("{prev}\n{seq}\n{at}\n{actor}\n{action}\n{target}").as_bytes(),
        ))
    }

    /// Append one entry. A log that cannot be written is reported, not ignored: the
    /// caller refuses the action when it fails.
    pub fn record(&self, actor: &str, action: &str, target: &str) -> Result<(), String> {
        let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let seq = s.0 + 1;
        let at = now();
        let hash = Self::hash(&s.1, seq, at, actor, action, target);
        let line = json!({
            "seq": seq, "at": at, "actor": actor, "action": action, "target": target,
            "prev": s.1, "hash": hash,
        })
        .to_string();
        if let Some(p) = &self.path {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(p)
                .map_err(|e| format!("cannot write the audit log: {e}"))?;
            writeln!(f, "{line}").map_err(|e| format!("cannot write the audit log: {e}"))?;
        }
        *s = (seq, hash);
        Ok(())
    }

    /// Check a log file from the start. `Ok(entries)` if every line commits to the last.
    pub fn verify(path: &Path) -> Result<usize, String> {
        let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let mut prev = "genesis".to_owned();
        let mut n = 0;
        for line in text.lines() {
            let v: Value = serde_json::from_str(line).map_err(|_| "a line is not JSON")?;
            let field = |k: &str| v[k].as_str().unwrap_or_default().to_owned();
            let seq = v["seq"].as_i64().unwrap_or(-1);
            let want = Self::hash(
                &prev,
                seq,
                v["at"].as_i64().unwrap_or(0),
                &field("actor"),
                &field("action"),
                &field("target"),
            );
            if field("prev") != prev
                || field("hash") != want
                || seq != i64::try_from(n + 1).unwrap_or(-1)
            {
                return Err(format!("the audit log breaks at entry {}", n + 1));
            }
            prev = want;
            n += 1;
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_keep_little() {
        assert_eq!(mask(&json!("Alice Smith")), json!("A•••••••"));
        assert_eq!(mask(&json!("ab")), json!("•••"));
        assert_eq!(mask(&json!(42)), json!("•••"));
        assert_eq!(mask(&Value::Null), Value::Null);
        let mut page = json!({"data": [{"name": "Alice", "id": "1"}], "meta": {}});
        mask_rows(&mut page, &["name".into()]);
        assert_eq!(page["data"][0]["name"], "A••••");
        assert_eq!(page["data"][0]["id"], "1");
        let mut one = json!({"name": "Alice"});
        mask_rows(&mut one, &["name".into()]);
        assert_eq!(one["name"], "A••••");
    }

    #[test]
    fn the_audit_log_chains_and_notices_tampering() {
        let dir = std::env::temp_dir().join(format!(
            "falak-studio-audit-{}-{}",
            std::process::id(),
            now()
        ));
        let path = dir.join("audit.jsonl");
        let a = Audit::open(Some(path.clone())).unwrap();
        a.record("u1", "login", "-").unwrap();
        a.record("u1", "update", "notebook/notes/1").unwrap();
        assert_eq!(Audit::verify(&path).unwrap(), 2);
        // Reopening continues the chain.
        let b = Audit::open(Some(path.clone())).unwrap();
        b.record("u2", "reveal", "notebook/notes/1").unwrap();
        assert_eq!(Audit::verify(&path).unwrap(), 3);
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, text.replace("u1", "u9")).unwrap();
        assert!(Audit::verify(&path).is_err());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn config_wants_https_and_plain_app_names() {
        let ok = Config {
            office_url: "https://office.test".into(),
            apps: vec![AppEntry {
                name: "notebook".into(),
                url: "http://127.0.0.1:1".into(),
            }],
            cookie_secure: true,
        };
        assert!(ok.validate().is_ok());
        let mut bad = ok.clone();
        bad.apps[0].url = "http://app.test".into();
        assert!(bad.validate().is_err());
        let mut bad = ok;
        bad.apps[0].name = "../x".into();
        assert!(bad.validate().is_err());
    }
}
