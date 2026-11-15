//! Where users, sessions, reset tokens and failed attempts are kept.
//!
//! [`AuthStore`] is the seam. [`MemoryStore`] is for tests and tools. [`SqlStore`] keeps
//! the data in the app's own database through a `StorageDriver`, so one database file
//! (SQLite or D1) or server (PostgreSQL) holds everything.
//!
//! Secrets are never stored: passwords as Argon2id hashes, session and reset tokens as
//! SHA-256 hashes of random 256-bit values. A leaked table cannot be replayed.

use std::{collections::HashMap, sync::Mutex};

use falak_contracts::{
    Error, ErrorKind, Result,
    driver::{Statement, StorageDriver, Value},
    identity::RequestContext,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRecord {
    pub id: String,
    pub email: String,
    pub password_hash: String,
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    pub id: String,
    pub user_id: String,
    /// SHA-256 of the refresh token, hex.
    pub token_hash: String,
    pub expires_at: i64,
    /// `None` while the session is usable.
    pub revoked: Option<Revoked>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Revoked {
    /// Replaced by a new token on refresh. Presenting it again means it was stolen.
    Rotated,
    /// Ended by logout, reset or an administrator.
    Ended,
}

impl Revoked {
    fn code(self) -> &'static str {
        match self {
            Self::Rotated => "rotated",
            Self::Ended => "ended",
        }
    }
    fn from_code(s: &str) -> Option<Self> {
        match s {
            "rotated" => Some(Self::Rotated),
            "ended" => Some(Self::Ended),
            _ => None,
        }
    }
}

pub trait AuthStore {
    /// Fails with `Conflict` (`email_taken`) if the email exists.
    async fn create_user(&self, user: UserRecord, now: i64) -> Result<()>;
    async fn user_by_email(&self, email: &str) -> Result<Option<UserRecord>>;
    async fn user_by_id(&self, id: &str) -> Result<Option<UserRecord>>;
    async fn set_password_hash(&self, user_id: &str, hash: &str) -> Result<()>;
    async fn set_roles(&self, user_id: &str, roles: &[String]) -> Result<()>;

    async fn record_failure(&self, key: &str, at: i64) -> Result<()>;
    /// Failures recorded for `key` at or after `since`.
    async fn failures_since(&self, key: &str, since: i64) -> Result<u32>;
    async fn clear_failures(&self, key: &str) -> Result<()>;

    async fn create_session(&self, session: SessionRecord) -> Result<()>;
    async fn session_by_hash(&self, token_hash: &str) -> Result<Option<SessionRecord>>;
    async fn revoke_session(&self, id: &str, how: Revoked) -> Result<()>;
    async fn revoke_all_sessions(&self, user_id: &str) -> Result<()>;

    async fn create_reset(&self, token_hash: &str, user_id: &str, expires_at: i64) -> Result<()>;
    /// Mark the token used and return its user, only if it is unused and unexpired.
    /// Two calls with the same token never both succeed.
    async fn consume_reset(&self, token_hash: &str, now: i64) -> Result<Option<String>>;
}

// ---------------------------------------------------------------- memory

#[derive(Default)]
struct Memory {
    users: Vec<UserRecord>,
    sessions: Vec<SessionRecord>,
    failures: HashMap<String, Vec<i64>>,
    resets: HashMap<String, (String, i64, bool)>,
}

#[derive(Default)]
pub struct MemoryStore(Mutex<Memory>);

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
    fn lock(&self) -> std::sync::MutexGuard<'_, Memory> {
        self.0.lock().unwrap_or_else(|p| p.into_inner())
    }
}

impl AuthStore for MemoryStore {
    async fn create_user(&self, user: UserRecord, _now: i64) -> Result<()> {
        let mut m = self.lock();
        if m.users.iter().any(|u| u.email == user.email) {
            return Err(email_taken());
        }
        m.users.push(user);
        Ok(())
    }
    async fn user_by_email(&self, email: &str) -> Result<Option<UserRecord>> {
        Ok(self.lock().users.iter().find(|u| u.email == email).cloned())
    }
    async fn user_by_id(&self, id: &str) -> Result<Option<UserRecord>> {
        Ok(self.lock().users.iter().find(|u| u.id == id).cloned())
    }
    async fn set_password_hash(&self, user_id: &str, hash: &str) -> Result<()> {
        if let Some(u) = self.lock().users.iter_mut().find(|u| u.id == user_id) {
            u.password_hash = hash.to_owned();
        }
        Ok(())
    }
    async fn set_roles(&self, user_id: &str, roles: &[String]) -> Result<()> {
        if let Some(u) = self.lock().users.iter_mut().find(|u| u.id == user_id) {
            u.roles = roles.to_vec();
        }
        Ok(())
    }
    async fn record_failure(&self, key: &str, at: i64) -> Result<()> {
        self.lock()
            .failures
            .entry(key.to_owned())
            .or_default()
            .push(at);
        Ok(())
    }
    async fn failures_since(&self, key: &str, since: i64) -> Result<u32> {
        let n = self
            .lock()
            .failures
            .get(key)
            .map_or(0, |v| v.iter().filter(|t| **t >= since).count());
        Ok(u32::try_from(n).unwrap_or(u32::MAX))
    }
    async fn clear_failures(&self, key: &str) -> Result<()> {
        self.lock().failures.remove(key);
        Ok(())
    }
    async fn create_session(&self, session: SessionRecord) -> Result<()> {
        self.lock().sessions.push(session);
        Ok(())
    }
    async fn session_by_hash(&self, token_hash: &str) -> Result<Option<SessionRecord>> {
        Ok(self
            .lock()
            .sessions
            .iter()
            .find(|s| s.token_hash == token_hash)
            .cloned())
    }
    async fn revoke_session(&self, id: &str, how: Revoked) -> Result<()> {
        if let Some(s) = self.lock().sessions.iter_mut().find(|s| s.id == id)
            && s.revoked.is_none()
        {
            s.revoked = Some(how);
        }
        Ok(())
    }
    async fn revoke_all_sessions(&self, user_id: &str) -> Result<()> {
        for s in self
            .lock()
            .sessions
            .iter_mut()
            .filter(|s| s.user_id == user_id)
        {
            if s.revoked.is_none() {
                s.revoked = Some(Revoked::Ended);
            }
        }
        Ok(())
    }
    async fn create_reset(&self, token_hash: &str, user_id: &str, expires_at: i64) -> Result<()> {
        self.lock().resets.insert(
            token_hash.to_owned(),
            (user_id.to_owned(), expires_at, false),
        );
        Ok(())
    }
    async fn consume_reset(&self, token_hash: &str, now: i64) -> Result<Option<String>> {
        let mut m = self.lock();
        match m.resets.get_mut(token_hash) {
            Some((user, expires, used)) if !*used && *expires > now => {
                *used = true;
                Ok(Some(user.clone()))
            }
            _ => Ok(None),
        }
    }
}

fn email_taken() -> Error {
    Error::new(
        ErrorKind::Conflict,
        "email_taken",
        "An account with this email already exists.",
    )
}

// ---------------------------------------------------------------- SQL

/// How the database spells a parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placeholders {
    /// `?` (SQLite and D1).
    Question,
    /// `$1`, `$2`, ... (PostgreSQL).
    Numbered,
}

/// Table definitions. Plain SQL that SQLite, D1 and PostgreSQL all accept.
pub const SCHEMA: [&str; 4] = [
    "CREATE TABLE IF NOT EXISTS falak_auth_users (\
        id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, \
        roles TEXT NOT NULL, created_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS falak_auth_sessions (\
        id TEXT PRIMARY KEY, user_id TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, \
        expires_at BIGINT NOT NULL, revoked TEXT)",
    "CREATE TABLE IF NOT EXISTS falak_auth_resets (\
        token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires_at BIGINT NOT NULL, \
        used INTEGER NOT NULL DEFAULT 0)",
    "CREATE TABLE IF NOT EXISTS falak_auth_failures (\
        attempt_key TEXT NOT NULL, attempted_at BIGINT NOT NULL)",
];

/// Identity data kept through a storage driver.
pub struct SqlStore<D> {
    driver: D,
    style: Placeholders,
}

fn ctx() -> RequestContext {
    RequestContext {
        principal: None,
        request_id: "falak-auth".into(),
    }
}

fn text(v: &Value) -> Option<String> {
    match v {
        Value::Text(s) => Some(s.clone()),
        _ => None,
    }
}

fn int(v: &Value) -> Option<i64> {
    match v {
        Value::Int64(n) => Some(*n),
        _ => None,
    }
}

fn corrupt() -> Error {
    Error::internal("identity row has an unexpected shape")
}

impl<D: StorageDriver> SqlStore<D> {
    pub fn new(driver: D, style: Placeholders) -> Self {
        Self { driver, style }
    }

    /// Create the tables if they are missing.
    pub async fn migrate(&self) -> Result<()> {
        let statements = SCHEMA.iter().map(|s| Statement::new(*s, vec![])).collect();
        self.driver.batch(&ctx(), statements).await?;
        // Index for the lockout lookup.
        self.run(
            "CREATE INDEX IF NOT EXISTS falak_auth_failures_key ON falak_auth_failures (attempt_key, attempted_at)",
            vec![],
        )
        .await?;
        Ok(())
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

    async fn run(&self, sql: &str, params: Vec<Value>) -> Result<u64> {
        let out = self
            .driver
            .batch(&ctx(), vec![Statement::new(self.render(sql), params)])
            .await?;
        Ok(out.first().map_or(0, |o| o.rows_affected))
    }

    async fn select(&self, sql: &str, params: Vec<Value>) -> Result<Vec<Vec<Value>>> {
        Ok(self
            .driver
            .query(&ctx(), Statement::new(self.render(sql), params))
            .await?
            .rows)
    }

    fn user_from(row: &[Value]) -> Result<UserRecord> {
        let get = |i: usize| row.get(i).and_then(text).ok_or_else(corrupt);
        Ok(UserRecord {
            id: get(0)?,
            email: get(1)?,
            password_hash: get(2)?,
            roles: split_roles(&get(3)?),
        })
    }
}

fn split_roles(s: &str) -> Vec<String> {
    s.split(',')
        .filter(|r| !r.is_empty())
        .map(str::to_owned)
        .collect()
}

fn join_roles(roles: &[String]) -> String {
    roles.join(",")
}

const USER_COLUMNS: &str = "id, email, password_hash, roles";

impl<D: StorageDriver> AuthStore for SqlStore<D> {
    async fn create_user(&self, user: UserRecord, now: i64) -> Result<()> {
        let result = self
            .run(
                "INSERT INTO falak_auth_users (id, email, password_hash, roles, created_at) VALUES (?, ?, ?, ?, ?)",
                vec![
                    Value::Text(user.id),
                    Value::Text(user.email),
                    Value::Text(user.password_hash),
                    Value::Text(join_roles(&user.roles)),
                    Value::Int64(now),
                ],
            )
            .await;
        match result {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == ErrorKind::Conflict => Err(email_taken()),
            Err(e) => Err(e),
        }
    }

    async fn user_by_email(&self, email: &str) -> Result<Option<UserRecord>> {
        let rows = self
            .select(
                &format!("SELECT {USER_COLUMNS} FROM falak_auth_users WHERE email = ?"),
                vec![Value::Text(email.into())],
            )
            .await?;
        rows.first().map(|r| Self::user_from(r)).transpose()
    }

    async fn user_by_id(&self, id: &str) -> Result<Option<UserRecord>> {
        let rows = self
            .select(
                &format!("SELECT {USER_COLUMNS} FROM falak_auth_users WHERE id = ?"),
                vec![Value::Text(id.into())],
            )
            .await?;
        rows.first().map(|r| Self::user_from(r)).transpose()
    }

    async fn set_password_hash(&self, user_id: &str, hash: &str) -> Result<()> {
        self.run(
            "UPDATE falak_auth_users SET password_hash = ? WHERE id = ?",
            vec![Value::Text(hash.into()), Value::Text(user_id.into())],
        )
        .await
        .map(|_| ())
    }

    async fn set_roles(&self, user_id: &str, roles: &[String]) -> Result<()> {
        self.run(
            "UPDATE falak_auth_users SET roles = ? WHERE id = ?",
            vec![Value::Text(join_roles(roles)), Value::Text(user_id.into())],
        )
        .await
        .map(|_| ())
    }

    async fn record_failure(&self, key: &str, at: i64) -> Result<()> {
        self.run(
            "INSERT INTO falak_auth_failures (attempt_key, attempted_at) VALUES (?, ?)",
            vec![Value::Text(key.into()), Value::Int64(at)],
        )
        .await
        .map(|_| ())
    }

    async fn failures_since(&self, key: &str, since: i64) -> Result<u32> {
        let rows = self
            .select(
                "SELECT COUNT(*) FROM falak_auth_failures WHERE attempt_key = ? AND attempted_at >= ?",
                vec![Value::Text(key.into()), Value::Int64(since)],
            )
            .await?;
        let n = rows
            .first()
            .and_then(|r| r.first())
            .and_then(int)
            .ok_or_else(corrupt)?;
        Ok(u32::try_from(n).unwrap_or(u32::MAX))
    }

    async fn clear_failures(&self, key: &str) -> Result<()> {
        self.run(
            "DELETE FROM falak_auth_failures WHERE attempt_key = ?",
            vec![Value::Text(key.into())],
        )
        .await
        .map(|_| ())
    }

    async fn create_session(&self, s: SessionRecord) -> Result<()> {
        self.run(
            "INSERT INTO falak_auth_sessions (id, user_id, token_hash, expires_at, revoked) VALUES (?, ?, ?, ?, ?)",
            vec![
                Value::Text(s.id),
                Value::Text(s.user_id),
                Value::Text(s.token_hash),
                Value::Int64(s.expires_at),
                s.revoked
                    .map_or(Value::Null, |r| Value::Text(r.code().into())),
            ],
        )
        .await
        .map(|_| ())
    }

    async fn session_by_hash(&self, token_hash: &str) -> Result<Option<SessionRecord>> {
        let rows = self
            .select(
                "SELECT id, user_id, token_hash, expires_at, revoked FROM falak_auth_sessions WHERE token_hash = ?",
                vec![Value::Text(token_hash.into())],
            )
            .await?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let get = |i: usize| row.get(i).and_then(text).ok_or_else(corrupt);
        Ok(Some(SessionRecord {
            id: get(0)?,
            user_id: get(1)?,
            token_hash: get(2)?,
            expires_at: row.get(3).and_then(int).ok_or_else(corrupt)?,
            revoked: row
                .get(4)
                .and_then(text)
                .and_then(|c| Revoked::from_code(&c)),
        }))
    }

    async fn revoke_session(&self, id: &str, how: Revoked) -> Result<()> {
        self.run(
            "UPDATE falak_auth_sessions SET revoked = ? WHERE id = ? AND revoked IS NULL",
            vec![Value::Text(how.code().into()), Value::Text(id.into())],
        )
        .await
        .map(|_| ())
    }

    async fn revoke_all_sessions(&self, user_id: &str) -> Result<()> {
        self.run(
            "UPDATE falak_auth_sessions SET revoked = 'ended' WHERE user_id = ? AND revoked IS NULL",
            vec![Value::Text(user_id.into())],
        )
        .await
        .map(|_| ())
    }

    async fn create_reset(&self, token_hash: &str, user_id: &str, expires_at: i64) -> Result<()> {
        self.run(
            "INSERT INTO falak_auth_resets (token_hash, user_id, expires_at, used) VALUES (?, ?, ?, 0)",
            vec![
                Value::Text(token_hash.into()),
                Value::Text(user_id.into()),
                Value::Int64(expires_at),
            ],
        )
        .await
        .map(|_| ())
    }

    async fn consume_reset(&self, token_hash: &str, now: i64) -> Result<Option<String>> {
        // One statement decides who wins: only one caller can flip `used` from 0 to 1.
        let changed = self
            .run(
                "UPDATE falak_auth_resets SET used = 1 WHERE token_hash = ? AND used = 0 AND expires_at > ?",
                vec![Value::Text(token_hash.into()), Value::Int64(now)],
            )
            .await?;
        if changed != 1 {
            return Ok(None);
        }
        let rows = self
            .select(
                "SELECT user_id FROM falak_auth_resets WHERE token_hash = ?",
                vec![Value::Text(token_hash.into())],
            )
            .await?;
        Ok(rows.first().and_then(|r| r.first()).and_then(text))
    }
}
