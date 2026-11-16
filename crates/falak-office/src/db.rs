//! Office's tables, over any native driver (PostgreSQL in production, SQLite in tests).

use std::sync::Arc;

use falak_contracts::{
    Result,
    driver::{Outcome, Statement, Value},
    identity::RequestContext,
};
use falak_runtime_native::NativeDriver;

pub struct Db {
    driver: Arc<dyn NativeDriver>,
    postgres: bool,
}

fn ctx() -> RequestContext {
    RequestContext {
        principal: None,
        request_id: "office".into(),
    }
}

const SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS office_apps (name TEXT NOT NULL PRIMARY KEY, tier BIGINT NOT NULL, public_key TEXT NOT NULL, kid TEXT NOT NULL, capabilities TEXT NOT NULL, passport_jti TEXT NOT NULL, status TEXT NOT NULL, created_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS office_enrollments (token_hash TEXT NOT NULL PRIMARY KEY, app TEXT NOT NULL, tier BIGINT NOT NULL, capabilities TEXT NOT NULL, expires_at BIGINT NOT NULL, used_by TEXT)",
    "CREATE TABLE IF NOT EXISTS office_memberships (user_id TEXT NOT NULL, app TEXT NOT NULL, tenant TEXT, roles TEXT NOT NULL, PRIMARY KEY (user_id, app))",
    "CREATE TABLE IF NOT EXISTS office_revocations (version BIGINT NOT NULL PRIMARY KEY, kind TEXT NOT NULL, id TEXT NOT NULL, at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS office_nonces (app TEXT NOT NULL, nonce TEXT NOT NULL, seen_at BIGINT NOT NULL, PRIMARY KEY (app, nonce))",
    "CREATE TABLE IF NOT EXISTS office_identities (issuer TEXT NOT NULL, subject TEXT NOT NULL, user_id TEXT NOT NULL, linked_at BIGINT NOT NULL, PRIMARY KEY (issuer, subject))",
    "CREATE TABLE IF NOT EXISTS office_stats (day BIGINT NOT NULL, kind TEXT NOT NULL, app TEXT NOT NULL, n BIGINT NOT NULL, PRIMARY KEY (day, kind, app))",
    "CREATE TABLE IF NOT EXISTS office_audit (seq BIGINT NOT NULL PRIMARY KEY, at BIGINT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL)",
];

impl Db {
    pub fn new(driver: Arc<dyn NativeDriver>) -> Self {
        let postgres = driver.profile().name == "postgres";
        Self { driver, postgres }
    }

    pub async fn migrate(&self) -> Result<()> {
        let stmts = SCHEMA
            .iter()
            .chain(crate::compute::SCHEMA)
            .map(|s| Statement::new(*s, vec![]))
            .collect();
        self.driver.batch(&ctx(), stmts).await.map(|_| ())
    }

    /// Turn each `?` in `template` into the driver's numbered placeholder.
    pub fn q(&self, template: &str) -> String {
        let mut out = String::with_capacity(template.len() + 8);
        let mut n = 0;
        for c in template.chars() {
            if c == '?' {
                n += 1;
                if self.postgres {
                    out.push_str(&format!("${n}"));
                } else {
                    out.push_str(&format!("?{n}"));
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    pub fn stmt(&self, template: &str, params: Vec<Value>) -> Statement {
        Statement::new(self.q(template), params)
    }

    /// Run one statement; the number of rows it changed.
    pub async fn run(&self, template: &str, params: Vec<Value>) -> Result<u64> {
        let out = self
            .driver
            .batch(&ctx(), vec![self.stmt(template, params)])
            .await?;
        Ok(out.first().map_or(0, |o| o.rows_affected))
    }

    pub async fn batch(&self, stmts: Vec<Statement>) -> Result<Vec<Outcome>> {
        self.driver.batch(&ctx(), stmts).await
    }

    pub async fn rows(&self, template: &str, params: Vec<Value>) -> Result<Vec<Vec<Value>>> {
        Ok(self
            .driver
            .query(&ctx(), self.stmt(template, params))
            .await?
            .rows)
    }
}

pub fn text(v: Option<&Value>) -> String {
    match v {
        Some(Value::Text(s)) => s.clone(),
        _ => String::new(),
    }
}

pub fn int(v: Option<&Value>) -> i64 {
    match v {
        Some(Value::Int64(n)) | Some(Value::TimestampMicros(n)) => *n,
        _ => 0,
    }
}

pub fn t(s: &str) -> Value {
    Value::Text(s.to_owned())
}
