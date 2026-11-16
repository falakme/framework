//! Executing ledger commands on PostgreSQL under `SERIALIZABLE`.
//!
//! One command is one transaction. A serialization failure (`40001`), a deadlock
//! (`40P01`) or a lost race on an idempotency key is retried, at most
//! [`LedgerConfig::max_attempts`] times, with jittered exponential backoff. When the
//! attempts run out the caller gets a retryable `Unavailable` error and nothing was
//! posted. The database's deferred constraints (see [`crate::schema`]) are the last
//! line of defence: a transaction that would overdraw an account or not balance cannot
//! commit whatever this code does.

use std::time::Duration;

use falak_contracts::{Error, ErrorKind, Result};
use sqlx::{PgPool, Row, postgres::PgPoolOptions};
use uuid::Uuid;

use crate::{
    command::{AccountInfo, Command, Facts, Plan, Posting, TxInfo},
    money::{Currency, account_id},
    reconcile::{Line, Report, reconcile},
    schema::schema_sql,
};

#[derive(Debug, Clone)]
pub struct LedgerConfig {
    /// Attempts per command, the first included.
    pub max_attempts: u32,
    pub base_backoff: Duration,
    pub max_backoff: Duration,
}

impl Default for LedgerConfig {
    fn default() -> Self {
        Self {
            max_attempts: 12,
            base_backoff: Duration::from_millis(4),
            max_backoff: Duration::from_millis(200),
        }
    }
}

/// The result of a posted command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Posted {
    pub tx_id: Uuid,
    /// True when the idempotency key had been used before and nothing new was posted.
    pub replayed: bool,
    /// Attempts used (1 when there was no conflict).
    pub attempts: u32,
}

/// The ledger-wide checks that must always hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invariants {
    pub negative_accounts: i64,
    pub unbalanced_transactions: i64,
    pub debits: i64,
    pub credits: i64,
}

impl Invariants {
    pub fn holds(&self) -> bool {
        self.negative_accounts == 0
            && self.unbalanced_transactions == 0
            && self.debits == self.credits
    }
}

#[derive(Clone)]
pub struct Ledger {
    pool: PgPool,
    config: LedgerConfig,
}

enum Fail {
    Retry,
    Fatal(Error),
}

fn db_err(e: sqlx::Error) -> Error {
    Error::internal(e)
}

fn classify(e: sqlx::Error) -> Fail {
    let Some(db) = e.as_database_error() else {
        return Fail::Fatal(
            Error::new(
                ErrorKind::Unavailable,
                "ledger_database_unavailable",
                "The ledger database is unavailable.",
            )
            .with_source(e),
        );
    };
    let code = db.code().map(|c| c.to_string()).unwrap_or_default();
    let message = db.message().to_owned();
    let constraint = db.constraint().unwrap_or_default().to_owned();
    match code.as_str() {
        "40001" | "40P01" => Fail::Retry,
        "23505" if constraint == "ledger_idempotency_pkey" => Fail::Retry,
        "23505" if constraint == "ledger_reversal_unique" => Fail::Fatal(Error::new(
            ErrorKind::Conflict,
            "ledger_already_reversed",
            "The transaction has already been reversed.",
        )),
        "23505" if constraint == "ledger_external_ref_unique" => Fail::Fatal(Error::new(
            ErrorKind::Conflict,
            "ledger_duplicate_reference",
            "A settlement with this external reference already exists.",
        )),
        "23505" if constraint == "ledger_accounts_pkey" => Fail::Fatal(Error::new(
            ErrorKind::Conflict,
            "ledger_hold_exists",
            "A hold with this id already exists.",
        )),
        "23514" if message.contains("ledger_insufficient_funds") => Fail::Fatal(Error::new(
            ErrorKind::Conflict,
            "ledger_insufficient_funds",
            "The account does not hold enough to cover this.",
        )),
        _ => Fail::Fatal(Error::internal(e)),
    }
}

fn jitter_millis(max: u64) -> u64 {
    let bytes = *Uuid::new_v4().as_bytes();
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]) % max.max(1)
}

impl Ledger {
    pub fn new(pool: PgPool) -> Self {
        Self::with_config(pool, LedgerConfig::default())
    }

    pub fn with_config(pool: PgPool, config: LedgerConfig) -> Self {
        Self { pool, config }
    }

    pub async fn connect(url: &str, max_connections: u32) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(Duration::from_secs(10))
            .connect(url)
            .await
            .map_err(|e| {
                Error::new(
                    ErrorKind::Unavailable,
                    "ledger_database_unavailable",
                    "The ledger database is unavailable.",
                )
                .with_source(e)
            })?;
        Ok(Self::new(pool))
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Create or update the schema. Run as the table owner, not as the application role.
    pub async fn install_schema(&self, app_role: Option<&str>) -> Result<()> {
        let sql = schema_sql(app_role)?;
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        sqlx::query("SELECT pg_advisory_xact_lock(8_100_001)")
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        sqlx::raw_sql(&sql)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        tx.commit().await.map_err(db_err)
    }

    /// Create an account. Repeating the call with the same settings succeeds; different
    /// settings for an existing account are a conflict.
    pub async fn create_account(
        &self,
        id: &str,
        currency: Currency,
        allow_negative: bool,
    ) -> Result<()> {
        account_id(id)?;
        sqlx::query(
            "INSERT INTO ledger_accounts (id, currency, allow_negative) VALUES ($1, $2, $3) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(id)
        .bind(currency.as_str())
        .bind(allow_negative)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        let row = sqlx::query(
            "SELECT currency, allow_negative, hold_of FROM ledger_accounts WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)?;
        let same = row.get::<String, _>(0) == currency.as_str()
            && row.get::<bool, _>(1) == allow_negative
            && row.get::<Option<String>, _>(2).is_none();
        if !same {
            return Err(Error::new(
                ErrorKind::Conflict,
                "ledger_account_exists",
                "The account exists with different settings.",
            ));
        }
        Ok(())
    }

    pub async fn balance(&self, id: &str) -> Result<i64> {
        sqlx::query_scalar(
            "SELECT COALESCE(SUM(amount), 0)::bigint FROM ledger_entries WHERE account_id = $1",
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)
    }

    /// Run a command exactly once per idempotency `key`.
    pub async fn execute(&self, key: &str, command: &Command) -> Result<Posted> {
        if key.is_empty() || key.len() > 200 {
            return Err(Error::invalid_input(
                "ledger_bad_key",
                "An idempotency key is 1 to 200 characters.",
            ));
        }
        command.validate()?;
        let hash = command.hash();
        let mut attempts = 0;
        loop {
            attempts += 1;
            match self.attempt(key, command, &hash).await {
                Ok(mut posted) => {
                    posted.attempts = attempts;
                    return Ok(posted);
                }
                Err(Fail::Fatal(e)) => return Err(e),
                Err(Fail::Retry) if attempts >= self.config.max_attempts => {
                    return Err(Error::new(
                        ErrorKind::Unavailable,
                        "ledger_busy",
                        "The ledger is busy. Nothing was posted; retry with the same key.",
                    ));
                }
                Err(Fail::Retry) => {
                    let cap = self.config.max_backoff.as_millis() as u64;
                    let ceiling = (self.config.base_backoff.as_millis() as u64)
                        .saturating_mul(1u64 << attempts.min(10))
                        .min(cap);
                    let wait = jitter_millis(ceiling);
                    tokio::time::sleep(Duration::from_millis(wait + 1)).await;
                }
            }
        }
    }

    async fn attempt(
        &self,
        key: &str,
        command: &Command,
        hash: &str,
    ) -> std::result::Result<Posted, Fail> {
        let mut tx = self.pool.begin().await.map_err(classify)?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            .execute(&mut *tx)
            .await
            .map_err(classify)?;

        if let Some(row) =
            sqlx::query("SELECT request_hash, tx_id FROM ledger_idempotency WHERE key = $1")
                .bind(key)
                .fetch_optional(&mut *tx)
                .await
                .map_err(classify)?
        {
            let stored: String = row.get(0);
            if stored != hash {
                return Err(Fail::Fatal(Error::new(
                    ErrorKind::Unprocessable,
                    "ledger_key_reused",
                    "This idempotency key was used for a different request.",
                )));
            }
            return Ok(Posted {
                tx_id: row.get(1),
                replayed: true,
                attempts: 1,
            });
        }

        let facts = load_facts(&mut tx, command).await?;
        let plan = command.plan(&facts).map_err(Fail::Fatal)?;
        let tx_id = Uuid::new_v4();
        write_plan(&mut tx, key, hash, tx_id, &plan).await?;
        tx.commit().await.map_err(classify)?;
        Ok(Posted {
            tx_id,
            replayed: false,
            attempts: 1,
        })
    }

    /// Every `settle` entry on `account`, one line per external reference.
    pub async fn ledger_lines(&self, account: &str) -> Result<Vec<Line>> {
        let rows = sqlx::query(
            "SELECT t.external_ref, e.currency, SUM(e.amount)::bigint \
             FROM ledger_entries e JOIN ledger_transactions t ON t.id = e.tx_id \
             WHERE e.account_id = $1 AND t.external_ref IS NOT NULL \
             GROUP BY t.external_ref, e.currency ORDER BY t.external_ref",
        )
        .bind(account)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        rows.iter()
            .map(|r| {
                Ok(Line {
                    external_ref: r.get(0),
                    currency: Currency::new(&r.get::<String, _>(1))?,
                    amount: r.get(2),
                })
            })
            .collect()
    }

    /// Store a statement for `account`. Statements are append-only: a new id each time.
    pub async fn import_statement(
        &self,
        statement_id: &str,
        account: &str,
        lines: &[Line],
    ) -> Result<()> {
        account_id(statement_id)?;
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        let inserted = sqlx::query(
            "INSERT INTO ledger_statements (id, account_id) VALUES ($1, $2) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(statement_id)
        .bind(account)
        .execute(&mut *tx)
        .await
        .map_err(|e| match e.as_database_error().and_then(|d| d.code()) {
            Some(c) if c == "23503" => Error::new(
                ErrorKind::NotFound,
                "ledger_unknown_account",
                "The account does not exist.",
            ),
            _ => db_err(e),
        })?;
        if inserted.rows_affected() == 0 {
            return Err(Error::new(
                ErrorKind::Conflict,
                "statement_exists",
                "A statement with this id was already imported.",
            ));
        }
        for (i, l) in lines.iter().enumerate() {
            sqlx::query(
                "INSERT INTO ledger_statement_lines \
                 (statement_id, line_no, external_ref, currency, amount) \
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(statement_id)
            .bind(i as i32 + 1)
            .bind(&l.external_ref)
            .bind(l.currency.as_str())
            .bind(l.amount)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        }
        tx.commit().await.map_err(db_err)
    }

    /// Compare a stored statement with the ledger's settlements on its account.
    pub async fn reconcile(&self, statement_id: &str) -> Result<Report> {
        let account: Option<String> =
            sqlx::query_scalar("SELECT account_id FROM ledger_statements WHERE id = $1")
                .bind(statement_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(db_err)?;
        let account = account.ok_or_else(Error::not_found)?;
        let rows = sqlx::query(
            "SELECT external_ref, currency, amount FROM ledger_statement_lines \
             WHERE statement_id = $1 ORDER BY line_no",
        )
        .bind(statement_id)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        let statement = rows
            .iter()
            .map(|r| {
                Ok(Line {
                    external_ref: r.get(0),
                    currency: Currency::new(&r.get::<String, _>(1))?,
                    amount: r.get(2),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(reconcile(&self.ledger_lines(&account).await?, &statement))
    }

    pub async fn invariants(&self) -> Result<Invariants> {
        let negative_accounts: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM (SELECT a.id FROM ledger_accounts a \
             LEFT JOIN ledger_entries e ON e.account_id = a.id \
             WHERE NOT a.allow_negative GROUP BY a.id \
             HAVING COALESCE(SUM(e.amount), 0) < 0) x",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)?;
        let unbalanced_transactions: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM (SELECT tx_id FROM ledger_entries \
             GROUP BY tx_id, currency HAVING SUM(amount) <> 0) x",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)?;
        let row = sqlx::query(
            "SELECT COALESCE(SUM(amount) FILTER (WHERE amount > 0), 0)::bigint, \
                    COALESCE(-SUM(amount) FILTER (WHERE amount < 0), 0)::bigint \
             FROM ledger_entries",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(Invariants {
            negative_accounts,
            unbalanced_transactions,
            debits: row.get(1),
            credits: row.get(0),
        })
    }
}

async fn load_facts(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    command: &Command,
) -> std::result::Result<Facts, Fail> {
    let needs = command.needs();
    let mut facts = Facts::default();
    for id in &needs.accounts {
        if facts.accounts.contains_key(id) {
            continue;
        }
        let Some(row) = sqlx::query("SELECT currency, hold_of FROM ledger_accounts WHERE id = $1")
            .bind(id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(classify)?
        else {
            continue;
        };
        let currency = Currency::new(&row.get::<String, _>(0)).map_err(Fail::Fatal)?;
        facts.accounts.insert(
            id.clone(),
            AccountInfo {
                currency,
                hold_of: row.get(1),
            },
        );
        let balance: i64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM(amount), 0)::bigint FROM ledger_entries WHERE account_id = $1",
        )
        .bind(id)
        .fetch_one(&mut **tx)
        .await
        .map_err(classify)?;
        facts.balances.insert(id.clone(), balance);
    }
    if let Some(id) = needs.tx
        && let Some(row) =
            sqlx::query("SELECT kind, currency FROM ledger_transactions WHERE id = $1")
                .bind(id)
                .fetch_optional(&mut **tx)
                .await
                .map_err(classify)?
    {
        let entries = sqlx::query(
            "SELECT account_id, amount FROM ledger_entries WHERE tx_id = $1 ORDER BY id",
        )
        .bind(id)
        .fetch_all(&mut **tx)
        .await
        .map_err(classify)?
        .iter()
        .map(|r| Posting {
            account: r.get(0),
            amount: r.get(1),
        })
        .collect();
        facts.txs.insert(
            id,
            TxInfo {
                kind: row.get(0),
                currency: Currency::new(&row.get::<String, _>(1)).map_err(Fail::Fatal)?,
                entries,
            },
        );
    }
    Ok(facts)
}

async fn write_plan(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    key: &str,
    hash: &str,
    tx_id: Uuid,
    plan: &Plan,
) -> std::result::Result<(), Fail> {
    // The idempotency row goes first, so two requests with one key collide on it (and
    // the loser retries and sees the winner) rather than on some later row.
    sqlx::query("INSERT INTO ledger_idempotency (key, request_hash, tx_id) VALUES ($1, $2, $3)")
        .bind(key)
        .bind(hash)
        .bind(tx_id)
        .execute(&mut **tx)
        .await
        .map_err(classify)?;
    for a in &plan.new_accounts {
        sqlx::query(
            "INSERT INTO ledger_accounts (id, currency, allow_negative, hold_of) \
             VALUES ($1, $2, false, $3)",
        )
        .bind(&a.id)
        .bind(a.currency.as_str())
        .bind(&a.hold_of)
        .execute(&mut **tx)
        .await
        .map_err(classify)?;
    }
    sqlx::query(
        "INSERT INTO ledger_transactions (id, kind, currency, external_ref, reverses) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(tx_id)
    .bind(plan.kind)
    .bind(plan.currency.as_str())
    .bind(&plan.external_ref)
    .bind(plan.reverses)
    .execute(&mut **tx)
    .await
    .map_err(classify)?;
    for p in &plan.postings {
        sqlx::query(
            "INSERT INTO ledger_entries (tx_id, account_id, currency, amount) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(tx_id)
        .bind(&p.account)
        .bind(plan.currency.as_str())
        .bind(p.amount)
        .execute(&mut **tx)
        .await
        .map_err(classify)?;
    }
    Ok(())
}
