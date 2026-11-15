//! PostgreSQL storage driver implementation.

use std::time::Duration;

use falak_contracts::{
    Result,
    capability::{CapabilityProfile, POSTGRES},
    driver::{Isolation, Outcome, Rows, Statement, StorageDriver, Transaction, TxOptions},
    identity::RequestContext,
};
use sqlx::{
    Executor, PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};

use crate::{
    convert::{bind_statement, rows_from_postgres},
    error::map_sqlx_error,
};

/// Configuration for PostgreSQL storage driver.
#[derive(Debug, Clone)]
pub struct PostgresConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub acquire_timeout: Duration,
    pub idle_timeout: Option<Duration>,
    pub max_lifetime: Option<Duration>,
}

impl Default for PostgresConfig {
    fn default() -> Self {
        let url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/falak".to_string());
        Self {
            url,
            max_connections: 20,
            min_connections: 1,
            acquire_timeout: Duration::from_secs(5),
            idle_timeout: Some(Duration::from_secs(600)),
            max_lifetime: Some(Duration::from_secs(1800)),
        }
    }
}

/// A PostgreSQL storage driver providing connection pooling,
/// transactional request isolation, and RLS session context injection.
#[derive(Clone)]
pub struct PostgresDriver {
    pool: PgPool,
}

impl PostgresDriver {
    /// Open a new PostgreSQL driver using the given configuration.
    pub async fn open(config: PostgresConfig) -> Result<Self> {
        let options: PgConnectOptions = config.url.parse().map_err(map_sqlx_error)?;

        let mut pool_builder = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .min_connections(config.min_connections)
            .acquire_timeout(config.acquire_timeout);

        if let Some(idle) = config.idle_timeout {
            pool_builder = pool_builder.idle_timeout(idle);
        }
        if let Some(lifetime) = config.max_lifetime {
            pool_builder = pool_builder.max_lifetime(lifetime);
        }

        let pool = pool_builder
            .connect_with(options)
            .await
            .map_err(map_sqlx_error)?;

        Ok(Self { pool })
    }

    /// Construct a driver wrapping an existing SQLx `PgPool`.
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Direct access to underlying connection pool.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

async fn set_session_context(
    conn: &mut sqlx::pool::PoolConnection<sqlx::Postgres>,
    ctx: &RequestContext,
) -> Result<()> {
    let tenant = ctx
        .principal
        .as_ref()
        .and_then(|p| p.tenant.as_deref())
        .unwrap_or("");
    let subject = ctx
        .principal
        .as_ref()
        .map(|p| p.subject.as_str())
        .unwrap_or("");

    sqlx::query(
        "SELECT set_config('falak.tenant_id', $1, true), set_config('falak.subject', $2, true);",
    )
    .bind(tenant)
    .bind(subject)
    .execute(&mut **conn)
    .await
    .map_err(map_sqlx_error)?;

    Ok(())
}

pub struct PostgresTx {
    conn: sqlx::pool::PoolConnection<sqlx::Postgres>,
    active: bool,
}

impl Transaction for PostgresTx {
    async fn query(&mut self, statement: Statement) -> Result<Rows> {
        let args = bind_statement(&statement);
        let rows = sqlx::query_with(&statement.sql, args)
            .fetch_all(&mut *self.conn)
            .await
            .map_err(map_sqlx_error)?;
        rows_from_postgres(rows)
    }

    async fn execute(&mut self, statement: Statement) -> Result<Outcome> {
        let sql_lower = statement.sql.trim().to_lowercase();
        let args = bind_statement(&statement);

        if sql_lower.starts_with("select") || sql_lower.contains("returning") {
            let rows = sqlx::query_with(&statement.sql, args)
                .fetch_all(&mut *self.conn)
                .await
                .map_err(map_sqlx_error)?;
            let rows_affected = rows.len() as u64;
            let converted_rows = rows_from_postgres(rows)?;
            Ok(Outcome {
                rows_affected,
                rows: converted_rows,
            })
        } else {
            let result = sqlx::query_with(&statement.sql, args)
                .execute(&mut *self.conn)
                .await
                .map_err(map_sqlx_error)?;
            Ok(Outcome {
                rows_affected: result.rows_affected(),
                rows: Rows::default(),
            })
        }
    }

    async fn commit(mut self) -> Result<()> {
        self.active = false;
        self.conn.execute("COMMIT;").await.map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn rollback(mut self) -> Result<()> {
        self.active = false;
        self.conn
            .execute("ROLLBACK;")
            .await
            .map_err(map_sqlx_error)?;
        Ok(())
    }
}

impl StorageDriver for PostgresDriver {
    type Tx = PostgresTx;

    fn profile(&self) -> &CapabilityProfile {
        &POSTGRES
    }

    async fn query(&self, ctx: &RequestContext, statement: Statement) -> Result<Rows> {
        let mut conn = self.pool.acquire().await.map_err(map_sqlx_error)?;
        conn.execute("BEGIN;").await.map_err(map_sqlx_error)?;
        if let Err(e) = set_session_context(&mut conn, ctx).await {
            let _ = conn.execute("ROLLBACK;").await;
            return Err(e);
        }

        let args = bind_statement(&statement);
        let rows = match sqlx::query_with(&statement.sql, args)
            .fetch_all(&mut *conn)
            .await
        {
            Ok(rows) => rows,
            Err(e) => {
                let _ = conn.execute("ROLLBACK;").await;
                return Err(map_sqlx_error(e));
            }
        };

        conn.execute("COMMIT;").await.map_err(map_sqlx_error)?;
        rows_from_postgres(rows)
    }

    async fn batch(
        &self,
        ctx: &RequestContext,
        statements: Vec<Statement>,
    ) -> Result<Vec<Outcome>> {
        let mut conn = self.pool.acquire().await.map_err(map_sqlx_error)?;
        conn.execute("BEGIN;").await.map_err(map_sqlx_error)?;
        if let Err(e) = set_session_context(&mut conn, ctx).await {
            let _ = conn.execute("ROLLBACK;").await;
            return Err(e);
        }

        let mut outcomes = Vec::with_capacity(statements.len());
        for stmt in statements {
            let sql_lower = stmt.sql.trim().to_lowercase();
            let args = bind_statement(&stmt);

            let outcome = if sql_lower.starts_with("select") || sql_lower.contains("returning") {
                let rows_res = sqlx::query_with(&stmt.sql, args)
                    .fetch_all(&mut *conn)
                    .await;
                match rows_res {
                    Ok(rows) => {
                        let rows_affected = rows.len() as u64;
                        let converted = rows_from_postgres(rows)?;
                        Outcome {
                            rows_affected,
                            rows: converted,
                        }
                    }
                    Err(e) => {
                        let _ = conn.execute("ROLLBACK;").await;
                        return Err(map_sqlx_error(e));
                    }
                }
            } else {
                let exec_res = sqlx::query_with(&stmt.sql, args).execute(&mut *conn).await;
                match exec_res {
                    Ok(res) => Outcome {
                        rows_affected: res.rows_affected(),
                        rows: Rows::default(),
                    },
                    Err(e) => {
                        let _ = conn.execute("ROLLBACK;").await;
                        return Err(map_sqlx_error(e));
                    }
                }
            };
            outcomes.push(outcome);
        }

        conn.execute("COMMIT;").await.map_err(map_sqlx_error)?;
        Ok(outcomes)
    }

    async fn begin(&self, ctx: &RequestContext, options: TxOptions) -> Result<Self::Tx> {
        let mut conn = self.pool.acquire().await.map_err(map_sqlx_error)?;

        let begin_sql = match options.isolation {
            Isolation::Serializable => "BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE;",
            Isolation::Default => "BEGIN;",
        };

        conn.execute(begin_sql).await.map_err(map_sqlx_error)?;

        if options.read_only {
            conn.execute("SET TRANSACTION READ ONLY;")
                .await
                .map_err(map_sqlx_error)?;
        }

        if let Err(e) = set_session_context(&mut conn, ctx).await {
            let _ = conn.execute("ROLLBACK;").await;
            return Err(e);
        }

        Ok(PostgresTx { conn, active: true })
    }
}
