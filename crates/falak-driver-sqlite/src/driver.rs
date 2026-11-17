//! SQLite storage driver implementation.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use falak_contracts::{
    Result,
    capability::{CapabilityProfile, SQLITE},
    driver::{Isolation, Outcome, Rows, Statement, StorageDriver, Transaction, TxOptions},
    identity::RequestContext,
};
use sqlx::{
    Executor, SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use tokio::sync::{Mutex, OwnedMutexGuard};

use crate::{
    convert::{bind_statement, rows_from_sqlite},
    error::map_sqlx_error,
};

static DB_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Configuration for SQLite storage driver.
#[derive(Debug, Clone)]
pub struct SqliteConfig {
    pub url: String,
    pub busy_timeout: Duration,
    pub reader_pool_size: u32,
}

impl Default for SqliteConfig {
    fn default() -> Self {
        Self {
            url: "sqlite::memory:".to_string(),
            busy_timeout: Duration::from_millis(5000),
            reader_pool_size: 8,
        }
    }
}

/// Owns the temporary database file behind an "in-memory" driver and removes it, with its
/// WAL and shared-memory files, when the last clone of the driver is dropped.
struct TempDbFile(std::path::PathBuf);

impl TempDbFile {
    fn sidecars(path: &std::path::Path) -> [std::path::PathBuf; 3] {
        let with = |suffix: &str| {
            let mut name = path.as_os_str().to_owned();
            name.push(suffix);
            std::path::PathBuf::from(name)
        };
        [path.to_path_buf(), with("-wal"), with("-shm")]
    }

    fn remove_files(path: &std::path::Path) {
        for f in Self::sidecars(path) {
            let _ = std::fs::remove_file(f);
        }
    }
}

impl Drop for TempDbFile {
    fn drop(&mut self) {
        Self::remove_files(&self.0);
    }
}

/// A SQLite storage driver providing WAL mode, single dedicated writer,
/// and concurrent reader pool.
#[derive(Clone)]
pub struct SqliteDriver {
    writer_pool: SqlitePool,
    reader_pool: SqlitePool,
    writer_lock: Arc<Mutex<()>>,
    // Declared last so the pools are dropped before the files are removed.
    _temp_file: Option<Arc<TempDbFile>>,
}

impl SqliteDriver {
    /// Open a new SQLite driver using the given configuration.
    pub async fn open(config: SqliteConfig) -> Result<Self> {
        let is_memory = config.url.contains(":memory:") || config.url.contains("mode=memory");

        // If in-memory is requested, assign a distinct temporary file on disk with WAL
        // mode so writers and readers enjoy real WAL snapshot isolation without schema locks.
        let mut temp_file = None;
        let effective_url = if is_memory {
            let id = DB_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("falak_mem_{}_{}.db", std::process::id(), id));
            // Process ids are reused and these files used to be left behind, so a file
            // from an earlier run (possibly with an older `_falak_migrations` layout)
            // can already sit at this path. An in-memory database must start empty.
            TempDbFile::remove_files(&path);
            let url = format!("sqlite://{}", path.display());
            temp_file = Some(Arc::new(TempDbFile(path)));
            url
        } else {
            config.url.clone()
        };

        let base_options: SqliteConnectOptions = effective_url
            .parse::<SqliteConnectOptions>()
            .map_err(map_sqlx_error)?
            .create_if_missing(true)
            .busy_timeout(config.busy_timeout)
            .foreign_keys(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .synchronous(sqlx::sqlite::SqliteSynchronous::Normal);

        let writer_pool = SqlitePoolOptions::new()
            .max_connections(1)
            .min_connections(1)
            .acquire_timeout(config.busy_timeout)
            .connect_with(base_options.clone())
            .await
            .map_err(map_sqlx_error)?;

        // Ensure WAL and pragmas are initialized on the database
        writer_pool
            .execute("PRAGMA journal_mode = WAL;")
            .await
            .map_err(map_sqlx_error)?;
        writer_pool
            .execute("PRAGMA synchronous = NORMAL;")
            .await
            .map_err(map_sqlx_error)?;
        writer_pool
            .execute("PRAGMA foreign_keys = ON;")
            .await
            .map_err(map_sqlx_error)?;

        // Reader options: query_only = ON
        let reader_pool = SqlitePoolOptions::new()
            .max_connections(config.reader_pool_size.max(1))
            .min_connections(1)
            .acquire_timeout(config.busy_timeout)
            .after_connect(|conn, _| {
                Box::pin(async move {
                    conn.execute("PRAGMA query_only = ON;").await?;
                    conn.execute("PRAGMA foreign_keys = ON;").await?;
                    Ok(())
                })
            })
            .connect_with(base_options)
            .await
            .map_err(map_sqlx_error)?;

        Ok(Self {
            writer_pool,
            reader_pool,
            writer_lock: Arc::new(Mutex::new(())),
            _temp_file: temp_file,
        })
    }

    /// Open an in-memory (isolated tempfile with WAL) database for testing and spikes.
    pub async fn in_memory() -> Result<Self> {
        Self::open(SqliteConfig::default()).await
    }

    /// Direct access to writer pool for DDL migrations.
    pub fn writer_pool(&self) -> &SqlitePool {
        &self.writer_pool
    }

    /// Direct access to reader pool.
    pub fn reader_pool(&self) -> &SqlitePool {
        &self.reader_pool
    }
}

pub struct SqliteTx {
    conn: sqlx::pool::PoolConnection<sqlx::Sqlite>,
    _guard: OwnedMutexGuard<()>,
    active: bool,
}

impl Transaction for SqliteTx {
    async fn query(&mut self, statement: Statement) -> Result<Rows> {
        let args = bind_statement(&statement);
        let rows = sqlx::query_with(&statement.sql, args)
            .fetch_all(&mut *self.conn)
            .await
            .map_err(map_sqlx_error)?;
        rows_from_sqlite(rows)
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
            let converted_rows = rows_from_sqlite(rows)?;
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

// SQLx rolls back only transactions it started itself; this one was opened with a plain
// `BEGIN`. A transaction dropped without commit or rollback would go back to the pool
// still open and every later write would fail inside it, so its connection is closed.
impl Drop for SqliteTx {
    fn drop(&mut self) {
        if self.active {
            self.conn.close_on_drop();
        }
    }
}

impl StorageDriver for SqliteDriver {
    type Tx = SqliteTx;

    fn profile(&self) -> &CapabilityProfile {
        &SQLITE
    }

    async fn query(&self, _ctx: &RequestContext, statement: Statement) -> Result<Rows> {
        let args = bind_statement(&statement);
        let rows = sqlx::query_with(&statement.sql, args)
            .fetch_all(&self.reader_pool)
            .await
            .map_err(map_sqlx_error)?;
        rows_from_sqlite(rows)
    }

    async fn batch(
        &self,
        _ctx: &RequestContext,
        statements: Vec<Statement>,
    ) -> Result<Vec<Outcome>> {
        let guard = self.writer_lock.clone().lock_owned().await;
        let mut conn = self.writer_pool.acquire().await.map_err(map_sqlx_error)?;

        conn.execute("BEGIN IMMEDIATE;")
            .await
            .map_err(map_sqlx_error)?;

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
                        // A row that cannot be converted must not leave the writer's
                        // transaction open: the next batch would run inside it.
                        let converted = match rows_from_sqlite(rows) {
                            Ok(c) => c,
                            Err(e) => {
                                let _ = conn.execute("ROLLBACK;").await;
                                return Err(e);
                            }
                        };
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
        drop(guard);

        Ok(outcomes)
    }

    async fn begin(&self, _ctx: &RequestContext, options: TxOptions) -> Result<Self::Tx> {
        let guard = self.writer_lock.clone().lock_owned().await;
        let mut conn = self.writer_pool.acquire().await.map_err(map_sqlx_error)?;

        let begin_sql = match options.isolation {
            Isolation::Serializable | Isolation::Default => "BEGIN IMMEDIATE;",
        };

        conn.execute(begin_sql).await.map_err(map_sqlx_error)?;

        Ok(SqliteTx {
            conn,
            _guard: guard,
            active: true,
        })
    }
}
