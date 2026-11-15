//! Storage driver contract.
//!
//! Drivers execute **parameterized statements only**. SQL text comes from templates
//! compiled into the IR; callers never build SQL from user input.
//!
//! Every call carries a [`RequestContext`] so the driver can apply isolation: on
//! PostgreSQL by setting the session context for row-level security inside the
//! transaction, on other drivers by whatever the compiled statements require.

use serde::{Deserialize, Serialize};

use crate::{Result, capability::CapabilityProfile, identity::RequestContext};

/// A storage value. `decimal_minor` is stored as `Int64`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Value {
    Null,
    Bool(bool),
    Int64(i64),
    Float64(f64),
    Text(String),
    Bytes(Vec<u8>),
    Uuid([u8; 16]),
    /// Microseconds since the Unix epoch, UTC.
    TimestampMicros(i64),
}

/// A parameterized statement. Placeholders are positional.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Statement {
    pub sql: String,
    pub params: Vec<Value>,
}

impl Statement {
    pub fn new(sql: impl Into<String>, params: Vec<Value>) -> Self {
        Self {
            sql: sql.into(),
            params,
        }
    }
}

/// Query result.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Rows {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Value>>,
}

/// Result of one statement in a batch or transaction.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Outcome {
    pub rows_affected: u64,
    pub rows: Rows,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Isolation {
    #[default]
    Default,
    Serializable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TxOptions {
    pub isolation: Isolation,
    pub read_only: bool,
}

/// An open interactive transaction. Dropping it without commit rolls back.
pub trait Transaction {
    async fn query(&mut self, statement: Statement) -> Result<Rows>;
    async fn execute(&mut self, statement: Statement) -> Result<Outcome>;
    async fn commit(self) -> Result<()>;
    async fn rollback(self) -> Result<()>;
}

/// A storage backend.
pub trait StorageDriver {
    type Tx: Transaction;

    fn profile(&self) -> &CapabilityProfile;

    /// Run one read statement outside an explicit transaction.
    async fn query(&self, ctx: &RequestContext, statement: Statement) -> Result<Rows>;

    /// Run statements atomically: all take effect or none do. Available on every driver.
    async fn batch(&self, ctx: &RequestContext, statements: Vec<Statement>)
    -> Result<Vec<Outcome>>;

    /// Start an interactive transaction. Fails with `Unsupported` unless the profile
    /// provides `interactive_transactions`.
    async fn begin(&self, ctx: &RequestContext, options: TxOptions) -> Result<Self::Tx>;
}
