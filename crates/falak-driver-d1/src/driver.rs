//! The D1 [`StorageDriver`].
//!
//! D1 runs in auto-commit and has no interactive transactions. The only atomic unit is
//! a batch, so [`StorageDriver::batch`] is the write path and
//! [`StorageDriver::begin`] always fails with `Unsupported`. Read-then-write commands
//! reach D1 as one conditional batch (T2.2).
//!
//! The driver does not apply row isolation itself. D1 has no row-level security, so
//! isolation comes from the policy predicates compiled into the statements (T1.4,
//! T3.1). The `RequestContext` is accepted to satisfy the contract and is not used to
//! build SQL.

use falak_contracts::{
    Error, Result,
    capability::{self, CapabilityProfile},
    driver::{Outcome, Rows, Statement, StorageDriver, Transaction, TxOptions},
    identity::RequestContext,
};

use crate::{
    convert::{OrderedRow, Param, rows_from_ordered, to_param},
    validate::check_statement,
};

/// A statement with its parameters converted for D1.
#[derive(Debug, Clone, PartialEq)]
pub struct BoundStatement {
    pub sql: String,
    pub params: Vec<Param>,
}

/// What D1 returned for one statement.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RawResult {
    pub rows: Vec<OrderedRow>,
    /// Rows changed by the statement (`meta.changes`).
    pub changes: u64,
}

/// The connection to D1. The real implementation, `WorkerD1`, exists only on `wasm32`.
/// Tests supply a fake.
pub trait D1Binding {
    /// Run the statements as one atomic batch and return one result per statement, in
    /// order. A failure in any statement rolls back all of them. Errors are already
    /// mapped to Falak errors.
    async fn batch(&self, statements: Vec<BoundStatement>) -> Result<Vec<RawResult>>;

    /// The newest D1 session bookmark, if any query has run. Pass it to the next
    /// request so reads see this request's writes even from a read replica.
    fn bookmark(&self) -> Option<String>;
}

/// Storage driver for Cloudflare D1.
#[derive(Debug)]
pub struct D1Driver<B> {
    binding: B,
}

impl<B: D1Binding> D1Driver<B> {
    pub fn new(binding: B) -> Self {
        Self { binding }
    }

    /// The newest session bookmark, to return to the client (for example in a response
    /// header) so its next request can continue from the same point.
    ///
    /// A bookmark only controls how fresh a read is. It grants no access.
    pub fn bookmark(&self) -> Option<String> {
        self.binding.bookmark()
    }

    fn prepare(statement: &Statement) -> Result<BoundStatement> {
        check_statement(statement, &capability::D1.limits)?;
        let params = statement
            .params
            .iter()
            .map(to_param)
            .collect::<Result<Vec<_>>>()?;
        Ok(BoundStatement {
            sql: statement.sql.clone(),
            params,
        })
    }
}

impl<B: D1Binding> StorageDriver for D1Driver<B> {
    type Tx = NoTransaction;

    fn profile(&self) -> &CapabilityProfile {
        &capability::D1
    }

    async fn query(&self, _ctx: &RequestContext, statement: Statement) -> Result<Rows> {
        let bound = Self::prepare(&statement)?;
        let mut results = self.binding.batch(vec![bound]).await?;
        match results.pop() {
            Some(result) if results.is_empty() => Ok(rows_from_ordered(result.rows)),
            _ => Err(Error::internal(
                "D1 returned an unexpected number of results",
            )),
        }
    }

    async fn batch(
        &self,
        _ctx: &RequestContext,
        statements: Vec<Statement>,
    ) -> Result<Vec<Outcome>> {
        if statements.is_empty() {
            return Ok(Vec::new());
        }
        let bound = statements
            .iter()
            .map(Self::prepare)
            .collect::<Result<Vec<_>>>()?;
        let expected = bound.len();
        let results = self.binding.batch(bound).await?;
        if results.len() != expected {
            return Err(Error::internal(
                "D1 returned an unexpected number of results",
            ));
        }
        Ok(results
            .into_iter()
            .map(|r| Outcome {
                rows_affected: r.changes,
                rows: rows_from_ordered(r.rows),
            })
            .collect())
    }

    async fn begin(&self, _ctx: &RequestContext, _options: TxOptions) -> Result<Self::Tx> {
        Err(Error::unsupported(
            "interactive_transactions_unsupported",
            "This storage layer does not support interactive transactions.",
        ))
    }
}

/// The transaction type of a driver that has none. It cannot be constructed.
#[derive(Debug)]
pub struct NoTransaction(());

impl Transaction for NoTransaction {
    async fn query(&mut self, _statement: Statement) -> Result<Rows> {
        unreachable_tx()
    }
    async fn execute(&mut self, _statement: Statement) -> Result<Outcome> {
        unreachable_tx()
    }
    async fn commit(self) -> Result<()> {
        unreachable_tx()
    }
    async fn rollback(self) -> Result<()> {
        unreachable_tx()
    }
}

fn unreachable_tx<T>() -> Result<T> {
    Err(Error::unsupported(
        "interactive_transactions_unsupported",
        "This storage layer does not support interactive transactions.",
    ))
}

#[cfg(test)]
mod tests {
    use std::{
        cell::RefCell,
        future::Future,
        pin::pin,
        task::{Context, Poll, Waker},
    };

    use falak_contracts::{ErrorKind, driver::Value};

    use super::*;
    use crate::convert::Cell;

    /// Run a future that never waits on anything outside itself.
    fn block_on<F: Future>(fut: F) -> F::Output {
        let mut fut = pin!(fut);
        let mut cx = Context::from_waker(Waker::noop());
        loop {
            if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }

    #[derive(Default)]
    struct Fake {
        seen: RefCell<Vec<Vec<BoundStatement>>>,
        reply: RefCell<Vec<Result<Vec<RawResult>>>>,
    }

    impl D1Binding for Fake {
        async fn batch(&self, statements: Vec<BoundStatement>) -> Result<Vec<RawResult>> {
            self.seen.borrow_mut().push(statements);
            self.reply.borrow_mut().remove(0)
        }
        fn bookmark(&self) -> Option<String> {
            Some("bm-1".into())
        }
    }

    fn ctx() -> RequestContext {
        RequestContext {
            principal: None,
            request_id: "r1".into(),
        }
    }

    fn driver(reply: Vec<Result<Vec<RawResult>>>) -> D1Driver<Fake> {
        D1Driver::new(Fake {
            reply: RefCell::new(reply),
            ..Fake::default()
        })
    }

    fn row(cells: Vec<(&str, Cell)>) -> OrderedRow {
        OrderedRow(cells.into_iter().map(|(n, c)| (n.to_owned(), c)).collect())
    }

    #[test]
    fn query_returns_positional_rows_and_converts_params() {
        let d = driver(vec![Ok(vec![RawResult {
            rows: vec![row(vec![
                ("id", Cell::Number(1.0)),
                ("title", Cell::Text("a".into())),
            ])],
            changes: 0,
        }])]);
        let rows = block_on(d.query(
            &ctx(),
            Statement::new(
                "SELECT id, title FROM notes WHERE ok = ?",
                vec![Value::Bool(true)],
            ),
        ))
        .unwrap();
        assert_eq!(rows.columns, ["id", "title"]);
        assert_eq!(rows.rows[0], [Value::Int64(1), Value::Text("a".into())]);
        let seen = d.binding.seen.borrow();
        assert_eq!(seen[0][0].params, [Param::Integer(1)]);
    }

    #[test]
    fn batch_sends_all_statements_in_one_call_and_reports_changes() {
        let d = driver(vec![Ok(vec![
            RawResult {
                rows: vec![],
                changes: 1,
            },
            RawResult {
                rows: vec![],
                changes: 3,
            },
        ])]);
        let out = block_on(d.batch(
            &ctx(),
            vec![
                Statement::new("UPDATE a SET x = ?", vec![Value::Int64(1)]),
                Statement::new("DELETE FROM b", vec![]),
            ],
        ))
        .unwrap();
        assert_eq!(
            out.iter().map(|o| o.rows_affected).collect::<Vec<_>>(),
            [1, 3]
        );
        let seen = d.binding.seen.borrow();
        assert_eq!(seen.len(), 1, "one call to D1 for the whole batch");
        assert_eq!(seen[0].len(), 2);
    }

    #[test]
    fn empty_batch_never_calls_d1() {
        let d = driver(vec![]);
        assert!(block_on(d.batch(&ctx(), vec![])).unwrap().is_empty());
        assert!(d.binding.seen.borrow().is_empty());
    }

    #[test]
    fn oversized_statement_is_rejected_before_d1_is_called() {
        let d = driver(vec![]);
        let e = block_on(d.batch(
            &ctx(),
            vec![Statement::new("SELECT 1", vec![Value::Null; 101])],
        ))
        .unwrap_err();
        assert_eq!(e.code(), "storage_param_limit");
        assert!(d.binding.seen.borrow().is_empty());
    }

    #[test]
    fn one_bad_statement_rejects_the_whole_batch_before_sending() {
        let d = driver(vec![]);
        let e = block_on(d.batch(
            &ctx(),
            vec![
                Statement::new("INSERT INTO t VALUES (?)", vec![Value::Int64(1)]),
                Statement::new("INSERT INTO t VALUES (?)", vec![Value::Int64(i64::MAX)]),
            ],
        ))
        .unwrap_err();
        assert_eq!(e.code(), "storage_integer_range");
        assert!(d.binding.seen.borrow().is_empty());
    }

    #[test]
    fn begin_is_unsupported() {
        let d = driver(vec![]);
        let e = block_on(d.begin(&ctx(), TxOptions::default()))
            .err()
            .unwrap();
        assert_eq!(e.kind(), ErrorKind::Unsupported);
    }

    #[test]
    fn binding_errors_pass_through() {
        let d = driver(vec![Err(Error::new(
            ErrorKind::Conflict,
            "unique_violation",
            "x",
        ))]);
        let e = block_on(d.batch(
            &ctx(),
            vec![Statement::new("INSERT INTO t VALUES (1)", vec![])],
        ))
        .unwrap_err();
        assert_eq!(e.code(), "unique_violation");
    }

    #[test]
    fn profile_is_the_d1_profile() {
        let d = driver(vec![]);
        assert_eq!(d.profile().name, "d1");
        assert!(
            !d.profile()
                .provides(capability::Capability::InteractiveTransactions)
        );
        assert_eq!(d.bookmark().as_deref(), Some("bm-1"));
    }
}
