//! The real D1 connection, through `workers-rs`. Built only for `wasm32`.
//!
//! One [`WorkerD1`] serves one request. It opens a D1 Sessions API session so that,
//! when read replication is on, reads follow the bookmark the client sent and the new
//! bookmark can go back in the response.

use falak_contracts::{Error, Result};
use worker::{D1Database, D1DatabaseSession, js_sys, wasm_bindgen::JsValue};

use crate::{
    SessionStart,
    convert::{OrderedRow, Param},
    driver::{BoundStatement, D1Binding, RawResult},
    error::map_d1_error,
};

/// A D1 session for one request.
#[derive(Debug)]
pub struct WorkerD1 {
    session: D1DatabaseSession,
}

impl WorkerD1 {
    /// Open a session on `db`.
    pub fn new(db: &D1Database, start: &SessionStart) -> Result<Self> {
        let session = db
            .with_session(Some(start.as_str()))
            .map_err(|e| map_d1_error(&e.to_string()))?;
        Ok(Self { session })
    }
}

fn to_js(param: &Param) -> JsValue {
    match param {
        Param::Null => JsValue::NULL,
        // Safe: `to_param` refuses integers outside the exact range of an f64.
        Param::Integer(n) => JsValue::from_f64(*n as f64),
        Param::Real(f) => JsValue::from_f64(*f),
        Param::Text(s) => JsValue::from_str(s),
        Param::Blob(b) => js_sys::Uint8Array::from(b.as_slice()).buffer().into(),
    }
}

impl D1Binding for WorkerD1 {
    async fn batch(&self, statements: Vec<BoundStatement>) -> Result<Vec<RawResult>> {
        let mut prepared = Vec::with_capacity(statements.len());
        for statement in statements {
            let args: Vec<JsValue> = statement.params.iter().map(to_js).collect();
            let stmt = self
                .session
                .prepare(statement.sql)
                .bind(&args)
                .map_err(|e| map_d1_error(&e.to_string()))?;
            prepared.push(stmt);
        }

        let results = self
            .session
            .batch(prepared)
            .await
            .map_err(|e| map_d1_error(&e.to_string()))?;

        results
            .into_iter()
            .map(|result| {
                if !result.success() {
                    let message = result.error().unwrap_or_default();
                    return Err(map_d1_error(&message));
                }
                let rows: Vec<OrderedRow> = result
                    .results()
                    .map_err(|e| Error::internal(e.to_string()))?;
                let changes = result
                    .meta()
                    .ok()
                    .flatten()
                    .and_then(|m| m.changes)
                    .unwrap_or(0);
                Ok(RawResult {
                    rows,
                    changes: changes as u64,
                })
            })
            .collect()
    }

    fn bookmark(&self) -> Option<String> {
        self.session.get_bookmark().ok().flatten()
    }
}
