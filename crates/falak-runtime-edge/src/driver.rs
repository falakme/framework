//! D1 behind the native runtime's driver trait.

use std::{future::Future, pin::Pin, sync::Arc};

use falak_contracts::{
    Result,
    capability::CapabilityProfile,
    driver::{Outcome, Rows, Statement, StorageDriver, TxOptions},
    identity::RequestContext,
};
use falak_driver_d1::{
    BoundStatement, D1Binding, D1Driver, NoTransaction, RawResult, SessionStart, WorkerD1,
};
use falak_runtime_native::NativeDriver;
use worker::{
    D1Database,
    send::{SendFuture, SendWrapper},
};

/// Opens a D1 session for each call. Read replication is off, so every session starts
/// on the primary and reads see earlier writes.
pub struct EdgeBinding {
    db: Arc<SendWrapper<D1Database>>,
}

impl D1Binding for EdgeBinding {
    async fn batch(&self, statements: Vec<BoundStatement>) -> Result<Vec<RawResult>> {
        let session = WorkerD1::new(&self.db, &SessionStart::FirstPrimary)?;
        session.batch(statements).await
    }

    fn bookmark(&self) -> Option<String> {
        None
    }
}

/// The D1 driver, made `Send` for the shared router.
#[derive(Clone)]
pub struct EdgeDriver {
    db: Arc<SendWrapper<D1Database>>,
}

impl EdgeDriver {
    pub fn new(db: D1Database) -> Self {
        Self {
            db: Arc::new(SendWrapper::new(db)),
        }
    }

    fn inner(&self) -> D1Driver<EdgeBinding> {
        D1Driver::new(EdgeBinding {
            db: self.db.clone(),
        })
    }
}

impl StorageDriver for EdgeDriver {
    type Tx = NoTransaction;

    fn profile(&self) -> &CapabilityProfile {
        &falak_contracts::capability::D1
    }

    async fn query(&self, ctx: &RequestContext, statement: Statement) -> Result<Rows> {
        StorageDriver::query(&self.inner(), ctx, statement).await
    }

    async fn batch(
        &self,
        ctx: &RequestContext,
        statements: Vec<Statement>,
    ) -> Result<Vec<Outcome>> {
        StorageDriver::batch(&self.inner(), ctx, statements).await
    }

    async fn begin(&self, ctx: &RequestContext, options: TxOptions) -> Result<Self::Tx> {
        StorageDriver::begin(&self.inner(), ctx, options).await
    }
}

impl NativeDriver for EdgeDriver {
    fn profile(&self) -> &CapabilityProfile {
        &falak_contracts::capability::D1
    }

    fn query<'a>(
        &'a self,
        ctx: &'a RequestContext,
        statement: Statement,
    ) -> Pin<Box<dyn Future<Output = Result<Rows>> + Send + 'a>> {
        Box::pin(SendFuture::new(StorageDriver::query(self, ctx, statement)))
    }

    fn batch<'a>(
        &'a self,
        ctx: &'a RequestContext,
        statements: Vec<Statement>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Outcome>>> + Send + 'a>> {
        Box::pin(SendFuture::new(StorageDriver::batch(self, ctx, statements)))
    }
}
