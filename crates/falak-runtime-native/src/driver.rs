//! Native storage driver trait with `Send` futures for Axum / Tokio.

use std::{future::Future, pin::Pin, sync::Arc};

#[cfg(any(feature = "sqlite", feature = "postgres"))]
use falak_contracts::driver::StorageDriver;
use falak_contracts::{
    Result,
    capability::CapabilityProfile,
    driver::{Outcome, Rows, Statement},
    identity::RequestContext,
};
#[cfg(feature = "postgres")]
use falak_driver_postgres::PostgresDriver;
#[cfg(feature = "sqlite")]
use falak_driver_sqlite::SqliteDriver;

/// Trait for storage drivers in the native runtime, ensuring returned futures
/// implement `Send` for multi-threaded Tokio / Axum compatibility.
pub trait NativeDriver: Send + Sync + 'static {
    fn profile(&self) -> &CapabilityProfile;

    fn query<'a>(
        &'a self,
        ctx: &'a RequestContext,
        statement: Statement,
    ) -> Pin<Box<dyn Future<Output = Result<Rows>> + Send + 'a>>;

    fn batch<'a>(
        &'a self,
        ctx: &'a RequestContext,
        statements: Vec<Statement>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Outcome>>> + Send + 'a>>;
}

#[cfg(feature = "sqlite")]
impl NativeDriver for SqliteDriver {
    fn profile(&self) -> &CapabilityProfile {
        <Self as StorageDriver>::profile(self)
    }

    fn query<'a>(
        &'a self,
        ctx: &'a RequestContext,
        statement: Statement,
    ) -> Pin<Box<dyn Future<Output = Result<Rows>> + Send + 'a>> {
        Box::pin(<Self as StorageDriver>::query(self, ctx, statement))
    }

    fn batch<'a>(
        &'a self,
        ctx: &'a RequestContext,
        statements: Vec<Statement>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Outcome>>> + Send + 'a>> {
        Box::pin(<Self as StorageDriver>::batch(self, ctx, statements))
    }
}

#[cfg(feature = "postgres")]
impl NativeDriver for PostgresDriver {
    fn profile(&self) -> &CapabilityProfile {
        <Self as StorageDriver>::profile(self)
    }

    fn query<'a>(
        &'a self,
        ctx: &'a RequestContext,
        statement: Statement,
    ) -> Pin<Box<dyn Future<Output = Result<Rows>> + Send + 'a>> {
        Box::pin(<Self as StorageDriver>::query(self, ctx, statement))
    }

    fn batch<'a>(
        &'a self,
        ctx: &'a RequestContext,
        statements: Vec<Statement>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Outcome>>> + Send + 'a>> {
        Box::pin(<Self as StorageDriver>::batch(self, ctx, statements))
    }
}

impl<D: NativeDriver> NativeDriver for Arc<D> {
    fn profile(&self) -> &CapabilityProfile {
        (**self).profile()
    }

    fn query<'a>(
        &'a self,
        ctx: &'a RequestContext,
        statement: Statement,
    ) -> Pin<Box<dyn Future<Output = Result<Rows>> + Send + 'a>> {
        (**self).query(ctx, statement)
    }

    fn batch<'a>(
        &'a self,
        ctx: &'a RequestContext,
        statements: Vec<Statement>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Outcome>>> + Send + 'a>> {
        (**self).batch(ctx, statements)
    }
}

impl NativeDriver for Arc<dyn NativeDriver> {
    fn profile(&self) -> &CapabilityProfile {
        (**self).profile()
    }

    fn query<'a>(
        &'a self,
        ctx: &'a RequestContext,
        statement: Statement,
    ) -> Pin<Box<dyn Future<Output = Result<Rows>> + Send + 'a>> {
        (**self).query(ctx, statement)
    }

    fn batch<'a>(
        &'a self,
        ctx: &'a RequestContext,
        statements: Vec<Statement>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Outcome>>> + Send + 'a>> {
        (**self).batch(ctx, statements)
    }
}
