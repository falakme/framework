//! `database` tenancy: one database per tenant (ADR-0003, T3.9).
//!
//! The strongest isolation on SQLite and D1: a request reaches its tenant's database and
//! no other, so there is no `WHERE tenant_id` to forget. The tenant comes only from the
//! verified token ([`RequestContext`]); a [`TenantRouter`] looks up (or provisions) that
//! tenant's database and runs the statement there. A request with no tenant reaches only
//! the control database, which holds identity and migration history, never app data.

#[cfg(feature = "sqlite")]
use std::{collections::HashMap, sync::Mutex};
use std::{future::Future, pin::Pin, sync::Arc};

#[cfg(feature = "sqlite")]
use falak_contracts::ir::Ir;
use falak_contracts::{
    Error, Result,
    capability::CapabilityProfile,
    driver::{Outcome, Rows, Statement},
    identity::RequestContext,
};

use crate::driver::NativeDriver;

type Boxed<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// Finds the database of one tenant, creating it the first time the tenant is seen.
pub trait TenantStore: Send + Sync + 'static {
    fn driver_for<'a>(&'a self, tenant: &'a str) -> Boxed<'a, Arc<dyn NativeDriver>>;
}

/// A tenant id is a UUID, spelled in lower case with hyphens. Anything else is refused
/// before it can become part of a file name or a binding name.
pub fn valid_tenant(tenant: &str) -> bool {
    let b = tenant.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_digit() || (b'a'..=b'f').contains(c),
        })
}

/// Sends each statement to the database of the request's tenant.
pub struct TenantRouter {
    control: Arc<dyn NativeDriver>,
    tenants: Arc<dyn TenantStore>,
}

impl TenantRouter {
    pub fn new(control: Arc<dyn NativeDriver>, tenants: Arc<dyn TenantStore>) -> Self {
        Self { control, tenants }
    }

    async fn route(&self, ctx: &RequestContext) -> Result<Arc<dyn NativeDriver>> {
        let tenant = ctx
            .principal
            .as_ref()
            .and_then(|p| p.tenant.as_deref())
            .filter(|t| !t.is_empty());
        match tenant {
            // No tenant: the control database. It has no app tables.
            None => Ok(self.control.clone()),
            Some(t) if valid_tenant(t) => self.tenants.driver_for(t).await,
            Some(_) => Err(Error::forbidden()),
        }
    }
}

impl NativeDriver for TenantRouter {
    fn profile(&self) -> &CapabilityProfile {
        self.control.profile()
    }

    fn query<'a>(&'a self, ctx: &'a RequestContext, statement: Statement) -> Boxed<'a, Rows> {
        Box::pin(async move { self.route(ctx).await?.query(ctx, statement).await })
    }

    fn batch<'a>(
        &'a self,
        ctx: &'a RequestContext,
        statements: Vec<Statement>,
    ) -> Boxed<'a, Vec<Outcome>> {
        Box::pin(async move { self.route(ctx).await?.batch(ctx, statements).await })
    }
}

/// One SQLite file per tenant, in a directory. Opened on first use, migrated to the
/// current version of the app, and kept open.
#[cfg(feature = "sqlite")]
pub struct SqliteTenants {
    dir: std::path::PathBuf,
    ir: Arc<Ir>,
    open: Mutex<HashMap<String, Arc<falak_driver_sqlite::SqliteDriver>>>,
    /// Serialises first use, so two requests do not both create the same file.
    opening: tokio::sync::Mutex<()>,
}

#[cfg(feature = "sqlite")]
impl SqliteTenants {
    pub fn new(dir: std::path::PathBuf, ir: Arc<Ir>) -> Self {
        Self {
            dir,
            ir,
            open: Mutex::new(HashMap::new()),
            opening: tokio::sync::Mutex::new(()),
        }
    }

    /// Change the app the tenants' databases follow. Databases already open are
    /// migrated again on their next use.
    pub fn set_ir(&mut self, ir: Arc<Ir>) {
        self.ir = ir;
        self.open.lock().unwrap_or_else(|p| p.into_inner()).clear();
    }
}

#[cfg(feature = "sqlite")]
impl TenantStore for SqliteTenants {
    fn driver_for<'a>(&'a self, tenant: &'a str) -> Boxed<'a, Arc<dyn NativeDriver>> {
        Box::pin(async move {
            if let Some(d) = self
                .open
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(tenant)
            {
                return Ok(d.clone() as Arc<dyn NativeDriver>);
            }
            let _guard = self.opening.lock().await;
            if let Some(d) = self
                .open
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(tenant)
            {
                return Ok(d.clone() as Arc<dyn NativeDriver>);
            }
            std::fs::create_dir_all(&self.dir)
                .map_err(|e| Error::internal(format!("cannot create the tenant directory: {e}")))?;
            let path = self.dir.join(format!("{tenant}.db"));
            let driver =
                falak_driver_sqlite::SqliteDriver::open(falak_driver_sqlite::SqliteConfig {
                    url: format!("sqlite://{}", path.display()),
                    ..falak_driver_sqlite::SqliteConfig::default()
                })
                .await?;
            let ctx = RequestContext {
                principal: None,
                request_id: "tenant-provision".into(),
            };
            falak_migrate::migrate(
                &driver,
                &ctx,
                &self.ir,
                falak_migrate::MigrateOptions::default(),
            )
            .await?;
            let driver = Arc::new(driver);
            self.open
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert(tenant.to_owned(), driver.clone());
            Ok(driver as Arc<dyn NativeDriver>)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_lower_case_uuids_are_tenants() {
        assert!(valid_tenant("00000000-0000-0000-0000-0000000000aa"));
        for bad in [
            "",
            "../../etc/passwd",
            "00000000-0000-0000-0000-0000000000AA",
            "00000000000000000000000000000000",
            "00000000-0000-0000-0000-0000000000aa.db",
            "00000000-0000-0000-0000-0000000000a/",
        ] {
            assert!(!valid_tenant(bad), "{bad}");
        }
    }
}
