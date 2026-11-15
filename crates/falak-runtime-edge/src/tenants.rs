//! `database` tenancy on D1: one D1 database per tenant (T3.9).
//!
//! Workers reach a D1 database only through a binding, and bindings are fixed when the
//! Worker is deployed. So tenants are provisioned with `falak tenant add`, which makes
//! the database, adds its binding to the deploy and publishes again. The Worker reads
//! the map of tenant to binding from `FALAK_TENANTS`. A tenant that is not in the map
//! is refused; it is never created from a request.

use std::{
    collections::{HashMap, HashSet},
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};

use falak_contracts::{Error, Result, identity::RequestContext, ir::Ir};
use falak_migrate::{MigrateOptions, migrate};
use falak_runtime_native::{NativeDriver, tenants::TenantStore};
use worker::{Env, send::SendFuture};

use crate::driver::EdgeDriver;

pub struct EdgeTenants {
    drivers: HashMap<String, Arc<EdgeDriver>>,
    ir: Arc<Ir>,
    options: MigrateOptions,
    /// Tenants whose database this isolate has brought to the current version.
    ready: Mutex<HashSet<String>>,
}

impl EdgeTenants {
    /// `map` is the JSON object in `FALAK_TENANTS`: tenant id to binding name.
    pub fn from_env(
        env: &Env,
        map: &str,
        ir: Arc<Ir>,
        options: MigrateOptions,
    ) -> std::result::Result<Self, String> {
        let parsed: HashMap<String, String> =
            serde_json::from_str(map).map_err(|e| format!("FALAK_TENANTS is not valid: {e}"))?;
        let mut drivers = HashMap::new();
        for (tenant, binding) in parsed {
            if !falak_runtime_native::tenants::valid_tenant(&tenant) {
                return Err(format!(
                    "FALAK_TENANTS names `{tenant}`, which is not a tenant id"
                ));
            }
            let db = env
                .d1(&binding)
                .map_err(|e| format!("no D1 binding `{binding}` for tenant `{tenant}`: {e}"))?;
            drivers.insert(tenant, Arc::new(EdgeDriver::new(db)));
        }
        Ok(Self {
            drivers,
            ir,
            options,
            ready: Mutex::new(HashSet::new()),
        })
    }
}

impl TenantStore for EdgeTenants {
    fn driver_for<'a>(
        &'a self,
        tenant: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Arc<dyn NativeDriver>>> + Send + 'a>> {
        Box::pin(SendFuture::new(async move {
            let Some(driver) = self.drivers.get(tenant) else {
                return Err(Error::forbidden());
            };
            let known = self
                .ready
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .contains(tenant);
            if !known {
                let ctx = RequestContext {
                    principal: None,
                    request_id: "tenant-migrate".into(),
                };
                migrate(driver.as_ref(), &ctx, &self.ir, self.options).await?;
                self.ready
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .insert(tenant.to_owned());
            }
            Ok(driver.clone() as Arc<dyn NativeDriver>)
        }))
    }
}
