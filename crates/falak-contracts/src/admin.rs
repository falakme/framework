//! Admin surface integration (Studio). Studio reaches data only through the app's API,
//! never directly; this trait lets an app describe what it exposes.

use crate::{Result, identity::Principal};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminEntity {
    pub name: String,
    pub label: String,
}

pub trait AdminProvider {
    /// Entities the principal may see in Studio, from the `admin:` metadata and policy.
    async fn entities(&self, principal: &Principal) -> Result<Vec<AdminEntity>>;
}
