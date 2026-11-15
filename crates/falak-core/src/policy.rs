//! Authorisation decisions (stage 1: ownership, roles, authentication).
//!
//! Policies are compiled into the IR as a list of rules. At request time
//! [`authorize`] turns the rules, the action and the verified principal into an
//! [`Access`] decision that the SQL builders in [`crate::sql`] apply. Default deny:
//! no rule, no principal, or no matching rule all give [`Access::Denied`].

use falak_contracts::{
    identity::Principal,
    ir::{IrAction, IrAllow, IrEntity},
};

/// What a principal may do with an entity for one action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Access {
    /// Nothing. No query is run.
    Denied,
    /// Every row (within the tenant, which is always applied separately).
    Unrestricted,
    /// Only rows whose owner field equals this subject. On create, the owner is set to it.
    OwnedBy(String),
}

impl Access {
    pub fn is_denied(&self) -> bool {
        matches!(self, Self::Denied)
    }
}

/// Decide access. Rules add: any satisfied rule that lists `action` grants access, and a
/// rule that needs no row condition beats one that restricts to the owner.
pub fn authorize(entity: &IrEntity, action: IrAction, principal: Option<&Principal>) -> Access {
    let Some(principal) = principal else {
        return Access::Denied;
    };
    let mut owner_rule = false;
    for rule in entity
        .policy
        .rules
        .iter()
        .filter(|r| r.actions.contains(&action))
    {
        match &rule.allow {
            IrAllow::Authenticated => return Access::Unrestricted,
            IrAllow::Role(role) if principal.roles.iter().any(|r| r == role) => {
                return Access::Unrestricted;
            }
            IrAllow::Role(_) => {}
            IrAllow::Owner => owner_rule = true,
        }
    }
    // An owner rule on an entity with no owner field cannot be satisfied. The loader
    // rejects that, but the IR may come from elsewhere, so fail closed.
    if owner_rule && entity.owner.is_some() {
        Access::OwnedBy(principal.subject.clone())
    } else {
        Access::Denied
    }
}
