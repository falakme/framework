//! Infers what an app needs from its drivers and checks it against each target's
//! capability profile (SCHEMA_SPECIFICATION §10), so an unsupported combination fails at
//! build time instead of at runtime.

use falak_contracts::{
    capability::{
        Capability, CapabilityProfile, D1, Limits, POSTGRES, Requirements, SQLITE, Unmet,
    },
    identity::TrustTier,
    ir::Ir,
};

use crate::{
    diagnostics::{Diagnostic, Position},
    schema::{CommandKind, DriverKind, Project},
};

/// A needed capability and why it is needed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Need {
    pub capability: Capability,
    pub reason: String,
}

pub fn profile(driver: DriverKind) -> &'static CapabilityProfile {
    match driver {
        DriverKind::Sqlite => &SQLITE,
        DriverKind::Postgres => &POSTGRES,
        DriverKind::D1 => &D1,
    }
}

/// Capabilities the app needs, each with its reason.
pub fn infer_needs(project: &Project) -> Vec<Need> {
    let mut needs: Vec<Need> = Vec::new();
    let mut add = |capability: Capability, reason: String| {
        if !needs.iter().any(|n| n.capability == capability) {
            needs.push(Need { capability, reason });
        }
    };
    let writes = project
        .commands
        .iter()
        .any(|c| c.kind != CommandKind::Custom)
        || project.policies.iter().any(|p| {
            p.rules.iter().any(|r| {
                r.actions
                    .iter()
                    .any(|a| !matches!(a, crate::schema::Action::Read))
            })
        });
    if writes {
        add(Capability::AtomicBatch, "the app writes data".into());
    }
    if let Some(c) = project
        .commands
        .iter()
        .find(|c| c.kind == CommandKind::Custom)
    {
        add(
            Capability::InteractiveTransactions,
            format!(
                "custom command `{}` runs a handler inside a transaction",
                c.name
            ),
        );
    }
    if project.app.trust_tier == TrustTier::HighAssurance {
        add(
            Capability::SerializableIsolation,
            "`trust_tier: high_assurance` needs serializable isolation".into(),
        );
    }
    for c in &project.app.requires {
        add(*c, "listed under `requires` in app.yaml".into());
    }
    needs
}

/// Numeric needs derived from the compiled app.
fn limit_needs(ir: &Ir, dialect: crate::sql::Dialect) -> Limits {
    let widest = ir
        .entities
        .iter()
        .map(|e| e.fields.len())
        .max()
        .unwrap_or(0);
    let ddl_bytes = crate::ddl::create_all(ir, dialect)
        .iter()
        .map(String::len)
        .max()
        .unwrap_or(0);
    Limits {
        // An insert binds every column.
        max_bound_params: u32::try_from(widest).ok(),
        max_statement_bytes: u32::try_from(ddl_bytes).ok(),
        ..Limits::default()
    }
}

/// Check the app against every driver it targets. One error per unmet requirement per driver.
pub fn check_drivers(project: &Project, ir: &Ir) -> Vec<Diagnostic> {
    let needs = infer_needs(project);
    let mut out = Vec::new();
    for driver in &project.app.drivers {
        let dialect = match driver {
            DriverKind::Sqlite => crate::sql::Dialect::Sqlite,
            DriverKind::Postgres => crate::sql::Dialect::Postgres,
            DriverKind::D1 => crate::sql::Dialect::D1,
        };
        let req = Requirements {
            capabilities: needs.iter().map(|n| n.capability).collect(),
            needs: limit_needs(ir, dialect),
        };
        let Err(unmet) = profile(*driver).check(&req) else {
            continue;
        };
        for u in unmet {
            let (message, help) = match &u {
                Unmet::Capability(c) => {
                    let why = needs
                        .iter()
                        .find(|n| n.capability == *c)
                        .map_or(String::new(), |n| format!(" ({})", n.reason));
                    (
                        format!("`{}` does not provide `{}`{why}", driver.name(), c.name()),
                        format!(
                            "remove `{}` from `drivers` in app.yaml, or change the app so it does not need `{}`",
                            driver.name(),
                            c.name()
                        ),
                    )
                }
                Unmet::Limit {
                    name,
                    needed,
                    available,
                } => (
                    format!(
                        "the app needs {name} = {needed}, but `{}` allows {available}",
                        driver.name()
                    ),
                    "split the entity into smaller ones, or remove this driver from `drivers`"
                        .to_string(),
                ),
            };
            out.push(
                Diagnostic::error(
                    "driver_unsupported",
                    "app.yaml",
                    Position { line: 1, column: 1 },
                    message,
                )
                .with_suggestion(help),
            );
        }
    }
    out
}
