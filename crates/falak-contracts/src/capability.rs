//! Driver capability profiles and build-time validation.
//!
//! The compiler asks a driver's [`CapabilityProfile`] whether it satisfies an app's
//! [`Requirements`] and rejects the build if not. The built-in profiles are the expected
//! values from ARCHITECTURE §4.4. **They have not yet been checked against vendor
//! documentation**; task T0.7 verifies them and records the sources.

/// A boolean feature a driver may or may not provide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    InteractiveTransactions,
    AtomicBatch,
    Savepoints,
    SerializableIsolation,
    ConcurrentWriters,
    RowLevelLocking,
    AdvisoryLocks,
    ReadReplicas,
    NativeRls,
    Returning,
    Upsert,
    JsonOperators,
    FullTextSearch,
    VectorSearch,
}

impl Capability {
    /// Stable name used in `app.yaml` and in error messages.
    pub fn name(self) -> &'static str {
        match self {
            Self::InteractiveTransactions => "interactive_transactions",
            Self::AtomicBatch => "atomic_batch",
            Self::Savepoints => "savepoints",
            Self::SerializableIsolation => "serializable_isolation",
            Self::ConcurrentWriters => "concurrent_writers",
            Self::RowLevelLocking => "row_level_locking",
            Self::AdvisoryLocks => "advisory_locks",
            Self::ReadReplicas => "read_replicas",
            Self::NativeRls => "native_rls",
            Self::Returning => "returning",
            Self::Upsert => "upsert",
            Self::JsonOperators => "json_operators",
            Self::FullTextSearch => "full_text_search",
            Self::VectorSearch => "vector_search",
        }
    }

    /// Parse the name used in `app.yaml`.
    pub fn from_name(name: &str) -> Option<Self> {
        ALL_CAPABILITIES.iter().copied().find(|c| c.name() == name)
    }
}

/// Every capability, for iteration.
pub const ALL_CAPABILITIES: [Capability; 14] = [
    Capability::InteractiveTransactions,
    Capability::AtomicBatch,
    Capability::Savepoints,
    Capability::SerializableIsolation,
    Capability::ConcurrentWriters,
    Capability::RowLevelLocking,
    Capability::AdvisoryLocks,
    Capability::ReadReplicas,
    Capability::NativeRls,
    Capability::Returning,
    Capability::Upsert,
    Capability::JsonOperators,
    Capability::FullTextSearch,
    Capability::VectorSearch,
];

/// Numeric limits. `None` means no fixed limit is known or imposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Limits {
    pub max_bound_params: Option<u32>,
    pub max_statement_bytes: Option<u32>,
    pub max_row_bytes: Option<u32>,
    pub max_database_bytes: Option<u64>,
}

/// What a storage driver provides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityProfile {
    pub name: &'static str,
    pub provided: &'static [Capability],
    pub limits: Limits,
}

impl CapabilityProfile {
    pub fn provides(&self, capability: Capability) -> bool {
        self.provided.contains(&capability)
    }

    /// Check an app's requirements. Returns every unmet item, not just the first.
    pub fn check(&self, requirements: &Requirements) -> std::result::Result<(), Vec<Unmet>> {
        let mut unmet = Vec::new();
        for &c in &requirements.capabilities {
            if !self.provides(c) {
                unmet.push(Unmet::Capability(c));
            }
        }
        let limit_checks = [
            (
                "max_bound_params",
                requirements.needs.max_bound_params.map(u64::from),
                self.limits.max_bound_params.map(u64::from),
            ),
            (
                "max_statement_bytes",
                requirements.needs.max_statement_bytes.map(u64::from),
                self.limits.max_statement_bytes.map(u64::from),
            ),
            (
                "max_row_bytes",
                requirements.needs.max_row_bytes.map(u64::from),
                self.limits.max_row_bytes.map(u64::from),
            ),
            (
                "max_database_bytes",
                requirements.needs.max_database_bytes,
                self.limits.max_database_bytes,
            ),
        ];
        for (name, needed, available) in limit_checks {
            if let (Some(needed), Some(available)) = (needed, available)
                && needed > available
            {
                unmet.push(Unmet::Limit {
                    name,
                    needed,
                    available,
                });
            }
        }
        if unmet.is_empty() { Ok(()) } else { Err(unmet) }
    }
}

/// What an app needs from its driver. Produced by the compiler from the app's entities,
/// commands and `app.yaml`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Requirements {
    pub capabilities: Vec<Capability>,
    /// The largest value the app's compiled statements need, per limit.
    pub needs: Limits,
}

/// One reason a profile does not satisfy a set of requirements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unmet {
    Capability(Capability),
    Limit {
        name: &'static str,
        needed: u64,
        available: u64,
    },
}

impl std::fmt::Display for Unmet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Capability(c) => write!(f, "requires `{}`", c.name()),
            Self::Limit {
                name,
                needed,
                available,
            } => write!(f, "needs {name} = {needed}, driver allows {available}"),
        }
    }
}

use Capability as C;

/// SQLite: serializable by default, a single writer, no row-level security.
/// Unverified figures: see the module note.
pub const SQLITE: CapabilityProfile = CapabilityProfile {
    name: "sqlite",
    provided: &[
        C::InteractiveTransactions,
        C::AtomicBatch,
        C::Savepoints,
        C::SerializableIsolation,
        C::AdvisoryLocks,
        C::Returning,
        C::Upsert,
        C::JsonOperators,
        C::FullTextSearch,
    ],
    limits: Limits {
        max_bound_params: Some(32_766),
        max_statement_bytes: Some(1_000_000),
        max_row_bytes: Some(1_000_000_000),
        max_database_bytes: None,
    },
};

/// PostgreSQL: multiple writers, row locking, native RLS.
pub const POSTGRES: CapabilityProfile = CapabilityProfile {
    name: "postgres",
    provided: &[
        C::InteractiveTransactions,
        C::AtomicBatch,
        C::Savepoints,
        C::SerializableIsolation,
        C::ConcurrentWriters,
        C::RowLevelLocking,
        C::AdvisoryLocks,
        C::NativeRls,
        C::Returning,
        C::Upsert,
        C::JsonOperators,
        C::FullTextSearch,
    ],
    limits: Limits {
        max_bound_params: Some(65_535),
        max_statement_bytes: None,
        max_row_bytes: None,
        max_database_bytes: None,
    },
};

/// Cloudflare D1: atomic batches only, no interactive transactions, no RLS.
/// The limit figures are placeholders pending T0.7.
pub const D1: CapabilityProfile = CapabilityProfile {
    name: "d1",
    provided: &[
        C::AtomicBatch,
        C::ReadReplicas,
        C::Returning,
        C::Upsert,
        C::JsonOperators,
        C::FullTextSearch,
    ],
    limits: Limits {
        max_bound_params: Some(100),
        max_statement_bytes: Some(100_000),
        max_row_bytes: Some(2_000_000),
        max_database_bytes: None,
    },
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn d1_rejects_interactive_transactions_and_rls() {
        let req = Requirements {
            capabilities: vec![C::InteractiveTransactions, C::NativeRls, C::AtomicBatch],
            needs: Limits::default(),
        };
        let unmet = D1.check(&req).unwrap_err();
        assert_eq!(
            unmet,
            vec![
                Unmet::Capability(C::InteractiveTransactions),
                Unmet::Capability(C::NativeRls)
            ]
        );
    }

    #[test]
    fn limits_are_checked() {
        let req = Requirements {
            capabilities: vec![],
            needs: Limits {
                max_bound_params: Some(500),
                ..Limits::default()
            },
        };
        assert!(D1.check(&req).is_err());
        assert!(POSTGRES.check(&req).is_ok());
    }

    #[test]
    fn names_round_trip() {
        for c in ALL_CAPABILITIES {
            assert_eq!(Capability::from_name(c.name()), Some(c));
        }
        assert_eq!(Capability::from_name("nope"), None);
    }
}
