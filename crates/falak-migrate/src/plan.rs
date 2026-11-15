//! Migration planning, expand-and-contract phase segregation, and checksum generation.

use falak_contracts::ir::{FieldType, Ir};
use falak_core::{
    ddl::{create_table, creation_order},
    sql::Dialect,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::diff::{SchemaDiff, diff_ir};

/// The phase of an expand-and-contract zero-downtime migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MigrationPhase {
    /// Non-breaking, additive changes (new tables, columns, indexes).
    Expand,
    /// Destructive cleanup (dropping obsolete columns or deprecated tables).
    Contract,
}

/// Database locking impact of a planned migration statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LockImpact {
    None,
    ShareUpdateExclusive,
    AccessExclusive,
}

/// Destructiveness rating of a planned statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Destructiveness {
    Safe,
    Caution,
    Breaking,
}

/// A planned SQL statement with phase, lock impact, and safety classifications.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedStatement {
    pub sql: String,
    pub phase: MigrationPhase,
    pub lock_impact: LockImpact,
    pub destructiveness: Destructiveness,
    pub description: String,
}

/// A complete migration plan containing expand and contract statements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationPlan {
    pub from_hash: Option<String>,
    pub to_hash: String,
    pub statements: Vec<PlannedStatement>,
    pub checksum: String,
}

impl MigrationPlan {
    /// Filter statements for the Expand phase.
    pub fn expand_statements(&self) -> Vec<&PlannedStatement> {
        self.statements
            .iter()
            .filter(|s| s.phase == MigrationPhase::Expand)
            .collect()
    }

    /// Filter statements for the Contract phase.
    pub fn contract_statements(&self) -> Vec<&PlannedStatement> {
        self.statements
            .iter()
            .filter(|s| s.phase == MigrationPhase::Contract)
            .collect()
    }
}

fn column_type_sql(ty: &FieldType, dialect: Dialect) -> &'static str {
    match (ty, dialect) {
        (FieldType::Uuid, Dialect::Postgres) => "uuid",
        (FieldType::Uuid | FieldType::Text, _) => "TEXT",
        (FieldType::Int64 | FieldType::DecimalMinor, Dialect::Postgres) => "bigint",
        (FieldType::Int64 | FieldType::DecimalMinor, _) => "INTEGER",
        (FieldType::Bool, Dialect::Postgres) => "boolean",
        (FieldType::Bool, _) => "INTEGER",
        (FieldType::Timestamptz, Dialect::Postgres) => "timestamptz",
        (FieldType::Timestamptz, _) => "INTEGER",
        (FieldType::Bytes, Dialect::Postgres) => "bytea",
        (FieldType::Bytes, _) => "BLOB",
        (FieldType::Json, Dialect::Postgres) => "jsonb",
        (FieldType::Json, _) => "TEXT",
    }
}

fn compute_checksum(statements: &[PlannedStatement]) -> String {
    let mut hasher = Sha256::new();
    for stmt in statements {
        hasher.update(stmt.sql.as_bytes());
        hasher.update(b"\n");
    }
    hex::encode(hasher.finalize())
}

/// Generate a migration plan between two IR versions.
pub fn plan_migration(from: Option<&Ir>, to: &Ir, dialect: Dialect) -> MigrationPlan {
    let mut statements = Vec::new();

    if from.is_none() {
        // Initial migration: create all tables and indexes in Expand phase
        // Referenced tables first: PostgreSQL checks a foreign key when the table is made.
        for entity in creation_order(to) {
            let entity_ddl = create_table(to, entity, dialect);
            for (idx, sql) in entity_ddl.into_iter().enumerate() {
                let is_create = idx == 0;
                statements.push(PlannedStatement {
                    sql,
                    phase: MigrationPhase::Expand,
                    lock_impact: if is_create {
                        LockImpact::AccessExclusive
                    } else {
                        LockImpact::ShareUpdateExclusive
                    },
                    destructiveness: Destructiveness::Safe,
                    description: if is_create {
                        format!("Create table `{}`", entity.table)
                    } else {
                        format!("Create index for `{}`", entity.table)
                    },
                });
            }
        }
    } else {
        let mut diffs = diff_ir(from, to);
        // New tables go first, referenced ones before the tables that reference them.
        let order = creation_order(to);
        diffs.sort_by_key(|d| match d {
            SchemaDiff::CreateTable(e) => order
                .iter()
                .position(|o| o.name == e.name)
                .unwrap_or(order.len()),
            _ => order.len() + 1,
        });

        // 1. Process Expand changes
        for diff in &diffs {
            match diff {
                SchemaDiff::CreateTable(entity) => {
                    let entity_ddl = create_table(to, entity, dialect);
                    for (idx, sql) in entity_ddl.into_iter().enumerate() {
                        let is_create = idx == 0;
                        statements.push(PlannedStatement {
                            sql,
                            phase: MigrationPhase::Expand,
                            lock_impact: if is_create {
                                LockImpact::AccessExclusive
                            } else {
                                LockImpact::ShareUpdateExclusive
                            },
                            destructiveness: Destructiveness::Safe,
                            description: if is_create {
                                format!("Create table `{}`", entity.table)
                            } else {
                                format!("Create index for `{}`", entity.table)
                            },
                        });
                    }
                }
                SchemaDiff::AlterTable {
                    table,
                    add_fields,
                    add_indexes,
                    ..
                } => {
                    for f in add_fields {
                        let ty_str = column_type_sql(&f.ty, dialect);
                        let sql = format!(
                            "ALTER TABLE \"{table}\" ADD COLUMN \"{}\" {ty_str};",
                            f.name
                        );
                        statements.push(PlannedStatement {
                            sql,
                            phase: MigrationPhase::Expand,
                            lock_impact: LockImpact::AccessExclusive,
                            destructiveness: Destructiveness::Safe,
                            description: format!("Add column `{}` to `{table}`", f.name),
                        });
                    }
                    for idx_name in add_indexes {
                        let sql =
                            format!("CREATE INDEX IF NOT EXISTS \"{idx_name}\" ON \"{table}\";");
                        statements.push(PlannedStatement {
                            sql,
                            phase: MigrationPhase::Expand,
                            lock_impact: LockImpact::ShareUpdateExclusive,
                            destructiveness: Destructiveness::Safe,
                            description: format!("Add index `{idx_name}` on `{table}`"),
                        });
                    }
                }
                SchemaDiff::DropTable(_) => {}
            }
        }

        // 2. Process Contract changes (drops)
        for diff in &diffs {
            match diff {
                SchemaDiff::AlterTable {
                    table,
                    drop_fields,
                    drop_indexes,
                    ..
                } => {
                    for idx_name in drop_indexes {
                        let sql = format!("DROP INDEX IF EXISTS \"{idx_name}\";");
                        statements.push(PlannedStatement {
                            sql,
                            phase: MigrationPhase::Contract,
                            lock_impact: LockImpact::ShareUpdateExclusive,
                            destructiveness: Destructiveness::Caution,
                            description: format!("Drop index `{idx_name}`"),
                        });
                    }
                    for field_name in drop_fields {
                        let sql = format!("ALTER TABLE \"{table}\" DROP COLUMN \"{field_name}\";");
                        statements.push(PlannedStatement {
                            sql,
                            phase: MigrationPhase::Contract,
                            lock_impact: LockImpact::AccessExclusive,
                            destructiveness: Destructiveness::Breaking,
                            description: format!("Drop column `{field_name}` from `{table}`"),
                        });
                    }
                }
                SchemaDiff::DropTable(table) => {
                    let sql = format!("DROP TABLE IF EXISTS \"{table}\";");
                    statements.push(PlannedStatement {
                        sql,
                        phase: MigrationPhase::Contract,
                        lock_impact: LockImpact::AccessExclusive,
                        destructiveness: Destructiveness::Breaking,
                        description: format!("Drop table `{table}`"),
                    });
                }
                SchemaDiff::CreateTable(_) => {}
            }
        }
    }

    let checksum = compute_checksum(&statements);
    MigrationPlan {
        from_hash: from.map(|ir| ir.content_hash.clone()),
        to_hash: to.content_hash.clone(),
        statements,
        checksum,
    }
}
