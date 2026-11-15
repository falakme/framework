//! Migration planning, expand-and-contract phase segregation, and checksum generation.

use falak_contracts::ir::{FieldType, Ir, IrDefault, IrEntity, IrField};
use falak_core::{
    ddl::{column_definition, column_type_name, create_table, creation_order},
    sql::Dialect,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::diff::{IndexSpec, SchemaDiff, diff_ir};

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
    /// Changes the planner cannot make safely. A plan with any of these must not be
    /// applied: the developer writes that migration by hand.
    #[serde(default)]
    pub unsupported: Vec<String>,
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

#[allow(dead_code)]
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

/// The SQL literal for a default the database can fill in for existing rows.
fn default_literal(f: &IrField, dialect: Dialect) -> Option<String> {
    match f.default.as_ref()? {
        IrDefault::Bool(b) if dialect == Dialect::Postgres => Some(b.to_string()),
        IrDefault::Bool(b) => Some(if *b { "1" } else { "0" }.to_owned()),
        IrDefault::Int(i) => Some(i.to_string()),
        IrDefault::Text(s) => Some(format!("'{}'", s.replace('\'', "''"))),
        IrDefault::Now | IrDefault::NewUuid => None,
    }
}

fn stmt(
    sql: String,
    phase: MigrationPhase,
    lock_impact: LockImpact,
    destructiveness: Destructiveness,
    description: String,
) -> PlannedStatement {
    PlannedStatement {
        sql,
        phase,
        lock_impact,
        destructiveness,
        description,
    }
}

fn create_stmts(to: &Ir, entity: &IrEntity, dialect: Dialect) -> Vec<PlannedStatement> {
    create_table(to, entity, dialect)
        .into_iter()
        .enumerate()
        .map(|(idx, sql)| {
            let is_create = idx == 0;
            stmt(
                sql,
                MigrationPhase::Expand,
                if is_create {
                    LockImpact::AccessExclusive
                } else {
                    LockImpact::ShareUpdateExclusive
                },
                Destructiveness::Safe,
                if is_create {
                    format!("Create table `{}`", entity.table)
                } else {
                    format!("Create index for `{}`", entity.table)
                },
            )
        })
        .collect()
}

/// Rebuild a table in the SQLite family (SQLite and D1), which cannot change a column in
/// place: make the new table, copy the rows across, swap. All in one atomic batch, with
/// foreign key checks deferred to the end so tables that reference this one survive the
/// swap. A row that does not fit the new definition fails the copy, and the whole batch
/// rolls back.
fn rebuild(
    to: &Ir,
    old: &IrEntity,
    new: &IrEntity,
    dialect: Dialect,
    out: &mut Vec<PlannedStatement>,
    unsupported: &mut Vec<String>,
) {
    let table = &new.table;
    let temp = format!("{table}__rebuild");
    let mut cols = Vec::new();
    let mut exprs = Vec::new();
    for f in &new.fields {
        if old.field(&f.name).is_some() {
            cols.push(format!("\"{}\"", f.name));
            exprs.push(format!("\"{}\"", f.name));
        } else if !f.nullable {
            match default_literal(f, dialect) {
                Some(lit) => {
                    cols.push(format!("\"{}\"", f.name));
                    exprs.push(lit);
                }
                None => {
                    unsupported.push(format!(
                        "`{table}.{}` is required and has no default the database can fill in for existing rows: make it optional or give it a default",
                        f.name
                    ));
                    return;
                }
            }
        }
    }
    let mut create = create_table(to, new, dialect);
    let first = create.remove(0);
    let create_temp = first.replacen(
        &format!("CREATE TABLE IF NOT EXISTS \"{table}\""),
        &format!("CREATE TABLE \"{temp}\""),
        1,
    );
    let caution = |sql: String, what: String| {
        stmt(
            sql,
            MigrationPhase::Expand,
            LockImpact::AccessExclusive,
            Destructiveness::Caution,
            what,
        )
    };
    out.push(caution(
        "PRAGMA defer_foreign_keys = ON".to_owned(),
        format!("Defer foreign key checks while `{table}` is rebuilt"),
    ));
    out.push(caution(
        create_temp,
        format!("Rebuild `{table}`: new table"),
    ));
    out.push(caution(
        format!(
            "INSERT INTO \"{temp}\" ({}) SELECT {} FROM \"{table}\"",
            cols.join(", "),
            exprs.join(", ")
        ),
        format!("Rebuild `{table}`: copy rows"),
    ));
    out.push(caution(
        format!("DROP TABLE \"{table}\""),
        format!("Rebuild `{table}`: drop the old table"),
    ));
    out.push(caution(
        format!("ALTER TABLE \"{temp}\" RENAME TO \"{table}\""),
        format!("Rebuild `{table}`: swap in the new table"),
    ));
    for sql in create {
        out.push(caution(
            sql,
            format!("Rebuild `{table}`: recreate an index"),
        ));
    }
}

#[allow(clippy::too_many_arguments)]
fn plan_alter(
    to: &Ir,
    dialect: Dialect,
    old: &IrEntity,
    new: &IrEntity,
    add_fields: &[IrField],
    drop_fields: &[String],
    changed_fields: &[(IrField, IrField)],
    add_indexes: &[IndexSpec],
    drop_indexes: &[String],
    out: &mut Vec<PlannedStatement>,
    unsupported: &mut Vec<String>,
) {
    let table = &new.table;
    let sqlite_family = dialect != Dialect::Postgres;

    // SQLite cannot drop a column that is indexed, unique, referencing or the key, and
    // cannot alter one in place at all.
    let drop_needs_rebuild = drop_fields.iter().any(|n| {
        old.field(n)
            .is_some_and(|f| f.unique || f.indexed || f.references.is_some() || f.name == "id")
    });
    let add_needs_rebuild = add_fields
        .iter()
        .any(|f| !f.nullable && f.references.is_some());
    if sqlite_family && (!changed_fields.is_empty() || drop_needs_rebuild || add_needs_rebuild) {
        rebuild(to, old, new, dialect, out, unsupported);
        return;
    }

    for f in add_fields {
        let mut def = column_definition(to, new, f, dialect);
        if !f.nullable {
            match default_literal(f, dialect) {
                Some(lit) => def.push_str(&format!(" DEFAULT {lit}")),
                None => {
                    unsupported.push(format!(
                        "`{table}.{}` is required and has no default the database can fill in for existing rows: make it optional or give it a default",
                        f.name
                    ));
                    continue;
                }
            }
        }
        out.push(stmt(
            format!("ALTER TABLE \"{table}\" ADD COLUMN {def}"),
            MigrationPhase::Expand,
            LockImpact::AccessExclusive,
            Destructiveness::Safe,
            format!("Add column `{}` to `{table}`", f.name),
        ));
    }

    if dialect == Dialect::Postgres {
        for (o, n) in changed_fields {
            if o.ty != n.ty {
                let ty = column_type_name(&n.ty, dialect);
                out.push(stmt(
                    format!(
                        "ALTER TABLE \"{table}\" ALTER COLUMN \"{0}\" TYPE {ty} USING \"{0}\"::{ty}",
                        n.name
                    ),
                    MigrationPhase::Expand,
                    LockImpact::AccessExclusive,
                    Destructiveness::Caution,
                    format!("Change the type of `{table}.{}`", n.name),
                ));
            }
            if o.nullable != n.nullable {
                let (verb, caution) = if n.nullable {
                    ("DROP", Destructiveness::Safe)
                } else {
                    ("SET", Destructiveness::Caution)
                };
                out.push(stmt(
                    format!(
                        "ALTER TABLE \"{table}\" ALTER COLUMN \"{}\" {verb} NOT NULL",
                        n.name
                    ),
                    MigrationPhase::Expand,
                    LockImpact::AccessExclusive,
                    caution,
                    format!("Change nullability of `{table}.{}`", n.name),
                ));
            }
            if o.max_length != n.max_length
                || o.min != n.min
                || o.max != n.max
                || o.references != n.references
            {
                unsupported.push(format!(
                    "changing the length, range or reference of `{table}.{}` needs a hand written migration",
                    n.name
                ));
            }
        }
    }

    // An index that changes (for example becomes unique) is dropped first, then made.
    for idx in add_indexes {
        if drop_indexes.contains(&idx.name) {
            out.push(stmt(
                format!("DROP INDEX IF EXISTS \"{}\"", idx.name),
                MigrationPhase::Expand,
                LockImpact::ShareUpdateExclusive,
                Destructiveness::Safe,
                format!("Replace index `{}`", idx.name),
            ));
        }
        out.push(stmt(
            format!(
                "CREATE {}INDEX IF NOT EXISTS \"{}\" ON \"{table}\" (\"{}\")",
                if idx.unique { "UNIQUE " } else { "" },
                idx.name,
                idx.column
            ),
            MigrationPhase::Expand,
            LockImpact::ShareUpdateExclusive,
            Destructiveness::Safe,
            format!("Add index `{}` on `{table}`", idx.name),
        ));
    }
    for name in drop_indexes {
        if add_indexes.iter().any(|i| &i.name == name) {
            continue;
        }
        out.push(stmt(
            format!("DROP INDEX IF EXISTS \"{name}\""),
            MigrationPhase::Contract,
            LockImpact::ShareUpdateExclusive,
            Destructiveness::Caution,
            format!("Drop index `{name}`"),
        ));
    }
    for field in drop_fields {
        out.push(stmt(
            format!("ALTER TABLE \"{table}\" DROP COLUMN \"{field}\""),
            MigrationPhase::Contract,
            LockImpact::AccessExclusive,
            Destructiveness::Breaking,
            format!("Drop column `{field}` from `{table}`"),
        ));
    }
}

/// Uploaded files: who owns each, in which tenant, and whether it passed the checks.
fn files_table(dialect: Dialect) -> String {
    let (int, time) = if dialect == Dialect::Postgres {
        ("bigint", "bigint")
    } else {
        ("INTEGER", "INTEGER")
    };
    format!(
        "CREATE TABLE IF NOT EXISTS \"_falak_files\" (\"id\" TEXT NOT NULL PRIMARY KEY, \"tenant\" TEXT, \"owner\" TEXT NOT NULL, \"name\" TEXT NOT NULL, \"content_type\" TEXT NOT NULL, \"size\" {int} NOT NULL, \"state\" TEXT NOT NULL, \"created_at\" {time} NOT NULL)"
    )
}

/// Generate a migration plan between two IR versions.
pub fn plan_migration(from: Option<&Ir>, to: &Ir, dialect: Dialect) -> MigrationPlan {
    let mut statements = Vec::new();
    let mut unsupported = Vec::new();

    if from.is_none() {
        // Referenced tables first: PostgreSQL checks a foreign key when the table is made.
        for entity in creation_order(to) {
            statements.extend(create_stmts(to, entity, dialect));
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
        for diff in &diffs {
            match diff {
                SchemaDiff::CreateTable(entity) => {
                    statements.extend(create_stmts(to, entity, dialect));
                }
                SchemaDiff::AlterTable {
                    old,
                    new,
                    add_fields,
                    drop_fields,
                    changed_fields,
                    add_indexes,
                    drop_indexes,
                    ..
                } => plan_alter(
                    to,
                    dialect,
                    old,
                    new,
                    add_fields,
                    drop_fields,
                    changed_fields,
                    add_indexes,
                    drop_indexes,
                    &mut statements,
                    &mut unsupported,
                ),
                SchemaDiff::DropTable(table) => statements.push(stmt(
                    format!("DROP TABLE IF EXISTS \"{table}\""),
                    MigrationPhase::Contract,
                    LockImpact::AccessExclusive,
                    Destructiveness::Breaking,
                    format!("Drop table `{table}`"),
                )),
            }
        }
        // Expand statements first, whatever order the tables came in.
        statements.sort_by_key(|s| s.phase == MigrationPhase::Contract);
    }

    // The table behind `/v1/_files`. Idempotent, so it is safe in every plan.
    statements.push(stmt(
        files_table(dialect),
        MigrationPhase::Expand,
        LockImpact::None,
        Destructiveness::Safe,
        "Create the file records table".to_owned(),
    ));
    statements.push(stmt(
        "CREATE INDEX IF NOT EXISTS \"idx__falak_files_owner\" ON \"_falak_files\" (\"owner\")"
            .to_owned(),
        MigrationPhase::Expand,
        LockImpact::None,
        Destructiveness::Safe,
        "Index the file records by owner".to_owned(),
    ));

    // Row-level security on PostgreSQL, from the same rules the runtime applies.
    if dialect == Dialect::Postgres {
        for sql in crate::rls::rls_statements(to) {
            statements.push(stmt(
                sql,
                MigrationPhase::Expand,
                LockImpact::ShareUpdateExclusive,
                Destructiveness::Safe,
                "Row-level security and runtime role".to_owned(),
            ));
        }
    }

    let checksum = compute_checksum(&statements);
    MigrationPlan {
        from_hash: from.map(|ir| ir.content_hash.clone()),
        to_hash: to.content_hash.clone(),
        statements,
        checksum,
        unsupported,
    }
}
