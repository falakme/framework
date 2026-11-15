//! `CREATE TABLE` and index statements per dialect, following the type mapping in
//! SCHEMA_SPECIFICATION §5.2.

use falak_contracts::ir::{FieldType, Ir, IrEntity, IrField, Tenancy};

use crate::{sql::Dialect, values::DEFAULT_TEXT_MAX};

fn q(s: &str) -> String {
    format!("\"{s}\"")
}

fn column_type(ty: &FieldType, dialect: Dialect) -> &'static str {
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

fn column(ir: &Ir, f: &IrField, dialect: Dialect, entity: &IrEntity) -> String {
    let mut s = format!("{} {}", q(&f.name), column_type(&f.ty, dialect));
    if f.name == "id" && f.builtin {
        s.push_str(" PRIMARY KEY");
    } else if !f.nullable {
        s.push_str(" NOT NULL");
    }
    if let Some((te, tf)) = &f.references
        && let Some(target) = ir.entity(te)
        && target.name != entity.name
    {
        s.push_str(&format!(" REFERENCES {}({})", q(&target.table), q(tf)));
    }
    let len = if dialect == Dialect::Postgres {
        "char_length"
    } else {
        "length"
    };
    let col = q(&f.name);
    if f.ty == FieldType::Text {
        let max = f.max_length.unwrap_or(DEFAULT_TEXT_MAX);
        s.push_str(&format!(" CHECK ({len}({col}) <= {max})"));
    }
    if let Some(m) = f.min {
        s.push_str(&format!(" CHECK ({col} >= {m})"));
    }
    if let Some(m) = f.max {
        s.push_str(&format!(" CHECK ({col} <= {m})"));
    }
    if f.ty == FieldType::Bool && dialect != Dialect::Postgres {
        s.push_str(&format!(" CHECK ({col} IN (0, 1))"));
    }
    s
}

/// Statements that create one entity's table and indexes.
pub fn create_table(ir: &Ir, entity: &IrEntity, dialect: Dialect) -> Vec<String> {
    let cols: Vec<String> = entity
        .fields
        .iter()
        .map(|f| column(ir, f, dialect, entity))
        .collect();
    let mut out = vec![format!(
        "CREATE TABLE IF NOT EXISTS {} (\n  {}\n)",
        q(&entity.table),
        cols.join(",\n  ")
    )];
    let tenant = ir.app.tenancy == Tenancy::Row;
    for f in entity
        .fields
        .iter()
        .filter(|f| !f.builtin && (f.unique || f.indexed) && !f.encrypted)
    {
        let lead = if tenant {
            format!("{}, ", q("tenant_id"))
        } else {
            String::new()
        };
        let kind = if f.unique { "UNIQUE INDEX" } else { "INDEX" };
        out.push(format!(
            "CREATE {kind} IF NOT EXISTS {} ON {} ({lead}{})",
            q(&format!("idx_{}_{}", entity.table, f.name)),
            q(&entity.table),
            q(&f.name)
        ));
    }
    if tenant {
        out.push(format!(
            "CREATE INDEX IF NOT EXISTS {} ON {} ({})",
            q(&format!("idx_{}_tenant", entity.table)),
            q(&entity.table),
            q("tenant_id")
        ));
    }
    out
}

/// Statements for every entity, ordered so a table appears after the tables it
/// references. A reference cycle is broken by creating the tables in name order; the
/// foreign key is still declared, which PostgreSQL requires to be satisfiable, so apps
/// should avoid cycles.
pub fn create_all(ir: &Ir, dialect: Dialect) -> Vec<String> {
    let mut order: Vec<&IrEntity> = Vec::new();
    fn visit<'a>(
        ir: &'a Ir,
        e: &'a IrEntity,
        order: &mut Vec<&'a IrEntity>,
        stack: &mut Vec<&'a str>,
    ) {
        if order.iter().any(|o| o.name == e.name) || stack.contains(&e.name.as_str()) {
            return;
        }
        stack.push(&e.name);
        for f in &e.fields {
            if let Some((te, _)) = &f.references
                && let Some(t) = ir.entity(te)
            {
                visit(ir, t, order, stack);
            }
        }
        stack.pop();
        order.push(e);
    }
    for e in &ir.entities {
        visit(ir, e, &mut order, &mut Vec::new());
    }
    order
        .into_iter()
        .flat_map(|e| create_table(ir, e, dialect))
        .collect()
}
