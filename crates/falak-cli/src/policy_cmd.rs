//! `falak policy explain`: the decision, the rule that gave it, and the SQL it becomes.
//!
//! For developers. It shows what a request from a chosen caller would be allowed to do
//! on one entity, and the statement the runtime would run. Nothing here reaches a
//! response (AUTHORIZATION specification §6.7).

use std::path::Path;

use falak_contracts::{
    driver::Value,
    identity::Principal,
    ir::{FieldType, IrAction, IrEntity},
};
use falak_core::{
    policy::{Access, explain},
    sql::{self, Dialect, ListQuery, Request, Scope, WriteContext},
};

use crate::project;

pub struct Options {
    pub entity: Option<String>,
    pub action: Option<String>,
    pub subject: Option<String>,
    pub roles: Vec<String>,
    pub tenant: Option<String>,
    pub dialect: Option<String>,
    /// Explain for a caller with no verified identity.
    pub anonymous: bool,
}

fn parse_action(s: &str) -> Result<IrAction, String> {
    match s {
        "read" => Ok(IrAction::Read),
        "create" => Ok(IrAction::Create),
        "update" => Ok(IrAction::Update),
        "delete" => Ok(IrAction::Delete),
        other => Err(format!(
            "`{other}` is not an action (read, create, update, delete)"
        )),
    }
}

fn parse_dialect(s: Option<&str>) -> Result<Dialect, String> {
    match s.unwrap_or("sqlite") {
        "sqlite" => Ok(Dialect::Sqlite),
        "postgres" => Ok(Dialect::Postgres),
        "d1" => Ok(Dialect::D1),
        other => Err(format!("`{other}` is not a driver (sqlite, postgres, d1)")),
    }
}

/// A value of the right type, to show a statement's shape.
fn sample(ty: &FieldType) -> Value {
    match ty {
        FieldType::Uuid => Value::Uuid([7; 16]),
        FieldType::Int64 | FieldType::DecimalMinor => Value::Int64(1),
        FieldType::Bool => Value::Bool(true),
        FieldType::Timestamptz => Value::TimestampMicros(0),
        FieldType::Bytes => Value::Bytes(vec![0]),
        FieldType::Json => Value::Text("{}".into()),
        FieldType::Text => Value::Text("sample".into()),
    }
}

fn show_access(access: &Access) -> String {
    match access {
        Access::Denied => "DENIED (no query runs)".into(),
        Access::Unrestricted => "ALLOWED on every row, every field".into(),
        Access::OwnedBy(_) => "ALLOWED on rows the caller owns, every field".into(),
        Access::Grants(g) => format!(
            "ALLOWED through {} rule(s), with conditions or masks",
            g.len()
        ),
    }
}

fn show_value(v: &Value) -> String {
    match v {
        Value::Text(s) => format!("'{s}'"),
        Value::Uuid(u) => falak_core::values::format_uuid(u),
        other => format!("{other:?}"),
    }
}

fn show_statement(label: &str, st: &falak_contracts::driver::Statement) {
    println!("  {label}:");
    println!("    {}", st.sql);
    for (i, p) in st.params.iter().enumerate() {
        println!("    ${} = {}", i + 1, show_value(p));
    }
}

pub fn run(dir: &Path, o: &Options) -> Result<u8, String> {
    let Some(compiled) = project::build(dir)? else {
        return Ok(1);
    };
    let ir = &compiled.ir;
    let entity_name = o.entity.as_deref().ok_or("`--entity <name>` is required")?;
    let entity: &IrEntity = ir.entity(entity_name).ok_or_else(|| {
        let names: Vec<_> = ir.entities.iter().map(|e| e.name.as_str()).collect();
        format!(
            "no entity `{entity_name}` (the app has: {})",
            names.join(", ")
        )
    })?;
    let action = parse_action(o.action.as_deref().unwrap_or("read"))?;
    let dialect = parse_dialect(o.dialect.as_deref())?;

    let principal = if o.anonymous {
        None
    } else {
        Some(Principal {
            subject: o
                .subject
                .clone()
                .unwrap_or_else(|| "00000000-0000-0000-0000-000000000001".into()),
            tenant: o.tenant.clone(),
            roles: o.roles.clone(),
        })
    };

    let e = explain(entity, action, principal.as_ref());
    println!("entity:    {}", entity.name);
    println!("action:    {action:?}");
    match &principal {
        None => println!("caller:    anonymous (no verified principal)"),
        Some(p) => println!(
            "caller:    subject {} roles [{}] tenant {}",
            p.subject,
            p.roles.join(", "),
            p.tenant.as_deref().unwrap_or("-")
        ),
    }
    println!("decision:  {}", show_access(&e.access));
    println!("rules:");
    if e.rules.is_empty() {
        println!("  (the entity has no rules: default deny)");
    }
    for r in &e.rules {
        println!(
            "  {} {:<24} {}",
            if r.applies { "yes" } else { "no " },
            r.rule,
            r.detail
        );
    }
    if let Access::Grants(grants) = &e.access {
        let unreadable: Vec<&str> = entity
            .fields
            .iter()
            .filter(|f| !e.access.reads_everywhere(f))
            .map(|f| f.name.as_str())
            .collect();
        if !unreadable.is_empty() {
            println!(
                "fields not readable on every row (cannot be filtered or sorted on): {}",
                unreadable.join(", ")
            );
        }
        let _ = grants;
    }
    if e.access.is_denied() {
        return Ok(0);
    }

    let scope = Scope {
        tenant: o
            .tenant
            .clone()
            .or_else(|| Some("00000000-0000-0000-0000-0000000000aa".into())),
        subject: principal.as_ref().map(|p| p.subject.clone()),
    };
    let req = Request {
        ir,
        entity,
        dialect,
        access: &e.access,
        scope: &scope,
    };
    let write_ctx = WriteContext {
        now_micros: 0,
        new_id: [9; 16],
    };
    println!("sql ({dialect:?}):");
    let built = match action {
        IrAction::Read => sql::list(req, &ListQuery::default()).map(|p| p.map(|p| p.statement)),
        IrAction::Delete => sql::delete(req, [9; 16], None, &write_ctx),
        IrAction::Update => {
            let field = entity.fields.iter().find(|f| {
                !f.builtin && entity.owner.as_deref() != Some(f.name.as_str()) && e.access.writes(f)
            });
            match field {
                Some(f) => sql::update(
                    req,
                    [9; 16],
                    &[(f.name.clone(), sample(&f.ty))],
                    None,
                    &write_ctx,
                ),
                None => {
                    println!("  (no field this caller may change)");
                    return Ok(0);
                }
            }
        }
        IrAction::Create => {
            let input: Vec<(String, Value)> = entity
                .fields
                .iter()
                .filter(|f| {
                    !f.builtin
                        && entity.owner.as_deref() != Some(f.name.as_str())
                        && e.access.writes(f)
                        && !f.nullable
                })
                .map(|f| (f.name.clone(), sample(&f.ty)))
                .collect();
            sql::insert(req, &input, &write_ctx)
        }
    };
    match built {
        Ok(Some(st)) => show_statement("statement", &st),
        Ok(None) => println!("  (the caller cannot be scoped: no query runs)"),
        Err(err) => println!("  (refused: {})", err.public_message()),
    }
    Ok(0)
}
