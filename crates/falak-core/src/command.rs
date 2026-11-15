//! Turns a declarative command plus its input into a statement.
//!
//! `update` and `delete` commands compile to a single conditional statement guarded by
//! the row's `version` column, so they run as an atomic batch on every driver, including
//! D1 which has no interactive transactions (DRIVER_SPECIFICATION §6.2). `custom`
//! commands are handled by their Rust handler and are not planned here.

use falak_contracts::{
    Error, Result,
    driver::{Statement, Value},
    ir::{IrCommand, IrCommandKind, IrSetValue},
};

use crate::{
    sql::{self, Request, WriteContext},
    values::check_value,
};

/// The effect to run, or nothing if access is denied.
#[derive(Debug, Clone, PartialEq)]
pub enum Plan {
    /// Run nothing; the caller maps this as `sql` documents (create: forbidden, otherwise not found).
    Denied,
    Run(Statement),
}

/// Plan a declarative command. `input` holds the caller's values by input name. With
/// `if_version`, an update or delete applies only if the row's version still matches.
pub fn plan(
    req: Request,
    command: &IrCommand,
    input: &[(String, Value)],
    if_version: Option<i64>,
    ctx: &WriteContext,
) -> Result<Plan> {
    if command.kind == IrCommandKind::Custom {
        return Err(Error::unsupported(
            "custom_command",
            "custom commands are run by their handler",
        ));
    }
    // Validate input first: unknown names, required, type and length.
    for (name, _) in input {
        if !command.input.iter().any(|i| &i.name == name) {
            return Err(Error::invalid_input(
                "invalid_input",
                format!("unknown input `{name}`"),
            ));
        }
    }
    for i in &command.input {
        let given = input.iter().find(|(n, _)| *n == i.name).map(|(_, v)| v);
        match given {
            None | Some(Value::Null) if i.required => {
                return Err(Error::invalid_input(
                    "invalid_input",
                    format!("input `{}` is required", i.name),
                ));
            }
            Some(v) => {
                let probe = falak_contracts::ir::IrField {
                    name: i.name.clone(),
                    ty: i.ty.clone(),
                    nullable: !i.required,
                    unique: false,
                    indexed: false,
                    pii: false,
                    encrypted: false,
                    max_length: i.max_length,
                    min: None,
                    max: None,
                    default: None,
                    references: None,
                    builtin: false,
                };
                check_value(&probe, v).map_err(|_| {
                    Error::invalid_input("invalid_input", format!("input `{}` is invalid", i.name))
                })?;
            }
            None => {}
        }
    }
    let lookup = |name: &str| {
        input
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.clone())
    };
    let resolved: Vec<(String, Value)> = command
        .set
        .iter()
        .map(|(field, v)| {
            let value = match v {
                IrSetValue::Bool(b) => Value::Bool(*b),
                IrSetValue::Int(i) => Value::Int64(*i),
                IrSetValue::Text(s) => Value::Text(s.clone()),
                IrSetValue::Now => Value::TimestampMicros(ctx.now_micros),
                IrSetValue::Input(name) => lookup(name).unwrap_or(Value::Null),
            };
            (field.clone(), value)
        })
        .collect();

    let target_id = || -> Result<[u8; 16]> {
        let name = command
            .target
            .as_deref()
            .ok_or_else(|| Error::invalid_input("invalid_input", "the command has no target"))?;
        match lookup(name) {
            Some(Value::Uuid(u)) => Ok(u),
            _ => Err(Error::invalid_input(
                "invalid_input",
                format!("input `{name}` must be a uuid"),
            )),
        }
    };

    let statement = match command.kind {
        IrCommandKind::Create => sql::insert(req, &resolved, ctx)?,
        IrCommandKind::Update => sql::update(req, target_id()?, &resolved, if_version, ctx)?,
        IrCommandKind::Delete => sql::delete(req, target_id()?, if_version, ctx)?,
        IrCommandKind::Custom => unreachable!("handled above"),
    };
    Ok(statement.map_or(Plan::Denied, Plan::Run))
}
