//! Builds parameterized SQL statements for an entity: get, list, insert, update, delete.
//!
//! Identifiers come only from the IR (validated at build time) and are always quoted.
//! Every value, including the policy and tenant predicates' values, is a bound parameter.
//! A builder returns `Ok(None)` when access is denied: the runtime then runs nothing and
//! answers `NotFound` for get/update/delete, an empty page for list and `Forbidden` for
//! create. That keeps "no policy" from ever reaching the database.

use falak_contracts::{
    Error, Result,
    capability::{CapabilityProfile, D1, POSTGRES, SQLITE},
    driver::{Statement, Value},
    ir::{FieldType, Ir, IrAction, IrDefault, IrEntity, IrField, Tenancy},
};

use crate::{
    policy::Access,
    values::{DEFAULT_TEXT_MAX, check_value, parse_uuid},
};

pub const MAX_PAGE_SIZE: u32 = 100;
pub const DEFAULT_PAGE_SIZE: u32 = 20;
pub const MAX_FILTERS: usize = 10;
pub const MAX_IN_ITEMS: usize = 20;
pub const MAX_LIKE_CHARS: usize = 100;
pub const MAX_LIKE_CHARS_D1: usize = 50;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Dialect {
    Sqlite,
    Postgres,
    D1,
}

impl Dialect {
    pub fn profile(self) -> &'static CapabilityProfile {
        match self {
            Self::Sqlite => &SQLITE,
            Self::Postgres => &POSTGRES,
            Self::D1 => &D1,
        }
    }

    fn placeholder(self, n: usize) -> String {
        match self {
            Self::Postgres => format!("${n}"),
            Self::Sqlite | Self::D1 => format!("?{n}"),
        }
    }

    fn max_like(self) -> usize {
        if self == Self::D1 {
            MAX_LIKE_CHARS_D1
        } else {
            MAX_LIKE_CHARS
        }
    }
}

/// Who is asking and for which tenant, already verified.
#[derive(Debug, Clone, Default)]
pub struct Scope {
    /// Required under row tenancy; ignored otherwise.
    pub tenant: Option<String>,
    /// The verified subject. Becomes the owner of rows the caller creates.
    pub subject: Option<String>,
}

/// Everything a builder needs to know about one request.
#[derive(Clone, Copy)]
pub struct Request<'a> {
    pub ir: &'a Ir,
    pub entity: &'a IrEntity,
    pub dialect: Dialect,
    pub access: &'a Access,
    pub scope: &'a Scope,
}

fn q(ident: &str) -> String {
    format!("\"{ident}\"")
}

fn columns(entity: &IrEntity) -> String {
    entity
        .fields
        .iter()
        .map(|f| q(&f.name))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Accumulates SQL text and bound values in step.
struct Builder {
    dialect: Dialect,
    params: Vec<Value>,
}

impl Builder {
    fn new(dialect: Dialect) -> Self {
        Self {
            dialect,
            params: Vec::new(),
        }
    }

    fn bind(&mut self, v: Value) -> String {
        self.params.push(v);
        self.dialect.placeholder(self.params.len())
    }

    fn finish(self, sql: String) -> Result<Statement> {
        let limit = self
            .dialect
            .profile()
            .limits
            .max_bound_params
            .unwrap_or(u32::MAX) as usize;
        if self.params.len() > limit {
            return Err(Error::invalid_input(
                "too_many_parameters",
                format!(
                    "the request needs {} values; this database allows {limit}",
                    self.params.len()
                ),
            ));
        }
        Ok(Statement::new(sql, self.params))
    }
}

/// Conditions that apply to every statement on an entity: tenant, soft delete and the
/// row restriction from the access decision. Returns `None` if the request cannot be
/// scoped, which means "run nothing".
fn base_conditions(
    ir: &Ir,
    entity: &IrEntity,
    access: &Access,
    scope: &Scope,
    b: &mut Builder,
) -> Option<Vec<String>> {
    let mut conds = Vec::new();
    if ir.app.tenancy == Tenancy::Row {
        let tenant = parse_uuid(scope.tenant.as_deref()?)?;
        let p = b.bind(Value::Uuid(tenant));
        conds.push(format!("{} = {p}", q("tenant_id")));
    }
    if entity.soft_delete {
        conds.push(format!("{} IS NULL", q("deleted_at")));
    }
    match access {
        Access::Denied => return None,
        Access::Unrestricted => {}
        Access::OwnedBy(subject) => {
            let owner = entity.owner.as_deref()?;
            let id = parse_uuid(subject)?;
            let p = b.bind(Value::Uuid(id));
            conds.push(format!("{} = {p}", q(owner)));
        }
    }
    Some(conds)
}

// ------------------------------------------------------------------ get

/// `SELECT` one row by id, within tenant, soft-delete and access restrictions.
pub fn get(req: Request, id: [u8; 16]) -> Result<Option<Statement>> {
    let Request {
        ir,
        entity,
        dialect,
        access,
        scope,
    } = req;
    let mut b = Builder::new(dialect);
    let Some(mut conds) = base_conditions(ir, entity, access, scope, &mut b) else {
        return Ok(None);
    };
    let p = b.bind(Value::Uuid(id));
    conds.insert(0, format!("{} = {p}", q("id")));
    let sql = format!(
        "SELECT {} FROM {} WHERE {}",
        columns(entity),
        q(&entity.table),
        conds.join(" AND ")
    );
    b.finish(sql).map(Some)
}

// ------------------------------------------------------------------ list

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Eq,
    Neq,
    Gt,
    Gte,
    Lt,
    Lte,
    Like,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Condition {
    Compare(Op, Value),
    In(Vec<Value>),
    IsNull(bool),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Filter {
    pub field: String,
    pub condition: Condition,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SortKey {
    pub field: String,
    pub descending: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ListQuery {
    pub filters: Vec<Filter>,
    /// Requested order. The compiler appends `id` so the order is total.
    pub sort: Vec<SortKey>,
    pub page_size: Option<u32>,
    /// Sort-key values of the last row of the previous page, in the resolved sort order
    /// (including the appended `id`).
    pub after: Option<Vec<Value>>,
}

#[derive(Debug, Clone)]
pub struct ListPlan {
    pub statement: Statement,
    /// The order actually used, with `id` appended.
    pub sort: Vec<SortKey>,
    /// Rows requested: `page_size + 1`, so the caller can tell whether more exist.
    pub fetch: u32,
    pub page_size: u32,
}

/// The sort order after the compiler appends `id`.
pub fn resolve_sort(entity: &IrEntity, requested: &[SortKey]) -> Result<Vec<SortKey>> {
    let mut out: Vec<SortKey> = Vec::new();
    for k in requested {
        let f = entity.field(&k.field).ok_or_else(|| {
            Error::invalid_input(
                "invalid_sort",
                format!("cannot sort by unknown field `{}`", k.field),
            )
        })?;
        if f.nullable || f.encrypted || matches!(f.ty, FieldType::Json | FieldType::Bytes) {
            return Err(Error::invalid_input(
                "invalid_sort",
                format!(
                    "cannot sort by `{}`: only required, unencrypted scalar fields can be sorted",
                    k.field
                ),
            ));
        }
        if out.iter().any(|o| o.field == k.field) {
            return Err(Error::invalid_input(
                "invalid_sort",
                format!("`{}` appears twice in sort", k.field),
            ));
        }
        out.push(k.clone());
    }
    if !out.iter().any(|k| k.field == "id") {
        out.push(SortKey {
            field: "id".into(),
            descending: false,
        });
    }
    Ok(out)
}

/// The values to put in a cursor for `row`, in the order of `sort`.
pub fn cursor_from_row(columns: &[String], row: &[Value], sort: &[SortKey]) -> Option<Vec<Value>> {
    sort.iter()
        .map(|k| {
            columns
                .iter()
                .position(|c| *c == k.field)
                .and_then(|i| row.get(i).cloned())
        })
        .collect()
}

fn check_filter(entity: &IrEntity, dialect: Dialect, f: &Filter) -> Result<()> {
    let bad = |m: String| Error::invalid_input("invalid_filter", m);
    let field = entity
        .field(&f.field)
        .ok_or_else(|| bad(format!("cannot filter on unknown field `{}`", f.field)))?;
    if field.encrypted || field.ty == FieldType::Json {
        return Err(bad(format!("cannot filter on `{}`", f.field)));
    }
    let typed = |v: &Value| -> Result<()> {
        // Reuse the type check; nullability is irrelevant for comparisons.
        let mut probe = field.clone();
        probe.nullable = false;
        probe.min = None;
        probe.max = None;
        probe.max_length = None;
        check_value(&probe, v)
            .map_err(|_| bad(format!("the value for `{}` has the wrong type", f.field)))
    };
    match &f.condition {
        Condition::Compare(Op::Like, v) => {
            if field.ty != FieldType::Text {
                return Err(bad(format!(
                    "`like` applies only to text fields, not `{}`",
                    f.field
                )));
            }
            let Value::Text(p) = v else {
                return Err(bad("`like` needs a text pattern".into()));
            };
            if p.chars().count() > dialect.max_like() {
                return Err(bad(format!(
                    "`like` patterns are limited to {} characters",
                    dialect.max_like()
                )));
            }
            if p.starts_with('%') || p.starts_with('_') {
                return Err(bad("`like` patterns cannot start with a wildcard".into()));
            }
        }
        Condition::Compare(op, v) => {
            typed(v)?;
            if matches!(op, Op::Gt | Op::Gte | Op::Lt | Op::Lte)
                && matches!(field.ty, FieldType::Bool | FieldType::Bytes)
            {
                return Err(bad(format!("`{}` cannot be compared with <, >", f.field)));
            }
            if matches!(v, Value::Null) {
                return Err(bad("use `is_null` to test for null".into()));
            }
        }
        Condition::In(vs) => {
            if vs.is_empty() || vs.len() > MAX_IN_ITEMS {
                return Err(bad(format!(
                    "`in` needs between 1 and {MAX_IN_ITEMS} values"
                )));
            }
            for v in vs {
                typed(v)?;
                if matches!(v, Value::Null) {
                    return Err(bad("`in` cannot contain null".into()));
                }
            }
        }
        Condition::IsNull(_) => {
            if !field.nullable {
                return Err(bad(format!("`{}` is never null", f.field)));
            }
        }
    }
    Ok(())
}

/// Build a page query. See the module note on `Ok(None)`.
pub fn list(req: Request, query: &ListQuery) -> Result<Option<ListPlan>> {
    let Request {
        ir,
        entity,
        dialect,
        access,
        scope,
    } = req;
    if query.filters.len() > MAX_FILTERS {
        return Err(Error::invalid_input(
            "invalid_filter",
            format!("at most {MAX_FILTERS} filters are allowed"),
        ));
    }
    let page_size = query.page_size.unwrap_or(DEFAULT_PAGE_SIZE);
    if page_size == 0 || page_size > MAX_PAGE_SIZE {
        return Err(Error::invalid_input(
            "invalid_page_size",
            format!("page size must be between 1 and {MAX_PAGE_SIZE}"),
        ));
    }
    for f in &query.filters {
        check_filter(entity, dialect, f)?;
    }
    let sort = resolve_sort(entity, &query.sort)?;

    let mut b = Builder::new(dialect);
    let Some(mut conds) = base_conditions(ir, entity, access, scope, &mut b) else {
        return Ok(None);
    };

    for f in &query.filters {
        let col = q(&f.field);
        match &f.condition {
            Condition::Compare(op, v) => {
                let p = b.bind(v.clone());
                conds.push(match op {
                    Op::Eq => format!("{col} = {p}"),
                    Op::Neq => format!("{col} <> {p}"),
                    Op::Gt => format!("{col} > {p}"),
                    Op::Gte => format!("{col} >= {p}"),
                    Op::Lt => format!("{col} < {p}"),
                    Op::Lte => format!("{col} <= {p}"),
                    Op::Like => format!("{col} LIKE {p} ESCAPE '\\'"),
                });
            }
            Condition::In(vs) => {
                let ps: Vec<String> = vs.iter().map(|v| b.bind(v.clone())).collect();
                conds.push(format!("{col} IN ({})", ps.join(", ")));
            }
            Condition::IsNull(true) => conds.push(format!("{col} IS NULL")),
            Condition::IsNull(false) => conds.push(format!("{col} IS NOT NULL")),
        }
    }

    if let Some(after) = &query.after {
        if after.len() != sort.len() {
            return Err(Error::invalid_input(
                "invalid_cursor",
                "the cursor does not match the sort order",
            ));
        }
        for (k, v) in sort.iter().zip(after) {
            let field = entity
                .field(&k.field)
                .expect("sort fields were resolved against the entity");
            let mut probe = field.clone();
            probe.min = None;
            probe.max = None;
            probe.max_length = None;
            check_value(&probe, v).map_err(|_| {
                Error::invalid_input("invalid_cursor", "the cursor does not match the sort order")
            })?;
        }
        // (k1 > c1) OR (k1 = c1 AND k2 > c2) OR ... ; `<` for descending keys.
        let mut alternatives = Vec::new();
        for i in 0..sort.len() {
            let mut parts = Vec::new();
            for (k, v) in sort.iter().zip(after).take(i) {
                let p = b.bind(v.clone());
                parts.push(format!("{} = {p}", q(&k.field)));
            }
            let (k, v) = (&sort[i], &after[i]);
            let p = b.bind(v.clone());
            parts.push(format!(
                "{} {} {p}",
                q(&k.field),
                if k.descending { "<" } else { ">" }
            ));
            alternatives.push(format!("({})", parts.join(" AND ")));
        }
        conds.push(format!("({})", alternatives.join(" OR ")));
    }

    let order: Vec<String> = sort
        .iter()
        .map(|k| {
            format!(
                "{} {}",
                q(&k.field),
                if k.descending { "DESC" } else { "ASC" }
            )
        })
        .collect();
    let fetch = page_size + 1;
    let sql = format!(
        "SELECT {} FROM {} WHERE {} ORDER BY {} LIMIT {fetch}",
        columns(entity),
        q(&entity.table),
        conds.join(" AND "),
        order.join(", ")
    );
    let statement = b.finish(sql)?;
    Ok(Some(ListPlan {
        statement,
        sort,
        fetch,
        page_size,
    }))
}

// ------------------------------------------------------------------ writes

/// Server-supplied values for a write.
#[derive(Debug, Clone)]
pub struct WriteContext {
    pub now_micros: i64,
    /// A fresh id for an insert.
    pub new_id: [u8; 16],
}

fn declared<'a>(entity: &'a IrEntity, name: &str) -> Result<&'a IrField> {
    match entity.field(name) {
        Some(f) if !f.builtin => Ok(f),
        Some(_) => Err(Error::invalid_input(
            "invalid_field",
            format!("`{name}` is managed by the server"),
        )),
        None => Err(Error::invalid_input(
            "invalid_field",
            format!("unknown field `{name}`"),
        )),
    }
}

fn default_value(d: &IrDefault, ctx: &WriteContext, ty: &FieldType) -> Value {
    match d {
        IrDefault::Bool(b) => Value::Bool(*b),
        IrDefault::Int(i) => Value::Int64(*i),
        IrDefault::Text(s) => Value::Text(s.clone()),
        IrDefault::Now => Value::TimestampMicros(ctx.now_micros),
        IrDefault::NewUuid => {
            let _ = ty;
            Value::Uuid(ctx.new_id)
        }
    }
}

/// `INSERT ... RETURNING` for a new row. `input` holds only declared fields; the id,
/// version, timestamps, tenant and owner are set here and cannot be supplied.
pub fn insert(
    req: Request,
    input: &[(String, Value)],
    ctx: &WriteContext,
) -> Result<Option<Statement>> {
    let Request {
        entity,
        access,
        scope,
        dialect,
        ..
    } = req;
    if access.is_denied() {
        return Ok(None);
    }
    for (name, _) in input {
        declared(entity, name)?;
        if entity.owner.as_deref() == Some(name.as_str()) {
            return Err(Error::invalid_input(
                "invalid_field",
                format!("`{name}` is set by the server"),
            ));
        }
    }
    if input
        .iter()
        .enumerate()
        .any(|(i, (n, _))| input[..i].iter().any(|(m, _)| m == n))
    {
        return Err(Error::invalid_input(
            "invalid_field",
            "a field was supplied twice",
        ));
    }
    let mut b = Builder::new(dialect);
    let mut cols = Vec::new();
    let mut vals = Vec::new();
    for f in &entity.fields {
        let value = match f.name.as_str() {
            "id" => Value::Uuid(ctx.new_id),
            "version" => Value::Int64(1),
            "created_at" | "updated_at" => Value::TimestampMicros(ctx.now_micros),
            "deleted_at" if f.builtin => continue,
            "tenant_id" if f.builtin => match scope.tenant.as_deref().and_then(parse_uuid) {
                Some(t) => Value::Uuid(t),
                None => return Ok(None),
            },
            name if entity.owner.as_deref() == Some(name) => {
                let subject = match access {
                    Access::OwnedBy(s) => Some(s.as_str()),
                    _ => scope.subject.as_deref(),
                };
                match subject.and_then(parse_uuid) {
                    Some(u) => Value::Uuid(u),
                    None => return Ok(None),
                }
            }
            name => match input.iter().find(|(n, _)| n == name) {
                Some((_, v)) => v.clone(),
                None => match &f.default {
                    Some(d) => default_value(d, ctx, &f.ty),
                    None if f.nullable => Value::Null,
                    None => {
                        return Err(Error::invalid_input(
                            "invalid_field",
                            format!("`{name}` is required"),
                        ));
                    }
                },
            },
        };
        if !f.builtin {
            check_value(f, &value)?;
        }
        cols.push(q(&f.name));
        vals.push(b.bind(value));
    }
    let sql = format!(
        "INSERT INTO {} ({}) VALUES ({}) RETURNING {}",
        q(&entity.table),
        cols.join(", "),
        vals.join(", "),
        columns(entity)
    );
    b.finish(sql).map(Some)
}

/// `UPDATE ... RETURNING` of declared fields. Bumps `version` and `updated_at`. With
/// `if_version`, the row is updated only if its version still matches; zero rows
/// returned then means "not found or changed", and the runtime tells them apart.
pub fn update(
    req: Request,
    id: [u8; 16],
    changes: &[(String, Value)],
    if_version: Option<i64>,
    ctx: &WriteContext,
) -> Result<Option<Statement>> {
    let Request {
        ir,
        entity,
        dialect,
        access,
        scope,
    } = req;
    if changes.is_empty() {
        return Err(Error::invalid_input("invalid_field", "nothing to update"));
    }
    let mut b = Builder::new(dialect);
    let mut sets = Vec::new();
    for (name, value) in changes {
        let f = declared(entity, name)?;
        if entity.owner.as_deref() == Some(name.as_str()) {
            return Err(Error::invalid_input(
                "invalid_field",
                format!("`{name}` cannot be changed"),
            ));
        }
        check_value(f, value)?;
        let p = b.bind(value.clone());
        sets.push(format!("{} = {p}", q(name)));
    }
    let p = b.bind(Value::Int64(1));
    sets.push(format!("{} = {} + {p}", q("version"), q("version")));
    let p = b.bind(Value::TimestampMicros(ctx.now_micros));
    sets.push(format!("{} = {p}", q("updated_at")));
    let Some(mut conds) = base_conditions(ir, entity, access, scope, &mut b) else {
        return Ok(None);
    };
    let p = b.bind(Value::Uuid(id));
    conds.insert(0, format!("{} = {p}", q("id")));
    if let Some(v) = if_version {
        let p = b.bind(Value::Int64(v));
        conds.push(format!("{} = {p}", q("version")));
    }
    let sql = format!(
        "UPDATE {} SET {} WHERE {} RETURNING {}",
        q(&entity.table),
        sets.join(", "),
        conds.join(" AND "),
        columns(entity)
    );
    b.finish(sql).map(Some)
}

/// Delete one row: `DELETE` normally, or a `deleted_at` update for soft-delete entities.
/// Check `rows_affected`: zero means not found, not visible, or version mismatch.
pub fn delete(
    req: Request,
    id: [u8; 16],
    if_version: Option<i64>,
    ctx: &WriteContext,
) -> Result<Option<Statement>> {
    let Request {
        ir,
        entity,
        dialect,
        access,
        scope,
    } = req;
    let mut b = Builder::new(dialect);
    let mut sets = Vec::new();
    if entity.soft_delete {
        let p = b.bind(Value::TimestampMicros(ctx.now_micros));
        sets.push(format!("{} = {p}", q("deleted_at")));
        sets.push(format!("{} = {p}", q("updated_at")));
        let p = b.bind(Value::Int64(1));
        sets.push(format!("{} = {} + {p}", q("version"), q("version")));
    }
    let Some(mut conds) = base_conditions(ir, entity, access, scope, &mut b) else {
        return Ok(None);
    };
    let p = b.bind(Value::Uuid(id));
    conds.insert(0, format!("{} = {p}", q("id")));
    if let Some(v) = if_version {
        let p = b.bind(Value::Int64(v));
        conds.push(format!("{} = {p}", q("version")));
    }
    let sql = if entity.soft_delete {
        format!(
            "UPDATE {} SET {} WHERE {}",
            q(&entity.table),
            sets.join(", "),
            conds.join(" AND ")
        )
    } else {
        format!(
            "DELETE FROM {} WHERE {}",
            q(&entity.table),
            conds.join(" AND ")
        )
    };
    b.finish(sql).map(Some)
}

/// The action an access decision was made for, for callers building error responses.
pub fn denial_for(action: IrAction) -> Error {
    match action {
        IrAction::Create => Error::forbidden(),
        _ => Error::not_found(),
    }
}

#[allow(dead_code)]
const _: u32 = DEFAULT_TEXT_MAX;
