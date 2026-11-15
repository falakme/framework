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
    ir::{
        FieldType, Ir, IrAction, IrCmp, IrCondValue, IrCondition, IrDefault, IrEntity, IrField,
        Tenancy,
    },
};

use crate::{
    policy::{Access, Grant, Via},
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

// ------------------------------------------------------------------ stage 2: grants

fn value_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Int64(x), Value::Int64(y)) => x == y,
        (Value::Bool(x), Value::Bool(y)) => x == y,
        (Value::Text(x), Value::Text(y)) => x == y,
        (Value::Uuid(x), Value::Uuid(y)) => x == y,
        _ => false,
    }
}

/// The value a condition compares `field` with, in the field's own type.
fn cond_value(entity: &IrEntity, field: &str, v: &IrCondValue, subject: &str) -> Option<Value> {
    let f = entity.field(field)?;
    Some(match (v, &f.ty) {
        (IrCondValue::Bool(b), _) => Value::Bool(*b),
        (IrCondValue::Int(i), _) => Value::Int64(*i),
        (IrCondValue::Text(s), FieldType::Uuid) => Value::Uuid(parse_uuid(s)?),
        (IrCondValue::Text(s), _) => Value::Text(s.clone()),
        (IrCondValue::Subject, FieldType::Uuid) => Value::Uuid(parse_uuid(subject)?),
        (IrCondValue::Subject, _) => Value::Text(subject.to_owned()),
    })
}

/// Whether a condition holds for a value being written. `None`: cannot be evaluated, so
/// the grant is unusable.
fn cond_holds_for(entity: &IrEntity, g: &Grant, c: &IrCondition, written: &Value) -> Option<bool> {
    let mut any = false;
    for v in &c.values {
        let expected = cond_value(entity, &c.field, v, &g.subject)?;
        any |= value_eq(written, &expected);
    }
    Some(match c.cmp {
        IrCmp::Eq | IrCmp::In => any,
        IrCmp::Ne => !any,
    })
}

/// The conditions of a grant that still have to be checked against stored rows, after
/// the ones on fields being written have been settled against the new values. `None`:
/// the grant cannot apply (a written value fails a condition, or a value is unusable).
fn pending_conds<'a>(
    entity: &IrEntity,
    g: &'a Grant,
    written: &[(String, Value)],
) -> Option<Vec<&'a IrCondition>> {
    let mut pending = Vec::new();
    for c in &g.conds {
        match written.iter().find(|(n, _)| *n == c.field) {
            Some((_, v)) => {
                if !cond_holds_for(entity, g, c, v)? {
                    return None;
                }
            }
            None => pending.push(c),
        }
    }
    // An owner rule needs a subject that is a uuid.
    if g.owner.as_deref().is_some_and(|s| parse_uuid(s).is_none()) {
        return None;
    }
    if g.via.is_some() && parse_uuid(&g.subject).is_none() {
        return None;
    }
    Some(pending)
}

/// A relationship rule as nested `EXISTS`: each step finds the related row by the id in
/// this row's column, and the last one must be owned by the caller. A related row that is
/// soft deleted, or in another tenant, does not count.
fn via_sql(base: &str, g: &Grant, via: &Via, b: &mut Builder) -> Option<String> {
    let related = &via.related;
    let subject = parse_uuid(&g.subject)?;
    let tenant = if related.tenant_scoped {
        Some(parse_uuid(via.tenant.as_deref()?)?)
    } else {
        None
    };
    let mut open = String::new();
    let mut close = String::new();
    let mut outer = q(base);
    for (i, hop) in related.hops.iter().enumerate() {
        let alias = format!("r{}", i + 1);
        let mut on = format!("{alias}.{} = {outer}.{}", q("id"), q(&hop.column));
        if let Some(t) = tenant {
            let p = b.bind(Value::Uuid(t));
            on.push_str(&format!(" AND {alias}.{} = {p}", q("tenant_id")));
        }
        if hop.soft_delete {
            on.push_str(&format!(" AND {alias}.{} IS NULL", q("deleted_at")));
        }
        open.push_str(&format!(
            "EXISTS (SELECT 1 FROM {} AS {alias} WHERE {on} AND ",
            q(&hop.table)
        ));
        close.push(')');
        outer = alias;
    }
    let p = b.bind(Value::Uuid(subject));
    Some(format!(
        "{open}{outer}.{} = {p}{close}",
        q(&related.owner_column)
    ))
}

/// SQL for the row conditions of one grant.
fn grant_sql(
    entity: &IrEntity,
    g: &Grant,
    pending: &[&IrCondition],
    b: &mut Builder,
) -> Option<String> {
    let mut parts = Vec::new();
    if let Some(subject) = &g.owner {
        let owner = entity.owner.as_deref()?;
        let p = b.bind(Value::Uuid(parse_uuid(subject)?));
        parts.push(format!("{} = {p}", q(owner)));
    }
    if let Some(via) = &g.via {
        parts.push(via_sql(&entity.table, g, via, b)?);
    }
    for c in pending {
        let col = q(&c.field);
        let mut ps = Vec::new();
        for v in &c.values {
            ps.push(b.bind(cond_value(entity, &c.field, v, &g.subject)?));
        }
        parts.push(match c.cmp {
            IrCmp::Eq => format!("{col} = {}", ps.first()?),
            IrCmp::Ne => format!("{col} <> {}", ps.first()?),
            IrCmp::In => format!("{col} IN ({})", ps.join(", ")),
        });
    }
    Some(format!("({})", parts.join(" AND ")))
}

/// The row condition for a set of grants: `Ok(None)` if they reach every row, `Err(())`
/// if none can apply (run nothing). `written` are the values a write sets: conditions on
/// those fields are checked against the new values instead of the stored ones.
#[allow(clippy::result_unit_err)]
fn grants_predicate(
    entity: &IrEntity,
    grants: &[&Grant],
    written: &[(String, Value)],
    b: &mut Builder,
) -> std::result::Result<Option<String>, ()> {
    let usable: Vec<(&Grant, Vec<&IrCondition>)> = grants
        .iter()
        .filter_map(|g| pending_conds(entity, g, written).map(|p| (*g, p)))
        .collect();
    if usable.is_empty() {
        return Err(());
    }
    if usable
        .iter()
        .any(|(g, pending)| g.owner.is_none() && g.via.is_none() && pending.is_empty())
    {
        return Ok(None);
    }
    let alts: Vec<String> = usable
        .iter()
        .filter_map(|(g, pending)| grant_sql(entity, g, pending, b))
        .collect();
    if alts.is_empty() {
        return Err(());
    }
    Ok(Some(format!("({})", alts.join(" OR "))))
}

/// The columns to return. A field that every grant allows is plain. A field that only
/// some grants allow is returned only for rows those grants reach; otherwise it is NULL.
fn select_list(entity: &IrEntity, access: &Access, b: &mut Builder) -> String {
    let Access::Grants(grants) = access else {
        return columns(entity);
    };
    entity
        .fields
        .iter()
        .map(|f| {
            let col = q(&f.name);
            if grants.iter().all(|g| g.allows_field(f)) {
                return col;
            }
            let allowing: Vec<&Grant> = grants.iter().filter(|g| g.allows_field(f)).collect();
            match grants_predicate(entity, &allowing, &[], b) {
                Ok(None) => col,
                Ok(Some(pred)) => format!("CASE WHEN {pred} THEN {col} END AS {col}"),
                Err(()) => format!("NULL AS {col}"),
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn unreadable(what: &'static str, f: &str) -> Error {
    // The same words as for a field that does not exist, so the answer reveals nothing.
    let message = match what {
        "invalid_filter" => format!("cannot filter on unknown field `{f}`"),
        "invalid_sort" => format!("cannot sort by unknown field `{f}`"),
        _ => format!("unknown field `{f}`"),
    };
    Error::invalid_input(what, message)
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
    match ir.app.tenancy {
        Tenancy::Row => {
            let tenant = parse_uuid(scope.tenant.as_deref()?)?;
            let p = b.bind(Value::Uuid(tenant));
            conds.push(format!("{} = {p}", q("tenant_id")));
        }
        // The tenant's rows are in a database of their own, chosen by the runtime. A
        // caller with no tenant has no database to reach.
        Tenancy::Database => {
            scope.tenant.as_deref().filter(|t| !t.is_empty())?;
        }
        Tenancy::None => {}
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
        Access::Grants(grants) => {
            let all: Vec<&Grant> = grants.iter().collect();
            match grants_predicate(entity, &all, &[], b) {
                Ok(None) => {}
                Ok(Some(p)) => conds.push(p),
                Err(()) => return None,
            }
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
    let list = select_list(entity, access, &mut b);
    let sql = format!(
        "SELECT {list} FROM {} WHERE {}",
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
        // A field the caller cannot read in every visible row is not a field they may
        // filter on: the rows that come back would reveal its values.
        if let Some(field) = entity.field(&f.field)
            && !access.reads_everywhere(field)
        {
            return Err(unreadable("invalid_filter", &f.field));
        }
        check_filter(entity, dialect, f)?;
    }
    for k in &query.sort {
        if let Some(field) = entity.field(&k.field)
            && !access.reads_everywhere(field)
        {
            return Err(unreadable("invalid_sort", &k.field));
        }
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
    let list = select_list(entity, access, &mut b);
    // An unrestricted caller on an app without tenancy or soft delete has no condition.
    let filter = if conds.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", conds.join(" AND "))
    };
    let sql = format!(
        "SELECT {list} FROM {}{filter} ORDER BY {} LIMIT {fetch}",
        q(&entity.table),
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
        ir,
        entity,
        access,
        scope,
        dialect,
    } = req;
    if access.is_denied() {
        return Ok(None);
    }
    if ir.app.tenancy == Tenancy::Database && scope.tenant.as_deref().is_none_or(str::is_empty) {
        return Ok(None);
    }
    for (name, _) in input {
        let f = declared(entity, name)?;
        if !access.writes(f) {
            return Err(unreadable("invalid_field", name));
        }
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
    let mut written: Vec<(String, Value)> = Vec::new();
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
        written.push((f.name.clone(), value.clone()));
        cols.push(q(&f.name));
        vals.push(b.bind(value));
    }
    // The new row must be one a rule lets the caller create: some grant's conditions
    // hold for the values being written.
    if let Access::Grants(grants) = access {
        let admitted = grants
            .iter()
            .any(|g| pending_conds(entity, g, &written).is_some_and(|p| p.is_empty()));
        if !admitted {
            return Err(Error::forbidden());
        }
    }
    let list = select_list(entity, access, &mut b);
    let sql = format!(
        "INSERT INTO {} ({}) VALUES ({}) RETURNING {list}",
        q(&entity.table),
        cols.join(", "),
        vals.join(", ")
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
    if access.is_denied() {
        return Ok(None);
    }
    let mut b = Builder::new(dialect);
    let mut sets = Vec::new();
    for (name, value) in changes {
        let f = declared(entity, name)?;
        if !access.writes(f) {
            return Err(unreadable("invalid_field", name));
        }
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
    // The row after the update must still be one a rule reaches (like a WITH CHECK). The
    // conditions on fields being changed are settled against the new values.
    if let Access::Grants(grants) = access {
        let touches = grants.iter().any(|g| {
            g.conds
                .iter()
                .any(|c| changes.iter().any(|(n, _)| *n == c.field))
        });
        if touches {
            let all: Vec<&Grant> = grants.iter().collect();
            match grants_predicate(entity, &all, changes, &mut b) {
                Ok(None) => {}
                Ok(Some(p)) => conds.push(p),
                Err(()) => return Err(Error::forbidden()),
            }
        }
    }
    let list = select_list(entity, access, &mut b);
    let sql = format!(
        "UPDATE {} SET {} WHERE {} RETURNING {list}",
        q(&entity.table),
        sets.join(", "),
        conds.join(" AND ")
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

// ------------------------------------------------------------------ level 2 queries

/// Most rows a query returns. One more is fetched, so the caller can tell it was cut.
pub const QUERY_MAX_ROWS: u32 = 1000;

/// What a level 2 query needs to run for one caller.
pub struct QueryCall<'a> {
    pub ir: &'a Ir,
    pub query: &'a falak_contracts::ir::IrQuery,
    pub dialect: Dialect,
    /// For each entity the query reads: the caller's read access to it.
    pub accesses: &'a [(&'a IrEntity, Access)],
    pub scope: &'a Scope,
    /// A value for each declared parameter.
    pub args: &'a [(String, Value)],
}

/// The statement for a level 2 query. Every entity the query reads becomes a CTE of the
/// same name that applies the tenant, soft-delete, policy and field-mask conditions a
/// generated read would, so the developer's SQL sees only what the caller could read
/// through the API. An entity the caller cannot read is an empty set, not an error.
/// The parameters are bound, in the order the SQL uses them.
pub fn query(call: QueryCall) -> Result<Statement> {
    let QueryCall {
        ir,
        query,
        dialect,
        accesses,
        scope,
        args,
    } = call;
    let mut b = Builder::new(dialect);
    let mut ctes = Vec::new();
    for (entity, access) in accesses {
        let table = q(&entity.table);
        let body = if access.is_denied() {
            format!("SELECT {} FROM {table} WHERE 1 = 0", columns(entity))
        } else {
            let list = select_list(entity, access, &mut b);
            match base_conditions(ir, entity, access, scope, &mut b) {
                Some(conds) if conds.is_empty() => format!("SELECT {list} FROM {table}"),
                Some(conds) => format!("SELECT {list} FROM {table} WHERE {}", conds.join(" AND ")),
                None => format!("SELECT {} FROM {table} WHERE 1 = 0", columns(entity)),
            }
        };
        ctes.push(format!("{} AS ({body})", q(&entity.name)));
    }
    let user_sql = crate::restricted::replace_params(&query.sql, |name| {
        let value = args
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.clone())
            .ok_or_else(|| format!("missing parameter `{name}`"))?;
        Ok(b.bind(value))
    })
    .map_err(|m| Error::invalid_input("invalid_query_parameter", m))?;
    let sql = format!(
        "WITH {} SELECT * FROM ({user_sql}) AS {} LIMIT {}",
        ctes.join(", "),
        q("falak_q"),
        QUERY_MAX_ROWS + 1
    );
    b.finish(sql)
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
