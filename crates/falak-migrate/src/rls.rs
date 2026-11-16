//! PostgreSQL row-level security, generated from the same policies the runtime applies
//! in SQL (ARCHITECTURE §4.7).
//!
//! RLS is the second wall. The statements the runtime builds already carry the tenant
//! and policy predicates; these policies make the database refuse a row to a caller who
//! should not have it even if a statement were wrong.
//!
//! * `ENABLE` and `FORCE ROW LEVEL SECURITY` on every entity table, so the table owner
//!   is held to the policies too.
//! * One permissive policy per action, the OR of the rules that list it: default deny
//!   when no rule does. Under `row` tenancy, a restrictive tenant policy is ANDed on top
//!   of every action.
//! * `USING` and `WITH CHECK` where the action reads or writes rows.
//! * The caller comes from per-transaction settings the driver sets with
//!   `set_config(..., true)`: `falak.subject`, `falak.tenant_id`, `falak.roles`. Missing
//!   or empty settings give NULL, and NULL denies.
//! * No `SECURITY DEFINER` anywhere.
//! * A runtime role, `falak_app`, with no `BYPASSRLS` and no ownership, holding only
//!   data privileges on the entity tables.
//!
//! RLS works on rows. Field masks are enforced by the runtime's SQL, not here.

use falak_contracts::ir::{
    FieldType, Ir, IrAction, IrAllow, IrCmp, IrCondValue, IrCondition, IrEntity, IrRule, Tenancy,
};

/// The role the runtime connects as. It owns nothing and cannot bypass RLS.
pub const RUNTIME_ROLE: &str = "falak_app";

fn q(s: &str) -> String {
    format!("\"{s}\"")
}

fn lit(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

const SUBJECT: &str = "NULLIF(current_setting('falak.subject', true), '')";
const TENANT: &str = "NULLIF(current_setting('falak.tenant_id', true), '')";

fn value(entity: &IrEntity, field: &str, v: &IrCondValue) -> String {
    let uuid = entity.field(field).is_some_and(|f| f.ty == FieldType::Uuid);
    match v {
        IrCondValue::Bool(b) => b.to_string(),
        IrCondValue::Int(i) => i.to_string(),
        IrCondValue::Text(s) if uuid => format!("{}::uuid", lit(s)),
        IrCondValue::Text(s) => lit(s),
        IrCondValue::Subject if uuid => format!("{SUBJECT}::uuid"),
        IrCondValue::Subject => SUBJECT.to_owned(),
    }
}

fn cond(entity: &IrEntity, c: &IrCondition) -> String {
    let col = q(&c.field);
    let vals: Vec<String> = c
        .values
        .iter()
        .map(|v| value(entity, &c.field, v))
        .collect();
    match c.cmp {
        IrCmp::Eq => format!("{col} = {}", vals[0]),
        IrCmp::Ne => format!("{col} <> {}", vals[0]),
        IrCmp::In => format!("{col} IN ({})", vals.join(", ")),
    }
}

fn rule_expr(entity: &IrEntity, rule: &IrRule) -> Option<String> {
    let mut parts = vec![match &rule.allow {
        IrAllow::Authenticated => format!("{SUBJECT} IS NOT NULL"),
        IrAllow::Role(r) => format!(
            "{} = ANY (string_to_array(COALESCE(current_setting('falak.roles', true), ''), ','))",
            lit(r)
        ),
        IrAllow::Owner => {
            let owner = entity.owner.as_deref()?;
            format!("{} = {SUBJECT}::uuid", q(owner))
        }
    }];
    parts.extend(rule.when.iter().map(|c| cond(entity, c)));
    Some(format!("({})", parts.join(" AND ")))
}

/// The rules that give a statement its rows. PostgreSQL applies the `SELECT` policy to
/// the rows an `UPDATE`, `DELETE` or `INSERT ... RETURNING` finds or returns, so the
/// `SELECT` policy covers a rule that grants any of these actions. The runtime's own
/// SQL still limits reads to rules that list `read`.
fn action_expr(entity: &IrEntity, action: IrAction) -> Option<String> {
    let alts: Vec<String> = entity
        .policy
        .rules
        .iter()
        .filter(|r| action == IrAction::Read || r.actions.contains(&action))
        .filter(|r| action != IrAction::Read || !r.actions.is_empty())
        .filter_map(|r| rule_expr(entity, r))
        .collect();
    (!alts.is_empty()).then(|| alts.join(" OR "))
}

/// The statements that put RLS and the runtime role on every entity table. Safe to run
/// again: policies are dropped and recreated, grants repeat.
pub fn rls_statements(ir: &Ir) -> Vec<String> {
    let mut out = vec![
        format!(
            "DO $falak$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{RUNTIME_ROLE}') THEN CREATE ROLE {RUNTIME_ROLE} NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE; END IF; END $falak$"
        ),
        format!("GRANT USAGE ON SCHEMA public TO {RUNTIME_ROLE}"),
        // Identity and idempotency tables, which the runtime creates before the app's.
        format!(
            "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {RUNTIME_ROLE}"
        ),
        // The event outbox numbers its rows with a sequence.
        format!("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {RUNTIME_ROLE}"),
        // The runtime never touches the migration history.
        format!("REVOKE ALL ON \"_falak_migrations\", \"_falak_schema\" FROM {RUNTIME_ROLE}"),
    ];
    let tenant_scoped = ir.app.tenancy == Tenancy::Row;
    for e in &ir.entities {
        let t = q(&e.table);
        out.push(format!("ALTER TABLE {t} ENABLE ROW LEVEL SECURITY"));
        out.push(format!("ALTER TABLE {t} FORCE ROW LEVEL SECURITY"));
        out.push(format!(
            "GRANT SELECT, INSERT, UPDATE, DELETE ON {t} TO {RUNTIME_ROLE}"
        ));

        out.push(format!(
            "DROP POLICY IF EXISTS {} ON {t}",
            q("falak_tenant")
        ));
        if tenant_scoped {
            let same = format!("{} = {TENANT}::uuid", q("tenant_id"));
            out.push(format!(
                "CREATE POLICY {} ON {t} AS RESTRICTIVE FOR ALL USING ({same}) WITH CHECK ({same})",
                q("falak_tenant")
            ));
        }
        for (name, action, kind) in [
            ("falak_read", IrAction::Read, "SELECT"),
            ("falak_create", IrAction::Create, "INSERT"),
            ("falak_update", IrAction::Update, "UPDATE"),
            ("falak_delete", IrAction::Delete, "DELETE"),
        ] {
            out.push(format!("DROP POLICY IF EXISTS {} ON {t}", q(name)));
            let Some(expr) = action_expr(e, action) else {
                continue; // No rule: default deny, with no permissive policy.
            };
            let checks = match kind {
                "SELECT" | "DELETE" => format!("USING ({expr})"),
                "INSERT" => format!("WITH CHECK ({expr})"),
                _ => format!("USING ({expr}) WITH CHECK ({expr})"),
            };
            out.push(format!(
                "CREATE POLICY {} ON {t} AS PERMISSIVE FOR {kind} {checks}",
                q(name)
            ));
        }
    }
    out
}

/// SQL that returns the tables of the app that are missing RLS or FORCE: a conformance
/// check. An empty result means every entity table is protected.
pub fn unprotected_tables_sql(ir: &Ir) -> String {
    let names: Vec<String> = ir.entities.iter().map(|e| lit(&e.table)).collect();
    format!(
        "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = 'public' AND c.relname IN ({}) \
         AND NOT (c.relrowsecurity AND c.relforcerowsecurity)",
        names.join(", ")
    )
}
