//! Level 2 SQL: parameterized, read-only statements written by the developer
//! (ARCHITECTURE §4.7, level 2).
//!
//! A query is a named file in the app, checked here with a SQL parser when the app is
//! built, and then fixed in the IR. A request can only run one by name, with bound
//! parameters; it can never supply SQL.
//!
//! * One statement, a `SELECT` (with `WITH`, `UNION` and sub-selects allowed).
//! * No `INTO`, no locking clause, no recursion, no table functions, no comments.
//! * Only functions on a short allow list.
//! * The tables it reads are **entity names**, not table names. At run time each entity
//!   it names becomes a CTE that applies the same tenant, policy and field-mask
//!   conditions as a generated read ([`crate::sql::query`]). So a query sees what its
//!   caller could read through the API, and nothing else: it cannot name a physical
//!   table, the migration history or the system catalogue.
//! * Parameters are written `:name`, declared in the file, and always bound.

use std::ops::ControlFlow;

use sqlparser::{
    ast::{Expr, Query, Select, SetExpr, Statement, TableFactor, Visit, Visitor},
    dialect::GenericDialect,
    parser::Parser,
};

/// Functions a query may call. Nothing that reads files, sleeps, or reaches the system.
pub const ALLOWED_FUNCTIONS: &[&str] = &[
    "abs",
    "avg",
    "ceil",
    "ceiling",
    "char_length",
    "coalesce",
    "concat",
    "count",
    "floor",
    "greatest",
    "least",
    "length",
    "lower",
    "ltrim",
    "max",
    "min",
    "nullif",
    "replace",
    "round",
    "rtrim",
    "substr",
    "substring",
    "sum",
    "trim",
    "upper",
];

/// What the checker learned about a query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checked {
    /// Entities the query reads, sorted.
    pub entities: Vec<String>,
    /// Parameter names the SQL uses, in order of first use.
    pub params: Vec<String>,
}

#[derive(Default)]
struct Collector {
    relations: Vec<String>,
    ctes: Vec<String>,
    problems: Vec<String>,
}

impl Visitor for Collector {
    type Break = ();

    fn pre_visit_query(&mut self, q: &Query) -> ControlFlow<()> {
        if let Some(with) = &q.with {
            if with.recursive {
                self.problems.push("`WITH RECURSIVE` is not allowed".into());
            }
            for c in &with.cte_tables {
                self.ctes.push(c.alias.name.value.to_lowercase());
            }
        }
        if !q.locks.is_empty() {
            self.problems.push("locking clauses are not allowed".into());
        }
        if q.for_clause.is_some() || q.settings.is_some() || q.format_clause.is_some() {
            self.problems.push("this clause is not allowed".into());
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_select(&mut self, s: &Select) -> ControlFlow<()> {
        if s.into.is_some() {
            self.problems
                .push("`SELECT ... INTO` is not allowed".into());
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_table_factor(&mut self, t: &TableFactor) -> ControlFlow<()> {
        match t {
            TableFactor::Table { name, args, .. } => {
                if args.is_some() {
                    self.problems.push("table functions are not allowed".into());
                }
                if name.0.len() != 1 {
                    self.problems.push(format!(
                        "`{name}` is qualified; name the entity only, without a schema"
                    ));
                } else {
                    self.relations
                        .push(name.to_string().trim_matches('"').to_lowercase());
                }
            }
            TableFactor::Derived { .. } | TableFactor::NestedJoin { .. } => {}
            other => self
                .problems
                .push(format!("`{other}` is not allowed in FROM")),
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, e: &Expr) -> ControlFlow<()> {
        if let Expr::Function(f) = e {
            let name = f.name.to_string().to_lowercase();
            if !ALLOWED_FUNCTIONS.contains(&name.as_str()) {
                self.problems
                    .push(format!("the function `{name}` is not allowed"));
            }
        }
        ControlFlow::Continue(())
    }
}

/// Visit `:name` parameters in `sql`, skipping quoted text and `::` casts. `f` returns
/// the replacement. Returns `Err` for anything that could hide a statement: comments.
pub fn replace_params(
    sql: &str,
    mut f: impl FnMut(&str) -> Result<String, String>,
) -> Result<String, String> {
    let chars: Vec<char> = sql.chars().collect();
    let mut out = String::with_capacity(sql.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match c {
            '\'' | '"' => {
                // Copy a quoted run. A doubled quote is an escaped quote.
                out.push(c);
                i += 1;
                while i < chars.len() {
                    out.push(chars[i]);
                    if chars[i] == c {
                        if chars.get(i + 1) == Some(&c) {
                            i += 1;
                            out.push(c);
                        } else {
                            break;
                        }
                    }
                    i += 1;
                }
                i += 1;
            }
            '-' if chars.get(i + 1) == Some(&'-') => {
                return Err("comments are not allowed in a query".into());
            }
            '/' if chars.get(i + 1) == Some(&'*') => {
                return Err("comments are not allowed in a query".into());
            }
            ':' if chars.get(i + 1) == Some(&':') => {
                out.push_str("::");
                i += 2;
            }
            ':' if chars
                .get(i + 1)
                .is_some_and(|n| n.is_ascii_alphabetic() || *n == '_') =>
            {
                let start = i + 1;
                let mut end = start;
                while end < chars.len() && (chars[end].is_ascii_alphanumeric() || chars[end] == '_')
                {
                    end += 1;
                }
                let name: String = chars[start..end].iter().collect();
                out.push_str(&f(&name)?);
                i = end;
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    Ok(out)
}

/// Check a query's SQL against the entities the app declares and the parameters the
/// file declares. Every problem found is returned.
pub fn check(
    sql: &str,
    entity_names: &[&str],
    declared_params: &[&str],
) -> Result<Checked, Vec<String>> {
    let mut problems = Vec::new();
    let mut used: Vec<String> = Vec::new();
    // Parse with each parameter standing in as the number 1.
    let probe = match replace_params(sql, |name| {
        if !declared_params.contains(&name) {
            return Err(format!(
                "the query uses `:{name}`, which `params` does not declare"
            ));
        }
        if !used.iter().any(|u| u == name) {
            used.push(name.to_owned());
        }
        Ok("1".to_owned())
    }) {
        Ok(p) => p,
        Err(e) => return Err(vec![e]),
    };
    for d in declared_params {
        if !used.iter().any(|u| u == d) {
            problems.push(format!("the parameter `{d}` is declared but not used"));
        }
    }

    let statements = match Parser::parse_sql(&GenericDialect {}, &probe) {
        Ok(s) => s,
        Err(e) => {
            problems.push(format!("the SQL does not parse: {e}"));
            return Err(problems);
        }
    };
    if statements.len() != 1 {
        problems.push("a query must be exactly one statement".into());
        return Err(problems);
    }
    let Statement::Query(query) = &statements[0] else {
        problems.push("a query must be a SELECT".into());
        return Err(problems);
    };
    if !matches!(
        *query.body,
        SetExpr::Select(_) | SetExpr::SetOperation { .. } | SetExpr::Query(_)
    ) {
        problems.push("a query must be a SELECT".into());
    }

    let mut collector = Collector::default();
    let _ = query.visit(&mut collector);
    problems.append(&mut collector.problems);

    let mut entities: Vec<String> = Vec::new();
    for rel in &collector.relations {
        if collector.ctes.contains(rel) {
            continue;
        }
        if entity_names.iter().any(|e| e.eq_ignore_ascii_case(rel)) {
            let name = entity_names
                .iter()
                .find(|e| e.eq_ignore_ascii_case(rel))
                .map(|e| (*e).to_owned())
                .unwrap_or_default();
            if !entities.contains(&name) {
                entities.push(name);
            }
        } else {
            problems.push(format!(
                "`{rel}` is not an entity of this app (a query reads entities by name, not tables)"
            ));
        }
    }
    entities.sort();
    if entities.is_empty() && problems.is_empty() {
        problems.push("a query must read at least one entity".into());
    }
    if problems.is_empty() {
        Ok(Checked {
            entities,
            params: used,
        })
    } else {
        problems.sort();
        problems.dedup();
        Err(problems)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENTITIES: &[&str] = &["doc", "tag"];

    fn ok(sql: &str, params: &[&str]) -> Checked {
        check(sql, ENTITIES, params).unwrap_or_else(|p| panic!("{p:?}"))
    }

    fn err(sql: &str, params: &[&str]) -> String {
        check(sql, ENTITIES, params).unwrap_err().join("; ")
    }

    #[test]
    fn a_plain_select_with_a_parameter_passes() {
        let c = ok(
            "SELECT title, COUNT(*) AS n FROM doc WHERE status = :status GROUP BY title ORDER BY title",
            &["status"],
        );
        assert_eq!(c.entities, ["doc"]);
        assert_eq!(c.params, ["status"]);
    }

    #[test]
    fn joins_unions_and_ctes_over_entities_pass() {
        let c = ok(
            "WITH p AS (SELECT id FROM doc WHERE title = :t) SELECT tag.name FROM tag JOIN p ON p.id = tag.doc_id UNION SELECT title FROM doc",
            &["t"],
        );
        assert_eq!(c.entities, ["doc", "tag"]);
    }

    #[test]
    fn writes_and_several_statements_are_refused() {
        assert!(err("DELETE FROM doc", &[]).contains("SELECT"));
        assert!(err("UPDATE doc SET title = 'x'", &[]).contains("SELECT"));
        assert!(err("SELECT 1 FROM doc; DROP TABLE docs", &[]).contains("exactly one"));
        assert!(err("INSERT INTO doc VALUES (1)", &[]).contains("SELECT"));
    }

    #[test]
    fn physical_tables_and_the_catalogue_are_refused() {
        assert!(err("SELECT * FROM docs", &[]).contains("not an entity"));
        assert!(err("SELECT * FROM _falak_migrations", &[]).contains("not an entity"));
        assert!(err("SELECT * FROM sqlite_master", &[]).contains("not an entity"));
        assert!(err("SELECT * FROM pg_catalog.pg_tables", &[]).contains("qualified"));
        assert!(err("SELECT * FROM main.doc", &[]).contains("qualified"));
    }

    #[test]
    fn dangerous_features_are_refused() {
        assert!(err("SELECT pg_sleep(10) FROM doc", &[]).contains("not allowed"));
        assert!(err("SELECT load_extension('x') FROM doc", &[]).contains("not allowed"));
        assert!(err("SELECT * FROM doc FOR UPDATE", &[]).contains("locking"));
        assert!(err("SELECT * INTO copy FROM doc", &[]).contains("INTO"));
        assert!(err("SELECT * FROM generate_series(1, 10)", &[]).contains("not allowed"));
        assert!(
            err(
                "WITH RECURSIVE r AS (SELECT 1 FROM doc) SELECT * FROM r",
                &[]
            )
            .contains("RECURSIVE")
        );
        assert!(err("SELECT 1 FROM doc -- hi", &[]).contains("comments"));
        assert!(err("SELECT /* x */ 1 FROM doc", &[]).contains("comments"));
    }

    #[test]
    fn parameters_must_match_the_declaration() {
        assert!(err("SELECT 1 FROM doc WHERE a = :a", &[]).contains("does not declare"));
        assert!(err("SELECT 1 FROM doc", &["a"]).contains("not used"));
    }

    #[test]
    fn a_colon_inside_text_or_a_cast_is_not_a_parameter() {
        let c = ok(
            "SELECT ':a' AS x, id::text FROM doc WHERE title = :t",
            &["t"],
        );
        assert_eq!(c.params, ["t"]);
    }

    #[test]
    fn an_injected_quote_cannot_hide_a_statement() {
        // Parameters are never spliced into the text, but the text itself is checked.
        let problems = err(
            "SELECT 1 FROM doc WHERE title = 'x'; DELETE FROM doc --'",
            &[],
        );
        assert!(!problems.is_empty());
    }
}
