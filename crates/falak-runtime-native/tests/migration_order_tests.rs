//! A table must be created after the tables it references. SQLite does not check a
//! foreign key when the table is made; PostgreSQL does. Notebook's `notes` references
//! `notebooks` and sorts first by name, which broke PostgreSQL until the plan was
//! ordered by reference.

use falak_core::{
    build::build_ir,
    load::{SourceFile, load_project},
    sql::Dialect,
};
use falak_migrate::plan::plan_migration;

fn notebook() -> falak_contracts::ir::Ir {
    let f = |p: &str, t: &str| SourceFile {
        path: p.into(),
        text: t.into(),
    };
    let (project, diags) = load_project(&[
        f(
            "app.yaml",
            include_str!("../../../examples/notebook/app.yaml"),
        ),
        f(
            "entities/note.yaml",
            include_str!("../../../examples/notebook/entities/note.yaml"),
        ),
        f(
            "entities/notebook.yaml",
            include_str!("../../../examples/notebook/entities/notebook.yaml"),
        ),
        f(
            "policies/note.yaml",
            include_str!("../../../examples/notebook/policies/note.yaml"),
        ),
        f(
            "policies/notebook.yaml",
            include_str!("../../../examples/notebook/policies/notebook.yaml"),
        ),
        f(
            "commands/archive_note.yaml",
            include_str!("../../../examples/notebook/commands/archive_note.yaml"),
        ),
        f(
            "commands/restore_note.yaml",
            include_str!("../../../examples/notebook/commands/restore_note.yaml"),
        ),
    ]);
    assert!(diags.is_empty(), "{diags:?}");
    build_ir(&project.unwrap())
}

fn position(statements: &[String], needle: &str) -> usize {
    statements
        .iter()
        .position(|s| s.contains(needle))
        .unwrap_or_else(|| panic!("no statement contains {needle}"))
}

#[test]
fn the_initial_plan_creates_a_referenced_table_first() {
    let ir = notebook();
    for dialect in [Dialect::Sqlite, Dialect::Postgres, Dialect::D1] {
        let plan = plan_migration(None, &ir, dialect);
        let sql: Vec<String> = plan
            .expand_statements()
            .into_iter()
            .map(|s| s.sql.clone())
            .collect();
        let notebooks = position(&sql, "CREATE TABLE IF NOT EXISTS \"notebooks\"");
        let notes = position(&sql, "CREATE TABLE IF NOT EXISTS \"notes\"");
        assert!(notebooks < notes, "{dialect:?}: notebooks must come first");
    }
}

#[test]
fn create_all_agrees() {
    let ir = notebook();
    let sql = falak_core::ddl::create_all(&ir, Dialect::Postgres);
    let notebooks = position(&sql, "CREATE TABLE IF NOT EXISTS \"notebooks\"");
    let notes = position(&sql, "CREATE TABLE IF NOT EXISTS \"notes\"");
    assert!(notebooks < notes);
}
