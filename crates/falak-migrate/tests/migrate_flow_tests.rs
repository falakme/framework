//! `migrate`: changing an app that already has data (T3.6, T3.8).

use falak_contracts::{
    driver::{Statement, StorageDriver, Value},
    identity::RequestContext,
    ir::Ir,
};
use falak_core::{
    build::build_ir,
    load::{SourceFile, load_project},
    sql::Dialect,
};
use falak_driver_sqlite::SqliteDriver;
use falak_migrate::{MigrateOptions, migrate, plan_migration};

const APP: &str = "schema_version: 1\nname: docs\nversion: 0.1.0\ntenancy: none\ntrust_tier: standard\ndrivers: [sqlite, postgres, d1]\n";
const POLICY: &str = "schema_version: 1\nentity: doc\nrules:\n  - id: any\n    actions: [read]\n    allow: { authenticated: true }\n";
const TAGS: &str = "schema_version: 1\nentity: tag\nfields:\n  name: { type: text, required: true }\n  doc_id: { type: uuid, required: true, references: doc.id }\n";
const TAG_POLICY: &str = "schema_version: 1\nentity: tag\nrules:\n  - id: any\n    actions: [read]\n    allow: { authenticated: true }\n";

fn ir(doc_fields: &str) -> Ir {
    let entity = format!("schema_version: 1\nentity: doc\nfields:\n{doc_fields}");
    let f = |p: &str, t: &str| SourceFile {
        path: p.into(),
        text: t.into(),
    };
    let (project, diags) = load_project(&[
        f("app.yaml", APP),
        f("entities/doc.yaml", &entity),
        f("policies/doc.yaml", POLICY),
        f("entities/tag.yaml", TAGS),
        f("policies/tag.yaml", TAG_POLICY),
    ]);
    assert!(!falak_core::diagnostics::has_errors(&diags), "{diags:?}");
    build_ir(&project.unwrap())
}

const V1: &str = "  title: { type: text, required: true, max_length: 200, indexed: true }\n  legacy: { type: text }\n";
fn ctx() -> RequestContext {
    RequestContext {
        principal: None,
        request_id: "t".into(),
    }
}

async fn db() -> SqliteDriver {
    SqliteDriver::in_memory().await.unwrap()
}

async fn count(db: &SqliteDriver, sql: &str) -> i64 {
    let rows = db.query(&ctx(), Statement::new(sql, vec![])).await.unwrap();
    match rows.rows[0][0] {
        Value::Int64(n) => n,
        ref other => panic!("not a count: {other:?}"),
    }
}

async fn seed(db: &SqliteDriver) {
    db.batch(
        &ctx(),
        vec![Statement::new(
            "INSERT INTO \"docs\" (\"id\",\"title\",\"legacy\",\"version\",\"created_at\",\"updated_at\") VALUES ('d1','hello','x',1,0,0)",
            vec![],
        )],
    )
    .await
    .unwrap();
}

fn safe() -> MigrateOptions {
    MigrateOptions::default()
}
fn any() -> MigrateOptions {
    MigrateOptions {
        allow_destructive: true,
    }
}

#[tokio::test]
async fn the_same_version_twice_is_a_no_op() {
    let db = db().await;
    let v1 = ir(V1);
    assert!(migrate(&db, &ctx(), &v1, safe()).await.unwrap().applied);
    assert!(!migrate(&db, &ctx(), &v1, safe()).await.unwrap().applied);
}

#[tokio::test]
async fn an_optional_column_is_added_in_place_and_keeps_the_data() {
    let db = db().await;
    migrate(&db, &ctx(), &ir(V1), safe()).await.unwrap();
    seed(&db).await;
    let v2 = ir(&format!("{V1}  note: {{ type: text }}\n"));
    let out = migrate(&db, &ctx(), &v2, safe()).await.unwrap();
    assert!(out.applied);
    assert!(
        out.plan
            .statements
            .iter()
            .any(|s| s.sql.contains("ADD COLUMN \"note\""))
    );
    assert_eq!(
        count(&db, "SELECT COUNT(*) FROM docs WHERE title = 'hello'").await,
        1
    );
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM pragma_table_info('docs') WHERE name = 'note'"
        )
        .await,
        1
    );
}

#[tokio::test]
async fn a_required_column_with_a_default_fills_existing_rows() {
    let db = db().await;
    migrate(&db, &ctx(), &ir(V1), safe()).await.unwrap();
    seed(&db).await;
    let v2 = ir(&format!(
        "{V1}  status: {{ type: text, required: true, default: draft }}\n"
    ));
    migrate(&db, &ctx(), &v2, safe()).await.unwrap();
    assert_eq!(
        count(&db, "SELECT COUNT(*) FROM docs WHERE status = 'draft'").await,
        1
    );
}

#[tokio::test]
async fn a_required_column_with_no_default_cannot_be_planned() {
    let db = db().await;
    migrate(&db, &ctx(), &ir(V1), safe()).await.unwrap();
    let v2 = ir(&format!("{V1}  status: {{ type: text, required: true }}\n"));
    let err = migrate(&db, &ctx(), &v2, safe()).await.err().unwrap();
    assert_eq!(err.code(), "migration_unsupported");
}

#[tokio::test]
async fn a_changed_column_rebuilds_the_table_only_when_allowed() {
    let db = db().await;
    migrate(&db, &ctx(), &ir(V1), safe()).await.unwrap();
    seed(&db).await;
    let v2 = ir(
        "  title: { type: text, required: true, max_length: 50, indexed: true }\n  legacy: { type: text }\n",
    );
    let err = migrate(&db, &ctx(), &v2, safe()).await.err().unwrap();
    assert_eq!(err.code(), "migration_needs_approval");
    assert_eq!(count(&db, "SELECT COUNT(*) FROM docs").await, 1);

    let out = migrate(&db, &ctx(), &v2, any()).await.unwrap();
    assert!(out.applied);
    assert!(
        out.plan
            .statements
            .iter()
            .any(|s| s.sql.contains("__rebuild"))
    );
    // The rows, the index and the tables that reference this one all survive.
    assert_eq!(
        count(&db, "SELECT COUNT(*) FROM docs WHERE title = 'hello'").await,
        1
    );
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'idx_docs_title'"
        )
        .await,
        1
    );
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM sqlite_master WHERE name = 'docs__rebuild'"
        )
        .await,
        0
    );
}

#[tokio::test]
async fn a_rebuild_that_does_not_fit_the_data_rolls_back() {
    let db = db().await;
    migrate(&db, &ctx(), &ir(V1), safe()).await.unwrap();
    db.batch(
        &ctx(),
        vec![Statement::new(
            format!(
                "INSERT INTO \"docs\" (\"id\",\"title\",\"version\",\"created_at\",\"updated_at\") VALUES ('long','{}',1,0,0)",
                "x".repeat(100)
            ),
            vec![],
        )],
    )
    .await
    .unwrap();
    let v2 = ir(
        "  title: { type: text, required: true, max_length: 50, indexed: true }\n  legacy: { type: text }\n",
    );
    assert!(migrate(&db, &ctx(), &v2, any()).await.is_err());
    // Nothing changed: the old table, its row, and the old version still recorded.
    assert_eq!(count(&db, "SELECT COUNT(*) FROM docs").await, 1);
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM sqlite_master WHERE name = 'docs__rebuild'"
        )
        .await,
        0
    );
}

#[tokio::test]
async fn dropping_a_column_needs_approval() {
    let db = db().await;
    migrate(&db, &ctx(), &ir(V1), safe()).await.unwrap();
    seed(&db).await;
    let v2 = ir("  title: { type: text, required: true, max_length: 200, indexed: true }\n");
    assert_eq!(
        migrate(&db, &ctx(), &v2, safe())
            .await
            .err()
            .unwrap()
            .code(),
        "migration_needs_approval"
    );
    migrate(&db, &ctx(), &v2, any()).await.unwrap();
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM pragma_table_info('docs') WHERE name = 'legacy'"
        )
        .await,
        0
    );
    assert_eq!(count(&db, "SELECT COUNT(*) FROM docs").await, 1);
}

#[test]
fn postgres_changes_a_type_in_place_and_d1_rebuilds() {
    let a = ir(V1);
    let b = ir(
        "  title: { type: text, required: true, max_length: 200, indexed: true }\n  legacy: { type: int64 }\n",
    );
    let pg = plan_migration(Some(&a), &b, Dialect::Postgres);
    assert!(
        pg.statements
            .iter()
            .any(|s| s.sql.contains("ALTER COLUMN \"legacy\" TYPE bigint")),
        "{:?}",
        pg.statements
    );
    let d1 = plan_migration(Some(&a), &b, Dialect::D1);
    assert!(d1.statements.iter().any(|s| s.sql.contains("__rebuild")));
    assert!(
        d1.statements
            .iter()
            .any(|s| s.sql.starts_with("PRAGMA defer_foreign_keys"))
    );
}
