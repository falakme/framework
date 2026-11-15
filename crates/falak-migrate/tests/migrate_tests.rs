use falak_contracts::{
    driver::{Statement, StorageDriver, Value},
    identity::RequestContext,
};
use falak_core::{
    build::build_ir,
    load::{SourceFile, load_project},
};
use falak_driver_sqlite::SqliteDriver;
use falak_migrate::{MIGRATIONS_TABLE, apply_initial_migration};

fn dummy_context() -> RequestContext {
    RequestContext {
        principal: None,
        request_id: "migrate_test_req".to_string(),
    }
}

fn minimal_files() -> Vec<SourceFile> {
    let f = |p: &str, t: &str| SourceFile {
        path: p.into(),
        text: t.into(),
    };
    vec![
        f(
            "app.yaml",
            include_str!("../../../specifications/examples/minimal/app.yaml"),
        ),
        f(
            "entities/note.yaml",
            include_str!("../../../specifications/examples/minimal/entities/note.yaml"),
        ),
        f(
            "policies/note.yaml",
            include_str!("../../../specifications/examples/minimal/policies/note.yaml"),
        ),
        f(
            "commands/archive_note.yaml",
            include_str!("../../../specifications/examples/minimal/commands/archive_note.yaml"),
        ),
    ]
}

#[tokio::test]
async fn test_initial_migration_creates_tables_and_is_idempotent() {
    let driver = SqliteDriver::in_memory().await.unwrap();
    let ctx = dummy_context();

    // Load and build the minimal project example into IR
    let files = minimal_files();
    let (project_opt, diags) = load_project(&files);
    assert!(
        diags.is_empty(),
        "Loading project produced diagnostics: {diags:?}"
    );
    let project = project_opt.expect("minimal project must load cleanly");
    let ir = build_ir(&project);

    // First migration run: creates tables and returns true
    let applied = apply_initial_migration(&driver, &ctx, &ir).await.unwrap();
    assert!(applied, "Initial migration should apply");

    // Verify _falak_migrations has recorded the migration
    let migration_rows = driver
        .query(
            &ctx,
            Statement::new(
                format!("SELECT version, content_hash FROM \"{MIGRATIONS_TABLE}\";"),
                vec![],
            ),
        )
        .await
        .unwrap();

    assert_eq!(migration_rows.rows.len(), 1);
    assert_eq!(
        migration_rows.rows[0][0],
        Value::Int64(ir.ir_version as i64)
    );
    assert_eq!(
        migration_rows.rows[0][1],
        Value::Text(ir.content_hash.clone())
    );

    // Verify that the entity table `notes` exists and can accept rows
    let insert_note = Statement::new(
        "INSERT INTO notes (id, title, body, archived, owner_id, version, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
        vec![
            Value::Text("note-100".to_string()),
            Value::Text("Test Note".to_string()),
            Value::Text("Testing migrations".to_string()),
            Value::Bool(false),
            Value::Text("018f6c40-1111-7000-8000-000000000001".to_string()),
            Value::Int64(1),
            Value::Int64(1700000000000000),
            Value::Int64(1700000000000000),
        ],
    );
    let outcome = driver.batch(&ctx, vec![insert_note]).await.unwrap();
    assert_eq!(outcome[0].rows_affected, 1);

    // Verify querying the note back
    let query_note = Statement::new(
        "SELECT id, title, archived FROM notes WHERE id = ?;",
        vec![Value::Text("note-100".to_string())],
    );
    let rows = driver.query(&ctx, query_note).await.unwrap();
    assert_eq!(rows.rows.len(), 1);
    assert_eq!(rows.rows[0][1], Value::Text("Test Note".to_string()));

    // Second run with the same IR should detect it's already applied and return false
    let applied_again = apply_initial_migration(&driver, &ctx, &ir).await.unwrap();
    assert!(!applied_again, "Second migration run should be a no-op");
}

#[test]
fn test_schema_diff_and_expand_contract_planning() {
    use falak_core::sql::Dialect;
    use falak_migrate::{Destructiveness, MigrationPhase, diff_ir, plan_migration};

    let files1 = minimal_files();
    let p1 = load_project(&files1).0.unwrap();
    let ir1 = build_ir(&p1);

    // Initial plan: all expand, safe
    let initial_plan = plan_migration(None, &ir1, Dialect::Postgres);
    assert!(!initial_plan.statements.is_empty());
    assert!(!initial_plan.checksum.is_empty());
    assert_eq!(initial_plan.from_hash, None);
    assert_eq!(initial_plan.to_hash, ir1.content_hash);
    assert!(initial_plan.contract_statements().is_empty());
    assert!(!initial_plan.expand_statements().is_empty());

    // Modified app: add a field to note and a new entity tag
    let mut files2 = minimal_files();
    files2.push(SourceFile {
        path: "entities/tag.yaml".into(),
        text: "schema_version: 1\nentity: tag\nowner: owner_id\nfields:\n  name: { type: text, required: true }\n  owner_id: { type: uuid, required: true }\n".into(),
    });
    files2.push(SourceFile {
        path: "policies/tag.yaml".into(),
        text: "schema_version: 1\nentity: tag\nrules:\n  - id: own\n    actions: [read]\n    allow: { owner: true }\n".into(),
    });
    let p2 = load_project(&files2).0.unwrap();
    let ir2 = build_ir(&p2);

    let diffs = diff_ir(Some(&ir1), &ir2);
    assert_eq!(diffs.len(), 1); // New table tag

    let plan2 = plan_migration(Some(&ir1), &ir2, Dialect::Postgres);
    assert!(!plan2.expand_statements().is_empty());
    assert!(plan2.contract_statements().is_empty());

    // Reverse migration: dropping tag
    let plan_reverse = plan_migration(Some(&ir2), &ir1, Dialect::Postgres);
    assert!(!plan_reverse.contract_statements().is_empty());
    let contract = plan_reverse.contract_statements()[0];
    assert_eq!(contract.phase, MigrationPhase::Contract);
    assert_eq!(contract.destructiveness, Destructiveness::Breaking);
}

#[tokio::test]
async fn test_drift_detection_and_history() {
    use falak_core::sql::Dialect;
    use falak_migrate::{MigrationRecord, detect_drift, ensure_history_table, fetch_history};

    let driver = SqliteDriver::in_memory().await.unwrap();
    let ctx = dummy_context();

    ensure_history_table(&driver, &ctx, Dialect::Sqlite)
        .await
        .unwrap();
    let history = fetch_history(&driver, &ctx, Dialect::Sqlite).await.unwrap();
    assert!(history.is_empty());

    let record1 = MigrationRecord {
        version: 1,
        content_hash: "hash_v1".to_string(),
        checksum: "sum_v1".to_string(),
        applied_at: 1000,
    };
    let expected = vec![record1.clone()];

    // Matches
    assert!(detect_drift(std::slice::from_ref(&record1), &expected).is_ok());

    // Mismatched checksum -> drift!
    let drifted_record = MigrationRecord {
        checksum: "sum_tampered".to_string(),
        ..record1.clone()
    };
    let err = detect_drift(&[drifted_record], &expected).unwrap_err();
    assert_eq!(err.code(), "migration_drift");

    // Unexpected extra migration -> drift!
    let extra_record = MigrationRecord {
        version: 2,
        content_hash: "hash_v2".to_string(),
        checksum: "sum_v2".to_string(),
        applied_at: 2000,
    };
    let err2 = detect_drift(&[record1, extra_record], &expected).unwrap_err();
    assert_eq!(err2.code(), "migration_drift");
}
