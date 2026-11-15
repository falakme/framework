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
