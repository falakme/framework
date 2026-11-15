//! Integration test verifying Litestream backup and restore for Notebook (T1.9).
//! "Works when: a restore from the Litestream replica brings back the Notebook data."

use std::{path::PathBuf, process::Command, time::Duration};

use falak_contracts::{
    driver::{Statement, StorageDriver, Value},
    identity::RequestContext,
};
use falak_core::{
    build::build_ir,
    load::{SourceFile, load_project},
};
use falak_driver_sqlite::{SqliteConfig, SqliteDriver};
use falak_migrate::apply_initial_migration;

fn find_litestream() -> Option<PathBuf> {
    if let Ok(output) = Command::new("which").arg("litestream").output()
        && output.status.success()
    {
        let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !path.is_empty() {
            return Some(PathBuf::from(path));
        }
    }
    let candidates = [
        "/opt/homebrew/bin/litestream",
        "/usr/local/bin/litestream",
        "/usr/bin/litestream",
    ];
    for c in candidates {
        let p = PathBuf::from(c);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

fn notebook_files() -> Vec<SourceFile> {
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
async fn test_litestream_replication_and_restore_brings_back_notebook_data() {
    let litestream_bin = match find_litestream() {
        Some(bin) => bin,
        None => {
            eprintln!("litestream binary not installed; skipping test");
            return;
        }
    };

    // 1. Prepare unique isolated test directories
    let unique_id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros();
    let temp_dir = std::env::temp_dir().join(format!("falak_litestream_{unique_id}"));
    std::fs::create_dir_all(&temp_dir).unwrap();

    let db_path = temp_dir.join("notebook.db");
    let replica_dir = temp_dir.join("replica");
    let restored_db_path = temp_dir.join("notebook_restored.db");

    let replica_url = format!("file://{}", replica_dir.display());

    // 2. Open SQLite database with WAL mode on disk
    let config = SqliteConfig {
        url: format!("sqlite://{}", db_path.display()),
        busy_timeout: Duration::from_millis(5000),
        reader_pool_size: 4,
    };
    let driver = SqliteDriver::open(config.clone()).await.unwrap();
    let ctx = RequestContext {
        principal: None,
        request_id: "litestream_setup".to_string(),
    };

    // 3. Apply schema migration to create Notebook tables
    let files = notebook_files();
    let (project_opt, diags) = load_project(&files);
    assert!(diags.is_empty(), "diags: {diags:?}");
    let ir = build_ir(&project_opt.unwrap());
    apply_initial_migration(&driver, &ctx, &ir).await.unwrap();

    // 4. Insert Notebook test data
    let note_id1 = [1u8; 16];
    let note_id2 = [2u8; 16];
    let user_id = [9u8; 16];
    let now = 1_700_000_000_000_000i64;

    driver
        .batch(
            &ctx,
            vec![
                Statement::new(
                    "INSERT INTO \"notes\" (id, title, body, archived, owner_id, created_at, updated_at, version) \
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
                    vec![
                        Value::Uuid(note_id1),
                        Value::Text("First Notebook Note".into()),
                        Value::Text("Litestream backup payload 1".into()),
                        Value::Bool(false),
                        Value::Uuid(user_id),
                        Value::TimestampMicros(now),
                        Value::TimestampMicros(now),
                        Value::Int64(1),
                    ],
                ),
                Statement::new(
                    "INSERT INTO \"notes\" (id, title, body, archived, owner_id, created_at, updated_at, version) \
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
                    vec![
                        Value::Uuid(note_id2),
                        Value::Text("Second Notebook Note".into()),
                        Value::Text("Litestream backup payload 2".into()),
                        Value::Bool(true),
                        Value::Uuid(user_id),
                        Value::TimestampMicros(now),
                        Value::TimestampMicros(now),
                        Value::Int64(1),
                    ],
                ),
            ],
        )
        .await
        .unwrap();

    // Drop the active driver to release all SQLite file locks before external tools
    drop(driver);

    // 5. Run Litestream one-shot replication to snapshot to replica
    let replicate_status = Command::new(&litestream_bin)
        .args([
            "replicate",
            "-once",
            "-force-snapshot",
            &db_path.to_string_lossy(),
            &replica_url,
        ])
        .status()
        .expect("Failed to execute litestream replicate");
    assert!(replicate_status.success(), "Litestream replication failed");

    // 6. Simulate disaster: delete original database and all WAL/SHM sidecars
    let _ = std::fs::remove_file(&db_path);
    let _ = std::fs::remove_file(temp_dir.join("notebook.db-wal"));
    let _ = std::fs::remove_file(temp_dir.join("notebook.db-shm"));
    assert!(!db_path.exists(), "Original database must be deleted");

    // 7. Restore database from Litestream replica
    let restore_status = Command::new(&litestream_bin)
        .args([
            "restore",
            "-o",
            &restored_db_path.to_string_lossy(),
            &replica_url,
        ])
        .status()
        .expect("Failed to execute litestream restore");
    assert!(restore_status.success(), "Litestream restore failed");
    assert!(
        restored_db_path.exists(),
        "Restored database must exist on disk"
    );

    // 8. Open restored database with a new SqliteDriver and verify Notebook data
    let restored_config = SqliteConfig {
        url: format!("sqlite://{}", restored_db_path.display()),
        busy_timeout: Duration::from_millis(5000),
        reader_pool_size: 4,
    };
    let restored_driver = SqliteDriver::open(restored_config).await.unwrap();

    let rows = restored_driver
        .query(
            &ctx,
            Statement::new(
                "SELECT title, body, archived FROM \"notes\" ORDER BY title ASC;",
                vec![],
            ),
        )
        .await
        .unwrap();

    assert_eq!(rows.rows.len(), 2, "Expected 2 restored notes");
    assert_eq!(rows.rows[0][0], Value::Text("First Notebook Note".into()));
    assert_eq!(
        rows.rows[0][1],
        Value::Text("Litestream backup payload 1".into())
    );
    assert_eq!(rows.rows[0][2], Value::Int64(0)); // 0/false in SQLite

    assert_eq!(rows.rows[1][0], Value::Text("Second Notebook Note".into()));
    assert_eq!(
        rows.rows[1][1],
        Value::Text("Litestream backup payload 2".into())
    );
    assert_eq!(rows.rows[1][2], Value::Int64(1)); // 1/true in SQLite

    // Clean up temporary directory
    let _ = std::fs::remove_dir_all(&temp_dir);
}
