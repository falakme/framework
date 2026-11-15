use falak_contracts::{
    ErrorKind,
    capability::Capability,
    driver::{Isolation, Outcome, Statement, StorageDriver, Transaction, TxOptions, Value},
    identity::RequestContext,
};
use falak_driver_sqlite::SqliteDriver;

fn dummy_context() -> RequestContext {
    RequestContext {
        principal: None,
        request_id: "test_req_1".to_string(),
    }
}

#[tokio::test]
async fn test_sqlite_driver_profile() {
    let driver = SqliteDriver::in_memory().await.unwrap();
    let profile = driver.profile();
    assert_eq!(profile.name, "sqlite");
    assert!(profile.provides(Capability::InteractiveTransactions));
    assert!(profile.provides(Capability::AtomicBatch));
    assert!(profile.provides(Capability::Savepoints));
    assert!(profile.provides(Capability::Returning));
    assert!(profile.provides(Capability::Upsert));
    assert!(!profile.provides(Capability::ConcurrentWriters));
    assert!(!profile.provides(Capability::NativeRls));
}

#[tokio::test]
async fn test_batch_and_query_crud() {
    let driver = SqliteDriver::in_memory().await.unwrap();
    let ctx = dummy_context();

    // 1. Create table using batch
    let ddl = Statement::new(
        "CREATE TABLE notes (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            body TEXT,
            pinned INTEGER DEFAULT 0,
            version INTEGER DEFAULT 1
        );",
        vec![],
    );
    driver.batch(&ctx, vec![ddl]).await.unwrap();

    // 2. Insert records using batch
    let insert = Statement::new(
        "INSERT INTO notes (id, title, body, pinned, version) VALUES (?, ?, ?, ?, ?);",
        vec![
            Value::Text("note-1".to_string()),
            Value::Text("Architecture".to_string()),
            Value::Text("Falak design notes".to_string()),
            Value::Bool(true),
            Value::Int64(1),
        ],
    );
    let outcomes = driver.batch(&ctx, vec![insert]).await.unwrap();
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].rows_affected, 1);

    // 3. Query records using query (via reader pool)
    let query_stmt = Statement::new(
        "SELECT id, title, body, pinned, version FROM notes WHERE id = ?;",
        vec![Value::Text("note-1".to_string())],
    );
    let rows = driver.query(&ctx, query_stmt).await.unwrap();
    assert_eq!(
        rows.columns,
        vec!["id", "title", "body", "pinned", "version"]
    );
    assert_eq!(rows.rows.len(), 1);
    assert_eq!(rows.rows[0][0], Value::Text("note-1".to_string()));
    assert_eq!(rows.rows[0][1], Value::Text("Architecture".to_string()));
    assert_eq!(
        rows.rows[0][2],
        Value::Text("Falak design notes".to_string())
    );
    assert_eq!(rows.rows[0][3], Value::Int64(1));
    assert_eq!(rows.rows[0][4], Value::Int64(1));
}

#[tokio::test]
async fn test_interactive_transaction_commit_and_rollback() {
    let driver = SqliteDriver::in_memory().await.unwrap();
    let ctx = dummy_context();

    let ddl = Statement::new(
        "CREATE TABLE items (id TEXT PRIMARY KEY, val INTEGER);",
        vec![],
    );
    driver.batch(&ctx, vec![ddl]).await.unwrap();

    // Rollback test
    let mut tx = driver
        .begin(
            &ctx,
            TxOptions {
                isolation: Isolation::Serializable,
                read_only: false,
            },
        )
        .await
        .unwrap();

    tx.execute(Statement::new(
        "INSERT INTO items (id, val) VALUES (?, ?);",
        vec![Value::Text("item-rollback".to_string()), Value::Int64(100)],
    ))
    .await
    .unwrap();

    tx.rollback().await.unwrap();

    // Confirm it wasn't saved
    let rows = driver
        .query(
            &ctx,
            Statement::new(
                "SELECT id FROM items WHERE id = ?;",
                vec![Value::Text("item-rollback".to_string())],
            ),
        )
        .await
        .unwrap();
    assert_eq!(rows.rows.len(), 0);

    // Commit test
    let mut tx2 = driver.begin(&ctx, TxOptions::default()).await.unwrap();

    tx2.execute(Statement::new(
        "INSERT INTO items (id, val) VALUES (?, ?);",
        vec![Value::Text("item-commit".to_string()), Value::Int64(200)],
    ))
    .await
    .unwrap();

    tx2.commit().await.unwrap();

    // Confirm it was saved
    let rows2 = driver
        .query(
            &ctx,
            Statement::new(
                "SELECT val FROM items WHERE id = ?;",
                vec![Value::Text("item-commit".to_string())],
            ),
        )
        .await
        .unwrap();
    assert_eq!(rows2.rows.len(), 1);
    assert_eq!(rows2.rows[0][0], Value::Int64(200));
}

#[tokio::test]
async fn test_returning_clause() {
    let driver = SqliteDriver::in_memory().await.unwrap();
    let ctx = dummy_context();

    let ddl = Statement::new(
        "CREATE TABLE returning_test (id TEXT PRIMARY KEY, name TEXT, version INTEGER);",
        vec![],
    );
    driver.batch(&ctx, vec![ddl]).await.unwrap();

    let insert_returning = Statement::new(
        "INSERT INTO returning_test (id, name, version) VALUES (?, ?, ?) RETURNING id, name, version;",
        vec![
            Value::Text("r-1".to_string()),
            Value::Text("First".to_string()),
            Value::Int64(1),
        ],
    );
    let outcomes: Vec<Outcome> = driver.batch(&ctx, vec![insert_returning]).await.unwrap();
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].rows_affected, 1);
    assert_eq!(outcomes[0].rows.columns, vec!["id", "name", "version"]);
    assert_eq!(
        outcomes[0].rows.rows[0][1],
        Value::Text("First".to_string())
    );
}

#[tokio::test]
async fn test_foreign_key_enforcement() {
    let driver = SqliteDriver::in_memory().await.unwrap();
    let ctx = dummy_context();

    let ddl = Statement::new(
        "CREATE TABLE parents (id TEXT PRIMARY KEY);
         CREATE TABLE children (id TEXT PRIMARY KEY, parent_id TEXT REFERENCES parents(id));",
        vec![],
    );
    driver.batch(&ctx, vec![ddl]).await.unwrap();

    // Insert child referencing non-existent parent must fail with InvalidInput
    let insert_child = Statement::new(
        "INSERT INTO children (id, parent_id) VALUES (?, ?);",
        vec![
            Value::Text("c-1".to_string()),
            Value::Text("missing-parent".to_string()),
        ],
    );
    let err = driver.batch(&ctx, vec![insert_child]).await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidInput);
    assert_eq!(err.code(), "constraint_violation");
}

#[tokio::test]
async fn test_unique_constraint_maps_to_conflict() {
    let driver = SqliteDriver::in_memory().await.unwrap();
    let ctx = dummy_context();

    let ddl = Statement::new("CREATE TABLE unique_items (id TEXT PRIMARY KEY);", vec![]);
    driver.batch(&ctx, vec![ddl]).await.unwrap();

    let insert = Statement::new(
        "INSERT INTO unique_items (id) VALUES (?);",
        vec![Value::Text("dup".to_string())],
    );
    driver.batch(&ctx, vec![insert.clone()]).await.unwrap();

    // Inserting duplicate must fail with ErrorKind::Conflict
    let err = driver.batch(&ctx, vec![insert]).await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Conflict);
    assert_eq!(err.code(), "unique_violation");
}

#[tokio::test]
async fn test_parameter_types_and_conversion() {
    let driver = SqliteDriver::in_memory().await.unwrap();
    let ctx = dummy_context();

    let ddl = Statement::new(
        "CREATE TABLE type_matrix (
            t_null TEXT,
            t_bool INTEGER,
            t_int INTEGER,
            t_float REAL,
            t_text TEXT,
            t_bytes BLOB,
            t_time INTEGER
        );",
        vec![],
    );
    driver.batch(&ctx, vec![ddl]).await.unwrap();

    let insert = Statement::new(
        "INSERT INTO type_matrix VALUES (?, ?, ?, ?, ?, ?, ?);",
        vec![
            Value::Null,
            Value::Bool(true),
            Value::Int64(9876543210),
            Value::Float64(42.5),
            Value::Text("Hello Falak".to_string()),
            Value::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]),
            Value::TimestampMicros(1700000000123456),
        ],
    );
    driver.batch(&ctx, vec![insert]).await.unwrap();

    let select = Statement::new("SELECT * FROM type_matrix;", vec![]);
    let rows = driver.query(&ctx, select).await.unwrap();
    assert_eq!(rows.rows.len(), 1);

    let row = &rows.rows[0];
    assert_eq!(row[0], Value::Null);
    assert_eq!(row[1], Value::Int64(1));
    assert_eq!(row[2], Value::Int64(9876543210));
    assert_eq!(row[3], Value::Float64(42.5));
    assert_eq!(row[4], Value::Text("Hello Falak".to_string()));
    assert_eq!(row[5], Value::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]));
    assert_eq!(row[6], Value::Int64(1700000000123456));
}
