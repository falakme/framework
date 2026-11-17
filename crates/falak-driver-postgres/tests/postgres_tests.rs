use std::time::Duration;

use falak_contracts::{
    ErrorKind,
    capability::POSTGRES,
    driver::{Statement, StorageDriver, Transaction, TxOptions, Value},
    identity::{Principal, RequestContext},
};
use falak_driver_postgres::{PostgresConfig, PostgresDriver};

fn get_test_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@127.0.0.1:54321/falak_test".to_string())
}

async fn setup_driver() -> Option<PostgresDriver> {
    let url = get_test_url();
    let config = PostgresConfig {
        url,
        max_connections: 5,
        min_connections: 1,
        acquire_timeout: Duration::from_secs(2),
        idle_timeout: Some(Duration::from_secs(60)),
        max_lifetime: Some(Duration::from_secs(120)),
    };
    match PostgresDriver::open(config).await {
        Ok(driver) => Some(driver),
        Err(e) => {
            if std::env::var("FALAK_REQUIRE_PG").as_deref() == Ok("1") {
                panic!("FALAK_REQUIRE_PG=1 but PostgreSQL is unavailable: {e}");
            }
            eprintln!(
                "SKIPPED: PostgreSQL test (no database; set FALAK_REQUIRE_PG=1 to fail instead): {e}"
            );
            None
        }
    }
}

#[tokio::test]
async fn test_profile() {
    let Some(driver) = setup_driver().await else {
        return;
    };
    assert_eq!(driver.profile(), &POSTGRES);
    assert_eq!(driver.profile().name, "postgres");
}

#[tokio::test]
async fn test_full_crud_types_roundtrip_and_batch() {
    let Some(driver) = setup_driver().await else {
        return;
    };

    let ctx = RequestContext {
        principal: Some(Principal {
            subject: "user_alice".to_string(),
            tenant: Some("tenant_acme".to_string()),
            roles: vec!["admin".to_string()],
        }),
        request_id: "req_001".to_string(),
    };

    // Clean & create test table
    let ddl = vec![
        Statement::new("DROP TABLE IF EXISTS test_items;", vec![]),
        Statement::new(
            r#"CREATE TABLE test_items (
                id uuid PRIMARY KEY,
                title text NOT NULL,
                body text,
                count bigint NOT NULL,
                ratio double precision,
                is_active boolean NOT NULL,
                data bytea,
                metadata jsonb,
                created_at timestamptz NOT NULL
            );"#,
            vec![],
        ),
    ];
    driver
        .batch(&ctx, ddl)
        .await
        .expect("table creation batch failed");

    // Insert with values
    let test_uuid = [42u8; 16];
    let test_time = 1_700_000_000_123_456i64; // microsecond timestamp
    let insert_stmt = Statement::new(
        r#"INSERT INTO test_items (
            id, title, body, count, ratio, is_active, data, metadata, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9)
        RETURNING id, title, body, count, ratio, is_active, data, metadata, created_at;"#,
        vec![
            Value::Uuid(test_uuid),
            Value::Text("Hello Postgres".to_string()),
            Value::Null,
            Value::Int64(100),
            Value::Float64(42.5),
            Value::Bool(true),
            Value::Bytes(vec![1, 2, 3, 4, 5]),
            Value::Text(r#"{"status":"active"}"#.to_string()),
            Value::TimestampMicros(test_time),
        ],
    );

    let outcomes = driver
        .batch(&ctx, vec![insert_stmt])
        .await
        .expect("insert batch failed");
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].rows_affected, 1);
    assert_eq!(outcomes[0].rows.rows.len(), 1);

    let row = &outcomes[0].rows.rows[0];
    assert_eq!(row[0], Value::Uuid(test_uuid));
    assert_eq!(row[1], Value::Text("Hello Postgres".to_string()));
    assert_eq!(row[2], Value::Null);
    assert_eq!(row[3], Value::Int64(100));
    assert_eq!(row[4], Value::Float64(42.5));
    assert_eq!(row[5], Value::Bool(true));
    assert_eq!(row[6], Value::Bytes(vec![1, 2, 3, 4, 5]));
    assert_eq!(row[7], Value::Text(r#"{"status":"active"}"#.to_string()));
    assert_eq!(row[8], Value::TimestampMicros(test_time));

    // Query back
    let query_stmt = Statement::new(
        "SELECT id, title, count, is_active FROM test_items WHERE id = $1;",
        vec![Value::Uuid(test_uuid)],
    );
    let rows = driver.query(&ctx, query_stmt).await.expect("query failed");
    assert_eq!(rows.rows.len(), 1);
    assert_eq!(rows.rows[0][0], Value::Uuid(test_uuid));
    assert_eq!(rows.rows[0][1], Value::Text("Hello Postgres".to_string()));
    assert_eq!(rows.rows[0][2], Value::Int64(100));
    assert_eq!(rows.rows[0][3], Value::Bool(true));
}

#[tokio::test]
async fn test_session_context_injection() {
    let Some(driver) = setup_driver().await else {
        return;
    };

    let ctx = RequestContext {
        principal: Some(Principal {
            subject: "usr_super_secret".to_string(),
            tenant: Some("tnt_enterprise_99".to_string()),
            roles: vec!["operator".to_string()],
        }),
        request_id: "req_ctx_test".to_string(),
    };

    // Query session settings
    let stmt = Statement::new(
        "SELECT current_setting('falak.tenant_id', true), current_setting('falak.subject', true);",
        vec![],
    );
    let rows = driver.query(&ctx, stmt).await.expect("query failed");
    assert_eq!(rows.rows.len(), 1);
    assert_eq!(
        rows.rows[0][0],
        Value::Text("tnt_enterprise_99".to_string())
    );
    assert_eq!(rows.rows[0][1], Value::Text("usr_super_secret".to_string()));

    // Anonymous context resets to empty
    let anon_ctx = RequestContext {
        principal: None,
        request_id: "req_anon".to_string(),
    };
    let stmt2 = Statement::new(
        "SELECT current_setting('falak.tenant_id', true), current_setting('falak.subject', true);",
        vec![],
    );
    let rows2 = driver.query(&anon_ctx, stmt2).await.expect("query failed");
    assert_eq!(rows2.rows.len(), 1);
    assert_eq!(rows2.rows[0][0], Value::Text("".to_string()));
    assert_eq!(rows2.rows[0][1], Value::Text("".to_string()));
}

#[tokio::test]
async fn test_interactive_transactions_commit_and_rollback() {
    let Some(driver) = setup_driver().await else {
        return;
    };

    let ctx = RequestContext {
        principal: None,
        request_id: "req_tx_test".to_string(),
    };

    driver
        .batch(
            &ctx,
            vec![
                Statement::new("DROP TABLE IF EXISTS test_tx;", vec![]),
                Statement::new(
                    "CREATE TABLE test_tx (id int PRIMARY KEY, val text NOT NULL);",
                    vec![],
                ),
            ],
        )
        .await
        .unwrap();

    // 1. Transaction rollback
    let mut tx = driver
        .begin(&ctx, TxOptions::default())
        .await
        .expect("begin failed");
    tx.execute(Statement::new(
        "INSERT INTO test_tx (id, val) VALUES ($1, $2);",
        vec![Value::Int64(1), Value::Text("reverted".to_string())],
    ))
    .await
    .unwrap();
    tx.rollback().await.unwrap();

    let check1 = driver
        .query(
            &ctx,
            Statement::new("SELECT count(*) FROM test_tx WHERE id = 1;", vec![]),
        )
        .await
        .unwrap();
    assert_eq!(check1.rows[0][0], Value::Int64(0));

    // 2. Transaction commit
    let mut tx2 = driver
        .begin(&ctx, TxOptions::default())
        .await
        .expect("begin failed");
    tx2.execute(Statement::new(
        "INSERT INTO test_tx (id, val) VALUES ($1, $2);",
        vec![Value::Int64(2), Value::Text("committed".to_string())],
    ))
    .await
    .unwrap();
    tx2.commit().await.unwrap();

    let check2 = driver
        .query(
            &ctx,
            Statement::new("SELECT val FROM test_tx WHERE id = 2;", vec![]),
        )
        .await
        .unwrap();
    assert_eq!(check2.rows[0][0], Value::Text("committed".to_string()));

    // 3. Drop transaction without commit causes implicit rollback
    {
        let mut tx3 = driver.begin(&ctx, TxOptions::default()).await.unwrap();
        tx3.execute(Statement::new(
            "INSERT INTO test_tx (id, val) VALUES ($1, $2);",
            vec![Value::Int64(3), Value::Text("dropped".to_string())],
        ))
        .await
        .unwrap();
        // tx3 is dropped here without commit
    }

    let check3 = driver
        .query(
            &ctx,
            Statement::new("SELECT count(*) FROM test_tx WHERE id = 3;", vec![]),
        )
        .await
        .unwrap();
    assert_eq!(check3.rows[0][0], Value::Int64(0));
}

#[tokio::test]
async fn test_error_mapping() {
    let Some(driver) = setup_driver().await else {
        return;
    };

    let ctx = RequestContext {
        principal: None,
        request_id: "req_err_test".to_string(),
    };

    driver
        .batch(
            &ctx,
            vec![
                Statement::new("DROP TABLE IF EXISTS test_constraints;", vec![]),
                Statement::new(
                    "CREATE TABLE test_constraints (id int PRIMARY KEY, age int CHECK (age >= 0));",
                    vec![],
                ),
                Statement::new(
                    "INSERT INTO test_constraints (id, age) VALUES (1, 20);",
                    vec![],
                ),
            ],
        )
        .await
        .unwrap();

    // Unique violation (23505) -> ErrorKind::Conflict
    let err_unique = driver
        .batch(
            &ctx,
            vec![Statement::new(
                "INSERT INTO test_constraints (id, age) VALUES (1, 30);",
                vec![],
            )],
        )
        .await
        .unwrap_err();
    assert_eq!(err_unique.kind(), ErrorKind::Conflict);

    // Check violation (23514) -> ErrorKind::InvalidInput
    let err_check = driver
        .batch(
            &ctx,
            vec![Statement::new(
                "INSERT INTO test_constraints (id, age) VALUES (2, -5);",
                vec![],
            )],
        )
        .await
        .unwrap_err();
    assert_eq!(err_check.kind(), ErrorKind::InvalidInput);
}
