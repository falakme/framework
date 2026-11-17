//! The outbox, relay and inbox on PostgreSQL (T5.2). Skipped when there is no database:
//! set `DATABASE_URL` to run it.

use std::{path::Path, sync::Arc, time::Duration};

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use falak_contracts::{
    driver::{Statement, StorageDriver, Value},
    identity::RequestContext,
    ir::Ir,
};
use falak_core::{build::build_ir, load::SourceFile, load::load_project, sql::Dialect};
use falak_driver_postgres::{PostgresConfig, PostgresDriver};
use falak_migrate::{MigrateOptions, migrate};
use falak_runtime_native::{
    context::DevAuthenticator,
    create_router,
    events::{Applied, Delivery, apply, relay_once},
};
use tower::ServiceExt;

fn load(name: &str) -> Ir {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/apps/gardenx")
        .join(name);
    let mut files = Vec::new();
    for rel in [
        "app.yaml",
        "entities/purchase.yaml",
        "entities/reservation.yaml",
        "entities/stock_move.yaml",
        "policies/purchase.yaml",
        "policies/reservation.yaml",
        "policies/stock_move.yaml",
        "commands/reserve.yaml",
        "events/order_placed.yaml",
    ] {
        if let Ok(text) = std::fs::read_to_string(root.join(rel)) {
            files.push(SourceFile {
                path: rel.into(),
                text,
            });
        }
    }
    let (p, d) = load_project(&files);
    assert!(p.is_some(), "{d:?}");
    build_ir(&p.unwrap())
}

fn ctx() -> RequestContext {
    RequestContext {
        principal: None,
        request_id: "t".into(),
    }
}

async fn count(driver: &PostgresDriver, table: &str) -> i64 {
    let r = StorageDriver::query(
        driver,
        &ctx(),
        Statement::new(format!("SELECT COUNT(*) FROM \"{table}\""), vec![]),
    )
    .await
    .unwrap();
    match r.rows[0][0] {
        Value::Int64(n) => n,
        ref v => panic!("{v:?}"),
    }
}

#[tokio::test]
async fn events_work_on_postgres() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        assert!(
            std::env::var("FALAK_REQUIRE_PG").as_deref() != Ok("1"),
            "FALAK_REQUIRE_PG=1 but DATABASE_URL is not set"
        );
        eprintln!("SKIPPED: DATABASE_URL is not set (set FALAK_REQUIRE_PG=1 to fail instead)");
        return;
    };
    let Ok(driver) = PostgresDriver::open(PostgresConfig {
        url,
        max_connections: 5,
        min_connections: 1,
        acquire_timeout: Duration::from_secs(2),
        idle_timeout: Some(Duration::from_secs(60)),
        max_lifetime: Some(Duration::from_secs(120)),
    })
    .await
    else {
        assert!(
            std::env::var("FALAK_REQUIRE_PG").as_deref() != Ok("1"),
            "FALAK_REQUIRE_PG=1 but PostgreSQL is unreachable"
        );
        eprintln!("SKIPPED: no PostgreSQL (set FALAK_REQUIRE_PG=1 to fail instead)");
        return;
    };
    let driver = Arc::new(driver);
    let _ = driver
        .batch(
            &ctx(),
            [
                "DROP TABLE IF EXISTS \"purchases\"",
                "DROP TABLE IF EXISTS \"reservations\"",
                "DROP TABLE IF EXISTS \"stock_moves\"",
                "DROP TABLE IF EXISTS \"_falak_outbox\"",
                "DROP TABLE IF EXISTS \"_falak_inbox\"",
                "DROP TABLE IF EXISTS \"_falak_migrations\"",
                "DROP TABLE IF EXISTS \"_falak_schema\"",
            ]
            .map(|s| Statement::new(s, vec![]))
            .to_vec(),
        )
        .await;

    // Orders: a change and its event are written together, then relayed.
    let orders = Arc::new(load("orders"));
    migrate(&*driver, &ctx(), &orders, MigrateOptions::default())
        .await
        .unwrap();
    let app = create_router(orders, driver.clone(), Arc::new(DevAuthenticator));
    for qty in 1..=2 {
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/purchases")
                    .header(
                        header::AUTHORIZATION,
                        "Bearer aaaaaaaa-0000-4000-8000-000000000001",
                    )
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!("{{\"sku\":\"rose\",\"qty\":{qty}}}")))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);
    }
    assert_eq!(count(&driver, "_falak_outbox").await, 2);
    let sent = std::sync::Mutex::new(0);
    let report = relay_once(&*driver, Dialect::Postgres, 10, 1_000, |_| {
        *sent.lock().unwrap() += 1;
        async { Ok(()) }
    })
    .await
    .unwrap();
    assert_eq!(report.sent, 2);
    assert_eq!(*sent.lock().unwrap(), 2);

    // Inventory: applied once however often it arrives.
    let inventory = load("inventory");
    let _ = driver
        .batch(
            &ctx(),
            vec![
                Statement::new("DROP TABLE IF EXISTS \"purchases\"", vec![]),
                Statement::new("DROP TABLE IF EXISTS \"_falak_schema\"", vec![]),
                Statement::new("DROP TABLE IF EXISTS \"_falak_migrations\"", vec![]),
            ],
        )
        .await;
    migrate(&*driver, &ctx(), &inventory, MigrateOptions::default())
        .await
        .unwrap();
    let d = Delivery {
        id: "r1:order_placed".into(),
        publisher: "orders".into(),
        name: "order_placed".into(),
        version: 1,
        payload: "{\"id\":\"bbbbbbbb-0000-4000-8000-000000000002\",\"sku\":\"rose\",\"qty\":2}"
            .into(),
    };
    assert_eq!(
        apply(&*driver, &inventory, Dialect::Postgres, &d, 1)
            .await
            .unwrap(),
        Applied::Applied
    );
    assert_eq!(
        apply(&*driver, &inventory, Dialect::Postgres, &d, 2)
            .await
            .unwrap(),
        Applied::Duplicate
    );
    assert_eq!(count(&driver, "reservations").await, 1);
}
