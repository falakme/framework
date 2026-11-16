//! The outbox, the relay and the inbox (T5.2), on GardenX.

use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

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
use falak_driver_sqlite::SqliteDriver;
use falak_migrate::apply_initial_migration;
use falak_runtime_native::{
    context::DevAuthenticator,
    create_router,
    events::{Applied, ApplyError, Delivery, apply, relay_once},
};
use tower::ServiceExt;

fn app_dir(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/gardenx")
        .join(name)
}

fn load(name: &str) -> Ir {
    let root = app_dir(name);
    let mut files = Vec::new();
    for (dir, file) in [
        ("", "app.yaml"),
        ("entities", "purchase.yaml"),
        ("entities", "reservation.yaml"),
        ("policies", "purchase.yaml"),
        ("policies", "reservation.yaml"),
        ("commands", "reserve.yaml"),
        ("events", "order_placed.yaml"),
    ] {
        let rel = if dir.is_empty() {
            file.to_owned()
        } else {
            format!("{dir}/{file}")
        };
        if let Ok(text) = std::fs::read_to_string(root.join(&rel)) {
            files.push(SourceFile { path: rel, text });
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

async fn count(driver: &SqliteDriver, table: &str) -> i64 {
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

const USER: &str = "aaaaaaaa-0000-4000-8000-000000000001";

async fn place(app: &axum::Router, body: &str) -> (StatusCode, String) {
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/purchase")
                .header(header::AUTHORIZATION, format!("Bearer {USER}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_owned()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = res.status();
    let bytes = http_body_util::BodyExt::collect(res.into_body())
        .await
        .unwrap()
        .to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

#[tokio::test]
async fn a_change_and_its_event_are_written_together_and_relayed_in_order() {
    let ir = Arc::new(load("orders"));
    assert_eq!(ir.events.len(), 1);
    let driver = Arc::new(SqliteDriver::in_memory().await.unwrap());
    apply_initial_migration(&*driver, &ctx(), &ir)
        .await
        .unwrap();
    let app = create_router(ir, driver.clone(), Arc::new(DevAuthenticator));

    for qty in 1..=3 {
        let (s, b) = place(&app, &format!("{{\"sku\":\"rose\",\"qty\":{qty}}}")).await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
    }
    // A rejected order leaves no event behind.
    let (s, _) = place(&app, "{\"sku\":\"rose\",\"qty\":0}").await;
    assert_ne!(s, StatusCode::CREATED);
    assert_eq!(count(&driver, "purchases").await, 3);
    assert_eq!(count(&driver, "_falak_outbox").await, 3);

    // The relay stops at the first failure and keeps order.
    let seen = Mutex::new(Vec::new());
    let report = relay_once(&*driver, Dialect::Sqlite, 100, 1_000, |r| {
        let mut s = seen.lock().unwrap();
        let res = if s.len() == 1 {
            Err("office is down".to_owned())
        } else {
            s.push(r.payload);
            Ok(())
        };
        async move { res }
    })
    .await
    .unwrap();
    assert_eq!(report.sent, 1);
    assert_eq!(report.stopped.as_deref(), Some("office is down"));

    // After recovery the rest go, oldest first, and nothing is sent twice.
    let sent = Mutex::new(Vec::new());
    let report = relay_once(&*driver, Dialect::Sqlite, 100, 2_000, |r| {
        sent.lock().unwrap().push(r.payload);
        async { Ok(()) }
    })
    .await
    .unwrap();
    assert_eq!(report.sent, 2);
    let sent = sent.into_inner().unwrap();
    assert!(
        sent[0].contains("\"qty\":2") && sent[1].contains("\"qty\":3"),
        "{sent:?}"
    );
    assert!(sent[0].contains("\"sku\":\"rose\"") && sent[0].contains("\"id\""));
    let report = relay_once(&*driver, Dialect::Sqlite, 100, 3_000, |_| async { Ok(()) })
        .await
        .unwrap();
    assert_eq!(report.sent, 0);

    // Retention: sent rows are removed once they are old enough.
    let later = 8 * 86_400 * 1_000_000;
    relay_once(&*driver, Dialect::Sqlite, 100, later, |_| async { Ok(()) })
        .await
        .unwrap();
    assert_eq!(count(&driver, "_falak_outbox").await, 0);
}

#[tokio::test]
async fn an_event_is_applied_once_however_often_it_arrives() {
    let ir = load("inventory");
    let driver = SqliteDriver::in_memory().await.unwrap();
    apply_initial_migration(&driver, &ctx(), &ir).await.unwrap();
    let d = Delivery {
        id: "r1:order_placed".into(),
        publisher: "orders".into(),
        name: "order_placed".into(),
        version: 1,
        payload: "{\"id\":\"bbbbbbbb-0000-4000-8000-000000000002\",\"sku\":\"rose\",\"qty\":2}"
            .into(),
    };
    let first = apply(&driver, &ir, Dialect::Sqlite, &d, 1).await.unwrap();
    assert_eq!(first, Applied::Applied);
    for _ in 0..3 {
        let again = apply(&driver, &ir, Dialect::Sqlite, &d, 2).await.unwrap();
        assert_eq!(again, Applied::Duplicate);
    }
    assert_eq!(count(&driver, "reservations").await, 1);
    assert_eq!(count(&driver, "_falak_inbox").await, 1);

    // An event the app does not subscribe to is ignored; a wrong version is permanent.
    let other = Delivery {
        publisher: "billing".into(),
        ..d.clone()
    };
    assert_eq!(
        apply(&driver, &ir, Dialect::Sqlite, &other, 3)
            .await
            .unwrap(),
        Applied::Ignored
    );
    let v2 = Delivery {
        id: "r2:order_placed".into(),
        version: 2,
        ..d.clone()
    };
    assert!(matches!(
        apply(&driver, &ir, Dialect::Sqlite, &v2, 4).await,
        Err(ApplyError::Permanent(_))
    ));
    // A payload the handler cannot use is permanent and leaves no inbox row behind.
    let bad = Delivery {
        id: "r3:order_placed".into(),
        payload: "{\"id\":\"not-a-uuid\",\"sku\":\"rose\",\"qty\":1}".into(),
        ..d
    };
    assert!(matches!(
        apply(&driver, &ir, Dialect::Sqlite, &bad, 5).await,
        Err(ApplyError::Permanent(_))
    ));
    assert_eq!(count(&driver, "_falak_inbox").await, 1);
}
