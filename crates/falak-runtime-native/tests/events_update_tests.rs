//! Update and delete events (T5.2): raised only when the write changes a row.

use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use falak_contracts::{
    driver::{Statement, StorageDriver, Value},
    identity::RequestContext,
};
use falak_core::{build::build_ir, load::SourceFile, load::load_project};
use falak_driver_sqlite::SqliteDriver;
use falak_migrate::apply_initial_migration;
use falak_runtime_native::{context::DevAuthenticator, create_router};
use tower::ServiceExt;

const USER: &str = "aaaaaaaa-0000-4000-8000-000000000001";

fn ctx() -> RequestContext {
    RequestContext {
        principal: None,
        request_id: "t".into(),
    }
}

async fn outbox(driver: &SqliteDriver) -> Vec<(String, i64)> {
    let r = StorageDriver::query(
        driver,
        &ctx(),
        Statement::new(
            "SELECT event, revision FROM _falak_outbox ORDER BY seq",
            vec![],
        ),
    )
    .await
    .unwrap();
    r.rows
        .iter()
        .map(|row| match (&row[0], &row[1]) {
            (Value::Text(e), Value::Int64(n)) => (e.clone(), *n),
            other => panic!("{other:?}"),
        })
        .collect()
}

#[tokio::test]
async fn updates_and_deletes_raise_events_only_when_they_change_a_row() {
    let f = |p: &str, t: &str| SourceFile {
        path: p.into(),
        text: t.into(),
    };
    let (p, d) = load_project(&[
        f(
            "app.yaml",
            "schema_version: 1\nname: docs\nversion: 0.1.0\ntenancy: none\ntrust_tier: standard\ndrivers: [sqlite]\n",
        ),
        f(
            "entities/doc.yaml",
            "schema_version: 1\nentity: doc\nfields:\n  title: { type: text, required: true }\nlifecycle:\n  soft_delete: true\n",
        ),
        f(
            "policies/doc.yaml",
            "schema_version: 1\nentity: doc\nrules:\n  - id: all\n    actions: [read, create, update, delete]\n    allow: { authenticated: true }\n",
        ),
        f(
            "events/doc_changed.yaml",
            "schema_version: 1\nevent: doc_changed\npublish:\n  entity: doc\n  on: update\n  version: 1\n  fields: [title]\n  subscribers: [search]\n",
        ),
        f(
            "events/doc_removed.yaml",
            "schema_version: 1\nevent: doc_removed\npublish:\n  entity: doc\n  on: delete\n  version: 1\n  subscribers: [search]\n",
        ),
    ]);
    assert!(p.is_some(), "{d:?}");
    let ir = Arc::new(build_ir(&p.unwrap()));
    let driver = Arc::new(SqliteDriver::in_memory().await.unwrap());
    apply_initial_migration(&*driver, &ctx(), &ir)
        .await
        .unwrap();
    let app = create_router(ir, driver.clone(), Arc::new(DevAuthenticator));
    let call =
        |method: &'static str, uri: String, body: &'static str, if_match: Option<&'static str>| {
            let app = app.clone();
            async move {
                let mut b = Request::builder()
                    .method(method)
                    .uri(uri)
                    .header(header::AUTHORIZATION, format!("Bearer {USER}"))
                    .header(header::CONTENT_TYPE, "application/json");
                if let Some(v) = if_match {
                    b = b.header("if-match", v);
                }
                let res = app
                    .oneshot(b.body(Body::from(body)).unwrap())
                    .await
                    .unwrap();
                let status = res.status();
                let bytes = http_body_util::BodyExt::collect(res.into_body())
                    .await
                    .unwrap()
                    .to_bytes();
                (
                    status,
                    serde_json::from_slice::<serde_json::Value>(&bytes).unwrap_or_default(),
                )
            }
        };
    let (s, v) = call("POST", "/v1/doc".into(), "{\"title\":\"a\"}", None).await;
    assert_eq!(s, StatusCode::CREATED);
    let id = v["id"].as_str().unwrap().to_owned();
    assert!(outbox(&driver).await.is_empty(), "no create event declared");

    let (s, _) = call("PATCH", format!("/v1/doc/{id}"), "{\"title\":\"b\"}", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(outbox(&driver).await, [("doc_changed".to_owned(), 2)]);

    let (s, _) = call(
        "PATCH",
        format!("/v1/doc/{id}"),
        "{\"title\":\"c\"}",
        Some("\"1\""),
    )
    .await;
    assert_eq!(s, StatusCode::PRECONDITION_FAILED);
    assert_eq!(
        outbox(&driver).await.len(),
        1,
        "a refused write raises nothing"
    );

    let (s, _) = call("DELETE", format!("/v1/doc/{id}"), "", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let all = outbox(&driver).await;
    assert_eq!(all.len(), 2);
    assert_eq!(all[1].0, "doc_removed");
}
