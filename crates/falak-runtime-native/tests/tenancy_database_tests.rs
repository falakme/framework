//! `database` tenancy on SQLite: one database file per tenant (T3.9).

use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode, header},
};
use falak_contracts::{identity::Principal, ir::Ir};
use falak_core::{
    build::build_ir,
    load::{SourceFile, load_project},
};
use falak_driver_sqlite::SqliteDriver;
use falak_runtime_native::{
    NativeDriver,
    context::{Authenticator, bearer_token},
    create_router,
    tenants::{SqliteTenants, TenantRouter},
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

const APP: &str = "schema_version: 1\nname: tdocs\nversion: 0.1.0\ntenancy: database\ntrust_tier: standard\ndrivers: [sqlite, d1]\n";
const ENTITY: &str = "schema_version: 1\nentity: doc\nowner: owner_id\nfields:\n  title: { type: text, required: true, max_length: 200 }\n  owner_id: { type: uuid, required: true }\n";
const POLICY: &str = "schema_version: 1\nentity: doc\nrules:\n  - id: own\n    actions: [read, create, update, delete]\n    allow: { owner: true }\n  - id: staff\n    actions: [read]\n    allow: { role: staff }\n";

const T1: &str = "00000000-0000-0000-0000-0000000000a1";
const T2: &str = "00000000-0000-0000-0000-0000000000a2";
const ALICE: &str = "00000000-0000-0000-0000-00000000000a";
const BOB: &str = "00000000-0000-0000-0000-00000000000b";

/// Test only: `Bearer <subject>@<tenant>[,<role>]`.
struct TenantAuth;

impl Authenticator for TenantAuth {
    fn authenticate(&self, headers: &HeaderMap) -> Option<Principal> {
        let token = bearer_token(headers)?;
        let (subject, rest) = token.split_once('@')?;
        let mut parts = rest.split(',');
        let tenant = parts.next()?.to_owned();
        Some(Principal {
            subject: subject.to_owned(),
            tenant: Some(tenant),
            roles: parts.map(str::to_owned).collect(),
        })
    }
}

fn ir() -> Arc<Ir> {
    let f = |p: &str, t: &str| SourceFile {
        path: p.into(),
        text: t.into(),
    };
    let (project, diags) = load_project(&[
        f("app.yaml", APP),
        f("entities/doc.yaml", ENTITY),
        f("policies/doc.yaml", POLICY),
    ]);
    assert!(!falak_core::diagnostics::has_errors(&diags), "{diags:?}");
    Arc::new(build_ir(&project.unwrap()))
}

async fn app(dir: &std::path::Path) -> Router {
    let ir = ir();
    let control: Arc<dyn NativeDriver> = Arc::new(SqliteDriver::in_memory().await.unwrap());
    let tenants = Arc::new(SqliteTenants::new(dir.to_path_buf(), ir.clone()));
    let router = Arc::new(TenantRouter::new(control, tenants));
    create_router(ir, router, Arc::new(TenantAuth))
}

async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    token: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"));
    if body.is_some() {
        b = b.header(header::CONTENT_TYPE, "application/json");
    }
    let req = b
        .body(body.map_or_else(Body::empty, |v| Body::from(v.to_string())))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn dir(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("falak-tenants-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

#[tokio::test]
async fn each_tenant_has_a_database_of_its_own() {
    let d = dir("own");
    let app = app(&d).await;
    let a = format!("{ALICE}@{T1}");
    let b = format!("{BOB}@{T2}");

    let (s, doc_a) = call(
        &app,
        "POST",
        "/v1/docs",
        &a,
        Some(json!({"title": "tenant one"})),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{doc_a}");
    let (s, _) = call(
        &app,
        "POST",
        "/v1/docs",
        &b,
        Some(json!({"title": "tenant two"})),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);

    // Two files, one per tenant.
    assert!(d.join(format!("{T1}.db")).is_file());
    assert!(d.join(format!("{T2}.db")).is_file());

    // Each sees only its own rows.
    let (_, list) = call(&app, "GET", "/v1/docs", &a, None).await;
    assert_eq!(list["data"].as_array().unwrap().len(), 1);
    assert_eq!(list["data"][0]["title"], "tenant one");
    let (_, list) = call(&app, "GET", "/v1/docs", &b, None).await;
    assert_eq!(list["data"][0]["title"], "tenant two");

    // Tenant two cannot reach tenant one's row by id, even as a role that reads all rows
    // in its own tenant: the row is in another database.
    let id = doc_a["id"].as_str().unwrap();
    let staff_two = format!("{BOB}@{T2},staff");
    let (s, _) = call(&app, "GET", &format!("/v1/docs/{id}"), &staff_two, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (_, list) = call(&app, "GET", "/v1/docs", &staff_two, None).await;
    assert_eq!(list["data"].as_array().unwrap().len(), 1);
    assert_eq!(list["data"][0]["title"], "tenant two");
    let _ = std::fs::remove_dir_all(&d);
}

#[tokio::test]
async fn a_tenant_that_is_not_a_uuid_reaches_nothing_and_makes_no_file() {
    let d = dir("bad");
    let app = app(&d).await;
    for tenant in ["../../escape", "T1", "00000000-0000-0000-0000-0000000000A1"] {
        let token = format!("{ALICE}@{tenant}");
        let (s, _) = call(
            &app,
            "POST",
            "/v1/docs",
            &token,
            Some(json!({"title": "x"})),
        )
        .await;
        assert!(
            s == StatusCode::FORBIDDEN || s == StatusCode::NOT_FOUND,
            "{tenant}: {s}"
        );
    }
    let made = std::fs::read_dir(&d).map(|r| r.count()).unwrap_or(0);
    assert_eq!(made, 0, "no database may be created for a bad tenant");
    let _ = std::fs::remove_dir_all(&d);
}

#[tokio::test]
async fn a_new_version_of_the_app_reaches_a_tenant_database_that_already_exists() {
    let d = dir("persist");
    {
        let app = app(&d).await;
        let a = format!("{ALICE}@{T1}");
        let (s, _) = call(&app, "POST", "/v1/docs", &a, Some(json!({"title": "kept"}))).await;
        assert_eq!(s, StatusCode::CREATED);
    }
    // A new process opens the same file and finds the row and the tables as they were.
    let app = app(&d).await;
    let (_, list) = call(&app, "GET", "/v1/docs", &format!("{ALICE}@{T1}"), None).await;
    assert_eq!(list["data"][0]["title"], "kept");
    let _ = std::fs::remove_dir_all(&d);
}
