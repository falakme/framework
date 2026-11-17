//! A page cursor is hex-encoded JSON and is not signed (API specification §2.2). These tests
//! pin down why that is safe: the cursor values are bound parameters, and the tenant and
//! policy predicates are applied to every page, so a forged cursor can only move the
//! position inside rows the caller may already see.

use std::collections::HashSet;
use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode, header},
};
use falak_contracts::{identity::Principal, identity::RequestContext};
use falak_core::{
    build::build_ir,
    load::{SourceFile, load_project},
};
use falak_driver_sqlite::SqliteDriver;
use falak_migrate::apply_initial_migration;
use falak_runtime_native::{
    context::{Authenticator, bearer_token},
    create_router,
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

const ALICE: &str = "00000000-0000-0000-0000-00000000000a";
const BOB: &str = "00000000-0000-0000-0000-00000000000b";
const T1: &str = "00000000-0000-0000-0000-0000000000a1";
const T2: &str = "00000000-0000-0000-0000-0000000000a2";

const APP: &str = "schema_version: 1\nname: tdocs\nversion: 0.1.0\ntenancy: row\ntrust_tier: standard\ndrivers: [sqlite]\n";
const NOTE: &str = "schema_version: 1\nentity: note\nowner: owner_id\nfields:\n  title: { type: text, required: true, max_length: 200 }\n  owner_id: { type: uuid, required: true, indexed: true }\n";
const NOTE_POLICY: &str = "schema_version: 1\nentity: note\nrules:\n  - id: owner_all\n    actions: [read, create, update, delete]\n    allow: { owner: true }\n";

/// `Bearer <subject>|<tenant>`.
struct TenantAuth;

impl Authenticator for TenantAuth {
    fn authenticate(&self, headers: &HeaderMap) -> Option<Principal> {
        let (subject, tenant) = bearer_token(headers)?.split_once('|')?;
        Some(Principal {
            subject: subject.to_owned(),
            tenant: Some(tenant.to_owned()),
            roles: vec![],
        })
    }
}

fn file(path: &str, text: &str) -> SourceFile {
    SourceFile {
        path: path.into(),
        text: text.into(),
    }
}

async fn app() -> Router {
    let files = vec![
        file("app.yaml", APP),
        file("entities/note.yaml", NOTE),
        file("policies/note.yaml", NOTE_POLICY),
    ];
    let (project, diags) = load_project(&files);
    assert!(!falak_core::diagnostics::has_errors(&diags), "{diags:?}");
    let ir = Arc::new(build_ir(&project.unwrap()));
    let driver = Arc::new(SqliteDriver::in_memory().await.unwrap());
    let ctx = RequestContext {
        principal: None,
        request_id: "t".into(),
    };
    apply_initial_migration(&*driver, &ctx, &ir).await.unwrap();
    create_router(ir, driver, Arc::new(TenantAuth))
}

async fn send(
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

/// Create `n` notes as `who` and return their ids.
async fn seed(app: &Router, who: &str, prefix: &str, n: usize) -> HashSet<String> {
    let mut ids = HashSet::new();
    for i in 0..n {
        let body = json!({"title": format!("{prefix}-{i}")});
        let (s, doc) = send(app, "POST", "/v1/notes", who, Some(body)).await;
        assert_eq!(s, StatusCode::CREATED, "{doc}");
        ids.insert(doc["id"].as_str().unwrap().to_owned());
    }
    ids
}

fn cursor(values: &Value) -> String {
    hex::encode(serde_json::to_vec(values).unwrap())
}

/// Either refused as `invalid_cursor`, or answered with only rows in `allowed`.
fn assert_refused_or_confined(status: StatusCode, body: &Value, allowed: &HashSet<String>) {
    if status == StatusCode::BAD_REQUEST {
        assert_eq!(body["code"], "invalid_cursor", "{body}");
        return;
    }
    assert_eq!(status, StatusCode::OK, "{body}");
    for row in body["data"].as_array().unwrap() {
        let id = row["id"].as_str().unwrap();
        assert!(
            allowed.contains(id),
            "a forged cursor returned a row the caller may not see: {row}"
        );
    }
}

#[tokio::test]
async fn a_cursor_taken_from_another_tenant_or_owner_reveals_no_row() {
    let app = app().await;
    let alice_t1 = format!("{ALICE}|{T1}");
    let bob_t1 = format!("{BOB}|{T1}");
    let alice_t2 = format!("{ALICE}|{T2}");
    let alices = seed(&app, &alice_t1, "a1", 3).await;
    let bobs = seed(&app, &bob_t1, "b1", 3).await;
    let other_tenant = seed(&app, &alice_t2, "a2", 3).await;

    // Real cursors cut from Bob's page (same tenant) and from the other tenant's page.
    let (_, bob_page) = send(&app, "GET", "/v1/notes?page[size]=1", &bob_t1, None).await;
    let bob_cursor = bob_page["meta"]["next_cursor"].as_str().unwrap().to_owned();
    let (_, t2_page) = send(&app, "GET", "/v1/notes?page[size]=1", &alice_t2, None).await;
    let t2_cursor = t2_page["meta"]["next_cursor"].as_str().unwrap().to_owned();

    for forged in [bob_cursor, t2_cursor] {
        let uri = format!("/v1/notes?page[size]=100&page[after]={forged}");
        let (s, body) = send(&app, "GET", &uri, &alice_t1, None).await;
        assert_refused_or_confined(s, &body, &alices);
        // Never Bob's rows, never the other tenant's.
        for row in body["data"].as_array().into_iter().flatten() {
            let id = row["id"].as_str().unwrap();
            assert!(!bobs.contains(id) && !other_tenant.contains(id), "{row}");
        }
    }
}

#[tokio::test]
async fn a_cursor_carrying_sql_is_a_value_not_a_statement() {
    let app = app().await;
    let alice_t1 = format!("{ALICE}|{T1}");
    let alices = seed(&app, &alice_t1, "a1", 3).await;
    seed(&app, &format!("{BOB}|{T1}"), "b1", 3).await;
    seed(&app, &format!("{ALICE}|{T2}"), "a2", 3).await;

    // Sorted by id (a uuid), a text value is refused as a bad cursor. Sorted by a text
    // field, the quote is just text, and the page still cannot widen.
    let attempts = [
        ("", json!(["' OR '1'='1' --"])),
        ("", json!(["'; DROP TABLE note; --"])),
        ("&sort=title", json!(["' OR '1'='1' --", "' OR 1=1 --"])),
        ("&sort=title", json!(["' OR '1'='1' --"])),
        ("&sort=title", json!(["\" ) OR 1=1; --"])),
        ("&sort=title", json!([null])),
        ("", json!([])),
        ("", json!({"values": ["x"]})),
    ];
    for (sort, values) in attempts {
        let uri = format!(
            "/v1/notes?page[size]=100{sort}&page[after]={}",
            cursor(&values)
        );
        let (s, body) = send(&app, "GET", &uri, &alice_t1, None).await;
        assert_refused_or_confined(s, &body, &alices);
    }

    // The table survived and Alice still sees exactly her rows.
    let (s, body) = send(&app, "GET", "/v1/notes?page[size]=100", &alice_t1, None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(body["data"].as_array().unwrap().len(), alices.len());
}
