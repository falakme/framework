//! Regression tests from the security audit: each one failed before its fix.

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
    context::{Authenticator, DevAuthenticator, bearer_token},
    create_router,
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

const ALICE: &str = "00000000-0000-0000-0000-00000000000a";
const BOB: &str = "00000000-0000-0000-0000-00000000000b";
const T1: &str = "00000000-0000-0000-0000-0000000000a1";
const T2: &str = "00000000-0000-0000-0000-0000000000a2";

fn f(p: &str, t: &str) -> SourceFile {
    SourceFile {
        path: p.into(),
        text: t.into(),
    }
}

async fn router(files: Vec<SourceFile>, auth: Arc<dyn Authenticator>) -> Router {
    let (project, diags) = load_project(&files);
    assert!(!falak_core::diagnostics::has_errors(&diags), "{diags:?}");
    let ir = Arc::new(build_ir(&project.unwrap()));
    let driver = Arc::new(SqliteDriver::in_memory().await.unwrap());
    let ctx = RequestContext {
        principal: None,
        request_id: "t".into(),
    };
    apply_initial_migration(&*driver, &ctx, &ir).await.unwrap();
    create_router(ir, driver, auth)
}

async fn send(
    app: &Router,
    method: &str,
    uri: &str,
    token: &str,
    extra: &[(&str, &str)],
    body: Option<Value>,
) -> (StatusCode, HeaderMap, Value) {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"));
    for (k, v) in extra {
        b = b.header(*k, *v);
    }
    if body.is_some() {
        b = b.header(header::CONTENT_TYPE, "application/json");
    }
    let req = b
        .body(body.map_or_else(Body::empty, |v| Body::from(v.to_string())))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        headers,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn tok(subject: &str, roles: &[&str]) -> String {
    let mut t = format!("sub:{subject}");
    for r in roles {
        t.push_str(&format!(",role:{r}"));
    }
    t
}

// ------------------------------------------------------------------ commands

const APP: &str = "schema_version: 1\nname: docs\nversion: 0.1.0\ntenancy: none\ntrust_tier: standard\ndrivers: [sqlite, postgres, d1]\n";
const DOC: &str = "schema_version: 1\nentity: doc\nowner: owner_id\nfields:\n  title: { type: text, required: true, max_length: 200 }\n  body: { type: text }\n  status: { type: text, max_length: 20 }\n  owner_id: { type: uuid, required: true, indexed: true }\n";
const DOC_POLICY: &str = "\
schema_version: 1
entity: doc
rules:
  - id: owner_all
    actions: [read, create, update, delete]
    allow: { owner: true }
  - id: editors
    actions: [read, update]
    allow: { role: editor }
  - id: viewers
    actions: [read]
    allow:
      role: viewer
      fields: [title, status]
";
const MEMO: &str = "schema_version: 1\nentity: memo\nowner: owner_id\nfields:\n  note: { type: text, max_length: 200 }\n  status: { type: text, max_length: 20 }\n  owner_id: { type: uuid, required: true }\n";
const MEMO_POLICY: &str = "schema_version: 1\nentity: memo\nrules:\n  - id: owner_all\n    actions: [read, create, update, delete]\n    allow: { owner: true }\n";
const LOG: &str = "schema_version: 1\nentity: log\nfields:\n  title: { type: text, required: true, max_length: 200 }\n  body: { type: text, max_length: 200 }\nadmin:\n  list_columns: [title, body]\n";
const LOG_POLICY: &str = "schema_version: 1\nentity: log\nrules:\n  - id: viewers\n    actions: [read]\n    allow:\n      role: viewer\n      fields: [title]\n  - id: admins\n    actions: [read]\n    allow: { role: admin }\n";
const PURGE: &str = "schema_version: 1\ncommand: purge\nentity: doc\nkind: delete\ninput:\n  id: { type: uuid, required: true }\ntarget: id\n";
const CLOSE: &str = "schema_version: 1\ncommand: close\nentity: doc\nkind: update\ninput:\n  id: { type: uuid, required: true }\ntarget: id\nset:\n  status: closed\n";
const WIPE: &str = "schema_version: 1\ncommand: wipe\nentity: memo\nkind: update\ninput:\n  id: { type: uuid, required: true }\ntarget: id\nset:\n  status: wiped\n";

async fn doc_app() -> Router {
    router(
        vec![
            f("app.yaml", APP),
            f("entities/doc.yaml", DOC),
            f("policies/doc.yaml", DOC_POLICY),
            f("entities/memo.yaml", MEMO),
            f("policies/memo.yaml", MEMO_POLICY),
            f("entities/log.yaml", LOG),
            f("policies/log.yaml", LOG_POLICY),
            f("commands/purge.yaml", PURGE),
            f("commands/close.yaml", CLOSE),
            f("commands/wipe.yaml", WIPE),
        ],
        Arc::new(DevAuthenticator),
    )
    .await
}

async fn alice_doc(app: &Router) -> String {
    let (s, _, doc) = send(
        app,
        "POST",
        "/v1/docs",
        &tok(ALICE, &[]),
        &[],
        Some(json!({"title": "t", "body": "secret", "status": "open"})),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{doc}");
    doc["id"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn a_delete_command_needs_the_delete_action_not_update() {
    let app = doc_app().await;
    let id = alice_doc(&app).await;
    // Editors may update documents but have no `delete` rule.
    let editor = tok(BOB, &["editor"]);
    let (s, _, body) = send(
        &app,
        "POST",
        &format!("/v1/docs/{id}/purge"),
        &editor,
        &[],
        Some(json!({})),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{body}");
    let (s, _, _) = send(
        &app,
        "GET",
        &format!("/v1/docs/{id}"),
        &tok(ALICE, &[]),
        &[],
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "the document must still exist");
    // The owner may delete, so the same command works for them.
    let (s, _, body) = send(
        &app,
        "POST",
        &format!("/v1/docs/{id}/purge"),
        &tok(ALICE, &[]),
        &[],
        Some(json!({})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn an_update_command_still_runs_for_an_updater() {
    let app = doc_app().await;
    let id = alice_doc(&app).await;
    let (s, _, body) = send(
        &app,
        "POST",
        &format!("/v1/docs/{id}/close"),
        &tok(BOB, &["editor"]),
        &[],
        Some(json!({})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "closed");
}

#[tokio::test]
async fn a_command_runs_only_on_its_own_entity() {
    let app = doc_app().await;
    let id = alice_doc(&app).await;
    // `wipe` belongs to `memo`; it must not run against a document.
    let (s, _, body) = send(
        &app,
        "POST",
        &format!("/v1/docs/{id}/wipe"),
        &tok(ALICE, &[]),
        &[],
        Some(json!({})),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{body}");
}

// ------------------------------------------------------------------ list input

#[tokio::test]
async fn a_filter_that_cannot_apply_is_refused_not_dropped() {
    let app = doc_app().await;
    alice_doc(&app).await;
    let alice = tok(ALICE, &[]);
    for uri in [
        "/v1/docs?filter[nope]=x",
        "/v1/docs?filter[owner_id]=not-a-uuid",
        "/v1/docs?filter[title][neq]=x",
    ] {
        let (s, _, body) = send(&app, "GET", uri, &alice, &[], None).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{uri}: {body}");
        assert_eq!(body["code"], "invalid_filter", "{uri}");
    }
    // A viewer may not read `body`, and an unknown field gives the same answer.
    let viewer = tok(BOB, &["viewer"]);
    let (s1, _, b1) = send(&app, "GET", "/v1/docs?filter[body]=x", &viewer, &[], None).await;
    let (s2, _, b2) = send(&app, "GET", "/v1/docs?filter[nope]=x", &viewer, &[], None).await;
    assert_eq!((s1, &b1["code"]), (s2, &b2["code"]));
    assert_eq!(s1, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_bad_cursor_is_refused() {
    let app = doc_app().await;
    alice_doc(&app).await;
    let (s, _, body) = send(
        &app,
        "GET",
        "/v1/docs?page[after]=zzzz",
        &tok(ALICE, &[]),
        &[],
        None,
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "invalid_cursor");
}

// ------------------------------------------------------------------ _schema

#[tokio::test]
async fn schema_does_not_list_fields_the_caller_may_not_read() {
    let app = doc_app().await;
    let names = |v: &Value, entity: &str| -> Vec<String> {
        v["entities"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["name"] == entity)
            .unwrap()["fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["name"].as_str().unwrap().to_owned())
            .collect()
    };
    let (s, _, full) = send(
        &app,
        "GET",
        "/v1/_schema",
        &tok(ALICE, &["admin"]),
        &[],
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert!(names(&full, "log").contains(&"body".to_owned()));
    // The viewer rule grants only `title`.
    let (s, _, masked) = send(
        &app,
        "GET",
        "/v1/_schema",
        &tok(BOB, &["viewer"]),
        &[],
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let seen = names(&masked, "log");
    assert!(seen.contains(&"title".to_owned()), "{seen:?}");
    assert!(!seen.contains(&"body".to_owned()), "{seen:?}");
    let log = masked["entities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == "log")
        .unwrap();
    assert_eq!(log["admin"]["list_columns"], json!(["title"]));
}

// ------------------------------------------------------------------ request id

#[tokio::test]
async fn an_oversized_or_odd_request_id_is_replaced() {
    let app = doc_app().await;
    let long = "a".repeat(500);
    let (_, h, _) = send(
        &app,
        "GET",
        "/v1/docs",
        &tok(ALICE, &[]),
        &[("x-request-id", &long)],
        None,
    )
    .await;
    assert_ne!(h["x-request-id"].to_str().unwrap(), long);
    let (_, h, _) = send(
        &app,
        "GET",
        "/v1/docs",
        &tok(ALICE, &[]),
        &[("x-request-id", "client-id_1.2")],
        None,
    )
    .await;
    assert_eq!(h["x-request-id"], "client-id_1.2");
    let (_, h, _) = send(
        &app,
        "GET",
        "/v1/docs",
        &tok(ALICE, &[]),
        &[("x-request-id", "a b\"c")],
        None,
    )
    .await;
    assert_ne!(h["x-request-id"], "a b\"c");
}

// ------------------------------------------------------------------ idempotency

/// `Bearer <subject>|<tenant>`: a verified-looking caller with a tenant, for tests.
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

#[tokio::test]
async fn an_idempotency_key_never_replays_across_tenants() {
    const TAPP: &str = "schema_version: 1\nname: tdocs\nversion: 0.1.0\ntenancy: row\ntrust_tier: standard\ndrivers: [sqlite]\n";
    const NOTE: &str = "schema_version: 1\nentity: note\nfields:\n  title: { type: text, required: true, max_length: 200 }\n";
    const NOTE_POLICY: &str = "schema_version: 1\nentity: note\nrules:\n  - id: any\n    actions: [read, create, update, delete]\n    allow: { authenticated: true }\n";
    let app = router(
        vec![
            f("app.yaml", TAPP),
            f("entities/note.yaml", NOTE),
            f("policies/note.yaml", NOTE_POLICY),
        ],
        Arc::new(TenantAuth),
    )
    .await;
    let body = json!({"title": "same body"});
    let key = [("idempotency-key", "k-1")];
    // One person, with tokens for two tenants, retries the same key and body.
    let in_t1 = format!("{ALICE}|{T1}");
    let in_t2 = format!("{ALICE}|{T2}");
    let (s, _, first) = send(&app, "POST", "/v1/notes", &in_t1, &key, Some(body.clone())).await;
    assert_eq!(s, StatusCode::CREATED, "{first}");
    // The same call again in the same tenant replays.
    let (s, h, again) = send(&app, "POST", "/v1/notes", &in_t1, &key, Some(body.clone())).await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(h["idempotent-replayed"], "true");
    assert_eq!(again["id"], first["id"]);
    // In the other tenant it must run fresh, not return tenant one's stored response.
    let (s, h, second) = send(&app, "POST", "/v1/notes", &in_t2, &key, Some(body)).await;
    assert_eq!(s, StatusCode::CREATED, "{second}");
    assert!(
        h.get("idempotent-replayed").is_none(),
        "replayed across tenants"
    );
    assert_ne!(second["id"], first["id"]);
    // And tenant two really holds its own row.
    let (_, _, list) = send(&app, "GET", "/v1/notes", &in_t2, &[], None).await;
    assert_eq!(list["data"].as_array().unwrap().len(), 1);
    assert_eq!(list["data"][0]["id"], second["id"]);
}

#[tokio::test]
async fn an_idempotency_key_has_a_length_limit() {
    let app = doc_app().await;
    let long = "k".repeat(300);
    let (s, _, body) = send(
        &app,
        "POST",
        "/v1/docs",
        &tok(ALICE, &[]),
        &[("idempotency-key", &long)],
        Some(json!({"title": "t"})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "invalid_idempotency_key");
}
