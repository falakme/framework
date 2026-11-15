//! Stage 2 policies: attribute conditions (`where`), field masks (`fields`) and the
//! side-channel rules, end to end through the router on SQLite.

use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use falak_contracts::identity::RequestContext;
use falak_core::{
    build::build_ir,
    load::{SourceFile, load_project},
};
use falak_driver_sqlite::SqliteDriver;
use falak_migrate::apply_initial_migration;
use falak_runtime_native::{context::DevAuthenticator, create_router};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

const ALICE: &str = "00000000-0000-0000-0000-00000000000a";
const BOB: &str = "00000000-0000-0000-0000-00000000000b";
const CAROL: &str = "00000000-0000-0000-0000-00000000000c";

const APP: &str = "schema_version: 1\nname: docs\nversion: 0.1.0\ntenancy: none\ntrust_tier: standard\ndrivers: [sqlite, postgres, d1]\n";
const ENTITY: &str = "schema_version: 1\nentity: doc\nowner: owner_id\nfields:\n  title: { type: text, required: true, max_length: 200 }\n  body: { type: text }\n  status: { type: text, required: true, max_length: 20 }\n  owner_id: { type: uuid, required: true, indexed: true }\n";
const POLICY: &str = "\
schema_version: 1
entity: doc
rules:
  - id: owner_all
    actions: [read, create, update, delete]
    allow: { owner: true }
  - id: reviewers_published
    actions: [read]
    allow:
      role: reviewer
      where: { status: published }
      fields: [title, status]
  - id: editors_drafts
    actions: [update]
    allow:
      role: editor
      where: { status: draft }
      fields: [title, body, status]
";

async fn app() -> Router {
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
    let ir = Arc::new(build_ir(&project.unwrap()));
    let driver = Arc::new(SqliteDriver::in_memory().await.unwrap());
    let ctx = RequestContext {
        principal: None,
        request_id: "t".into(),
    };
    apply_initial_migration(&*driver, &ctx, &ir).await.unwrap();
    create_router(ir, driver, Arc::new(DevAuthenticator))
}

fn token(subject: &str, roles: &[&str]) -> String {
    let mut t = format!("sub:{subject}");
    for r in roles {
        t.push_str(&format!(",role:{r}"));
    }
    t
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

/// Alice owns one draft and one published document.
async fn seeded() -> (Router, String, String) {
    let app = app().await;
    let alice = token(ALICE, &[]);
    let (s, draft) = call(
        &app,
        "POST",
        "/v1/docs",
        &alice,
        Some(json!({"title": "draft one", "body": "secret draft", "status": "draft"})),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{draft}");
    let (s, published) = call(
        &app,
        "POST",
        "/v1/docs",
        &alice,
        Some(json!({"title": "public one", "body": "secret body", "status": "published"})),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{published}");
    (
        app,
        draft["id"].as_str().unwrap().to_owned(),
        published["id"].as_str().unwrap().to_owned(),
    )
}

#[tokio::test]
async fn an_attribute_rule_shows_only_matching_rows() {
    let (app, draft, published) = seeded().await;
    let bob = token(BOB, &["reviewer"]);
    let (s, list) = call(&app, "GET", "/v1/docs", &bob, None).await;
    assert_eq!(s, StatusCode::OK);
    let rows = list["data"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "{list}");
    assert_eq!(rows[0]["id"], published);

    let (s, _) = call(&app, "GET", &format!("/v1/docs/{draft}"), &bob, None).await;
    assert_eq!(
        s,
        StatusCode::NOT_FOUND,
        "a draft must be invisible, not forbidden"
    );
}

#[tokio::test]
async fn a_field_mask_hides_the_other_fields() {
    let (app, _, published) = seeded().await;
    let bob = token(BOB, &["reviewer"]);
    let (s, row) = call(&app, "GET", &format!("/v1/docs/{published}"), &bob, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(row["title"], "public one");
    assert!(
        row["body"].is_null(),
        "the reviewer rule does not grant `body`: {row}"
    );
}

#[tokio::test]
async fn an_owner_still_reads_every_field_of_their_own_rows() {
    let (app, draft, _) = seeded().await;
    // Alice is also a reviewer. The owner rule grants the body of her own rows.
    let alice = token(ALICE, &["reviewer"]);
    let (s, row) = call(&app, "GET", &format!("/v1/docs/{draft}"), &alice, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(row["body"], "secret draft");
}

#[tokio::test]
async fn a_mixed_list_masks_per_row() {
    let (app, _, _) = seeded().await;
    // Bob owns one published document of his own and can also review.
    let bob = token(BOB, &["reviewer"]);
    let (s, mine) = call(
        &app,
        "POST",
        "/v1/docs",
        &bob,
        Some(json!({"title": "bobs", "body": "bob body", "status": "published"})),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{mine}");
    let (s, list) = call(&app, "GET", "/v1/docs", &bob, None).await;
    assert_eq!(s, StatusCode::OK);
    let rows = list["data"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    for row in rows {
        if row["title"] == "bobs" {
            assert_eq!(row["body"], "bob body");
        } else {
            assert!(row["body"].is_null(), "alice's body leaked: {row}");
        }
    }
}

#[tokio::test]
async fn filtering_or_sorting_on_an_unreadable_field_is_refused() {
    let (app, _, _) = seeded().await;
    let bob = token(BOB, &["reviewer"]);
    let (s, err) = call(&app, "GET", "/v1/docs?filter[body]=secret", &bob, None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{err}");
    assert_eq!(err["code"], "invalid_filter");
    let (s, err) = call(&app, "GET", "/v1/docs?sort=body", &bob, None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{err}");
    // A field that is readable can be used.
    let (s, _) = call(
        &app,
        "GET",
        "/v1/docs?filter[title]=public%20one",
        &bob,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    // The refusal reads like one for a field that does not exist.
    let (_, unknown) = call(&app, "GET", "/v1/docs?sort=nope", &bob, None).await;
    assert_eq!(err["code"], unknown["code"], "{unknown}");
    assert_eq!(
        err["detail"].as_str().map(|d| d.replace("body", "X")),
        unknown["detail"].as_str().map(|d| d.replace("nope", "X")),
        "the two refusals must read the same"
    );
}

#[tokio::test]
async fn an_editor_changes_only_drafts_and_only_masked_fields() {
    let (app, draft, published) = seeded().await;
    let carol = token(CAROL, &["editor"]);

    let (s, row) = call(
        &app,
        "PATCH",
        &format!("/v1/docs/{draft}"),
        &carol,
        Some(json!({"title": "edited"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{row}");
    assert_eq!(row["title"], "edited");

    // A published document is outside the rule: not found.
    let (s, _) = call(
        &app,
        "PATCH",
        &format!("/v1/docs/{published}"),
        &carol,
        Some(json!({"title": "nope"})),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Moving a draft out of the rule's reach does not happen: the row is not updated.
    let (s, err) = call(
        &app,
        "PATCH",
        &format!("/v1/docs/{draft}"),
        &carol,
        Some(json!({"status": "published"})),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{err}");
    let (_, row) = call(
        &app,
        "GET",
        &format!("/v1/docs/{draft}"),
        &token(ALICE, &[]),
        None,
    )
    .await;
    assert_eq!(row["status"], "draft", "the status must be unchanged");

    // The editor rule gives no read of other people's drafts and no delete.
    let (s, _) = call(&app, "GET", &format!("/v1/docs/{draft}"), &carol, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = call(&app, "DELETE", &format!("/v1/docs/{draft}"), &carol, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_user_without_a_matching_rule_sees_nothing() {
    let (app, draft, _) = seeded().await;
    let dave = token("00000000-0000-0000-0000-00000000000d", &[]);
    let (s, list) = call(&app, "GET", "/v1/docs", &dave, None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(list["data"].as_array().unwrap().is_empty());
    let (s, _) = call(&app, "GET", &format!("/v1/docs/{draft}"), &dave, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}
